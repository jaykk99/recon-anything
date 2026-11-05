"""Nuclei-style template verification engine (safe checks only).

Nuclei's real strength is its template library: small declarative
check definitions (request + matchers + extractors) run against a
target. This plugin is that idea, rebuilt inside ReconAnything:

- Templates are dicts: {id, severity, requests[], matchers[],
  matchers_condition, extractors[], cve_map}. The starter pack below
  ships in-code; extra templates can be dropped as JSON files (JSON
  is a YAML subset) into the directory named by the
  RECON_NUCLEI_TEMPLATE_DIR env var or the module override
  "nuclei_template_verify:template_dir".
- Requests are GET only, probed through ctx.probe (cached, rate
  limited, single-flight). Matchers run on status / headers / body.
- Verification is SAFE: version matches, response signatures, and
  the first matcher line of an exposed file. For /.env the engine
  records only the exposed KEY NAMES (``APP_KEY=`` -> ``APP_KEY``),
  never values, never the file body. No exploit payloads, no auth
  bypass, no file downloads beyond the probe's response head.

Dedupes against neighbours by design: directory listing belongs to
opendir, VCS crawling to git.py, header gaps to the header plugins,
version CVEs NOT in the pack to cves.py. This pack only ships
templates whose check is a template-shaped probe those plugins do
not already run, and reuses the shared finding keys (git_exposed,
exposed_env) where the finding is the same one.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# ---------------------------------------------------------------------------
# Starter template pack. Matcher types: status | word | regex |
# cve_version (extractor-driven, see CVE_CHECKS). Parts: body |
# header (all headers joined) | header:<name>.
# ---------------------------------------------------------------------------

CVE_CHECKS = [
    # product, kind ("exact" | "below"), version, cve, severity, note
    ("apache", "exact", "2.4.49", "CVE-2021-41773", "high",
     "Apache 2.4.49 path traversal / RCE (mod_cgi) version match"),
    ("apache", "exact", "2.4.50", "CVE-2021-42013", "high",
     "Apache 2.4.50 path traversal / RCE (incomplete 41773 fix)"),
    ("apache", "below", "2.4.60", "CVE-2024-38476", "medium",
     "Apache < 2.4.60 is in the CVE-2024-38476 affected range "
     "(mod_rewrite SSRF; needs specific config - verify manually)"),
    ("php", "below", "8.1.0", None, "low",
     "PHP version is end-of-life (< 8.1): no security patches"),
]

TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "git-head-exposed",
        "name": "Git repository metadata exposed (.git/HEAD)",
        "severity": "high",
        "key": "git_exposed",
        "requests": [{"method": "GET", "path": "/.git/HEAD"}],
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["ref: refs/"]},
        ],
        "matchers_condition": "and",
        "remediation": ("Block access to /.git at the web server or "
                        "remove the repository metadata from the "
                        "document root."),
    },
    {
        "id": "env-file-exposed",
        "name": "Environment file exposed (.env)",
        "severity": "high",
        "key": "exposed_env",
        "requests": [{"method": "GET", "path": "/.env"}],
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "regex", "part": "body",
             "regex": [r"(?m)^[A-Za-z_][A-Za-z0-9_]*="]},
        ],
        "matchers_condition": "and",
        "post": "env_key_names",
        "remediation": ("Remove .env from the document root and deny "
                        "dotfile access at the web server. Rotate every "
                        "secret named in the file."),
    },
    {
        "id": "phpinfo-exposed",
        "name": "phpinfo() page exposed",
        "severity": "medium",
        "key": "phpinfo_exposed",
        "requests": [{"method": "GET", "path": "/phpinfo.php"},
                     {"method": "GET", "path": "/info.php"}],
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["PHP Version"]},
        ],
        "matchers_condition": "and",
        "remediation": ("Delete phpinfo pages from production; they "
                        "leak paths, modules and environment values."),
    },
    {
        "id": "spring-actuator-env-exposed",
        "name": "Spring Boot Actuator /env exposed",
        "severity": "high",
        "key": "actuator_env_exposed",
        "requests": [{"method": "GET", "path": "/actuator/env"}],
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["propertySources"]},
        ],
        "matchers_condition": "and",
        "remediation": ("Restrict Actuator endpoints: "
                        "management.endpoints.web.exposure.include "
                        "should exclude env, and /actuator must sit "
                        "behind authentication."),
    },
    {
        "id": "apache-server-status-exposed",
        "name": "Apache mod_status page exposed (/server-status)",
        "severity": "medium",
        "key": "server_status_exposed",
        "requests": [{"method": "GET", "path": "/server-status"}],
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body",
             "words": ["Apache Server Status"]},
        ],
        "matchers_condition": "and",
        "remediation": ("Restrict /server-status to localhost or "
                        "trusted admin IPs in the mod_status config."),
    },
    {
        "id": "outdated-server-cve-match",
        "name": "Server banner version matches a known CVE range",
        "severity": "medium",
        "key": "cve_version_match",
        "requests": [{"method": "GET", "path": "/"}],
        "matchers": [{"type": "cve_version"}],
        "matchers_condition": "and",
        "remediation": ("Upgrade the server/PHP to a supported version "
                        "outside the affected range, then re-scan."),
    },
]

_SERVER_RE = re.compile(r"(?i)\b(apache|nginx|microsoft-iis|php)"
                        r"[/ ](\d+)\.(\d+)(?:\.(\d+))?")
_ENV_KEY_RE = re.compile(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)=")


def _version_tuple(text: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in text.split(".") if p.isdigit())


def _check_cve_versions(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Map Server / X-Powered-By banners to CVE_CHECKS entries."""
    hay = " ".join(str(headers.get(k, "")) for k in
                   ("server", "x-powered-by"))
    hits: List[Dict[str, Any]] = []
    seen = set()
    for m in _SERVER_RE.finditer(hay):
        product = m.group(1).lower()
        if product == "microsoft-iis":
            continue
        ver = ".".join(g for g in m.groups()[1:] if g is not None)
        for prod, kind, want, cve, sev, note in CVE_CHECKS:
            if prod != product:
                continue
            vt, wt = _version_tuple(ver), _version_tuple(want)
            match = (vt == wt) if kind == "exact" else (vt < wt)
            if match and (product, cve, ver) not in seen:
                seen.add((product, cve, ver))
                hits.append({"product": product, "version": ver,
                             "cve": cve, "severity": sev, "note": note})
    return hits


def _part_text(part: str, resp: Dict[str, Any]) -> str:
    headers = resp.get("headers") or {}
    if part == "body":
        return resp.get("text") or ""
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in headers.items())
    if part.startswith("header:"):
        return str(headers.get(part.split(":", 1)[1].lower(), ""))
    return ""


def _match_one(matcher: Dict[str, Any], resp: Dict[str, Any]) -> bool:
    mtype = matcher.get("type")
    if mtype == "status":
        return int(resp.get("status") or 0) in matcher.get("status", [])
    if mtype == "cve_version":
        return bool(_check_cve_versions(resp.get("headers") or {}))
    text = _part_text(matcher.get("part", "body"), resp)
    if mtype == "word":
        found = any(w in text for w in matcher.get("words", []))
    elif mtype == "regex":
        found = any(re.search(r, text) for r in matcher.get("regex", []))
    else:
        found = False
    return (not found) if matcher.get("negative") else found


def _template_matches(tpl: Dict[str, Any], resp: Dict[str, Any]) -> bool:
    results = [_match_one(m, resp) for m in tpl.get("matchers", [])]
    if not results:
        return False
    if tpl.get("matchers_condition") == "or":
        return any(results)
    return all(results)


def _load_extra_templates(ctx: Ctx) -> List[Dict[str, Any]]:
    """Operator-supplied templates: JSON files in a directory.

    JSON is a subset of YAML, so nuclei-style template files written
    as JSON load unchanged. Bad files are skipped, never fatal.
    """
    out: List[Dict[str, Any]] = []
    tdir = (ctx.module_overrides.get("nuclei_template_verify:template_dir")
            or os.environ.get("RECON_NUCLEI_TEMPLATE_DIR") or "")
    if not tdir or not os.path.isdir(tdir):
        return out
    for name in sorted(os.listdir(tdir)):
        if not name.endswith((".json", ".yaml", ".yml")):
            continue
        try:
            with open(os.path.join(tdir, name), encoding="utf-8") as fh:
                data = json.load(fh)
            for tpl in (data if isinstance(data, list) else [data]):
                if isinstance(tpl, dict) and tpl.get("id") \
                        and tpl.get("requests") and tpl.get("matchers"):
                    out.append(tpl)
        except Exception:
            continue
    return out


class NucleiTemplateVerifyPlugin(Plugin):
    id = "nuclei_template_verify"
    label = "Template Verification (Nuclei-style)"
    accepts = ["domain", "url"]
    passive = False
    aggressive = False
    cost = Cost.FREE
    group = "web"
    timeout_s = 90
    description = ("Declarative template checks (status/header/body "
                   "matchers + extractors) that verify common web CVEs "
                   "and misconfigurations with safe GET probes only. "
                   "Ships a starter pack; loads extra JSON templates "
                   "from RECON_NUCLEI_TEMPLATE_DIR.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        start = time.time()
        if self.module_mode(ctx) == "passive":
            return self._ok([], "template verification sends probes; "
                                "needs active mode")
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        base = await web_base(ctx, target, domain)
        templates = TEMPLATES + _load_extra_templates(ctx)
        findings: List[Finding] = []
        sem = asyncio.Semaphore(5)

        async def run_template(tpl: Dict[str, Any]) -> None:
            for req in tpl.get("requests", []):
                if str(req.get("method", "GET")).upper() != "GET":
                    continue  # safe verification: GET only, ever
                url = urljoin(base.rstrip("/") + "/", req.get("path", "/"))
                async with sem:
                    resp = await ctx.probe(url, timeout=8)
                if not resp or int(resp.get("status") or 0) == 0:
                    continue
                if not _template_matches(tpl, resp):
                    continue
                ev: Dict[str, Any] = {
                    "severity": tpl.get("severity", "low"),
                    "template_id": tpl["id"],
                    "template_name": tpl.get("name", tpl["id"]),
                    "matched_url": url,
                    "status": resp.get("status"),
                    "remediation": tpl.get(
                        "remediation",
                        "Apply the vendor fix for this template check "
                        "and re-scan to verify."),
                }
                if tpl.get("post") == "env_key_names":
                    # Flag, don't exfiltrate: key NAMES only, no values,
                    # no body text anywhere in the finding.
                    keys = _ENV_KEY_RE.findall(resp.get("text") or "")
                    ev["exposed_key_names"] = sorted(set(keys))[:25]
                if any(m.get("type") == "cve_version"
                       for m in tpl.get("matchers", [])):
                    hits = _check_cve_versions(resp.get("headers") or {})
                    if not hits:
                        continue
                    ev["cve_matches"] = hits
                    ev["severity"] = hits[0]["severity"]
                    ev["cve"] = hits[0]["cve"]
                findings.append(self._f(
                    "web", tpl.get("key", "nuclei_template_hit"),
                    f"{tpl.get('name', tpl['id'])} verified at {url}",
                    source="nuclei-style template verification",
                    source_url=url, confidence=85, passive=False,
                    evidence=ev))
                break  # one finding per template

        await asyncio.gather(*(run_template(t) for t in templates))
        result = self._ok(findings,
                          f"{len(templates)} templates run, "
                          f"{len(findings)} verified")
        result.duration_ms = int((time.time() - start) * 1000)
        return result
