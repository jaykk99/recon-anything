"""Jaeles-style signature engine (Tier-4 Vuln/CVE).

Jaeles' model: vulnerabilities as portable YAML signatures with
matchers, run in two modes - passive (evaluate against an already
fetched response: headers / cookies / body) and active (issue the
signature's own safe GET and match the response). This plugin ships
a starter signature set in real YAML, loads it with a YAML parser
at runtime (falling back to the identical built-in structures when
PyYAML is unavailable), and evaluates every signature against the
target's homepage plus each active signature's path.

Detection only: signatures match banners, headers, cookie flags,
debug markers and exposed-path status codes. No payloads.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

SIGNATURES_YAML = """
- id: server-version-disclosure
  mode: passive
  severity: low
  matchers:
    - type: header_regex
      header: server
      pattern: "[0-9]+\\\\.[0-9]+"
  description: Server header discloses an exact version
- id: powered-by-disclosure
  mode: passive
  severity: low
  matchers:
    - type: header_present
      header: x-powered-by
  description: X-Powered-By header present
- id: cookie-missing-httponly
  mode: passive
  severity: medium
  matchers:
    - type: cookie_flag_missing
      flag: httponly
  description: A Set-Cookie is issued without HttpOnly
- id: debug-mode-marker
  mode: passive
  severity: high
  matchers:
    - type: body_regex
      pattern: "(?i)(django.*debug\\\\s*=\\\\s*true|wp_debug|APP_DEBUG=true|debug mode is on)"
  description: Page body advertises a framework debug mode
- id: git-head-exposed
  mode: active
  severity: high
  path: /.git/HEAD
  matchers:
    - type: status
      status: 200
    - type: body_regex
      pattern: "ref: refs/"
  description: /.git/HEAD readable (repository exposure)
- id: env-file-exposed
  mode: active
  severity: high
  path: /.env
  matchers:
    - type: status
      status: 200
    - type: body_not_regex
      pattern: "(?i)(<!doctype|<html)"
  description: /.env returns HTTP 200 with a non-HTML body (existence check only; catch-all HTML pages do not match)
- id: actuator-health-exposed
  mode: active
  severity: medium
  path: /actuator/health
  matchers:
    - type: status
      status: 200
    - type: body_regex
      pattern: '"status"\\s*:\\s*"UP"'
  description: Spring Boot actuator health endpoint public
- id: directory-listing
  mode: active
  severity: medium
  path: /uploads/
  matchers:
    - type: status
      status: 200
    - type: body_regex
      pattern: "(?i)(index of /|directory listing)"
  description: /uploads/ serves a directory listing
"""

_REQUIRED = ("id", "mode", "matchers")


def load_signatures() -> List[Dict]:
    """Load the starter set from its YAML text (built-in fallback)."""
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(SIGNATURES_YAML)
        if isinstance(data, list):
            return [s for s in data if isinstance(s, dict)
                    and all(k in s for k in _REQUIRED)]
    except Exception:
        pass
    return _fallback_signatures()


def _fallback_signatures() -> List[Dict]:
    return [
        {"id": "server-version-disclosure", "mode": "passive",
         "severity": "low", "description": "Server header discloses an "
         "exact version", "matchers": [
             {"type": "header_regex", "header": "server",
              "pattern": r"[0-9]+\.[0-9]+"}]},
        {"id": "powered-by-disclosure", "mode": "passive",
         "severity": "low", "description": "X-Powered-By header present",
         "matchers": [{"type": "header_present",
                       "header": "x-powered-by"}]},
        {"id": "cookie-missing-httponly", "mode": "passive",
         "severity": "medium", "description": "A Set-Cookie is issued "
         "without HttpOnly", "matchers": [
             {"type": "cookie_flag_missing", "flag": "httponly"}]},
        {"id": "debug-mode-marker", "mode": "passive", "severity": "high",
         "description": "Page body advertises a framework debug mode",
         "matchers": [{"type": "body_regex", "pattern":
                       r"(?i)(django.*debug\s*=\s*true|wp_debug|"
                       r"APP_DEBUG=true|debug mode is on)"}]},
        {"id": "git-head-exposed", "mode": "active", "severity": "high",
         "path": "/.git/HEAD", "description": "/.git/HEAD readable "
         "(repository exposure)", "matchers": [
             {"type": "status", "status": 200},
             {"type": "body_regex", "pattern": "ref: refs/"}]},
        {"id": "env-file-exposed", "mode": "active", "severity": "high",
         "path": "/.env", "description": "/.env returns HTTP 200 "
         "with a non-HTML body (existence check only)", "matchers": [
             {"type": "status", "status": 200},
             {"type": "body_not_regex",
              "pattern": r"(?i)(<!doctype|<html)"}]},
        {"id": "actuator-health-exposed", "mode": "active",
         "severity": "medium", "path": "/actuator/health",
         "description": "Spring Boot actuator health endpoint public",
         "matchers": [{"type": "status", "status": 200},
                      {"type": "body_regex",
                       "pattern": r'"status"\s*:\s*"UP"'}]},
        {"id": "directory-listing", "mode": "active",
         "severity": "medium", "path": "/uploads/",
         "description": "/uploads/ serves a directory listing",
         "matchers": [{"type": "status", "status": 200},
                      {"type": "body_regex",
                       "pattern": r"(?i)(index of /|directory listing)"}]},
    ]


def _matcher_ok(m: Dict, status: int, headers: Dict[str, str],
                cookies: List[str], body: str) -> bool:
    t = m.get("type")
    try:
        if t == "status":
            return status == int(m.get("status", -1))
        if t == "header_present":
            return str(m.get("header", "")).lower() in headers
        if t == "header_regex":
            val = headers.get(str(m.get("header", "")).lower(), "")
            return bool(re.search(str(m.get("pattern", "")), val))
        if t == "body_regex":
            return bool(re.search(str(m.get("pattern", "")),
                                  body or ""))
        if t == "body_not_regex":
            return not re.search(str(m.get("pattern", "")),
                                 body or "")
        if t == "cookie_flag_missing":
            flag = str(m.get("flag", "")).lower()
            return any(flag not in c.lower() for c in cookies)
    except Exception:
        return False
    return False


def signature_matches(sig: Dict, status: int, headers: Dict[str, str],
                      cookies: List[str], body: str) -> bool:
    matchers = sig.get("matchers") or []
    return bool(matchers) and all(
        _matcher_ok(m, status, headers, cookies, body) for m in matchers)


class JaelesScanPlugin(Plugin):
    id = "jaeles_scan"
    label = "Jaeles Signature Engine"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = ("Jaeles-style YAML signature engine: passive "
                   "header/cookie/body signatures + active safe-GET "
                   "signatures, starter set bundled.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        page = await ctx.fetch_page(base + "/", timeout=12)
        if page is None:
            return self._degraded("homepage unreachable")
        headers = {str(k).lower(): str(v)
                   for k, v in dict(page.get("headers") or {}).items()}
        hdrs_obj = page.get("headers")
        cookies: List[str] = []
        try:
            if hasattr(hdrs_obj, "get_list"):
                cookies = list(hdrs_obj.get_list("set-cookie"))
            elif headers.get("set-cookie"):
                cookies = [headers["set-cookie"]]
        except Exception:
            cookies = []
        body = (page.get("text") or "")[:200000]
        status = int(page.get("status_code") or 0)
        findings: List[Finding] = []
        sigs = load_signatures()
        for sig in sigs:
            if sig.get("mode") == "passive":
                ok = signature_matches(sig, status, headers, cookies, body)
                url = base + "/"
            else:
                r = await ctx.probe(base + str(sig.get("path", "/")),
                                    timeout=8)
                ok = signature_matches(
                    sig, int(r.get("status") or 0),
                    {str(k).lower(): str(v) for k, v in
                     (r.get("headers") or {}).items()},
                    [], r.get("text") or "")
                url = base + str(sig.get("path", "/"))
            if ok:
                findings.append(self._f(
                    "web", "jaeles_signature_match",
                    f"Signature {sig['id']}: {sig.get('description', '')}",
                    source="jaeles signature engine", source_url=url,
                    confidence=85, passive=(sig.get("mode") == "passive"),
                    evidence={"severity": sig.get("severity", "low"),
                              "signature": sig["id"],
                              "remediation": (
                                  "Address the condition this signature "
                                  "detects, then re-run the signature "
                                  "set to verify it no longer matches.")}))
        return PluginResult(
            plugin_id=self.id, status="ok", findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"evaluated {len(sigs)} signatures, "
                   f"{len(findings)} matched")
