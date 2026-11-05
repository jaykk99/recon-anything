"""Zero-Day Candidate Hunter: error-path miner.

error_pages.py already knocks on two nonexistent paths and reads the
404. This hunter goes after the error paths of the target's REAL
endpoints: deliberately malformed requests (non-numeric IDs where
numbers are expected, negative and overflowing IDs, broken percent
encodings, truncated JSON bodies) coax each discovered endpoint into
its error branch, and the error bodies are mined for internals no
checklist enumerated for this target:

- internal source file paths (the target's own code layout),
- SQL fragments and database error detail,
- stack traces / debug output,
- internal hostnames and private-range IPs,
- environment variable / config key names,
- framework and runtime versions.

Each DISTINCT disclosure is one finding. Disclosures that reveal the
target's own source files are additionally labeled candidate_zero_day
(they expose a code path nothing else in the scan disclosed); the
rest are plain info/medium findings in this pack's terms (low/medium
on the shared 3-level risk scale). Evidence is the target's own error
text (shown in full per the standing rule) plus request metadata.

Boundary: malformed is not malicious - these requests carry no
injection payloads and no exploit strings; they are the kind of
garbage any broken client sends. Passive mode never sends them.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import same_domain
from .param_fuzzer import STATE_CHANGING_HINTS
from .zeroday_util import candidate_evidence, mine_disclosures

MAX_ENDPOINTS = 6
REQ_TIMEOUT = 8
MAX_FINDINGS = 30

REMEDIATION = ("Error responses must be uniform and content-free: a "
               "generic message and a correlation ID, with the detail "
               "kept in server-side logs. Every internal path, SQL "
               "fragment, hostname or version in an error body is a "
               "free map of the system for whoever asks badly enough.")


# ---------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------

_ID_PARAM = re.compile(r"^(?:id|uid|user_?id|item_?id|obj_?id|ref)$", re.I)
_NUM_SEG = re.compile(r"^\d{1,12}$")


def malformed_variants(url: str) -> List[Dict[str, str]]:
    """Malformed-request variants of a discovered endpoint URL.

    Returns [{name, url, description}] - GET-level garbling only:
    bad IDs (path segment or id-shaped query parameter), overflowing
    and negative IDs, broken percent-encodings. No payloads.
    """
    out: List[Dict[str, str]] = []
    parts = urlparse(url)
    segments = parts.path.split("/")

    def rebuild(path: str, query: str) -> str:
        return urlunparse(parts._replace(path=path, query=query))

    # numeric path segment -> bad / huge / negative id
    for i, seg in enumerate(segments):
        if _NUM_SEG.match(seg):
            for name, repl, desc in (
                    ("bad_id_path", "abc", "non-numeric value in a "
                                           "numeric ID path segment"),
                    ("huge_id_path", "99999999999999999999",
                     "overflowing numeric ID in path"),
                    ("negative_id_path", "-1", "negative ID in path")):
                segs = list(segments)
                segs[i] = repl
                out.append({"name": name,
                            "url": rebuild("/".join(segs), parts.query),
                            "description": desc})
            break

    # id-shaped query parameter -> same treatment
    params = parse_qsl(parts.query, keep_blank_values=True)
    for idx, (k, v) in enumerate(params):
        if _ID_PARAM.match(k) or (v.isdigit() and k.lower().endswith("id")):
            for name, repl, desc in (
                    ("bad_id_param", "abc!", "non-numeric value in an "
                                             "ID parameter"),
                    ("huge_id_param", "99999999999999999999",
                     "overflowing numeric ID parameter"),
                    ("negative_id_param", "-1", "negative ID parameter")):
                ps = list(params)
                ps[idx] = (k, repl)
                out.append({"name": name,
                            "url": rebuild(parts.path, urlencode(ps)),
                            "description": desc})
            break

    # broken encodings in the first parameter value: raw surgery on
    # the original query string so the % sequences reach the server
    # exactly as written (urlencode would re-encode them).
    if params and parts.query:
        tokens = parts.query.split("&")
        head, _, _old = tokens[0].partition("=")
        for name, bad, desc in (
                ("truncated_percent", "%", "lone percent sign as value"),
                ("bad_utf8", "%C3%28", "invalid UTF-8 byte sequence"),
                ("double_encoded", "%252e%252e",
                 "double-encoded traversal-shaped value")):
            raw = "&".join([f"{head}={bad}"] + tokens[1:])
            out.append({"name": name,
                        "url": rebuild(parts.path, raw),
                        "description": desc})
    return out


# ---------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------

class ZerodayErrorMinerPlugin(Plugin):
    id = "zeroday_error_miner"
    label = "Zero-Day Candidate Hunter (Error-Path Miner)"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    phase = 2
    timeout_s = 180
    description = ("Sends deliberately malformed requests (bad IDs, "
                   "broken encodings, truncated bodies) to discovered "
                   "endpoints and mines the error responses for "
                   "internal paths, SQL detail, hostnames, env names "
                   "and versions nobody enumerated.")

    async def _send(self, ctx: Ctx, method: str, url: str,
                    **kw) -> Optional[Tuple[int, str]]:
        try:
            resp = await fetch(ctx.http, ctx.limiter, method, url,
                               timeout=REQ_TIMEOUT, follow_redirects=True,
                               max_retries=0, **kw)
        except Exception:
            return None
        return resp.status_code, resp.text or ""

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if self.module_mode(ctx) == "passive":
            return self._skipped(
                "passive mode: malformed requests are never sent in "
                "passive mode")
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        endpoints: List[str] = []
        for eu in ctx.consume("endpoints"):
            u = str(eu)
            p = urlparse(u)
            if not p.netloc or not same_domain(u, domain):
                continue
            low = (p.path + "?" + p.query).lower()
            if any(h in low for h in STATE_CHANGING_HINTS):
                continue
            if u not in endpoints:
                endpoints.append(u)
            if len(endpoints) >= MAX_ENDPOINTS:
                break
        if not endpoints:
            from ..net import web_base
            base = web_base(target.normalized)
            if base:
                endpoints = [base]

        findings: List[Finding] = []
        emitted = set()          # (kind, match.lower()) already reported
        probes = 0
        for endpoint in endpoints:
            if len(findings) >= MAX_FINDINGS:
                break
            baseline = await self._send(ctx, "GET", endpoint)
            baseline_disc = set()
            if baseline is not None:
                baseline_disc = {(d["kind"], d["match"].lower())
                                 for d in mine_disclosures(baseline[1])}
            jobs: List[Tuple[str, str, Dict[str, Any]]] = \
                [(v["name"], v["url"], {}) for v in
                 malformed_variants(endpoint)]
            if "/api" in urlparse(endpoint).path.lower():
                jobs.append(("truncated_json_body", endpoint, {
                    "content": '{"id": ',
                    "headers": {"Content-Type": "application/json"},
                    "_method": "POST"}))
            for name, url, kw in jobs:
                if len(findings) >= MAX_FINDINGS:
                    break
                method = kw.pop("_method", "GET")
                got = await self._send(ctx, method, url, **kw)
                if got is None:
                    continue
                probes += 1
                status, text = got
                for d in mine_disclosures(text):
                    key = (d["kind"], d["match"].lower())
                    if key in emitted or key in baseline_disc:
                        continue
                    # The response came from a malformed request, so
                    # anything internal in it is error-context by
                    # construction; disclosures already present in the
                    # endpoint's normal response were subtracted above
                    # (they are other plugins' territory).
                    emitted.add(key)
                    findings.append(self._finding(
                        endpoint, name, url, status, d))
            self._checkpoint(findings)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{probes} malformed probes across "
                                 f"{len(endpoints)} endpoints, "
                                 f"{len(findings)} distinct internal "
                                 f"disclosures")
        res.duration_ms = dur
        return res

    def _finding(self, endpoint: str, probe: str, url: str,
                 status: int, d: Dict[str, Any]) -> Finding:
        is_candidate = bool(d["is_code_path"])
        extra = {
            "disclosure_kind": d["kind"],
            "disclosed": d["match"],
            "context": d["context"],
            "endpoint": endpoint, "probe": probe,
            "response_status": status,
            "remediation": REMEDIATION,
        }
        if is_candidate:
            ev = candidate_evidence(
                "error_miner", "internal_code_path_disclosure", 62,
                severity=d["severity"], extra=extra)
            ev["severity"] = d["severity"]
        else:
            ev = dict(extra)
            ev["severity"] = d["severity"]
        label = "CANDIDATE (not yet verified): " if is_candidate else ""
        return self._f(
            "leak",
            "candidate_zero_day" if is_candidate
            else "error_internal_disclosure",
            f"{label}{d['label']}: {d['match']} "
            f"(via {probe} at {urlparse(endpoint).path or '/'})",
            source="zero-day error-path miner", source_url=url,
            confidence=62 if is_candidate else 80,
            passive=False, evidence=ev)
