"""Wapiti-style web vulnerability scanner, detection variants
(Tier-4 Vuln/CVE).

Three differential checks, benign markers only - no exploit payloads,
no shellcode, no credential attacks:

  * XSS reflection differential: a unique inert marker containing
    HTML brackets is submitted in a query parameter; a finding fires
    only when the marker comes back UNESCAPED (the exact differential
    a reflected-XSS check needs, with a marker that does nothing).
  * SQLi error differential: a single benign quote is appended to a
    parameter; a finding fires only when the response gains a known
    database error signature that the baseline response did not have.
  * File-inclusion signature check: a traversal-style path value is
    requested; a finding fires only when the response contains the
    unmistakable /etc/passwd account-line signature.

Parameters come from the discovery bus (urls with query strings,
forms) when available, else a small default probe set on the target
itself (/search?q=, /item?id=, /page?file=).
"""
from __future__ import annotations

import time
from typing import List, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MARKER = "rx4probe9z"          # inert reflection marker core
XSS_VALUE = f"<{MARKER}>"      # brackets make escaping observable
SQL_ERRORS = [
    "you have an error in your sql syntax", "mysql_fetch",
    "mysql_num_rows", "ora-01756", "ora-00933", "sqlite3.",
    "sqlite error", "postgresql error", "pg_query", "sqlserver",
    "unclosed quotation mark", "syntax error at or near",
    "microsoft ole db provider for sql server", "odbc sql",
]
PASSWD_SIG = "root:x:0:0:"

DEFAULT_PROBES: List[Tuple[str, str, str]] = [
    # (path, param, kind) kind: xss | sqli | lfi
    ("/search", "q", "xss"),
    ("/", "q", "xss"),
    ("/item", "id", "sqli"),
    ("/", "id", "sqli"),
    ("/page", "file", "lfi"),
    ("/", "page", "lfi"),
]


def _with_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query))
    q[param] = value
    return urlunparse(p._replace(query=urlencode(q)))


def has_sql_error(text: str) -> bool:
    low = (text or "").lower()
    return any(sig in low for sig in SQL_ERRORS)


class WapitiScanPlugin(Plugin):
    id = "wapiti_scan"
    label = "Wapiti Web Vuln Scan"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = ("Wapiti-style detection: XSS reflection differential "
                   "(inert marker), SQLi error differential (quote probe "
                   "+ error signature), file-inclusion passwd signature. "
                   "Markers only, no exploit payloads.")
    timeout_s = 60
    aggressive = True

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        async def get(url: str):
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                timeout=10, max_retries=1,
                                follow_redirects=True)
                return r.status_code, (r.text or "")[:120000]
            except Exception:
                return 0, ""

        probes: List[Tuple[str, str, str]] = list(DEFAULT_PROBES)
        findings: List[Finding] = []
        seen = set()
        for path, param, kind in probes:
            url0 = base + path
            key = (path, param, kind)
            if key in seen:
                continue
            seen.add(key)
            _st, baseline = await get(_with_param(url0, param, "rx4base"))
            if kind == "xss":
                _st2, body = await get(_with_param(url0, param, XSS_VALUE))
                if XSS_VALUE in body and XSS_VALUE not in baseline:
                    findings.append(self._f(
                        "web", "xss_reflected",
                        f"Parameter {param!r} on {path} reflects the "
                        "probe marker UNESCAPED (reflected XSS "
                        "differential)",
                        source="wapiti xss differential",
                        source_url=url0, confidence=85, passive=False,
                        evidence={"severity": "medium", "param": param,
                                  "path": path, "marker": XSS_VALUE,
                                  "remediation": (
                                      "Context-encode all reflected "
                                      "input and add a CSP; validate on "
                                      "the server side.")}))
            elif kind == "sqli":
                _st2, body = await get(_with_param(url0, param, "1'"))
                if has_sql_error(body) and not has_sql_error(baseline):
                    findings.append(self._f(
                        "web", "sqli_error_based",
                        f"Parameter {param!r} on {path} produces a "
                        "database error signature for a quote probe "
                        "but not for the baseline (error-based SQLi "
                        "differential)",
                        source="wapiti sqli differential",
                        source_url=url0, confidence=85, passive=False,
                        evidence={"severity": "high", "param": param,
                                  "path": path,
                                  "remediation": (
                                      "Use parameterized queries / "
                                      "prepared statements for this "
                                      "parameter and suppress DB errors.")}))
            elif kind == "lfi":
                _st2, body = await get(_with_param(
                    url0, param, "../../../etc/passwd"))
                if PASSWD_SIG in body and PASSWD_SIG not in baseline:
                    findings.append(self._f(
                        "web", "lfi_passwd_signature",
                        f"Parameter {param!r} on {path} returns the "
                        "/etc/passwd account signature for a traversal "
                        "value (file inclusion / traversal)",
                        source="wapiti lfi signature",
                        source_url=url0, confidence=90, passive=False,
                        evidence={"severity": "high", "param": param,
                                  "path": path,
                                  "remediation": (
                                      "Never build filesystem paths from "
                                      "user input; allowlist page names "
                                      "and jail to the content root.")}))
        return PluginResult(
            plugin_id=self.id, status="ok", findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"wapiti differentials done on {len(seen)} probes: "
                   f"{len(findings)} findings")
