"""SQL injection error-based detector (Milestone: critical findings).

Non-destructive: appends a single quote to discovered query parameters
and looks for database error strings in the response. No data
extraction, no stacked queries, no time-based payloads. One probe per
parameter. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

SQL_ERRORS = [
    (r"SQL syntax.*?MySQL", "MySQL"),
    (r"Warning.*mysql_.*", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"MySqlClient\.", "MySQL"),
    (r"PostgreSQL.*?ERROR|ERROR.*?PostgreSQL|pg_query\(\).*?ERROR", "PostgreSQL"),
    (r"Warning.*\Wpg_.*", "PostgreSQL"),
    (r"valid PostgreSQL result", "PostgreSQL"),
    (r"Driver.*? SQL[\-\_\ ]*Server", "MSSQL"),
    (r"OLE DB.*? SQL Server", "MSSQL"),
    (r"SQLServer JDBC Driver", "MSSQL"),
    (r"ORA-[0-9]{5}", "Oracle"),
    (r"Oracle error", "Oracle"),
    (r"SQLite3::", "SQLite"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"Microsoft Access Driver", "MS Access"),
    (r"ODBC Driver", "ODBC"),
]

REMEDIATION = ("Use parameterized queries / prepared statements everywhere. "
               "Never build SQL by string concatenation. Apply least-privilege "
               "DB accounts and hide error details in production.")


class SqliPlugin(Plugin):
    id = "sqli"
    label = "SQLi Probe"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "Error-based SQLi check: single-quote probe per query param."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends probe requests)")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []

        # discover URLs with query params from the homepage
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:300000]
            page_url = str(r.url)
        except Exception as e:
            res = self._error(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        urls = set()
        for m in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', html, re.I):
            u = m.group(1)
            if u.startswith("/"):
                p = urlparse(page_url)
                u = f"{p.scheme}://{p.netloc}{u}"
            if domain in urlparse(u).netloc:
                urls.add(u)
        # also forms
        for m in re.finditer(r'<form[^>]+action=["\']([^"\']*)["\']', html, re.I):
            a = m.group(1) or page_url
            if a.startswith("/"):
                p = urlparse(page_url)
                a = f"{p.scheme}://{p.netloc}{a}"
            if "?" in a and domain in urlparse(a).netloc:
                urls.add(a)

        tested = 0
        for u in list(urls)[:10]:
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            for name, val in params[:3]:
                tested += 1
                probe = [(n, (v + "'") if n == name else v) for n, v in params]
                purl = urlunparse(parts._replace(query=urlencode(probe)))
                try:
                    pr = await fetch(ctx.http, ctx.limiter, "GET", purl, timeout=15)
                    body = pr.text[:200000]
                except Exception:
                    continue
                for pat, db in SQL_ERRORS:
                    if re.search(pat, body, re.I | re.S):
                        findings.append(self._f(
                            "leak", "sqli_error_based",
                            f"CRITICAL: possible SQL injection in parameter '{name}' "
                            f"({db} error leaked) at {parts.path or '/'}",
                            source="sqli probe", source_url=purl,
                            confidence=85, passive=False,
                            evidence={"severity": "critical",
                                      "parameter": name,
                                      "database": db,
                                      "remediation": REMEDIATION,
                                      "scope_note": "Authorized testing only. Do not exploit beyond this detection."}))
                        break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"probed {tested} params across {len(urls)} URLs, "
                                 f"{len(findings)} SQLi signals")
        res.duration_ms = dur
        return res
