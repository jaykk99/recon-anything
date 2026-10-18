"""Prototype pollution detection plugin.

Two angles, detection only:
1. Static: checks JavaScript library versions (from the discovery bus and
   page content) against known prototype-pollution-vulnerable ranges
   (lodash <4.17.21, jQuery <3.4.0, backbone <1.5.0, handlebars <4.7.7,
   merge-deep / deepmerge variants).
2. Dynamic: appends safe pollution patterns (?__proto__[reconTest]=1)
   to a URL and reports if the marker string is reflected in the
   response - evidence of unsanitized input handling. No exploitation:
   the payload does nothing harmful and is never executed server-side.
"""
from __future__ import annotations

import re
import time
from typing import List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (library, vulnerable-if-below, CVE/reference note)
VULN_LIBS: List[Tuple[str, str, str]] = [
    ("lodash", "4.17.21", "CVE-2020-8203 / CVE-2021-23337"),
    ("jquery", "3.4.0", "CVE-2019-11358"),
    ("backbone", "1.5.0", "CVE-2021-27601 (models/collections merge)"),
    ("handlebars", "4.7.7", "CVE-2021-20922 / CVE-2021-41184"),
    ("underscore", "1.13.0", "prototype pollution in extend/template"),
    ("deepmerge", "4.2.2", "CVE-2021-27290"),
    ("merge-deep", "3.0.1", "CVE-2019-10784"),
    ("defaults-deep", "0.2.4", "CVE-2020-15366"),
]

LIB_PATTERNS = [
    re.compile(r"(lodash)[\.-](\d+\.\d+\.\d+)", re.I),
    re.compile(r"(jquery)[\.-](\d+\.\d+\.\d+)", re.I),
    re.compile(r"(backbone)[\.-](\d+\.\d+\.\d+)", re.I),
    re.compile(r"(handlebars)[\.-](\d+\.\d+\.\d+)", re.I),
    re.compile(r"(underscore)[\.-](\d+\.\d+\.\d+)", re.I),
    re.compile(r"(deepmerge)[\.-](\d+\.\d+\.\d+)", re.I),
    re.compile(r"(merge-deep)[\.-](\d+\.\d+\.\d+)", re.I),
    re.compile(r"(defaults-deep)[\.-](\d+\.\d+\.\d+)", re.I),
    re.compile(r"lodash[:=]\s*['\"](\d+\.\d+\.\d+)", re.I),  # lodash: '4.17.20'
]

SAFE_PATTERNS = [
    "?__proto__[reconProbe]=reconProbeValue",
    "?__proto__.reconProbe=reconProbeValue",
    "?constructor[prototype][reconProbe]=reconProbeValue",
]

MARKERS = ["reconProbeValue", "reconProbe"]


def _parse_ver(s: str) -> Optional[Tuple[int, int, int]]:
    try:
        parts = [int(x) for x in re.findall(r"\d+", s)[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])  # type: ignore[return-value]
    except Exception:
        return None


class ProtoPollutionPlugin(Plugin):
    id = "proto_pollution"
    label = "Prototype Pollution Detector"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Checks JS library versions for known prototype-pollution "
                   "CVEs and tests for safe pollution-marker reflection.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")

        findings: List[Finding] = []
        seen_libs = set()

        async def fetch_text(url: str) -> str:
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10,
                                max_retries=1, follow_redirects=True)
                return r.text[:300000]
            except Exception:
                return ""

        # --- 1. Library version checks -------------------------------------
        sources: List[str] = []
        home = await fetch_text(base + "/")
        if home:
            sources.append(home)
        for js_url in ctx.consume("js_files")[:12]:
            txt = await fetch_text(js_url if js_url.startswith("http") else base + js_url)
            if txt:
                sources.append(txt)

        for src in sources:
            for pat in LIB_PATTERNS:
                for m in pat.finditer(src):
                    groups = m.groups()
                    name = groups[0].lower() if len(groups) == 2 else None
                    ver = groups[-1]
                    if name is None:  # lodash:'x.y.z' pattern
                        name, ver = "lodash", groups[0]
                    key = f"{name}:{ver}"
                    if key in seen_libs:
                        continue
                    seen_libs.add(key)
                    for lib, below, cve in VULN_LIBS:
                        if lib != name:
                            continue
                        v_parsed = _parse_ver(ver)
                        below_parsed = _parse_ver(below)
                        if v_parsed and below_parsed and v_parsed < below_parsed:
                            findings.append(self._f(
                                "web", f"proto_pollution_{lib}",
                                f"Vulnerable {name} {ver} in use (fixed in {below}; "
                                f"{cve}) - prototype pollution possible",
                                source="Prototype pollution detector",
                                source_url=base + "/",
                                confidence=80, passive=True,
                                evidence={"severity": "medium",
                                          "exploitability": "public_poc",
                                          "remediation": f"Upgrade {name} to "
                                          f"{below} or newer, or pin a fixed "
                                          "version, then re-scan."}))
                        elif v_parsed:
                            findings.append(self._f(
                                "web", f"proto_pollution_{lib}_ok",
                                f"{name} {ver} is at or above the safe version "
                                f"({below}) for prototype pollution",
                                source="Prototype pollution detector",
                                source_url=base + "/",
                                confidence=70, passive=True,
                                evidence={"severity": "low",
                                          "exploitability": "unknown",
                                          "remediation": "No action needed."}))

        # --- 2. Safe reflection probes --------------------------------------
        for pattern in SAFE_PATTERNS:
            url = base + "/" + pattern
            txt = await fetch_text(url)
            if not txt:
                continue
            reflected = [m for m in MARKERS if m in txt]
            if reflected:
                findings.append(self._f(
                    "web", "proto_pollution_reflection",
                    f"Pollution marker '{reflected[0]}' reflected in response "
                    f"body for pattern {pattern} - input flows into page "
                    "content without full sanitization (pollution vector "
                    "candidate)",
                    source="Prototype pollution detector", source_url=url,
                    confidence=65, passive=False,
                    evidence={"severity": "medium",
                              "exploitability": "theoretical",
                              "remediation": "Validate and sanitize all URL "
                              "parameters; block __proto__/constructor keys "
                              "before merging user input; use safe merge "
                              "helpers."}))
                break  # one reflection finding is enough; probes are harmless

        if not findings:
            findings.append(self._f(
                "web", "proto_pollution_clean",
                "No vulnerable JS library versions and no pollution-marker "
                "reflection detected",
                source="Prototype pollution detector", source_url=base,
                confidence=70, passive=True,
                evidence={"severity": "low", "exploitability": "unknown",
                          "remediation": "No action needed."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(seen_libs)} JS libs + "
                                 f"{len(SAFE_PATTERNS)} reflection probes")
        res.duration_ms = dur
        return res
