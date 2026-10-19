"""Finding deduplicator: filter duplicates across plugins and runs.

Problems it solves:
1. Multiple plugins flag the same issue (e.g. both headers.py and
   misconfig_sweep.py report a missing header) -> keep the best one.
2. Repeat scans re-report the same finding -> suppress if unchanged
   since last scan (uses the dedup cache).
3. Same finding with slightly different text -> fuzzy match on
   (vuln class, normalized value).

Smart detection additions:
4. Cross-plugin merge: the same CVE reported by cves.py ("cve_match")
   and js_retire.py ("vuln_js_library") becomes ONE finding with merged
   evidence. The same exposed secret reported by secrets.py and
   gitleaks_scan.py becomes ONE finding.
5. Corroboration boost: when 2+ INDEPENDENT plugins flag the same
   underlying issue (same URL + same vuln class), confidence +15
   (capped at 95) - two detectors agreeing is stronger than one.
6. Contradiction penalty: when plugins disagree about the same asset
   (e.g. one says a port is open, another says it is filtered),
   confidence is lowered and the conflict is flagged for manual review.

How it works: consumes finding dicts from the "poc_findings" bus
(published by the runner as each plugin finishes), groups by
(vuln_class, identity), merges evidence, adjusts confidence, checks the
dedup cache for previously-reported groups, and re-publishes the unique
findings to "deduped_findings".

Emits: a summary finding with dedup stats.

Pure logic - no network calls. Keyless.
Phase 2 chain plugin: runs after all discovery.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
PORT_RE = re.compile(r"\bport\s+(\d{1,5})\b", re.I)


def _canonical(value: str) -> str:
    """Normalize a finding value for fuzzy comparison."""
    v = value.lower()
    v = re.sub(r"https?://[^\s]+", "URL", v)       # URLs -> placeholder
    v = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "IP", v)  # IPs -> placeholder
    v = re.sub(r":\d{2,5}\b", ":PORT", v)          # ports -> placeholder
    v = re.sub(r"\s+", " ", v).strip()
    return v[:300]


# ---------------------------------------------------------------------------
# Vuln classes: finding keys from different plugins that describe the SAME
# underlying issue. Two findings with the same (class, identity) are one
# finding, with merged evidence.
# ---------------------------------------------------------------------------

# key -> canonical vuln class
VULN_CLASS_MAP: Dict[str, str] = {
    # CVEs: cves.py version matching + js_retire.py library CVEs
    "cve_match": "cve",
    "vuln_js_library": "cve",
    "cve_osv": "cve",
    # Exposed secrets: secrets.py + gitleaks_scan.py + js_secrets.py
    "exposed_aws_key": "secret",
    "exposed_aws_secret": "secret",
    "exposed_github_token": "secret",
    "exposed_stripe_key": "secret",
    "exposed_generic_secret": "secret",
    "exposed_private_key": "secret",
    "hardcoded_password": "secret",
    "aws_secret_hint": "secret",
    "azure_client_secret": "secret",
    "stripe_secret": "secret",
    "gitleaks_scan": "secret",
    "js_secret": "secret",
    "sourcemap_secret": "secret",
    "wallet_private_key": "secret",
    # Source maps: sourcemap.py + jsdeep.py
    "sourcemap_exposed": "sourcemap",
    "source_map": "sourcemap",
    # GraphQL endpoints: graphql.py + graphql_deep.py
    "graphql_endpoint": "graphql_endpoint",
    # Missing security headers: headers.py + misconfig_sweep.py
    "missing_security_header": "missing_header",
    "missing_header": "missing_header",
    # Open S3 buckets
    "s3_public_read": "s3_exposure",
    "s3_public_write": "s3_exposure",
    # Subdomain takeover
    "subdomain_takeover": "takeover",
    "takeover_candidate": "takeover",
}

# secret-kind hints used to build a stable secret identity
SECRET_KIND_RE = re.compile(
    r"(aws|github|stripe|azure|slack|discord|private key|password|api[_ ]?key|"
    r"token|secret|webhook|database|db_)",
    re.I)


def vuln_class(item: Dict[str, Any]) -> str:
    """Canonical vuln class for a finding dict (cross-plugin)."""
    key = str(item.get("key", ""))
    return VULN_CLASS_MAP.get(key, key)


def _identity(item: Dict[str, Any], vclass: str) -> str:
    """Stable identity within a vuln class.

    Two findings with the same (class, identity) are the same underlying
    issue even when reported by different plugins with different text.
    """
    ev = item.get("evidence") or {}
    value = str(item.get("value", ""))
    if vclass == "cve":
        cve = ev.get("cve") or ""
        if not cve:
            m = CVE_RE.search(value)
            cve = m.group(0).upper() if m else ""
        software = str(ev.get("software") or ev.get("library") or "").lower()
        return f"cve:{cve}:{software}"
    if vclass == "secret":
        kind = str(ev.get("secret_kind") or ev.get("kind") or "")
        if not kind:
            m = SECRET_KIND_RE.search(str(item.get("key", "")) + " " + value)
            kind = m.group(1).lower() if m else "generic"
        # identity = the secret token itself when visible: two plugins
        # flagging the same AKIA... token are the same finding even when
        # their wording differs. Fall back to a value-tail hash.
        token = ""
        m2 = re.search(r"[A-Za-z0-9_+/=\-]{16,}", value)
        if m2:
            token = m2.group(0)
        if not token:
            tail = _canonical(value)[-60:]
            token = "h:" + hashlib.sha256(tail.encode()).hexdigest()[:12]
        return f"secret:{kind}:{token}"
    if vclass == "sourcemap":
        url = str(item.get("source_url") or "")
        return f"sourcemap:{_canonical(url)}"
    if vclass == "graphql_endpoint":
        url = str(item.get("source_url") or value)
        return f"graphql:{_canonical(url)}"
    # default: class + canonical value (fuzzy within one key family)
    return f"{vclass}:{_canonical(value)}"


# ---------------------------------------------------------------------------
# Contradictions: plugins disagreeing about the same asset
# ---------------------------------------------------------------------------

# finding key -> asserted port state
PORT_STATE_KEYS: Dict[str, str] = {
    "port_open": "open",
    "web_port_open": "open",
    "port_closed": "closed",
    "port_filtered": "filtered",
}
CONTRADICTION_PENALTY = 20  # confidence points docked on conflict
CORROBORATION_BONUS = 15    # confidence points for 2+ plugins agreeing
CONFIDENCE_CAP = 95


def _port_identity(item: Dict[str, Any], domain: str) -> str:
    ev = item.get("evidence") or {}
    port = ev.get("port")
    if not port:
        m = PORT_RE.search(str(item.get("value", "")))
        port = m.group(1) if m else "?"
    return f"{domain}:{port}"


def _apply_contradictions(groups: Dict[str, Dict[str, Any]],
                           domain: str) -> int:
    """Lower confidence where plugins contradict each other.

    Currently: port state conflicts (open vs closed/filtered on the same
    host:port). Returns the number of findings penalized.
    """
    by_asset: Dict[str, List[str]] = {}
    for gid, g in groups.items():
        primary = g["primary"]
        state = PORT_STATE_KEYS.get(str(primary.get("key", "")))
        if not state:
            continue
        asset = _port_identity(primary, domain)
        by_asset.setdefault(asset, []).append(gid)

    penalized = 0
    for asset, gids in by_asset.items():
        states = {PORT_STATE_KEYS.get(str(groups[g]["primary"].get("key", "")))
                  for g in gids}
        if "open" in states and ("closed" in states or "filtered" in states):
            for gid in gids:
                g = groups[gid]
                p = g["primary"]
                old = int(p.get("confidence", 0) or 0)
                new = max(old - CONTRADICTION_PENALTY, 10)
                if new < old:
                    p["confidence"] = new
                    ev = p.setdefault("evidence", {})
                    ev["contradiction"] = (
                        f"plugins disagree about {asset}: one reports "
                        f"OPEN, another reports "
                        f"{'CLOSED' if 'closed' in states else 'FILTERED'} - "
                        f"verify manually before acting")
                    ev["contradicted"] = True
                    penalized += 1
    return penalized


class DedupPlugin(Plugin):
    id = "dedup"
    label = "Finding Deduplicator"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Remove duplicate findings across plugins and repeat "
                   "scans; merge cross-plugin evidence; boost corroborated "
                   "findings; flag contradictions.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        raw_findings = ctx.consume("poc_findings")
        if not raw_findings:
            return self._ok([], "no findings on bus to dedup")

        # Group by (vuln class, identity): cross-plugin smart dedup.
        # Same CVE from cves.py and js_retire.py -> one group.
        # Same secret from secrets.py and gitleaks_scan.py -> one group.
        groups: Dict[str, Dict[str, Any]] = {}
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            vclass = vuln_class(item)
            gid = _identity(item, vclass)
            g = groups.get(gid)
            if g is None:
                groups[gid] = {"primary": dict(item),
                               "vclass": vclass,
                               "plugins": {str(item.get("plugin_id", "?"))},
                               "members": [item]}
            else:
                g["members"].append(item)
                g["plugins"].add(str(item.get("plugin_id", "?")))
                # keep the highest-confidence instance as the primary
                conf = int(item.get("confidence", 0) or 0)
                if conf > int(g["primary"].get("confidence", 0) or 0):
                    g["primary"] = dict(item)

        suppressed_dup = len(raw_findings) - len(groups)
        corroborated = 0

        # Corroboration boost + evidence merge.
        for gid, g in groups.items():
            primary = g["primary"]
            plugins = sorted(g["plugins"])
            ev = primary.setdefault("evidence", {})
            if len(plugins) >= 2:
                # 2+ independent plugins, same issue -> stronger signal
                old = int(primary.get("confidence", 0) or 0)
                primary["confidence"] = min(old + CORROBORATION_BONUS,
                                            CONFIDENCE_CAP)
                ev["corroborated"] = True
                ev["corroborated_by"] = plugins
                corroborated += 1
            # merged evidence: every reporting plugin stays visible
            ev["merged_from"] = [
                {"plugin": str(m.get("plugin_id", "?")),
                 "source": str(m.get("source", "")),
                 "confidence": int(m.get("confidence", 0) or 0),
                 "value": str(m.get("value", ""))[:200]}
                for m in g["members"]
            ]
            ev["reporting_plugins"] = plugins

        # Contradiction penalty (e.g. port open vs filtered).
        contradicted = _apply_contradictions(groups, domain)

        # Check against previously reported (cross-run dedup)
        cache_key = (f"dedup:seen:"
                     f"{hashlib.sha256(domain.encode()).hexdigest()[:16]}")
        try:
            seen = set(ctx.cache.get("dedup", cache_key) or [])
        except Exception:
            seen = set()

        unique: List[Dict[str, Any]] = []
        suppressed_repeat = 0
        for gid, g in groups.items():
            if gid in seen:
                suppressed_repeat += 1
                continue
            unique.append(g["primary"])
            seen.add(gid)

        # Persist the seen set (cap at 5000 to bound cache size)
        try:
            ctx.cache.set("dedup", cache_key, sorted(seen)[-5000:],
                          ttl=86400 * 90)
        except Exception:
            pass

        # Re-publish unique findings for downstream consumers
        for item in unique:
            ctx.publish("deduped_findings", item)

        findings: List[Finding] = [self._f(
            "web", "dedup_summary",
            f"Dedup: {len(raw_findings)} raw -> {len(unique)} unique "
            f"({suppressed_dup} cross-plugin dups, {suppressed_repeat} "
            f"repeat-scan suppressions, {corroborated} corroborated "
            f"boosted, {contradicted} contradictions flagged).",
            source="Dedup", confidence=95,
            evidence={"severity": "low",
                      "remediation": "No action needed - this is pipeline "
                                     "hygiene. Review the unique findings.",
                      "raw_count": len(raw_findings),
                      "unique_count": len(unique),
                      "cross_plugin_dups": suppressed_dup,
                      "repeat_suppressions": suppressed_repeat,
                      "corroborated_boosted": corroborated,
                      "contradictions_flagged": contradicted})]

        reason = f"{len(raw_findings)} -> {len(unique)} unique findings"
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
