"""Scan-time priority tiers for the scan budget (600s since 2026-10-20).

A full scan has a HARD 600s ceiling (was 80s, which cut most plugins and
made findings differ every run - Jay's order 2026-10-20: find more). The
runner dispatches plugins in
priority order and, as the budget runs out, stops starting new low-priority
plugins (they are recorded as ok(0) with a "skipped: time budget" note -
never an error, never a hang).

Tiers:
  HIGH (1) - direct vulnerability / exposure signal. These run first and are
             the last to be cut. Named by Jay: cves, leaks, exposures, vulns.
  MEDIUM (2) - default. Solid recon, runs after HIGH.
  LOW (3)  - slow enumeration with lower per-finding signal (subdomain brute
             force, wayback, deep crawls, crypto-adjacent scans). Runs last,
             cut first when the budget runs out.

Findings always win over speed: a cut plugin is never silently dropped, it
gets an explicit "skipped: time budget" note in its result reason.
"""
from __future__ import annotations

HIGH = 1
MEDIUM = 2
LOW = 3

# Direct vuln probes + exposure/leak finders: run first, cut last.
HIGH_PRIORITY = {
    "cves",
    "sqli", "nosqli", "xss", "ssrf", "ssti", "rce", "cmdi",
    "idor", "bola", "xpathi", "htmli", "logici", "traversal",
    "leaks", "secrets", "keyleak", "creds", "email_exposure",
    "email_breach", "opendir", "git", "backup", "cloud_buckets", "s3",
    "takeover", "infodisclosure", "auth", "auth_surface", "cors",
    "clickjack", "tls", "headers", "dns", "waf", "email_infra",
}

# Slow, low-signal enumeration: runs last, cut first on a tight budget.
# Includes the empirically slow plugins (timeouts/hangs seen 2026-10-18:
# bounty, docker, cloud_buckets, backup, artifacts, emails, enterprise,
# exif, favicon_hash, financial) and the brute-force/deep-crawl class.
LOW_PRIORITY = {
    "subdomains", "wayback", "connections", "deepcrawl", "crawler",
    "social", "usernames", "phones", "pastes", "dorks", "bounty",
    "emails", "exif", "favicon_hash", "enterprise", "financial",
    "mobile", "docker", "hypervisor", "k8s", "iot", "supplychain",
    "giftcards", "giftinfra", "nft", "defi", "rugpull", "bridge",
    "tokenapproval", "walletcheck", "wallets", "crypto", "cryptoconfig",
    "smartcontract", "cards", "credential_strength", "hashid",
    "asn_scan", "rdap", "pivots", "registry", "cloud", "ldapi",
    # Native crawler/enumerator tools: heavy by nature, run last so
    # findings lead and enumeration trails. (Jay's order 2026-10-18.)
    "katana", "hakrawler", "wget", "httrack", "gobuster", "feroxbuster",
    "gau", "waybackurls", "stealth_crawler", "threat_monitor",
    "subdomain_brute", "port_scan", "port_audit",
    # Full-app extraction plugins: heavy by nature, run last so findings
    # lead and enumeration trails. (Jay's order 2026-10-18.)
    "allsources", "assetmap", "filehunter", "jsdeep",
}


# Bounty mode (Jay's order 2026-10-19): high-impact vuln classes run FIRST.
# These find the big stuff - RCE/SQLi/SSTI/SSRF/XXE/auth/IDOR/secrets.
BOUNTY_BOOST = {
    "sqli", "nosqli", "ssti", "ssrf", "rce", "cmdi", "xxe", "xpathi",
    "idor", "bola", "idor_comparator", "auth", "auth_surface", "authscan",
    "traversal", "logici", "deserialization",
    "js_secrets", "secrets", "keyleak", "gitleaks_scan", "creds",
    "graphql", "graphql_deep", "apidiscover", "param_discovery",
    "endpointauth", "forms", "jsdeep",
}


def priority_for(plugin_id: str, bounty: bool = False) -> int:
    """1 = HIGH (run first), 2 = MEDIUM (default), 3 = LOW (run last).

    In bounty mode, high-impact vuln classes jump the queue.
    """
    if bounty and plugin_id in BOUNTY_BOOST:
        return HIGH
    if plugin_id in HIGH_PRIORITY:
        return HIGH
    if plugin_id in LOW_PRIORITY:
        return LOW
    return MEDIUM


def tier_name(tier: int) -> str:
    return {HIGH: "high", MEDIUM: "medium", LOW: "low"}.get(tier, "medium")
