"""Finding-chaining layer: every finding feeds follow-up commands.

Separate from crypto: this is the generic map from a phase-1 finding to
the follow-up work that finding justifies, on the SAME run/target.

How chaining already worked before this layer: phase-2 plugins consume
the discovery bus (ctx.shared) that phase-1 plugins publish into
(subdomains, endpoints, js, contract_addresses, emails, ...). Examples
already in the tree: chain_osint and contract_audit consume
contract_addresses, endpointauth consumes endpoints, jsdeep consumes js,
graphql_deep consumes graphql_endpoints, email_breach/keyleak consume
emails. The chain was real but implicit: no single place listed it,
no dedupe/cap/depth policy, and no audit trail of what chained from
what.

This module makes it explicit and bounded:

- CHAIN_RULES: the whole map, keyed by finding-key prefix (for
  findings) and by bus kind (for bus items). Every followup_plugin id
  must exist in the plugin registry (enforced by test).
- plan_from_findings / plan_from_bus: pure functions. Given findings
  (or bus items), return a deduped, capped plan plus an audit list.
- Depth: MAX_CHAIN_DEPTH = 2. Depth 1 is a bus item (or finding) from
  phase 1. Depth 2 is one extra hop only: links actually present in
  a depth-1 probed page, on the same target, followed once. Nothing
  at depth 2 is followed further, and chain_followups publishes
  nothing back into the bus, so a chain cannot loop or fan out
  runaway. A scan therefore does not stop at pattern matches: a
  finding is confirmed by a real probe, and the probe's own links
  are followed one level deeper.
- Scope: only the scanned target. plan_from_bus drops any item whose
  host is not the target domain or one of its subdomains, and any
  absolute URL on another host. crypto.com (apex or subdomain) is
  refused outright, matching the standing never-a-target rule.
  Followed links must actually appear in a probed page's text:
  paths are never guessed, never brute-forced, and no login, auth
  bypass, or credential use is ever attempted.
- Secrets: an item that looks like a secret (64-hex private-key
  shape, WIF, or a secret-key finding) is never used as a probe
  input and never appears raw in a plan or audit entry. It is
  skipped with a masked value plus a SHA-256 fingerprint only.
  A scan that exposes no secret reports none, honestly: nothing
  here guarantees, invents, or requires a secret finding.
- Rate limiting: the executing plugin (chain_followups) runs its
  probes sequentially through ctx.probe, which caches and single-
  flights per URL, and caps total probes at MAX_CHAIN_PROBES.
- Audit: every planned, executed, delegated, and skipped item gets
  an audit entry {source, item, followup_plugin, command, depth,
  status, reason}. The plugin writes the audit into ctx.shared
  ["chain_audit"] and into each chain_plan finding's evidence.

What this layer does NOT do:
- It never expands to a new unauthorized target, never confirms an
  exploit, never performs a takeover step, never brute-forces, never
  bypasses auth, and never signs or sends anything on-chain. A rule
  whose followup would need any of those is not a rule here.
- Delegated rules (contract_audit, chain_osint, ...) are plan-only
  from this layer: those plugins run in their own phase-2 slot and
  this layer must not duplicate their network calls. Only the
  same-target web probes (subdomain liveness, endpoint status) are
  executed by chain_followups itself, through the cached probe path.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

MAX_CHAIN_DEPTH = 2
MAX_CHAIN_ITEMS = 20
MAX_CHAIN_PROBES = 30
MAX_SUBLINKS_PER_ITEM = 5
BLOCKED_DOMAINS = ("crypto.com",)

# Secret shapes that must never be used as probe input or shown raw.
_SECRET_RES = (
    re.compile(r"0x[0-9a-fA-F]{64}\b"),          # raw private-key hex
    re.compile(r"\b[0-9a-fA-F]{64}\b"),          # bare 64-hex key
    re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"),  # WIF
)
_SECRET_KEY_RE = re.compile(r"secret|private_key|privkey|mnemonic|seed_phrase")


def looks_like_secret(value: str) -> bool:
    return any(rx.search(value or "") for rx in _SECRET_RES)


def mask_secret(value: str) -> str:
    """Masked value + fingerprint only, never the raw secret."""
    s = (value or "").strip()
    fp = hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()[:12]
    if len(s) <= 8:
        return f"***:sha256:{fp}"
    return f"{s[:4]}...{s[-4:]}:sha256:{fp}"


def _norm_host(value: str) -> str:
    try:
        host = urlparse(value).netloc or value
        return host.split(":")[0].lower().strip()
    except Exception:
        return ""


def is_blocked_domain(domain: Optional[str]) -> bool:
    if not domain:
        return False
    d = domain.lower().strip()
    return d == "crypto.com" or d.endswith(".crypto.com")


def in_scope(item: str, target_domain: Optional[str]) -> bool:
    """True only for the target domain, its subdomains, or a relative path."""
    if not item or not target_domain:
        return False
    item = item.strip()
    if item.startswith("/"):
        return True  # relative path on the target host
    host = _norm_host(item) if "://" in item or "." in item else item.lower()
    if not host:
        return False
    td = target_domain.lower()
    return host == td or host.endswith("." + td)


# Each rule: finding-key prefixes it matches, bus kinds it matches,
# the followup plugin, and the command that followup represents.
# "consumes_bus" notes whether the followup plugin itself reads that
# bus kind (verified against the tree); otherwise the rule is a plan
# mapping and the followup runs from the target, not from the bus.
CHAIN_RULES: List[Dict[str, Any]] = [
    {"key_prefixes": ("subdomain",), "bus_kinds": ("subdomains",),
     "followup_plugin": "cmd_dns",
     "command": "dig {item}",
     "notes": "DNS probe for a discovered subdomain, same target only.",
     "consumes_bus": False},
    {"key_prefixes": ("subdomain",), "bus_kinds": ("subdomains",),
     "followup_plugin": "cmd_http",
     "command": "GET https://{item}/ (cached probe)",
     "notes": "Executed by chain_followups via ctx.probe when in scope.",
     "consumes_bus": False},
    {"key_prefixes": ("endpoint", "hidden_api", "api_route"),
     "bus_kinds": ("endpoints",),
     "followup_plugin": "endpointauth",
     "command": "endpointauth check on {item}",
     "notes": "Phase-2 plugin consumes the endpoints bus.",
     "consumes_bus": True},
    {"key_prefixes": ("endpoint", "hidden_api", "api_route"),
     "bus_kinds": ("endpoints",),
     "followup_plugin": "cmd_http",
     "command": "GET {item} (cached probe, confirms public exposure)",
     "notes": "Executed by chain_followups via ctx.probe; the probed "
              "page's same-target links are then followed once.",
     "consumes_bus": False},
    {"key_prefixes": ("js_", "sourcemap"), "bus_kinds": ("js",),
     "followup_plugin": "jsdeep",
     "command": "jsdeep analysis of {item}",
     "notes": "Phase-2 plugin consumes the js bus.",
     "consumes_bus": True},
    {"key_prefixes": ("js_", "sourcemap"), "bus_kinds": ("js",),
     "followup_plugin": "cmd_http",
     "command": "GET {item} (cached probe, confirms JS reachable)",
     "notes": "Executed by chain_followups via ctx.probe; links and "
              "config references inside the JS are followed once.",
     "consumes_bus": False},
    {"key_prefixes": ("token_contract", "nft_contract", "erc", "contract_",
                       "proxy_", "wallet_role"),
     "bus_kinds": ("contract_addresses",),
     "followup_plugin": "contract_audit",
     "command": "contract_audit on {item}",
     "notes": "Phase-2 plugin consumes contract_addresses; read-only audit.",
     "consumes_bus": True},
    {"key_prefixes": ("token_contract", "nft_contract", "erc", "contract_",
                       "wallet_", "btc_address", "eth_address", "ens_name"),
     "bus_kinds": ("contract_addresses",),
     "followup_plugin": "chain_osint",
     "command": "chain_osint enrichment of {item}",
     "notes": "Phase-2 plugin consumes contract_addresses; read-only.",
     "consumes_bus": True},
    {"key_prefixes": ("email",), "bus_kinds": ("emails",),
     "followup_plugin": "email_breach",
     "command": "email_breach check for {item}",
     "notes": "Phase-2 plugin consumes the emails bus; defensive only.",
     "consumes_bus": True},
    {"key_prefixes": ("email", "exposed_", "secret"), "bus_kinds": ("emails",),
     "followup_plugin": "keyleak",
     "command": "keyleak check for {item}",
     "notes": "Phase-2 plugin consumes the emails bus.",
     "consumes_bus": True},
    {"key_prefixes": ("graphql",), "bus_kinds": ("graphql_endpoints",),
     "followup_plugin": "graphql_deep",
     "command": "graphql_deep introspection of {item}",
     "notes": "Phase-2 plugin consumes graphql_endpoints.",
     "consumes_bus": True},
    {"key_prefixes": ("tech",), "bus_kinds": ("tech",),
     "followup_plugin": "appintel",
     "command": "appintel analysis of {item}",
     "notes": "Phase-2 plugin consumes the tech bus.",
     "consumes_bus": True},
]


def _dedupe_plan(plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for step in plan:
        k = (step["source"], step["item"], step["followup_plugin"])
        if k in seen:
            continue
        seen.add(k)
        out.append(step)
    return out[:MAX_CHAIN_ITEMS]


def _audit(source: str, item: Any, rule: Dict[str, Any], depth: int,
           status: str, reason: str = "") -> Dict[str, Any]:
    text = item if isinstance(item, str) else str(item)
    return {"source": source, "item": text[:200],
            "followup_plugin": rule["followup_plugin"],
            "command": rule["command"].format(item=text[:200]),
            "depth": depth, "status": status, "reason": reason}


def plan_from_findings(findings: List[Any], depth: int = 1) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Map finding objects/dicts to followup steps. Pure, no network."""
    if depth > MAX_CHAIN_DEPTH:
        return [], [{"source": "chain", "item": "", "followup_plugin": "",
                     "command": "", "depth": depth, "status": "skipped",
                     "reason": "depth limit exceeded"}]
    plan, audit = [], []
    for f in findings:
        key = f.get("key", "") if isinstance(f, dict) else getattr(f, "key", "")
        value = f.get("value", "") if isinstance(f, dict) else getattr(f, "value", "")
        if looks_like_secret(value) or _SECRET_KEY_RE.search(key):
            # Never use a found credential, never show it raw: masked
            # fingerprint only, and no followup step is created from it.
            audit.append({"source": key, "item": mask_secret(value),
                          "followup_plugin": "", "command": "",
                          "depth": depth, "status": "skipped_secret_masked",
                          "reason": "secret-shaped finding is never used"})
            continue
        for rule in CHAIN_RULES:
            if any(key.startswith(p) for p in rule["key_prefixes"]):
                step = {"source": key, "item": value,
                        "followup_plugin": rule["followup_plugin"],
                        "command": rule["command"].format(item=value),
                        "depth": depth, "notes": rule["notes"]}
                plan.append(step)
                audit.append(_audit(key, value, rule, depth, "planned"))
    return _dedupe_plan(plan), audit


def plan_from_bus(bus: Dict[str, List[Any]], target_domain: Optional[str],
                  depth: int = 1) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Map discovery-bus items to followup steps, scope-checked. Pure."""
    if is_blocked_domain(target_domain):
        return [], [{"source": "chain", "item": "", "followup_plugin": "",
                     "command": "", "depth": depth, "status": "skipped",
                     "reason": "blocked target domain"}]
    if depth > MAX_CHAIN_DEPTH:
        return [], [{"source": "chain", "item": "", "followup_plugin": "",
                     "command": "", "depth": depth, "status": "skipped",
                     "reason": "depth limit exceeded"}]
    plan, audit = [], []
    for rule in CHAIN_RULES:
        for kind in rule["bus_kinds"]:
            for raw in bus.get(kind, []) or []:
                item = raw.get("url") if isinstance(raw, dict) else raw
                if not isinstance(item, str) or not item:
                    continue
                if looks_like_secret(item):
                    audit.append({"source": kind,
                                  "item": mask_secret(item),
                                  "followup_plugin": "",
                                  "command": "", "depth": depth,
                                  "status": "skipped_secret_masked",
                                  "reason": "secret-shaped item is never used"})
                    continue
                if not in_scope(item, target_domain):
                    audit.append(_audit(kind, item, rule, depth,
                                        "skipped_out_of_scope",
                                        "item host is not the target"))
                    continue
                step = {"source": kind, "item": item,
                        "followup_plugin": rule["followup_plugin"],
                        "command": rule["command"].format(item=item),
                        "depth": depth, "notes": rule["notes"]}
                plan.append(step)
                audit.append(_audit(kind, item, rule, depth, "planned"))
    return _dedupe_plan(plan), audit
