"""Plugin chaining: tech-triggered follow-up scans.

The runner executes plugins in two phases. Phase-1 plugins publish what
they discover onto the shared discovery bus (``ctx.publish`` /
``ctx.consume``). Between the phases the runner calls
:func:`evaluate_chains`, which matches bus signals against CHAIN_MAP and
publishes ``chain`` signals that phase-2 consumers act on.

CHAIN MAP
---------
1. cms_chain
   Trigger : tech_fingerprint or fingerprint detects a CMS
             (WordPress, Drupal, Joomla, Shopify, Magento, Ghost, TYPO3,
             PrestaShop, OpenCart) -> publishes ``tech`` / ``cms``.
   Consumer: cms_probes (phase 2). Runs that CMS's deep checks
             (readme.html, version disclosure, known-vuln paths) and
             boosts confidence when the chain hint is confirmed.

2. graphql_chain
   Trigger : graphql.py finds a live endpoint -> publishes
             ``graphql_endpoints``.
   Consumer: graphql_deep (phase 2). Full read-only schema enumeration,
             dangerous-operation name review, batching and GET-query
             probes. Never executes mutations.

3. sourcemap_chain
   Trigger : sourcemap.py recovers original sources from ``.map``
             files -> publishes them to ``js`` / ``recovered_sources``.
   Consumer: jsdeep (phase 2). Runs deep JS analysis over the
             recovered sources (endpoints, secrets, sinks).

4. api_chain
   Trigger : apidiscover.py finds API base paths -> publishes
             ``endpoints`` (API-looking paths also mirrored to
             ``api_base_paths``).
   Consumer: param_discovery (phase 2). Fuzzes hidden GET parameters on
             those base paths with inert canaries.

All chains are detection-only. A chain never sends an exploit; the
deepest any consumer goes is a read-only probe or an inert canary.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# ---------------------------------------------------------------------------
# Chain definitions
# ---------------------------------------------------------------------------

CMS_NAMES = (
    "wordpress", "drupal", "joomla", "shopify", "magento", "ghost",
    "typo3", "prestashop", "opencart", "squarespace", "wix",
)

# bus tech names (lowercase) -> canonical cms name
TECH_TO_CMS = {
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "shopify": "shopify",
    "magento": "magento",
    "ghost": "ghost",
    "typo3": "typo3",
    "prestashop": "prestashop",
    "opencart": "opencart",
    "squarespace": "squarespace",
    "wix": "wix",
}


@dataclass
class ChainDef:
    """One producer -> consumer chain."""
    id: str
    name: str
    producer: str        # plugin id that fires the trigger
    consumer: str        # plugin id that acts on the signal
    bus_kind: str        # discovery-bus bucket the trigger is read from
    signal_prefix: str   # "chain" signals look like "<prefix>:<detail>"
    trigger_desc: str    # human description of the trigger condition
    action_desc: str     # human description of what the consumer does
    detect: Callable[["ChainCtx", "ChainDef"], List[str]] = field(
        default=None, repr=False)  # returns signal details ("" = none)


class ChainCtx:
    """Tiny adapter so chains work on a real Ctx or a plain dict bus."""

    def __init__(self, ctx: Any):
        self._ctx = ctx

    def consume(self, kind: str) -> List[Any]:
        try:
            return list(self._ctx.consume(kind))
        except Exception:
            bus = getattr(self._ctx, "shared", None) or {}
            if isinstance(self._ctx, dict):
                bus = self._ctx
            return list(bus.get(kind, []) or [])

    def publish(self, kind: str, item: Any) -> None:
        try:
            self._ctx.publish(kind, item)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Detectors: bus signal -> chain signal details
# ---------------------------------------------------------------------------

def _detect_cms(bus: ChainCtx, chain: ChainDef) -> List[str]:
    found: List[str] = []
    seen = set()
    for bucket in ("cms", "tech"):
        for item in bus.consume(bucket):
            if not isinstance(item, str):
                continue
            low = item.lower()
            for tech, cms in TECH_TO_CMS.items():
                if tech in low and cms not in seen:
                    seen.add(cms)
                    found.append(cms)
    return found


def _looks_like_api_path(url: str) -> bool:
    low = url.lower()
    return any(seg in low for seg in (
        "/api/", "/api/v", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql",
        "/openapi", "/swagger"))


def _detect_api(bus: ChainCtx, chain: ChainDef) -> List[str]:
    found: List[str] = []
    seen = set()
    for item in bus.consume("endpoints"):
        if not isinstance(item, str) or not _looks_like_api_path(item):
            continue
        # keep the base path: scheme://host/<first api-ish segment>
        try:
            from urllib.parse import urlparse
            p = urlparse(item)
            segs = [s for s in p.path.split("/") if s]
            base = f"{p.scheme}://{p.netloc}"
            for i, s in enumerate(segs):
                if s in ("api", "v1", "v2", "v3", "rest", "graphql"):
                    end = i + 1
                    # keep a version segment too: /api/v1, /rest/v2
                    if end < len(segs) and re.fullmatch(r"v\d+",
                                                       segs[end], re.I):
                        end += 1
                    base += "/" + "/".join(segs[:end])
                    break
            else:
                base += "/" + segs[0] if segs else ""
        except Exception:
            base = item
        if base not in seen:
            seen.add(base)
            found.append(base)
    for item in bus.consume("api_base_paths"):
        if isinstance(item, str) and item not in seen:
            seen.add(item)
            found.append(item)
    return found


def _detect_graphql(bus: ChainCtx, chain: ChainDef) -> List[str]:
    found = []
    for item in bus.consume("graphql_endpoints"):
        if isinstance(item, str) and item not in found:
            found.append(item)
    return found


def _detect_sourcemap(bus: ChainCtx, chain: ChainDef) -> List[str]:
    found = []
    for item in bus.consume("recovered_sources"):
        if isinstance(item, str) and item not in found:
            found.append(item)
    # sourcemap.py also republishes recovered files onto "js" tagged so;
    # accept those too.
    for item in bus.consume("js"):
        if isinstance(item, dict) and item.get("recovered") \
                and isinstance(item.get("url"), str):
            if item["url"] not in found:
                found.append(item["url"])
    return found


CHAIN_MAP: Dict[str, ChainDef] = {
    "cms_chain": ChainDef(
        id="cms_chain",
        name="CMS deep probes",
        producer="tech_fingerprint",
        consumer="cms_probes",
        bus_kind="cms",
        signal_prefix="cms",
        trigger_desc=("tech_fingerprint/fingerprint publishes a CMS name "
                      "to the 'tech' or 'cms' bus bucket"),
        action_desc=("cms_probes runs that CMS's version-disclosure and "
                     "known-vuln checks; confidence +5 when the chain hint "
                     "is confirmed"),
        detect=_detect_cms,
    ),
    "graphql_chain": ChainDef(
        id="graphql_chain",
        name="GraphQL deep introspection",
        producer="graphql",
        consumer="graphql_deep",
        bus_kind="graphql_endpoints",
        signal_prefix="graphql",
        trigger_desc=("graphql.py finds a live GraphQL endpoint and "
                      "publishes its URL to 'graphql_endpoints'"),
        action_desc=("graphql_deep enumerates the schema read-only, "
                     "reviews dangerous operation names, and probes "
                     "batching / GET-query support. No mutations executed."),
        detect=_detect_graphql,
    ),
    "sourcemap_chain": ChainDef(
        id="sourcemap_chain",
        name="Recovered-source JS analysis",
        producer="sourcemap",
        consumer="jsdeep",
        bus_kind="recovered_sources",
        signal_prefix="recovered_js",
        trigger_desc=("sourcemap.py recovers original sources from .map "
                      "files and publishes them to 'recovered_sources' "
                      "(also mirrored onto 'js')"),
        action_desc=("jsdeep analyzes the recovered sources for endpoints, "
                     "secrets, and sinks"),
        detect=_detect_sourcemap,
    ),
    "api_chain": ChainDef(
        id="api_chain",
        name="API param discovery",
        producer="apidiscover",
        consumer="param_discovery",
        bus_kind="endpoints",
        signal_prefix="api_base",
        trigger_desc=("apidiscover.py publishes API base paths to "
                      "'endpoints' / 'api_base_paths'"),
        action_desc=("param_discovery (phase 2) fuzzes hidden GET "
                     "parameters on those base paths with inert canaries"),
        detect=_detect_api,
    ),
}


# ---------------------------------------------------------------------------
# Evaluation: called by the runner between phase 1 and phase 2
# ---------------------------------------------------------------------------

def detect_triggers(ctx: Any) -> List[Dict[str, Any]]:
    """Match the discovery bus against CHAIN_MAP.

    Returns a list of ``{"chain": id, "name": ..., "producer": ...,
    "consumer": ..., "signals": [details...]}`` for every chain whose
    trigger condition is met.
    """
    bus = ChainCtx(ctx)
    triggered: List[Dict[str, Any]] = []
    for chain_id, chain in CHAIN_MAP.items():
        try:
            details = chain.detect(bus, chain) if chain.detect else []
        except Exception:
            details = []
        if details:
            triggered.append({
                "chain": chain_id,
                "name": chain.name,
                "producer": chain.producer,
                "consumer": chain.consumer,
                "signals": details,
            })
    return triggered


def publish_signals(ctx: Any, triggers: List[Dict[str, Any]]) -> int:
    """Publish ``chain`` signals so phase-2 consumers can act on them.

    Signal format: ``"<signal_prefix>:<detail>"``, e.g.
    ``"cms:wordpress"``, ``"graphql:https://host/graphql"``,
    ``"api_base:https://host/api/v1"``,
    ``"recovered_js:https://host/static/app.js"``.
    Returns the number of signals published.
    """
    bus = ChainCtx(ctx)
    n = 0
    for t in triggers:
        chain = CHAIN_MAP.get(t.get("chain", ""))
        if not chain:
            continue
        for detail in t.get("signals", []):
            bus.publish("chain", f"{chain.signal_prefix}:{detail}")
            n += 1
    return n


def chain_signals(ctx: Any, prefix: str) -> List[str]:
    """Consumer helper: details of chain signals with a given prefix."""
    bus = ChainCtx(ctx)
    out = []
    for item in bus.consume("chain"):
        if isinstance(item, str) and item.startswith(prefix + ":"):
            out.append(item.split(":", 1)[1])
    return out


def evaluate_chains(ctx: Any) -> List[Dict[str, Any]]:
    """Full chain pass for the runner: detect triggers, publish signals.

    Call once after phase 1 (and it is safe to call again after phase 2
    for chains whose producers are phase-2, e.g. sourcemap_chain).
    Returns the triggered chains so the runner can log/emit them.
    """
    triggers = detect_triggers(ctx)
    if triggers:
        publish_signals(ctx, triggers)
    return triggers


def describe() -> List[Dict[str, str]]:
    """Human-readable chain map (for docs / API)."""
    return [{
        "id": c.id,
        "name": c.name,
        "trigger": f"{c.producer}: {c.trigger_desc}",
        "action": f"{c.consumer}: {c.action_desc}",
    } for c in CHAIN_MAP.values()]
