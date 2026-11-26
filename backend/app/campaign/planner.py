"""Planner: turn an objective plus the current graph into the next intents.

This is the ARTEX-shaped part of the engine: the plan is not a fixed
checklist, it is a pure function of what the campaign already knows.
Every round reads the graph, emits the highest-value untried actions,
and stops emitting once a fact has been attempted. Chained actions
(enumerate the exposed console you just found, crack the JWT you just
captured) are planned from evidence, which is what makes the loop
advance instead of repeat.

No I/O here. The planner returns intents; the engine decides whether
they are allowed to run.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import Intent, canon_target
from .scope import Scope

# ---------------------------------------------------------------------------
# Objective -> goal classes. Keyword matching is deliberately simple and
# visible: an operator can read why a campaign chose its probe set.
# ---------------------------------------------------------------------------
GOAL_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "secrets": ("secret", "credential", "leak", "git", ".env", "key",
                "token", "password", "source", "backup"),
    "access": ("auth", "access", "bypass", "idor", "bola", "admin",
               "console", "dashboard", "panel", "privilege", "takeover"),
    "injection": ("inject", "sqli", "sql", "xss", "ssti", "ssrf",
                  "traversal", "xxe", "crlf", "nosql", "ldap", "xpath"),
    "exposure": ("expos", "unauth", "open", "misconfig", "public",
                 "data", "leak", "elastic", "docker", "kubernetes",
                 "jenkins", "jupyter", "couchdb", "prometheus", "grafana"),
    "takeover": ("takeover", "dangling", "cname", "subdomain", "typosquat"),
    "recon": ("recon", "enumerat", "map", "surface", "fingerprint",
              "discover", "inventory"),
}

# Probe tiers, cheapest and highest-signal first. A probe not present in
# this table is still runnable directly; it is simply not auto-planned.
PROBE_TIERS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("exposure", (
        "docker-api", "k8s-api", "jupyter", "jenkins", "couchdb",
        "elasticsearch", "minio", "rabbitmq", "grafana", "prometheus",
    )),
    ("secrets", (
        "git-exposed", "env-secrets", "backup-files", "s3-open",
        "open-bucket",
    )),
    ("application", (
        "swagger", "graphql", "actuator-env", "phpinfo", "server-status",
        "debug-pprof", "admin-panels", "verbose-errors", "jwt-live",
        "cors", "clickjack", "cookie-flags", "http-methods",
    )),
    ("injection", (
        "sqli", "nosql-injection", "ldap-injection", "xpath-injection",
        "xss-reflected", "ssti", "ssrf", "dir-traversal", "crlf",
        "host-header", "open-redirect", "xxe", "idor", "bola",
        "auth-bypass",
    )),
)

_TIER_GOALS = {
    "exposure": ("exposure", "full", "access"),
    "secrets": ("secrets", "full", "exposure"),
    "application": ("access", "full", "exposure", "takeover", "secrets"),
    "injection": ("injection", "full"),
}

# Higher-value probes run before their tier peers.
PROBE_PRIORITY: Dict[str, int] = {
    "docker-api": 12, "k8s-api": 12, "jupyter": 13, "jenkins": 14,
    "couchdb": 15, "elasticsearch": 15, "minio": 16, "rabbitmq": 16,
    "grafana": 17, "prometheus": 17,
    "git-exposed": 18, "env-secrets": 19, "s3-open": 20,
    "backup-files": 21, "open-bucket": 22,
    "actuator-env": 24, "swagger": 25, "graphql": 25,
    "jwt-live": 26, "admin-panels": 27, "phpinfo": 28,
    "sqli": 32, "nosql-injection": 33, "ldap-injection": 33,
    "xpath-injection": 33, "ssrf": 34, "idor": 34, "bola": 34,
    "auth-bypass": 35, "xss-reflected": 36, "ssti": 36,
}

# A target gets at most this many probe intents per planning round, so
# each round's observations can shape the next round instead of firing
# the whole catalogue blind.
PROBES_PER_TARGET_PER_ROUND = 3
MAX_INTENTS_DEFAULT = 12

# Finding tag -> chained action. These are the "use what you found to
# find more" rules; each is a read-only follow-up, never a payload.
CONSOLE_ACTIONS = {
    "docker": "enumerate:docker", "k8s": "enumerate:k8s",
    "jupyter": "enumerate:jupyter",
    "jenkins": "enumerate:jenkins", "couchdb": "enumerate:couchdb",
    "elasticsearch": "enumerate:elasticsearch", "minio": "enumerate:minio",
    "rabbitmq": "enumerate:rabbitmq", "grafana": "enumerate:grafana",
    "prometheus": "enumerate:prometheus",
}


def goals_for(objective: str) -> List[str]:
    """Map a natural-language objective onto goal classes."""
    text = (objective or "").lower()
    goals: List[str] = []
    for goal, words in GOAL_KEYWORDS.items():
        if any(w in text for w in words):
            goals.append(goal)
    if not goals:
        goals = ["full"]
    # "exploit" implies the whole chain, not just one tier.
    if "exploit" in text or "full" in text or "everything" in text:
        if "full" not in goals:
            goals.append("full")
    # Deterministic order: full first, then the specific goals.
    goals = sorted(set(goals), key=lambda g: (g != "full", g))
    return goals


def selected_probes(goals: Sequence[str]) -> List[str]:
    """The probe set for these goals, in execution order."""
    goalset = set(goals)
    out: List[str] = []
    for tier, probes in PROBE_TIERS:
        if not (set(_TIER_GOALS[tier]) & goalset):
            continue
        for p in probes:
            if p not in out:
                out.append(p)
    out.sort(key=lambda p: PROBE_PRIORITY.get(p, 50))
    return out


def _base_url(target: str) -> str:
    t = (target or "").strip().rstrip("/")
    if not t:
        return ""
    return t if "://" in t else "https://" + t


def _attempted(graph, key: str) -> bool:
    return key in (graph.attempts or {})


def _http_targets(graph) -> List[str]:
    """Hosts and URLs worth probing, most specific first."""
    urls = [a["value"] for a in graph.assets_of("url")]
    hosts = [f"https://{a['value']}" for a in graph.assets_of("host")]
    ordered: List[str] = []
    for t in urls + hosts:
        if t and t not in ordered:
            ordered.append(t)
    return ordered


def _chain_intents(graph, pending: Set[str], attempted: Set[str]) -> List[Intent]:
    out: List[Intent] = []

    def _fresh(it: Intent) -> bool:
        return it.key not in pending and it.key not in attempted
    for f in graph.confirmed_findings():
        tags = set(f.get("tags") or [])
        target = f.get("target", "")
        if not target:
            continue
        meta = f.get("meta") or {}
        if "exposed_console" in tags:
            console = str(meta.get("console") or "").lower()
            action = CONSOLE_ACTIONS.get(console)
            if action:
                it = Intent(
                    kind="impact", action=action, target=target, goal="impact",
                    why=[f["id"]], requires_approval=True, cost=2,
                    priority=1,
                    meta={"console": console, "finding": f["id"]},
                )
                if _fresh(it):
                    out.append(it)
        if "object_storage" in tags:
            it = Intent(kind="verify", action="bucket-list", target=target,
                        goal="exposure", why=[f["id"]], cost=1, priority=3,
                        meta={"finding": f["id"]})
            if _fresh(it):
                out.append(it)
        if "auth" in tags and (meta.get("token") or meta.get("jwt")):
            it = Intent(kind="verify", action="jwt-forge", target=target,
                        goal="access", why=[f["id"]], cost=0, priority=2,
                        meta={"token": meta.get("token") or meta.get("jwt"),
                              "finding": f["id"]})
            if _fresh(it):
                out.append(it)
    return out


def next_intents(graph, scope: Scope, goals: Sequence[str], *,
                 limit: int = MAX_INTENTS_DEFAULT,
                 pending: Optional[Iterable[str]] = None) -> List[Intent]:
    """The next executable intents, best first.

    Denied intents are never returned: scope is a hard filter here and
    re-checked by the engine before execution.
    """
    pending_set = set(pending or ())
    attempted = graph.attempted_keys()
    intents: List[Intent] = []

    # 1. Chained actions from confirmed evidence.
    for it in _chain_intents(graph, pending_set, attempted):
        ok, _ = scope.allows_intent(it)
        if ok:
            intents.append(it)

    # 2. Surface each target once before probing it.
    needs_surface: Set[str] = set()
    for target in _http_targets(graph):
        base = _base_url(target)
        key = f"recon:surface:{canon_target(base)}"
        if key in attempted or key in pending_set:
            continue
        it = Intent(kind="recon", action="surface", target=base,
                    goal="recon", priority=10, cost=1)
        ok, _ = scope.allows_intent(it)
        if ok:
            intents.append(it)
        needs_surface.add(canon_target(base))

    # 3. Probes, only on targets whose surface is already known.
    probes = selected_probes(goals)
    per_target: Dict[str, int] = {}
    for target in _http_targets(graph):
        base = _base_url(target)
        if canon_target(base) in needs_surface:
            continue
        if not _attempted(graph, f"recon:surface:{canon_target(base)}"):
            continue
        for pid in probes:
            if per_target.get(base, 0) >= PROBES_PER_TARGET_PER_ROUND:
                break
            it = Intent(kind="probe", action=pid, target=base,
                        goal=_probe_goal(pid),
                        priority=PROBE_PRIORITY.get(pid, 50), cost=1)
            if it.key in attempted or it.key in pending_set:
                continue
            ok, _ = scope.allows_intent(it)
            if not ok:
                continue
            intents.append(it)
            per_target[base] = per_target.get(base, 0) + 1

    intents.sort(key=lambda i: (i.priority, i.target, i.action))
    # Chained impact work is expensive; never let a probe crowd it out.
    chain = [i for i in intents if i.kind == "impact"]
    rest = [i for i in intents if i.kind != "impact"]
    return (chain + rest)[:limit]


def _probe_goal(pid: str) -> str:
    for tier, probes in PROBE_TIERS:
        if pid in probes:
            return tier
    return "probe"


# ---------------------------------------------------------------------------
# Goal evaluation: when has the campaign proven enough to stop?
# ---------------------------------------------------------------------------
GOAL_TAGS: Dict[str, Set[str]] = {
    "secrets": {"secret", "exposed_data"},
    "access": {"auth_bypass", "exposed_console"},
    "injection": {"injection"},
    "exposure": {"exposed_console", "exposed_data", "secret",
                 "object_storage"},
    "takeover": {"takeover"},
    "recon": set(),
    "full": {"secret", "exposed_data", "auth_bypass", "exposed_console",
             "injection", "takeover"},
}

_SEV_OK = {"critical", "high"}


def goal_proven(goals: Sequence[str], graph) -> Dict[str, Any]:
    """Which goals are demonstrated, and by which finding ids.

    A goal is proven by evidence, never by attempt count: the finding
    must be confirmed and, for the full goal, at least high severity.
    """
    findings = graph.confirmed_findings()
    per_goal: Dict[str, Dict[str, Any]] = {}
    for goal in goals:
        if goal == "recon":
            assets = [a for a in graph.assets.values()
                      if a["type"] in ("http_service", "endpoint", "tech")]
            per_goal[goal] = {"proven": bool(assets),
                              "by": [a["id"] for a in assets[:5]]}
            continue
        tags = GOAL_TAGS.get(goal, set())
        hits = [f for f in findings if tags & set(f.get("tags") or [])]
        if goal == "full":
            strong = [f for f in hits if f.get("severity") in _SEV_OK]
            if strong:
                hits = strong
        per_goal[goal] = {"proven": bool(hits),
                          "by": [f["id"] for f in hits[:8]]}
    proven = all(v["proven"] for v in per_goal.values()) if per_goal else False
    return {"proven": proven, "per_goal": per_goal}


def next_actions(graph, scope: Scope, goals: Sequence[str],
                 limit: int = 5) -> List[Dict[str, Any]]:
    """What the engine would do next, for the report's handoff section."""
    return [i.to_dict() for i in
            next_intents(graph, scope, goals, limit=limit)]
