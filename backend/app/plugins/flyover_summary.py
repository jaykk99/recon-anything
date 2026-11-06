"""Flyover attack-surface summary (Tier-5 orchestration).

A flyover is the 30,000-foot pass before anyone dives: how big is
this surface, what classes of asset dominate it, what are the top
exposures, and what changed since the last run? It is a reporting /
aggregation plugin - it probes nothing, verifies nothing, and
invents nothing; it ranks and summarises what the run's discovery
plugins already found.

Inputs are the discovery bus (subdomains, IPs, ports, endpoints,
tech, JS files, emails, cert SANs) plus, when a caller provides it,
the previous run's counts (ctx.shared["flyover_previous_counts"])
for change reporting. Endpoints are ranked by surface shape
(admin / .env / .git / backup / config / debug / internal / api /
params) into a top-exposures list; counts are reported per asset
class; deltas vs the previous run are reported per class and as a
dedicated change finding when anything moved.

Distinct from lifecycle_orchestrator (PR #118): that plugin probes
its top candidates live and emits per-target priority findings with
remediation. Flyover never probes and never grades individual
targets - it is the aggregate briefing layer above the whole run.
Silent when the bus is (nearly) empty: fewer than three discovered
assets means there is no surface to summarise.
"""
from __future__ import annotations

import time
from typing import Dict, List, Tuple

from ..classifier import domain_from_target
from ._orchestration import consume, shared_get
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

CLASSES = {
    "subdomains": "subdomains", "ips": "ips", "ports": "ports",
    "endpoints": "endpoints", "tech": "tech", "js_files": "js_files",
    "emails": "emails", "cert_sans": "cert_sans", "urls": "urls",
}

SCORE_HINTS = [(".env", 9), (".git", 9), ("backup", 7), ("config", 7),
               ("admin", 6), ("debug", 6), ("internal", 6),
               ("actuator", 6), ("upload", 5), ("api", 3),
               ("login", 3), ("graphql", 4), ("swagger", 4)]


def _score(url: str) -> Tuple[int, str]:
    low = (url or "").lower()
    score, why = 0, ""
    for hint, pts in SCORE_HINTS:
        if hint in low and pts > score:
            score, why = pts, hint
    if "?" in low and "=" in low:
        score += 2
        why = why or "parameterised"
    return score, why


class FlyoverSurfaceSummaryPlugin(Plugin):
    id = "flyover_surface_summary"
    label = "Flyover Surface Summary"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    phase = 2
    timeout_s = 30
    description = ("Aggregates discovery outputs into a ranked "
                   "attack-surface overview: counts by class, top "
                   "exposures, and change since the last run.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        counts: Dict[str, int] = {}
        assets: Dict[str, List[str]] = {}
        for kind in CLASSES:
            values = [v for v in consume(ctx, kind)
                      if isinstance(v, str) and v.strip()]
            assets[kind] = values
            counts[kind] = len(values)
        total = sum(counts.values())
        if total < 3:
            return self._ok([], f"flyover: only {total} assets on the "
                                f"bus, nothing to summarise")
        ranked: List[Tuple[int, str, str]] = []
        seen = set()
        for url in assets.get("endpoints", []) + assets.get("urls", []):
            if url in seen:
                continue
            seen.add(url)
            score, why = _score(url)
            if score >= 5:
                ranked.append((score, why, url))
        ranked.sort(key=lambda item: -item[0])

        previous = shared_get(ctx, "flyover_previous_counts")
        deltas: Dict[str, int] = {}
        if isinstance(previous, dict):
            for kind in CLASSES:
                try:
                    deltas[kind] = counts[kind] - int(previous.get(kind)
                                                      or 0)
                except Exception:
                    continue
        findings: List[Finding] = []
        for score, why, url in ranked[:10]:
            findings.append(self._f(
                "graph", "top_exposure",
                f"Top exposure ({score}/10, {why}): {url}",
                source="flyover_surface_summary", source_url=url,
                confidence=75,
                evidence={"severity": "high" if score >= 7 else "medium",
                          "score": score, "signal": why, "url": url,
                          "remediation": "Review this exposure first "
                                         "in the detailed findings; "
                                         "the flyover ranks shape, the "
                                         "owning plugin confirms it."}))
        changed = {k: v for k, v in deltas.items() if v}
        if changed:
            findings.append(self._f(
                "graph", "surface_change",
                f"Surface change since last run for {domain}: "
                + ", ".join(f"{k} {v:+d}" for k, v in
                            sorted(changed.items())),
                source="flyover_surface_summary", confidence=85,
                evidence={"severity": "medium", "deltas": deltas,
                          "current_counts": counts,
                          "remediation": "Growth in subdomains, IPs "
                                         "or endpoints between runs is "
                                         "new surface: make sure it "
                                         "was an intended change."}))
        top_str = ranked[0][2] if ranked else "none scored"
        findings.append(self._f(
            "graph", "flyover_summary",
            f"Flyover for {domain}: {total} assets "
            f"({', '.join(f'{k}={v}' for k, v in counts.items() if v)}); "
            f"{len(ranked)} ranked exposures, top: {top_str}",
            source="flyover_surface_summary", confidence=90,
            evidence={"severity": "low", "counts": counts,
                      "total_assets": total,
                      "ranked_exposures": [
                          {"score": s, "signal": w, "url": u}
                          for s, w, u in ranked[:10]],
                      "deltas": deltas,
                      "remediation": "Start from the ranked exposures, "
                                     "then work class by class; the "
                                     "flyover is a briefing, not a "
                                     "verdict - confirm in the owning "
                                     "plugins' findings."}))
        res = self._ok(findings, f"flyover: {total} assets, "
                                 f"{len(ranked)} ranked exposures")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
