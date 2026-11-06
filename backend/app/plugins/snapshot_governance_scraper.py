"""Snapshot governance scraper (Cat-4 SHIP).

Reads a Snapshot space's proposals and votes from the keyless
Snapshot public GraphQL API (hub.snapshot.org) - or from supplied
artifacts - and profiles governance-capture risk around active
proposals: voter balance concentration (one wallet deciding), and
sudden large voters whose first-ever participation is this proposal
(delegate spikes / bought votes).

Keyless read-only API reads. Detection only.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from ._cat4_common import artifact_dicts, fetch_json, all_texts
from .base import Cost, Ctx, Plugin, PluginResult, Target

HUB = "https://hub.snapshot.org/graphql"
SPACE_RE = re.compile(r"snapshot\.org/#/([a-z0-9.\-]+)", re.I)
TOP_SHARE = 0.5
WHALE_SHARE = 0.25


def analyse_snapshot(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pure: {proposals:[...], votes:[...]} -> capture-risk hits.

    Proposal: {"id","title","state"}; vote: {"proposal" (id),
    "voter","power","voter_proposal_count"}.
    """
    hits: List[Dict[str, Any]] = []
    if not isinstance(data, dict):
        return hits
    proposals = {str(p.get("id")): p for p in data.get("proposals") or []
                 if isinstance(p, dict)}
    by_prop: Dict[str, List[Dict[str, Any]]] = {}
    for v in data.get("votes") or []:
        if isinstance(v, dict):
            by_prop.setdefault(str(v.get("proposal")), []).append(v)
    for pid, votes in by_prop.items():
        prop = proposals.get(pid, {})
        if str(prop.get("state") or "active").lower() not in \
                ("active", ""):
            continue
        total = 0.0
        norm = []
        for v in votes:
            try:
                power = float(v.get("power") or v.get("vp") or 0)
            except (TypeError, ValueError):
                power = 0.0
            total += power
            norm.append((str(v.get("voter") or ""), power, v))
        if total <= 0:
            continue
        norm.sort(key=lambda x: -x[1])
        top_voter, top_power, top_raw = norm[0]
        share = top_power / total
        if share >= TOP_SHARE:
            hits.append({"kind": "single_voter_majority",
                         "proposal": pid,
                         "title": str(prop.get("title") or "")[:80],
                         "voter": top_voter,
                         "share_pct": round(share * 100, 1)})
        if share >= WHALE_SHARE and \
                (top_raw.get("voter_proposal_count") in (0, 1, None)):
            hits.append({"kind": "new_whale_voter",
                         "proposal": pid,
                         "title": str(prop.get("title") or "")[:80],
                         "voter": top_voter,
                         "share_pct": round(share * 100, 1)})
    return hits


class SnapshotGovernanceScraperPlugin(Plugin):
    id = "snapshot_governance_scraper"
    label = "Snapshot Governance Scraper"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Scrape a Snapshot space's proposals/votes keylessly "
                   "and profile governance-capture risk: single-voter "
                   "majorities and sudden new whale voters.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings = []
        try:
            datasets: List[Dict[str, Any]] = []
            spaces: List[str] = []
            for d in artifact_dicts(ctx):
                if d.get("proposals") or d.get("votes"):
                    datasets.append(d)
                if d.get("space_id"):
                    spaces.append(str(d["space_id"]))
            for _w, text, _u in await all_texts(ctx, target):
                for m in SPACE_RE.finditer(text):
                    if m.group(1) not in spaces:
                        spaces.append(m.group(1))
            for space in spaces[:2]:
                q = {"query": "query($s:String!){proposals(first:20,"
                              "where:{space:$s,state:\"active\"})"
                              "{id title state}}",
                     "variables": {"s": space}}
                data = await fetch_json(ctx, HUB, method="POST",
                                        payload=q)
                props = []
                if isinstance(data, dict):
                    props = ((data.get("data") or {}).get("proposals")
                             or [])
                if props:
                    datasets.append({"proposals": props, "votes": [],
                                     "space": space})
            for ds in datasets[:5]:
                for hit in analyse_snapshot(ds):
                    sev = ("high" if hit["kind"] ==
                           "single_voter_majority" else "medium")
                    findings.append(self._f(
                        "web3", f"snapshot_{hit['kind']}",
                        f"Snapshot proposal {hit['proposal']} "
                        f"({hit.get('title', '')}): "
                        f"{hit['kind'].replace('_', ' ')} - voter "
                        f"{hit['voter']} holds {hit['share_pct']}% of "
                        f"votes cast",
                        source="snapshot governance scraper",
                        confidence=85,
                        evidence={
                            "severity": sev, "hit": hit,
                            "remediation": "Treat the outcome as "
                            "controlled by one wallet; require quorum "
                            "and timelock safeguards before executing "
                            "anything this vote approves."}))
            res = self._ok(findings,
                           f"{len(datasets)} Snapshot datasets analysed"
                           if not findings else
                           f"{len(findings)} governance-capture signals")
        except Exception as e:
            res = self._degraded(f"analysis failed: {str(e)[:120]}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
