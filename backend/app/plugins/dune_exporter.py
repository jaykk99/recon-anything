"""Dune Analytics query-result exporter (Tier-7, keyed).

No Dune coverage on master. This plugin is the exporter structure:
given a Dune query id in the target (dune:<id> or ?query=<id>), it
fetches the latest result via the Dune API and reports row count,
execution time and result staleness as findings - a stale exported
result silently misinforms dashboards and trading decisions. Needs
DUNE_API_KEY (ctx key "dune"); skips cleanly without it.
"""
from __future__ import annotations

import os
import re
from typing import Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target

API = "https://api.dune.com/api/v1/query"
Q_RX = re.compile(r"(?:dune:|query=|query/)(\d{3,})")
STALE_S = 86400


def extract_query_id(target: Target) -> Optional[str]:
    for cand in [target.raw or "", target.normalized or ""]:
        m = Q_RX.search(cand)
        if m:
            return m.group(1)
    return None


class DuneExporterPlugin(Plugin):
    id = "dune_exporter"
    label = "Dune API Exporter"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.PAID
    group = "web3"
    requires_keys = []
    description = ("Exports the latest result of a Dune query "
                   "(dune:<id> in target) and reports rows + result "
                   "staleness. Needs DUNE_API_KEY; skips cleanly "
                   "without it.")
    phase = 2
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        key = ctx.keys.get("dune") or os.environ.get("DUNE_API_KEY")
        if not key:
            return self._skipped("needs DUNE_API_KEY: Dune API is "
                                 "key-only")
        qid = extract_query_id(target)
        if not qid:
            return self._skipped("no Dune query id in target "
                                 "(use dune:<id>)")
        try:
            resp = await ctx.http.get(
                f"{API}/{qid}/results",
                headers={"X-Dune-API-Key": key}, timeout=20)
            if resp.status_code != 200:
                return self._degraded(f"Dune API HTTP {resp.status_code}")
            data = resp.json()
        except Exception as e:
            return self._degraded(f"Dune API error: {e}")
        if not isinstance(data, dict):
            return self._degraded("Dune API returned non-object payload")
        result = data.get("result") or {}
        rows = result.get("rows") or []
        meta = result.get("metadata") or {}
        submitted = data.get("submitted_at") or ""
        findings = [self._f(
            "web3", "dune_query_result",
            f"query {qid}: {len(rows)} rows, state "
            f"{data.get('state', '?')}",
            "DuneAPI", confidence=85,
            evidence={"severity": "low", "query_id": qid,
                      "rows": len(rows),
                      "row_count_meta": meta.get("row_count"),
                      "submitted_at": submitted,
                      "remediation": "Pin consumers to result age: a "
                                     "Dune export is a snapshot, not "
                                     "live chain state."})]
        exec_ts = data.get("execution_ended_at")
        if data.get("is_execution_finished") is False:
            findings.append(self._f(
                "web3", "dune_result_pending",
                f"query {qid}: latest execution not finished",
                "DuneAPI", confidence=80,
                evidence={"severity": "medium", "query_id": qid,
                          "execution_ended_at": exec_ts,
                          "remediation": "Consumers reading now get "
                                         "the previous (older) result."}))
        return self._ok(findings, f"exported query {qid}")
