"""QuickNode Streams describe/validate (Tier-7, keyed).

No QuickNode Streams coverage on master (the cp_apikey_quicknode
plugin only scans code for leaked QuickNode keys - a different
thing). This plugin validates, against the QuickNode Streams REST
API, which streams exist and whether any stream watches a target
address (streams deliver block/address data to webhooks/datasets;
a forgotten stream is a silent data-egress path). Structure is real:
with QUICKNODE_API_KEY (ctx key "quicknode") it lists streams and
matches their filters; without a key it skips cleanly.
"""
from __future__ import annotations

import os
import re
from typing import List

from .base import Cost, Ctx, Plugin, PluginResult, Target

ADDR_RX = re.compile(r"0x[a-fA-F0-9]{40}")
API = "https://api.quicknode.com/streams/rest/v1/streams"


def extract_addresses(target: Target, ctx: Ctx) -> List[str]:
    out: List[str] = []
    for cand in [target.raw or "", target.normalized or ""]:
        out += ADDR_RX.findall(cand)
    seen, uniq = set(), []
    for a in out:
        if a.lower() not in seen:
            seen.add(a.lower())
            uniq.append(a)
    return uniq[:4]


class QuickNodeStreamsPlugin(Plugin):
    id = "quicknode_streams"
    label = "QuickNode Streams (Describe/Validate)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.PAID
    group = "web3"
    requires_keys = []
    description = ("Lists QuickNode Streams and reports any stream "
                   "whose filter watches the target address. Needs "
                   "QUICKNODE_API_KEY; skips cleanly without it.")
    phase = 2
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        key = ctx.keys.get("quicknode") or os.environ.get(
            "QUICKNODE_API_KEY")
        if not key:
            return self._skipped("needs QUICKNODE_API_KEY: QuickNode "
                                 "Streams API is key-only")
        addrs = extract_addresses(target, ctx)
        try:
            resp = await ctx.http.get(
                API, headers={"x-api-key": key, "accept": "application/json"},
                timeout=15)
            if resp.status_code != 200:
                return self._degraded(
                    f"QuickNode Streams API HTTP {resp.status_code}")
            data = resp.json()
        except Exception as e:
            return self._degraded(f"QuickNode Streams API error: {e}")
        streams = []
        if isinstance(data, dict):
            streams = data.get("data") or data.get("streams") or []
        elif isinstance(data, list):
            streams = data
        findings = []
        for s in streams if isinstance(streams, list) else []:
            if not isinstance(s, dict):
                continue
            blob = str(s).lower()
            watched = [a for a in addrs if a.lower() in blob]
            findings.append(self._f(
                "web3", "quicknode_stream_watching_address"
                if watched else "quicknode_stream_config",
                f"stream {s.get('name') or s.get('id')}: "
                f"status={s.get('status')} network={s.get('network')} "
                f"destination={s.get('destination_type') or s.get('destination')}",
                "QuickNodeStreams", confidence=85,
                evidence={"severity": "medium" if watched else "low",
                          "stream_id": s.get("id"),
                          "watched_addresses": watched,
                          "remediation": "Audit stream destinations: a "
                                         "stream to an unknown webhook "
                                         "is a silent data-egress path. "
                                         "Disable streams you do not "
                                         "recognize."}))
        return self._ok(findings, f"{len(findings)} streams described")
