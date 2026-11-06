"""Alchemy Notify webhook describe/validate (Tier-7, keyed).

No Alchemy Notify coverage on master (cp_apikey_alchemy only scans
code for leaked Alchemy keys). This plugin lists Address Activity
webhooks via the Alchemy Notify API and reports any webhook whose
tracked addresses include the target - an unknown activity webhook
means a third party is alerted on every transfer to/from the
address. With ALCHEMY_API_KEY (ctx key "alchemy") it queries the
real API; without a key it skips cleanly.
"""
from __future__ import annotations

import os
import re
from typing import List

from .base import Cost, Ctx, Plugin, PluginResult, Target

ADDR_RX = re.compile(r"0x[a-fA-F0-9]{40}")
API = "https://dashboard.alchemy.com/api/address-activity-webhooks"


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


class AlchemyWebhooksPlugin(Plugin):
    id = "alchemy_webhooks"
    label = "Alchemy Notify Webhooks (Describe/Validate)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.PAID
    group = "web3"
    requires_keys = []
    description = ("Lists Alchemy Address Activity webhooks and "
                   "reports any tracking the target address. Needs "
                   "ALCHEMY_API_KEY; skips cleanly without it.")
    phase = 2
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        key = ctx.keys.get("alchemy") or os.environ.get("ALCHEMY_API_KEY")
        if not key:
            return self._skipped("needs ALCHEMY_API_KEY: Alchemy "
                                 "Notify API is key-only")
        addrs = extract_addresses(target, ctx)
        try:
            resp = await ctx.http.get(
                API, headers={"X-Alchemy-Token": key,
                              "accept": "application/json"}, timeout=15)
            if resp.status_code != 200:
                return self._degraded(
                    f"Alchemy Notify API HTTP {resp.status_code}")
            data = resp.json()
        except Exception as e:
            return self._degraded(f"Alchemy Notify API error: {e}")
        hooks = []
        if isinstance(data, dict):
            hooks = data.get("data") or []
        elif isinstance(data, list):
            hooks = data
        findings = []
        for h in hooks if isinstance(hooks, list) else []:
            if not isinstance(h, dict):
                continue
            tracked = [str(a).lower() for a in
                       (h.get("addresses") or [])]
            watched = [a for a in addrs if a.lower() in tracked]
            findings.append(self._f(
                "web3", "alchemy_webhook_tracking_address"
                if watched else "alchemy_webhook_config",
                f"webhook {h.get('id')}: url={h.get('url')} "
                f"network={h.get('network')} active={h.get('is_active')}",
                "AlchemyNotify", confidence=85,
                evidence={"severity": "medium" if watched else "low",
                          "webhook_id": h.get("id"),
                          "watched_addresses": watched,
                          "remediation": "Audit activity webhooks: an "
                                         "unrecognized webhook tracking "
                                         "your address leaks transfer "
                                         "timing to a third party."}))
        return self._ok(findings, f"{len(findings)} webhooks described")
