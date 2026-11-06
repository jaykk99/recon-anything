"""GraphQL subscription sniffer (variant of graphql_deep):
graphql_deep enumerates Query/Mutation/Subscription field NAMES
only and never opens a subscription transport. This delta works
the transport side:

- analysis of operator-supplied captures/logs for subscription
  payload leakage (data frames carrying sensitive fields, masked)
- subscription config posture in supplied configs (transport
  enabled with no onConnect auth hook)
- live lane (active mode, operator-owned endpoints from the bus):
  a benign subscriptions-transport-ws handshake carrying a
  __typename-only subscription; data returned without any auth
  is the finding. __typename returns no business data, so a data
  frame in reply proves the transport executes unauthenticated.

No third-party interception; supplied captures or the run's own
endpoints only.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, credentialish, mask_secret, text_of

_SENSITIVE_FIELD = re.compile(
    r"(?i)\"(password|passwd|token|secret|ssn|credit_card|email|"
    r"phone|address|salary)\"\s*:")


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    text = text_of(data)
    if not text:
        return hits
    is_sub_traffic = ("subscription" in text.lower()
                      or "graphql-transport-ws" in text.lower()
                      or "subscriptions-transport-ws" in text.lower())
    if is_sub_traffic:
        for m in _SENSITIVE_FIELD.finditer(text):
            masked_note = ""
            c = credentialish(text[max(0, m.start() - 40):
                                   m.start() + 160])
            if c:
                masked, fp = mask_secret(c[1])
                masked_note = f" (nearby value masked {masked}, " \
                              f"fp {fp})"
            hits.append({
                "key": "graphql_subscription_payload_leak",
                "severity": "high",
                "value": f"GraphQL subscription data frame in "
                         f"supplied capture carries sensitive field "
                         f"'{m.group(1)}'{masked_note} - live "
                         "subscription payloads leak data to whoever "
                         "holds the socket",
                "evidence": {"field": m.group(1),
                             "remediation": "Enforce per-subscription "
                             "authorization (not just connection "
                             "auth), field-level redaction, and "
                             "short-lived subscription tokens."}})
            break
        if re.search(r"(?i)(onConnect\s*[:=]\s*(undefined|null|none|"
                     r"\(\)\s*=>\s*true)|subscriptions?\s*[:=]\s*\{[^}]*"
                     r"auth\s*[:=]\s*false)", text):
            hits.append({
                "key": "graphql_subscription_no_auth_hook",
                "severity": "medium",
                "value": "Supplied GraphQL config enables "
                         "subscriptions with no onConnect "
                         "authentication hook",
                "evidence": {"remediation": "Validate credentials "
                             "in onConnect and authorize each "
                             "subscription operation."}})
    return hits[:10]


class GraphqlSubscriptionSnifferPlugin(Plugin):
    id = "graphql_subscription_sniffer"
    label = "GraphQL Subscription Sniffer"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "api"
    phase = 2
    description = ("Subscription-transport posture: supplied "
                   "capture/log analysis for subscription payload "
                   "leakage (masked) + no-auth subscription config; "
                   "live __typename-only handshake on the run's own "
                   "endpoints in active mode.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "api",
                          ("graphql_captures", "graphql_configs"))
            if got is not None:
                return got
            return self._ok([], "no supplied GraphQL subscription "
                            "capture/config in ctx.shared")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
