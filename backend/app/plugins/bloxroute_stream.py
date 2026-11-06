"""bloXroute Cloud stream describe/validate (Tier-10, MONITORING ONLY).

bloXroute's Cloud-API / Blockchain Distribution Network stream is a
keyed service: without BXR_AUTH_HEADER there is no public stream to
read, so the plugin clean-skips with a needs-config reason (the Tier-7
keyed-plugin pattern). With a key it VALIDATES the credential against
the Cloud-API (a read-only account/quota call) and describes the
configured stream state. It never subscribes on the user's behalf to
relay or submit anything, and it never sends transactions.
"""
from __future__ import annotations

from .base import Cost, Ctx, Plugin, PluginResult, Target

API = "https://api.blxrbdn.com"
KEY_NAME = "BXR_AUTH_HEADER"


class BloxrouteStreamPlugin(Plugin):
    id = "bloxroute_stream"
    label = "bloXroute Stream Describe"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = [KEY_NAME]
    description = ("Keyed describe/validate for a bloXroute Cloud-API "
                   "stream (account/quota read with BXR_AUTH_HEADER). "
                   "Clean needs-config skip without the key. "
                   "Monitoring only.")
    phase = 1
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        auth = (ctx.keys or {}).get(KEY_NAME)
        if not auth:
            return self._skipped(
                f"needs {KEY_NAME}: bloXroute Cloud-API streams are "
                "keyed; no public keyless stream endpoint exists")
        findings = []
        try:
            resp = await ctx.http.post(
                API, headers={"Authorization": auth},
                json={"jsonrpc": "2.0", "id": 1,
                      "method": "get_stats", "params": {}}, timeout=15)
        except Exception as e:
            return self._degraded(f"bloXroute API unreachable: "
                                  f"{type(e).__name__}")
        if resp.status_code in (401, 403):
            findings.append(self._f(
                "web3", "bloxroute_auth_rejected",
                f"bloXroute rejected BXR_AUTH_HEADER (HTTP "
                f"{resp.status_code})", "bloXroute", confidence=85,
                evidence={"severity": "medium",
                          "http_status": resp.status_code,
                          "remediation": "Rotate the bloXroute "
                                         "authorization header; mempool "
                                         "stream monitoring is blind "
                                         "until it validates."}))
            return self._ok(findings, "bloXroute auth rejected")
        if resp.status_code != 200:
            return self._degraded(
                f"bloXroute API HTTP {resp.status_code}")
        try:
            data = resp.json()
        except Exception:
            return self._degraded("bloXroute API returned non-JSON")
        result = data.get("result") if isinstance(data, dict) else None
        if isinstance(result, dict) and result:
            findings.append(self._f(
                "web3", "bloxroute_stream_state",
                f"bloXroute Cloud-API validated: "
                f"{str(result)[:180]}", "bloXroute", confidence=85,
                evidence={"severity": "low", "stats": result,
                          "remediation": "Monitoring only: stream state "
                                         "described, nothing subscribed "
                                         "or submitted."}))
        else:
            findings.append(self._f(
                "web3", "bloxroute_stream_validated",
                "bloXroute Cloud-API credential validated (empty stats)",
                "bloXroute", confidence=70,
                evidence={"severity": "low",
                          "remediation": "Credential works; configure a "
                                         "stream filter to receive "
                                         "pending-tx events."}))
        return self._ok(findings, f"{len(findings)} bloXroute findings")
