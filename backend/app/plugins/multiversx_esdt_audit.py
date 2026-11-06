"""MultiversX ESDT audit.
Token JSON: flags canFreeze/canWipe/canPause/canMint capabilities held by a single owner. Source: flags ESDT issuance / special-role assignment with no owner check."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


def analyze_artifact(text):
    hits = []
    if not text:
        return hits
    try:
        data = json.loads(text)
    except Exception:
        data = None
    if isinstance(data, dict) and any(k in data for k in ("canFreeze", "canWipe", "canPause", "canMint")):
        for flag, sev in (("canWipe", "high"), ("canFreeze", "medium"), ("canPause", "medium"), ("canMint", "high")):
            if data.get(flag):
                hits.append({"key": f"esdt_{flag.lower()}_enabled",
                    "value": f"ESDT token has {flag}=true - the token owner ({data.get('owner', 'single owner')}) can {'wipe holder balances' if flag=='canWipe' else flag.replace('can','').lower() + ' the token'} unilaterally",
                    "severity": sev,
                    "remediation": f"Disable {flag} or move the special role behind a multisig contract."})
        return hits
    if re.search(r"issue_fungible|ESDTSystem|issue\s*\(", text) and not re.search(r"only_owner|check_owner|access.*owner|require.*owner", text, re.I):
        hits.append({"key": "esdt_issue_no_owner_check",
            "value": "MultiversX contract issues ESDT tokens with no owner check in the source",
            "severity": "high",
            "remediation": "Gate ESDT issuance and special-role assignment on the contract owner / multisig."})
    if re.search(r"set_special_role|special_role", text, re.I) and not re.search(r"multisig|governance", text, re.I):
        hits.append({"key": "esdt_special_role_single_holder",
            "value": "ESDT special roles are assigned with no multisig/governance holder in the contract",
            "severity": "medium",
            "remediation": "Assign ESDT special roles to a multisig contract."})
    return hits


async def _get_artifact(target, ctx):
    try:
        for kind in ("artifacts", "source", "sources", "code",
                     "artifact_text", "files", "contracts"):
            for item in ctx.consume(kind):
                if isinstance(item, str) and len(item) > 20:
                    return item
                if isinstance(item, dict):
                    import json as _j
                    return _j.dumps(item)
    except Exception:
        pass
    raw = (getattr(target, "raw", "") or "").strip()
    norm = (getattr(target, "normalized", "") or "").strip()
    if raw and (len(raw) > 30 or raw.startswith("{") or "\n" in raw):
        return raw
    if norm.startswith("http"):
        try:
            page = await ctx.fetch_page(norm)
            if page:
                txt = page.get("text") if isinstance(page, dict) else getattr(page, "text", "")
                if txt:
                    return txt
        except Exception:
            pass
    return raw


class MultiversxEsdtAudit(Plugin):
    id = "multiversx_esdt_audit"
    label = "MultiversX ESDT Audit"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Audits MultiversX ESDT tokens/contracts: freeze/wipe/pause capabilities, special-role holders, unguarded issuance."
    passive = True

    async def run(self, target, ctx):
        try:
            text = await _get_artifact(target, ctx)
            hits = analyze_artifact(text or "")
            findings = [
                self._f("web3", h["key"], h["value"], self.id,
                        confidence=85,
                        evidence={"severity": h.get("severity", "medium"),
                                  "remediation": h.get("remediation", "")})
                for h in hits]
            return self._ok(
                findings,
                reason=f"{len(findings)} alt-chain finding(s) from artifact analysis")
        except Exception as exc:  # never raise fatally
            return self._ok([], reason=f"degraded: {type(exc).__name__}: {exc}")
