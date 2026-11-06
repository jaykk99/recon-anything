"""Substrate pallet scanner.
Parses runtime metadata JSON (pallets/calls) and pallet source: flags privileged calls dispatchable with a weak origin, an exposed Sudo pallet, and zero/unbounded weights in source."""
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
    if isinstance(data, dict):
        for pal in data.get("pallets") or []:
            if not isinstance(pal, dict):
                continue
            pname = str(pal.get("name") or "")
            if pname.lower() == "sudo":
                hits.append({"key": "substrate_sudo_pallet_present",
                    "value": "Runtime includes the Sudo pallet - a single key can dispatch root calls",
                    "severity": "medium",
                    "remediation": "Remove Sudo before production or move its key behind multisig/governance."})
            for call in pal.get("calls") or []:
                if not isinstance(call, dict):
                    continue
                if call.get("privileged") and str(call.get("origin") or "") in ("Signed", "Any", "None", ""):
                    hits.append({"key": "substrate_privileged_call_weak_origin",
                        "value": f"Pallet '{pname}' privileged call '{call.get('name')}' is dispatchable with origin '{call.get('origin') or 'unspecified'}' instead of Root/governance",
                        "severity": "high",
                        "remediation": "Require Root or governance origin for privileged pallet calls."})
        return hits
    if re.search(r"#\[pallet::weight\(0\)\]|weight\s*=\s*0\b", text):
        hits.append({"key": "substrate_unbounded_weight",
            "value": "Pallet call declares zero weight - unbounded execution can be used for block stuffing / DoS",
            "severity": "medium",
            "remediation": "Benchmark and assign a realistic weight to every dispatchable."})
    if re.search(r"pub fn (force_\w+|set_\w+)\s*\(", text) and not re.search(r"ensure_root|ensure_signed", text):
        hits.append({"key": "substrate_privileged_fn_no_origin_check",
            "value": "Privileged-looking pallet function (force_*/set_*) has no ensure_root / origin check in the pallet source",
            "severity": "high",
            "remediation": "Call ensure_root(origin) (or the correct origin check) first in privileged dispatchables."})
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


class SubstratePalletScanner(Plugin):
    id = "substrate_pallet_scanner"
    label = "Substrate Pallet Scanner"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Inventories Substrate pallets/extrinsics from runtime metadata and flags privileged calls with weak origins, sudo surface, unbounded weights."
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
