"""Bitcoin script parser.
Decodes scriptPubKey/scriptSig/witness hex into opcodes, classifies multisig m-of-n and timelocks (OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY), flagging 1-of-n multisig and short timelocks."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


OPNAMES = {0x00:"OP_0",0x76:"OP_DUP",0xa9:"OP_HASH160",0x88:"OP_EQUALVERIFY",0x87:"OP_EQUAL",0xac:"OP_CHECKSIG",0xae:"OP_CHECKMULTISIG",0xb1:"OP_CHECKLOCKTIMEVERIFY",0xb2:"OP_CHECKSEQUENCEVERIFY",0x6a:"OP_RETURN",0x75:"OP_DROP"}

def decode_script(hexstr):
    t = re.sub(r"\s+", "", hexstr or "")
    if not re.fullmatch(r"[0-9a-fA-F]+", t or ""):
        return []
    raw = bytes.fromhex(t)
    out, i = [], 0
    while i < len(raw):
        b = raw[i]; i += 1
        if 0x51 <= b <= 0x60:
            out.append((f"OP_{b-0x50}", b-0x50))
        elif 0x01 <= b <= 0x4b:
            data = raw[i:i+b]; i += b
            val = int.from_bytes(data, "little") if data else 0
            out.append((f"PUSH({data.hex()})", val))
        elif b in OPNAMES:
            out.append((OPNAMES[b], None))
        else:
            out.append((f"OP_{b:02x}", None))
    return out

def analyze_artifact(text):
    hits = []
    toks = decode_script(text or "")
    if not toks:
        return hits
    names = [n for n, _ in toks]
    if "OP_CHECKMULTISIG" in names:
        idx = names.index("OP_CHECKMULTISIG")
        nums = [v for n, v in toks[:idx] if isinstance(v, int) and n.startswith("OP_")]
        # m is first small-int opcode, n is last before CHECKMULTISIG
        small = [v for n, v in toks[:idx] if n.startswith("OP_") and isinstance(v, int)]
        if small and small[0] == 1:
            hits.append({"key": "bitcoin_multisig_one_of_n",
                "value": f"Bitcoin multisig requires only 1 signature (1-of-{small[-1] if len(small)>1 else 'n'}) - a single key controls the funds",
                "severity": "high",
                "remediation": "Use at least 2-of-3 multisig for custody."})
    for j, (n, v) in enumerate(toks):
        if n in ("OP_CHECKLOCKTIMEVERIFY", "OP_CHECKSEQUENCEVERIFY") and j > 0:
            pv = toks[j-1][1]
            if isinstance(pv, int):
                if pv < 500000000 and pv < 750000:
                    hits.append({"key": "bitcoin_timelock_too_short",
                        "value": f"Bitcoin timelock ({n}) value {pv} is a short block-height lock (< 750000 / near-term) - funds become spendable almost immediately",
                        "severity": "medium",
                        "remediation": "Use a timelock far enough in the future for the intended custody delay."})
                elif pv >= 500000000 and pv < 1735689600:
                    hits.append({"key": "bitcoin_timelock_in_past",
                        "value": f"Bitcoin timelock ({n}) timestamp {pv} is already in the past - the lock provides no delay",
                        "severity": "medium",
                        "remediation": "Set the timelock timestamp in the future."})
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


class BitcoinScriptParser(Plugin):
    id = "bitcoin_script_parser"
    label = "Bitcoin Script Parser"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Decodes Bitcoin scripts (hex) into readable opcodes; flags 1-of-n multisig and weak CLTV/CSV timelocks."
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
