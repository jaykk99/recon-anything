"""TRON TVM decompiler (variant of bytecode_deep_analysis).
Delta: TVM opcode dialect (incl. TRON token/call-token opcodes) instead of plain EVM decoding; same dangerous-flow scan with TVM labels."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


TVM_OPS = {0x00:"STOP",0x01:"ADD",0x02:"MUL",0x10:"LT",0x14:"EQ",0x50:"POP",0x54:"SLOAD",0x55:"SSTORE",0x60:"PUSH1",0x61:"PUSH2",0x7f:"PUSH32",0x80:"DUP1",0x90:"SWAP1",0xa1:"LOG1",0xf1:"CALL",0xf2:"CALLCODE",0xf4:"DELEGATECALL",0xfa:"CREATE2",0xff:"SELFDESTRUCT",0xd4:"CALLTOKEN",0xd5:"TOKENBALANCE",0xd6:"TOKENTRANSFER"}

def disassemble_tvm(hexstr):
    t = re.sub(r"\s+", "", hexstr or "")
    if not re.fullmatch(r"[0-9a-fA-F]+", t or ""):
        return []
    raw = bytes.fromhex(t)
    out, i = [], 0
    while i < len(raw):
        b = raw[i]; i += 1
        name = TVM_OPS.get(b, f"OP_{b:02x}")
        out.append(name)
        if name.startswith("PUSH"):
            n = int(name[4:]); i += n
    return out

def analyze_artifact(text):
    hits = []
    ops = disassemble_tvm(text or "")
    if not ops:
        # textual TRON source fallback
        if re.search(r"delegatecall|\.callToken\s*\(", text or "", re.I) and not re.search(r"require|assert|onlyOwner|msg\.sender", text or "", re.I):
            hits.append({"key": "tron_unchecked_delegate_or_token_call",
                "value": "TRON contract performs a delegate/token call with no caller or result check in the source",
                "severity": "high",
                "remediation": "Gate delegate/token calls on the caller and check their results."})
        return hits
    if "DELEGATECALL" in ops:
        hits.append({"key": "tron_tvm_delegatecall",
            "value": "TRON TVM bytecode contains DELEGATECALL - the contract executes external code in its own storage context",
            "severity": "high",
            "remediation": "Verify the delegate target is fixed/trusted; remove delegatecall if not required."})
    if "SELFDESTRUCT" in ops:
        hits.append({"key": "tron_tvm_selfdestruct",
            "value": "TRON TVM bytecode contains SELFDESTRUCT (suicide) - the contract can be destroyed and its TRX/token balance forced out",
            "severity": "high",
            "remediation": "Remove selfdestruct or gate it behind multisig/timelock."})
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


class TronTvmDecompiler(Plugin):
    id = "tron_tvm_decompiler"
    label = "TRON TVM Decompiler"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Variant of bytecode_deep_analysis: TRON TVM dialect - disassembles TRON bytecode with TVM opcodes and flags delegatecall/selfdestruct-equivalent flows."
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
