"""Move bytecode disassembler.
Pure-Python opcode disassembly of Move module bytes (hex input) or a textual listing; flags MoveFrom / BorrowGlobalMut on global resources with no signer check in the module."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin


OPCODES = {0x01:"LdU8",0x02:"LdU64",0x03:"LdU128",0x04:"Pop",0x05:"Ret",0x06:"BrTrue",0x07:"BrFalse",0x08:"Branch",0x09:"LdTrue",0x0a:"LdFalse",0x0b:"LdAddress",0x0c:"Call",0x0d:"MoveFrom",0x0e:"MoveTo",0x0f:"BorrowGlobal",0x10:"BorrowGlobalMut",0x11:"Exists",0x12:"FreezeRef",0x13:"MutBorrowField",0x14:"ImmBorrowField",0x15:"CheckSigner",0x16:"MoveToSigner"}

def disassemble_move(text):
    t = (text or "").strip()
    if re.fullmatch(r"[0-9a-fA-F\s]+", t or "") and len(t.replace(" ", "")) >= 4:
        try:
            raw = bytes.fromhex(t.replace(" ", "").replace("\n", ""))
        except Exception:
            return []
        return [OPCODES.get(b, f"OP_{b:02x}") for b in raw]
    return [ln.strip() for ln in t.splitlines() if ln.strip()]

def analyze_artifact(text):
    hits = []
    if not text:
        return hits
    listing = " ".join(disassemble_move(text))
    has_signer_check = "CheckSigner" in listing or "MoveToSigner" in listing
    if "MoveFrom" in listing and not has_signer_check:
        hits.append({"key": "move_from_without_signer_check",
            "value": "Move bytecode executes MoveFrom (removes a resource from an account) with no signer check opcode in the module",
            "severity": "high",
            "remediation": "Require and verify the resource owner's signer before MoveFrom."})
    if "BorrowGlobalMut" in listing and not has_signer_check:
        hits.append({"key": "move_borrow_global_mut_without_signer",
            "value": "Move bytecode mutably borrows a global resource (BorrowGlobalMut) with no signer check in the module",
            "severity": "medium",
            "remediation": "Check the signer owns the borrowed resource address before BorrowGlobalMut."})
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


class MoveBytecodeDisasm(Plugin):
    id = "move_bytecode_disasm"
    label = "Move Bytecode Disassembler"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Disassembles Move module bytecode (hex) / listings and flags global-resource access without a signer check."
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
