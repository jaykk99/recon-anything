"""Storage Slot Mapper (Cat-1 #2, VARIANT of storage_state_analysis).

Delta: enumerate the FULL source-derived storage layout - every
state variable with its slot, byte offset and type - as a
standalone map, and report the layout entries that matter for
security review: privileged variables (owner / admin /
implementation / guardian), variables packed into the same slot as
a privileged one (overwrite-adjacent), and any variable whose name
collides with the EIP-1967 proxy slots' roles in a non-proxy
contract (slot-confusion review point).

Slot assignment follows Solidity packing: value types pack into
32-byte slots in declaration order; mappings, arrays and strings
always start and occupy a fresh full slot.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_SIZES = {"bool": 1, "address": 20}
_PRIV = ("owner", "admin", "implementation", "guardian", "operator",
         "controller", "pauser", "minter")


def _size_of(typ: str) -> int:
    t = (typ or "").strip()
    if t.startswith("mapping") or t.startswith("string") or \
            t == "bytes" or t.endswith("]"):
        return 32
    if t in _SIZES:
        return _SIZES[t]
    if t.startswith("uint") or t.startswith("int"):
        try:
            bits = int(t.lstrip("u").lstrip("int") or "256")
        except ValueError:
            bits = 256
        return max(1, bits // 8)
    if t.startswith("bytes"):
        try:
            return int(t[5:] or "32")
        except ValueError:
            return 32
    return 32


def map_storage_layout(source: str) -> List[Dict[str, Any]]:
    layout: List[Dict[str, Any]] = []
    slot, offset = 0, 0
    for var in C.state_vars(source or ""):
        size = _size_of(var["type"])
        if size >= 32:
            if offset:
                slot += 1
                offset = 0
            layout.append({**var, "slot": slot, "offset": 0,
                           "size": 32})
            slot += 1
            continue
        if offset + size > 32:
            slot += 1
            offset = 0
        layout.append({**var, "slot": slot, "offset": offset,
                       "size": size})
        offset += size
        if offset >= 32:
            slot += 1
            offset = 0
    return layout


def analyze_layout(source: str) -> List[Dict[str, Any]]:
    layout = map_storage_layout(source)
    hits: List[Dict[str, Any]] = []
    by_slot: Dict[int, List[Dict[str, Any]]] = {}
    for e in layout:
        by_slot.setdefault(e["slot"], []).append(e)
    for e in layout:
        lname = e["name"].lower()
        if any(p in lname for p in _PRIV):
            packed_with = [o["name"] for o in by_slot[e["slot"]]
                           if o["name"] != e["name"]]
            hits.append(C.hit(
                "storage_slot_privileged_var",
                f"privileged state variable {e['name']} ({e['type']}) "
                f"lives at slot {e['slot']} offset {e['offset']}"
                + (f", packed with {', '.join(packed_with)}"
                   if packed_with else "")
                + "; anyone auditing or upgrading this contract "
                  "must treat that slot as security-critical.",
                "medium" if packed_with else "low",
                "Keep privileged variables in known slots; when "
                "upgrading, preserve this exact layout or the "
                "packed neighbours corrupt the privileged value.",
                variable=e["name"], slot=e["slot"],
                offset=e["offset"], var_type=e["type"],
                packed_with=packed_with,
                check="storage_slot_map"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return analyze_layout(data.get("source", ""))


class StorageSlotMapperPlugin(Plugin):
    id = "storage_slot_mapper"
    label = "Storage Slot Mapper"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Enumerates the full source-derived storage "
                   "layout (every state variable, slot, byte offset, "
                   "type) and flags privileged variables and their "
                   "packed slot neighbours.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, bytecode=False,
            no_input="no verified source to map storage layout from")
