"""Defense watch: live read-only state snapshots for one contract.

Snapshot fields (all read-only eth_call / eth_getStorageAt via
cast; nothing is ever sent):
- owner()            - who controls the contract right now
- paused()           - freeze state
- EIP-1967 implementation slot, admin slot, beacon slot
- code hash          - did the deployed bytecode change
- native balance     - funds held
- allowance(holder, spender) for named spenders on a token
  (holder defaults to owner(), else the contract itself)

diff_snapshots(prev, cur) turns two snapshots into a change
list: owner changed, implementation swapped, paused flipped,
allowance grew. That is the upgrade-window / admin-change alert
the defense detectors point at.

A field that cannot be read is null with its name in
"unavailable" - a missing read is reported, never treated as
"unchanged" or "clean". Keyless, public RPC only.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .fork_attack import STRANGER, find_foundry_tool
from .plugins import contract_chain as cc
from .proxy_bridge_live import (
    SLOT_ZEPPELINOS_IMPLEMENTATION as _SLOT_ZEPPELINOS)
from .proxy_bridge_live import (
    SLOT_ZEPPELINOS_IMPLEMENTATION_MINUS1 as _SLOT_ZEPPELINOS_MINUS1)
from .proxy_bridge_live import analyze_upgrade as _analyze_upgrade
from .proxy_bridge_live import diff_implementations  # noqa: F401
from .proxy_bridge_live import extract_selectors  # noqa: F401

SLOT_IMPLEMENTATION = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
SLOT_ADMIN = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")
SLOT_BEACON = (
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")
# ZeppelinOS implementation slot (Wave 1.3): the ORIGINAL ZeppelinOS
# lineage (e.g. USDC's FiatTokenProxy) uses the RAW keccak256, no
# "-1" - read live 2026-11-12, the raw slot holds the live
# implementation while the keccak-1 slot reads zero. The keccak-1
# variant is what openzeppelin-sdk's later AdminUpgradeabilityProxy
# used, so the snapshot reads raw first and falls back to keccak-1.
# The constant is imported from proxy_bridge_live (single source of
# truth) so the two modules can never drift apart again.
# NOTE (Wave 1.3 fix): SLOT_BEACON above was truncated to 62 hex
# chars (missing the trailing "50") - it read the wrong storage
# word, so beacon proxies never resolved. The correct 32-byte slot
# is keccak256("eip1967.proxy.beacon") - 1; see
# tests/test_proxy_bridge_live.py::test_proxy_slots_are_keccak_minus_one.
SLOT_ZEPPELINOS_IMPLEMENTATION = _SLOT_ZEPPELINOS
SLOT_ZEPPELINOS_IMPLEMENTATION_MINUS1 = _SLOT_ZEPPELINOS_MINUS1

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _cast(args: List[str], timeout: float = 20):
    """subprocess.run wrapper (monkeypatch seam for tests).

    Returns (stdout+stderr text or None, error string or None)."""
    import subprocess
    cast = find_foundry_tool("cast")
    if not cast:
        return None, "cast not available"
    try:
        r = subprocess.run([cast, *args], capture_output=True,
                           text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), None
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def _rpc_urls(chain: str) -> List[str]:
    cfg = cc.CHAINS.get(chain)
    return list(cfg.rpc_urls) if cfg else []


def _call(chain: str, address: str, signature: str,
          args: tuple = ()) -> Optional[str]:
    """One read-only cast call; first RPC that answers wins.

    Revert = the function does not exist (definitive, not
    retried); transport failures fall through to the next RPC.
    Returns the raw output string, or None when unreadable."""
    for rpc in _rpc_urls(chain):
        out, _err = _cast(["call", "--from", STRANGER,
                           "--rpc-url", rpc, address, signature,
                           *args], timeout=15)
        if out is None:
            continue
        s = out.strip()
        if not s:
            continue
        if "revert" in s.lower():
            return None
        if "Error" in s:
            continue
        return s
    return None


def _parse_address(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    s = raw.strip()
    if s.startswith("0x") and len(s) == 66:
        addr = "0x" + s[-40:]
        return addr if _ADDRESS_RE.match(addr) else None
    if _ADDRESS_RE.match(s):
        return s
    return None


def _parse_bool(raw: Optional[str]) -> Optional[bool]:
    if not raw:
        return None
    s = raw.strip()
    if s.startswith("0x"):
        try:
            return int(s, 16) != 0
        except Exception:  # noqa: BLE001
            return None
    if s.lower() in ("true", "1"):
        return True
    if s.lower() in ("false", "0"):
        return False
    return None


def _parse_uint(raw: Optional[str]) -> Optional[int]:
    if not raw:
        return None
    s = raw.strip().splitlines()[0].strip()
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except Exception:  # noqa: BLE001
        return None


def _storage(chain: str, address: str, slot: str) -> Optional[str]:
    for rpc in _rpc_urls(chain):
        out, _err = _cast(["storage", "--rpc-url", rpc, address,
                           slot], timeout=15)
        if out is None:
            continue
        s = out.strip().splitlines()[0].strip() if out.strip() else ""
        if s.startswith("0x") and len(s) == 66:
            return s
    return None


def _slot_address(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    if raw == "0x" + "0" * 64:
        return None
    return _parse_address(raw)


def _native_balance(chain: str, address: str) -> Optional[int]:
    for rpc in _rpc_urls(chain):
        out, _err = _cast(["balance", "--rpc-url", rpc, address],
                          timeout=15)
        n = _parse_uint(out)
        if n is not None:
            return n
    return None


def _code_hash(chain: str, address: str) -> Optional[str]:
    for rpc in _rpc_urls(chain):
        out, _err = _cast(["code", "--rpc-url", rpc, address],
                          timeout=20)
        if out is None:
            continue
        code = out.strip()
        if code.startswith("0x"):
            return hashlib.sha256(code.encode()).hexdigest()
    return None


def snapshot(chain: str, address: str,
             spenders: Optional[List[str]] = None,
             token: Optional[str] = None) -> Dict[str, Any]:
    """Read-only live snapshot of one contract's control state."""
    now = datetime.now(timezone.utc).isoformat()
    snap: Dict[str, Any] = {
        "chain": chain, "address": address, "observed_at": now,
        "owner": None, "paused": None, "implementation": None,
        "admin": None, "beacon": None,
        "zeppelinos_implementation": None,
        "code_hash": None,
        "native_wei": None, "allowances": {},
        "unavailable": [],
    }
    if chain not in cc.CHAINS:
        snap["unavailable"] = ["chain"]
        snap["detail"] = f"unknown chain {chain}"
        return snap
    if not _ADDRESS_RE.match(address or ""):
        snap["unavailable"] = ["address"]
        snap["detail"] = "address must be 0x + 40 hex characters"
        return snap
    snap["owner"] = _parse_address(
        _call(chain, address, "owner()(address)"))
    if snap["owner"] is None:
        snap["unavailable"].append("owner")
    snap["paused"] = _parse_bool(
        _call(chain, address, "paused()(bool)"))
    if snap["paused"] is None:
        snap["unavailable"].append("paused")
    snap["implementation"] = _slot_address(
        _storage(chain, address, SLOT_IMPLEMENTATION))
    if snap["implementation"] is None:
        snap["unavailable"].append("implementation")
    snap["admin"] = _slot_address(
        _storage(chain, address, SLOT_ADMIN))
    if snap["admin"] is None:
        snap["unavailable"].append("admin")
    snap["beacon"] = _slot_address(
        _storage(chain, address, SLOT_BEACON))
    if snap["beacon"] is None:
        snap["unavailable"].append("beacon")
    # ZeppelinOS implementation slot (Wave 1.3): pre-EIP-1967
    # proxies (e.g. old ZeppelinOS / OpenZeppelin 2.x) store the
    # implementation here instead. Raw keccak first, keccak-1
    # fallback (see the SLOT_ZEPPELINOS_IMPLEMENTATION note above).
    # Zero = not that flavour.
    snap["zeppelinos_implementation"] = _slot_address(
        _storage(chain, address, SLOT_ZEPPELINOS_IMPLEMENTATION))
    if snap["zeppelinos_implementation"] is None:
        snap["zeppelinos_implementation"] = _slot_address(
            _storage(chain, address,
                     SLOT_ZEPPELINOS_IMPLEMENTATION_MINUS1))
    if snap["zeppelinos_implementation"] is None:
        snap["unavailable"].append("zeppelinos_implementation")
    snap["code_hash"] = _code_hash(chain, address)
    if snap["code_hash"] is None:
        snap["unavailable"].append("code_hash")
    snap["native_wei"] = _native_balance(chain, address)
    if snap["native_wei"] is None:
        snap["unavailable"].append("native_wei")
    holder = snap["owner"] or address
    token_addr = token or address
    for spender in spenders or []:
        if not _ADDRESS_RE.match(spender or ""):
            snap["allowances"][spender] = None
            continue
        snap["allowances"][spender] = _parse_uint(_call(
            chain, token_addr,
            "allowance(address,address)(uint256)",
            (holder, spender)))
    return snap


def diff_snapshots(prev: Dict[str, Any],
                   cur: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Change list between two snapshots. Unreadable fields are
    never reported as changes - a field missing from either side
    is skipped, not treated as unchanged."""
    changes: List[Dict[str, Any]] = []

    def _flag(field: str, before: Any, after: Any,
              severity: str, note: str) -> None:
        if before is None or after is None:
            return
        if before != after:
            changes.append({"field": field, "before": before,
                            "after": after, "severity": severity,
                            "note": note})

    _flag("owner", prev.get("owner"), cur.get("owner"), "high",
          "contract ownership changed - verify the new owner")
    _flag("implementation", prev.get("implementation"),
          cur.get("implementation"), "high",
          "proxy implementation swapped - the contract logic changed")
    _flag("admin", prev.get("admin"), cur.get("admin"), "high",
          "proxy admin changed")
    _flag("beacon", prev.get("beacon"), cur.get("beacon"), "high",
          "upgrade beacon changed")
    _flag("paused", prev.get("paused"), cur.get("paused"), "medium",
          "pause state flipped")
    _flag("code_hash", prev.get("code_hash"), cur.get("code_hash"),
          "high", "deployed bytecode changed")
    _flag("native_wei", prev.get("native_wei"),
          cur.get("native_wei"), "medium",
          "native balance moved")
    prev_allow = prev.get("allowances") or {}
    cur_allow = cur.get("allowances") or {}
    for spender in sorted(set(prev_allow) | set(cur_allow)):
        b, a = prev_allow.get(spender), cur_allow.get(spender)
        if b is None or a is None:
            continue
        if a > b:
            changes.append({"field": f"allowance:{spender}",
                            "before": b, "after": a,
                            "severity": "medium",
                            "note": "allowance grew for this spender"})
        elif a < b:
            changes.append({"field": f"allowance:{spender}",
                            "before": b, "after": a,
                            "severity": "low",
                            "note": "allowance shrank for this spender"})
    return changes


async def analyze_upgrade(prev: Dict[str, Any], cur: Dict[str, Any],
                          source_analyzer=None) -> Dict[str, Any]:
    """Upgrade report between two snapshots (Wave 1.3).

    Thin wrapper over ``proxy_bridge_live.analyze_upgrade`` with a
    code reader built on the cast transport above (``cast code`` per
    implementation address). ``source_analyzer(chain, address)``
    optionally re-runs the repo's analysis on the new
    implementation's verified source - the plugin path wires that
    in; the CLI leaves it off and reports bytecode-diff only.

    The report always records an implementation change; findings
    appear only when the new implementation gains dangerous opcodes
    or trips re-analysis (notably an open upgrade window on the new
    implementation). Verdict is "candidate" / "clean" / "degraded";
    never VERIFIED_REAL.
    """
    import asyncio

    async def _code_reader(chain: str, address: str):
        out, _err = await asyncio.to_thread(
            _cast, ["code", "--rpc-url", _rpc_urls(chain)[0], address]
            if _rpc_urls(chain) else ["code", address])
        if out is None:
            return None
        code = out.strip()
        return code if code.startswith("0x") else None

    return await _analyze_upgrade(prev, cur, _code_reader,
                                  source_analyzer)
