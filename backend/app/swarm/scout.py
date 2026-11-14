"""Scout: pick up a target and read everything about it.

The Scout is the swarm's eyes. For one target it records, all from
read-only sources:

- on-chain facts: bytecode (eth_getCode), native balance
  (eth_getBalance), live chain id, a small set of well-known view
  calls (owner/totalSupply/name/symbol/decimals/balanceOf) from the
  unfunded stranger;
- verified source, when the chain's Blockscout API serves it;
- static findings: the full ``batch_scan.scan_source`` stack when
  importable (deep detectors on for high-value targets), else a small
  labelled regex fallback that never pretends to be the full stack;
- related addresses named in the source (proxy implementations,
  linked tokens, libraries): chaining leads for the Coordinator.

The Scout never writes, never signs, never guesses a finding it did
not measure. No source means bytecode-only mode, recorded as such.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional

from .rpc import RpcClient, decode_address, decode_uint256, fetch_verified_source, selector

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_ZERO_ADDRESS = "0x" + "0" * 40

# Small labelled fallback detectors, used ONLY when the repo's
# batch_scan stack is not importable. Each is a regex over source,
# reported with source="scout-fallback-regex" so nobody mistakes it
# for the full plugin stack.
_FALLBACK_CHECKS = [
    ("selfdestruct", re.compile(r"\bselfdestruct\s*\(", re.I),
     "high", "contract can selfdestruct"),
    ("delegatecall_untrusted", re.compile(r"\.delegatecall\s*\(", re.I),
     "high", "delegatecall present; target must be checked"),
    ("tx_origin", re.compile(r"\btx\.origin\b", re.I),
     "high", "tx.origin used for authorization"),
    ("unguarded_withdraw", re.compile(
        r"function\s+(withdraw|claim|rescue|sweep)\s*\([^)]*\)"
        r"\s*(public|external)[^{]*\{", re.I | re.S),
     "medium", "withdraw-like function present; access control unchecked by fallback"),
    ("unbounded_mint", re.compile(
        r"function\s+mint\s*\([^)]*\)\s*(public|external)", re.I),
     "medium", "public mint present; access control unchecked by fallback"),
]

_VIEW_CALLS = [
    ("owner", "owner()"),
    ("totalSupply", "totalSupply()"),
    ("name", "name()"),
    ("symbol", "symbol()"),
    ("decimals", "decimals()"),
]


def _related_addresses(source: str, self_address: str) -> List[str]:
    if not source:
        return []
    seen: List[str] = []
    for m in _ADDRESS_RE.findall(source):
        low = m.lower()
        if low == (self_address or "").lower() or low == _ZERO_ADDRESS:
            continue
        if low not in seen:
            seen.append(low)
    return seen[:10]


def _fallback_scan(source: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for kind, pattern, severity, detail in _FALLBACK_CHECKS:
        if pattern.search(source):
            findings.append({
                "kind": kind, "key": kind, "severity": severity,
                "title": kind.replace("_", " "),
                "detail": detail,
                "evidence": {"source": "scout-fallback-regex"},
                "plugin": "swarm-scout-fallback",
            })
    return findings


def _static_scan(source: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """Full scan stack when available, labelled fallback otherwise."""
    if not source:
        return {"findings": [], "engine": "none",
                "note": "no source: bytecode-only mode, no static scan"}
    try:
        from ..batch_scan import scan_source  # type: ignore
        findings = scan_source(source, meta, deep=True)
        return {"findings": list(findings or []), "engine": "batch_scan.scan_source(deep=True)",
                "note": "full CPU detection stack over verified source"}
    except Exception as e:  # noqa: BLE001 - fallback must not kill scout
        return {"findings": _fallback_scan(source),
                "engine": "scout-fallback-regex",
                "note": f"batch_scan unavailable ({type(e).__name__}: {e}); regex fallback only"}


class ScoutAgent:
    """Role agent: read everything about one target."""

    name = "scout"

    def run(self, target: Dict[str, Any], rpc: RpcClient,
            board: Any) -> Dict[str, Any]:
        key = f"{str(target.get('chain') or '').lower()}:{str(target.get('address') or '').lower()}"
        started = time.time()
        address = str(target.get("address") or "")
        chain = str(target.get("chain") or "")
        report: Dict[str, Any] = {
            "agent": self.name, "chain": chain, "address": address,
            "key": key, "errors": [],
        }
        if not _ADDRESS_RE.fullmatch(address or ""):
            report["errors"].append(f"invalid address: {address!r}")
            report["elapsed_s"] = round(time.time() - started, 3)
            board.post(self.name, key, "scout", report)
            return report

        # On-chain facts, all read-only.
        try:
            code = rpc.get_code(address)
            report["bytecode_len"] = (len(code) - 2) // 2 if code.startswith("0x") else 0
            report["has_code"] = report["bytecode_len"] > 0
        except Exception as e:  # noqa: BLE001
            report["errors"].append(f"eth_getCode failed: {e}")
            report["has_code"] = False
            report["bytecode_len"] = 0
        try:
            balance_wei = rpc.get_balance(address)
            report["native_balance_wei"] = balance_wei
            report["native_balance_eth"] = balance_wei / 1e18
        except Exception as e:  # noqa: BLE001
            report["errors"].append(f"eth_getBalance failed: {e}")
        try:
            live_chain_id = rpc.chain_id_live()
            report["chain_id_live"] = live_chain_id
            expected = rpc.chain_id
            report["chain_id_matches"] = (expected is None or live_chain_id == expected)
        except Exception as e:  # noqa: BLE001
            report["errors"].append(f"eth_chainId failed: {e}")

        # Well-known view calls from the stranger. A revert is data:
        # it means the function is absent or gated, recorded as such.
        views: Dict[str, Any] = {}
        for label, sig in _VIEW_CALLS:
            try:
                data = "0x" + selector(sig)
                resp = rpc.eth_call(address, data)
                if "result" in resp:
                    raw = str(resp["result"])
                    views[label] = {
                        "ok": True, "raw": raw,
                        "uint256": decode_uint256(raw),
                        "address": decode_address(raw),
                    }
                else:
                    views[label] = {"ok": False,
                                    "error": (resp.get("error") or {}).get("message", "reverted")}
            except Exception as e:  # noqa: BLE001
                views[label] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        report["views"] = views

        # Verified source (best effort; flaky explorers are normal).
        fetched = fetch_verified_source(chain, address)
        report["source_via"] = fetched.get("via")
        report["source_error"] = fetched.get("error")
        report["contract_name"] = (
            fetched.get("name") or target.get("name") or "")
        source = fetched.get("source") or ""
        report["source_len"] = len(source)
        report["has_source"] = bool(source)
        # Source + ABI live in the board's blob store (memory only),
        # so the ForkTester can read them without a second fetch and
        # without bloating the event log.
        board.put_blob(key, "source", source)
        try:
            board.put_blob(key, "abi",
                           json.loads(fetched.get("abi") or "[]"))
        except Exception:  # noqa: BLE001
            board.put_blob(key, "abi", None)

        # Static findings.
        scan = _static_scan(source, {"chain": chain, "address": address,
                                     "name": report["contract_name"]})
        report["scan_engine"] = scan["engine"]
        report["scan_note"] = scan["note"]
        report["findings"] = scan["findings"]
        report["findings_count"] = len(scan["findings"])
        severities = [str(f.get("severity") or "info").lower()
                      for f in scan["findings"]]
        report["worst_severity"] = (
            min(severities, key=lambda s: {"critical": 0, "high": 1,
                                           "medium": 2, "low": 3,
                                           "info": 4}.get(s, 4))
            if severities else None)

        # Chaining leads: only addresses that actually have code.
        # Source text also names bytes32 storage-slot constants that
        # merely LOOK like addresses (e.g. ERC1967 slot hashes); those
        # have no code and must not become targets. A code check that
        # errors keeps the address (flaky RPC must not drop a real
        # lead); a 0x code result drops it, with the reason recorded.
        related_raw = _related_addresses(source, address)
        related: List[str] = []
        dropped: List[Dict[str, str]] = []
        for candidate in related_raw:
            try:
                code = rpc.get_code(candidate)
                if code and code != "0x":
                    related.append(candidate)
                else:
                    dropped.append({"address": candidate,
                                    "reason": "no code at address"})
            except Exception as e:  # noqa: BLE001 - keep on error
                related.append(candidate)
                dropped.append({"address": candidate,
                                "reason": f"code check failed, kept: {e}"})
        report["related_addresses"] = related
        report["related_dropped"] = dropped
        report["elapsed_s"] = round(time.time() - started, 3)
        board.post(self.name, key, "scout", report)
        return report
