"""Smart Contract Recon: pull a contract's code out and show it.

Given a contract address - as the scan target itself (optionally
chain-prefixed, e.g. "bsc:0x...") or discovered on a web target by the
address miners - this fetches the contract's code READ-ONLY from
public chain data and turns the code into findings:

- verified source (keyless Blockscout / Sourcify; Etherscan only when
  a key is already configured) is inventoried function by function:
  identity, proxy pattern, privileged functions (owner/admin, mint,
  withdraw/sweep, pause, blacklist), delegatecall, selfdestruct,
  tx.origin, unchecked calls, hardcoded addresses, embedded
  URLs/IPs, and secret-looking strings. Every finding SHOWS the code.
- when no verified source exists, the deployed bytecode is analyzed
  instead: hash, size, known function selectors, sensitive opcodes,
  EIP-1167 proxy detection, Solidity metadata - clearly labeled
  "bytecode only".

Detection only. Never sends a transaction, never calls the contract;
the deepest access is eth_getCode and public explorer reads.

Secret-looking strings are shown IN FULL in findings, per Jay's
order (2026-10-29) - never masked.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc

MAX_ADDRESSES = 4       # addresses reconned per run
MAX_CHAIN_PAIRS = 4     # (chain, address) pairs analyzed per run

_KIND_TO_KEY = {
    "identity": "contract_code_identity",
    "proxy": "contract_proxy",
    "privileged_function": "contract_privileged_function",
    "delegatecall": "contract_delegatecall_code",
    "selfdestruct": "contract_selfdestruct_code",
    "tx_origin": "contract_tx_origin_code",
    "unchecked_call": "contract_unchecked_call_code",
    "hardcoded_address": "contract_hardcoded_address",
    "embedded_endpoint": "contract_embedded_endpoint",
    "secret_string": "contract_secret_string",
    "ownership_takeover_fallback": "contract_ownership_takeover_fallback",
    "deposit_to_own": "contract_deposit_to_own",
    "full_balance_withdraw": "contract_full_balance_withdraw",
    "ownership_takeover_path": "contract_ownership_takeover_path",
    "fallback_state_write": "contract_fallback_state_write",
}

_REMEDIATION = {
    "contract_secret_string": (
        "This secret sits in PUBLIC verified source - treat it as "
        "burned. Rotate it now and sweep any funds it controls to a "
        "fresh wallet generated offline."),
    "contract_ownership_takeover_path": (
        "Break the path: ownership must never change through "
        "receive()/fallback() or deposit comparisons, and full-balance "
        "withdrawal must sit behind a timelock + multisig, not a "
        "single acquirable owner key."),
    "contract_ownership_takeover_fallback": (
        "Remove ownership assignment from receive()/fallback(). A "
        "plain ETH transfer must never change who owns the contract."),
    "contract_deposit_to_own": (
        "Deposits must never influence ownership. Remove the "
        "contributions comparison from the ownership logic."),
    "contract_proxy": (
        "Know who the proxy admin is: an upgradeable proxy means the "
        "code you audited can be replaced. Prefer timelocked, "
        "multisig-controlled admins and verify the implementation."),
    "contract_privileged_function": (
        "Confirm every privileged function sits behind strong, "
        "preferably multisig, access control - these functions are "
        "the contract's master keys."),
}


class ContractReconPlugin(Plugin):
    id = "contract_recon"
    label = "Smart Contract Recon"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []  # keyless-first: Blockscout + Sourcify + public RPC
    description = ("Pulls a contract's code from public chain data "
                   "(Ethereum, BNB Chain, Polygon, Arbitrum) and shows "
                   "it as findings: privileged functions, proxy pattern, "
                   "dangerous code, secrets - plus bytecode analysis "
                   "when source is unverified. Read-only, never "
                   "interacts with contracts.")
    phase = 2  # also consumes addresses discovered by phase-1 miners
    timeout_s = 180

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None

        work = self._collect(target, ctx)
        if not work:
            res = self._skipped(
                "no contract address to recon: scan a contract address "
                "(optionally chain-prefixed, e.g. bsc:0x...) or a web "
                "target whose pages reference one")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        pairs_done = 0
        reconned = 0
        for chain_hint, addr in work:
            if pairs_done >= MAX_CHAIN_PAIRS:
                break
            try:
                pairs = await self._recon_address(
                    ctx, key, chain_hint, addr, findings)
            except Exception:
                pairs = 0
                findings.append(self._f(
                    "web3", "contract_recon_failed",
                    f"MEDIUM: {addr}: recon failed - chain data could "
                    "not be retrieved (explorers/RPC unreachable). "
                    "No conclusion drawn.",
                    source="contract recon",
                    confidence=60, passive=True,
                    evidence={"severity": "medium", "address": addr,
                              "remediation": "Retry the scan; if the "
                                             "chain RPCs stay down, "
                                             "recon this address "
                                             "manually on its block "
                                             "explorer."}))
            pairs_done += pairs
            if pairs:
                reconned += 1

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"reconned {reconned} contract "
                                 f"address(es), {len(findings)} "
                                 f"findings")
        res.duration_ms = dur
        return res

    # -- target collection --------------------------------------------
    def _collect(self, target: Target,
                 ctx: Ctx) -> List[Tuple[Optional[str], str]]:
        out: List[Tuple[Optional[str], str]] = []
        seen = set()

        def add(chain_hint: Optional[str], addr: str) -> None:
            addr = (addr or "").strip()
            if not cc.ADDRESS_RE.match(addr):
                return
            if addr.lower() == cc.ZERO_ADDRESS:
                return
            k = addr.lower()
            if k in seen:
                return
            seen.add(k)
            out.append((chain_hint, addr))

        # The target itself may be a contract address.
        for raw in (target.normalized, target.raw):
            chain_hint, addr = cc.parse_target_address(raw or "")
            if addr:
                add(chain_hint, addr)
                break

        # Addresses discovered during a web scan.
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else \
                    str(item.get("address", ""))
                add(None, a)
        for item in ctx.consume("chain_contracts"):
            if isinstance(item, dict):
                hint = item.get("chain")
                add(hint if isinstance(hint, str) and
                    hint in cc.CHAINS else None,
                    str(item.get("address", "")))
        return out[:MAX_ADDRESSES]

    # -- per-address recon ---------------------------------------------
    async def _recon_address(self, ctx: Ctx, key: Optional[str],
                             chain_hint: Optional[str], addr: str,
                             findings: List[Finding]) -> int:
        """Recon one address on its chain (or probe all chains).

        Appends findings; returns the number of (chain, address) pairs
        that actually held contract code.
        """
        if chain_hint:
            chain_ids = [chain_hint]
        else:
            chain_ids = list(cc.DEFAULT_CHAIN_ORDER)
        pairs = 0
        rpc_all_failed = True
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS[cid]
            code = await cc.rpc_get_code(ctx, chain, addr)
            if code is None:
                continue  # this chain's RPCs failed; try the next
            rpc_all_failed = False
            if code == "0x" or len(code) < 4:
                continue  # no contract code on this chain
            pairs += 1
            await self._recon_on_chain(ctx, key, chain, addr, code,
                                       findings)
            if chain_hint:
                break
        if pairs == 0 and not rpc_all_failed:
            findings.append(self._f(
                "web3", "contract_no_code",
                f"LOW: {addr}: no contract code on "
                f"{'the named chain' if chain_hint else 'Ethereum, BNB Chain, Polygon or Arbitrum'} "
                "- the address is a wallet (EOA) there, or the "
                "contract lives on a chain this tool does not cover.",
                source="public JSON-RPC eth_getCode",
                confidence=85, passive=True,
                evidence={"severity": "low", "address": addr,
                          "chain": chain_hint or "all configured",
                          "remediation": "Confirm the chain the "
                                         "contract is deployed on and "
                                         "re-scan with a chain prefix "
                                         "(e.g. bsc:0x...)."}))
        elif pairs == 0 and rpc_all_failed:
            findings.append(self._f(
                "web3", "contract_recon_failed",
                f"MEDIUM: {addr}: every public RPC endpoint failed, "
                "so no chain data could be retrieved. No conclusion "
                "drawn.",
                source="public JSON-RPC eth_getCode",
                confidence=60, passive=True,
                evidence={"severity": "medium", "address": addr,
                          "remediation": "Retry later; the public RPC "
                                         "endpoints for this chain "
                                         "were unreachable."}))
        return pairs

    async def _recon_on_chain(self, ctx: Ctx, key: Optional[str],
                              chain: cc.ChainConfig, addr: str,
                              code_hex: str,
                              findings: List[Finding]) -> None:
        url = cc.explorer_url(chain, addr)
        base_ev = {"address": addr, "chain": chain.id,
                   "chain_id": chain.chain_id}
        ctx.publish("chain_contracts", {
            "address": addr, "chain": chain.id,
            "is_contract": True, "verified": False, "name": ""})

        src = await cc.fetch_verified_source(ctx, chain, addr, key)
        bc = cc.analyze_bytecode(code_hex)

        if src:
            meta = {"contract_name": src.get("contract_name", ""),
                    "compiler": src.get("compiler", ""),
                    "implementation": src.get("implementation", "")}
            for item in cc.analyze_contract_source(src["source"], meta):
                kind = item["kind"]
                fkey = _KIND_TO_KEY.get(kind, "contract_code")
                sev = item["severity"]
                value = f"{sev.upper()}: {item['title']}"
                if item.get("code"):
                    value += f"\n\nCode:\n{item['code']}"
                ev = dict(base_ev)
                ev.update({
                    "severity": sev,
                    "check": kind,
                    "function": item.get("function", ""),
                    "code": item.get("code", ""),
                    "detail": item.get("detail", ""),
                    "source_origin": src.get("origin", ""),
                    "remediation": _REMEDIATION.get(
                        fkey,
                        "Review this code. It is published on-chain; "
                        "anyone can read and reason about it."),
                })
                for extra in ("contract_name", "compiler",
                              "function_count", "priv_category", "gated",
                              "implementation", "pattern", "addresses",
                              "urls", "ips", "secret_kind",
                              "secret_value"):
                    if extra in item:
                        ev[extra] = item[extra]
                findings.append(self._f(
                    "web3", fkey, value,
                    source=f"{src.get('origin', 'explorer')} verified "
                           f"source ({chain.name})",
                    source_url=url,
                    confidence=88, passive=True, evidence=ev))
            findings.append(self._bytecode_finding(
                chain, addr, url, bc, base_ev, source_available=True))
            return

        # Bytecode-only path: no verified source anywhere.
        findings.append(self._f(
            "web3", "contract_source_unavailable",
            f"MEDIUM: {addr} on {chain.name}: verified source is not "
            "published on Blockscout, Sourcify or Etherscan, so the "
            "code cannot be read as Solidity. Bytecode analysis only "
            "(below) - treat this contract as unauditable until its "
            "source is verified.",
            source="Blockscout/Sourcify/Etherscan source lookup",
            source_url=url, confidence=90, passive=True,
            evidence={**base_ev,
                      "severity": "medium",
                      "remediation": "Do not trust a contract whose "
                                     "source is unverified. Ask the "
                                     "publisher to verify it on the "
                                     "block explorer."}))
        findings.append(self._bytecode_finding(
            chain, addr, url, bc, base_ev, source_available=False))

    def _bytecode_finding(self, chain: cc.ChainConfig, addr: str,
                          url: str, bc: Dict[str, Any],
                          base_ev: Dict[str, Any],
                          source_available: bool) -> Finding:
        known = [s for s in bc["selectors"] if s.get("signature")]
        sel_lines = [
            f"  {s['selector']}  {s['signature'] or '(unknown function)'}"
            for s in bc["selectors"][:40]]
        op_bits = ", ".join(
            f"{name} x{count}" for name, count in
            sorted(bc["opcodes"].items()))
        meta = bc["metadata"]
        meta_bits = []
        if meta.get("solc"):
            meta_bits.append(f"solc {meta['solc']}")
        if meta.get("ipfs"):
            meta_bits.append(f"ipfs metadata {meta['ipfs']}")
        if meta.get("swarm"):
            meta_bits.append(f"swarm metadata {meta['swarm']}")
        title = (f"LOW: {addr} on {chain.name}: deployed bytecode "
                 f"{bc['size']} bytes, sha256 {bc['sha256'][:16]}...; "
                 f"{len(bc['selectors'])} function selector(s) seen, "
                 f"{len(known)} matched to known functions"
                 + (f"; opcodes: {op_bits}" if op_bits else "")
                 + (f"; {', '.join(meta_bits)}" if meta_bits else "")
                 + ("; source also analyzed above"
                    if source_available else
                    "; SOURCE UNAVAILABLE - bytecode analysis only"))
        value = title
        if sel_lines:
            value += "\n\nSelectors found in bytecode:\n" + \
                "\n".join(sel_lines)
        if bc.get("minimal_proxy_impl"):
            value += (f"\n\nEIP-1167 minimal proxy: all calls forward "
                      f"to implementation "
                      f"{bc['minimal_proxy_impl']}")
        ev = dict(base_ev)
        ev.update({
            "severity": "low",
            "bytecode_size": bc["size"],
            "bytecode_sha256": bc["sha256"],
            "selectors": bc["selectors"],
            "opcodes": bc["opcodes"],
            "metadata": bc["metadata"],
            "minimal_proxy_impl": bc.get("minimal_proxy_impl"),
            "source_available": source_available,
            "remediation": ("Selectors and opcodes are the contract's "
                            "public machine code fingerprint. Match "
                            "them against the verified source (when "
                            "published) before trusting the contract."),
        })
        return self._f(
            "web3", "contract_bytecode", value,
            source=f"public JSON-RPC eth_getCode ({chain.name})",
            source_url=url, confidence=80, passive=True, evidence=ev)
