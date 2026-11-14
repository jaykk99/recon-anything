"""Live bridge invariant plugins (Wave 1.3).

The existing ``bridge_*`` detectors are static source patterns
(including ``bridge_validator_quorum_manipulation``). These three
plugins replace that approach for the invariants that matter, with
live read-only RPC reads - no name matching:

- ``bridge_live_locked_vs_minted``: locked token balance on one side
  vs minted totalSupply on the other. Fires only when minted exceeds
  locked, with both numbers in evidence.
- ``bridge_live_validator_quorum``: quorum threshold vs the live
  validator set, read from the bridge contract. Fires when the quorum
  can never be reached, the set is empty, or quorum is 1 (any single
  validator can authorize messages).
- ``bridge_live_nonce_continuity``: source emitted nonce vs
  destination processed nonce. Fires only when the destination is
  ahead of the source (messages processed that were never emitted).

Targets are compact specs (the bridge's two sides cannot be guessed
from one address):

    bridge-lock:<chainA>:<vaultA>:<tokenA>:<chainB>:<mintTokenB>
    bridge-quorum:<chain>:<bridge>[:<quorumSig>[:<countSig>]]
    bridge-nonce:<chainA>:<bridgeA>:<chainB>:<bridgeB>

Chains use the repo's ids (ethereum, bsc, polygon, arbitrum, base,
optimism). Every read is eth_call / eth_getCode / eth_getStorageAt
through the shared chain readers; nothing is ever sent. Findings are
candidates until the validator live-probes them; an unreadable side
is degraded, never clean.
"""
from __future__ import annotations

import time
from typing import List

from .. import proxy_bridge_live as pbl
from . import contract_chain as cc
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _target_spec(target: Target) -> str:
    return ((target.raw or "") or (target.normalized or "")).strip()


class _BaseBridgePlugin(Plugin):
    # No id here on purpose: an intermediate base must not register
    # itself (Plugin.id defaults to "base", which discover() would
    # collect as a phantom plugin). Concrete subclasses set id.
    id = ""
    accepts = ["crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    timeout_s = 120

    def _finding(self, check_id: str, result: dict,
                 chain: str) -> Finding:
        ev = {
            "severity": "high",
            "check": check_id,
            "report_class": "candidate",
            "live": True,
            "remediation": (
                "Halt new mints / messages on the affected side, "
                "reconcile both sides' ledgers from the bridge's own "
                "events, and re-run this check after the gap closes. "
                "Do not treat a candidate as proof of a drain - the "
                "validator must live-probe it first."),
        }
        ev.update({k: v for k, v in result.items()
                   if k not in ("check", "verdict", "broken")})
        return self._f(
            "web3", check_id,
            f"HIGH: {result['detail']}",
            source=f"bridge live invariant check ({check_id})",
            source_url=None,
            confidence=80, passive=True, evidence=ev)


class BridgeLiveLockedVsMintedPlugin(_BaseBridgePlugin):
    id = "bridge_live_locked_vs_minted"
    label = "Live Bridge Locked vs Minted"
    description = (
        "LIVE bridge invariant: locked token balance on one side vs "
        "minted totalSupply on the other, both read on-chain. Fires "
        "(candidate) only when minted exceeds locked, with both "
        "numbers in evidence. Read-only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        cfg = pbl.parse_bridge_target(_target_spec(target))
        if not isinstance(cfg, pbl.BridgeLockMintConfig):
            res = self._skipped(
                "bridge-lock spec needed: "
                "bridge-lock:<chainA>:<vaultA>:<tokenA>:<chainB>:"
                "<mintTokenB>")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        result = await pbl.check_locked_vs_minted(
            pbl.CtxReader(ctx), cfg)
        dur = int((time.monotonic() - t0) * 1000)
        if result["verdict"] == "degraded":
            res = self._degraded(
                f"bridge_live_locked_vs_minted: {result['detail']}")
            res.duration_ms = dur
            return res
        findings: List[Finding] = []
        if result["broken"]:
            findings.append(self._finding(
                self.id, result, cfg.chain_a))
        res = self._ok(
            findings,
            f"bridge_live_locked_vs_minted: locked "
            f"{result['locked']} (chain {cfg.chain_a} vault "
            f"{cfg.vault_a}) vs minted {result['minted']} (chain "
            f"{cfg.chain_b} {cfg.mint_token_b}); "
            f"{len(findings)} finding(s)")
        res.duration_ms = dur
        return res


class BridgeLiveValidatorQuorumPlugin(_BaseBridgePlugin):
    id = "bridge_live_validator_quorum"
    label = "Live Bridge Validator Quorum"
    description = (
        "LIVE bridge invariant: quorum threshold vs the live "
        "validator set, both read from the bridge contract. Fires "
        "(candidate) when the quorum is unreachable, the set is "
        "empty, or quorum is 1. Read-only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        cfg = pbl.parse_bridge_target(_target_spec(target))
        if not isinstance(cfg, pbl.BridgeQuorumConfig):
            res = self._skipped(
                "bridge-quorum spec needed: "
                "bridge-quorum:<chain>:<bridge>[:<quorumSig>"
                "[:<countSig>]]")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        result = await pbl.check_validator_quorum(
            pbl.CtxReader(ctx), cfg)
        dur = int((time.monotonic() - t0) * 1000)
        if result["verdict"] == "degraded":
            res = self._degraded(
                f"bridge_live_validator_quorum: {result['detail']}")
            res.duration_ms = dur
            return res
        findings: List[Finding] = []
        if result["broken"]:
            findings.append(self._finding(
                self.id, result, cfg.chain))
        res = self._ok(
            findings,
            f"bridge_live_validator_quorum: quorum "
            f"{result['quorum']} ({result['quorum_sig']}) vs live "
            f"validators {result['validator_count']} "
            f"({result['count_sig']}) on {cfg.bridge}; "
            f"{len(findings)} finding(s)")
        res.duration_ms = dur
        return res


class BridgeLiveNonceContinuityPlugin(_BaseBridgePlugin):
    id = "bridge_live_nonce_continuity"
    label = "Live Bridge Nonce Continuity"
    description = (
        "LIVE bridge invariant: source emitted nonce vs destination "
        "processed nonce, both read on-chain. Fires (candidate) only "
        "when the destination is ahead of the source. Read-only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        cfg = pbl.parse_bridge_target(_target_spec(target))
        if not isinstance(cfg, pbl.BridgeNonceConfig):
            res = self._skipped(
                "bridge-nonce spec needed: "
                "bridge-nonce:<chainA>:<bridgeA>:<chainB>:<bridgeB>")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        result = await pbl.check_nonce_continuity(
            pbl.CtxReader(ctx), cfg)
        dur = int((time.monotonic() - t0) * 1000)
        if result["verdict"] == "degraded":
            res = self._degraded(
                f"bridge_live_nonce_continuity: {result['detail']}")
            res.duration_ms = dur
            return res
        findings: List[Finding] = []
        if result["broken"]:
            findings.append(self._finding(
                self.id, result, cfg.chain_a))
        res = self._ok(
            findings,
            f"bridge_live_nonce_continuity: source nonce "
            f"{result['source_nonce']} (chain {cfg.chain_a}) vs "
            f"destination nonce {result['dest_nonce']} (chain "
            f"{cfg.chain_b}); {len(findings)} finding(s)")
        res.duration_ms = dur
        return res
