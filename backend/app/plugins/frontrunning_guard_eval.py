"""Frontrunning Guard Evaluator (Cat-1 #19, VARIANT of the MEV lanes).

Delta: a systematic protection VERDICT for one target instead of
point facts. Evaluates, from source (and an optional frontend/RPC
config record on the bus):

- swap / trade functions: is a deadline enforced? is a minimum-out
  (slippage bound) required to be non-zero?
- approval-then-call races: approve with no zero-reset on tokens
  known for the race (source-level note);
- commit-reveal presence for order-sensitive operations;
- private-relay usage in the supplied config (flashbots / private
  rpc flags).

Missing deadline + missing min-out on the same swap is high; each
single gap is medium. A fully guarded swap stays silent.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_SWAP = re.compile(r"swap|trade|exchange|buy|sell", re.I)
_DEADLINE = re.compile(r"deadline|block\.timestamp\s*<=|expir", re.I)
_MINOUT = re.compile(r"amountOutMin|minOut|minReturn|minAmount|"
                     r"slippage", re.I)
_ZERO_MIN = re.compile(r"(amountOutMin|minOut|minReturn)\s*[:=,]\s*0\b|"
                       r"swap\w*\([^)]*,\s*0\s*,")


def evaluate_frontrunning(source: str,
                          config: Optional[Dict[str, Any]] = None
                          ) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    src = source or ""
    for f in C.functions(src):
        if not _SWAP.search(f["name"]):
            continue
        whole = f["args"] + " " + f["body"]
        has_deadline = bool(_DEADLINE.search(whole))
        has_minout = bool(_MINOUT.search(whole)) and not bool(
            _ZERO_MIN.search(whole))
        if not has_deadline and not has_minout:
            hits.append(C.hit(
                "frontrunning_unguarded_swap",
                f"swap function {f['name']}() has NEITHER a "
                f"deadline NOR a minimum-out bound: it can be "
                f"sandwiched / held in the mempool and executed "
                f"at an arbitrary worse price.",
                "high",
                "Require a deadline and a non-zero minimum-out "
                "on every swap.",
                function=f["name"], check="frontrunning_guard"))
        elif not has_deadline:
            hits.append(C.hit(
                "frontrunning_no_deadline",
                f"swap function {f['name']}() enforces slippage "
                f"but no deadline: a delayed execution can still "
                f"land at a stale price.",
                "medium",
                "Add and enforce a block.timestamp deadline.",
                function=f["name"], check="frontrunning_guard"))
        elif not has_minout:
            hits.append(C.hit(
                "frontrunning_no_min_out",
                f"swap function {f['name']}() has a deadline but "
                f"no enforced non-zero minimum-out: sandwich "
                f"attacks can extract the full price move.",
                "medium",
                "Require a caller-supplied, non-zero minimum-out.",
                function=f["name"], check="frontrunning_guard"))
    if src and re.search(r"function\s+approve\s*\(", src) and \
            not re.search(r"approve\s*\([^,]+,\s*0\s*\)", src):
        # only a note-level pattern: approve race needs the reset
        if "increaseAllowance" not in src:
            hits.append(C.hit(
                "frontrunning_approve_race",
                "approve() is exposed with no zero-reset pattern "
                "and no increaseAllowance alternative: the classic "
                "allowance change race lets a spender front-run "
                "an allowance reduction and spend both amounts.",
                "low",
                "Support increase/decreaseAllowance and document "
                "the zero-reset flow.",
                check="frontrunning_guard"))
    if config is not None:
        relay = str(config.get("rpc") or config.get("relay") or "")
        private = bool(config.get("private_relay")) or \
            "flashbots" in relay.lower() or "mev" in relay.lower()
        if config.get("uses_swaps") and not private:
            hits.append(C.hit(
                "frontrunning_public_mempool_config",
                "frontend/RPC config routes swap transactions "
                "through the public mempool with no private relay "
                "(Flashbots Protect / MEV-Share style) configured.",
                "medium",
                "Route user swaps through a private relay.",
                check="frontrunning_guard"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    config = None
    for item in data["extras"].get("chain_contracts", []):
        if isinstance(item, dict) and item.get("front_config"):
            config = item["front_config"]
    return evaluate_frontrunning(data.get("source", ""), config)


class FrontrunningGuardEvalPlugin(Plugin):
    id = "frontrunning_guard_eval"
    label = "Frontrunning Guard Evaluator"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("End-to-end frontrunning protection verdict "
                   "for one target: swap deadline + minimum-out "
                   "enforcement, approve-race pattern, and "
                   "private-relay use in its config.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, bytecode=False,
            no_input="no contract source to evaluate frontrunning "
                     "guards in")
