"""Flashloan Simulator (Cat-1 #11, VARIANT of contract_fuzz /
anvil_fork_probe).

Delta: flashloan-funded attack MODELING as a scenario layer -
borrow -> manipulate the spot price a victim contract reads ->
extract -> repay - evaluated against the target's source patterns
(does it price from spot reserves / pair balances? does it expose
a flashLoan / flash borrower surface? is there TWAP or slippage
protection?) and, when a numeric scenario is supplied on the bus
(flashloan_scenario: {spot_price, reference_price, borrow,
victim_exposure}), the extractable spread is estimated.

BOUNDARY: local fixtures/forks ONLY - nothing is broadcast, no
live transaction is ever sent. Every finding is mechanically
stamped UNVERIFIED by the shared emitter.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_SPOT = re.compile(r"getReserves\s*\(|balanceOf\s*\(\s*address\s*\(\s*pair|"
                   r"pair\.balanceOf|getAmountsOut|slot0\s*\(")
_FLASH = re.compile(r"flashLoan|flash\s*\(|onFlashLoan|executeOperation|"
                    r"receiveFlashLoan|dYdX|SoloLoan")
_PROTECT = re.compile(r"twap|TWAP|consult\s*\(|observe\s*\(|"
                      r"amountOutMin|slippage|minReturn|deadline")


def analyze_flashloan(source: str,
                      scenario: Optional[Dict[str, Any]] = None
                      ) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    src = source or ""
    if scenario:
        try:
            spot = float(scenario.get("spot_price", 0))
            ref = float(scenario.get("reference_price", 0))
            exposure = float(scenario.get("victim_exposure", 0))
            if spot > 0 and ref > 0 and exposure > 0:
                dev = abs(spot - ref) / ref
                if dev >= 0.02:
                    est = exposure * dev
                    hits.append(C.hit(
                        "flashloan_scenario_spread",
                        f"scenario model: spot price deviates "
                        f"{dev * 100:.1f}% from reference under a "
                        f"flashloan-funded push; a victim pricing "
                        f"off spot with exposure {exposure:g} "
                        f"leaks an estimated {est:,.2f} before "
                        f"repayment. Local scenario math only.",
                        "high" if dev >= 0.05 else "medium",
                        "Price from a TWAP / robust oracle and "
                        "enforce slippage bounds; never settle "
                        "against a manipulable spot price.",
                        deviation_bps=int(dev * 10000),
                        estimated_extraction=est,
                        check="flashloan_simulator"))
        except Exception:
            pass
    if src.strip():
        spot = bool(_SPOT.search(src))
        flash = bool(_FLASH.search(src))
        protected = bool(_PROTECT.search(src))
        if spot and not protected:
            hits.append(C.hit(
                "flashloan_spot_price_victim",
                "contract prices from spot reserves / pair state "
                "with no TWAP, slippage or deadline protection "
                "found: the borrow-manipulate-extract-repay "
                "flashloan scenario applies to it in a local "
                "fixture model.",
                "high",
                "Consume a TWAP or Chainlink price and enforce "
                "minimum-out bounds on every spot-priced trade.",
                check="flashloan_simulator"))
        if flash and spot and not protected:
            hits.append(C.hit(
                "flashloan_surface_and_spot_pricing",
                "contract both exposes a flash-loan surface and "
                "reads spot pricing unprotected: an attacker can "
                "fund the manipulation from the contract's own "
                "liquidity in the local model.",
                "high",
                "Separate flash liquidity from pricing inputs and "
                "add oracle/TWAP protection.",
                check="flashloan_simulator"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    scenario = None
    for item in data["extras"].get("flashloan_scenario", []):
        if isinstance(item, dict):
            scenario = item
            break
    return analyze_flashloan(data.get("source", ""), scenario)


class FlashloanSimulatorPlugin(Plugin):
    id = "flashloan_simulator"
    label = "Flashloan Simulator"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Flashloan-funded attack modeling "
                   "(borrow/manipulate/extract/repay) against a "
                   "target's spot-pricing and flash surfaces. "
                   "Local fixtures/forks only; every finding is "
                   "stamped UNVERIFIED.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze,
            extras=("flashloan_scenario",), fetch=True, stamp=True,
            bytecode=False,
            no_input="no source or flashloan scenario to model")
