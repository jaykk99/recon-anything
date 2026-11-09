"""Flash-loan simulation matrix.

For each candidate (a contract function suspected of pricing off a spot AMM
read), the matrix:

  1. classifies the pricing dependency (static source markers + a dynamic
     displacement probe: how much does the price the contract uses move when
     a large swap hits the pair it reads?),
  2. runs an attack grid in LOCAL simulation (anvil): flash-borrow the base
     asset, manipulate the pair, call the suspect function, unwind, repay,
     and measure the unfunded stranger's NET balance delta after repayment
     and the stated cost model,
  3. emits one of SIM_DRAIN_POSITIVE / SIM_NO_EDGE / SIM_NOT_SPOT_ORACLE /
     SIM_ERROR, with full evidence (pair, reserves, loan size, in/out, net).

HARD RULES baked into the output shape: every row is an UNVERIFIED candidate
(`candidate_status`), the matrix never emits VERIFIED_REAL, and simulation
is never described as live proof. Live proof stays validator v2's job.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import amm
from .evm import (Rpc, balance_of, compile_source, decode_word, encode_args,
                  encode_call, hex_to_bytes)

# ------------------------------------------------------------------ verdicts
SIM_DRAIN_POSITIVE = "SIM_DRAIN_POSITIVE"
SIM_NO_EDGE = "SIM_NO_EDGE"
SIM_NOT_SPOT_ORACLE = "SIM_NOT_SPOT_ORACLE"
SIM_ERROR = "SIM_ERROR"

CANDIDATE_STATUS = "UNVERIFIED"  # sim output is a candidate, never a finding

# ------------------------------------------------------------------ cost model
GAS_COST_USD = 25.0          # flat per attack attempt, stated assumption
FLASH_FEE_BPS_LENDER = 9     # MockFlashLender fee (fixtures)
DISPLACEMENT_SPOT_THRESHOLD_PCT = 1.0   # below this, pricing is not spot-live
DEFAULT_GRID_USD = [100_000, 500_000, 1_000_000, 5_000_000]
E18 = 10 ** 18

# ------------------------------------------------------------------ static scan
SPOT_MARKERS = ["getAmountsOut", "getAmountOut", "getReserves", "slot0",
                "quoteExactInput"]
TWAP_MARKERS = ["twap", "TWAP", "cumulativePrice", "price0CumulativeLast",
                "price1CumulativeLast", "observe(", "AggregatorV3",
                "latestAnswer", "latestRoundData"]
ANTI_CONTRACT_PATTERNS = [
    r"require\s*\(\s*!\s*isContract\s*\(",
    r"require\s*\(\s*msg\.sender\s*==\s*tx\.origin",
    r"extcodesize\s*\(\s*msg\.sender",
]
VESTING_MARKERS = ["allocateDUEL", "vesting", "Vesting", "lockup",
                   "claimableAfter", "releaseTime"]


def classify_static(source: Optional[str]) -> Dict[str, Any]:
    """Marker scan over verified source. Evidence only; the dynamic probe is
    what settles spot dependency where it can run."""
    if not source:
        return {"source_available": False, "spot_markers": [],
                "twap_markers": [], "anti_contract_gate": False,
                "vesting_payout": False}
    spot = [m for m in SPOT_MARKERS if m in source]
    twap = [m for m in TWAP_MARKERS if m in source]
    gate = any(re.search(p, source) for p in ANTI_CONTRACT_PATTERNS)
    vesting = any(m in source for m in VESTING_MARKERS)
    return {"source_available": True, "spot_markers": spot,
            "twap_markers": twap, "anti_contract_gate": gate,
            "vesting_payout": vesting}


# ------------------------------------------------------------------ reserves
def read_reserves(rpc: Rpc, pair: str) -> Tuple[int, int, str, str]:
    """(reserve0, reserve1, token0, token1) via eth_call."""
    out = rpc.eth_call(pair, encode_call("getReserves()", [], []))
    r0, r1 = decode_word(out, 0), decode_word(out, 1)
    t0 = "0x" + rpc.eth_call(pair, encode_call("token0()", [], []))[12:].hex()
    t1 = "0x" + rpc.eth_call(pair, encode_call("token1()", [], []))[12:].hex()
    return r0, r1, t0.lower(), t1.lower()


def oriented_hops(rpc: Rpc, path_pairs: Sequence[str],
                  path_tokens: Sequence[str]) -> List[Tuple[int, int]]:
    """Reserves oriented along a token path: [(reserve_in, reserve_out)]."""
    hops = []
    for pair, tok_in in zip(path_pairs, path_tokens):
        r0, r1, t0, _t1 = read_reserves(rpc, pair)
        hops.append((r0, r1) if t0 == tok_in.lower() else (r1, r0))
    return hops


def displaced_quote(hops: List[Tuple[int, int]], reference_in: int,
                    manip_in: int, hop_index: int = 0) -> Dict[str, Any]:
    """Model a manipulation that BUYS the quote-path input asset on one hop
    (pays the hop's out-side asset in, takes the in-side asset out - the
    direction that pumps the input asset's unit price). Returns the quote
    before/after and displacement %. Pure math over observed reserves;
    cross-validated against executed fixture swaps in the pytest gate."""
    quote_before = amm.get_amounts_out(reference_in, hops)[-1]
    rin, rout = hops[hop_index]
    bought, new_rout, new_rin = amm.reserves_after_swap(manip_in, rout, rin)
    new_hops = list(hops)
    new_hops[hop_index] = (new_rin, new_rout)
    quote_after = amm.get_amounts_out(reference_in, new_hops)[-1]
    return {"quote_before": quote_before, "quote_after": quote_after,
            "displacement_pct": amm.displacement_pct(quote_before, quote_after),
            "manip_in": manip_in, "bought": bought, "hop_index": hop_index}


# ------------------------------------------------------------------ fixtures
_FIXTURE_CACHE: Dict[str, Tuple[str, list]] = {}


def _fixture_contract(name: str, source: str) -> Tuple[str, list]:
    if name not in _FIXTURE_CACHE:
        _FIXTURE_CACHE[name] = compile_source(source, name)
    return _FIXTURE_CACHE[name]


def _must_send(rpc: Rpc, frm: str, to: str, sig: str,
               types: Sequence[str], vals: Sequence[Any]) -> Dict[str, Any]:
    rcpt = rpc.send(frm, to, encode_call(sig, types, vals))
    if rcpt["status"] != "0x1":
        raise RuntimeError(f"send {sig} to {to} reverted")
    return rcpt


def deploy_fixtures(rpc: Rpc, deployer: str, source: str,
                    vault_kind: str) -> Dict[str, Any]:
    """Deploy the fixture world on a fresh local anvil.

    Tokens A (input) and B (payout/numeraire, treated as $1). Pair A/B is
    seeded 1,000,000 A / 50,000 B (A spot ~ 0.05 B). The vault holds
    400,000 B; the flash lender holds 600,000 B.
    """
    def dep(name: str, ctor: bytes = b"") -> str:
        bc, _abi = _fixture_contract(name, source)
        return rpc.deploy(deployer, bc, ctor)

    tok_a = dep("MockERC20", encode_args(["string", "string"], ["Token A", "TKA"]))
    tok_b = dep("MockERC20", encode_args(["string", "string"], ["Token B", "TKB"]))
    for tok, amt in ((tok_a, 2_000_000 * E18), (tok_b, 1_500_000 * E18)):
        _must_send(rpc, deployer, tok, "mint(address,uint256)",
                   ["address", "uint256"], [deployer, amt])
    pair = dep("MockV2Pair", encode_args(["address", "address"], [tok_a, tok_b]))
    _must_send(rpc, deployer, tok_a, "transfer(address,uint256)",
               ["address", "uint256"], [pair, 1_000_000 * E18])
    _must_send(rpc, deployer, tok_b, "transfer(address,uint256)",
               ["address", "uint256"], [pair, 50_000 * E18])
    _must_send(rpc, deployer, pair, "sync()", [], [])
    router = dep("MockRouter")
    _must_send(rpc, deployer, router, "setPair(address,address,address)",
               ["address", "address", "address"], [tok_a, tok_b, pair])
    lender = dep("MockFlashLender")
    _must_send(rpc, deployer, tok_b, "transfer(address,uint256)",
               ["address", "uint256"], [lender, 600_000 * E18])
    if vault_kind == "spot":
        vault = dep("SpotOracleVault", encode_args(
            ["address", "address", "address"], [router, tok_a, tok_b]))
        oracle = None
    elif vault_kind == "twap":
        unit = amm.unit_price(E18, [(1_000_000 * E18, 50_000 * E18)])
        oracle = dep("MockTwapOracle", encode_args(["uint256"], [unit]))
        vault = dep("TwapOracleVault", encode_args(
            ["address", "address", "address"], [oracle, tok_a, tok_b]))
    else:
        raise ValueError(f"unknown vault_kind {vault_kind}")
    _must_send(rpc, deployer, tok_b, "transfer(address,uint256)",
               ["address", "uint256"], [vault, 400_000 * E18])
    executor = dep("FlashExecutor")
    return {"token_a": tok_a, "token_b": tok_b, "pair": pair,
            "router": router, "lender": lender, "vault": vault,
            "oracle": oracle, "executor": executor}


def run_fixture_matrix(rpc: Rpc, deployer: str, source: str,
                       vault_kind: str = "spot",
                       grid_usd: Sequence[int] = (10_000, 25_000, 40_000),
                       probe_amount: int = 10_000 * E18) -> Dict[str, Any]:
    """Full matrix over a fixture vault: displacement probe (executed) +
    attack grid (executed). Returns one result row."""
    fx = deploy_fixtures(rpc, deployer, source, vault_kind)
    vault, pair = fx["vault"], fx["pair"]
    tok_a, tok_b, lender, executor = (fx["token_a"], fx["token_b"],
                                      fx["lender"], fx["executor"])

    def quote(amount: int) -> int:
        out = rpc.eth_call(vault, encode_call(
            "quoteConvert(uint256)", ["uint256"], [amount]))
        return decode_word(out, 0)

    r_a, r_b, _t0, _t1 = read_reserves(rpc, pair)  # token0 = A, token1 = B
    quote_before = quote(probe_amount)

    # --- displacement probe: executed manipulation swap, then revert -------
    manip_probe = max(grid_usd) * E18 * 98 // 100
    snap = rpc.snapshot()
    a_out_probe = amm.get_amount_out(manip_probe, r_b, r_a)
    _must_send(rpc, deployer, tok_b, "transfer(address,uint256)",
               ["address", "uint256"], [pair, manip_probe])
    _must_send(rpc, deployer, pair, "swap(uint256,uint256,address,bytes)",
               ["uint256", "uint256", "address", "bytes"],
               [a_out_probe, 0, deployer, b""])
    quote_after = quote(probe_amount)
    rpc.revert(snap)
    disp = displaced_quote([(r_a, r_b)], probe_amount, manip_probe, 0)
    displacement_pct = amm.displacement_pct(quote_before, quote_after)

    # --- attack grid --------------------------------------------------------
    cells: List[Dict[str, Any]] = []
    unit_pre = amm.unit_price(E18, [(r_a, r_b)])
    for loan_usd in grid_usd:
        loan = loan_usd * E18
        fee = max(loan * FLASH_FEE_BPS_LENDER // 10_000, 1)
        manip_in = loan * 98 // 100
        a_out, b_res_after, a_res_after = amm.reserves_after_swap(
            manip_in, r_b, r_a)
        unit_after = amm.unit_price(E18, [(a_res_after, b_res_after)])
        payout_modeled = a_out * unit_after // E18
        net_modeled = payout_modeled - manip_in - fee - int(GAS_COST_USD * E18)
        snap = rpc.snapshot()
        steps = [
            (tok_b, encode_call("transfer(address,uint256)",
                                ["address", "uint256"], [pair, manip_in])),
            (pair, encode_call("swap(uint256,uint256,address,bytes)",
                               ["uint256", "uint256", "address", "bytes"],
                               [a_out, 0, executor, b""])),
            (tok_a, encode_call("approve(address,uint256)",
                                ["address", "uint256"], [vault, a_out])),
            (vault, encode_call("convert(uint256)", ["uint256"], [a_out])),
        ]
        data = encode_args(["address[]", "bytes[]"],
                           [[t for t, _ in steps],
                            [hex_to_bytes(d) for _, d in steps]])
        rcpt = rpc.send(deployer, lender, encode_call(
            "flashLoan(address,address,uint256,bytes)",
            ["address", "address", "uint256", "bytes"],
            [executor, tok_b, loan, data]))
        executed = rcpt["status"] == "0x1"
        cell: Dict[str, Any] = {
            "loan_usd": loan_usd, "loan": loan, "manip_in": manip_in,
            "bought_input": a_out, "flash_fee": fee, "executed": executed,
            "net_modeled": net_modeled, "payout_modeled": payout_modeled,
        }
        if executed:
            bal_b = balance_of(rpc, tok_b, executor)
            bal_a = balance_of(rpc, tok_a, executor)
            value = bal_b + bal_a * unit_pre // E18
            cell.update({"executor_balance_b": bal_b,
                         "executor_balance_a": bal_a,
                         "net": value - int(GAS_COST_USD * E18)})
        else:
            cell["error"] = "attack tx reverted (repayment or vault liquidity)"
            cell["net"] = None
        rpc.revert(snap)
        cells.append(cell)

    spot_live = displacement_pct >= DISPLACEMENT_SPOT_THRESHOLD_PCT
    if not spot_live:
        verdict = SIM_NOT_SPOT_ORACLE
    elif any(c.get("net") is not None and c["net"] > 0 for c in cells):
        verdict = SIM_DRAIN_POSITIVE
    else:
        verdict = SIM_NO_EDGE
    return {
        "chain": "local-fixture", "address": vault,
        "function": "convert(uint256)", "candidate_status": CANDIDATE_STATUS,
        "verdict": verdict, "vault_kind": vault_kind,
        "classification": {
            "method": "executed probe on local fixture pair",
            "spot_live": spot_live, "displacement_pct": displacement_pct,
            "quote_before": quote_before, "quote_after": quote_after,
            "modeled_displacement_pct": disp["displacement_pct"],
            "pair": pair, "reserves": {"input": r_a, "payout": r_b},
        },
        "cells": cells,
        "cost_model": {"gas_usd_flat": GAS_COST_USD,
                       "flash_fee_bps": FLASH_FEE_BPS_LENDER,
                       "valuation": "pre-attack spot unit price"},
    }


# ------------------------------------------------------------------ fork runs
def run_fork_candidate(rpc: Rpc, spec: Dict[str, Any]) -> Dict[str, Any]:
    """Matrix over a real contract on a LOCAL FORK (read-only state).

    spec keys: chain, address, function, source (optional), price_view
    (optional eth_call signature returning a uint quote), quote_path
    {pairs, tokens, reference_in}, grid_usd, usd_per_manip_unit (how many
    USD one unit - 1e18 wei - of the manipulation asset is worth, from the
    path's own tail reserves), manip_hop (default 0).

    The displacement probe is modeled from live reserves with the exact V2
    math the fixture gate validates against execution. A full attack is
    executed only when the candidate is spot-live AND has no structural
    blocker AND an explicit attack spec was staged; otherwise the blocker /
    staging gap is the recorded reason.
    """
    row: Dict[str, Any] = {
        "chain": spec.get("chain"), "address": spec.get("address"),
        "function": spec.get("function"),
        "candidate_status": CANDIDATE_STATUS,
        "source_origin": spec.get("source_origin"),
        "spec_note": spec.get("note"),
    }
    static = classify_static(spec.get("source"))
    row["classification"] = {"static": static}
    blockers: List[str] = []
    if static["anti_contract_gate"]:
        blockers.append("suspect function rejects contract callers "
                        "(anti-contract gate): no atomic flash-loan execution "
                        "path exists for a stranger contract")
    if static["vesting_payout"]:
        blockers.append("payout routes through a vesting/locking contract: "
                        "even a successful price move pays locked, "
                        "non-liquid value, not an immediate drain")
    row["blockers"] = blockers

    qp = spec.get("quote_path")
    if not qp:
        if static["spot_markers"] and not static["twap_markers"]:
            row["verdict"] = SIM_ERROR
            row["error"] = ("spot-pricing markers present but no quote path "
                            "(pairs) staged for the displacement probe")
        else:
            row["verdict"] = SIM_NOT_SPOT_ORACLE
            row["error"] = None
        return row

    try:
        hops = oriented_hops(rpc, qp["pairs"], qp["tokens"])
    except Exception as e:  # noqa: BLE001
        row["verdict"] = SIM_ERROR
        row["error"] = f"could not read pair reserves on local fork: {e}"
        return row
    row["classification"]["hops_reserves"] = hops

    reference_in = qp.get("reference_in", E18)
    modeled_quote = amm.get_amounts_out(reference_in, hops)[-1]
    row["classification"]["modeled_quote"] = modeled_quote
    if spec.get("price_view"):
        try:
            live = rpc.eth_call(spec["address"], encode_call(
                spec["price_view"], [], []))
            row["classification"]["live_price_view"] = decode_word(live, 0)
        except Exception as e:  # noqa: BLE001
            row["classification"]["live_price_view_error"] = str(e)

    usd_per_unit = spec.get("usd_per_manip_unit")
    cells: List[Dict[str, Any]] = []
    max_disp = 0.0
    for loan_usd in spec.get("grid_usd", DEFAULT_GRID_USD):
        if not usd_per_unit:
            cells.append({"loan_usd": loan_usd, "executed": False,
                          "error": "usd_per_manip_unit not staged"})
            continue
        manip_in = int(loan_usd * E18 / usd_per_unit)
        try:
            disp = displaced_quote(hops, reference_in, manip_in,
                                   spec.get("manip_hop", 0))
        except Exception as e:  # noqa: BLE001
            cells.append({"loan_usd": loan_usd, "executed": False,
                          "error": f"displacement model failed: {e}"})
            continue
        max_disp = max(max_disp, disp["displacement_pct"])
        cells.append({"loan_usd": loan_usd, "executed": False,
                      "mode": "modeled displacement probe",
                      "manip_in": manip_in,
                      "quote_before": disp["quote_before"],
                      "quote_after": disp["quote_after"],
                      "displacement_pct": disp["displacement_pct"]})
    row["cells"] = cells
    row["classification"]["max_displacement_pct"] = max_disp
    spot_live = max_disp >= DISPLACEMENT_SPOT_THRESHOLD_PCT
    row["classification"]["spot_live"] = spot_live

    if not spot_live:
        row["verdict"] = SIM_NOT_SPOT_ORACLE
    elif blockers:
        row["verdict"] = SIM_NO_EDGE
        row["error"] = None
        row["note"] = ("spot-priced and displaceable, but no executable edge: "
                       + "; ".join(blockers))
    else:
        row["verdict"] = SIM_ERROR
        row["error"] = ("spot-priced and displaceable, but no attack spec "
                        "staged for full execution in this run; recorded as "
                        "an open candidate for the execution lane, NOT as a "
                        "finding")
    return row


def run_static_candidate(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Source-only classification for candidates whose pricing path cannot
    be staged (no verified pair set). Honest either way: no spot markers in
    the pricing path means not spot-oracle; markers without a stageable
    path is a recorded SIM_ERROR, never a guessed verdict."""
    static = classify_static(spec.get("source"))
    row: Dict[str, Any] = {
        "chain": spec.get("chain"), "address": spec.get("address"),
        "function": spec.get("function"),
        "candidate_status": CANDIDATE_STATUS,
        "source_origin": spec.get("source_origin"),
        "spec_note": spec.get("note"),
        "classification": {"static": static, "method": "static source scan"},
        "blockers": [],
    }
    if not static["source_available"]:
        row["verdict"] = SIM_ERROR
        row["error"] = "verified source unavailable; cannot classify pricing"
    elif static["twap_markers"] and not static["spot_markers"]:
        row["verdict"] = SIM_NOT_SPOT_ORACLE
    elif not static["spot_markers"]:
        row["verdict"] = SIM_NOT_SPOT_ORACLE
        row["note"] = "no spot-pricing markers in verified source"
    else:
        row["verdict"] = SIM_ERROR
        row["error"] = ("spot-pricing markers present but pair/quote path "
                        "not staged; needs path staging before a verdict")
    return row
