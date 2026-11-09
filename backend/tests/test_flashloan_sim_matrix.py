"""Gate for the flash-loan simulation matrix.

- keccak / ABI codec vectors (independently known selectors).
- AMM math hand-checks (values computed by hand from the V2 formula).
- Fixture gate on a local anvil: the DUEL-shaped spot-oracle vault MUST
  come back SIM_DRAIN_POSITIVE with measured net matching the pure-Python
  modeled net (the hand-checkable accounting case); the TWAP-priced vault
  MUST come back SIM_NOT_SPOT_ORACLE with ~0 displacement and no positive
  cell.
- Output discipline: rows are UNVERIFIED candidates, never VERIFIED_REAL.

Simulation is local-only; these tests never touch a live chain.
"""
from __future__ import annotations

import json
import os

import pytest

from app.flashsim import amm, matrix as mx
from app.flashsim.evm import Anvil, encode_call, find_anvil, find_solc, selector

FIXTURE_SOL = os.path.join(os.path.dirname(__file__), "..", "app",
                           "flashsim", "fixtures", "FlashSimFixtures.sol")
E18 = 10 ** 18

needs_evm = pytest.mark.skipif(not (find_anvil() and find_solc()),
                               reason="anvil/solc not available")


# ------------------------------------------------------------------ codec
def test_keccak_selector_vectors():
    assert selector("transfer(address,uint256)").hex() == "a9059cbb"
    assert selector("balanceOf(address)").hex() == "70a08231"
    assert selector("getReserves()").hex() == "0902f1ac"


def test_encode_call_shape():
    data = encode_call("balanceOf(address)", ["address"],
                       ["0x000000000000000000000000000000000000dEaD"])
    assert data.startswith("0x70a08231")
    assert data.endswith("00000000000000000000000000000000000000000000000000000000dead".replace(" ", "")) or \
        "dead" in data[-8:]


# ------------------------------------------------------------------ AMM math
def test_amm_handcheck():
    # By hand: 1000*997*100000 / (100000*1000 + 1000*997)
    #        = 99,700,000,000 / 100,997,000 = 987.09... -> 987
    assert amm.get_amount_out(1000, 100_000, 100_000) == 987
    assert amm.get_amount_out(0, 100_000, 100_000) == 0
    # Multi-hop composes single hops.
    hops = [(100_000, 50_000), (200_000, 400_000)]
    step = amm.get_amount_out(1000, *hops[0])
    assert amm.get_amounts_out(1000, hops) == [1000, step,
                                               amm.get_amount_out(step, *hops[1])]
    # Flash repayment: ceil(1000 * 1000 / 997) = ceil(1003.009...) = 1004
    assert amm.flash_repay_amount(1000) == 1004
    assert amm.flash_repay_amount(997) == 1000


def test_displacement_direction():
    hops = [(1_000_000 * E18, 50_000 * E18)]
    disp = mx.displaced_quote(hops, E18, 39_200 * E18, 0)
    assert disp["quote_after"] > disp["quote_before"]
    assert disp["displacement_pct"] > 100.0  # thin pool, big pump


# ------------------------------------------------------------------ static scan
def test_static_classification():
    duel_like = (
        "function getRainValue() public view returns (uint256) {"
        " return router.getAmountsOut(1e18, route)[2]; }"
        "function convertRain(uint256 a) external {"
        " require(!isContract(msg.sender), \"ACCESS_FORBIDDEN\");"
        " IVesting(v).allocateDUEL(msg.sender, x, y); }"
    )
    st = mx.classify_static(duel_like)
    assert "getAmountsOut" in st["spot_markers"]
    assert st["anti_contract_gate"] is True
    assert st["vesting_payout"] is True
    twap_like = "contract C { uint256 p; function q() view returns (uint256) { return oracle.latestAnswer(); } }"
    st2 = mx.classify_static(twap_like)
    assert "latestAnswer" in st2["twap_markers"]
    assert not st2["spot_markers"]


# ------------------------------------------------------------------ fixtures
@needs_evm
def test_fixture_spot_vault_drains():
    with open(FIXTURE_SOL) as f:
        source = f.read()
    with Anvil(18711) as rpc:
        row = mx.run_fixture_matrix(rpc, rpc.accounts()[0], source, "spot")
    assert row["verdict"] == mx.SIM_DRAIN_POSITIVE
    assert row["candidate_status"] == "UNVERIFIED"
    assert "VERIFIED_REAL" not in json.dumps(row)
    assert row["classification"]["displacement_pct"] > 50.0
    good = [c for c in row["cells"] if c.get("net") is not None and c["net"] > 0]
    assert good, f"no positive cell: {row['cells']}"
    for cell in good:
        # Measured net must match the pure-Python modeled net closely:
        # same integer AMM math, only division-order rounding differs.
        tol = max(E18, abs(cell["net_modeled"]) // 100)
        assert abs(cell["net"] - cell["net_modeled"]) <= tol, cell


@needs_evm
def test_fixture_twap_vault_no_edge():
    with open(FIXTURE_SOL) as f:
        source = f.read()
    with Anvil(18712) as rpc:
        row = mx.run_fixture_matrix(rpc, rpc.accounts()[0], source, "twap")
    assert row["verdict"] == mx.SIM_NOT_SPOT_ORACLE
    assert row["candidate_status"] == "UNVERIFIED"
    assert abs(row["classification"]["displacement_pct"]) < 1.0
    assert not any(c.get("net") is not None and c["net"] > 0
                   for c in row["cells"])
