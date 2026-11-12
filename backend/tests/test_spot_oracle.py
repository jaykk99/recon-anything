"""Spot-oracle payout analyzer (100x lane L1): fixture discipline.

The vulnerable shapes (borrow / mint / redeem priced off AMM spot
reserves with no protection) MUST produce candidate-grade hits
with the recipient and the oracle evidence on the finding; every
protected or non-payout shape (TWAP, Chainlink, bounded spot,
spot-for-display) MUST stay completely silent.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts"))

import depth_benchmark_corpus as corpus  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.spot_oracle import SPEC_ID, \
    analyze_spot_oracle_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ADDR = "0x1111111111111111111111111111111111111111"

HELPER_SPLIT = """
interface IPair { function getReserves() external view returns (uint112 r0, uint112 r1, uint32 ts); }
contract VulnHelperSpot {
    IPair public pair;
    constructor(address _pair) { pair = IPair(_pair); }
    function _spotPrice() internal view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return (uint256(r1) * 1e18) / uint256(r0);
    }
    function borrow(uint256 collateralTokens) public {
        uint256 price = _spotPrice();
        uint256 amount = (collateralTokens * price) / 1e18;
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

RESERVE_GETTERS = """
interface IPair { function reserve0() external view returns (uint112); function reserve1() external view returns (uint112); }
contract VulnReserveGetters {
    IPair public pair;
    constructor(address _pair) { pair = IPair(_pair); }
    function borrow(uint256 collateralTokens) public {
        uint256 price = (uint256(pair.reserve1()) * 1e18) / uint256(pair.reserve0());
        uint256 amount = (collateralTokens * price) / 1e18;
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

BALANCEOF_RATIO = """
interface IERC20 { function balanceOf(address a) external view returns (uint256); }
contract VulnBalanceRatio {
    IERC20 public token0;
    IERC20 public token1;
    address public pair;
    function borrow(uint256 collateralTokens) public {
        uint256 price = (token1.balanceOf(pair) * 1e18) / token0.balanceOf(pair);
        uint256 amount = (collateralTokens * price) / 1e18;
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

BOUNDED_SPOT = """
interface IPair { function getReserves() external view returns (uint112 r0, uint112 r1, uint32 ts); }
contract CleanBoundedSpot {
    IPair public pair;
    uint256 public constant MIN_PRICE = 1e15;
    uint256 public constant MAX_PRICE = 1e21;
    constructor(address _pair) { pair = IPair(_pair); }
    function borrow(uint256 collateralTokens) public {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 price = (uint256(r1) * 1e18) / uint256(r0);
        require(price >= MIN_PRICE && price <= MAX_PRICE, "price out of bounds");
        uint256 amount = (collateralTokens * price) / 1e18;
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

SPOT_WITH_TWAP_DEVIATION = """
interface IPair { function getReserves() external view returns (uint112 r0, uint112 r1, uint32 ts); }
interface ITwapOracle { function consult(address token, uint256 amountIn) external view returns (uint256); }
contract CleanSpotDeviationChecked {
    IPair public pair;
    ITwapOracle public twapOracle;
    address public token;
    constructor(address _pair, address _oracle) { pair = IPair(_pair); twapOracle = ITwapOracle(_oracle); }
    function borrow(uint256 collateralTokens) public {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 price = (uint256(r1) * 1e18) / uint256(r0);
        uint256 twapPrice = twapOracle.consult(token, 1e18);
        require(price * 100 >= twapPrice * 95 && price * 100 <= twapPrice * 105, "deviation too large");
        uint256 amount = (collateralTokens * price) / 1e18;
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""


def candidates(src, contract_name=""):
    return [i for i in analyze_spot_oracle_source(src, "", contract_name)
            if i["report_class"] == "candidate"]


def test_benchmark_vuln_borrow_fires_with_evidence():
    hits = candidates(corpus.VULN_SPOT_ORACLE, "VulnOracleBorrow")
    assert len(hits) == 1
    h = hits[0]
    assert h["kind"] == SPEC_ID and h["id"] == SPEC_ID
    assert h["function"] == "borrow"
    assert h["severity"] == "high"
    assert h["recipient"] == "CALLER"
    assert h["pricing_source"] == "pair spot reserves"
    assert h["protection"] == "none found"
    assert "/" in h["price_expression"] and "r1" in h["price_expression"]
    assert h["evidence"]["pricing_source"] == "pair spot reserves"
    assert h["evidence"]["protection"] == "none found"


def test_mint_and_redeem_variants_fire():
    mint = candidates(corpus.VULN_SPOT_ORACLE_MINT, "VulnSpotMint")
    assert len(mint) == 1
    assert mint[0]["function"] == "mint"
    assert mint[0]["recipient"] == "CALLER"
    redeem = candidates(corpus.VULN_SPOT_ORACLE_REDEEM,
                        "VulnSpotRedeem")
    assert len(redeem) == 1
    assert redeem[0]["function"] == "redeem"
    assert redeem[0]["recipient"] == "CALLER-SUPPLIED"


def test_helper_split_pricing_fires_on_entry():
    hits = candidates(HELPER_SPLIT, "VulnHelperSpot")
    assert len(hits) == 1
    assert hits[0]["function"] == "borrow"
    assert hits[0]["recipient"] == "CALLER"


def test_reserve_getter_and_balanceof_ratio_shapes_fire():
    hits = candidates(RESERVE_GETTERS, "VulnReserveGetters")
    assert len(hits) == 1 and hits[0]["function"] == "borrow"
    hits = candidates(BALANCEOF_RATIO, "VulnBalanceRatio")
    assert len(hits) == 1 and hits[0]["function"] == "borrow"
    assert hits[0]["pricing_source"] == "spot token balances"


def test_protected_and_display_shapes_stay_silent():
    for src, name in (
            (corpus.CLEAN_ORACLE_TWAP, "CleanTwapBorrow"),
            (corpus.CLEAN_ORACLE_CHAINLINK, "CleanChainlinkBorrow"),
            (corpus.CLEAN_SPOT_DISPLAY, "CleanSpotDisplay"),
            (BOUNDED_SPOT, "CleanBoundedSpot"),
            (SPOT_WITH_TWAP_DEVIATION, "CleanSpotDeviationChecked")):
        items = analyze_spot_oracle_source(src, "", name)
        assert items == [], f"{name}: fired {items}"


def test_unrelated_clean_corpus_stays_silent():
    for case in corpus.SOURCE_CASES:
        if case["id"].startswith("vuln_spot_oracle"):
            continue
        items = analyze_spot_oracle_source(
            case["source"], "", case["contract_name"])
        assert items == [], f"{case['id']}: fired {items}"


def test_plugin_registered():
    reg = discover()
    assert SPEC_ID in reg
    assert len(reg) == 1233, f"registry size {len(reg)}, expected 1233"


# ---------------------------------------------------------------------------
# Plugin run() end-to-end (chain layer stubbed, recipient_first pattern)
# ---------------------------------------------------------------------------

class FakeCtx:
    def __init__(self, shared=None):
        self.keys = {}
        self.mode = "passive"
        self.http = None
        self.limiter = None
        self.cache = None
        self.run_id = "test"
        self.module_overrides = {}
        self.shared = shared or {}

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


def _patch(monkeypatch, source):
    async def fake_get_code(ctx, chain, address):
        return "0x60006000"

    async def fake_source(ctx, chain, address, key=None):
        return source

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)


def _meta(source):
    if source is None:
        return None
    return {"source": source, "contract_name": "Fixture",
            "compiler": "v0.8.20+commit", "proxy": False,
            "implementation": "", "origin": "Blockscout"}


def _target():
    return Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                  normalized=f"ethereum:{ADDR}")


def test_plugin_run_flags_vulnerable_with_evidence(monkeypatch):
    _patch(monkeypatch, _meta(corpus.VULN_SPOT_ORACLE))
    res = asyncio.run(discover()[SPEC_ID]().run(_target(), FakeCtx()))
    hits = [f for f in res.findings if f.key == SPEC_ID]
    assert hits
    for h in hits:
        assert h.evidence["report_class"] == "candidate"
        assert h.evidence["recipient"] == "CALLER"
        assert h.evidence["pricing_source"] == "pair spot reserves"
        assert h.evidence["protection"] == "none found"


def test_plugin_run_clean_source_no_findings(monkeypatch):
    _patch(monkeypatch, _meta(corpus.CLEAN_ORACLE_TWAP))
    res = asyncio.run(discover()[SPEC_ID]().run(_target(), FakeCtx()))
    assert [f for f in res.findings if f.key == SPEC_ID] == []
