"""Crypto Contract Drain Analyzer (crypto_drain_scanner) tests.

Layers:
1. Pure analyzer against fixture sources: a canary vault whose
   unguarded functions MUST flag (emergencyWithdraw draining the
   full balance to msg.sender, rescueTokens, sweepTo via
   .call{value:}, selfdestruct to a parameter), and clean controls
   that MUST NOT flag (onlyOwner versions, require(msg.sender ==
   owner), the BNB-style `if (msg.sender != owner) throw;` gate,
   a custom only* modifier, an own-balance withdraw, a view
   function, an internal helper, transferFrom pulling the caller's
   own tokens in).
2. Interface declarations (no body) never flag.
3. Plugin runs with the chain layer stubbed (no network): canary
   source path with full evidence shape, clean source path, and
   the no-verified-source path (fails honest, flags nothing).
4. Registry discovery picks the plugin up.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import crypto_drain  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ADDR = "0x" + "ab" * 20

CANARY_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract CanaryVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function emergencyWithdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }

    function rescueTokens(address token, address to) external {
        IERC20(token).transfer(to, IERC20(token).balanceOf(address(this)));
    }

    function sweepTo(address to, uint256 amount) external {
        (bool ok, ) = payable(to).call{value: amount}("");
        require(ok, "sweep failed");
    }

    function kill(address payable beneficiary) external {
        selfdestruct(beneficiary);
    }
}
"""

CLEAN_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract CleanVault {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function emergencyWithdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function rescueTokens(address token, address to, uint256 amount)
        external onlyOwner
    {
        IERC20(token).transfer(to, amount);
    }

    function sweep() public {
        require(msg.sender == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }

    function collectFees() public onlyRouter {
        payable(msg.sender).transfer(address(this).balance);
    }

    function withdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }

    function pullTokens(address token, uint256 amount) external {
        IERC20(token).transferFrom(msg.sender, msg.sender, amount);
    }

    function quoteWithdraw(uint256 amount) public view returns (uint256) {
        return amount * 2;
    }

    function _pay(address to, uint256 amount) internal {
        payable(to).transfer(amount);
    }
}
"""

# Old-style (0.4.x) gate the plugin's gate regex does not know:
# a bare sender comparison with throw. Recipient is msg.sender, so
# only the comparison discipline keeps this from flagging.
BNB_STYLE_SOURCE = r"""
pragma solidity ^0.4.24;

contract OldToken {
    address public owner;

    function withdrawEther(uint256 amount) public {
        if (msg.sender != owner) throw;
        payable(msg.sender).transfer(amount);
    }

    function withdrawAll() public {
        if (msg.sender != owner) throw;
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""

# StandardCrowdsale shape (the REQ live-smoke false positive,
# 2026-11-02): the token payout is derived from the msg.value the
# caller just paid in the same transaction - a purchase, not a
# drain. MUST NOT flag.
CROWDSALE_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Sale {
    IERC20 public token;
    uint256 public rate = 100;

    function buyTokens() public payable {
        uint256 weiAmount = msg.value;
        uint256 tokens = weiAmount * rate;
        require(token.transfer(msg.sender, tokens));
    }
}
"""

# Same payable shape, but the payout amount is a raw caller
# parameter - not bought with msg.value. Anyone could name any
# amount and take it. MUST flag.
PAYABLE_PARAM_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract LooseSale {
    IERC20 public token;

    function buyTokens(uint256 tokens) public payable {
        require(token.transfer(msg.sender, tokens));
    }
}
"""

# The USDT live-smoke shape (2026-11-02): the token's own ERC20
# overrides delegate to super - the call debits the caller's
# balance / enforces the caller's allowance inside the contract's
# own token implementation. MUST NOT flag.
SUPER_TOKEN_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LegacyToken {
    function transferFrom(address _from, address _to, uint _value)
        public whenNotPaused
    {
        return super.transferFrom(_from, _to, _value);
    }

    function transfer(address _to, uint _value) public {
        return super.transfer(_to, _value);
    }
}
"""

INTERFACE_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IDrainable {
    function emergencyWithdraw() external;
    function rescueTokens(address token, address to, uint256 amount) external;
    function kill(address payable beneficiary) external;
}
"""


# ---------------------------------------------------------------------------
# 1 + 2. Pure analyzer
# ---------------------------------------------------------------------------

def _flagged(src):
    return crypto_drain.analyze_drain_source(src)


def test_canary_flags_all_drain_kinds():
    hits = _flagged(CANARY_SOURCE)
    by_fn = {h["function"]: h for h in hits}
    assert set(by_fn) == {"emergencyWithdraw", "rescueTokens",
                          "sweepTo", "kill"}
    assert by_fn["emergencyWithdraw"]["drain_kind"] == \
        "full_balance_sweep"
    assert by_fn["rescueTokens"]["drain_kind"] == "token_rescue"
    assert by_fn["sweepTo"]["drain_kind"] == "withdraw_sweep"
    assert by_fn["kill"]["drain_kind"] == "selfdestruct"
    for h in hits:
        assert h["kind"] == "unprotected_drain"
        assert h["severity"] == "high"
        assert h["code"]  # the finding SHOWS the code


def test_canary_emergency_withdraw_shows_code():
    hits = [h for h in _flagged(CANARY_SOURCE)
            if h["function"] == "emergencyWithdraw"]
    assert len(hits) == 1
    assert "address(this).balance" in hits[0]["code"]
    assert hits[0]["recipient"] == "msg.sender"


def test_clean_controls_never_flag():
    assert _flagged(CLEAN_SOURCE) == []


def test_bnb_style_throw_gate_never_flags():
    assert _flagged(BNB_STYLE_SOURCE) == []


def test_interface_declarations_never_flag():
    assert _flagged(INTERFACE_SOURCE) == []


def test_crowdsale_purchase_payout_never_flags():
    assert _flagged(CROWDSALE_SOURCE) == []


def test_super_token_overrides_never_flag():
    assert _flagged(SUPER_TOKEN_SOURCE) == []


def test_payable_param_amount_still_flags():
    hits = _flagged(PAYABLE_PARAM_SOURCE)
    assert len(hits) == 1
    assert hits[0]["function"] == "buyTokens"
    assert hits[0]["drain_kind"] == "token_rescue"


# ---------------------------------------------------------------------------
# 3. Plugin runs (chain layer stubbed, no network)
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


def _patch(monkeypatch, code_by_chain, source):
    async def fake_get_code(ctx, chain, address):
        return code_by_chain.get(chain.id)

    async def fake_source(ctx, chain, address, key=None):
        return source

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)


def _run(source, raw=None):
    raw = raw or f"ethereum:{ADDR}"
    src_meta = None
    if source is not None:
        src_meta = {"source": source, "contract_name": "Fixture",
                    "compiler": "v0.8.20+commit", "proxy": False,
                    "implementation": "", "origin": "Blockscout"}
    return src_meta


def test_plugin_flags_canary_with_evidence(monkeypatch):
    _patch(monkeypatch, {"ethereum": "0x60006000"},
           _run(CANARY_SOURCE))
    p = crypto_drain.CryptoDrainPlugin()
    target = Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                    normalized=f"ethereum:{ADDR}")
    res = asyncio.run(p.run(target, FakeCtx()))
    drains = [f for f in res.findings if f.key == "unprotected_drain"]
    assert {f.evidence["function"] for f in drains} == \
        {"emergencyWithdraw", "rescueTokens", "sweepTo", "kill"}
    for f in drains:
        ev = f.evidence
        assert ev["severity"] == "high"
        assert ev["gated"] is False
        assert ev["ungated_basis"]
        assert ev["chain"] == "ethereum"
        assert ev["address"] == ADDR
        assert ev["contract_role"] == "standalone"
        assert ev["code"]
    ew = [f for f in drains
          if f.evidence["function"] == "emergencyWithdraw"][0]
    assert "address(this).balance" in ew.evidence["code"]
    assert ew.evidence["drain_kind"] == "full_balance_sweep"
    assert "4 unprotected drain(s) found" in res.reason


def test_plugin_clean_source_no_drains(monkeypatch):
    _patch(monkeypatch, {"ethereum": "0x60006000"},
           _run(CLEAN_SOURCE))
    p = crypto_drain.CryptoDrainPlugin()
    target = Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                    normalized=f"ethereum:{ADDR}")
    res = asyncio.run(p.run(target, FakeCtx()))
    assert [f for f in res.findings
            if f.key == "unprotected_drain"] == []
    assert "0 unprotected drain(s) found" in res.reason


def test_plugin_no_verified_source_flags_nothing(monkeypatch):
    _patch(monkeypatch, {"ethereum": "0x60006000"}, None)
    p = crypto_drain.CryptoDrainPlugin()
    target = Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                    normalized=f"ethereum:{ADDR}")
    res = asyncio.run(p.run(target, FakeCtx()))
    assert [f for f in res.findings
            if f.key == "unprotected_drain"] == []
    assert "without verified source" in res.reason


def test_plugin_no_address_skips_clean():
    p = crypto_drain.CryptoDrainPlugin()
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(p.run(target, FakeCtx()))
    assert res.findings == []


# ---------------------------------------------------------------------------
# 4. Registry
# ---------------------------------------------------------------------------

def test_registry_discovers_drain_plugin():
    reg = discover()
    assert "crypto_drain_scanner" in reg
    assert reg["crypto_drain_scanner"] is \
        crypto_drain.CryptoDrainPlugin
