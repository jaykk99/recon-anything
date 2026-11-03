"""Contract Fuzz lane (contract_fuzz) tests.

Layers:
1. Pure helpers: pragma/solc resolution, bundle scoping (test/mock
   units dropped, target + ancestors kept), ABI wrapper planning,
   harness generation (accounting, properties, token-mode dialect),
   Echidna output parsing, sequence translation, static recipient
   classification of the culprit function.
2. Plugin behavior with NO engine/subprocess: a fast/default
   context is refused with one info note; a missing engine binary
   reports fuzz_inconclusive(engine_absent), never a fake result.
3. LIVE canaries against the real Echidna + solc on this machine
   (skipped when either is absent - the same availability contract
   the plugin itself follows):
   - A: ungated drain paying msg.sender MUST confirm
     (fuzz_confirmed, recipient CALLER, counterexample present);
   - B: the same drain behind onlyOwner MUST NOT confirm;
   - C: self-service deposit/withdraw-own MUST NOT confirm (the
     claim accounting settles returns against own deposits);
   - D: a free public mint MUST confirm on the token property.
4. Registry discovery picks the plugin up (count 655 = master 654
   + this plugin).
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import contract_fuzz as cf  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ENGINE = cf.fuzz_engine()
SOLC = cf.resolve_solc("pragma solidity ^0.8.20;")
needs_engine = pytest.mark.skipif(
    not ENGINE or not SOLC,
    reason="echidna binary or local solc not installed on this VM")

VAULT_BODY = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FuzzVault {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawMine() external {
        uint256 a = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(a);
    }
%s
    receive() external payable {}
}
"""

CANARY_A = VAULT_BODY % r"""
    function drain() external {
        payable(msg.sender).transfer(address(this).balance);
    }
"""

CANARY_B = VAULT_BODY % r"""
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
    function drain() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
"""

CANARY_C = VAULT_BODY % ""

CANARY_D = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FreeToken {
    mapping(address => uint256) public balanceOf;

    function mint(uint256 a) external {
        balanceOf[msg.sender] += a;
    }
}
"""

ECHIDNA_FAILURE_FIXTURE = """\
[2026-11-03 14:30:00.00] Compiling `FuzzProject.sol`... Done!
echidna_stranger_no_eth_profit: failed!
  Reason: ReturnFalse
  Call sequence:
    ReconFuzzHarness.fz_deposit_0() Time delay: 1 seconds Block delay: 1
    ReconFuzzHarness.fz_drain_1()

Traces:

Total calls: 1234
Seed: 424242
"""


class FakeCtx:
    """Heavy-lane context by default (module override marker)."""

    def __init__(self, shared=None, run_id="test", heavy=True):
        self.keys = {}
        self.mode = "active"
        self.http = None
        self.limiter = None
        self.cache = None
        self.run_id = run_id
        self.module_overrides = {"contract_fuzz": "heavy"} if heavy \
            else {}
        self.shared = shared or {}

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


def _plugin(**attrs):
    p = cf.ContractFuzzPlugin()
    for k, v in attrs.items():
        setattr(p, k, v)
    return p


def _run(plugin, ctx, raw="fuzz"):
    return asyncio.run(plugin.run(
        Target(raw=raw, type="url", normalized=raw), ctx))


# ---------------------------------------------------------------------------
# 1. Pure helpers
# ---------------------------------------------------------------------------

def test_pragma_and_flavor():
    assert cf.pragma_version("pragma solidity ^0.8.20;") == (0, 8, 20)
    assert cf.pragma_version("pragma solidity 0.5.17;") == (0, 5, 17)
    assert cf.pragma_version("no pragma here") is None
    assert cf.harness_flavor((0, 8, 26)) == "modern"
    assert cf.harness_flavor((0, 7, 6)) == "legacy"
    assert cf.harness_flavor((0, 6, 12)) == "legacy"
    assert cf.harness_flavor((0, 5, 17)) == "unsupported"
    assert cf.harness_flavor((0, 0, 0)) == "modern"  # shim


def test_resolve_solc_matches_pragma():
    if not SOLC:
        pytest.skip("no local solc on this VM")
    assert os.path.isfile(SOLC)
    path = cf.resolve_solc("pragma solidity ^0.8.20;")
    assert path and os.path.isfile(path)


def test_scope_drops_test_units_and_picks_target():
    bundle = (
        "// SPDX-License-Identifier: MIT\n"
        "// ==== contracts/Token.sol ====\n"
        "pragma solidity ^0.8.20;\n"
        "import \"./Lib.sol\";\n"
        "contract MyToken { function mint(uint256 a) external {} }\n"
        "// ==== contracts/Lib.sol ====\n"
        "pragma solidity ^0.8.20;\n"
        "library Lib { function f(uint256 x) internal pure returns (uint256) { return x; } }\n"
        "// ==== contracts/test/MockToken.sol ====\n"
        "pragma solidity ^0.8.20;\n"
        "contract MockToken { function drain() external {} }\n"
    )
    scoped, name = cf.build_scoped_source(bundle, "MyToken")
    assert name == "MyToken"
    assert "MockToken" not in scoped
    assert 'import "' not in scoped
    assert scoped.count("pragma solidity") == 1
    # No hint: the last concrete contract in kept units wins, and
    # the test unit is still excluded from the choice.
    _s2, name2 = cf.build_scoped_source(bundle)
    assert name2 == "MyToken"


def test_plan_wrappers_and_constructor():
    abi = [
        {"type": "function", "name": "balanceOf",
         "stateMutability": "view",
         "inputs": [{"type": "address"}],
         "outputs": [{"type": "uint256"}]},
        {"type": "function", "name": "deposit",
         "stateMutability": "payable", "inputs": []},
        {"type": "function", "name": "withdraw",
         "stateMutability": "nonpayable",
         "inputs": [{"type": "uint256"}]},
        {"type": "function", "name": "batchMove",
         "stateMutability": "nonpayable",
         "inputs": [{"type": "address[]"}]},
        {"type": "constructor", "inputs": [{"type": "address"}]},
    ]
    wrappers, skipped = cf.plan_wrappers(abi)
    names = [w["name"] for w in wrappers]
    assert names == ["deposit", "withdraw"]  # view excluded
    assert skipped == ["batchMove"]          # array param skipped
    assert wrappers[0]["payable"] is True
    assert wrappers[1]["payable"] is False
    assert cf.has_balance_of(abi) is True
    ctor, reason = cf.constructor_plan(abi)
    assert ctor == [{"type": "address"}] and reason == ""
    bad = [{"type": "constructor",
            "inputs": [{"type": "uint256[]"}]}]
    ctor2, reason2 = cf.constructor_plan(bad)
    assert ctor2 is None and reason2 == "unsupported_constructor"
    assert cf.constructor_plan([]) == ([], "")


def test_harness_generation_accounting_and_token_dialects():
    abi = [
        {"type": "function", "name": "deposit",
         "stateMutability": "payable", "inputs": []},
        {"type": "function", "name": "drain",
         "stateMutability": "nonpayable", "inputs": []},
    ]
    wrappers, _ = cf.plan_wrappers(abi)
    h = cf.generate_harness("Vault", wrappers, [], False, "modern")
    assert f"contract {cf.HARNESS_NAME}" in h
    assert f"contract {cf.HOUSE_NAME}" in h
    assert "HEVM.deal" in h
    assert "house.fund{value:" in h
    assert "_settle(_b, _tb, msg.value)" in h
    assert "_settle(_b, _tb, 0)" in h
    assert "if (gain > claim) { ethProfit = true; }" in h
    assert f"function {cf.PROP_ETH}()" in h
    assert f"function {cf.PROP_TOKEN}()" in h
    # Token mode OFF: the harness must never reference balanceOf -
    # the call would not compile against a non-token target.
    assert "balanceOf" not in h
    legacy = cf.generate_harness("Vault", wrappers, [], False,
                                 "legacy")
    assert ".value(msg.value)" in legacy
    assert "{value:" not in legacy
    # Token mode ON: balanceOf is wired into the accounting.
    abi_tok = abi + [{"type": "function", "name": "balanceOf",
                      "stateMutability": "view",
                      "inputs": [{"type": "address"}]}]
    h2 = cf.generate_harness("Tok", wrappers, [], True, "modern")
    assert "target.balanceOf(address(this))" in h2


def test_parse_echidna_output_failure_and_sequence():
    parsed = cf.parse_echidna_output(ECHIDNA_FAILURE_FIXTURE)
    assert cf.PROP_ETH in parsed["failed"]
    info = parsed["failed"][cf.PROP_ETH]
    assert info["call_sequence"] == [
        "ReconFuzzHarness.fz_deposit_0() Time delay: 1 seconds "
        "Block delay: 1",
        "ReconFuzzHarness.fz_drain_1()",
    ]
    assert info["reason"] == "ReturnFalse"
    assert parsed["total_calls"] == 1234
    assert parsed["seed"] == 424242
    assert parsed["deploy_failed"] is False
    clean = cf.parse_echidna_output(
        "echidna_stranger_no_eth_profit: passed!\nTotal calls: 99\n")
    assert clean["failed"] == {}
    assert cf.PROP_ETH in clean["passed"]


def test_translate_sequence_and_static_recipient():
    wrappers, _ = cf.plan_wrappers([
        {"type": "function", "name": "drain",
         "stateMutability": "nonpayable", "inputs": []},
        {"type": "function", "name": "rescue",
         "stateMutability": "nonpayable", "inputs": []},
    ])
    out = cf.translate_sequence(
        ["ReconFuzzHarness.fz_drain_0()"], wrappers)
    assert out == ["drain() [target drain() via fz_drain_0]"]
    src_fixed = r"""
    contract T {
        address public treasury;
        function rescue() external {
            payable(treasury).transfer(address(this).balance);
        }
        function drain() external {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    """
    recip, _detail = cf.static_recipient_of(src_fixed, "drain")
    assert recip == "CALLER"
    recip2, _d2 = cf.static_recipient_of(src_fixed, "rescue")
    assert recip2 in ("FIXED", "UNRESOLVED")
    assert cf.static_recipient_of(src_fixed, "nope")[0] == \
        "UNRESOLVED"


def test_budget_resolution_defaults_and_clamps(monkeypatch):
    monkeypatch.delenv("RECON_FUZZ_TIMEOUT", raising=False)
    assert cf.fuzz_timeout_s() == cf.DEFAULT_FUZZ_TIMEOUT_S
    monkeypatch.setenv("RECON_FUZZ_TIMEOUT", "5")
    assert cf.fuzz_timeout_s() == cf.MIN_FUZZ_TIMEOUT_S
    monkeypatch.setenv("RECON_FUZZ_TIMEOUT", "99999")
    assert cf.fuzz_timeout_s() == cf.MAX_FUZZ_TIMEOUT_S
    monkeypatch.setenv("RECON_FUZZ_TIMEOUT", "junk")
    assert cf.fuzz_timeout_s() == cf.DEFAULT_FUZZ_TIMEOUT_S


# ---------------------------------------------------------------------------
# 2. Plugin behavior without an engine run
# ---------------------------------------------------------------------------

def test_fast_context_refused_immediately():
    p = _plugin()
    ctx = FakeCtx(heavy=False, shared={
        "fuzz_candidates": [{"source": CANARY_A,
                             "contract_name": "FuzzVault"}]})
    res = _run(p, ctx)
    assert len(res.findings) == 1
    assert res.findings[0].key == "contract_fuzz_note"
    assert "stayed off" in res.findings[0].value


def test_engine_absent_is_inconclusive_not_fake(monkeypatch):
    monkeypatch.setattr(cf, "fuzz_engine", lambda: None)
    p = _plugin(test_limit_attr=500)
    ctx = FakeCtx(shared={
        "fuzz_candidates": [{"source": CANARY_A,
                             "contract_name": "FuzzVault"}]})
    res = _run(p, ctx)
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.key == "fuzz_inconclusive"
    assert f.evidence["fuzz_inconclusive"] == "engine_absent"
    assert f.evidence["report_class"] == "candidate"
    assert f.evidence["severity"] == "low"


def test_no_candidates_skips_cleanly():
    p = _plugin()
    res = _run(p, FakeCtx())
    assert res.findings == []


# ---------------------------------------------------------------------------
# 3. Live canaries (real Echidna + solc)
# ---------------------------------------------------------------------------

def _live_run(source, name, limit=4000):
    p = _plugin(test_limit_attr=limit, seq_len_attr=12,
                fuzz_timeout_s_attr=120.0)
    ctx = FakeCtx(shared={
        "fuzz_candidates": [{"source": source,
                             "contract_name": name}]})
    return _run(p, ctx)


@needs_engine
def test_canary_a_ungated_drain_confirms():
    res = _live_run(CANARY_A, "FuzzVault")
    confirmed = [f for f in res.findings
                 if f.key == "fuzz_confirmed_stranger_profit"]
    assert len(confirmed) == 1, [f.value for f in res.findings]
    ev = confirmed[0].evidence
    assert ev["fuzz_confirmed"] is True
    assert ev["report_class"] == "fuzz_confirmed"
    assert ev["recipient"] == "CALLER"
    assert ev["severity"] == "high"
    assert ev["counterexample"]
    assert any("drain" in step for step in ev["counterexample"])
    assert "drain" in (ev["culprit_function"] or "")


@needs_engine
def test_canary_b_owner_gated_drain_never_confirms():
    res = _live_run(CANARY_B, "FuzzVault")
    assert not [f for f in res.findings
                if f.key == "fuzz_confirmed_stranger_profit"]
    assert any(f.key in ("fuzz_no_violation", "fuzz_inconclusive")
               for f in res.findings)


@needs_engine
def test_canary_c_self_service_never_confirms():
    res = _live_run(CANARY_C, "FuzzVault")
    assert not [f for f in res.findings
                if f.key == "fuzz_confirmed_stranger_profit"]
    clean = [f for f in res.findings if f.key == "fuzz_no_violation"]
    assert clean, [f.value for f in res.findings]
    assert clean[0].evidence["total_calls"] > 0


@needs_engine
def test_canary_d_free_mint_confirms_token_property():
    res = _live_run(CANARY_D, "FreeToken")
    confirmed = [f for f in res.findings
                 if f.key == "fuzz_confirmed_stranger_profit"]
    assert len(confirmed) == 1, [f.value for f in res.findings]
    assert confirmed[0].evidence["property"] == cf.PROP_TOKEN
    assert confirmed[0].evidence["profit_kind"] == "token"


# ---------------------------------------------------------------------------
# 4. Registry
# ---------------------------------------------------------------------------

def test_registry_discovers_contract_fuzz():
    reg = discover()
    assert "contract_fuzz" in reg
    assert reg["contract_fuzz"] is cf.ContractFuzzPlugin
    assert len(reg) == 655  # master 654 (incl. PR #76) + this plugin
