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
   - B: the same drain behind onlyOwner MUST NOT confirm (the
     owner is ASSIGNED in the constructor - the pre-fix canary
     declared `address public owner` but never assigned it, so
     it could never catch a harness that hands the stranger the
     deployer role);
   - C: self-service deposit/withdraw-own MUST NOT confirm (the
     claim accounting settles returns against own deposits);
   - D: a free public mint MUST confirm on the token property;
   - E: an Ownable vault whose constructor assigns the owner and
     whose drain is owner-only MUST NOT confirm - regression for
     the deployer-role flaw (the harness used to deploy the
     target itself, silently holding every constructor role);
   - F: a USSD-shaped token (constructor-set owner, one-shot
     onlyOwner setter appointing the staking contract, role-gated
     mintRewards) MUST NOT confirm - the exact shape that
     produced the false confirmation in the Nov 3 backlog run.
4. Registry discovery picks the plugin up (count 778 = master 655,
   this plugin included, + 100 BSC/BNB detectors + ast_visual_audit).
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
    constructor() {
        owner = msg.sender;
    }
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

CANARY_E = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OwnedVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawMine() external {
        uint256 a = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(a);
    }

    function drain() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
"""

CANARY_F = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RoleMintToken {
    mapping(address => uint256) public balanceOf;
    address public owner;
    address public stakingContract;
    address public insuranceContract;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function connectStaking(address s) external onlyOwner {
        require(stakingContract == address(0), "already set");
        stakingContract = s;
    }

    function mintRewards(uint256 amount, address to) external {
        require(msg.sender == stakingContract ||
                msg.sender == insuranceContract, "not minter");
        balanceOf[to] += amount;
    }

    receive() external payable {}
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


def test_scope_dedupes_spdx_identifiers():
    # A flattened bundle carries one SPDX line per original file;
    # solc hard-errors on more than one in the merged unit.
    bundle = (
        "// SPDX-License-Identifier: MIT\n"
        "// ==== contracts/Token.sol ====\n"
        "pragma solidity ^0.8.20;\n"
        "contract MyToken { function mint(uint256 a) external {} }\n"
        "// ==== contracts/Lib.sol ====\n"
        "// SPDX-License-Identifier: GPL-3.0\n"
        "pragma solidity ^0.8.20;\n"
        "library Lib { function f(uint256 x) internal pure returns (uint256) { return x; } }\n"
        "// ==== contracts/Other.sol ====\n"
        "//SPDX-License-Identifier: Apache-2.0\n"
        "pragma solidity ^0.8.20;\n"
        "contract Other { function g() external {} }\n"
    )
    scoped, name = cf.build_scoped_source(bundle, "MyToken")
    assert name == "MyToken"
    assert scoped.count("SPDX-License-Identifier:") == 1
    assert "duplicate SPDX identifier stripped" in scoped


def test_scope_orders_base_units_before_derived():
    # Flattened bundles list units in arbitrary (often
    # alphabetical) order; solc requires a base contract to be
    # defined before the contracts that inherit from it.
    bundle = (
        "// SPDX-License-Identifier: MIT\n"
        "// ==== contracts/Token.sol ====\n"
        "pragma solidity ^0.8.20;\n"
        "contract MyToken is ERC20 { function mint(uint256 a) external {} }\n"
        "// ==== contracts/Context.sol ====\n"
        "pragma solidity ^0.8.20;\n"
        "contract Context { function _msgSender() internal view returns (address) { return msg.sender; } }\n"
        "// ==== contracts/ERC20.sol ====\n"
        "pragma solidity ^0.8.20;\n"
        "contract ERC20 is Context { function f() external {} }\n"
    )
    scoped, name = cf.build_scoped_source(bundle, "MyToken")
    assert name == "MyToken"
    assert scoped.index("contract Context") < \
        scoped.index("contract ERC20")
    assert scoped.index("contract ERC20") < \
        scoped.index("contract MyToken")
    # The first pragma / SPDX in bundle order still win.
    assert scoped.count("pragma solidity") == 1
    assert scoped.count("SPDX-License-Identifier:") == 1


_FAKE_CANCS = [((0, 8, 20), "/fake/solc-0.8.20"),
               ((0, 8, 26), "/fake/solc-0.8.26"),
               ((0, 7, 6), "/fake/solc-0.7.6"),
               ((0, 6, 12), "/fake/solc-0.6.12"),
               ((0, 0, 0), "/fake/shim")]


def test_resolve_solc_exact_pragma(monkeypatch):
    monkeypatch.setattr(cf, "_solc_candidates",
                        lambda: list(_FAKE_CANCS))
    # Exact version installed: that artifact, NOT the newest
    # patch of the same major.minor (solc rejects exact pragmas
    # compiled by any other version).
    assert cf.resolve_solc_status("pragma solidity 0.8.20;") == \
        ("/fake/solc-0.8.20", "")
    # Exact version missing: a distinct reason, never a silent
    # substitution that would manufacture a compile_fail.
    path, reason = cf.resolve_solc_status("pragma solidity 0.8.19;")
    assert path is None and reason == "exact_pragma_unavailable"
    assert cf.resolve_solc("pragma solidity 0.8.19;") is None


def test_resolve_solc_ranges_pick_highest_satisfying(monkeypatch):
    monkeypatch.setattr(cf, "_solc_candidates",
                        lambda: list(_FAKE_CANCS))
    # Caret: highest installed inside the caret range.
    assert cf.resolve_solc("pragma solidity ^0.8.19;") == \
        "/fake/solc-0.8.26"
    assert cf.resolve_solc("pragma solidity ^0.6.0;") == \
        "/fake/solc-0.6.12"
    # Range with an upper bound: 0.8.x must NOT be picked.
    assert cf.resolve_solc("pragma solidity >=0.6.0 <0.8.0;") == \
        "/fake/solc-0.7.6"
    # Unsatisfiable range: distinct reason, no guess.
    path, reason = cf.resolve_solc_status(
        "pragma solidity >=0.8.27 <0.9.0;")
    assert path is None and reason == "pragma_range_unavailable"
    # No pragma at all: legacy fallback (newest artifact).
    assert cf.resolve_solc_status("") == ("/fake/solc-0.8.26", "")
    # Nothing installed: solc_absent.
    monkeypatch.setattr(cf, "_solc_candidates", lambda: [])
    assert cf.resolve_solc_status("pragma solidity ^0.8.20;") == \
        (None, "solc_absent")


def test_harness_house_deploys_target_never_stranger():
    abi = [
        {"type": "function", "name": "deposit",
         "stateMutability": "payable", "inputs": []},
        {"type": "function", "name": "drain",
         "stateMutability": "nonpayable", "inputs": []},
        {"type": "constructor", "inputs": [{"type": "address"}]},
    ]
    wrappers, _ = cf.plan_wrappers(abi)
    ctor, _r = cf.constructor_plan(abi)
    h = cf.generate_harness("Vault", wrappers, ctor, False,
                            "modern")
    house_part, _sep, harness_part = h.partition(
        f"contract {cf.HARNESS_NAME}")
    # The HOUSE deploys the target (with the defaulted ctor args);
    # the harness only ever receives it via house.deploy().
    assert "function deploy()" in house_part
    assert "return new Vault(address(0));" in house_part
    assert "target = house.deploy();" in harness_part
    assert "new Vault(" not in harness_part


def test_solc_diagnostics_classification_and_tail():
    diag = (
        "Compiling FuzzProject.sol...\n"
        "Error: Identifier not found or not unique.\n"
        " --> FuzzProject.sol:9:22:\n"
        "  |\n"
        "9 | contract X is Missing {\n"
        "  |             ^^^^^^^\n")
    assert cf.looks_like_solc_diagnostics(diag) is True
    assert cf.looks_like_solc_diagnostics(
        "echidna_stranger_no_eth_profit: passed!\n") is False
    assert cf._first_error_line(diag).startswith("Error:")
    long = "\n".join(f"line {i}" for i in range(200))
    tail = cf._output_tail(long)
    assert tail.splitlines()[-1] == "line 199"
    assert len(tail.splitlines()) == 40
    assert len(tail) <= 4000


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
def test_canary_e_constructor_owner_vault_never_confirms():
    # Regression for the deployer-role flaw: the target's
    # constructor assigns owner = msg.sender. If the harness (the
    # stranger) deployed the target - as the first merged version
    # did - it would hold the owner role and drain() would
    # confirm. With the house deploying, drain() always reverts
    # for the stranger and the campaign completes clean.
    res = _live_run(CANARY_E, "OwnedVault")
    assert not [f for f in res.findings
                if f.key == "fuzz_confirmed_stranger_profit"], \
        [f.value for f in res.findings]
    clean = [f for f in res.findings if f.key == "fuzz_no_violation"]
    assert clean, [f.value for f in res.findings]
    assert clean[0].evidence["total_calls"] > 0


@needs_engine
def test_canary_f_ussd_shape_never_confirms():
    # The exact shape behind the Nov 3 false confirmation:
    # constructor-set owner, one-shot onlyOwner connectStaking,
    # mintRewards gated on the staking/insurance role addresses.
    # A stranger can neither appoint itself nor call the mint.
    res = _live_run(CANARY_F, "RoleMintToken")
    assert not [f for f in res.findings
                if f.key == "fuzz_confirmed_stranger_profit"], \
        [f.value for f in res.findings]
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
    assert len(reg) == 1081  # master 655 + 100 BSC/BNB detectors (bsc100) + 1 ast_visual_audit plugin + 5 deep-audit detectors + 6 deep-audit batch-2 detectors + 6 recipient-first detectors + 1 auto-validator + 4 deep-analysis plugins (deep_layers) + 5 deep3 detectors + 3 deep-audit batch-4 detectors (deep_audit4) + 8 deep-audit batch-9 detectors (deep_audit9) + 1 unified keyword search plugin (unified_keyword_search) + 5 deep-audit batch-10 detectors (deep_audit10) + 6 beyond-recon plugins (nuclei_templates, lifecycle, content_discovery, param_discovery_arjun, js_linkfinder, wayback_surface) + 5 sec_* secret-exposure detectors (secretpack) + 1 idorleak detector (idor-error-leak) + 1 meta_orchestrator plugin (PR #77) + 10 Tier-1 OSINT plugins (PR #119) + 8 Tier-2 Enumeration plugins (PR #124) + 6 Tier-3 Fuzzing plugins (PR #121) + 10 Tier-4 Vuln/CVE plugins (PR #125) + 10 Tier-5 Orchestration plugins (PR #123) + 8 Tier-6 Detection plugins (PR #126) + 10 Tier-7 Blockchain Ingestion plugins (PR #127) + 5 Tier-8 Static Analysis plugins (PR #129) + 8 Tier-9 plugins (PR #128) + 10 Tier-10 Mempool/MEV plugins (PR #130)
