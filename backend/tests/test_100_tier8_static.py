"""Tier-8 Static Analysis & Smart Contract AST Parsing
(100-plugin expansion).

Duplicate rule is the core of this tier: master dee4763 already
carries a full external-tool lane (audit_toolbox: Slither +
Slitherin, Aderyn, Mythril, Securify 2.0, Solhint security
ruleset, Wake, SMTChecker, Heimdall, Surya, 4byte) and a second
Mythril lane (contract_sim). Evidence tests below pin those
verdicts against the REAL saved tool-output fixtures in
tests/fixtures/toolbox/:

  Slither   -> DUPLICATE-OF audit_toolbox (parse_slither generic
               over every detector + SWC table + real binary)
  Mythril   -> DUPLICATE-OF audit_toolbox _adapt_mythril +
               contract_sim symbolic lane (find_mythril)
  Securify2 -> DUPLICATE-OF audit_toolbox (parse_securify +
               _adapt_securify)
  Solhint   -> security ruleset DUPLICATE-OF audit_toolbox;
               style lint shipped as solhint_lint (the toolbox
               config deliberately enables NO style rules)
  4envis    -> presence-level bytecode DUPLICATE-OF
               analyze_bytecode / heimdall / bytecode_deep;
               instruction-SEQUENCE patterns shipped as
               envis_bytecode
  Manticore -> DUPLICATE-OF the Mythril symbolic lane (same EVM
               symbolic-execution class; no second executor)
  Oyente    -> source-level classes DUPLICATE-OF contract_logic;
               bytecode-level classes shipped as oyente_bytecode
  SmartCheck-> no adapter on master at all; distinctive remainder
               rules shipped as smartcheck_rules
  Solgraph  -> call graphs DUPLICATE-OF surya / cross-contract
               graph; per-function CFG flags shipped as
               solgraph_cfg
  Aderyn    -> DUPLICATE-OF audit_toolbox (parse_aderyn generic
               over detector_name + real binary)

Per shipped plugin: fires on its VULN fixture, silent on the
CLEAN fixture (toolbox Clean.sol, a guarded vault), no crash on
malformed input. Plugin run() is exercised through the real
framework with artifacts on ctx.shared (the seam tier8_common
documents), not just the pure analyzers.
"""
import asyncio
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins import contract_sim, toolbox  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.envis_bytecode import (  # noqa: E402
    EnvisBytecodePlugin, analyze_envis_bytecode)
from app.plugins.oyente_bytecode import (  # noqa: E402
    OyenteBytecodePlugin, analyze_oyente_bytecode)
from app.plugins.registry import discover  # noqa: E402
from app.plugins.smartcheck_rules import (  # noqa: E402
    SmartcheckRulesPlugin, analyze_smartcheck_source)
from app.plugins.solgraph_cfg import (  # noqa: E402
    SolgraphCfgPlugin, analyze_solgraph_source)
from app.plugins.solhint_lint import (  # noqa: E402
    SolhintLintPlugin, analyze_lint_source)
from app.ratelimit import RateLimiter  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "fixtures", "toolbox")

NEW_IDS = ["solhint_lint", "smartcheck_rules", "oyente_bytecode",
           "envis_bytecode", "solgraph_cfg"]
DUP_IDS = ["audit_toolbox", "contract_simulation"]


def _load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


def _load_json(name):
    return json.loads(_load(name))


CLEAN_SRC = _load("Clean.sol")
VULN_SRC = _load("Vulnerable.sol")

LINT_VULN = """
import * as Lib from "./Lib.sol";
contract bad_name {
    uint256 public constant max_supply = 100;
    event transfer_done(address to);
    function do_stuff() payable public {}
    function empty_one() public {}
}
"""

SMART_VULN = """
contract SmartVuln {
    address public token;
    uint256 public total;
    function setToken(address _token) public {
        token = _token;
    }
    function hashIt(bytes memory d) public pure returns (bytes32) {
        return sha3(d);
    }
    function failHard() public { throw; }
    function accumulate(uint256 n) public {
        for (uint256 i = 0; i < n; i++) { total += i; }
    }
}
"""

SOLGRAPH_VULN = """
contract GraphVuln {
    mapping(address => uint256) public balances;
    function withdrawCredit() public {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
    function pick(bool ok) public returns (uint256) {
        if (ok) {
            return 1;
        }
    }
    function dead() public returns (uint256) {
        return 5;
        uint256 x = 1;
    }
}
"""


def _cbor_tail(solc=(0, 8, 20)):
    cbor = b"solc" + bytes([0x43, solc[0], solc[1], solc[2]]) + \
        b"\x00\x00"
    return cbor + len(cbor).to_bytes(2, "big")


def _hex(instructions, solc=(0, 8, 20)):
    return "0x" + (bytes(instructions) + _cbor_tail(solc)).hex()


# Oyente vuln: TIMESTAMP, PUSH1 0, PUSH1 0, SSTORE, ADD, CALL;
# solc 0.4.26 metadata; no GAS anywhere.
OYENTE_VULN = _hex([0x42, 0x60, 0x00, 0x60, 0x00, 0x55, 0x01, 0xF1],
                   solc=(0, 4, 26))
# Oyente clean: GAS, CALL, ISZERO, ADD; solc 0.8.20; no TIMESTAMP.
OYENTE_CLEAN = _hex([0x5A, 0xF1, 0x15, 0x01])
# 4envis vuln: PUSH4 mint selector, CALL, SSTORE (no ISZERO).
ENVIS_VULN = _hex([0x63, 0x40, 0xC1, 0x0F, 0x19, 0xF1, 0x55])
# 4envis clean: GAS, CALL, ISZERO, PUSH1 0, SSTORE, PUSH4 owner().
ENVIS_CLEAN = _hex([0x5A, 0xF1, 0x15, 0x60, 0x00, 0x55,
                    0x63, 0x8D, 0xA5, 0xCB, 0x5B])

GARBAGE_SRC = "\x00\xff{{{ not solidity at all ;;;"
GARBAGE_HEX = "0xzzzz-not-hex"


# ---------------------------------------------------------------------------
# Duplicate-of evidence (existing lanes, real saved tool outputs)
# ---------------------------------------------------------------------------

def test_dup_slither_parser_covers_core_detectors():
    hits = toolbox.parse_slither(_load_json("slither-vulnerable.json"),
                                  VULN_SRC)
    detectors = {h["detector"] for h in hits}
    assert "reentrancy-eth" in detectors
    assert "suicidal" in detectors
    clean = toolbox.parse_slither(_load_json("slither-clean.json"),
                                  CLEAN_SRC)
    assert not [h for h in clean if h["severity"] == "high"]


def test_dup_mythril_two_lanes_exist():
    hits = toolbox.parse_mythril(_load_json("mythril-canary.json"),
                                  _load("MythrilCanary.sol"))
    assert hits and hits[0]["tool"] == "mythril"
    assert toolbox.TOOL_LANES["mythril"] == "symbolic"
    assert callable(contract_sim.find_mythril)
    assert callable(toolbox._adapt_mythril)


def test_dup_securify_parser_violations():
    hits = toolbox.parse_securify(_load("securify-vulnerable.txt"))
    assert hits and all(h["tool"] == "securify" for h in hits)
    assert callable(toolbox._adapt_securify)


def test_dup_aderyn_parser():
    hits = toolbox.parse_aderyn(_load_json("aderyn-vulnerable.json"),
                                VULN_SRC)
    assert hits and all(h["tool"] == "aderyn" for h in hits)
    assert callable(toolbox._adapt_aderyn)


def test_dup_solhint_security_only_config():
    hits = toolbox.parse_solhint(_load_json("solhint-vulnerable.json"),
                                  VULN_SRC)
    assert hits and all(h["tool"] == "solhint" for h in hits)
    rules = toolbox.SOLHINT_CONFIG["rules"]
    assert "reentrancy" in rules and "avoid-tx-origin" in rules
    # the style half of solhint is deliberately NOT enabled there -
    # that gap is exactly what solhint_lint ships
    for style_rule in ("no-empty-blocks", "contract-name-camelcase",
                       "func-name-mixedcase", "const-name-snakecase",
                       "event-name-camelcase",
                       "visibility-modifier-order"):
        assert style_rule not in rules


def test_dup_manticore_symbolic_class_covered_by_mythril():
    # Manticore is an EVM symbolic executor; the class is covered
    # by the Mythril symbolic lane in two places. No second
    # symbolic executor is shipped in this tier.
    assert toolbox.TOOL_LANES["mythril"] == "symbolic"
    assert "contract_simulation" in discover()


# ---------------------------------------------------------------------------
# Shipped plugins: pure analyzers
# ---------------------------------------------------------------------------

def test_solhint_lint_fires_on_vuln():
    kinds = {h["kind"] for h in analyze_lint_source(LINT_VULN)}
    assert "lint_no_global_import" in kinds
    assert "lint_contract_name_camelcase" in kinds
    assert "lint_const_name_snakecase" in kinds
    assert "lint_event_name_camelcase" in kinds
    assert "lint_func_name_mixedcase" in kinds
    assert "lint_no_empty_blocks" in kinds
    assert "lint_visibility_modifier_order" in kinds


def test_solhint_lint_silent_on_clean():
    assert analyze_lint_source(CLEAN_SRC) == []


def test_smartcheck_fires_on_vuln():
    kinds = {h["kind"] for h in analyze_smartcheck_source(SMART_VULN)}
    assert "smartcheck_deprecated_sha3" in kinds
    assert "smartcheck_deprecated_throw" in kinds
    assert "smartcheck_costly_op_in_loop" in kinds
    assert "smartcheck_zero_address_unchecked" in kinds


def test_smartcheck_silent_on_clean():
    assert analyze_smartcheck_source(CLEAN_SRC) == []


def test_oyente_fires_on_vuln():
    kinds = {h["kind"] for h in analyze_oyente_bytecode(OYENTE_VULN)}
    assert "oyente_timestamp_dependence" in kinds
    assert "oyente_timestamp_state_write" in kinds
    assert "oyente_pre08_integer_overflow" in kinds
    assert "oyente_callstack_depth_risk" in kinds


def test_oyente_silent_on_clean():
    assert analyze_oyente_bytecode(OYENTE_CLEAN) == []


def test_envis_fires_on_vuln():
    kinds = {h["kind"] for h in analyze_envis_bytecode(ENVIS_VULN)}
    assert "envis_unchecked_call_result" in kinds
    assert "envis_call_before_state_write" in kinds
    assert "envis_mint_surface_ungated_shape" in kinds


def test_envis_silent_on_clean():
    assert analyze_envis_bytecode(ENVIS_CLEAN) == []


def test_solgraph_fires_on_vuln():
    hits = analyze_solgraph_source(SOLGRAPH_VULN)
    kinds = {h["kind"] for h in hits}
    assert "solgraph_missing_return_path" in kinds
    assert "solgraph_unreachable_code" in kinds
    assert all(h["cfg"]["blocks"] >= 1 for h in hits)


def test_solgraph_silent_on_clean():
    assert analyze_solgraph_source(CLEAN_SRC) == []


@pytest.mark.parametrize("fn,arg", [
    (analyze_lint_source, GARBAGE_SRC),
    (analyze_smartcheck_source, GARBAGE_SRC),
    (analyze_solgraph_source, GARBAGE_SRC),
    (analyze_oyente_bytecode, GARBAGE_HEX),
    (analyze_envis_bytecode, GARBAGE_HEX),
    (analyze_oyente_bytecode, ""),
    (analyze_envis_bytecode, ""),
    (analyze_lint_source, ""),
    (analyze_smartcheck_source, ""),
    (analyze_solgraph_source, ""),
])
def test_analyzers_no_crash_on_malformed(fn, arg):
    assert fn(arg) == []


# ---------------------------------------------------------------------------
# Shipped plugins: run() through the real framework
# ---------------------------------------------------------------------------

def _handler(request):
    return httpx.Response(404, content="", request=request)


def make_ctx(shared=None):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(_handler),
        follow_redirects=True, trust_env=False)
    ctx = Ctx(run_id="tier8-test", mode="passive", http=client,
              cache=Cache(), keys={},
              limiter=RateLimiter(default_rps=10000.0),
              evidence_dir="/tmp", source_type="website")
    if shared:
        ctx.shared.update(shared)
    return ctx


def run(cls, shared):
    async def _go():
        ctx = make_ctx(shared=shared)
        try:
            return await cls().run(
                Target(raw="artifact", type="url",
                       normalized="artifact"), ctx)
        finally:
            await ctx.http.aclose()
    return asyncio.run(_go())


def test_run_solhint_lint():
    res = run(SolhintLintPlugin, {"contract_source": [LINT_VULN]})
    assert {f.key for f in res.findings}
    res = run(SolhintLintPlugin, {"contract_source": [CLEAN_SRC]})
    assert res.findings == []


def test_run_smartcheck():
    res = run(SmartcheckRulesPlugin,
              {"contract_source": [SMART_VULN]})
    assert {f.key for f in res.findings}
    res = run(SmartcheckRulesPlugin,
              {"contract_source": [CLEAN_SRC]})
    assert res.findings == []


def test_run_oyente():
    res = run(OyenteBytecodePlugin,
              {"contract_bytecode": [OYENTE_VULN]})
    assert {f.key for f in res.findings}
    res = run(OyenteBytecodePlugin,
              {"contract_bytecode": [OYENTE_CLEAN]})
    assert res.findings == []


def test_run_envis():
    res = run(EnvisBytecodePlugin, {"contract_bytecode": [ENVIS_VULN]})
    assert {f.key for f in res.findings}
    res = run(EnvisBytecodePlugin,
              {"contract_bytecode": [ENVIS_CLEAN]})
    assert res.findings == []


def test_run_solgraph():
    res = run(SolgraphCfgPlugin, {"contract_source": [SOLGRAPH_VULN]})
    assert {f.key for f in res.findings}
    assert all(f.evidence.get("cfg") for f in res.findings)
    res = run(SolgraphCfgPlugin, {"contract_source": [CLEAN_SRC]})
    assert res.findings == []


def test_run_no_crash_on_garbage():
    for cls, shared in [
            (SolhintLintPlugin, {"contract_source": [GARBAGE_SRC]}),
            (SmartcheckRulesPlugin,
             {"contract_source": [GARBAGE_SRC]}),
            (SolgraphCfgPlugin, {"contract_source": [GARBAGE_SRC]}),
            (OyenteBytecodePlugin,
             {"contract_bytecode": [GARBAGE_HEX]}),
            (EnvisBytecodePlugin,
             {"contract_bytecode": [GARBAGE_HEX]})]:
        res = run(cls, shared)
        assert res.findings == []


def test_new_source_analyzers_silent_on_fp_clean_corpus():
    # fp gate: the repo's adjudicated clean corpus
    # (tests/fixtures/fp_clean, the fp_regression clean set) must
    # stay silent under every new Tier-8 source analyzer. This is
    # the pass that dropped solgraph's unguarded-call-path flag
    # and restricted smartcheck's zero-address rule to runtime
    # setters (constructors excluded).
    import glob
    corpus = glob.glob(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixtures",
        "fp_clean", "*.sol"))
    assert len(corpus) >= 10
    for path in corpus:
        src = open(path).read()
        assert analyze_lint_source(src) == [], path
        assert analyze_smartcheck_source(src) == [], path
        assert analyze_solgraph_source(src) == [], path


def test_registry_count_and_ids():
    reg = discover()
    assert len(reg) == 1346, f"registry size {len(reg)}, expected 1346"
    for pid in NEW_IDS + DUP_IDS:
        assert pid in reg, pid
    for cls in (SolhintLintPlugin, SmartcheckRulesPlugin,
                OyenteBytecodePlugin, EnvisBytecodePlugin,
                SolgraphCfgPlugin):
        assert cls.group == "web3"
