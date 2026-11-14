"""Tests for the autonomous multi-agent swarm (backend/app/swarm/).

Pure in-memory tests: no network, no file writes. Network-facing
agents are exercised through an injected fake RPC transport.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app.swarm import Blackboard, Coordinator  # noqa: E402
from app.swarm.bus import Blackboard as Board  # noqa: E402
from app.swarm.fork import _local_plan, plan_fork  # noqa: E402
from app.swarm.hypothesis import _fallback_hypothesis  # noqa: E402
from app.swarm.probe import (LiveProberAgent, build_candidate,  # noqa: E402
                             classify_recipient)
from app.swarm.reporter import render_report  # noqa: E402
from app.swarm.rpc import (RpcClient, decode_address, decode_uint256,  # noqa: E402
                           keccak256, selector)
from app.swarm.rules import (check_readonly, is_forbidden_target,  # noqa: E402
                             recipient_counts_as_real)
from app.swarm.triage import rank_targets, target_key, try_nn_ranker  # noqa: E402

STRANGER = "0x000000000000000000000000000000000000dEaD"


# -- keccak / selectors ---------------------------------------------------

def test_keccak_vectors():
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    assert keccak256(b"hello").hex() == (
        "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
    assert keccak256(b"abc").hex() == (
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")


def test_selectors():
    assert selector("owner()") == "8da5cb5b"
    assert selector("totalSupply()") == "18160ddd"
    assert selector("transfer(address,uint256)") == "a9059cbb"
    assert selector("balanceOf(address)") == "70a08231"


def test_decode_helpers():
    assert decode_uint256("0x" + "00" * 31 + "2a") == 42
    assert decode_uint256("0x1234") is None
    assert decode_address("0x" + "00" * 12 + "ab" * 20) == "0x" + "ab" * 20


# -- rules -----------------------------------------------------------------

def test_readonly_allowlist():
    check_readonly("eth_call")
    check_readonly("eth_getCode")
    for bad in ("eth_sendTransaction", "eth_sendRawTransaction",
                "eth_sign", "eth_signTransaction", "personal_sign"):
        with pytest.raises(ValueError):
            check_readonly(bad)


def test_forbidden_target_crypto_com():
    assert is_forbidden_target({"address": "0x" + "11" * 20,
                                "name": "Crypto.com Vault"}) is not None
    assert is_forbidden_target({"address": "0x" + "11" * 20,
                                "name": "Plain Token"}) is None


def test_recipient_classes():
    assert recipient_counts_as_real("CALLER")
    assert recipient_counts_as_real("CALLER-SUPPLIED")
    assert recipient_counts_as_real("caller-supplied")
    for trigger in ("FIXED", "HOLDER-SELF", "OWNER", "UNKNOWN", None):
        assert not recipient_counts_as_real(trigger)


# -- blackboard --------------------------------------------------------------

def test_blackboard_post_get_and_blobs():
    board = Board("run-1")
    board.post("scout", "optimism:0xabc", "scout", {"findings_count": 3})
    assert board.get("optimism:0xabc", "scout")["findings_count"] == 3
    assert board.get("optimism:0xabc", "missing") is None
    board.put_blob("optimism:0xabc", "source", "contract X {}")
    assert board.get_blob("optimism:0xabc", "source") == "contract X {}"
    assert len(board.to_jsonl().strip().splitlines()) == 1


# -- triage -------------------------------------------------------------------

def test_triage_value_first():
    targets = [
        {"chain": "optimism", "address": "0x" + "01" * 20, "value_usd": 5000},
        {"chain": "optimism", "address": "0x" + "02" * 20, "value_usd": 250000},
        {"chain": "optimism", "address": "0x" + "03" * 20},
        {"chain": "optimism", "address": "0x" + "04" * 20, "value_usd": 900000},
    ]
    ranked = rank_targets(targets)
    addrs = [t["address"] for t in ranked]
    # Known high value first, then unknown, then known dust last.
    assert addrs[0].endswith("04" * 20)
    assert addrs[1].endswith("02" * 20)
    assert addrs[2].endswith("03" * 20)
    assert addrs[3].endswith("01" * 20)


def test_triage_fresh_beats_stale_on_tie():
    a = {"chain": "scroll", "address": "0x" + "0a" * 20, "fresh_7d": True}
    b = {"chain": "scroll", "address": "0x" + "0b" * 20, "fresh_7d": False}
    ranked = rank_targets([b, a])
    assert ranked[0]["address"] == a["address"]


def test_target_key_dedupes_case():
    assert target_key({"chain": "Scroll", "address": "0xAB" + "11" * 19}) == \
        target_key({"chain": "scroll", "address": "0xab" + "11" * 19})


def test_nn_ranker_absent_on_master():
    # app/nn lives on another branch; on master the hook degrades.
    assert try_nn_ranker() is None


# -- hypothesis ---------------------------------------------------------------

def test_hypothesis_story_needs_drain_kind_and_function():
    findings = [{
        "kind": "unprotected_withdraw", "severity": "high",
        "function": "withdraw",
        "evidence": {"recipient": "msg.sender"},
    }]
    h = _fallback_hypothesis(findings)
    assert h["kind"] == "story"
    assert h["function"] == "withdraw"
    assert h["next_test"] == "live_probe"


def test_hypothesis_non_drain_is_lead():
    h = _fallback_hypothesis([{"kind": "weird_event", "severity": "high"}])
    assert h["kind"] == "lead"
    assert h["next_test"] == "fork_sequence"


def test_hypothesis_empty_is_no_story():
    h = _fallback_hypothesis([])
    assert h["kind"] == "no_story"


# -- fork planning --------------------------------------------------------------

def test_local_plan_pairs_setup_and_sensitive():
    src = ("contract T { function deposit() public {} "
           "function withdraw() public {} function owner() public view {} }")
    seqs = _local_plan(src)
    assert seqs and seqs[0]["target"] == "withdraw"
    assert plan_fork("") == []


def test_plan_fork_falls_back_when_repo_planner_plans_nothing():
    # A source the repo planner has no opinion on must still get a
    # local plan: an empty plan from planner #1 is not an answer.
    src = ("contract T { function deposit() public {} "
           "function upgrade(address a, bytes32 h, bytes calldata p) "
           "external {} }")
    seqs = plan_fork(src)
    assert seqs and any(s["target"] == "upgrade" for s in seqs)


def test_calldata_single_arg_encodings():
    from app.swarm.fork import _calldata_for
    abi = [
        {"type": "function", "name": "transferGovernance",
         "inputs": [{"name": "newGovernance", "type": "address"}]},
        {"type": "function", "name": "setPauseStatus",
         "inputs": [{"name": "isPaused", "type": "bool"}]},
        {"type": "function", "name": "upgrade",
         "inputs": [{"name": "a", "type": "address"},
                    {"name": "h", "type": "bytes32"},
                    {"name": "p", "type": "bytes"}]},
        {"type": "function", "name": "paused",
         "inputs": []},
    ]
    gov = _calldata_for("transferGovernance", abi, "0x" + "aa" * 20)
    assert gov is not None and gov.startswith("0x")
    assert gov.endswith("000000000000000000000000000000000000dead")
    pause = _calldata_for("setPauseStatus", abi, "0x" + "aa" * 20)
    assert pause is not None and pause.endswith("00" * 32)
    assert _calldata_for("upgrade", abi, "0x" + "aa" * 20) is None
    assert _calldata_for("paused", abi, "0x" + "aa" * 20) is not None
    assert _calldata_for("missing", abi, "0x" + "aa" * 20) is not None


# -- probe ----------------------------------------------------------------------

def test_classify_recipient():
    assert classify_recipient(
        {"evidence": {"recipient_class": "CALLER-SUPPLIED"}}) == "CALLER-SUPPLIED"
    assert classify_recipient({"detail": "pays msg.sender"}) == "CALLER"
    assert classify_recipient({}) == "UNKNOWN"


def test_build_candidate_never_carries_simulation():
    cand = build_candidate(
        {"address": "0x" + "aa" * 20, "chain": "scroll"},
        {"function": "withdraw", "finding_kind": "unprotected_withdraw",
         "severity": "high"},
        {"kind": "unprotected_withdraw",
         "evidence": {"recipient_class": "CALLER"}})
    assert "simulation" not in cand
    assert cand["recipient_class"] == "CALLER"


def _fake_rpc():
    def transport(url, payload):
        method = payload["method"]
        if method == "eth_getCode":
            return {"jsonrpc": "2.0", "id": 1, "result": "0x60006000"}
        if method == "eth_getBalance":
            return {"jsonrpc": "2.0", "id": 1, "result": "0x0"}
        if method == "eth_chainId":
            return {"jsonrpc": "2.0", "id": 1, "result": "0x82750"}
        if method == "eth_call":
            return {"jsonrpc": "2.0", "id": 1,
                    "result": "0x" + "00" * 32}
        raise AssertionError(f"unexpected method {method}")
    return RpcClient("scroll", transport=transport)


def test_rpc_refuses_non_readonly_even_with_transport():
    rpc = _fake_rpc()
    with pytest.raises(ValueError):
        rpc.call("eth_sendTransaction", [{}, "latest"])


def test_rpc_eth_call_uses_stranger_sender():
    seen = {}

    def transport(url, payload):
        seen.update(payload["params"][0])
        return {"jsonrpc": "2.0", "id": 1, "result": "0x" + "00" * 32}
    rpc = RpcClient("scroll", transport=transport)
    rpc.eth_call("0x" + "aa" * 20, "0x8da5cb5b")
    assert seen["from"] == STRANGER
    assert seen["value"] == "0x0"


def test_liveprober_trigger_only_builds_no_candidate():
    import app.swarm.scout as scout_mod
    orig = scout_mod.fetch_verified_source
    scout_mod.fetch_verified_source = lambda c, a: {
        "source": None, "name": None, "abi": None, "via": None,
        "error": "patched out in test"}
    try:
        rpc = _fake_rpc()
        board = Blackboard("run-test")
        target = {"chain": "scroll",
                  "address": "0x" + "aa" * 20, "name": "FixedVault"}
        from app.swarm.scout import ScoutAgent
        scout = ScoutAgent().run(target, rpc, board)
        scout["findings"] = [{
            "kind": "unprotected_withdraw", "severity": "high",
            "function": "withdraw",
            "evidence": {"recipient_class": "FIXED"}}]
        from app.swarm.hypothesis import HypothesizerAgent
        hyp = HypothesizerAgent().run(scout, board)
        probe = LiveProberAgent().run(target, hyp, scout, rpc, board)
        assert probe["verdict"] == "TRIGGER_ONLY"
        assert probe["candidates"] == []
        assert probe["sender"] == STRANGER
        assert all(p["from"] == STRANGER for p in probe["probes"])
    finally:
        scout_mod.fetch_verified_source = orig


# -- coordinator ------------------------------------------------------------------

def test_coordinator_intake_rules():
    coord = Coordinator()
    targets = [
        {"chain": "scroll", "address": "0x" + "aa" * 20},
        {"chain": "scroll", "address": "0x" + "AA" * 20},  # dup
        {"chain": "scroll", "address": "0x" + "bb" * 20,
         "name": "crypto.com bridge"},
        {"chain": "solana", "address": "0x" + "cc" * 20},
        {"chain": "scroll", "address": "not-an-address"},
    ]
    accepted, rejected = coord.filter_intake(targets)
    assert len(accepted) == 1
    assert len(rejected) == 4
    reasons = " ".join(r["reason"] for r in rejected)
    assert "duplicate" in reasons and "crypto.com" in reasons


def test_coordinator_run_queue_fake_rpc_isolates_errors():
    import app.swarm.scout as scout_mod
    orig = scout_mod.fetch_verified_source
    scout_mod.fetch_verified_source = lambda c, a: {
        "source": None, "name": None, "abi": None, "via": None,
        "error": "patched out in test"}
    try:
        def rpc_factory(chain):
            return _fake_rpc()
        coord = Coordinator(max_concurrent_targets=1, chain_depth=0,
                            rpc_factory=rpc_factory)
        targets = [
            {"chain": "scroll", "address": "0x" + "aa" * 20},
            {"chain": "scroll", "address": "0x" + "aa" * 20},  # dup
            {"chain": "scroll", "address": "0x" + "bb" * 20},
        ]
        record = coord.run_queue(targets, run_id="test-run")
        m = record["metrics"]
        assert m["targets_queued"] == 3
        assert m["targets_rejected"] == 1
        assert m["targets_attempted"] == 2
        assert m["targets_completed"] == 2
        assert m["findings_total"] == 0
        assert m["candidates_total"] == 0
        assert m["verified_real"] == 0
        assert m["seconds_per_target"] >= 0
    finally:
        scout_mod.fetch_verified_source = orig


def test_coordinator_error_in_one_target_does_not_kill_run():
    def bad_factory(chain):
        raise RuntimeError("boom")
    coord = Coordinator(max_concurrent_targets=1, chain_depth=0,
                        rpc_factory=bad_factory)
    record = coord.run_queue(
        [{"chain": "scroll", "address": "0x" + "aa" * 20}],
        run_id="test-err")
    assert record["metrics"]["targets_errored"] == 1
    assert record["metrics"]["targets_completed"] == 0


# -- reporter ----------------------------------------------------------------------

def test_reporter_render_shows_real_probe_outputs():
    target = {"chain": "scroll", "address": "0x" + "aa" * 20,
              "name": "T", "fresh_7d": True}
    scout = {"contract_name": "T", "has_code": True, "bytecode_len": 1234,
             "native_balance_wei": 0, "native_balance_eth": 0,
             "has_source": False, "source_len": 0, "source_via": None,
             "scan_engine": "none", "findings_count": 0,
             "worst_severity": None, "related_addresses": [],
             "views": {"owner": {"ok": False, "error": "execution reverted"}},
             "errors": []}
    hyp = {"kind": "no_story", "story": None, "function": "",
           "recipient": "unknown", "next_test": "none", "engine": "x"}
    fork = {"engine": "plan_only", "planned_count": 0, "executed": False,
            "executed_count": 0, "state_carried_between_steps": False,
            "note": "no sequences", "outcomes": []}
    probe = {"sender": STRANGER, "verdict": "CLEAN", "candidates": [],
             "verdicts": [],
             "probes": [{"signature": "owner()", "ok": False,
                         "error": "execution reverted"}]}
    md = render_report(target, scout, hyp, fork, probe)
    assert "execution reverted" in md
    assert "CLEAN" in md
    assert "no transaction sent" in md
