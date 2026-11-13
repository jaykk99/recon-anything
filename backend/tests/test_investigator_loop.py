"""Investigator loop (Wave 1.1): flag -> hypothesis -> fork -> validator
-> verdict -> pack, plus the wiring it fixes (validator bus, priority,
deep lanes, validator cap).

Offline by construction: no network, no anvil, no live chain. The live
probe step runs the pure validator on supplied source, which honestly
returns UNVERIFIED naming the missing live probe.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from app.investigator import (  # noqa: E402
    Investigation, candidates_from_findings, filter_metered,
    publish_validator_candidates, run_investigation, validate_candidates)
from app.investigator.fixtures import (  # noqa: E402
    VAULT_ADDRESS, VAULT_VULN_SOURCE, WETH9_SOURCE, WETH_ADDRESS)
from app.investigator.picker import (  # noqa: E402
    meets_live_floor, order_targets)
from app.investigator.state import BOUNTY_FLOOR_USD  # noqa: E402


# ---------------------------------------------------------------------------
# Picker: value-first, $100k floor, unknown value never dust
# ---------------------------------------------------------------------------

def test_picker_orders_value_first_and_keeps_unknown():
    targets = [
        {"address": "0x00000000000000000000000000000000000000d1",
         "chain": "ethereum", "value_usd": 500.0},
        {"address": "0x00000000000000000000000000000000000000a1",
         "chain": "ethereum", "value_usd": 2_000_000.0},
        {"address": "0x00000000000000000000000000000000000000b1",
         "chain": "ethereum"},  # unknown value
        {"address": "0x00000000000000000000000000000000000000c1",
         "chain": "ethereum", "value_usd": 150_000.0},
    ]
    ordered = order_targets(targets)
    addrs = [t["address"][-4:] for t in ordered]
    assert addrs == ["00a1", "00c1", "00b1", "00d1"], addrs
    assert ordered[2]["value_band"] == "unknown"


def test_live_floor_blocks_known_dust_not_unknown():
    assert meets_live_floor(500.0) is False
    assert meets_live_floor(100_000.0) is True
    assert meets_live_floor(None) is True  # unknown is never dust


def test_live_floor_skips_low_value_target():
    d = tempfile.mkdtemp()
    inv = run_investigation(
        VAULT_ADDRESS, "ethereum", source=VAULT_VULN_SOURCE,
        value_usd=500.0, live=True, store_dir=d, out_dir=d + "/packs")
    assert inv.verdict == "SKIPPED"
    assert inv.findings == []  # never entered the loop
    assert inv.phase == "CLOSED"


# ---------------------------------------------------------------------------
# Fixtures: planted-vuln vault -> verdict + pack; clean WETH9 -> CLEAN
# ---------------------------------------------------------------------------

def test_vault_fixture_flag_to_verdict_with_pack():
    d = tempfile.mkdtemp()
    inv = run_investigation(
        VAULT_ADDRESS, "ethereum", source=VAULT_VULN_SOURCE,
        value_usd=250_000.0, store_dir=d, out_dir=d + "/packs")
    # Flag: high/critical drain findings on withdrawAll.
    assert inv.findings, "loop found nothing on a planted-vuln vault"
    assert any(f.get("function") == "withdrawAll"
               for f in inv.findings)
    # Candidates: published to the bus, all on withdrawAll.
    assert inv.candidates
    assert {c["function"] for c in inv.candidates} == {"withdrawAll"}
    assert any(c["kind"] == "fund_drain" for c in inv.candidates)
    # Hypothesis: one concrete attack story on withdrawAll.
    assert inv.hypothesis is not None
    assert inv.hypothesis["function"] == "withdrawAll"
    assert inv.hypothesis["next_test"] == "fork_sequence"
    # Fork: sequences planned, sim only, never proof.
    assert inv.fork.get("planned_count", 0) >= 1
    assert inv.fork.get("sim_derived") is True
    assert inv.fork.get("executed") is False
    # Validator: offline, so UNVERIFIED naming the missing live probe.
    assert inv.verdict == "UNVERIFIED"
    assert inv.verdicts
    assert all(v.get("verdict") == "UNVERIFIED" for v in inv.verdicts)
    assert any("probe" in (v.get("reason") or "").lower()
               for v in inv.verdicts)
    assert inv.verdict != "VERIFIED_REAL"  # no live probe, no stamp
    # Pack: high-value triage pack written, verdict stated in it.
    assert inv.report, "pack rule should fire on a $250k target"
    report_path = inv.report["files"]["report"]
    assert os.path.isfile(report_path)
    assert os.path.isfile(inv.report["files"]["findings"])
    assert os.path.isfile(inv.report["files"]["verdicts"])
    assert os.path.isfile(inv.report["files"]["manifest"])
    with open(report_path, encoding="utf-8") as fh:
        md = fh.read()
    assert "UNVERIFIED" in md
    assert VAULT_ADDRESS in md
    assert "Investigator verdict: UNVERIFIED" in md
    assert "VERIFIED_REAL" not in md


def test_clean_weth_closes_with_zero_candidates():
    d = tempfile.mkdtemp()
    inv = run_investigation(
        WETH_ADDRESS, "ethereum", source=WETH9_SOURCE,
        store_dir=d, out_dir=d + "/packs")
    # Findings exist (medium/low notes) but none is a candidate: the
    # only high, fund_drain/withdraw, is caller-metered (HOLDER-SELF).
    assert inv.findings
    assert inv.candidates == []
    assert inv.hypothesis is None
    assert inv.verdict == "CLEAN"
    assert inv.verdicts == []
    assert inv.report == {}  # no pack on a clean close
    assert any("HOLDER-SELF" in n for n in inv.notes)


def test_loop_never_feeds_simulation_to_validator(monkeypatch):
    import app.plugins.auto_validator as av
    seen = []

    def _capture(candidate):
        seen.append(dict(candidate))
        return {"address": candidate.get("address", ""),
                "chain": candidate.get("chain", ""),
                "function": candidate.get("function", ""),
                "kind": candidate.get("kind", ""),
                "verdict": "UNVERIFIED",
                "reason": "captured",
                "missing": ["live probe"]}

    monkeypatch.setattr(av, "validate_candidate", _capture)
    d = tempfile.mkdtemp()
    inv = run_investigation(
        VAULT_ADDRESS, "ethereum", source=VAULT_VULN_SOURCE,
        value_usd=250_000.0, store_dir=d, out_dir=d + "/packs")
    assert seen, "validator was never called"
    assert all("simulation" not in c for c in seen), \
        "fork simulation must never reach the validator as proof"
    assert len(seen) == len(inv.candidates)


# ---------------------------------------------------------------------------
# Validator bus: publish -> consume -> validate
# ---------------------------------------------------------------------------

def test_publish_validator_candidates_bus_shapes():
    cands = [{"address": "0xabc", "chain": "ethereum",
              "function": "withdrawAll", "kind": "fund_drain"}]
    lst: list = []
    assert publish_validator_candidates(lst, cands) == 1
    assert lst[0]["kind"] == "fund_drain"
    bus: dict = {}
    assert publish_validator_candidates(bus, cands) == 1
    assert bus["validator_candidates"][0]["function"] == "withdrawAll"

    class FakeCtx:
        def __init__(self):
            self.shared = {}

        def publish(self, kind, item):
            self.shared.setdefault(kind, []).append(item)

    ctx = FakeCtx()
    assert publish_validator_candidates(ctx, cands) == 1
    assert ctx.shared["validator_candidates"][0]["address"] == "0xabc"
    assert publish_validator_candidates(lst, []) == 0


def test_candidates_only_drain_kinds_high_severity():
    findings = [
        {"kind": "fund_drain", "severity": "critical",
         "function": "withdrawAll", "detail": "drain"},
        {"kind": "privileged_function", "severity": "high",
         "function": "withdrawAll", "detail": "privileged"},
        {"kind": "missing_access_control", "severity": "medium",
         "function": "deposit", "detail": "no gate"},
        {"kind": "reentrancy", "severity": "high", "function": "x",
         "detail": "reenter", "evidence": {"report_class": "trigger_only"}},
    ]
    cands = candidates_from_findings(findings, "0xabc", "ethereum")
    assert [(c["kind"], c["function"]) for c in cands] == [
        ("fund_drain", "withdrawAll")]
    # filter_metered keeps unassessable candidates (no source).
    kept, skipped = filter_metered(cands, source=None)
    assert kept == cands and skipped == []


def test_validator_cap_raised_for_loop(monkeypatch):
    import app.plugins.auto_validator as av
    calls = []

    def _capture(candidate):
        calls.append(candidate.get("kind"))
        return {"address": candidate.get("address", ""),
                "chain": candidate.get("chain", ""),
                "function": candidate.get("function", ""),
                "kind": candidate.get("kind", ""),
                "verdict": "UNVERIFIED", "reason": "captured",
                "missing": []}

    monkeypatch.setattr(av, "validate_candidate", _capture)
    cands = [{"address": "0xabc", "chain": "ethereum", "function": f"f{i}",
              "kind": "fund_drain"} for i in range(12)]
    out = validate_candidates(cands)
    assert len(out) == 12 and len(calls) == 12  # past the old cap of 8
    # Plugin default stays 8; env raises it for loop-driven runs.
    assert av.validator_max_candidates() == 8
    monkeypatch.setenv("RECON_VALIDATOR_MAX_CANDIDATES", "40")
    assert av.validator_max_candidates() == 40


# ---------------------------------------------------------------------------
# State: persists per phase, reloads
# ---------------------------------------------------------------------------

def test_state_persists_and_resumes():
    d = tempfile.mkdtemp()
    inv = run_investigation(
        VAULT_ADDRESS, "ethereum", source=VAULT_VULN_SOURCE,
        value_usd=250_000.0, store_dir=d, out_dir=d + "/packs")
    assert os.path.isfile(os.path.join(d, f"{inv.id}.json"))
    again = Investigation.load(d, inv.id)
    assert again.verdict == inv.verdict == "UNVERIFIED"
    assert again.hypothesis["function"] == "withdrawAll"
    phases = [h["phase"] for h in again.history]
    for want in ("PICKED", "READ", "HYPOTHESIS", "FORK_TEST",
                 "LIVE_PROBE", "CHAIN", "VERDICT", "CLOSED"):
        assert want in phases, phases
