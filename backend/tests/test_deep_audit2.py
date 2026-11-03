"""Deep-audit batch-2 detectors (AI dev, 2026-11-03).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis, classified
candidate; the FIXED-recipient variant MUST fire trigger-only
at low severity (never a candidate); every clean control MUST
stay silent under ALL six detectors; every other plugin's
vulnerable fixture MUST stay silent under this one (no
cross-talk); the registry discovers exactly 762 plugins
including all six.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit2_fixtures as fx  # noqa: E402
from app.plugins.deep_audit2 import SPECS, SPECS_BY_ID, \
    analyze_deep2_source, eip7702_delegate_of  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep2_source(src, SPECS_BY_ID[pid])


def test_six_plugins_registered():
    assert len(IDS) == 6
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_762():
    reg = discover()
    assert len(reg) == 762, \
        f"registry size {len(reg)}, expected 762"


def test_vuln_fires_candidate_with_evidence():
    for pid in IDS:
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in hits)
        for h in hits:
            assert h["code"], f"{pid}: no code evidence"
            assert h["detail"], f"{pid}: no detail"
            assert h["function"], f"{pid}: no function"
            assert h["gate_analysis"], \
                f"{pid}: no gate analysis (validator-ready bar)"
            assert h["report_class"] == "candidate", (
                f"{pid}: vuln fixture must be a candidate, got "
                f"{h['report_class']} ({h.get('recipient')})")
            assert h["severity"] == "high"
            assert h["recipient"] in (
                "CALLER", "CALLER-SUPPLIED", "UNRESOLVED")


def test_variant_fires_trigger_only_never_candidate():
    for pid in IDS:
        hits = hits_for(fx.VARIANT[pid], pid)
        assert hits, f"{pid}: FIXED variant did not fire"
        for h in hits:
            assert h["report_class"] == "trigger_only", (
                f"{pid}: FIXED variant escalated to candidate")
            assert h["severity"] == "low"
            assert h["recipient"] == "FIXED"


def test_clean_controls_silent_under_all_six():
    for clean_id, src in fx.CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {clean_id} clean "
                f"control: {hits}")


def test_no_cross_talk_between_vuln_fixtures():
    for vuln_id, src in fx.VULN.items():
        for pid in IDS:
            if pid == vuln_id:
                continue
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: "
                f"{hits}")


def test_hook_names_the_send_function():
    hits = hits_for(fx.VULN["hook_cei_reentrancy"],
                    "hook_cei_reentrancy")
    assert [h["function"] for h in hits] == ["send"]
    assert "tokensReceived" in hits[0]["detail"]


def test_bridge_names_the_missing_bindings():
    hits = hits_for(fx.VULN["bridge_replay_unbound_digest"],
                    "bridge_replay_unbound_digest")
    assert [h["function"] for h in hits] == ["executeMessage"]
    for label in ("source chain id", "origin sender",
                  "nonce / message id"):
        assert label in hits[0]["detail"], (
            f"missing binding {label} not named in detail")


def test_7702_designator_parsing():
    delegate = "0x" + "22" * 20
    code = "0xef0100" + "22" * 20
    assert eip7702_delegate_of(code) == delegate
    assert eip7702_delegate_of("0x60006000") is None
    assert eip7702_delegate_of("") is None
    assert eip7702_delegate_of("0xef0100") is None


def test_l2_names_the_liquidate_function():
    hits = hits_for(fx.VULN["l2_sequencer_uptime_missing"],
                    "l2_sequencer_uptime_missing")
    assert [h["function"] for h in hits] == ["liquidate"]
    assert "sequencer" in hits[0]["detail"]


def test_fot_names_the_deposit_function():
    hits = hits_for(fx.VULN["fee_on_transfer_overcredit"],
                    "fee_on_transfer_overcredit")
    assert [h["function"] for h in hits] == ["deposit"]


def test_create2_names_the_deploy_function():
    hits = hits_for(fx.VULN["create2_metamorphic_redeploy"],
                    "create2_metamorphic_redeploy")
    assert [h["function"] for h in hits] == ["deploy"]
    assert "kill" in hits[0]["detail"]
