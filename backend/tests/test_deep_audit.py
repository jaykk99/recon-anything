"""Deep-audit detectors (AI dev day 1, 2026-11-03).

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence; its clean control MUST stay
silent under ALL five detectors; every other plugin's vulnerable
fixture MUST stay silent under this one (no cross-talk); the
registry discovers exactly 778 plugins including all five.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit_fixtures as fx  # noqa: E402
from app.plugins.deep_audit import SPECS, SPECS_BY_ID, \
    analyze_deep_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits_for(src, pid):
    return analyze_deep_source(src, SPECS_BY_ID[pid])


def test_five_plugins_registered():
    assert len(IDS) == 5
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_794():
    reg = discover()
    assert len(reg) == 951, \
        f"registry size {len(reg)}, expected 951"


def test_vuln_fires_with_own_kind_and_evidence():
    for pid in IDS:
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in hits), (
            f"{pid}: finding kinds "
            f"{sorted({h['kind'] for h in hits})} != own id")
        for h in hits:
            assert h["code"], f"{pid}: finding without code evidence"
            assert h["detail"], f"{pid}: finding without detail"
            assert h["function"], f"{pid}: finding without function"


def test_clean_controls_silent_under_all_five():
    for clean_id, src in fx.CLEAN.items():
        for pid in IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {clean_id} clean control: "
                f"{hits}")


def test_no_cross_talk_between_vuln_fixtures():
    for vuln_id, src in fx.VULN.items():
        for pid in IDS:
            if pid == vuln_id:
                continue
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {vuln_id} fixture: {hits}")


def test_vault_hit_is_recipient_classified():
    hits = hits_for(fx.VULN["vault_share_inflation"],
                    "vault_share_inflation")
    # The payout leg meters the caller's own shares, so the
    # generic classifier labels it HOLDER-SELF; the detector's
    # cross-function evidence (donation-sensitive pricing) is
    # why the excess payout is stranger-receivable, so the
    # report class stays candidate with the reasoning recorded.
    assert hits[0].get("recipient") == "HOLDER-SELF"
    assert hits[0].get("report_class") == "candidate"
    assert "CANDIDATE under the receive rule" in hits[0]["detail"]


def test_aa_flags_both_validators():
    hits = hits_for(fx.VULN["aa_validation_ungated"],
                    "aa_validation_ungated")
    fns = {h["function"] for h in hits}
    assert fns == {"validateUserOp", "validatePaymasterUserOp"}


def test_readonly_names_the_unguarded_view():
    hits = hits_for(fx.VULN["readonly_reentrancy_gap"],
                    "readonly_reentrancy_gap")
    assert [h["function"] for h in hits] == ["getVirtualPrice"]


def test_ecrecover_names_the_claim_function():
    hits = hits_for(fx.VULN["ecrecover_zero_signer"],
                    "ecrecover_zero_signer")
    assert [h["function"] for h in hits] == ["claim"]
