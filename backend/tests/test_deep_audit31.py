"""Deep-audit batch-31 detectors: Hamonis-taught patterns.

Per plugin: the vulnerable fixture MUST fire with the plugin's
own finding kind + code evidence + gate analysis. The oracle
detector classifies the borrower as a candidate (CALLER);
the honeypot, upgrade, and mint detectors fire WITHOUT a
recipient classification (batch-20 auction precedent: a
honeypot is a scam warning to buyers, an upgrade held by one
key and an owner mint are trust warnings about the privileged
actor - neither is value a stranger can receive). The
honeypot fee leg (99% sell fee) MUST fire under the same
detector. The FIXED-recipient variant of the oracle fixture
MUST fire trigger-only at low severity (never a candidate);
every clean control MUST stay silent under ALL four
detectors; every other plugin's vulnerable fixture MUST stay
silent under this one (no cross-talk); the batch-26/27/28
fixtures MUST stay silent under all four (no cross-batch
noise); the FP-regression shapes (deep_audit13 + deep_audit14
fixtures) and the fp_clean corpus MUST stay silent under all
four. The registry discovers exactly 1494 plugins including
all four.

DOCUMENTED CO-FIRES (pinned explicitly, not pretended
silent): the upgrade and mint detectors flag single-key
authority wherever it exists, including in other batches'
fixtures that are "clean" only for their own detector's
dimension - a contract whose upgrade is gated only by
onlyOwner genuinely carries single-key upgrade authority,
and a contract whose mint is gated only by onlyOwner with
no cap genuinely carries uncapped owner mint. Concretely:
upgrade_single_key_admin fires on the batch-7 beacon VULN
fixture and on the batch-7 uups/beacon CLEAN fixtures, on
the batch-10 eip7702 EXTRA_CLEAN fixture, and on the
batch-17 upgrade-gated EXTRA_CLEAN fixtures; owner_mint_
uncapped fires on the batch-17 mint-gated EXTRA_CLEAN
fixture. No other deep_audit fixture VULN fires under any
batch-31 detector, and no fp_clean file fires.
"""
import glob
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import deep_audit13_fixtures as fx13  # noqa: E402
import deep_audit14_fixtures as fx14  # noqa: E402
import deep_audit17_fixtures as fx17  # noqa: E402
import deep_audit26_fixtures as fx26  # noqa: E402
import deep_audit27_fixtures as fx27  # noqa: E402
import deep_audit28_fixtures as fx28  # noqa: E402
import deep_audit31_fixtures as fx  # noqa: E402
import deep_audit7_fixtures as fx7  # noqa: E402
import deep_audit10_fixtures as fx10  # noqa: E402
from app.plugins.bsc_bep20 import SPECS as BEP20_SPECS  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.bsc_proxy import SPECS as PROXY_SPECS  # noqa: E402
from app.plugins.cryptopack_protocol import (  # noqa: E402
    audit_protocol_source)
from app.plugins.deep_audit20 import (  # noqa: E402
    SPECS_BY_ID as SPECS20, analyze_deep20_source)
from app.plugins.deep_audit31 import (  # noqa: E402
    SPECS, SPECS_BY_ID, analyze_deep31_source)
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]
RECIPIENT_IDS = ["oracle_spot_collateral_borrow"]
NO_RECIPIENT_IDS = ["honeypot_sell_gate_static",
                    "upgrade_single_key_admin",
                    "owner_mint_uncapped"]
BEP20_BY_ID = {s.id: s for s in BEP20_SPECS}
PROXY_BY_ID = {s.id: s for s in PROXY_SPECS}


def hits_for(src, pid):
    return analyze_deep31_source(src, SPECS_BY_ID[pid])


def test_four_plugins_registered():
    assert len(IDS) == 4
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1494():
    reg = discover()
    assert len(reg) == 1494, \
        f"registry size {len(reg)}, expected 1494"


def test_oracle_vuln_fires_candidate_with_evidence():
    pid = "oracle_spot_collateral_borrow"
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


def test_no_recipient_detectors_fire_without_candidate():
    for pid in NO_RECIPIENT_IDS:
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in hits)
        for h in hits:
            assert h["code"], f"{pid}: no code evidence"
            assert h["detail"], f"{pid}: no detail"
            assert h["function"], f"{pid}: no function"
            assert h["gate_analysis"], \
                f"{pid}: no gate analysis (validator-ready bar)"
            assert h.get("report_class") is None, (
                f"{pid}: must not carry a candidate "
                f"classification, got {h.get('report_class')}")
            if pid == "honeypot_sell_gate_static":
                assert h["severity"] == "high"
            else:
                assert h["severity"] == "medium"


def test_honeypot_fee_leg_fires():
    pid = "honeypot_sell_gate_static"
    hits = hits_for(fx.VULN_FEE, pid)
    assert hits, f"{pid}: 99% sell-fee fixture did not fire"
    assert all(h["kind"] == pid for h in hits)
    assert all(h["severity"] == "high" for h in hits)
    assert all(h.get("report_class") is None for h in hits)


def test_variant_fires_trigger_only_never_candidate():
    for pid in fx.VARIANT:
        hits = hits_for(fx.VARIANT[pid], pid)
        assert hits, f"{pid}: FIXED variant did not fire"
        for h in hits:
            assert h["report_class"] == "trigger_only", (
                f"{pid}: FIXED variant must be trigger-only, "
                f"got {h['report_class']}")
            assert h["severity"] == "low", (
                f"{pid}: FIXED variant must be low severity, "
                f"got {h['severity']}")


def test_clean_controls_silent_under_all_four():
    for pid, src in fx.CLEAN.items():
        for det in IDS:
            hits = hits_for(src, det)
            assert hits == [], (
                f"{det}: fired on CLEAN {pid}: {hits}")
    for name, src in fx.EXTRA_CLEAN.items():
        for det in IDS:
            hits = hits_for(src, det)
            assert hits == [], (
                f"{det}: fired on EXTRA_CLEAN {name}: {hits}")


def test_no_cross_talk_between_vuln_fixtures():
    for pid, src in fx.VULN.items():
        for det in IDS:
            if det == pid:
                continue
            hits = hits_for(src, det)
            assert hits == [], (
                f"{det}: fired on {pid} vuln fixture: {hits}")
    for det in IDS:
        if det == "honeypot_sell_gate_static":
            continue
        hits = hits_for(fx.VULN_FEE, det)
        assert hits == [], (
            f"{det}: fired on honeypot fee fixture: {hits}")


def test_batch26_27_28_fixtures_silent_under_all_four():
    for fxmod in (fx26, fx27, fx28):
        for pid, src in fxmod.VULN.items():
            for det in IDS:
                hits = hits_for(src, det)
                assert hits == [], (
                    f"{det}: fired on {fxmod.__name__} {pid}: "
                    f"{hits}")


def test_fp_regression_shapes_silent_under_all_four():
    # Shapes hand-read as false positives on earlier live
    # corpus passes (deep_audit13/14) plus the adjudicated
    # fp_clean corpus: all must stay silent under every
    # batch-31 detector.
    shapes = dict(fx13.FP_REGRESSION)
    shapes.update(fx14.FP_REGRESSION)
    for fid, src in shapes.items():
        for det in IDS:
            hits = hits_for(src, det)
            assert hits == [], (
                f"{det}: fired on FP-regression {fid}: {hits}")
    corpus = glob.glob(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "fixtures",
        "fp_clean", "*.sol"))
    assert len(corpus) >= 10
    for path in corpus:
        src = open(path).read()
        for det in IDS:
            hits = hits_for(src, det)
            assert hits == [], (
                f"{det}: fired on fp_clean {path}: {hits}")


def test_neighbour_oracle_cofire_documented():
    # single_source_oracle fires on the oracle VULN fixture
    # by design - the spot read is the same signal; the new
    # detector adds the borrow leg the generic oracle
    # detector cannot express. Pinned explicitly, not
    # pretended silent.
    pid = "oracle_spot_collateral_borrow"
    items = audit_protocol_source(fx.VULN[pid])
    checks = [i["check"] for i in items]
    assert "single_source_oracle" in checks, (
        f"expected single_source_oracle co-fire, got {checks}")


def test_neighbour_borrow_no_collateral_silent():
    # The oracle fixture HAS a collateral require, so the
    # no-collateral-check detector must stay silent.
    pid = "oracle_spot_collateral_borrow"
    hits = analyze_deep20_source(
        fx.VULN[pid], SPECS20["borrow_no_collateral_check"])
    assert hits == [], (
        f"borrow_no_collateral_check fired on {pid}: {hits}")


def test_neighbour_proxy_upgrade_gap_silent():
    # The upgrade fixture IS gated (onlyOwner), so the
    # ungated-upgrade detector must stay silent.
    pid = "upgrade_single_key_admin"
    hits = analyze_bsc_source(
        fx.VULN[pid],
        PROXY_BY_ID["proxy_upgrade_authorization_gap"])
    assert hits == [], (
        f"proxy_upgrade_authorization_gap fired on {pid}: {hits}")


def test_neighbour_mint_detectors_silent():
    # The mint fixture declares NO cap (cap-bypass needs a
    # declared cap) and IS named mint (side-door endpoints
    # exclude mint()), so both neighbours must stay silent.
    pid = "owner_mint_uncapped"
    for nid in ("bep20_mint_cap_bypass",
                "bep20_arbitrary_minting_endpoints"):
        hits = analyze_bsc_source(fx.VULN[pid], BEP20_BY_ID[nid])
        assert hits == [], f"{nid} fired on {pid}: {hits}"


def test_documented_cofires_single_key_authority():
    # Single-key upgrade / mint authority is genuinely
    # present in these other batches' fixtures; they are
    # "clean" only for their own detector's dimension.
    # Batch-7 beacon VULN: upgradeBeacon gated only by
    # onlyOwner, no timelock.
    assert hits_for(
        fx7.VULN["beacon_implementation_zero_accepted"],
        "upgrade_single_key_admin"), \
        "upgrade detector must fire on batch-7 beacon VULN"
    # Batch-7 CLEAN: same onlyOwner upgrade, clean only for
    # the zero-check / missing-override detectors.
    assert hits_for(
        fx7.CLEAN["uups_authorize_upgrade_missing"],
        "upgrade_single_key_admin")
    assert hits_for(
        fx7.CLEAN["beacon_implementation_zero_accepted"],
        "upgrade_single_key_admin")
    # Batch-10 EXTRA_CLEAN: OptimismMintableToken upgradeTo
    # gated only by msg.sender == owner.
    assert hits_for(
        fx10.EXTRA_CLEAN["eip7702_low_slot_collision_upgradeable_fp"],
        "upgrade_single_key_admin")
    # Batch-17 EXTRA_CLEAN: gated upgrade / mint fixtures.
    assert hits_for(
        fx17.EXTRA_CLEAN["zeroday_exploit_chain_upgrade_gated"],
        "upgrade_single_key_admin")
    assert hits_for(
        fx17.EXTRA_CLEAN["zeroday_exploit_chain_upgrade_authorize_gated"],
        "upgrade_single_key_admin")
    assert hits_for(
        fx17.EXTRA_CLEAN["zeroday_exploit_chain_mint_gated"],
        "owner_mint_uncapped")


def test_corpus_vuln_fires_only_documented():
    # Every deep_audit fixture VULN set: the only fires
    # under any batch-31 detector are this batch's own four
    # VULN fixtures plus the documented batch-7 beacon
    # co-fire.
    allowed = {
        ("deep_audit31_fixtures", "honeypot_sell_gate_static"),
        ("deep_audit31_fixtures", "oracle_spot_collateral_borrow"),
        ("deep_audit31_fixtures", "upgrade_single_key_admin"),
        ("deep_audit31_fixtures", "owner_mint_uncapped"),
        ("deep_audit7_fixtures", "beacon_implementation_zero_accepted"),
    }
    here = os.path.dirname(os.path.abspath(__file__))
    for path in sorted(glob.glob(os.path.join(
            here, "deep_audit*_fixtures.py"))):
        modname = os.path.basename(path)[:-3]
        mod = importlib.import_module(modname)
        for pid, src in getattr(mod, "VULN", {}).items():
            for det in IDS:
                hits = hits_for(src, det)
                if hits:
                    assert (modname, pid) in allowed, (
                        f"{det}: unexpected fire on {modname} "
                        f"{pid}: {hits}")
                    if modname == "deep_audit31_fixtures":
                        assert det == pid, (
                            f"{det}: fired on own {pid} fixture")
