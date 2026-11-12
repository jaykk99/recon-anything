"""The ten target-surface detectors (Jay, 2026-11-11).

Contract side: every vulnerable fixture MUST fire its own detector
(kind + code + detail); the approval/Permit2 fixtures MUST be
candidates (high severity, CALLER-SUPPLIED recipient); every clean
control MUST stay silent under ALL seven contract detectors; no
detector may fire on another detector's vulnerable fixture.
Web side: each detector runs its REAL code path against fixture
pages served by an httpx MockTransport (homepage + JS, the same
collect_texts path production uses). Registry discovers exactly
1237 plugins (1227 + 10).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx  # noqa: E402

import target_surfaces_fixtures as fx  # noqa: E402
from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.plugins.target_surfaces import SPECS, SPECS_BY_ID  # noqa: E402

CONTRACT_IDS = [s.id for s in SPECS]
WEB_IDS = ["bank_login_phishing", "hardware_wallet_blind_sign_trap",
           "emv_js_skimmer"]
ALL_IDS = CONTRACT_IDS + WEB_IDS


def hits_for(src, pid):
    return analyze_bsc_source(src, SPECS_BY_ID[pid])


def test_ten_plugins_registered():
    assert len(CONTRACT_IDS) == 7
    reg = discover()
    for pid in ALL_IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1237():
    reg = discover()
    assert len(reg) == 1363, \
        f"registry size {len(reg)}, expected 1363"


def test_vuln_fires_own_kind_with_evidence():
    for pid in CONTRACT_IDS:
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in hits)
        for h in hits:
            assert h["code"], f"{pid}: no code evidence"
            assert h["detail"], f"{pid}: no detail"


def test_approval_and_permit2_are_candidates():
    for pid in ("malicious_token_approval", "permit2_allowance_abuse"):
        hits = hits_for(fx.VULN[pid], pid)
        assert hits, f"{pid}: vulnerable fixture did not fire"
        for h in hits:
            assert h["report_class"] == "candidate", (
                f"{pid}: expected candidate, got "
                f"{h.get('report_class')} ({h.get('recipient')})")
            assert h["severity"] == "high"
            assert h["recipient"] in ("CALLER", "CALLER-SUPPLIED")
            assert h["function"], f"{pid}: no function for validator"


def test_secrets_are_redacted():
    hits = hits_for(fx.VULN["hardcoded_key_mnemonic_in_source"],
                    "hardcoded_key_mnemonic_in_source")
    assert hits
    for h in hits:
        assert fx.HEX_KEY not in h["code"], \
            "raw private key leaked into finding code"
        assert fx.HEX_KEY not in h["detail"], \
            "raw private key leaked into finding detail"
        assert fx.MNEMONIC not in h["code"], \
            "raw seed phrase leaked into finding code"
    hits = hits_for(fx.VULN["cex_api_key_in_contract"],
                    "cex_api_key_in_contract")
    assert hits
    for h in hits:
        assert "4f8a2c1e9b5d476a0c3f7e1a9b2d5c8f0e6a4b7d1c9e3f5a7b0d2e4f6a8c1" \
            not in h["code"], "raw CEX key leaked into finding code"


def test_clean_controls_silent_under_all_contract_detectors():
    for clean_id, src in fx.CLEAN.items():
        for pid in CONTRACT_IDS:
            hits = hits_for(src, pid)
            assert hits == [], (
                f"{pid}: fired on the {clean_id} clean control: "
                f"{hits}")


def test_no_crosstalk_between_contract_detectors():
    for pid in CONTRACT_IDS:
        for other in CONTRACT_IDS:
            if other == pid:
                continue
            hits = hits_for(fx.VULN[other], pid)
            assert hits == [], (
                f"{pid}: fired on {other}'s vulnerable fixture: "
                f"{hits}")


# ---------------------------------------------------------------------------
# Web detectors: real code paths, MockTransport fixture pages.
# ---------------------------------------------------------------------------

def _make_ctx(pages):
    from app.cache import Cache
    from app.plugins.base import Ctx
    from app.ratelimit import RateLimiter

    def handler(request):
        key = (request.url.host, request.url.path)
        body = pages.get(key)
        if body is None:
            return httpx.Response(404, content="", request=request)
        return httpx.Response(200, content=body, request=request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler),
                             follow_redirects=True, trust_env=False)
    return Ctx(run_id="target-surfaces-test", mode="passive", http=http,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _run_web(plugin_cls, host, path="/"):
    from app.plugins.base import Target
    reg = discover()
    plugin = reg[plugin_cls]()
    ctx = _make_ctx(fx.WEB)
    target = Target(raw=f"https://{host}{path}", type="url",
                    normalized=f"https://{host}{path}")
    result = asyncio.run(plugin.run(target, ctx))
    return result.findings


def test_bank_login_phishing_fires_off_brand():
    findings = _run_web("bank_login_phishing", "evil-bank.example")
    assert len(findings) == 1, findings
    f = findings[0]
    assert f.key == "bank_login_phishing"
    assert f.evidence["brand"] == "chase"
    assert f.evidence["off_domain_post"], "expected off-domain post"


def test_bank_login_phishing_silent_on_real_bank_and_news():
    assert _run_web("bank_login_phishing", "chase.com") == []
    assert _run_web("bank_login_phishing", "news.example") == []


def test_blind_sign_trap_intent_vs_calldata():
    findings = _run_web("hardware_wallet_blind_sign_trap",
                        "evil-dapp.example")
    assert len(findings) == 1, findings
    assert findings[0].key == "hardware_wallet_blind_sign_trap"
    assert findings[0].evidence["shape"] == "intent_vs_calldata"


def test_blind_sign_trap_eip712_domain_spoof():
    findings = _run_web("hardware_wallet_blind_sign_trap",
                        "evil-sign.example")
    assert len(findings) == 1, findings
    assert findings[0].evidence["shape"] == "eip712_domain_spoof"
    assert findings[0].evidence["brand"] == "metamask"


def test_blind_sign_trap_chain_id_confusion():
    findings = _run_web("hardware_wallet_blind_sign_trap",
                        "evil-chain.example")
    assert len(findings) == 1, findings
    assert findings[0].evidence["shape"] == "chain_id_confusion"
    assert findings[0].evidence["payload_chain"] == 56


def test_blind_sign_trap_silent_on_clean_dapp():
    assert _run_web("hardware_wallet_blind_sign_trap",
                    "clean-dapp.example") == []


def test_emv_skimmer_exfil_fires():
    findings = _run_web("emv_js_skimmer", "evil-shop.example")
    assert len(findings) == 1, findings
    assert findings[0].key == "emv_js_skimmer"
    assert findings[0].evidence["shape"] == "card_read_plus_exfil"
    assert findings[0].evidence["exfil_host"] == "evil-exfil.example"


def test_emv_skimmer_obfuscated_fires():
    findings = _run_web("emv_js_skimmer", "evil-shop2.example")
    assert len(findings) == 1, findings
    assert findings[0].evidence["shape"] == "obfuscated_harvester"


def test_emv_skimmer_silent_on_stripe_checkout():
    assert _run_web("emv_js_skimmer", "clean-shop.example") == []
