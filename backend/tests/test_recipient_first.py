"""Recipient-first detector family: fixture discipline.

For every detector: the vulnerable fixture MUST produce a
candidate-grade hit (recipient CALLER / CALLER-SUPPLIED is part of
the finding), the clean control MUST stay silent, and the FIXED /
HOLDER-SELF variant of the same code MUST stay silent or come out
trigger-only - never as a candidate.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import recipient_first_fixtures as fx  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.recipient_first import SPECS, \
    analyze_recipient_source  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ADDR = "0x1111111111111111111111111111111111111111"


def candidates(spec_id, src):
    return [i for i in analyze_recipient_source(src, spec_id)
            if i["report_class"] == "candidate"]


def triggers(spec_id, src):
    return [i for i in analyze_recipient_source(src, spec_id)
            if i["report_class"] == "trigger_only"]


def test_all_six_specs_registered():
    reg = discover()
    for spec_id in SPECS:
        assert spec_id in reg, spec_id
    assert "auto_validator" in reg
    assert len(reg) == 870, f"registry size {len(reg)}, expected 870"  # + 5 sec_* secret-exposure detectors (secretpack) + 1 idorleak detector (idor-error-leak) + 1 meta_orchestrator plugin (PR #77) + 10 Tier-1 OSINT plugins (PR #119)


def test_vulnerable_fixtures_fire_as_candidates():
    for spec_id, src in fx.VULN.items():
        hits = candidates(spec_id, src)
        assert hits, f"{spec_id}: vulnerable fixture did not fire"
        for h in hits:
            assert h["recipient"] in ("CALLER", "CALLER-SUPPLIED"), \
                (spec_id, h["recipient"])
            assert h["severity"] == "high"


def test_alt_vulnerable_shapes_fire():
    for spec_id, src in fx.VULN_ALT.items():
        hits = candidates(spec_id, src)
        assert hits, f"{spec_id}: alt vulnerable shape did not fire"


def test_clean_controls_stay_silent():
    for spec_id, src in fx.CLEAN.items():
        items = analyze_recipient_source(src, spec_id)
        assert items == [], f"{spec_id}: clean control fired {items}"


def test_fixed_and_holder_variants_never_candidate():
    for spec_id, src in fx.TRIGGER_ONLY.items():
        assert candidates(spec_id, src) == [], \
            f"{spec_id}: FIXED/HOLDER variant became a candidate"
    # mint-to-treasury and rescue-to-fixed-wallet actively
    # classify as trigger-only items (recipient in the finding)
    for spec_id in ("recipient_mint_to_caller",
                    "recipient_rescue_to_param"):
        items = triggers(spec_id, fx.TRIGGER_ONLY[spec_id])
        assert items, f"{spec_id}: expected a trigger-only item"
        for i in items:
            assert i["recipient"] == "FIXED"
            assert i["severity"] == "low"


def test_holder_self_unwrap_stays_silent():
    items = analyze_recipient_source(
        fx.TRIGGER_ONLY["recipient_overdraw_withdraw"],
        "recipient_overdraw_withdraw")
    assert items == [], f"WETH unwrap shape fired: {items}"


# ---------------------------------------------------------------------------
# Plugin run() end-to-end (chain layer stubbed)
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


def _patch(monkeypatch, source):
    async def fake_get_code(ctx, chain, address):
        return "0x60006000"

    async def fake_source(ctx, chain, address, key=None):
        return source

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)


def _meta(source):
    if source is None:
        return None
    return {"source": source, "contract_name": "Fixture",
            "compiler": "v0.8.20+commit", "proxy": False,
            "implementation": "", "origin": "Blockscout"}


def _target():
    return Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                  normalized=f"ethereum:{ADDR}")


def test_plugin_run_flags_vulnerable_with_recipient(monkeypatch):
    pid = "recipient_rescue_to_param"
    _patch(monkeypatch, _meta(fx.VULN[pid]))
    res = asyncio.run(discover()[pid]().run(_target(), FakeCtx()))
    hits = [f for f in res.findings if f.key == pid]
    assert hits
    for h in hits:
        assert h.evidence["report_class"] == "candidate"
        assert h.evidence["recipient"] == "CALLER-SUPPLIED"


def test_plugin_run_clean_source_no_findings(monkeypatch):
    pid = "recipient_rescue_to_param"
    _patch(monkeypatch, _meta(fx.CLEAN[pid]))
    res = asyncio.run(discover()[pid]().run(_target(), FakeCtx()))
    assert [f for f in res.findings if f.key == pid] == []


def test_plugin_run_no_source_skips(monkeypatch):
    pid = "recipient_mint_to_caller"
    _patch(monkeypatch, None)
    res = asyncio.run(discover()[pid]().run(_target(), FakeCtx()))
    assert [f for f in res.findings if f.key == pid] == []
