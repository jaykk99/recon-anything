"""Exchange-web block 2 (wallet infra exposure): same gate as block 1."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import exchange_web2_fixtures as fx  # noqa: E402
from app.plugins._exchange_common import analyze  # noqa: E402
from app.plugins.exchange_web2 import SPECS, SPECS_BY_ID  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

IDS = [s.id for s in SPECS]


def hits(pid, text, headers=None):
    return analyze(text, SPECS_BY_ID[pid], headers)


def test_ten_plugins_registered():
    assert len(IDS) == 10
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


def test_registry_count_1327():
    reg = discover()
    assert len(reg) == 1335, \
        f"registry size {len(reg)}, expected 1335"


def test_vuln_fixtures_fire():
    for pid in IDS:
        text, headers = fx.VULN[pid]
        got = hits(pid, text, headers)
        assert got, f"{pid}: vulnerable fixture did not fire"
        assert all(h["kind"] == pid for h in got)
        assert all(h["code"] for h in got)
        assert all(h["detail"] for h in got)


def test_clean_controls_silent_under_all_ten():
    for clean_id, (text, headers) in fx.CLEAN.items():
        for pid in IDS:
            got = hits(pid, text, headers)
            assert got == [], (
                f"{pid}: fired on clean control {clean_id}: {got}")


def test_no_cross_talk_between_vuln_fixtures():
    for vuln_id, (text, headers) in fx.VULN.items():
        for pid in IDS:
            if pid == vuln_id:
                continue
            got = hits(pid, text, headers)
            assert got == [], (
                f"{pid}: fired on the {vuln_id} fixture: {got}")


def test_clean_bundle_silent_under_all_ten():
    for pid in IDS:
        got = hits(pid, fx.CLEAN_BUNDLE, fx.STRONG_HEADERS)
        assert got == [], f"{pid}: fired on the clean bundle: {got}"
