"""Exchange-web block 1 (frontend secret exposure): each vuln fixture fires its own detector, clean controls stay silent under all ten, no cross-talk, registry = 1327."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import exchange_web1_fixtures as fx  # noqa: E402
from app.plugins._exchange_common import analyze  # noqa: E402
from app.plugins.exchange_web1 import SPECS, SPECS_BY_ID  # noqa: E402
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
    assert len(reg) == 1327, \
        f"registry size {len(reg)}, expected 1327"


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


RAW_SECRETS = [
    "AKEX9f2kLmN8pQr4sT6v", "Zx8Qw2Er5Ty7Ui9Op0As3Df6Gh1Jk4Lz",
    "tn8Kd3Pw9Qx2Vb7Nm4Hs6J", "WD7hJ3kL9mN2pQ5rS8tV1x",
    "SM9qW8eR7tY6uI5oP4aS3d", "Zx9Qw8Er7Ty6Ui5Op4As3Df6Gh",
    "SG7hJ9kL2mN4pQ6rS8tV0xZ", "SB3dF5gH7jK9lM1nP3qR5s",
    "PT5tG7hJ9kL1mN3pQ5rS7v", "WH2wE4rT6yU8iO0pA3sD5f",
    "lk9H8gF7dS6aP5oI4uY3tR2eW1q",
]


def test_findings_never_carry_full_secret():
    for pid in IDS:
        text, headers = fx.VULN[pid]
        for h in hits(pid, text, headers):
            blob = h["code"] + h["detail"]
            for raw in RAW_SECRETS:
                assert raw not in blob, (
                    f"{pid}: full secret leaked into finding")
            assert h["fingerprint_sha256"]
