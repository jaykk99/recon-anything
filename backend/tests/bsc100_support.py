"""Shared helpers for the BSC-100 detector test files.

Each family test file (test_bsc_<family>.py) parametrizes over
its family's 10 detector specs: the family's vulnerable fixture
for a detector MUST produce a finding whose kind is that
detector's own id, and the family's clean control MUST produce
zero findings from every spec in the family.
"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.plugins.bsc_common import analyze_bsc_source  # noqa: E402
import bsc100_fixtures as fx  # noqa: E402

FAMILY_MODULES = {
    "bep20": "bsc_bep20",
    "pancake": "bsc_pancake",
    "lending": "bsc_lending",
    "staking": "bsc_staking",
    "governance": "bsc_governance",
    "proxy": "bsc_proxy",
    "access": "bsc_access",
    "gamefi": "bsc_gamefi",
    "mev_bridge": "bsc_mev_bridge",
    "math_system": "bsc_math_system",
}


def family_specs(family: str):
    mod = importlib.import_module(
        f"app.plugins.{FAMILY_MODULES[family]}")
    return list(mod.SPECS)


def all_specs():
    out = {}
    for family in FAMILY_MODULES:
        for spec in family_specs(family):
            out[spec.id] = spec
    return out


def hits_for(src: str, spec):
    return analyze_bsc_source(src, spec)


def assert_fires(spec):
    src = fx.VULN[spec.id]
    hits = hits_for(src, spec)
    assert hits, f"{spec.id}: vulnerable fixture did not fire"
    assert all(h["kind"] == spec.id for h in hits), (
        f"{spec.id}: finding kinds "
        f"{sorted({h['kind'] for h in hits})} != own id")
    for h in hits:
        assert h["code"], f"{spec.id}: finding without code evidence"
        assert h["detail"], f"{spec.id}: finding without detail"
    return hits


def assert_family_clean(family: str):
    src = fx.CLEAN[family]
    for spec in family_specs(family):
        hits = hits_for(src, spec)
        assert hits == [], (
            f"{spec.id}: fired on the {family} clean control: "
            f"{hits}")
