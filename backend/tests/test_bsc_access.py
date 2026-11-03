"""access-control / signature detectors (bsc100 family: access).

For EVERY detector id in this family: the vulnerable fixture in
bsc100_fixtures.VULN must fire with the detector's OWN finding
kind, and the family clean control (bsc100_fixtures.CLEAN) must
produce zero findings from all 10 family detectors.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from bsc100_support import (assert_family_clean, assert_fires,
                            family_specs)  # noqa: E402

FAMILY = "access"
SPECS = family_specs(FAMILY)
IDS = [s.id for s in SPECS]


def test_family_has_exactly_10_detectors():
    assert len(SPECS) == 10
    assert len(set(IDS)) == 10


@pytest.mark.parametrize("spec", SPECS, ids=IDS)
def test_vulnerable_fixture_fires_own_kind(spec):
    assert_fires(spec)


def test_clean_control_silent_for_whole_family():
    assert_family_clean(FAMILY)
