"""Realizable-value triage: a real $100k contract vs one holding dust."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.valuation import (  # noqa: E402
    realizable_value_usd, is_dust, value_band, DUST_POOL_FLOOR_USD,
)


def test_no_pool_token_is_dust_regardless_of_nominal():
    # 100k "nominal" with no pool is not realizable money
    assert realizable_value_usd(0, [{"nominal_usd": 100000,
                                     "liquidity_usd": 0}]) == 0.0
    assert realizable_value_usd(0, [{"nominal_usd": 100000,
                                     "liquidity_usd": None}]) == 0.0


def test_position_capped_by_pool_liquidity():
    # nominal 100k but only 2k of pool depth -> realizable 2k
    assert realizable_value_usd(0, [{"nominal_usd": 100000,
                                     "liquidity_usd": 2000}]) == 2000.0


def test_native_plus_deep_pool_token_counts_fully():
    assert realizable_value_usd(
        15000, [{"nominal_usd": 90000, "liquidity_usd": 500000}]) == 105000.0


def test_below_floor_pool_is_dust():
    assert realizable_value_usd(
        0, [{"nominal_usd": 100000,
             "liquidity_usd": DUST_POOL_FLOOR_USD - 1}]) == 0.0


def test_is_dust_treats_missing_value_as_unknown_not_dust():
    assert is_dust(None, 100000) is False      # can't assess -> never filtered
    assert is_dust(50000, 100000) is True
    assert is_dust(150000, 100000) is False


def test_value_band_labels():
    assert value_band(None) == "unknown"
    assert value_band(100) == "dust"
    assert value_band(50000) == "low"
    assert value_band(250000) == "mid"
    assert value_band(5_000_000) == "high"
