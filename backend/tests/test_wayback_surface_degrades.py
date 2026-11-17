"""Regression: wayback_surface must degrade, not crash, on a non-list
CDX payload.

The Wayback CDX API normally returns a list of rows; on an error or
empty result it can return a dict or null. The plugin sliced/indexed
that directly (`rows[1:]`), which raised `KeyError: slice(1, None, None)`
on a dict and crashed the plugin instead of returning no findings.
A malformed external response must always degrade to "no data".
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app.plugins.wayback_surface as ws  # noqa: E402


class _Resp:
    def __init__(self, payload):
        self.status_code = 200
        self._payload = payload

    def json(self):
        return self._payload


class _Ctx:
    http = None
    limiter = None


def _run_cdx(payload):
    plugin = ws.WaybackSurface() if hasattr(ws, "WaybackSurface") else None
    if plugin is None:
        from app.plugins.registry import discover
        plugin = discover()["wayback_surface_waymore"]()

    async def fake_fetch(*a, **k):
        return _Resp(payload)

    orig = ws.fetch
    ws.fetch = fake_fetch
    try:
        return asyncio.run(plugin._cdx(_Ctx(), "example.com"))
    finally:
        ws.fetch = orig


def test_dict_payload_degrades_to_empty():
    # the exact crash case: a dict instead of the expected list of rows
    assert _run_cdx({"error": "rate limited"}) == []


def test_null_payload_degrades_to_empty():
    assert _run_cdx(None) == []


def test_malformed_rows_are_skipped_not_crashed():
    # header row + one good row + one malformed (non-list) row
    payload = [["original", "timestamp"],
               ["http://example.com/a", "2020"],
               "garbage"]
    out = _run_cdx(payload)
    assert ("http://example.com/a", "2020") in out
    assert len(out) == 1  # the string row is skipped, not crashed on


def test_well_formed_list_still_works():
    payload = [["original", "timestamp"],
               ["http://example.com/x", "2021"],
               ["http://example.com/y", "2022"]]
    out = _run_cdx(payload)
    assert ("http://example.com/x", "2021") in out
    assert ("http://example.com/y", "2022") in out
