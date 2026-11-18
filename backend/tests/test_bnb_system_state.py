"""BNB system-contract live-state reader (bnb_system_state).

The plugin's transport (_batch_read) is stubbed: no network. The
tests prove the flaw-condition logic against canned live-shaped
state - the real mainnet numbers are asserted by the standalone
live-probe run, not here.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from app.plugins import bnb_system_state as bss  # noqa: E402
from app.plugins.base import Target  # noqa: E402


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


def _word(n: int) -> str:
    return "%064x" % n


def _addr(i: int) -> str:
    return "0x" + "00" * 19 + "%02x" % i


def _addr_array(addrs):
    out = _word(32) + _word(len(addrs))
    for a in addrs:
        out += "0" * 24 + a[2:]
    return "0x" + out


def _mining_array(addrs):
    # (address[], bytes[]): two offsets, then the address array.
    addrs_hex = _word(len(addrs))
    for a in addrs:
        addrs_hex += "0" * 24 + a[2:]
    second_off = 32 + 32 + 32 * len(addrs)
    return "0x" + _word(64) + _word(second_off) + addrs_hex + _word(0)


def _bool_word(b: bool) -> str:
    return "0x" + _word(1 if b else 0)


def _uint_word(n: int) -> str:
    return "0x" + _word(n)


LIVE_45 = [_addr(i + 1) for i in range(45)]
LIVE_21 = LIVE_45[:21]


def make_stub(*, felony=150, misd=50, scope=28800, mal_vote=True,
              down_amt=10 * 10**18, fel_amt=200 * 10**18,
              down_jail=2 * 86400, fel_jail=30 * 86400,
              cabinets=21, working=3):
    main = [
        _addr_array(LIVE_45),
        _uint_word(cabinets),
        _uint_word(working),
        _mining_array(LIVE_21),
        _uint_word(misd),
        _uint_word(felony),
        _uint_word(scope),
        _bool_word(mal_vote),
        _uint_word(down_amt),
        _uint_word(fel_amt),
        _uint_word(down_jail),
        _uint_word(fel_jail),
    ]
    ind = ["0x" + _word(6_000_000 + i) + _word(i)
           for i in range(3)]

    async def _stub(ctx, calls):
        if len(calls) == 12:
            return list(main)
        return list(ind)

    return _stub


def run_plugin(stub):
    bss._batch_read = stub
    plugin = bss.BnbSystemStatePlugin()
    target = Target(raw="bsc:0x0000000000000000000000000000000000001000",
                    type="crypto_wallet")
    return asyncio.run(plugin.run(target, FakeCtx()))


def keys(res):
    return [f.key for f in res.findings]


def test_live_values_fire_p02_p04_p05_p07_p08():
    res = run_plugin(make_stub())
    ks = keys(res)
    assert ks.count("bnb_parlia_p02_live") == 2
    assert "bnb_parlia_p04_live" in ks
    assert "bnb_parlia_p05_live" in ks
    assert "bnb_parlia_p07_live" in ks
    assert "bnb_parlia_p08_live" in ks
    assert len(res.findings) == 6
    p02 = [f for f in res.findings if f.key == "bnb_parlia_p02_live"]
    assert "150 blocks" in p02[0].value
    assert "28800" in p02[1].value
    p08 = [f for f in res.findings if f.key == "bnb_parlia_p08_live"][0]
    assert "200 BNB" in p08.value and "10 BNB" in p08.value
    assert p08.evidence["slash_ratio"] == 20.0
    p05 = [f for f in res.findings if f.key == "bnb_parlia_p05_live"][0]
    assert p05.evidence["mining_validators"] == 21


def test_malicious_vote_slash_disabled_is_high():
    res = run_plugin(make_stub(mal_vote=False))
    p04 = [f for f in res.findings if f.key == "bnb_parlia_p04_live"][0]
    assert p04.evidence["severity"] == "high"
    assert "FALSE" in p04.value


def test_moved_thresholds_do_not_fire_p02_p08():
    res = run_plugin(make_stub(felony=1000, scope=200000,
                               fel_amt=20 * 10**18, fel_jail=4 * 86400))
    ks = keys(res)
    assert "bnb_parlia_p02_live" not in ks
    assert "bnb_parlia_p08_live" not in ks
    assert "bnb_parlia_p04_live" in ks
    assert "bnb_parlia_p05_live" in ks
    assert "bnb_parlia_p07_live" in ks


def test_all_routes_down_is_degraded_not_clean():
    async def _none(ctx, calls):
        return [None] * len(calls)
    res = run_plugin(_none)
    assert res.findings == []
    assert "DEGRADED" in res.reason


def test_decoders():
    assert bss.decode_uint("0x" + _word(150)) == 150
    assert bss.decode_uint("0x" + _word(7) + _word(9), 1) == 9
    assert bss.decode_uint("0x1234") is None
    assert bss.decode_bool("0x" + _word(1)) is True
    assert bss.decode_bool("0x" + _word(0)) is False
    assert bss.decode_address_array(_addr_array(LIVE_45)) == LIVE_45
    assert bss.decode_address_array(_mining_array(LIVE_21)) == LIVE_21
    assert bss.decode_address_array("0x") == []
