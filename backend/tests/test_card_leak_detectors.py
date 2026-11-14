"""Unit gate for the card-leak detector pack (2 detectors).

exposed_card_number_leak must fire on the canary (a Luhn-valid
non-test Visa PAN in an inline script + a Luhn-valid non-test
Mastercard PAN in /.env), stay silent on the clean site (published
test cards + a non-Luhn 16-digit number), and never carry a full
planted PAN in any finding (brand + BIN + last 4 + SHA-256
fingerprint only). cc_to_crypto_onramp must fire on the on-ramp
canary (MoonPay script src + Transak SDK reference) and on the
generic flow page (buy crypto with card), and stay silent on the
clean site. Live card endpoints are never called: liveness is never
probed, and the fixture PANs are generated non-test numbers.
"""

import asyncio
import hashlib
import json
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.card_leak_detectors import (  # noqa: E402
    TEST_PANS,
    brand_of,
    is_test_pan,
    scan_text_for_pans,
)
from app.plugins.cards import luhn_ok  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

CANARY = "cardleak.test"
CLEAN = "cardclean.test"
ONRAMP = "onramp.test"
FLOW = "flow.test"

# Fixture PANs: Luhn-valid, generated, NOT published test cards.
VISA_PAN = "4532015112830366"
MC_PAN = "5425233430109903"

CANARY_HOME = """<html><head><title>Leaky Shop</title></head><body>
<script>
var checkout = {"card_number": "4532015112830366", "exp": "12/27"};
</script>
<p>Pay with your credit card at checkout.</p>
</body></html>"""

CANARY_ENV = "PAYMENT_CARD=5425233430109903\nAPI_KEY=demo\n"
CANARY_ENV_LOCAL = 'CARD="4242424242424242"\n'

CLEAN_HOME = """<html><head><title>Clean Shop</title></head><body>
<p>Test with card 4242424242424242. Order ref 1234567890123456.</p>
</body></html>"""

ONRAMP_HOME = """<html><head><title>Buy Crypto</title>
<script src="https://buy.moonpay.com/index.js"></script>
</head><body>
<script>
const transak = new TransakConfig({apiKey: "demo"});
</script>
<p>Fast crypto purchases.</p>
</body></html>"""

FLOW_HOME = """<html><head><title>Buy BTC</title></head><body>
<p>Buy Bitcoin with a credit card today, no account needed.</p>
</body></html>"""

ROUTES = {
    CANARY: {
        "/": ("text/html", CANARY_HOME),
        "/.env": ("text/plain", CANARY_ENV),
        "/.env.local": ("text/plain", CANARY_ENV_LOCAL),
    },
    CLEAN: {
        "/": ("text/html", CLEAN_HOME),
    },
    ONRAMP: {
        "/": ("text/html", ONRAMP_HOME),
    },
    FLOW: {
        "/": ("text/html", FLOW_HOME),
    },
}


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    path = request.url.path or "/"
    route = ROUTES.get(host, {}).get(path)
    if route is not None:
        ctype, body = route
        return httpx.Response(200, content=body,
                              headers={"Content-Type": ctype},
                              request=request)
    return httpx.Response(404, content="not found", request=request)


def _ctx() -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                               follow_redirects=True, trust_env=False)
    return Ctx(run_id="card-leak-test", mode="active", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _run(pid: str, host: str):
    cls = discover()[pid]
    ctx = _ctx()
    target = Target(raw=f"https://{host}/", type="url",
                    normalized=f"https://{host}/")
    try:
        return asyncio.run(cls().run(target, ctx))
    finally:
        asyncio.run(ctx.http.aclose())


def _by_key(result, key):
    return [f for f in result.findings if f.key == key]


def _blob(result) -> str:
    return json.dumps([f.value for f in result.findings]) + json.dumps(
        [f.evidence for f in result.findings], default=str)


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------------------

def test_both_detectors_registered():
    reg = discover()
    assert "exposed_card_number_leak" in reg
    assert "cc_to_crypto_onramp" in reg
    assert len(reg) == 1438  # 1361 master + 2 card-leak detectors + 5 deep-audit batch-20 detectors (deep_audit20)


def test_card_leak_fires_two():
    r = _run("exposed_card_number_leak", CANARY)
    hits = _by_key(r, "exposed_card_number_leak")
    assert len(hits) == 2, r.reason
    by_brand = {f.evidence.get("brand"): f for f in hits}
    assert set(by_brand) == {"Visa", "Mastercard"}
    visa = by_brand["Visa"]
    assert visa.evidence.get("bin6") == "453201"
    assert visa.evidence.get("last4") == "0366"
    assert visa.evidence.get("fingerprint16") == _fp(VISA_PAN)[:16]
    assert visa.evidence.get("fingerprint_sha256") == _fp(VISA_PAN)
    assert visa.evidence.get("tag") == "UNVERIFIED"
    assert visa.evidence.get("fingerprint_only") is True
    assert visa.confidence == 75
    mc = by_brand["Mastercard"]
    assert mc.evidence.get("bin6") == "542523"
    assert mc.evidence.get("last4") == "9903"
    assert mc.evidence.get("fingerprint16") == _fp(MC_PAN)[:16]


def test_no_full_pan_in_any_finding():
    r = _run("exposed_card_number_leak", CANARY)
    blob = _blob(r)
    for pan in (VISA_PAN, MC_PAN, "4242424242424242"):
        assert pan not in blob, f"full PAN leaked: {pan[:6]}..."


def test_card_leak_clean_silent():
    r = _run("exposed_card_number_leak", CLEAN)
    assert r.findings == [], (r.reason, r.findings)


def test_test_pans_ignored():
    for pan in ("4111111111111111", "4242424242424242",
                "5555555555554444", "378282246310005",
                "371449635398431", "6011111111111117"):
        assert is_test_pan(pan)
        assert scan_text_for_pans(
            f'card_number "{pan}"', require_context=False) == []
    assert not is_test_pan(VISA_PAN)
    assert not is_test_pan(MC_PAN)


def test_luhn_and_brand_units():
    assert luhn_ok(VISA_PAN) and luhn_ok(MC_PAN)
    assert not luhn_ok("1234567890123456")
    assert not luhn_ok("4532015112830367")
    assert brand_of(VISA_PAN) == "Visa"
    assert brand_of(MC_PAN) == "Mastercard"
    assert brand_of("378282246310005") == "Amex"
    assert brand_of("6011111111111117") == "Discover"
    assert brand_of("1234567890123456") is None


def test_svg_path_coordinates_silent():
    # moonpay.com live false positive (Nov 12): SVG path coordinates
    # "M50 100C77.6142 100 ... 22.3858 ..." matched as the 13-digit
    # "3858 0 0 22.3858 0" and passed Luhn by chance, with card words
    # nearby. 1-3 digit groups are numeric soup, not a PAN.
    svg = (
        '<svg width="16" height="16" viewBox="0 0 100 100">'
        '<path d="M50 100C77.6142 100 100 77.6142 100 50C100 22.3858 '
        '77.6142 0 50 0C22.3858 0 0 22.3858 0 50C0 77.6142 22.3858 '
        '100 50 100Z"/></svg>'
        "<p>Pay with your credit card at checkout.</p>")
    assert scan_text_for_pans(svg, require_context=True) == []


def test_formatted_pan_groups():
    # Real formatted PANs use 4+ digit groups and must still fire.
    assert len(scan_text_for_pans(
        'card_number "4532 0151 1283 0366"', require_context=True)) == 1
    assert len(scan_text_for_pans(
        'card_number "4532-0151-1283-0366"', require_context=True)) == 1
    # A 3-digit group is not a formatted PAN.
    assert scan_text_for_pans(
        'card_number "4532 015 1283 0366"', require_context=True) == []


def test_context_gate_units():
    # Bare PAN with no card words nearby: silent on web/contract text.
    assert scan_text_for_pans(
        "order 4532015112830366 shipped", require_context=True) == []
    # Same PAN with card context: fires.
    assert len(scan_text_for_pans(
        'card_number "4532015112830366"', require_context=True)) == 1
    # Config files are ungated: fires without card words.
    assert len(scan_text_for_pans(
        "PAYMENT_CARD=5425233430109903", require_context=False)) == 1


def test_onramp_fires_two():
    r = _run("cc_to_crypto_onramp", ONRAMP)
    hits = _by_key(r, "cc_to_crypto_onramp")
    assert len(hits) == 2, r.reason
    by_provider = {f.evidence.get("provider"): f for f in hits}
    assert set(by_provider) == {"moonpay", "transak"}
    assert by_provider["moonpay"].evidence.get("marker_kind") == "script src"
    assert by_provider["moonpay"].confidence == 90
    assert by_provider["transak"].evidence.get("marker_kind") == \
        "SDK/widget reference"
    assert by_provider["transak"].confidence == 85
    assert all(f.evidence.get("tag") == "SURFACE" for f in hits)


def test_onramp_flow_generic():
    r = _run("cc_to_crypto_onramp", FLOW)
    hits = _by_key(r, "cc_to_crypto_onramp")
    assert len(hits) == 1, r.reason
    assert hits[0].evidence.get("provider") == "generic"
    assert hits[0].evidence.get("marker_kind") == "checkout flow"
    assert hits[0].confidence == 75


def test_onramp_clean_silent():
    r = _run("cc_to_crypto_onramp", CLEAN)
    assert r.findings == [], (r.reason, r.findings)
    r2 = _run("cc_to_crypto_onramp", CANARY)
    assert r2.findings == [], (r2.reason, r2.findings)


def test_no_card_data_in_onramp_findings():
    r = _run("cc_to_crypto_onramp", ONRAMP)
    blob = _blob(r)
    for pan in (VISA_PAN, MC_PAN):
        assert pan not in blob
