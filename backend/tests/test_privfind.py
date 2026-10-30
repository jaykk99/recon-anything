"""Unit gate for the pf_* private-findings pack (100 detectors).

Runs every pf plugin through the REAL Ctx against a canary site served
via httpx MockTransport (tests/privfind_samples.py): every detector
must fire on its planted fake secret, no detector may fire on the
clean site, and every planted SECRET value must appear IN FULL in its
finding value and evidence full_value (Jay's 2026-10-29 full-value
order), while planted PII values (identity category) never appear in
full anywhere (masked + fingerprint only).
"""
import asyncio
import hashlib
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import privfind_samples as samples  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.plugins import privfind  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

CANARY = "canary.test"
CLEAN = "clean.test"
CLEAN_HTML = ("<html><head><title>Clean Co</title></head><body>"
              "<h1>Clean Co</h1><p>Nothing sensitive here.</p></body></html>")

# Extracted secret values for the context-gated snippet detectors.
EXTRACTED = {
    "pf_otpauth_seed": "otpauth://totp/PFCanary:user@canary.test?secret=JBSWY3DPEHPK3PXP&issuer=PFCanary",
    "pf_filecoin_key_export": "UEZBQ0FOQVJZZmlsZWNvaW5rZXkwMTIzNDU2Nzg5YWJjZGVmZ2hpams=",
    "pf_tendermint_privkey": "UEZBQ0FOQVJZdmFsaWRhdG9ya2V5MDEyMzQ1Njc4OWFiY2RlZg==",
    "pf_near_secret_key": "3tgSMqsjcFKCe1T87n2gGGtYJvPFCanaryNearKey111",
    "pf_jwk_private_key": "UEZBQ0FOQVJZandsZXkwMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0",
    "pf_ably_api_key": "PFCAN1.PFCAN2:PFCANARYablysecret0123456789",
}
EXPECTED_VALUE = {**samples.VALUES, **EXTRACTED}

PF_IDS = sorted(privfind.PRIVFIND_IDS)
CONTENT_IDS = [s["id"] for s in privfind.CONTENT_SPECS]
PATH_IDS = [s["id"] for s in privfind.PATH_SPECS]


def _handler(request: httpx.Request) -> httpx.Response:
    host, path = request.url.host, request.url.path or "/"
    if host == CANARY:
        route = samples.ROUTES.get(path)
        if route is None:
            return httpx.Response(404, content="not found", request=request)
        ctype, body = route
        return httpx.Response(200, content=body,
                              headers={"Content-Type": ctype}, request=request)
    if host == CLEAN:
        if path in ("/", "/index.html"):
            return httpx.Response(200, content=CLEAN_HTML,
                                  headers={"Content-Type": "text/html"},
                                  request=request)
        return httpx.Response(404, content="not found", request=request)
    return httpx.Response(404, content="", request=request)


def _ctx() -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                               follow_redirects=True, trust_env=False)
    return Ctx(run_id="privfind-test", mode="active", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _run(pid: str, host: str):
    cls = discover()[pid]
    ctx = _ctx()
    target = Target(raw=f"https://{host}/", type="url",
                    normalized=f"https://{host}/")
    try:
        result = asyncio.run(cls().run(target, ctx))
        return result
    finally:
        asyncio.run(ctx.http.aclose())


def test_exactly_100_new_detectors_registered():
    pf = [k for k in discover() if k.startswith("pf_")]
    assert len(pf) == 100
    assert sorted(pf) == PF_IDS
    assert len(CONTENT_IDS) == 71 and len(PATH_IDS) == 29


def test_validators_accept_samples_and_reject_mutations():
    v = privfind.VALIDATORS
    checks = [
        ("ssn", samples.VALUES["pf_pii_ssn_us"]),
        ("sin", samples.VALUES["pf_pii_sin_ca"]),
        ("nhs", samples.VALUES["pf_pii_nhs_uk"]),
        ("nino", samples.VALUES["pf_pii_nino_uk"]),
        ("aadhaar", samples.VALUES["pf_pii_aadhaar_in"]),
        ("pan", samples.VALUES["pf_pii_pan_in"]),
        ("tfn", samples.VALUES["pf_pii_tfn_au"]),
        ("iban", samples.VALUES["pf_pii_iban"]),
        ("xrp_seed", samples.VALUES["pf_xrp_family_seed"]),
        ("stellar_secret", samples.VALUES["pf_stellar_secret_key"]),
    ]
    structural_bad = {
        "ssn": "000-45-6789",        # area 000 is never issued
        "nino": "QQ123456A",         # Q prefix is never issued
        "pan": "AAAZ1234C",          # 4th char must be a holder-type code
    }
    for name, good in checks:
        assert v[name](good), f"{name} rejected its canary value"
        if name in structural_bad:
            bad = structural_bad[name]
        else:
            bad = good[:-1] + ("0" if good[-1] != "0" else "1")
        assert not v[name](bad), f"{name} accepted mutated value {bad}"
    # Verhoeff reference vector: 236 -> check digit 3
    assert v["aadhaar"]("2363".ljust(12, "0")) is False  # wrong shape is fine
    assert privfind.v_aadhaar(samples.VALUES["pf_pii_aadhaar_in"])


@pytest.mark.parametrize("pid", CONTENT_IDS)
def test_content_detector_fires_on_canary(pid):
    result = _run(pid, CANARY)
    assert result.status.value == "ok", f"{pid}: {result.reason}"
    assert result.findings, f"{pid} produced no finding on the canary"
    expected = EXPECTED_VALUE[pid]
    fps = {f.evidence.get("fingerprint_sha256") for f in result.findings}
    assert hashlib.sha256(expected.encode()).hexdigest() in fps, (
        f"{pid}: no finding fingerprinted to its planted value; "
        f"got keys {[f.key for f in result.findings]}")


@pytest.mark.parametrize("pid", PATH_IDS)
def test_path_detector_fires_on_canary(pid):
    result = _run(pid, CANARY)
    assert result.status.value == "ok", f"{pid}: {result.reason}"
    assert result.findings, f"{pid} produced no finding on the canary"
    for f in result.findings:
        assert f.evidence.get("marker_matched") is True
        assert f.evidence.get("body_sha256")
        assert f.evidence.get("path")


@pytest.mark.parametrize("pid", PF_IDS)
def test_no_detector_fires_on_clean_site(pid):
    result = _run(pid, CLEAN)
    assert result.findings == [], (
        f"{pid} fired on the clean site: "
        f"{[f.value for f in result.findings]}")


PII_IDS = {s["id"] for s in privfind.CONTENT_SPECS
           if s["category"] == "identity"}


@pytest.mark.parametrize("pid", CONTENT_IDS)
def test_full_value_shown_for_secrets_masked_for_pii(pid):
    result = _run(pid, CANARY)
    expected = EXPECTED_VALUE[pid]
    for f in result.findings:
        blob = f.value + " " + str(f.evidence)
        assert f.evidence.get("match_redacted")
        if pid in PII_IDS:
            assert expected not in blob, \
                f"{pid} leaked its full PII value"
        else:
            assert expected in blob, \
                f"{pid} did not show its full secret value"
    if pid not in PII_IDS:
        assert any(f.evidence.get("full_value") == expected
                   for f in result.findings), \
            f"{pid}: no finding carried full_value"
