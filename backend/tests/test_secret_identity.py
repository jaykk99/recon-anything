"""Tests for secret identification with full values shown.

All values in this file are invented fakes for testing only. No real
secret appears here. Since Jay's 2026-10-29 order (reversing the
2026-10-27 masked-only rule), findings carry the full found value in
``full_value``, in the context snippet, and in the finding text, with
the fingerprint and masked preview kept as extra metadata.
"""
import asyncio
import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins.secret_identity import (  # noqa: E402
    contains_full_secret, context_snippet, fingerprint, identify_finding,
    mask_value, locate)
from app.plugins.secret_identity import SecretIdentityPlugin  # noqa: E402

# Invented fake value, used only as a canary in these tests.
FAKE_VALUE = "CANARY-FAKE-IDENTITY-VALUE-9876543210"
FAKE_PAGE = (
    "<html><head><title>Canary</title></head><body>\n"
    "<script>\n"
    f"const canary_api_key = \"{FAKE_VALUE}\";\n"
    "</script></body></html>")


def test_fingerprint_is_deterministic_and_sha256():
    assert fingerprint(FAKE_VALUE) == (
        "sha256:" + hashlib.sha256(FAKE_VALUE.encode()).hexdigest())
    assert fingerprint(FAKE_VALUE) == fingerprint(FAKE_VALUE)
    assert fingerprint(FAKE_VALUE) != fingerprint(FAKE_VALUE + "x")


def test_mask_value_is_only_a_preview():
    # The masked preview still exists as metadata; it is no longer the
    # only form of the value a finding carries.
    masked = mask_value(FAKE_VALUE)
    assert masked != FAKE_VALUE
    assert FAKE_VALUE not in masked
    assert masked.startswith(FAKE_VALUE[:4])
    assert masked.endswith(FAKE_VALUE[-4:])


def test_locate_and_context_snippet():
    text = "line one\nline two " + FAKE_VALUE + " tail\n"
    line, column = locate(text, FAKE_VALUE)
    assert line == 2
    assert column > 0
    ctx = context_snippet(text, FAKE_VALUE)
    # Context is shown exactly as found: the value is visible in it.
    assert FAKE_VALUE in ctx
    assert "[REDACTED]" not in ctx
    assert "line two" in ctx


def test_identify_finding_carries_full_value():
    ev = identify_finding(
        source="canary page", source_url="https://canary.test/",
        secret_type="canary_api_key", secret=FAKE_VALUE,
        context_text=FAKE_PAGE,
        derived_public_wallet="canary-public-wallet-label",
        balance="0 (canary, not a real balance)")
    assert ev["secret_type"] == "canary_api_key"
    assert ev["full_value"] == FAKE_VALUE
    assert ev["length"] == len(FAKE_VALUE)
    assert ev["masked_value"] == mask_value(FAKE_VALUE)
    assert ev["fingerprint"] == fingerprint(FAKE_VALUE)
    assert ev["line"] == 3
    assert ev["derived_public_wallet"] == "canary-public-wallet-label"
    assert ev["full_value_included"] is True
    assert contains_full_secret(ev, FAKE_VALUE)
    assert FAKE_VALUE in ev["context"]


def test_plugin_canary_through_real_pipeline():
    """Run the real plugin against a fake page served in-memory.

    This exercises the real Ctx/fetch path (not a unit stub of the
    plugin's own helpers): the plugin fetches the page, finds the
    assignment, and emits a finding showing the full value.
    """
    import httpx
    from app.cache import Cache
    from app.plugins.base import Ctx, Target
    from app.ratelimit import RateLimiter

    def handler(request):
        return httpx.Response(
            200, content=FAKE_PAGE,
            headers={"Content-Type": "text/html"}, request=request)

    async def run():
        client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            follow_redirects=True, trust_env=False)
        ctx = Ctx(run_id="secret-identity-canary", mode="passive",
                  http=client, cache=Cache(), keys={},
                  limiter=RateLimiter(), evidence_dir="/tmp",
                  source_type="website")
        try:
            result = await SecretIdentityPlugin().run(
                Target(raw="https://canary.test/", type="url",
                       normalized="https://canary.test/"), ctx)
            return result
        finally:
            await client.aclose()

    result = asyncio.run(run())
    assert result.findings, "canary plugin produced no findings"
    finding = result.findings[0]
    assert finding.plugin_id == "secret_identity"
    ev = finding.evidence
    assert ev["secret_type"] == "canary_api_key"
    assert ev["full_value"] == FAKE_VALUE
    assert ev["fingerprint"] == fingerprint(FAKE_VALUE)
    assert ev["line"] == 3
    assert ev["source_url"] == "https://canary.test/"
    # The whole finding carries the full fake value.
    assert contains_full_secret(finding.value, FAKE_VALUE)
    assert contains_full_secret(ev, FAKE_VALUE)
    assert FAKE_VALUE in json.dumps(finding.value)
    assert FAKE_VALUE in json.dumps(ev)


def test_matcher_identifies_by_fingerprint_without_revealing_value(tmp_path):
    labels = tmp_path / "labels.txt"
    labels.write_text(
        f"canary-label={FAKE_VALUE}\n"
        "other-label=SOME-OTHER-FAKE-VALUE-1234567890\n")
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([{
        "evidence": {"fingerprint": fingerprint(FAKE_VALUE)}}]))
    script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "scripts", "match_secret_fingerprint.py")
    proc = subprocess.run(
        [sys.executable, script, "--findings", str(findings),
         "--secrets-file", str(labels)],
        capture_output=True, text=True, check=False)
    assert proc.returncode == 0
    assert "MATCH label=canary-label" in proc.stdout
    assert fingerprint(FAKE_VALUE) in proc.stdout
    # The matcher must never print the value, even on a match.
    assert FAKE_VALUE not in proc.stdout
    assert FAKE_VALUE not in proc.stderr
