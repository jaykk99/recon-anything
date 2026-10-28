"""Unit gate for the AI-crawler surface pack (ai_*, 5 detectors).

Every ai plugin runs through the REAL Ctx against a canary served
via httpx MockTransport (tests/aipack_samples.py): each extraction
class must fire on the canary, every plugin must stay silent on the
clean site, and no full planted secret may appear in any finding
(masked + fingerprint only).
"""
import asyncio
import hashlib
import json
import os
import sys
from urllib.parse import urlsplit

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aipack_samples as samples  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.plugins.aipack import AI_IDS, parse_llms_links, parse_robots_groups  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

CANARY = "canary.test"
CLEAN = "clean.test"


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    path = request.url.path or "/"
    if host == CLEAN:
        if path in ("/", "/index.html"):
            return httpx.Response(200, content=samples.CLEAN_HTML,
                                  headers={"Content-Type": "text/html"},
                                  request=request)
        if path == "/robots.txt":
            return httpx.Response(200, content=samples.CLEAN_ROBOTS,
                                  headers={"Content-Type": "text/plain"},
                                  request=request)
        return httpx.Response(404, content="not found", request=request)
    if host == CANARY:
        route = samples.ROUTES.get(path)
        if route is not None:
            ctype, body = route
            return httpx.Response(200, content=body,
                                  headers={"Content-Type": ctype},
                                  request=request)
        return httpx.Response(404, content="not found", request=request)
    return httpx.Response(404, content="", request=request)


def _ctx() -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                               follow_redirects=True, trust_env=False)
    return Ctx(run_id="aipack-test", mode="active", http=client,
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


def _run_with_ctx(pid: str, host: str):
    cls = discover()[pid]
    ctx = _ctx()
    target = Target(raw=f"https://{host}/", type="url",
                    normalized=f"https://{host}/")
    try:
        return asyncio.run(cls().run(target, ctx)), ctx
    finally:
        asyncio.run(ctx.http.aclose())


def _by_key(result, key):
    return [f for f in result.findings if f.key == key]


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _blob(result) -> str:
    return json.dumps([f.value for f in result.findings]) + json.dumps(
        [f.evidence for f in result.findings], default=str)


# ---------------------------------------------------------------------------

def test_exactly_5_new_detectors_registered():
    ai = sorted(k for k in discover() if k.startswith("ai_"))
    assert ai == sorted(AI_IDS)
    assert len(ai) == 5
    # 602 when the xml pack landed; +5 ai_* (AI-crawler surface pack)
    assert len(discover()) == 623  # 617 master + 5 cp_web3 gap plugins + 1 chain_followups (crypto-chain, rebased 2026-10-27)


def test_llms_index_present_and_links_fed_to_hunters():
    r, ctx = _run_with_ctx("ai_llms_index", CANARY)
    assert _by_key(r, "ai_llms_present"), r.reason
    assert _by_key(r, "ai_llms_full_present"), r.reason
    fed = ctx.consume("endpoints")
    assert any("internal.md" in u for u in fed), fed
    assert any("overview.md" in u for u in fed), fed
    # External links are reported, never fed to the bus.
    assert not any("example.org" in u for u in fed), fed


def test_llms_sensitive_and_external_links_flagged():
    r = _run("ai_llms_index", CANARY)
    sens = _by_key(r, "ai_llms_sensitive_link")
    assert any("/docs/internal.md" in f.value for f in sens), r.reason
    assert any("/private/guide.md" in f.value for f in sens), r.reason
    ext = _by_key(r, "ai_llms_external_link")
    assert ext and "example.org" in ext[0].value, r.reason


def test_llms_secret_masked_with_fingerprint():
    r = _run("ai_llms_secrets", CANARY)
    hits = _by_key(r, "ai_llms_secret")
    assert hits, r.reason
    fps = {f.evidence.get("fingerprint_sha256") for f in hits}
    assert _fp(samples.STRIPE_KEY) in fps
    assert samples.STRIPE_KEY not in _blob(r)


def test_robots_ai_inventory():
    r = _run("ai_robots_ai", CANARY)
    rules = _by_key(r, "ai_robots_bot_rule")
    assert any("GPTBot" in f.value and "blocked" in f.value
               for f in rules), r.reason
    assert any("ClaudeBot" in f.value
               and "partially restricted" in f.value
               for f in rules), r.reason


def test_llms_robots_conflict():
    r = _run("ai_llms_conflict", CANARY)
    hits = _by_key(r, "ai_llms_robots_conflict")
    assert hits and any("/private/guide.md" in f.value
                        for f in hits), r.reason
    # /docs/internal.md is NOT robots-disallowed: no conflict for it.
    assert not any("/docs/internal.md" in f.value for f in hits)


def test_tdm_reservation_and_policy():
    r = _run("ai_tdm", CANARY)
    assert _by_key(r, "ai_tdm_reservation"), r.reason
    assert _by_key(r, "ai_tdm_policy"), r.reason
    assert _by_key(r, "ai_tdmrep_present"), r.reason
    res = _by_key(r, "ai_tdm_reservation")[0]
    assert res.evidence.get("reserved") is True


def test_robots_group_parser_unit():
    groups = parse_robots_groups(samples.ROBOTS_TXT)
    assert len(groups) == 3
    assert groups[0]["agents"] == ["GPTBot"]
    assert groups[0]["disallow"] == ["/"]
    assert groups[0].get("tdm_reservation") == "1"
    assert groups[0].get("tdm_policy") == "/.well-known/tdmrep.json"


def test_llms_link_parser_unit():
    links = parse_llms_links(samples.LLMS_TXT, "https://canary.test")
    urls = [l["url"] for l in links]
    assert "https://canary.test/docs/internal.md" in urls
    assert "https://canary.test/private/guide.md" in urls
    ext = [l for l in links if not l["same_origin"]]
    assert ext and ext[0]["url"] == "https://example.org/other.md"


def test_all_plugins_silent_on_clean_site():
    for pid in AI_IDS:
        r = _run(pid, CLEAN)
        assert not r.findings, f"{pid} fired on clean site: {r.findings}"
