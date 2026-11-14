"""Tests for the LLM advisor (feat/llm-advisor).

Offline tests only: no network calls. Live behaviour (real model
outputs on real findings) is verified by scripts/verify_llm_advisor.py,
whose output is recorded in app/llm_advisor/VERIFY_2026-11-14.md.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.llm_advisor import client, prompts  # noqa: E402
from app.llm_advisor.enrich import draft_detector, stress_hypothesis  # noqa: E402
from app.vuln_advisor import advise, advise_with_llm  # noqa: E402


def test_chain_order_winner_first():
    labels = [b["label"] for b in client.DEFAULT_CHAIN]
    assert labels[0] == "meromero-26b", labels
    assert labels[1] == "heretic-31b"
    assert labels[2] == "rocinante-12b"
    assert "qwen3-14b" not in labels, "qwen3 403s on every attempt, must stay out"
    assert labels[-1] == "dolphin-3b"


def test_chain_env_override():
    os.environ["RECON_LLM_CHAIN"] = "heretic-31b,meromero-26b"
    try:
        assert [b["label"] for b in client._chain()] == [
            "heretic-31b", "meromero-26b"]
    finally:
        del os.environ["RECON_LLM_CHAIN"]


def test_is_refusal():
    assert client.is_refusal("I'm sorry, I can't help with that request at all, sorry.")
    assert client.is_refusal("I'm not here for stories like that, find someone else.")
    assert not client.is_refusal("An unguarded mint lets anyone create tokens.")
    assert not client.is_refusal("short")


def test_prompts_never_claim_verified():
    findings = [{"plugin": "p", "key": "k", "severity": "high",
                 "chain": "bsc", "address": "0xabc", "function": "mint",
                 "validation": {"verdict": "UNVERIFIED", "reason": "no src"}}]
    assert "UNVERIFIED" in prompts.rank_findings_prompt(findings)
    assert "never claim" in prompts.SYSTEM.lower()
    cand = {"name": "x", "severity": "high", "confidence": 80,
            "why_viable": "y", "evidence_refs": []}
    assert "UNVERIFIED" in prompts.explain_candidate_prompt(cand)
    assert "UNVERIFIED" in prompts.hypothesis_prompt({"kind": "mint"})


def test_advise_with_llm_offline_disabled():
    os.environ["RECON_LLM_OFF"] = "1"
    try:
        findings = [{"key": "phpinfo_exposed",
                     "source_url": "https://example.com/phpinfo.php"}]
        out = advise_with_llm(findings, {"targets": [{"normalized": "example.com"}]})
        assert out["llm"]["enabled"] is False
        assert out["candidates"] == advise(findings, {"targets": [{"normalized": "example.com"}]})
        assert all("llm_analysis" not in c for c in out["candidates"])
    finally:
        del os.environ["RECON_LLM_OFF"]


def _offline(monkeypatch=None):
    """Stub out all transport so the test never touches the network."""
    import app.llm_advisor.client as _c
    import app.llm_advisor.enrich as _e

    def _dead(*a, **k):
        raise RuntimeError("offline (test stub)")

    _c._call_direct = _dead
    _c._post_json = _dead
    _e.chat = _c.chat  # enrich imports chat at module load; keep it
    return _c


def test_advise_with_llm_offline_no_network():
    # All transports stubbed dead: enrichment must fail soft, never
    # raise, never change heuristic candidates.
    _offline()
    findings = [{"key": "phpinfo_exposed",
                 "source_url": "https://example.com/phpinfo.php"}]
    base = advise(findings, {"targets": [{"normalized": "example.com"}]})
    out = advise_with_llm(findings, {"targets": [{"normalized": "example.com"}]})
    # Enrichment may only ADD llm_analysis; it must never change the
    # heuristic fields (confidence, verified, needs_manual_verification).
    for got, want in zip(out["candidates"], base):
        assert {k: v for k, v in got.items() if k != "llm_analysis"} == want
        assert got.get("llm_analysis", {}).get("error")
    assert out["llm"]["enabled"] is False


def test_draft_detector_and_stress_fail_soft_offline():
    _offline()
    assert draft_detector({"name": "x", "why_viable": "y"})["code"] is None
    assert stress_hypothesis({"kind": "mint"})["text"] is None
