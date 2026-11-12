"""Tests for the keyless Venice analysis pack.

The pack builder makes no network calls and needs no API key: it
turns a completed run into paste-ready markdown for Venice's free
guest chat. Tests assert content, the size cap, and that no key can
ever leak into a pack.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.venice_pack import (  # noqa: E402
    DEFAULT_MAX_CHARS,
    SUGGESTED_MODEL,
    build_pack,
    collect_repo_context,
    pack_size_note,
)
from app.vuln_advisor import advise, advise_with_pack  # noqa: E402


def _f(key, plugin="p", category="web", value="v", evidence=None,
       source_url=None):
    d = {"key": key, "plugin": plugin, "category": category, "value": value,
         "evidence": evidence or {}, "source": "s"}
    if source_url:
        d["source_url"] = source_url
    return d


def _summary():
    return {"targets": [{"normalized": "example.com"}]}


def _cands():
    findings = [
        _f("phpinfo_exposed", source_url="https://example.com/phpinfo.php"),
        _f("graphql_introspection_enabled"),
    ]
    return advise(findings, _summary()), findings


def test_pack_contains_candidates_and_instructions():
    cands, findings = _cands()
    pack = build_pack(cands, findings=findings, run_summary=_summary())
    assert "phpinfo" in pack
    assert "graphql-introspection" in pack
    assert SUGGESTED_MODEL in pack
    assert "venice.ai" in pack
    # Detection-only guardrail is in the pack's instructions.
    assert "do NOT write executable" in pack
    assert "do NOT give instructions to take funds" in pack


def test_pack_respects_char_budget():
    cands, findings = _cands()
    pack = build_pack(cands, findings=findings, run_summary=_summary(),
                      max_chars=500)
    assert len(pack) <= 500
    # Top-ranked candidate survives the cut; the header stays.
    assert "phpinfo" in pack
    assert pack.startswith("# ReconAnything analysis pack")


def test_pack_with_no_candidates_says_so():
    pack = build_pack([], findings=[], run_summary=_summary())
    assert "no advisor candidates" in pack


def test_pack_includes_code_excerpts_when_given():
    cands, findings = _cands()
    pack = build_pack(cands, findings=findings, run_summary=_summary(),
                      code_context=[{"path": "app/foo.py",
                                     "excerpt": "def leak(): pass"}])
    assert "app/foo.py" in pack
    assert "def leak(): pass" in pack


def test_pack_size_note_reports_chars_and_tokens():
    note = pack_size_note("x" * 4000)
    assert "4000 chars" in note
    assert "~1000 tokens" in note


def test_collect_repo_context_reads_files_and_skips_missing(tmp_path):
    good = tmp_path / "a.py"
    good.write_text("print('hi')\n" * 50)
    ctx = collect_repo_context([str(good), str(tmp_path / "nope.py")],
                               max_chars=2000)
    assert len(ctx) == 1
    assert ctx[0]["path"] == str(good)
    assert "print('hi')" in ctx[0]["excerpt"]


def test_collect_repo_context_respects_budget(tmp_path):
    big = tmp_path / "big.py"
    big.write_text("x" * 5000)
    ctx = collect_repo_context([str(big)], max_chars=100)
    assert len(ctx) == 1
    assert len(ctx[0]["excerpt"]) <= 100


def test_advise_with_pack_matches_heuristic_candidates():
    findings = [
        _f("phpinfo_exposed", source_url="https://example.com/phpinfo.php"),
        _f("graphql_introspection_enabled"),
    ]
    result = advise_with_pack(findings, _summary())
    assert result["candidates"] == advise(findings, _summary())
    assert "phpinfo" in result["venice_pack"]
    assert result["venice_pack_chars"] == len(result["venice_pack"])
    assert result["venice_pack_chars"] <= DEFAULT_MAX_CHARS
    assert "venice.ai" in result["how_to_use"]
    assert SUGGESTED_MODEL in result["how_to_use"]


def test_advise_with_pack_empty_findings_no_crash():
    result = advise_with_pack([], _summary())
    assert result["candidates"] == []
    assert "no advisor candidates" in result["venice_pack"]


def test_pack_never_contains_an_api_key(monkeypatch):
    monkeypatch.setenv("VENICE_API_KEY", "sk-test-key-that-must-not-leak")
    cands, findings = _cands()
    pack = build_pack(cands, findings=findings, run_summary=_summary())
    assert "sk-test-key-that-must-not-leak" not in pack
    result = advise_with_pack(findings, _summary())
    assert "sk-test-key-that-must-not-leak" not in result["venice_pack"]
    assert "sk-test-key-that-must-not-leak" not in result["how_to_use"]
