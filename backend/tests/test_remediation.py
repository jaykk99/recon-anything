"""Recon -> remediation workflow (app/remediation.py): offline, fake LLM."""
import json

from app import remediation as rem


def _row(i, score, sev="high", **kw):
    ev = {"severity": sev, "nn": {"score": score}} if score is not None \
        else {"severity": sev}
    return {"id": i, "plugin": "headers", "category": "web",
            "key": kw.get("key", f"k{i}"), "value": kw.get("value", "v"),
            "source": "s", "confidence": 90, "evidence": ev}


def test_queue_orders_by_nn_score_and_applies_threshold_and_limit():
    rows = [_row(1, 30), _row(2, 90), _row(3, 60), _row(4, 75), _row(5, None)]
    q = rem.select_queue(rows, min_score=40, limit=2)
    assert [r["id"] for r in q] == [2, 4]
    assert rem.select_queue(rows, min_score=95) == []


def test_info_and_unscored_findings_never_queue():
    rows = [_row(1, 99, sev="info"), _row(2, None)]
    assert rem.select_queue(rows, min_score=0) == []


def test_prompt_redacts_credentials():
    secret = "AKIA" + "A" * 16
    p = rem.build_prompt(_row(1, 80, value=f"key {secret} and 0x{'ab' * 32}"))
    assert secret not in p and "0x" + "ab" * 32 not in p
    assert "[REDACTED]" in p


def test_system_prompt_is_defensive_only():
    assert "Never produce exploit code" in rem.SYSTEM_PROMPT


def test_pipeline_drafts_fix_and_test_and_survives_errors():
    calls = []

    def fake(system, user):
        calls.append(user)
        if len(calls) == 2:
            raise RuntimeError("provider down")
        return "```fix\nAdd HSTS.\n```\n```python\ndef test_x():\n    assert True\n```"

    res = rem.run_pipeline([_row(1, 90), _row(2, 80), _row(3, 70)],
                           complete=fake, min_score=40, limit=5)
    assert [r["status"] for r in res] == ["drafted", "error", "drafted"]
    assert res[0]["fix"] == "Add HSTS." and "def test_x" in res[0]["test"]


def test_incomplete_response_is_flagged_not_trusted():
    res = rem.run_pipeline([_row(1, 90)], complete=lambda s, u: "no blocks",
                           min_score=0)
    assert res[0]["status"] == "incomplete"


def test_write_results_creates_reviewable_files(tmp_path):
    res = rem.run_pipeline(
        [_row(1, 90, key="hsts_missing")],
        complete=lambda s, u: "```fix\nF\n```\n```python\nassert True\n```",
        min_score=0)
    rem.write_results(res, tmp_path)
    names = {p.name for p in tmp_path.iterdir()}
    assert "index.json" in names
    assert any(n.endswith(".fix.md") for n in names)
    assert any(n.startswith("test_") for n in names)
    assert "fix" not in json.loads((tmp_path / "index.json").read_text())[0]


def test_unknown_provider_is_rejected(monkeypatch):
    monkeypatch.setenv("RECON_LLM_PROVIDER", "nope")
    try:
        rem.get_completer()
    except RuntimeError as e:
        assert "unknown" in str(e)
    else:
        raise AssertionError("expected RuntimeError")
