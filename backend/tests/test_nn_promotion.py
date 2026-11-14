"""nn_train promotion gate and --with-feedback training."""
import json
import shutil
from pathlib import Path

import pytest

from app import nn_engine, nn_train

np = pytest.importorskip("numpy")

SEVS = ["info", "low", "medium", "high", "critical"]


def _f(sev, conf=80, plugin="p"):
    return {"plugin": plugin, "category": "web", "key": f"k_{plugin}",
            "value": "v", "confidence": conf,
            "evidence": {"severity": sev, "exploitability": "unknown"}}


def _write(path, recs):
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))
    return path


def _inverted_corpus(tmp_path):
    # labels that REVERSE severity: any model fit to this breaks the gate
    recs = [{"finding": _f(s, c, plugin=f"p{i}{c}"), "label": 1 - i / 4}
            for i, s in enumerate(SEVS) for c in (30, 60, 90) for _ in range(4)]
    return _write(tmp_path / "inv.jsonl", recs)


@pytest.fixture()
def weights(tmp_path):
    w = tmp_path / "weights.json"
    shutil.copy(nn_train.WEIGHTS_PATH, w)
    return w


def test_shipped_model_passes_properties_and_old_one_would_not():
    assert nn_train.check_properties(nn_engine.load_model()) == []
    bad = json.loads(Path(nn_train.WEIGHTS_PATH).read_text())
    for layer in bad["layers"]:  # flip the network's sign: order reverses
        if layer["name"] == "actionability":
            layer["w"] = [[-v for v in row] for row in layer["w"]]
    assert nn_train.check_properties(bad)


def test_gate_refuses_a_model_that_breaks_ordering(tmp_path, weights):
    before = weights.read_bytes()
    m = nn_train.run(_inverted_corpus(tmp_path), epochs=200, out=weights)
    assert m["promoted"] is False and m["property_violations"]
    assert "ranking-property" in m["gate"][0]
    assert weights.read_bytes() == before


def test_force_writes_anyway_and_says_so(tmp_path, weights):
    m = nn_train.run(_inverted_corpus(tmp_path), epochs=200, out=weights,
                     force=True)
    assert m["promoted"] is True and m["gate"][0].startswith("forced past")
    assert json.loads(weights.read_text())["training"]["records"] == m["records"]


def test_dry_run_reports_gate_and_writes_nothing(tmp_path):
    m = nn_train.run(_inverted_corpus(tmp_path), epochs=50, out=None)
    assert m["promoted"] is False and m["gate"]


def test_promotes_when_clean(tmp_path, weights, monkeypatch):
    monkeypatch.setattr(nn_train, "check_properties", lambda model: [])
    recs = [{"finding": _f(s, c, plugin=f"p{i}{c}"), "label": i / 4}
            for i, s in enumerate(SEVS) for c in (30, 60, 90) for _ in range(4)]
    m = nn_train.run(_write(tmp_path / "ok.jsonl", recs), epochs=100,
                     out=weights)
    assert m["promoted"] is True and m["gate"] == ["passed"]


def test_with_feedback_mixes_weighted_labels_and_evaluates(tmp_path, weights,
                                                            monkeypatch):
    monkeypatch.setattr(nn_train, "check_properties", lambda model: [])
    base = _write(tmp_path / "base.jsonl",
                  [{"finding": _f(s, plugin=f"b{i}{j}"), "label": i / 4}
                   for i, s in enumerate(SEVS) for j in range(6)])
    fb = _write(tmp_path / "fb.jsonl",
                [{"finding": _f(s, plugin=f"f{i}"), "label": float(i >= 3)}
                 for i, s in enumerate(SEVS)])
    m = nn_train.run(base, epochs=100, out=weights, feedback_path=fb,
                     feedback_weight=3)
    assert m["feedback_labels"] == 5 and m["feedback_weight"] == 3
    assert m["records"] == 30 + 5 * 3
    fe = m["feedback_eval"]
    assert {"candidate", "current", "scope"} <= set(fe)


def test_refuses_when_feedback_ranking_gets_worse(tmp_path, weights,
                                                  monkeypatch):
    monkeypatch.setattr(nn_train, "check_properties", lambda model: [])
    calls = iter([{"spearman": 0.2}, {"spearman": 0.9}])  # candidate, current
    monkeypatch.setattr(nn_train, "evaluate_records",
                        lambda *a, **k: dict(next(calls), records=5))
    base = _write(tmp_path / "base.jsonl",
                  [{"finding": _f(s, plugin=f"b{i}{j}"), "label": i / 4}
                   for i, s in enumerate(SEVS) for j in range(6)])
    fb = _write(tmp_path / "fb.jsonl",
                [{"finding": _f(s, plugin=f"f{i}"), "label": float(i >= 3)}
                 for i, s in enumerate(SEVS)])
    before = weights.read_bytes()
    m = nn_train.run(base, epochs=50, out=weights, feedback_path=fb)
    assert m["promoted"] is False and "worse" in m["gate"][0]
    assert weights.read_bytes() == before


def test_cli_exit_code_3_when_not_promoted(tmp_path, weights, capsys):
    rc = nn_train.main(["--corpus", str(_inverted_corpus(tmp_path)),
                        "--epochs", "100", "--out", str(weights)])
    assert rc == 3
    assert "NOT promoted" in capsys.readouterr().out


def test_dry_run_compares_feedback_against_shipped_model(tmp_path):
    base = _write(tmp_path / "base.jsonl",
                  [{"finding": _f(s, plugin=f"b{i}{j}"), "label": i / 4}
                   for i, s in enumerate(SEVS) for j in range(6)])
    fb = _write(tmp_path / "fb.jsonl",
                [{"finding": _f(s, plugin=f"f{i}"), "label": float(i >= 3)}
                 for i, s in enumerate(SEVS)])
    m = nn_train.run(base, epochs=50, out=None, feedback_path=fb)
    assert "current" in m["feedback_eval"] and m["promoted"] is False
