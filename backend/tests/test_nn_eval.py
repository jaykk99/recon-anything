"""Neural engine evaluation: ranking properties of the shipped weights,
plus the nn_train --eval / --dry-run tooling."""
import json

import pytest

from app import nn_engine, nn_train

SEVS = ["info", "low", "medium", "high", "critical"]


def _f(sev="medium", conf=80, key="generic_issue", plugin="headers",
       exploit="unknown"):
    return {"plugin": plugin, "category": "web", "key": key, "value": "v",
            "confidence": conf,
            "evidence": {"severity": sev, "exploitability": exploit}}


def _s(row):
    return nn_engine.score(row)["score"]


def test_severity_is_monotone():
    scores = [_s(_f(sev=s)) for s in SEVS]
    assert scores == sorted(scores), dict(zip(SEVS, scores))
    assert scores[-1] > scores[0]


def test_confidence_never_lowers_the_score():
    lo, hi = _s(_f(sev="high", conf=30)), _s(_f(sev="high", conf=95))
    assert hi >= lo, (lo, hi)


def test_irrelevant_fields_do_not_move_the_score():
    a = _f(sev="high")
    b = dict(a, id=999, first_seen="2026-01-01", target_id="zzz")
    assert _s(a) == _s(b)


def test_scores_bounded_for_every_severity_and_confidence():
    for s in SEVS:
        for c in (0, 50, 100):
            v = _s(_f(sev=s, conf=c))
            assert 0 <= v <= 100


def _write_labels(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_evaluate_reports_metrics_without_numpy_or_training(tmp_path):
    labels = tmp_path / "labels.jsonl"
    _write_labels(labels, [
        {"finding": _f(sev="critical", conf=95), "label": 0.95},
        {"finding": _f(sev="high", conf=90), "label": 0.8},
        {"finding": _f(sev="medium"), "label": 0.4},
        {"finding": _f(sev="low", conf=40), "label": 0.1},
        {"finding": _f(sev="info", conf=30), "label": 0.0},
        "not json is skipped",
    ])
    m = nn_train.evaluate(labels, k=2)
    assert m["records"] == 5
    assert m["spearman"] > 0.8, m  # model orders these like the labels
    assert m["precision_at_2"] == 1.0
    assert 0 <= m["mae"] <= 1


def test_eval_cli_does_not_touch_weights(tmp_path, capsys):
    labels = tmp_path / "labels.jsonl"
    _write_labels(labels, [{"finding": _f(sev=s), "label": i / 4}
                           for i, s in enumerate(SEVS)])
    before = nn_train.WEIGHTS_PATH.read_bytes()
    assert nn_train.main(["--eval", str(labels)]) == 0
    assert "spearman" in capsys.readouterr().out
    assert nn_train.WEIGHTS_PATH.read_bytes() == before


def test_dry_run_trains_but_writes_nothing(tmp_path):
    pytest.importorskip("numpy")
    labels = tmp_path / "labels.jsonl"
    rows = [{"finding": _f(sev=s, conf=c, key=f"k{s}{c}", plugin=f"p{i}"),
             "label": i / 4}
            for i, s in enumerate(SEVS) for c in (30, 60, 90)] * 3
    _write_labels(labels, rows)
    out = tmp_path / "weights.json"
    m = nn_train.run(labels, epochs=20, out=None)
    assert m["records"] == len(rows) and "holdout_spearman" in m
    assert not out.exists()


def test_evaluate_rejects_empty_corpus(tmp_path):
    empty = tmp_path / "e.jsonl"
    empty.write_text("")
    with pytest.raises(SystemExit):
        nn_train.evaluate(empty)
