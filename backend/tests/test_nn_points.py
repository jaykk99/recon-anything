"""Unit + real-model gate for the NN point system (app/nn/points.py).

Jay's rule: +1 point per right call, -1 per wrong call, over real
adjudicated findings. Run directly (`python tests/test_nn_points.py`)
or under pytest. Checks that:
  * point math is exact (+1 / -1, no partial credit),
  * streaks reset on a wrong call and carry across ledger rounds,
  * per-plugin and per-chain points sum to the round total,
  * the ledger round-trips (save -> load -> append a round),
  * the verdict fallback labels rows that carry no numeric label,
  * the REAL shipped models reproduce their honest numbers on the
    frozen 145-row own holdout (multimodal +137, v2 +119), scored
    through the real runtime load path.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn import points  # noqa: E402

_HERE = Path(__file__).resolve().parent
BACKEND = _HERE.parent
HOLDOUT = BACKEND / "app" / "nn" / "eval" / "own-holdout-145.jsonl"


def _row(label, plugin="unchecked_math_user_input", chain="bsc"):
    return {"label": label, "plugin": plugin, "chain": chain,
            "finding": {"plugin": plugin, "key": plugin, "confidence": 80,
                        "severity": "high", "value": "x"}}


def test_point_math_exact():
    # Fake scorer: p=0.9 (predict 1) for the first two rows, p=0.1
    # (predict 0) for the last two. Labels 1, 0, 1, 0.
    ps = iter([0.9, 0.9, 0.1, 0.1])
    rows = [_row(1), _row(0), _row(1), _row(0)]
    results = points.score_rows(None, rows, scorer=lambda f: next(ps))
    assert [r["points"] for r in results] == [1, -1, -1, 1]
    assert [r["pred"] for r in results] == [1, 1, 0, 0]
    assert [r["correct"] for r in results] == [True, False, False, True]


def test_unscored_counts_as_wrong():
    rows = [_row(1)]
    results = points.score_rows(None, rows, scorer=lambda f: None)
    assert results[0]["points"] == -1
    assert results[0]["correct"] is False


def test_streaks_and_per_plugin_sums():
    ps = iter([0.9, 0.9, 0.1, 0.9, 0.9])
    rows = [_row(1, plugin="a"), _row(1, plugin="a"), _row(1, plugin="b"),
            _row(0, plugin="b"), _row(1, plugin="a")]
    rnd = points.run_round("fake", rows, scorer=lambda f: next(ps))
    assert rnd["points"] == 1  # +1 +1 -1 -1 +1
    assert rnd["n_tests"] == 5
    assert rnd["correct"] == 3
    assert rnd["streak_end"] == 1  # last row right, previous wrong
    assert rnd["best_streak"] == 2
    assert rnd["per_plugin"] == {"a": 3, "b": -2}
    assert sum(rnd["per_plugin"].values()) == rnd["points"]
    assert sum(rnd["per_chain"].values()) == rnd["points"]


def test_ledger_round_trip_and_streak_carry():
    ps1 = iter([0.9, 0.9, 0.1])
    rows1 = [_row(1), _row(1), _row(1)]
    rnd1 = points.run_round("fake", rows1, scorer=lambda f: next(ps1))
    ledger = points.empty_ledger()
    points.apply_round(ledger, rnd1)
    assert ledger["total_points"] == 1  # +1 +1 -1
    assert ledger["current_streak"] == 0  # round ended on a wrong call
    assert ledger["best_streak"] == 2
    assert len(ledger["rounds"]) == 1

    ps2 = iter([0.9, 0.9])
    rows2 = [_row(0), _row(0)]
    rnd2 = points.run_round("fake", rows2, scorer=lambda f: next(ps2))
    points.apply_round(ledger, rnd2)
    assert ledger["total_points"] == -1  # +1 -1 -1
    assert ledger["current_streak"] == 0
    assert len(ledger["rounds"]) == 2

    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "ledger.json"
        points.save_ledger(ledger, path)
        back = points.load_ledger(path)
    assert back["total_points"] == ledger["total_points"]
    assert back["n_tests"] == 5
    assert len(back["rounds"]) == 2
    assert back["per_plugin"] == ledger["per_plugin"]


def test_verdict_fallback_labels():
    rows = [{"verdict": "UNVERIFIED", "plugin": "p", "chain": "bsc",
             "finding": {"plugin": "p"}},
            {"verdict": "FALSE_POSITIVE", "plugin": "p", "chain": "bsc",
             "finding": {"plugin": "p"}},
            {"verdict": "TRIGGER_ONLY", "plugin": "p", "chain": "bsc",
             "finding": {"plugin": "p"}}]
    ps = iter([0.9, 0.9, 0.9])
    results = points.score_rows(None, rows, scorer=lambda f: next(ps))
    assert [r["label"] for r in results] == [1, 0, 0]
    assert [r["points"] for r in results] == [1, -1, -1]


def test_summarize_lists_top_and_bottom_plugin():
    ledger = points.empty_ledger()
    ledger["per_plugin"] = {"good": 40, "bad": -7, "mid": 3}
    ledger["per_chain"] = {"bsc": 36}
    ledger["total_points"] = 36
    ledger["n_tests"] = 50
    ledger["n_correct"] = 43
    ledger["n_wrong"] = 7
    ledger["accuracy"] = 0.86
    text = points.summarize(ledger)
    assert "total points: 36" in text
    assert "top plugin: good (+40 pts)" in text
    assert "bottom plugin: bad (-7 pts)" in text


def test_real_models_on_frozen_holdout():
    """Real-model smoke: both shipped models through the real runtime
    load path on the frozen 145-row own holdout. Numbers below were
    measured by running (NN-REVAL-2026-11-14 agrees); they guard
    against silent regressions in the scorer or the eval set."""
    assert HOLDOUT.exists(), "frozen holdout missing from the repo"
    rows = points.load_eval_rows(HOLDOUT)
    assert len(rows) == 145
    assert sum(points.row_label(r) for r in rows) == 124

    multi = points.run_round("multimodal", rows)
    assert multi["confusion"] == {"tp": 122, "fp": 2, "fn": 2, "tn": 19}
    assert multi["accuracy"] == 0.9724
    assert multi["points"] == 137

    v2 = points.run_round("v2", rows)
    assert v2["confusion"] == {"tp": 114, "fp": 3, "fn": 10, "tn": 18}
    assert v2["accuracy"] == 0.9103
    assert v2["points"] == 119


def test_cli_both_models_writes_ledger(tmp_path=None):
    import io
    from contextlib import redirect_stdout

    with tempfile.TemporaryDirectory() as d:
        ledger_path = Path(d) / "ledger.json"
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = points.main(["--model", "both", "--rounds", "1",
                              "--eval", str(HOLDOUT),
                              "--ledger", str(ledger_path)])
        out = buf.getvalue()
        assert rc == 0
        assert "[multimodal] round 1: +137 points" in out
        assert "[v2] round 1: +119 points" in out
        assert "total points: 256" in out  # 137 + 119
        ledger = points.load_ledger(ledger_path)
        assert ledger["n_tests"] == 290
        assert len(ledger["rounds"]) == 2


if __name__ == "__main__":
    test_point_math_exact()
    test_unscored_counts_as_wrong()
    test_streaks_and_per_plugin_sums()
    test_ledger_round_trip_and_streak_carry()
    test_verdict_fallback_labels()
    test_summarize_lists_top_and_bottom_plugin()
    test_real_models_on_frozen_holdout()
    test_cli_both_models_writes_ledger()
    print("test_nn_points: all 8 tests passed")
