"""Unit gate for the neural scoring engine (app/nn_engine.py).

Pure-stdlib runtime: runs without fastapi/sqlalchemy/httpx/numpy, so it
works in any environment. Run directly (`python tests/test_nn_engine.py`)
or under pytest. Checks that:
  * the bundled weights load and the feature vector has its documented shape,
  * scoring is deterministic and total on malformed input,
  * a worse finding always outranks a benign one,
  * bands agree with scores and stay in range,
  * the run exposure block is bounded, ordered and clean on no findings,
  * a missing/corrupt model degrades instead of raising,
  * every score explains itself with real feature names.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import nn_engine  # noqa: E402
from app.correlate import correlate  # noqa: E402


def _f(plugin, category, key, value, severity="medium", exploitability="unknown",
       confidence=80, **ev):
    return {"plugin": plugin, "category": category, "key": key, "value": value,
            "confidence": confidence, "evidence": dict(severity=severity,
                                                      exploitability=exploitability,
                                                      **ev)}


def _band_of(score):
    return ("critical" if score >= 80 else "high" if score >= 55
            else "medium" if score >= 30 else "low" if score > 0 else "clean")


def test_model_available():
    assert nn_engine.available(), "nn_weights.json missing or invalid"
    assert nn_engine.N_FEATURES == len(nn_engine.FEATURE_NAMES)
    assert nn_engine.N_FEATURES == len(nn_engine.features({}))


def test_features_total_on_junk():
    for row in ({}, {"evidence": "not-a-dict"}, {"key": None, "value": 12345},
                {"evidence": {"severity": "weird"}, "confidence": "abc"}):
        x = nn_engine.features(row)
        assert len(x) == nn_engine.N_FEATURES, row
        assert all(isinstance(v, float) and v == v for v in x), row


def test_score_deterministic():
    row = _f("cves", "web", "cve_2021_44228_log4shell",
             "Log4Shell RCE", "critical", "weaponized", 95)
    a, b = nn_engine.score(row), nn_engine.score(row)
    assert a == b, (a, b)
    assert 0 <= a["score"] <= 100


def test_worse_finding_scores_higher():
    benign = _f("headers", "web", "missing_hsts", "HSTS not set", "low",
                "unknown", 45)
    bad = _f("keyharvest", "leak", "exposed_aws_access_key",
             "AKIAIOSFODNN7EXAMPLE", "critical", "weaponized", 95,
             commands=[{"cmd": "aws sts get-caller-identity"}])
    gap = nn_engine.score(bad)["score"] - nn_engine.score(benign)["score"]
    assert gap > 20, gap


def test_bands_match_scores():
    rows = [
        _f("x", "web", "missing_hsts", "", "low", "unknown", 40),
        _f("cves", "web", "rce_confirmed", "RCE", "critical", "weaponized", 95),
        _f("cors", "api", "cors_reflect_origin", "", "medium", "public_poc", 70),
    ]
    for r in rows:
        b = nn_engine.score(r)
        assert b["band"] == _band_of(b["score"]), b


def test_drivers_are_real_features():
    b = nn_engine.score(_f("git", "web", "git_exposed", ".git/config",
                           "high", "public_poc", 85))
    assert b["drivers"], b
    for d in b["drivers"]:
        assert d["feature"] in nn_engine.FEATURE_NAMES, d
        assert isinstance(d["contribution"], float)


def test_score_findings_aligned():
    rows = [_f("a", "web", "x", "1"), _f("b", "api", "y", "2")]
    out = nn_engine.score_findings(rows)
    assert len(out) == len(rows) and all(out)


def test_run_exposure_bounded_and_ordered():
    clean = nn_engine.score_run([])
    assert clean["score"] == 0 and clean["band"] == "clean", clean

    low = [_f("headers", "web", "missing_hsts", "", "low", "unknown", 40)]
    mixed = low + [_f("cors", "api", "cors_reflect_origin", "", "medium",
                      "public_poc", 70)]
    worst = mixed + [_f("keyharvest", "leak", "exposed_aws_access_key",
                        "AKIA", "critical", "weaponized", 95)]
    s_low = nn_engine.score_run(low)["score"]
    s_mixed = nn_engine.score_run(mixed)["score"]
    s_worst = nn_engine.score_run(worst)["score"]
    assert s_low < s_mixed < s_worst, (s_low, s_mixed, s_worst)
    assert 0 <= s_low and s_worst <= 100
    assert nn_engine.score_run(worst)["top"], "exposure block has no top findings"


def test_correlation_paths_are_scoreable():
    rows = [
        _f("keyharvest", "leak", "exposed_aws_access_key", "AKIA", "high",
           "weaponized"),
        _f("buckets", "leak", "s3_public_write", "s3://acme", "high"),
    ]
    paths, _exposure = correlate(rows)
    assert paths, "correlate produced no paths for the fixture"
    for p in paths:
        b = nn_engine.score(p)
        assert b is not None and b["score"] > 0, p.get("value")


def test_missing_model_degrades():
    assert nn_engine.load_model(Path("/nonexistent/nn_weights.json")) is None
    with tempfile.TemporaryDirectory() as d:
        bad = Path(d) / "nn_weights.json"
        bad.write_text(json.dumps({"layers": [{"w": [[1, 2]], "b": [0]}]}))
        assert nn_engine.load_model(bad) is None
    assert nn_engine.score(None) is None
    assert nn_engine.score_run([{"not": "a finding"}])["score"] >= 0


def test_priority_order_by_nn_score():
    from app.prioritizer import nn_priority_key, nn_score_of, sort_by_nn

    def row(score=None, sev="medium", **extra):
        r = {"plugin": "p", "category": "web", "key": "k", "value": "v",
             "confidence": 80, "evidence": {"severity": sev, **extra}}
        if score is not None:
            r["evidence"]["nn"] = {"score": score}
        return r

    rows = [row(10, "high"), row(90, "low"), row(50, "critical")]
    assert [nn_score_of(r) for r in sort_by_nn(rows)] == [90, 50, 10]
    # stable, and the input list is untouched
    assert [nn_score_of(r) for r in rows] == [10, 90, 50]

    # unscored legacy rows keep the heuristic order, behind scored ones
    legacy = [row(None, "critical"), row(None, "low")]
    assert [r["evidence"]["severity"] for r in sort_by_nn(legacy)] == [
        "critical", "low"]
    assert nn_score_of(row(None)) is None
    # ...and mixing them ranks scored rows first
    mixed = sort_by_nn(legacy + [row(5, "low")])
    assert nn_score_of(mixed[0]) == 5

    # CISA KEV still beats any model score
    kev = row(1, "low", kev=True)
    assert sort_by_nn([row(100, "critical"), kev])[0] is kev

    # a corrupt block degrades to the heuristic key, never raises
    bad = row(None)
    bad["evidence"]["nn"] = {"score": "not-a-number"}
    assert nn_score_of(bad) is None and nn_priority_key(bad)[2] == 1


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} nn engine tests passed")


if __name__ == "__main__":
    _run_all()
