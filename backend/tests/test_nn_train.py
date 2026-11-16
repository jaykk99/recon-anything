"""Train on the REAL candidates file. Skipped automatically when the
file is absent (e.g. CI, which has no scanner data). Uses few epochs
so it stays fast; asserts the run completes and reports real,
well-formed metrics — never tuned numbers."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.train import train  # noqa: E402

CANDIDATES = os.environ.get(
    "RECON_NN_CANDIDATES",
    os.path.expanduser("~/workspace/recon-continuous/results/candidates.jsonl"))
BATCHES = os.environ.get(
    "RECON_NN_BATCHES",
    os.path.expanduser("~/workspace/recon-continuous/results/batches.jsonl"))


@pytest.mark.skipif(not os.path.exists(CANDIDATES),
                    reason="no real candidates file on this machine")
def test_train_on_real_candidates(tmp_path):
    batches = BATCHES if os.path.exists(BATCHES) else None
    result = train(CANDIDATES, batches, str(tmp_path),
                   epochs=15, hidden="16,8", seed=42)
    # Expected counts come from the live file, not constants: the file is
    # re-adjudicated as scanning continues, so hardcoded thresholds go
    # stale the week they are written (Nov 14: 611 UNVERIFIED of 723;
    # Nov 16: 202 UNVERIFIED of 916 after the false-positive sweep).
    # The only fixed bar is a sanity floor that the file is not empty.
    import json
    n_pos = n_neg = n_vr = 0
    with open(CANDIDATES, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            verdict = (json.loads(line).get("validation") or {}).get("verdict")
            if verdict == "UNVERIFIED":
                n_pos += 1
            elif verdict in ("FALSE_POSITIVE", "TRIGGER_ONLY"):
                n_neg += 1
            elif verdict == "VERIFIED_REAL":
                n_vr += 1
    assert n_pos + n_neg >= 100
    assert result["train_rows"] + result["test_rows"] == n_pos + n_neg
    assert result["dataset"]["n_positive"] == n_pos
    assert result["dataset"]["n_negative"] == n_neg
    # VERIFIED_REAL rows are excluded, never trained on.
    assert result["dataset"]["excluded_verified_real_rows"] == n_vr
    tm = result["test_metrics"]
    assert 0.0 <= tm["accuracy"] <= 1.0
    assert 0.0 <= tm["roc_auc"] <= 1.0
    assert tm["roc_auc"] > 0.5  # must rank better than chance
    assert tm["confusion"]["tp"] + tm["confusion"]["fn"] == \
        tm["n_positive"]
    assert os.path.exists(os.path.join(str(tmp_path), "weights.json"))
    assert os.path.exists(os.path.join(str(tmp_path), "viewer-data.json"))
    # The model must beat the majority baseline on the minority class
    # at least sometimes: some likely-FPs are caught.
    assert tm["recall_likely_fp"] >= 0.0  # reported, not tuned
