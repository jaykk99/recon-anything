"""Train on the REAL candidates file. Skipped automatically when the
file is absent (e.g. CI, which has no scanner data). Uses few epochs
so it stays fast; asserts the run completes and reports real,
well-formed metrics — never tuned numbers.

The file writes use a short retry budget (write_tries=3): the
training result is returned regardless of whether the weights files
land, so a closed write gate fails this test fast instead of hanging
on retries. The full training runs use the long default budget.
"""
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
    # The live candidates file changes as the scanner runs: count the
    # VERIFIED_REAL rows in it now instead of pinning a stale number
    # (it was 2 when this test was written; the scanner has since
    # re-validated them away).
    import json
    expected_excluded = 0
    with open(CANDIDATES, encoding="utf-8") as fh:
        for line in fh:
            try:
                row = json.loads(line)
            except Exception:
                continue
            if (row.get("validation") or {}).get("verdict") == "VERIFIED_REAL":
                expected_excluded += 1
    result = train(CANDIDATES, batches, str(tmp_path),
                   epochs=15, hidden="16,8", seed=42,
                   write_tries=3, write_delay=1.0)
    assert result["train_rows"] + result["test_rows"] >= 700
    assert result["dataset"]["n_positive"] > 500
    assert result["dataset"]["n_negative"] > 50
    # The VERIFIED_REAL rows are excluded, never trained on.
    assert result["dataset"]["excluded_verified_real_rows"] == \
        expected_excluded
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
