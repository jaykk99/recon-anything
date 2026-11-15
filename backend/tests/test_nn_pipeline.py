"""Pipeline wiring: scoring attaches nn_score + nn_top_features, is
off by default, and never breaks a scan when the model is missing."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.features import build_vocab, extract  # noqa: E402
from app.nn.mlp import MLP  # noqa: E402
from app.nn.pipeline import (attach_nn_scores, load_model,  # noqa: E402
                             maybe_score_findings, nn_enabled,
                             score_finding_dicts)
from nn_fixtures import ROWS  # noqa: E402


def _trained_model():
    spec = build_vocab([f for f, _ in ROWS])
    X = [extract(f, spec) for f, _ in ROWS]
    y = [label for _, label in ROWS]
    net = MLP([spec.dim, 8, 1], seed=5, lr=0.1)
    net.fit(X, y, epochs=30, batch_size=6)
    return net, spec, {}


def test_score_finding_dicts_ranks_and_labels():
    import copy
    findings = [copy.deepcopy(f) for f, _ in ROWS]
    ranked = score_finding_dicts(findings, model=_trained_model())
    assert len(ranked) == len(ROWS)
    scores = [f["nn_score"] for f in ranked]
    assert all(isinstance(s, float) and 0.0 <= s <= 1.0 for s in scores)
    assert scores == sorted(scores, reverse=True)
    for f in ranked:
        assert f["nn_label"] in ("worth-validating", "likely-false-positive")
        assert isinstance(f["nn_top_features"], list)
        assert len(f["nn_top_features"]) <= 3


def test_attach_nn_scores_dict_and_finding_object():
    import copy
    from app.plugins.base import Finding
    model = _trained_model()
    d = copy.deepcopy(ROWS[0][0])
    attach_nn_scores([d], model=model)
    assert 0.0 <= d["nn_score"] <= 1.0
    assert d["nn_label"] in ("worth-validating", "likely-false-positive")
    finding = Finding(plugin_id="contract_logic", category="web3",
                      key="access_control_flaw", value="x", source="t",
                      evidence={"severity": "high", "recipient": "CALLER",
                                "chain": "bsc", "function": "mint"})
    attach_nn_scores([finding], model=model)
    assert 0.0 <= finding.evidence["nn_score"] <= 1.0
    assert finding.evidence["nn_label"] in (
        "worth-validating", "likely-false-positive")
    assert finding.evidence["nn_top_features"]


def test_disabled_by_default_and_never_raises(monkeypatch):
    import copy
    monkeypatch.delenv("RECON_NN_SCORING", raising=False)
    assert nn_enabled() is False
    findings = [copy.deepcopy(f) for f, _ in ROWS]
    out = maybe_score_findings(findings)
    assert out is findings  # untouched, same objects
    assert "nn_score" not in findings[0]
    # Enabled but no model available: still a no-op, never raises.
    monkeypatch.setenv("RECON_NN_SCORING", "1")
    monkeypatch.setattr("app.nn.pipeline._get_model", lambda: None)
    out2 = maybe_score_findings(findings)
    assert out2 is findings
    assert "nn_score" not in findings[0]


def test_load_model_missing_file_returns_none(tmp_path):
    assert load_model(str(tmp_path / "nope.json")) is None
