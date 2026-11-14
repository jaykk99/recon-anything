"""Trainer for the neural scoring engine (``app/nn_engine.py``).

Dev-only: needs numpy. The runtime never imports numpy - it loads the
JSON weights this script writes, so the shipped engine stays pure
stdlib.

Two label sources:

1. **Policy distillation (default).** Build a training corpus from the
   real plugin registry vocabulary (every ``id``/``label``/``group``
   declared under ``app/plugins/``, parsed textually so no plugin is
   imported and no dependency is needed) and label each record with the
   project's own adjudication policy: ``prioritizer.impact_of`` x
   exploitability tier x confidence, plus the semantic-signal count from
   ``correlate``. The network therefore starts as a compact, faithful
   reconstruction of the hand-tuned policy across *all* plugins, which
   is what makes one comparable score per finding possible.

2. **Real adjudication labels** (``--corpus labels.jsonl``): one JSON
   object per line, ``{"finding": {...}, "label": 0..1}``. Use this as
   `runs/` adjudications accumulate - it replaces the distilled policy
   label with measured ground truth.

Both paths split by plugin/record so the reported metrics are on data
the network never saw:

    python -m app.nn_train                       # distill policy, write weights
    python -m app.nn_train --corpus labels.jsonl # fit real labels
    python -m app.nn_train --self-report

``spearman`` on the holdout is the metric that matters for a ranker:
1.0 means the network orders findings exactly like the policy it was
trained on. MAE is the mean absolute error on the 0-1 actionability
scale.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from . import nn_engine
from .correlate import _detect_signals as _signals_of
from .prioritizer import impact_of

PLUGIN_DIR = Path(__file__).with_name("plugins")
WEIGHTS_PATH = nn_engine.MODEL_FILE
VERSION = "2026-11-14"

# Groups declared by the Plugin base class map onto the engine's categories.
_GROUP_TO_CAT = {
    "network": "network", "web": "web", "api": "api", "mobile": "mobile",
    "identity": "identity", "infra": "infra", "web3": "web3",
    "financial": "financial", "graph": "graph", "dns": "dns",
    "leak": "leak",
}

# A few high-signal keys the impact table scores at the extremes. Plugin ids
# cover most vocabulary; these pin down the classes the policy treats as
# full-compromise primitives so the distilled model reproduces them.
_EXTRA_KEYS = [
    ("rce_confirmed", "web", "medium"), ("sqli_error", "web", "high"),
    ("ssti_evaluated", "web", "high"), ("auth_bypass", "web", "high"),
    ("ssrf_internal", "web", "high"), ("xxe_file_read", "web", "high"),
    ("idor_candidate", "api", "medium"), ("open_redirect", "web", "low"),
    ("cors_reflect_origin", "web", "medium"), ("xss_reflected", "web", "medium"),
    ("missing_hsts", "web", "low"), ("cookie_flag_missing", "web", "low"),
    ("server_version_banner", "network", "low"),
    ("exposed_aws_access_key", "leak", "high"),
    ("exposed_github_token", "leak", "high"), ("git_exposed", "web", "medium"),
    ("s3_public_write", "leak", "high"), ("graphql_introspection", "api", "low"),
    ("unauthenticated_admin", "web", "critical"),
    ("crash_dump_exposed", "web", "medium"),
]

_EXPL_W = {"weaponized": 1.0, "public_poc": 0.85, "theoretical": 0.6,
           "unknown": 0.45}


# ---------------------------------------------------------------------------
# Corpus: real plugin vocabulary, parsed from source (no imports)
# ---------------------------------------------------------------------------

_ID_RX = re.compile(r"^\s*id\s*=\s*[\"']([^\"']+)[\"']")
_LABEL_RX = re.compile(r"^\s*label\s*=\s*[\"']([^\"']+)[\"']")
_GROUP_RX = re.compile(r"^\s*group\s*=\s*[\"']([^\"']+)[\"']")


def plugin_specs(plugin_dir: Path = PLUGIN_DIR) -> List[Tuple[str, str, str]]:
    """(id, label, group) for every plugin class declared on disk."""
    specs: List[Tuple[str, str, str]] = []
    seen = set()
    for path in sorted(Path(plugin_dir).rglob("*.py")):
        cur: Dict[str, str] = {}
        try:
            lines = path.read_text("utf-8", "ignore").splitlines()
        except Exception:
            continue
        for line in lines:
            m = _ID_RX.match(line)
            if m:
                if cur.get("id") and cur["id"] not in seen:
                    seen.add(cur["id"])
                    specs.append((cur["id"], cur.get("label", ""),
                                  cur.get("group", "")))
                cur = {"id": m.group(1)}
                continue
            if not cur:
                continue
            m = _GROUP_RX.match(line)
            if m and "group" not in cur:
                cur["group"] = m.group(1)
            m = _LABEL_RX.match(line)
            if m and "label" not in cur:
                cur["label"] = m.group(1)
        if cur.get("id") and cur["id"] not in seen:
            seen.add(cur["id"])
            specs.append((cur["id"], cur.get("label", ""), cur.get("group", "")))
    return specs


def _target(row: Dict[str, Any]) -> float:
    """The policy this run distills: impact x exploitability x confidence,
    plus semantic-signal breadth and available verification commands."""
    try:
        impact = float(impact_of(row)) / 10.0
    except Exception:
        impact = 0.4
    ev = row.get("evidence") or {}
    expl = str(ev.get("exploitability") or "unknown").lower()
    conf = float(row.get("confidence") or 80) / 100.0
    sig = len(_signals_of(row))
    val = impact * _EXPL_W.get(expl, 0.45) * (0.60 + 0.40 * conf)
    val += min(0.10, 0.02 * sig)
    if ev.get("commands"):
        val += 0.03
    return max(0.0, min(1.0, val))


def build_corpus(plugin_dir: Path = PLUGIN_DIR) -> List[Tuple[Dict[str, Any], float, str]]:
    """(finding, target, group_key) triples covering the whole registry."""
    out: List[Tuple[Dict[str, Any], float, str]] = []
    variants = [
        ("high", "unknown", 80, False),
        ("medium", "public_poc", 70, True),
        ("critical", "weaponized", 90, True),
        ("low", "theoretical", 60, False),
        ("high", "public_poc", 85, True),
    ]
    for i, (pid, label, group) in enumerate(plugin_specs(plugin_dir)):
        cat = _GROUP_TO_CAT.get((group or "").lower(), "other")
        sev, expl, conf, cmds = variants[i % len(variants)]
        row = {
            "plugin": pid, "category": cat, "key": pid,
            "value": (label or pid)[:80], "confidence": conf,
            "source_url": "https://example.invalid/x" if i % 3 == 0 else None,
            "bounty_value": sev,
            "evidence": {
                "severity": sev, "exploitability": expl,
                "commands": ([{"cmd": f"curl -sI https://x/{pid}"}] if cmds
                             else []),
                "needs_manual_verification": expl == "unknown",
            },
        }
        out.append((row, _target(row), pid))
        # a second, weaker reading of the same capability (low confidence)
        row2 = json.loads(json.dumps(row))
        row2["confidence"] = 35
        row2["evidence"]["severity"] = "low"
        row2["evidence"]["exploitability"] = "unknown"
        row2["evidence"]["commands"] = []
        out.append((row2, _target(row2), pid))
    for key, cat, sev in _EXTRA_KEYS:
        for expl in ("weaponized", "unknown"):
            row = {
                "plugin": "vocab", "category": cat, "key": key,
                "value": key.replace("_", " "), "confidence": 80,
                "bounty_value": sev,
                "evidence": {"severity": sev, "exploitability": expl,
                             "commands": [{"cmd": "curl -s https://x"}]},
            }
            out.append((row, _target(row), f"vocab:{key}"))
    return out


def load_labeled_corpus(path: Path) -> List[Tuple[Dict[str, Any], float, str]]:
    """Real adjudication labels: {"finding": {...}, "label": 0..1}."""
    out: List[Tuple[Dict[str, Any], float, str]] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                finding = rec.get("finding") or rec.get("row") or rec
                label = float(rec["label"])
            except Exception:
                continue
            if not isinstance(finding, dict):
                continue
            key = str(finding.get("plugin") or finding.get("plugin_id") or "")
            out.append((finding, max(0.0, min(1.0, label)), key or "unknown"))
    return out


# ---------------------------------------------------------------------------
# Model + training
# ---------------------------------------------------------------------------

def _init(rng: np.random.Generator, hidden: int) -> List[Tuple[np.ndarray, np.ndarray]]:
    n_in = nn_engine.N_FEATURES
    w1 = rng.normal(0.0, math.sqrt(2.0 / n_in), size=(hidden, n_in))
    b1 = np.zeros(hidden)
    w2 = rng.normal(0.0, math.sqrt(2.0 / hidden), size=(1, hidden))
    b2 = np.zeros(1)
    return [(w1, b1), (w2, b2)]


def _forward(params, x: np.ndarray) -> np.ndarray:
    (w1, b1), (w2, b2) = params
    a1 = np.tanh(x @ w1.T + b1)
    z2 = a1 @ w2.T + b2
    return 1.0 / (1.0 + np.exp(-np.clip(z2, -60, 60)))


def train(x: np.ndarray, y: np.ndarray, *, hidden: int = 16,
          epochs: int = 500, lr: float = 0.02, seed: int = 7
          ) -> List[Tuple[np.ndarray, np.ndarray]]:
    """Full-batch Adam on MSE. Deterministic for a fixed seed."""
    rng = np.random.default_rng(seed)
    params = _init(rng, hidden)
    (w1, b1), (w2, b2) = params
    m = [np.zeros_like(w1), np.zeros_like(b1), np.zeros_like(w2), np.zeros_like(b2)]
    v = [np.zeros_like(w1), np.zeros_like(b1), np.zeros_like(w2), np.zeros_like(b2)]
    b1m, b2m, eps = 0.9, 0.999, 1e-8
    n = max(len(y), 1)
    for t in range(1, epochs + 1):
        a1 = np.tanh(x @ w1.T + b1)
        p = 1.0 / (1.0 + np.exp(-np.clip(a1 @ w2.T + b2, -60, 60)))
        dz2 = (p.reshape(-1) - y).reshape(-1, 1) * 2.0 / n
        dw2 = dz2.T @ a1
        db2 = dz2.sum(axis=0)
        da1 = dz2 @ w2 * (1.0 - a1 ** 2)
        dw1 = da1.T @ x
        db1 = da1.sum(axis=0)
        grads = [dw1, db1, dw2, db2]
        for i, g in enumerate(grads):
            m[i] = b1m * m[i] + (1 - b1m) * g
            v[i] = b2m * v[i] + (1 - b2m) * (g * g)
            mhat = m[i] / (1 - b1m ** t)
            vhat = v[i] / (1 - b2m ** t)
            params[i // 2][i % 2][...] -= lr * mhat / (np.sqrt(vhat) + eps)
    return params


def _spearman(a: Sequence[float], b: Sequence[float]) -> float:
    def ranks(v):
        order = sorted(range(len(v)), key=lambda i: v[i])
        r = [0.0] * len(v)
        i = 0
        while i < len(order):
            j = i
            while j + 1 < len(order) and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1.0
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return np.array(r)

    ra, rb = ranks(list(a)), ranks(list(b))
    if ra.std() == 0 or rb.std() == 0:
        return 0.0
    return float(np.corrcoef(ra, rb)[0, 1])


def _auc(y: np.ndarray, p: np.ndarray) -> Optional[float]:
    pos, neg = p[y >= 0.5], p[y < 0.5]
    if len(pos) == 0 or len(neg) == 0:
        return None
    wins = sum(1.0 if a > b else 0.5 if a == b else 0.0
               for a in pos for b in neg)
    return round(wins / (len(pos) * len(neg)), 4)


def _export(params, hidden: int, metrics: Dict[str, Any],
            path: Path = WEIGHTS_PATH) -> None:
    (w1, b1), (w2, b2) = params
    payload = {
        "version": VERSION,
        "n_features": nn_engine.N_FEATURES,
        "features": nn_engine.FEATURE_NAMES,
        "layers": [
            {"activation": "tanh", "name": "hidden",
             "w": w1.round(6).tolist(), "b": b1.round(6).tolist()},
            {"activation": "sigmoid", "name": "actionability",
             "w": w2.round(6).tolist(), "b": b2.round(6).tolist()},
        ],
        "training": dict(metrics, hidden=hidden, version=VERSION),
    }
    Path(path).write_text(json.dumps(payload, separators=(",", ":")) + "\n",
                          "utf-8")


def run(corpus_path: Optional[Path] = None, *, hidden: int = 16,
        epochs: int = 500, out: Path = WEIGHTS_PATH) -> Dict[str, Any]:
    corpus = (load_labeled_corpus(corpus_path) if corpus_path
              else build_corpus())
    if not corpus:
        raise SystemExit("empty training corpus")
    x = np.array([nn_engine.features(f) for f, _y, _g in corpus], dtype=float)
    y = np.array([yy for _f, yy, _g in corpus], dtype=float)
    groups = [g for _f, _y, g in corpus]
    holdout = np.array([int(hashlib.sha1(g.encode()).hexdigest(), 16) % 5 == 0
                        for g in groups])
    if holdout.sum() < 10 or (~holdout).sum() < 10:
        holdout = np.arange(len(y)) % 5 == 0
    params = train(x[~holdout], y[~holdout], hidden=hidden, epochs=epochs)
    pred = _forward(params, x[holdout]).reshape(-1)
    gold = y[holdout]
    metrics = {
        "corpus": (str(corpus_path) if corpus_path
                   else "policy distillation over the plugin registry"),
        "records": int(len(y)),
        "holdout_records": int(holdout.sum()),
        "holdout_spearman": round(_spearman(pred, gold), 4),
        "holdout_mae": round(float(np.mean(np.abs(pred - gold))), 4),
        "trained_at": VERSION,
    }
    auc = _auc(gold, pred)
    if auc is not None:
        metrics["holdout_auc"] = auc
    _export(params, hidden, metrics, out)
    return metrics


def self_report(path: Path = WEIGHTS_PATH) -> int:
    model = nn_engine.load_model(path)
    if model is None:
        print(f"no model at {path}")
        return 1
    tr = model.get("training") or {}
    print(f"model {model['version']}: {model['n_features']} features, "
          f"{len(model['layers'])} layers")
    for k in ("corpus", "records", "holdout_records", "holdout_spearman",
              "holdout_mae", "holdout_auc"):
        if k in tr:
            print(f"  {k}: {tr[k]}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m app.nn_train",
        description="Train the neural scoring engine's weights.")
    ap.add_argument("--corpus", type=Path, default=None,
                    help='JSONL of {"finding": {...}, "label": 0..1} '
                         "(default: distill the policy over the registry)")
    ap.add_argument("--hidden", type=int, default=16)
    ap.add_argument("--epochs", type=int, default=500)
    ap.add_argument("--out", type=Path, default=WEIGHTS_PATH)
    ap.add_argument("--self-report", action="store_true")
    args = ap.parse_args(argv)
    if args.self_report:
        return self_report(args.out)
    metrics = run(args.corpus, hidden=args.hidden, epochs=args.epochs,
                  out=args.out)
    print(json.dumps(metrics, indent=1))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
