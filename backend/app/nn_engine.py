"""Neural-network scoring engine: one learned model over every finding.

The rest of the analysis stack scores a finding with hand-written rules
spread across ``prioritizer`` (impact tables), ``correlate`` (semantic
signals, exposure score) and each plugin's own confidence. This module
replaces that scatter with a single small neural network that reads the
same evidence every plugin produces and emits ONE comparable number per
finding - so findings from 1,400 plugins can be ranked against each
other, and a run can be summarised by one score.

DESIGN RULES (match the rest of the codebase)
---------------------------------------------
* Pure stdlib inference. No numpy / torch / sklearn at runtime. The
  network is a 2-layer MLP whose weights live in ``nn_weights.json``
  next to this file; the forward pass is ~1.3k multiply-adds per
  finding. ``nn_train.py`` (dev-only, numpy) fits the weights.
* Deterministic. Same finding -> same score, in any process. Tokens are
  bucketed with sha1, never Python's salted ``hash()``.
* Never raises. A missing/corrupt weights file disables the engine
  (``available()`` is False, ``score()`` returns None) and every caller
  keeps working on the heuristic path.
* Explainable. Every score ships the input features that drove it, so a
  number can always be traced back to evidence rather than trusted as a
  black box.
* Not a verdict. The score is a ranking signal - the same contract the
  detectors already follow ("a finding is a candidate until verified").

WHAT IT LEARNS
--------------
The shipped weights are trained by ``nn_train.py`` on the project's own
adjudicated policy: impact (``prioritizer.impact_of``), exploitability
tier and confidence, over the real plugin registry vocabulary - one
record per registered plugin id. So the network starts as a faithful,
compact distillation of the hand-tuned policy across *all* plugins, and
can be retrained on real adjudication labels as they accumulate:

    python -m app.nn_train --corpus labels.jsonl   # {finding, label}

Public API
----------
``available()``       -> bool, model loaded
``score(finding)``    -> dict | None  (score 0-100, p, band, drivers)
``score_findings(rows)`` -> list[dict | None], aligned with ``rows``
``score_run(rows)``   -> dict: the run-level exposure block (or {})
``main()``            -> CLI: score a findings JSONL and print the ranking
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:  # shared signal vocabulary + row readers (pure stdlib)
    from .correlate import _detect_signals as _signals_of
    from .correlate import _row_expl as _expl_of
    from .correlate import _row_plugin as _plugin_of
    from .correlate import _row_sev as _sev_of
except Exception:  # pragma: no cover - keeps the module standalone
    def _norm(s: Any) -> str:
        return str(s or "").strip().lower()

    def _plugin_of(r):
        return str(r.get("plugin") or r.get("plugin_id") or "")

    def _sev_of(r):
        return _norm((r.get("evidence") or {}).get("severity")) or "low"

    def _expl_of(r):
        return _norm((r.get("evidence") or {}).get("exploitability")) or "unknown"

    def _signals_of(r):  # type: ignore
        return set()


MODEL_FILE = Path(__file__).with_name("nn_weights.json")

# Feature vocabulary. Fixed order - the trainer and the runtime must
# agree, so both build the vector through features() only.
SEVERITIES = ("critical", "high", "medium", "low")
EXPLOITABILITY = ("weaponized", "public_poc", "theoretical", "unknown")
BOUNTY = ("critical", "high", "medium", "low")
CATEGORIES = ("web", "api", "network", "dns", "infra", "leak",
              "identity", "mobile", "web3", "graph", "financial", "other")
SIGNALS = ("api_docs", "auth_surface", "breach", "ci_config", "cloud_hosted",
           "cors", "credential", "debug_mode", "default_creds", "exposure",
           "forgeable_token", "idor", "internal_host", "mgmt_port", "oauth",
           "open_redirect", "pkg_manifest", "privileged_endpoint",
           "source_exposed", "ssrf", "ssrf_metadata", "storage",
           "storage_writable", "takeover_candidate", "wallet_key",
           "weak_headers", "weaponized_cve")
# Hashed key-token buckets: a plugin's own vocabulary ("aws_access_key",
# "reentrancy", "crash_dump") without a per-plugin lookup table, so a new
# plugin is scored the moment it runs.
KEY_BUCKETS = 24

FEATURE_NAMES: List[str] = (
    [f"sev_{s}" for s in SEVERITIES]
    + [f"expl_{e}" for e in EXPLOITABILITY]
    + ["confidence", "has_commands", "needs_manual_verification",
       "has_source_url", "long_value"]
    + [f"bounty_{b}" for b in BOUNTY]
    + [f"sig_{s}" for s in SIGNALS]
    + [f"key_{i}" for i in range(KEY_BUCKETS)]
    + [f"cat_{c}" for c in CATEGORIES]
)
N_FEATURES = len(FEATURE_NAMES)

_BANDS = ((80, "critical", "Critical exposure — act now."),
          (55, "high", "High exposure — prioritize remediation."),
          (30, "medium", "Moderate exposure — several issues to fix."),
          (1, "low", "Low exposure — minor findings only."),
          (0, "clean", "No material exposure found."))

_TOKENS = re.compile(r"[^a-z0-9]+")


def _norm(s: Any) -> str:
    return str(s or "").strip().lower()


def _evidence(row: Dict[str, Any]) -> Dict[str, Any]:
    ev = row.get("evidence")
    return ev if isinstance(ev, dict) else {}


def _bucket(token: str) -> int:
    """Stable bucket for a key token (sha1 - no salted hash())."""
    h = hashlib.sha1(token.encode("utf-8", "ignore")).digest()
    return h[0] % KEY_BUCKETS


def _band(score: int) -> tuple:
    for floor, name, headline in _BANDS:
        if score >= floor:
            return name, headline
    return "clean", _BANDS[-1][2]


def features(row: Dict[str, Any]) -> List[float]:
    """Map one finding to the model's fixed-length input vector.

    Pure, total: any dict (or partial row) yields a full vector; missing
    or malformed evidence falls back to neutral values rather than
    raising. This is the only place features are defined, so scoring and
    training can never drift apart.
    """
    ev = _evidence(row if isinstance(row, dict) else {})
    sev = _norm(ev.get("severity") or ev.get("risk")
                or row.get("bounty_value") or "low")
    expl = _norm(ev.get("exploitability") or "unknown")
    bounty = _norm(row.get("bounty_value") or sev)
    cat = _norm(row.get("category"))
    try:
        conf = float(row.get("confidence") or ev.get("confidence") or 80)
    except (TypeError, ValueError):
        conf = 80.0

    x: List[float] = []
    x += [1.0 if sev == s else 0.0 for s in SEVERITIES]
    x += [1.0 if expl == e else 0.0 for e in EXPLOITABILITY]
    x.append(max(0.0, min(1.0, conf / 100.0)))
    x.append(1.0 if ev.get("commands") else 0.0)
    x.append(1.0 if ev.get("needs_manual_verification") else 0.0)
    x.append(1.0 if row.get("source_url") else 0.0)
    x.append(1.0 if len(str(row.get("value") or "")) > 60 else 0.0)
    x += [1.0 if bounty == b else 0.0 for b in BOUNTY]

    try:
        raised = _signals_of(row) if isinstance(row, dict) else set()
    except Exception:
        # a malformed evidence blob must not break scoring
        raised = set()
    x += [1.0 if s in raised else 0.0 for s in SIGNALS]

    key = _norm(row.get("key"))
    buckets = [0.0] * KEY_BUCKETS
    toks = [t for t in _TOKENS.split(key) if len(t) > 1]
    for t in toks:
        buckets[_bucket(t)] += 1.0
    norm = math.sqrt(len(toks)) if toks else 1.0
    x += [b / norm for b in buckets]

    if cat not in CATEGORIES:
        cat = "other"
    x += [1.0 if cat == c else 0.0 for c in CATEGORIES]
    return x


# ---------------------------------------------------------------------------
# Model load + forward pass
# ---------------------------------------------------------------------------

_MODEL: Optional[Dict[str, Any]] = None
_MODEL_TRIED = False
# Memo of score blocks keyed by the feature vector itself. The model is
# deterministic, so identical evidence always yields the identical block;
# this keeps read-time scoring of a large run (and repeat polls of the
# same run) cheap. Capped and cleared rather than pruned.
_MEMO: Dict[tuple, Dict[str, Any]] = {}
_MEMO_MAX = 50000


def _activate(name: str, v: float) -> float:
    if name == "tanh":
        return math.tanh(v)
    if name == "sigmoid":
        return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, v))))
    if name == "relu":
        return v if v > 0 else 0.0
    return v


def load_model(path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Load (and cache) the bundled weights. None if unavailable/broken."""
    global _MODEL, _MODEL_TRIED
    if path is None and _MODEL_TRIED:
        return _MODEL
    try:
        raw = json.loads(Path(path or MODEL_FILE).read_text("utf-8"))
        layers = raw.get("layers") or []
        if not layers:
            raise ValueError("no layers")
        if int(raw.get("n_features") or N_FEATURES) != N_FEATURES:
            raise ValueError("feature mismatch")
        for layer in layers:
            w, b = layer["w"], layer["b"]
            if len(w) != len(b) or any(len(row) != len(w[0]) for row in w):
                raise ValueError("ragged layer")
        if len(layers[0]["w"][0]) != N_FEATURES or len(layers[-1]["w"]) != 1:
            raise ValueError("layer shapes do not match the feature vector")
        for prev, cur in zip(layers, layers[1:]):
            if len(cur["w"][0]) != len(prev["w"]):
                raise ValueError("hidden sizes do not line up")
        model = raw
    except Exception:
        model = None
    if path is None:
        _MODEL, _MODEL_TRIED = model, True
    return model


def available() -> bool:
    return load_model() is not None


def model_version() -> str:
    model = load_model()
    return str((model or {}).get("version") or "none")


def _forward(model: Dict[str, Any], x: Sequence[float]):
    """Run the MLP. Returns (p, per-input contribution vector)."""
    v = list(x)
    contrib: List[float] = []
    layers = model["layers"]
    for i, layer in enumerate(layers):
        w, b, act = layer["w"], layer["b"], layer.get("activation", "tanh")
        out = []
        for row, bias in zip(w, b):
            out.append(_activate(act, sum(wi * vi for wi, vi in zip(row, v))
                                 + bias))
        if i == 0 and len(v) == N_FEATURES:
            # attribute hidden-layer pre-activation mass back to inputs
            contrib = [sum(abs(w[j][k]) * v[k] for j in range(len(w)))
                       for k in range(len(v))]
        v = out
    p = v[0] if v else 0.0
    return max(0.0, min(1.0, p)), contrib


def score(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Score one finding. None when the model is unavailable."""
    model = load_model()
    if model is None or not isinstance(row, dict):
        return None
    try:
        x = features(row)
        ck = tuple(round(v, 6) for v in x)
        cached = _MEMO.get(ck)
        if cached is not None:
            return dict(cached)
        p, contrib = _forward(model, x)
        s = int(round(p * 100))
        band, _headline = _band(s)
        drivers = sorted(
            ((FEATURE_NAMES[i], round(contrib[i], 3))
             for i in range(min(len(contrib), N_FEATURES)) if x[i]),
            key=lambda kv: -abs(kv[1]))[:3]
        block = {
            "score": s,
            "p": round(p, 4),
            "band": band,
            "version": model.get("version"),
            "drivers": [{"feature": f, "contribution": c} for f, c in drivers],
        }
        if len(_MEMO) >= _MEMO_MAX:
            _MEMO.clear()
        _MEMO[ck] = block
        return dict(block)
    except Exception:
        return None


def score_findings(rows: Sequence[Dict[str, Any]]) -> List[Optional[Dict]]:
    """Score a whole finding set, aligned 1:1 with ``rows``."""
    return [score(r) for r in rows]


def score_run(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Run-level exposure block driven by the network.

    Aggregation: the single strongest finding sets most of the score (one
    real critical is already bad), and the summed probability mass across
    the run adds the rest with diminishing returns, so a noisy run of
    low-confidence notes cannot peg at 100.

    Returns {} when the model is unavailable, so callers keep the
    heuristic exposure score unchanged.
    """
    model = load_model()
    if model is None:
        return {}
    safe = [r for r in (rows or []) if isinstance(r, dict)]
    blocks = [(r, b) for r, b in zip(safe, score_findings(safe)) if b]
    if not blocks:
        return {"engine": "nn", "model_version": model.get("version"),
                "score": 0, "band": "clean",
                "headline": _band(0)[1], "count": 0, "actionable": 0,
                "top": []}
    ps = [b["p"] for _r, b in blocks]
    p_max, mass = max(ps), sum(ps)
    raw = 100.0 * (0.75 * p_max + 0.25 * (1.0 - math.exp(-mass / 2.0)))
    s = int(round(max(0.0, min(100.0, raw))))
    band, headline = _band(s)
    top = sorted(blocks, key=lambda rb: (-rb[1]["p"],
                                         str(rb[0].get("key") or "")))[:5]
    return {
        "engine": "nn",
        "model_version": model.get("version"),
        "score": s,
        "band": band,
        "headline": headline,
        "count": len(blocks),
        "actionable": sum(1 for p in ps if p >= 0.5),
        "mean_p": round(mass / len(ps), 4),
        "top": [{
            "plugin": _plugin_of(r),
            "key": r.get("key"),
            "score": b["score"],
            "band": b["band"],
        } for r, b in top],
    }


# ---------------------------------------------------------------------------
# CLI: score any findings JSONL, newest-first ranking on stdout
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        prog="python -m app.nn_engine",
        description="Score findings with the neural scoring engine.")
    ap.add_argument("path", nargs="?",
                    help="JSONL of finding dicts (or '-' for stdin). "
                         "Omit to print the model's self-report.")
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    if not args.path:
        model = load_model()
        if model is None:
            print("no model loaded (nn_weights.json missing or invalid)")
            return 1
        tr = model.get("training") or {}
        print(f"model {model.get('version')}: {N_FEATURES} features, "
              f"{len(model['layers'])} layers, "
              f"{sum(len(l['w']) for l in model['layers'])} units")
        print(f"trained on {tr.get('corpus', '?')} "
              f"({tr.get('records', '?')} records)")
        if "holdout_spearman" in tr:
            print(f"holdout spearman {tr['holdout_spearman']}, "
                  f"mae {tr.get('holdout_mae')}")
        return 0

    stream = sys.stdin if args.path == "-" else open(args.path, "r",
                                                     encoding="utf-8")
    rows = []
    try:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if isinstance(d, dict):
                rows.append(d)
    finally:
        if stream is not sys.stdin:
            stream.close()

    exposure = score_run(rows)
    scored = [(r, b) for r, b in zip(rows, score_findings(rows)) if b]
    scored.sort(key=lambda rb: -rb[1]["score"])
    if args.json:
        print(json.dumps({"exposure": exposure,
                          "findings": [dict(r, nn=b) for r, b in scored]},
                         indent=1, default=str))
        return 0
    if not scored:
        print("no model loaded, or no scoreable findings")
        return 1
    print(f"exposure {exposure['score']}/100 ({exposure['band']}) — "
          f"{exposure['actionable']} actionable of {exposure['count']}")
    for r, b in scored[:max(args.top, 1)]:
        print(f"  {b['score']:3d}  {_plugin_of(r) or '?':28s} "
              f"{str(r.get('key') or '')[:44]:44s} {str(r.get('value') or '')[:60]}")
    return 0


__all__ = ["FEATURE_NAMES", "N_FEATURES", "available", "features",
           "load_model", "main", "model_version", "score", "score_findings",
           "score_run"]


if __name__ == "__main__":  # python -m app.nn_engine
    import sys as _sys

    _sys.exit(main())
