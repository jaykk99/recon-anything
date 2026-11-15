"""Feature extraction: plugin finding -> fixed-length numeric vector.

V2 spec — every plugin gets its own block of inputs, not a single
one-hot. For each plugin in the top-K vocab (plus an OTHER bucket),
the network sees 8 inputs:

    fired            this finding came from this plugin (0/1)
    confidence       the finding's confidence, 0-1 (0 if not fired)
    severity         the finding's severity, ordinal 0-1
    risk             the evidence risk, ordinal 0-1
    count            how many findings this plugin produced on this
                     target, scaled 0-1 (count / 8, capped)
    gate_present     the finding reports a gate analysis (0/1)
    gate_no_caller   the gate analysis says "no caller gate" (0/1)
    detector_present the finding reports a detector outcome (0/1)

Only the finding's own plugin block is live in any one row; the other
blocks read all-zero ("this plugin did not produce this finding").
That is honest: a single finding cannot evidence another plugin's
profile, so nothing is invented for the silent plugins. The point of
the blocks is that confidence / severity / risk / count / gate /
detector now attach to the SPECIFIC plugin that produced the finding,
so the network can learn per-plugin patterns (e.g. "this plugin's
high-confidence findings are usually real, that plugin's are usually
noise") instead of one global value shared by every plugin.

The count comes from the finding dict's "plugin_finding_count" field:
- scanner rows (data.py): how many findings the same plugin produced
  on the same (chain, address) in batches.jsonl; 1 when the finding
  has no batch match.
- external rows (build_external_dataset.py): how many findings the
  same plugin class produced in the same audit project / repo.
- live scoring (score.py): how many findings the plugin produced in
  the run being scored.
Absent -> 1 (one finding). Never guessed beyond that.

Everything else is per-finding as before: top finding key (one-hot),
bounty value, recipient class, chain, source origin, bytecode-only
flags, contract role, report class, proxy/implementation presence,
function presence/length, value length, evidence count.

Labels never leak into features: validation verdicts and live-probe
outcomes are label-side only and are never read here.
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence, Tuple

TOP_K = 24

# One block of inputs per plugin. Order is fixed; feature_names()
# emits "plugin:<id>:<field>" for every plugin in the vocab + OTHER.
PLUGIN_BLOCK = ("fired", "confidence", "severity", "risk", "count",
                "gate_present", "gate_no_caller", "detector_present")
COUNT_CAP = 8.0

# One-hot vocabularies for small categorical fields.
RECIPIENT_CLASSES = ("CALLER", "CALLER-SUPPLIED", "FIXED",
                     "HOLDER-SELF", "OTHER")
CHAINS = ("bsc", "ethereum", "base", "arbitrum", "polygon", "other")
SOURCE_ORIGINS = ("Sourcify v2", "Blockscout", "other")
CONTRACT_ROLES = ("implementation", "standalone", "proxy_shell", "other")
REPORT_CLASSES = ("candidate", "trigger_only", "other")
SEVERITY_ORDER = ("low", "medium", "high", "critical")
BOUNTY_ORDER = ("low", "medium", "high", "critical")


def _ordinal(value: str, order: Sequence[str]) -> float:
    v = (value or "").strip().lower()
    if v not in order:
        return 0.0
    return order.index(v) / max(1, len(order) - 1)


def _one_hot(value: str, choices: Sequence[str]) -> List[float]:
    v = (value or "").strip()
    out = [0.0] * len(choices)
    if v in choices:
        out[choices.index(v)] = 1.0
    else:
        out[-1] = 1.0  # "other" bucket is always the last choice
    return out


def _top_one_hot(value: str, vocab: Sequence[str]) -> List[float]:
    """One-hot over the learned top-K vocab plus an "other" slot."""
    out = [0.0] * (len(vocab) + 1)
    v = (value or "").strip()
    if v in vocab:
        out[vocab.index(v)] = 1.0
    else:
        out[-1] = 1.0
    return out


class FeatureSpec:
    """Vocabulary + layout for the feature vector.

    Built from the training rows (build_vocab) and saved with the
    model weights, so scoring uses exactly the layout training used.
    """

    def __init__(self, plugins: Sequence[str] = (),
                 keys: Sequence[str] = ()) -> None:
        self.plugins = list(plugins)
        self.keys = list(keys)

    @property
    def dim(self) -> int:
        return len(self.feature_names())

    def plugin_block_names(self) -> List[str]:
        """All plugin blocks: top-K plugins + OTHER, 8 inputs each."""
        names: List[str] = []
        for p in list(self.plugins) + ["OTHER"]:
            names += [f"plugin:{p}:{b}" for b in PLUGIN_BLOCK]
        return names

    def feature_names(self) -> List[str]:
        names: List[str] = []
        names += self.plugin_block_names()
        names += [f"key:{k}" for k in self.keys] + ["key:OTHER"]
        names += (["bounty_value"] +
                  ["recipient:" + r for r in RECIPIENT_CLASSES])
        names += ["chain:" + c for c in CHAINS]
        names += ["source:" + s for s in SOURCE_ORIGINS]
        names += ["bytecode_only_present", "bytecode_only_true"]
        names += ["role:" + r for r in CONTRACT_ROLES]
        names += ["report:" + r for r in REPORT_CLASSES]
        names += ["proxy_present", "implementation_present",
                  "function_present", "function_len",
                  "value_len", "evidence_count"]
        return names

    def groups(self) -> Dict[str, Tuple[int, int]]:
        """Named index ranges, for permutation importance."""
        names = self.feature_names()
        idx = {n: i for i, n in enumerate(names)}

        def span(prefix: str) -> Tuple[int, int]:
            hits = [i for n, i in idx.items() if n.startswith(prefix)]
            return (min(hits), max(hits) + 1)

        return {
            # All plugin blocks together (fired + profile fields).
            "plugin": (0, len(self.plugin_block_names())),
            "key": span("key:"),
            "bounty_value": (idx["bounty_value"], idx["bounty_value"] + 1),
            "recipient_class": span("recipient:"),
            "chain": span("chain:"),
            "source_origin": span("source:"),
            "bytecode_signals": (idx["bytecode_only_present"],
                                 idx["bytecode_only_true"] + 1),
            "contract_role": span("role:"),
            "report_class": span("report:"),
            "proxy_impl": (idx["proxy_present"],
                           idx["implementation_present"] + 1),
            "function": (idx["function_present"], idx["function_len"] + 1),
            "value_len": (idx["value_len"], idx["value_len"] + 1),
            "evidence_count": (idx["evidence_count"],
                               idx["evidence_count"] + 1),
        }

    def to_dict(self) -> Dict:
        return {"plugins": self.plugins, "keys": self.keys,
                "spec_version": 2}

    @classmethod
    def from_dict(cls, data: Dict) -> "FeatureSpec":
        return cls(data.get("plugins", []), data.get("keys", []))


def build_vocab(rows: Sequence[Dict], top_k: int = TOP_K) -> FeatureSpec:
    """Learn the top-K plugin ids and finding keys from training rows."""
    from collections import Counter
    plugins = Counter()
    keys = Counter()
    for row in rows:
        f = row.get("finding") or row
        if f.get("plugin"):
            plugins[str(f["plugin"])] += 1
        key = (f.get("key") or (f.get("evidence") or {}).get("check") or "")
        if key:
            keys[str(key)] += 1
    return FeatureSpec(
        [p for p, _ in plugins.most_common(top_k)],
        [k for k, _ in keys.most_common(top_k)])


def extract(finding: Dict, spec: FeatureSpec) -> List[float]:
    """One finding dict -> feature vector in spec order."""
    ev = finding.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}
    vec: List[float] = []

    # Per-plugin blocks: only the finding's own plugin block is live.
    n_blocks = len(spec.plugins) + 1
    plugin = str(finding.get("plugin") or "")
    fired_idx = (spec.plugins.index(plugin) if plugin in spec.plugins
                 else n_blocks - 1)  # OTHER block
    try:
        conf = float(finding.get("confidence") or 0)
    except (TypeError, ValueError):
        conf = 0.0
    conf = max(0.0, min(1.0, conf / 100.0))
    sev = _ordinal(str(finding.get("severity") or ev.get("severity") or ""),
                   SEVERITY_ORDER)
    risk = _ordinal(str(ev.get("risk") or ""), SEVERITY_ORDER)
    try:
        count = float(finding.get("plugin_finding_count") or 1)
    except (TypeError, ValueError):
        count = 1.0
    count = max(0.0, min(1.0, count / COUNT_CAP))
    gate = str(ev.get("gate_analysis") or "")
    gate_low = gate.lower()
    gate_present = 1.0 if gate else 0.0
    gate_no_caller = 1.0 if "no caller gate" in gate_low else 0.0
    detector_present = 1.0 if ev.get("detector_outcome") not in (None, "") else 0.0
    block_vals = [1.0, conf, sev, risk, count, gate_present,
                  gate_no_caller, detector_present]
    for b in range(n_blocks):
        if b == fired_idx:
            vec += block_vals
        else:
            vec += [0.0] * len(PLUGIN_BLOCK)

    key = finding.get("key") or ev.get("check") or ""
    vec += _top_one_hot(str(key), spec.keys)
    vec.append(_ordinal(str(finding.get("bounty_value") or ""), BOUNTY_ORDER))
    vec += _one_hot(str(finding.get("recipient_class") or "OTHER"),
                    RECIPIENT_CLASSES)
    # Chain lives at row level in batch rows and inside evidence for
    # some plugins; either source counts, else the "other" bucket.
    chain = (finding.get("chain") or ev.get("chain") or "other")
    vec += _one_hot(str(chain).lower(), CHAINS)
    src = str(ev.get("source_origin") or "")
    vec += _one_hot(src if src in SOURCE_ORIGINS else "other",
                    SOURCE_ORIGINS)
    # bytecode_only arrives as the string "false"/"true" in the batch
    # rows (clean_ev stringifies evidence), not a bool.
    bonly = ev.get("bytecode_only")
    vec.append(1.0 if bonly is not None else 0.0)
    vec.append(1.0 if bonly is True
               or str(bonly).strip().lower() == "true" else 0.0)
    vec += _one_hot(str(ev.get("contract_role") or "other"),
                    CONTRACT_ROLES)
    vec += _one_hot(str(ev.get("report_class") or "other"),
                    REPORT_CLASSES)
    vec.append(1.0 if ev.get("proxy_address") else 0.0)
    vec.append(1.0 if ev.get("implementation_address") else 0.0)
    fn = str(finding.get("function") or ev.get("function") or "")
    vec.append(1.0 if fn else 0.0)
    vec.append(min(1.0, len(fn) / 64.0))
    value = str(finding.get("value") or "")
    vec.append(min(1.0, math.log10(1.0 + len(value)) / 4.0))
    vec.append(min(1.0, len(ev) / 20.0))
    return vec


def top_features(finding: Dict, spec: FeatureSpec, net,
                 k: int = 3, extra: Optional[List[float]] = None) -> List[Dict]:
    """Top contributing features for one scored finding.

    Leave-one-out: zero each feature (or feature group member) and
    measure how far the score moves. A feature whose removal moves
    the score most is the most responsible for this score. Direction
    "up" means the feature pushes the score toward worth-validating.

    extra: extra inputs appended after the spec vector (e.g. the
    multimodal block) when the net was trained with them; the
    leave-one-out pass only perturbs the spec features.
    """
    x = extract(finding, spec)
    if extra:
        x = x + list(extra)
    base = net.predict_proba(x)
    names = spec.feature_names()
    deltas = []
    for i, name in enumerate(names):
        if x[i] == 0.0:
            continue
        x2 = list(x)
        x2[i] = 0.0
        d = base - net.predict_proba(x2)
        deltas.append((abs(d), d, name))
    deltas.sort(reverse=True)
    out = []
    for _abs, d, name in deltas[:k]:
        out.append({"feature": name,
                    "direction": "up" if d > 0 else "down",
                    "delta": round(d, 4)})
    return out
