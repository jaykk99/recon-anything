"""Training data: real labeled rows from the continuous scanner.

Sources (both outside the repo, in ~/workspace/recon-continuous/results/):
- candidates.jsonl: one row per candidate the scanner promoted, with the
  auto-validator's verdict. This is the ONLY labeled data.
- batches.jsonl: the full finding rows those candidates came from, with
  the complete evidence dicts (confidence, source_origin, gate_analysis,
  contract_role, ...). Candidates alone carry no evidence, so each
  candidate is joined back to its batch finding on
  (chain, address, plugin, key) to enrich the features. Candidates
  with no batch match keep their candidate-row fields and absent
  evidence (never invented).

Labels (triage only):
- 1 = worth-validating: verdict UNVERIFIED (the candidate survived
  triage and still needs a live probe).
- 0 = likely-false-positive: verdict FALSE_POSITIVE or TRIGGER_ONLY.
- VERIFIED_REAL rows are EXCLUDED: both rows in this data are
  already-adjudicated simulation-path false positives, so the real
  verified count is 0 and there is nothing real to learn that class
  from. The model must never predict VERIFIED_REAL.

batches.jsonl has torn rows (the scanner died mid-write on some
batches); they are skipped and counted, never fatal.
"""
from __future__ import annotations

import json
import random
from typing import Dict, Iterator, List, Optional, Tuple

LABEL_WORTH_VALIDATING = 1
LABEL_LIKELY_FP = 0

# verdict -> label (None = exclude from training)
VERDICT_LABELS = {
    "UNVERIFIED": LABEL_WORTH_VALIDATING,
    "FALSE_POSITIVE": LABEL_LIKELY_FP,
    "TRIGGER_ONLY": LABEL_LIKELY_FP,
    "VERIFIED_REAL": None,
}


def load_jsonl(path: str) -> Iterator[Tuple[Dict, Optional[str]]]:
    """Yield (row, error). Torn lines yield (None, message) and are
    counted by the caller instead of aborting the load."""
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line), None
            except Exception as e:  # noqa: BLE001 - torn row, keep going
                yield None, f"{type(e).__name__}: {e}"


def _join_key(chain: str, address: str, plugin: str, key: str) -> Tuple:
    return ((chain or "").lower(), (address or "").lower(),
            (plugin or ""), (key or ""))


def build_dataset(candidates_path: str,
                  batches_path: Optional[str] = None,
                  limit: Optional[int] = None) -> Dict:
    """Build the labeled training set. Returns rows + build stats."""
    candidates: List[Dict] = []
    torn = 0
    for row, err in load_jsonl(candidates_path):
        if err is not None:
            torn += 1
            continue
        candidates.append(row)
        if limit and len(candidates) >= limit:
            break

    # Index batch findings by join key for evidence enrichment.
    enriched: Dict[Tuple, Dict] = {}
    batch_rows = 0
    batch_torn = 0
    batch_findings = 0
    if batches_path:
        for row, err in load_jsonl(batches_path):
            if err is not None:
                batch_torn += 1
                continue
            batch_rows += 1
            for f in row.get("findings") or []:
                batch_findings += 1
                key = _join_key(row.get("chain", ""), row.get("address", ""),
                                f.get("plugin", ""), f.get("key", ""))
                # First occurrence wins: the finding as first scanned.
                enriched.setdefault(key, f)

    rows: List[Dict] = []
    excluded = 0
    unenriched = 0
    for cand in candidates:
        verdict = (cand.get("validation") or {}).get("verdict")
        label = VERDICT_LABELS.get(verdict)
        if label is None:
            excluded += 1
            continue
        key = _join_key(cand.get("chain", ""), cand.get("address", ""),
                        cand.get("plugin", ""), cand.get("key", ""))
        finding = enriched.get(key)
        if finding is None:
            unenriched += 1
            # Candidate row alone: real fields, evidence absent.
            finding = {
                "plugin": cand.get("plugin"),
                "key": cand.get("key"),
                "severity": cand.get("severity"),
                "bounty_value": None,
                "confidence": None,
                "value": cand.get("value") or "",
                "recipient_class": cand.get("recipient_class"),
                "chain": cand.get("chain"),
                "function": cand.get("function"),
                "evidence": {},
            }
        else:
            # Chain lives at batch-row level, not in the finding dict:
            # stamp it on so the feature extractor sees the real chain
            # (without this every training row read chain "other").
            finding = dict(finding)
            finding.setdefault("chain", cand.get("chain"))
        rows.append({
            "finding": finding,
            "label": label,
            "verdict": verdict,
            "chain": cand.get("chain"),
            "address": cand.get("address"),
            "plugin": cand.get("plugin"),
            "key": cand.get("key"),
            "function": cand.get("function"),
        })

    stats = {
        "candidates": len(candidates),
        "candidates_torn_lines": torn,
        "batch_rows": batch_rows,
        "batch_torn_lines": batch_torn,
        "batch_findings": batch_findings,
        "joined_with_evidence": len(rows) - unenriched,
        "without_batch_match": unenriched,
        "excluded_verified_real_rows": excluded,
        "train_rows": len(rows),
        "n_positive": sum(1 for r in rows if r["label"] == 1),
        "n_negative": sum(1 for r in rows if r["label"] == 0),
    }
    return {"rows": rows, "stats": stats}


def stratified_split(rows: List[Dict], test_frac: float = 0.2,
                     seed: int = 42) -> Tuple[List[Dict], List[Dict]]:
    """Stratified train/test split (keeps the class ratio in both)."""
    rng = random.Random(seed)
    by_label: Dict[int, List[Dict]] = {}
    for r in rows:
        by_label.setdefault(r["label"], []).append(r)
    train: List[Dict] = []
    test: List[Dict] = []
    for label, items in by_label.items():
        items = list(items)
        rng.shuffle(items)
        n_test = max(1, round(len(items) * test_frac)) if len(items) > 1 else 0
        test.extend(items[:n_test])
        train.extend(items[n_test:])
    rng.shuffle(train)
    rng.shuffle(test)
    return train, test
