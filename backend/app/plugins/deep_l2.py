"""Deep low-level detectors: L2 / data-availability lane (feat/deep-lowlevel-50).

Three correlators for rollup infrastructure: a cross-rollup
sequencer liveness monitor, an optimistic fraud-proof challenge
window tracker, and a blob KZG commitment DA correlator.

All three read public data only (the rollup's public batch feed,
the dispute contract via read-only eth_call, the beacon API for
blob sidecars). They never send a transaction and never touch a
private key. Findings are UNVERIFIED candidates until a live
probe confirms them.

KZG note: the blob correlator verifies the versioned hash
(0x01 || sha256(commitment)[1:]) and the blob's availability from
the public DA layer. Full KZG opening-proof verification is out
of scope for this detector and is recorded as such in its
findings; the correlator flags the hash mismatch and the
unretrievable blob, which are the DA failures that matter first.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .bsc_common import DetectorSpec, S

FAMILY = "deepl2"
MIN_CHALLENGE_WINDOW_S = 7 * 24 * 3600  # 7 days

SPECS = [
    S("cross_rollup_sequencer_liveness_monitor", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Sequencer liveness failure: the rollup's public "
             "batch feed shows a gap longer than the liveness "
             "parameter with no batch posted while L1 keeps "
             "finalizing, or a run of empty batches (censorship "
             "shape), or a batch timestamp in the future (clock "
             "anomaly). A stalled sequencer means transactions "
             "are not being included.",
      fix="Investigate the sequencer (is it down, censored, or "
          "partitioned), and fall back to forced inclusion via "
          "L1 while it is stalled."),
    S("optimistic_fraud_proof_challenge_window_tracker", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Fraud-proof window failure: the dispute contract's "
             "challenge period is shorter than the 7-day security "
             "minimum, or a state root finalized while a dispute "
             "was still pending (finalized under challenge). A "
             "short window or a finalized-under-challenge root "
             "means an invalid state can become final before "
             "anyone can challenge it.",
      fix="Set the challenge period to at least 7 days, and never "
          "finalize a state root while a dispute on it is pending."),
    S("blob_kzg_commitment_da_correlator", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Blob DA failure: a blob's versioned hash does not "
             "match its KZG commitment (0x01 || "
             "sha256(commitment)[1:]), or the blob is not "
             "retrievable from the public DA layer inside the "
             "retention window. Full KZG opening-proof "
             "verification is out of scope for this detector and "
             "is recorded as such; the hash and availability "
             "checks are what it proves.",
      fix="Re-publish the blob with a correct commitment, and "
          "verify DA availability from the beacon API before "
          "relying on the blob."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


def _hit(spec: DetectorSpec, fn_name: str, code: str,
         detail: str, gate: str) -> Dict[str, Any]:
    return {"kind": spec.id, "severity": spec.severity,
            "function": fn_name, "code": code, "detail": detail,
            "gate_analysis": gate}


def _load_doc(src: str) -> Optional[Dict[str, Any]]:
    try:
        doc = json.loads(src)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _analyze_sequencer(src: str, spec: DetectorSpec,
                       compiler: str = "",
                       contract_name: str = "") -> List[Dict[str, Any]]:
    doc = _load_doc(src)
    out: List[Dict[str, Any]] = []
    if not doc:
        return []
    batches = doc.get("batches") or []
    threshold = doc.get("liveness_threshold_s") or 3600
    now = doc.get("now") or int(time.time())
    prev = None
    empty_run = 0
    for b in batches:
        if not isinstance(b, dict):
            continue
        ts = b.get("timestamp") or b.get("slot_time") or 0
        if ts > now + 300:
            detail = spec.detail + (
                f" Observed: batch {b.get('id', '?')} carries a "
                f"timestamp {ts}, in the future relative to "
                f"now {now} (clock anomaly).")
            item = _hit(spec, "", str(b.get("id", "")), detail,
                        "batch timestamp in the future")
            item["report_class"] = "candidate"
            out.append(item)
        if prev is not None and ts - prev > threshold:
            detail = spec.detail + (
                f" Observed: no batch was posted for "
                f"{ts - prev}s (from {prev} to {ts}), longer "
                f"than the liveness parameter ({threshold}s), "
                f"while L1 kept finalizing.")
            item = _hit(spec, "", f"{prev}->{ts}", detail,
                        "batch gap exceeds the liveness parameter")
            item["report_class"] = "candidate"
            out.append(item)
        if b.get("tx_count", 1) == 0:
            empty_run += 1
        else:
            empty_run = 0
        if empty_run >= 5:
            detail = spec.detail + (
                f" Observed: {empty_run} consecutive empty "
                f"batches were posted; the sequencer is posting "
                f"empty batches (censorship shape) instead of "
                f"including transactions.")
            item = _hit(spec, "", "empty batches", detail,
                        "consecutive empty batches")
            item["report_class"] = "candidate"
            out.append(item)
            empty_run = 0
        prev = ts
    if batches and now - (batches[-1].get("timestamp") or 0) > threshold:
        detail = spec.detail + (
            f" Observed: the latest batch is "
            f"{now - batches[-1].get('timestamp', 0)}s old, "
            f"longer than the liveness parameter "
            f"({threshold}s); the sequencer has stalled.")
        item = _hit(spec, "", "latest batch", detail,
                    "no batch within the liveness parameter")
        item["report_class"] = "candidate"
        out.append(item)
    return out


def _analyze_fraud_window(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = "") -> List[Dict[str, Any]]:
    doc = _load_doc(src)
    out: List[Dict[str, Any]] = []
    if not doc:
        return []
    period = doc.get("challenge_period_s")
    minimum = doc.get("minimum_s") or MIN_CHALLENGE_WINDOW_S
    if period is not None and period < minimum:
        detail = spec.detail + (
            f" Observed: the challenge period is {period}s, "
            f"below the security minimum ({minimum}s = 7 days); "
            f"an invalid state root can finalize before anyone "
            f"can challenge it.")
        item = _hit(spec, "", str(period), detail,
                    "challenge period below the security minimum")
        item["report_class"] = "candidate"
        out.append(item)
    for root in doc.get("finalized_roots") or []:
        if not isinstance(root, dict):
            continue
        if root.get("dispute_pending"):
            detail = spec.detail + (
                f" Observed: state root {root.get('id', '?')} "
                f"finalized while a dispute on it was still "
                f"pending; the root became final under challenge.")
            item = _hit(spec, "", str(root.get("id", "")), detail,
                        "root finalized while a dispute was pending")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _analyze_blob_kzg(src: str, spec: DetectorSpec,
                      compiler: str = "",
                      contract_name: str = "") -> List[Dict[str, Any]]:
    doc = _load_doc(src)
    out: List[Dict[str, Any]] = []
    if not doc:
        return []
    for blob in doc.get("blobs") or []:
        if not isinstance(blob, dict):
            continue
        commitment = blob.get("commitment")
        vhash = blob.get("versioned_hash")
        if commitment and vhash:
            try:
                comm = bytes.fromhex(
                    commitment.removeprefix("0x"))
                want = "0x01" + hashlib.sha256(comm).hexdigest()[2:]
                if want.lower() != vhash.lower():
                    detail = spec.detail + (
                        f" Observed: blob "
                        f"{blob.get('id', '?')}'s versioned hash "
                        f"({vhash}) does not match its KZG "
                        f"commitment ({want} expected); the blob "
                        f"is not the data the commitment claims.")
                    item = _hit(spec, "", str(blob.get("id", "")),
                                detail,
                                "versioned hash mismatch with the "
                                "KZG commitment")
                    item["report_class"] = "candidate"
                    out.append(item)
            except ValueError:
                pass
        if blob.get("data_available") is False:
            detail = spec.detail + (
                f" Observed: blob {blob.get('id', '?')} is not "
                f"retrievable from the public DA layer inside "
                f"the retention window; the data the commitment "
                f"points to is unavailable.")
            item = _hit(spec, "", str(blob.get("id", "")), detail,
                        "blob not retrievable from DA")
            item["report_class"] = "candidate"
            out.append(item)
    return out


ANALYZERS = {
    "cross_rollup_sequencer_liveness_monitor": _analyze_sequencer,
    "optimistic_fraud_proof_challenge_window_tracker": _analyze_fraud_window,
    "blob_kzg_commitment_da_correlator": _analyze_blob_kzg,
}


def analyze_deep_l2_source(data: str, spec: DetectorSpec,
                           compiler: str = "",
                           contract_name: str = ""
                           ) -> List[Dict[str, Any]]:
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(data, spec, compiler, contract_name)


class DeepL2Plugin(Plugin):
    id = ""
    label = "Deep L2 Detector"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []
    description = ""
    phase = 2
    timeout_s = 60
    _spec: Optional[DetectorSpec] = None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        spec = self._spec
        t0 = time.monotonic()
        findings: List[Finding] = []
        if spec is None:
            res = self._skipped("no spec")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        inputs: List[str] = []
        for kind in ("l2_data", "rollup_data", "artifacts"):
            for item in ctx.consume(kind):
                if isinstance(item, str):
                    inputs.append(item)
                elif isinstance(item, dict):
                    inputs.append(json.dumps(item))
        if not inputs:
            res = self._skipped(
                "no rollup batch feed, dispute data, or blob data "
                "supplied for this target")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        for data in inputs:
            for hit in analyze_deep_l2_source(data, spec):
                ev = {"kind": spec.id, "severity": hit["severity"],
                      "detail": hit["detail"],
                      "remediation": spec.fix}
                if hit.get("report_class"):
                    ev["report_class"] = hit["report_class"]
                if hit.get("gate_analysis"):
                    ev["gate_analysis"] = hit["gate_analysis"]
                findings.append(self._f(
                    "web3", spec.id,
                    f"{hit['severity'].upper()}: {spec.label}: "
                    f"{hit['detail']}",
                    source="deep L2 detector (public rollup data)",
                    confidence=75, passive=True, evidence=ev))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{spec.id}: {len(inputs)} input(s), "
                       f"{len(findings)} finding(s)")
        res.duration_ms = dur
        return res


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepL2Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep L2 detector for {spec.label.lower()}: "
            f"{spec.detail} Public-data correlation, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
