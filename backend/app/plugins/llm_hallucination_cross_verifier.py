"""LLM hallucination cross-verifier (variant of auto_validator).

auto_validator validates crypto candidates only. This plugin's delta:
general claim cross-verification for ordinary findings/report claims.
Each supplied claim (a version, a count, an offset, a header value) is
checked against supplied static ground truth (a second independent
source in the same run). Claims that contradict ground truth, or that
no second source supports, are flagged as unverified-claim findings.
Pure comparison, keyless.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def analyze_claims(claims: Any, ground_truth: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not isinstance(claims, list):
        return rows
    gt: Dict[str, Any] = ground_truth if isinstance(ground_truth, dict) else {}

    def lookup(claim: Dict[str, Any]) -> Any:
        kind = str(claim.get("fact_type") or claim.get("kind") or "")
        subject = str(claim.get("subject") or "")
        bucket = gt.get(kind) if isinstance(gt.get(kind), dict) else gt
        if isinstance(bucket, dict):
            if subject in bucket:
                return bucket[subject]
            if str(claim.get("value")) in [str(v) for v in bucket.values()]:
                return claim.get("value")
        return None

    for c in claims:
        if not isinstance(c, dict) or "value" not in c:
            continue
        label = str(c.get("text") or c.get("subject") or c.get("fact_type") or "claim")[:70]
        truth = lookup(c)
        sources = c.get("sources") if isinstance(c.get("sources"), list) else []
        if truth is None and len(sources) < 2:
            rows.append({"key": "claim_unverified",
                         "value": f"Claim '{label}' (value: {c.get('value')}) "
                                  f"is supported by fewer than two independent "
                                  f"sources and matches no ground truth: "
                                  f"unverified claim",
                         "severity": "medium",
                         "evidence": {"claim": label,
                                      "claimed_value": str(c.get("value"))}})
        elif truth is not None and str(truth) != str(c.get("value")):
            rows.append({"key": "claim_contradicted",
                         "value": f"Claim '{label}' asserts '{c.get('value')}' "
                                  f"but static ground truth says '{truth}': "
                                  f"contradicted claim (likely hallucination)",
                         "severity": "high",
                         "evidence": {"claim": label,
                                      "claimed_value": str(c.get("value")),
                                      "ground_truth": str(truth)}})
    return rows


class LlmHallucinationCrossVerifierPlugin(Plugin):
    id = "llm_hallucination_cross_verifier"
    label = "LLM Hallucination Cross-Verifier"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Cross-verify supplied report claims (versions, counts, "
                   "offsets, headers) against static ground truth; flag "
                   "contradicted or single-source claims.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            gt = ctx.consume("ground_truth")
            rows = analyze_claims(ctx.consume("claims"),
                                  gt[0] if gt else {})
        except Exception as exc:
            return self._degraded(f"cross-verifier failed: {exc}")
        findings: List[Finding] = [
            self._f("web", r["key"], r["value"], source="Cross-verifier",
                    confidence=85,
                    evidence={"severity": r["severity"],
                              "remediation": "Correct or remove the claim, "
                                             "or back it with a second "
                                             "independent source.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"claim rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
