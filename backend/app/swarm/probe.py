"""LiveProber: read-only live eth_call probes from the stranger.

The LiveProber takes the hypothesis and tests it against the REAL
contract in its current state, with read-only eth_call probes from
the unfunded stranger address. No transaction is ever sent: no
signing, no broadcast, no value moved, no state changed.

For each probe it records the raw RPC response (return data or
revert message) so the evidence stands on its own. It then builds
validator candidates and, when the validator is importable, runs
them through the existing validator path. The verdict that comes
back is passed through unchanged with ``verdict_source:
"validator"``; when the validator is unavailable the verdict is
UNVERIFIED with the reason recorded. Swarm code NEVER constructs a
VERIFIED_REAL verdict.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .rpc import RpcClient, selector
from .rules import STRANGER_ADDRESS, recipient_counts_as_real

# View/pure functions worth probing on any contract, by signature.
_PROBE_SIGNATURES = [
    "owner()",
    "paused()",
    "implementation()",
    "authModule()",
    "totalSupply()",
]


def classify_recipient(finding: Dict[str, Any]) -> str:
    """Recipient class of a finding, upper-cased for the rules check."""
    ev = finding.get("evidence") or {}
    if isinstance(ev, dict):
        for k in ("recipient_class", "recipient"):
            if ev.get(k):
                return str(ev[k]).upper()
    detail = str(finding.get("detail") or "")
    if "msg.sender" in detail:
        return "CALLER"
    return "UNKNOWN"


def build_candidate(target: Dict[str, Any], hypothesis: Dict[str, Any],
                    finding: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One validator candidate. Never carries simulation evidence:
    fork outcomes are analysis signal only and must not be laundered
    into a verdict."""
    finding = finding or {}
    return {
        "address": target.get("address", ""),
        "chain": target.get("chain", ""),
        "function": hypothesis.get("function") or finding.get("function") or "",
        "kind": hypothesis.get("finding_kind") or finding.get("kind") or "",
        "recipient_class": classify_recipient(finding),
        "severity": hypothesis.get("severity") or finding.get("severity") or "",
    }


def _run_validator(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run candidates through the existing validator path.

    Prefers the investigator loop's validate_candidates (raised cap,
    strips simulation evidence); falls back to the plugin validator's
    validate_candidate. Returns verdict dicts with verdict_source
    marked. Raises only when no validator is importable at all.
    """
    try:
        from ..investigator.validate import validate_candidates  # type: ignore
        verdicts = validate_candidates(candidates)
        for v in verdicts:
            v["verdict_source"] = "investigator.validate"
        return verdicts
    except Exception:  # noqa: BLE001 - try the plugin validator
        pass
    from ..plugins.auto_validator import validate_candidate  # type: ignore
    out = []
    for cand in candidates:
        cand = dict(cand)
        cand.pop("simulation", None)
        verdict = validate_candidate(cand)
        verdict["verdict_source"] = "auto_validator.validate_candidate"
        out.append(verdict)
    return out


class LiveProberAgent:
    """Role agent: prove (or kill) the story with live read-only probes."""

    name = "liveprober"

    def run(self, target: Dict[str, Any], hypothesis: Dict[str, Any],
            scout_report: Dict[str, Any], rpc: RpcClient,
            board: Any) -> Dict[str, Any]:
        key = str(scout_report.get("key") or "")
        started = time.time()
        address = str(target.get("address") or "")
        report: Dict[str, Any] = {
            "agent": self.name, "address": address, "key": key,
            "sender": STRANGER_ADDRESS,
            "probes": [], "candidates": [], "verdicts": [],
            "verdict": "UNVERIFIED", "errors": [],
        }
        findings = scout_report.get("findings") or []

        # 1. View/pure probes from the stranger: raw outputs recorded.
        for sig in _PROBE_SIGNATURES:
            try:
                data = "0x" + selector(sig)
                resp = rpc.eth_call(address, data)
                probe = {"signature": sig, "calldata": data,
                         "from": STRANGER_ADDRESS}
                if "result" in resp:
                    probe["ok"] = True
                    probe["result"] = resp["result"]
                else:
                    probe["ok"] = False
                    probe["error"] = (resp.get("error") or {}).get(
                        "message", "reverted")
                report["probes"].append(probe)
            except Exception as e:  # noqa: BLE001 - one dead probe is data
                report["probes"].append(
                    {"signature": sig, "ok": False,
                     "error": f"{type(e).__name__}: {e}"})

        # 2. Hypothesis function probe (no-arg form): can a stranger
        # even call it, and what does it return?
        fn = hypothesis.get("function") or ""
        if fn and hypothesis.get("kind") == "story":
            try:
                data = "0x" + selector(f"{fn}()")
                resp = rpc.eth_call(address, data)
                probe = {"signature": f"{fn}()", "calldata": data,
                         "from": STRANGER_ADDRESS,
                         "hypothesis_function": True}
                if "result" in resp:
                    probe["ok"] = True
                    probe["result"] = resp["result"]
                else:
                    probe["ok"] = False
                    probe["error"] = (resp.get("error") or {}).get(
                        "message", "reverted")
                report["probes"].append(probe)
            except Exception as e:  # noqa: BLE001
                report["probes"].append(
                    {"signature": f"{fn}()", "ok": False,
                     "error": f"{type(e).__name__}: {e}"})

        # 3. Candidates: only findings whose recipient counts as real
        # can become candidates; FIXED / HOLDER-SELF are trigger-only.
        story_finding = None
        for f in findings:
            kind = str(f.get("kind") or f.get("key") or "")
            if kind == hypothesis.get("finding_kind"):
                story_finding = f
                break
        if hypothesis.get("kind") == "story" and story_finding is not None:
            rc = classify_recipient(story_finding)
            if recipient_counts_as_real(rc):
                report["candidates"].append(
                    build_candidate(target, hypothesis, story_finding))
            else:
                report["verdict"] = "TRIGGER_ONLY"
                report["trigger_only_reason"] = (
                    f"recipient class {rc} is trigger-only: only "
                    "CALLER / CALLER-SUPPLIED count as real")
        elif hypothesis.get("kind") == "lead":
            report["verdict"] = "UNVERIFIED"
            report["unverified_reason"] = (
                "hypothesis is a lead, not a story: no candidate built")
        else:
            report["verdict"] = "CLEAN"
            report["clean_reason"] = "no findings, no story, no candidate"

        # 4. Validator path (only route to VERIFIED_REAL, passthrough).
        if report["candidates"]:
            try:
                verdicts = _run_validator(report["candidates"])
                report["verdicts"] = verdicts
                vs = [str(v.get("verdict", "UNVERIFIED")) for v in verdicts]
                if "VERIFIED_REAL" in vs:
                    # Passthrough from the validator, never constructed
                    # here. The validator's own live-probe bar decided.
                    report["verdict"] = "VERIFIED_REAL"
                elif all(v == "FALSE_POSITIVE" for v in vs):
                    report["verdict"] = "FALSE_POSITIVE"
                elif "TRIGGER_ONLY" in vs and all(
                        v in ("TRIGGER_ONLY", "FALSE_POSITIVE") for v in vs):
                    report["verdict"] = "TRIGGER_ONLY"
                else:
                    report["verdict"] = "UNVERIFIED"
            except Exception as e:  # noqa: BLE001 - validator missing
                report["verdict"] = "UNVERIFIED"
                report["validator_error"] = (
                    f"validator unavailable in this checkout: "
                    f"{type(e).__name__}: {e}; live probe outputs above "
                    "are the evidence, verdict stays UNVERIFIED")
        report["elapsed_s"] = round(time.time() - started, 3)
        board.post(self.name, key, "probe", report)
        return report
