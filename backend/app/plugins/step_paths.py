"""Full step-path builder + corroboration (Phase 2D).

Given a candidate finding and the shared per-target record (the
ctx.shared["deep_targets"] record the deep layers maintain:
source analysis, live storage values, call-graph edges, token
params / math outputs, probe result when one exists), assemble
the full step sequence a stranger would walk:

    entry -> gate(s) -> hop(s) -> release -> recipient -> amount

Every step is {step, kind, status, source, detail} where status
is "evidenced" only when a concrete source backs it (a source
line, a storage slot + live value, a probe status, a math
function + its inputs); otherwise the step is "UNPROVEN" with
the missing piece named.

Verdict rule (weakest step governs, per Jay's Nov 4 order):
- any UNPROVEN step -> verdict "UNVERIFIED" (the label the
  codebase already uses for unproven candidates; the finding
  stays candidate-grade at most).
- every step evidenced, no live probe -> "PATH_COMPLETE"
  (strongest label available without a probe; still NOT a live
  proof under the no-simulation rule).
- every step evidenced AND a successful read-only live probe on
  record -> "VERIFIED_REAL_CANDIDATE" (a candidate FOR parent
  adjudication as VERIFIED_REAL; this module never emits a final
  VERIFIED_REAL verdict itself).

Corroboration: when two independent lanes speak to the same
claim (e.g. the source detector and the bytecode lane, or
Slither via the confirmation lane), record
{claim, source_says, bytecode_says, agree} ; on disagreement the
finding is marked probe_settles=True - the live probe result,
when present, wins.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def _step(n: int, kind: str, evidenced: bool, source: str,
          detail: str) -> Dict[str, Any]:
    return {"step": n, "kind": kind,
            "status": "evidenced" if evidenced else "UNPROVEN",
            "source": source, "detail": detail}


def build_step_path(candidate: Dict[str, Any],
                    record: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Assemble steps[] for one candidate.

    candidate keys used: function, code (source snippet), gated
    (bool|None), recipient, claim/check, amount_figures (math
    output dict), probe ({status,...}).
    record keys used: storage {owner, paused, implementation,
    slots}, call_edges [{from_fn,to_addr,to_fn}], sources,
    token_params, math.
    """
    record = record or {}
    storage = record.get("storage") or {}
    steps: List[Dict[str, Any]] = []
    fn = candidate.get("function") or ""
    code = candidate.get("code") or ""

    # 1. entry ------------------------------------------------------------
    if fn and code:
        first_line = code.strip().splitlines()[0][:200] if code.strip() else ""
        steps.append(_step(1, "entry", True,
                           f"source: {first_line}",
                           f"entry function '{fn}' identified in "
                           "verified source with its body as evidence"))
    else:
        steps.append(_step(1, "entry", False, "",
                           "entry function or its source body is "
                           "missing - cannot evidence the entry step"))

    # 2. gate ---------------------------------------------------------------
    gated = candidate.get("gated")
    paused = storage.get("paused")
    owner = storage.get("owner")
    if gated is False:
        gate_src = "source gate analysis: no gate found in function/modifiers/helpers"
        detail = "function is ungated in source"
        if paused is not None:
            gate_src += (f"; storage slot (paused) live value = {paused}")
            detail += (f"; live paused={paused}"
                       + (" - contract is paused, the path is "
                          "currently blocked" if paused else
                          " - contract is NOT paused, path is open"))
        if owner:
            gate_src += f"; live owner = {owner}"
        steps.append(_step(2, "gate", True, gate_src, detail))
    elif gated is True:
        steps.append(_step(2, "gate", True,
                           "source gate analysis: gate present",
                           "function is gated in source; the path "
                           "requires the gate holder"))
    else:
        steps.append(_step(2, "gate", False, "",
                           "gate state not determined (no source "
                           "gate analysis on record)"))

    # 3. hops (call-graph edges out of the entry function) ------------------
    edges = [e for e in (record.get("call_edges") or [])
             if not fn or e.get("from_fn") == fn]
    if edges:
        for e in edges[:4]:
            ok = e.get("status") == "ran" and bool(e.get("to_fn"))
            steps.append(_step(
                len(steps) + 1, "hop", ok,
                (f"call-graph edge {e.get('from_fn')} -> "
                 f"{e.get('to_addr')}:{e.get('to_fn')}"),
                "external hop follows the recorded call-graph edge"
                if ok else
                "call-graph edge is DEGRADED (callee source "
                "unavailable) - the hop's behaviour is unproven"))
    # no edges: the hop step is legitimately absent (direct release)

    # 4. release --------------------------------------------------------------
    if code and any(t in code for t in (".transfer(", ".call", ".send(",
                                        "transferFrom", "_mint(",
                                        "selfdestruct")):
        steps.append(_step(len(steps) + 1, "release", True,
                           "source: value-moving call present in "
                           "the entry function body",
                           "the function body contains the "
                           "value-release call shown in evidence"))
    elif candidate.get("claim") or candidate.get("check"):
        steps.append(_step(len(steps) + 1, "release", False, "",
                           "no value-release call evidenced in the "
                           "entry function body on record"))
    else:
        steps.append(_step(len(steps) + 1, "release", False, "",
                           "no release evidence on record"))

    # 5. recipient ------------------------------------------------------------
    recipient = candidate.get("recipient") or ""
    if recipient and recipient != "UNRESOLVED":
        steps.append(_step(len(steps) + 1, "recipient", True,
                           "recipient dataflow classification over "
                           "the function body",
                           f"value lands at a {recipient} destination"))
    else:
        steps.append(_step(len(steps) + 1, "recipient", False, "",
                           "recipient could not be classified - "
                           "the destination expression is unresolved"))

    # 6. amount ---------------------------------------------------------------
    figures = candidate.get("amount_figures") or \
        (record.get("math") or {}).get(fn) or {}
    if figures:
        steps.append(_step(len(steps) + 1, "amount", True,
                           f"quant_math output: {figures}",
                           "amount computed by the math layer from "
                           "live reads stamped in the record"))
    else:
        steps.append(_step(len(steps) + 1, "amount", False, "",
                           "no math-layer figure on record for "
                           "this path (amount unquantified)"))

    # verdict -----------------------------------------------------------------
    unproven = [s for s in steps if s["status"] == "UNPROVEN"]
    probe = candidate.get("probe") or record.get("probe") or {}
    probe_ok = probe.get("status") == "success"
    if unproven:
        verdict = "UNVERIFIED"
    elif probe_ok:
        verdict = "VERIFIED_REAL_CANDIDATE"
    else:
        verdict = "PATH_COMPLETE"
    return {"steps": steps, "verdict": verdict,
            "unproven_steps": [s["step"] for s in unproven],
            "probe_status": probe.get("status", "")}


def corroborate(claim: str, source_says: str, other_says: str,
                other_lane: str = "bytecode",
                probe: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One corroboration record for a claim two lanes speak to.
    agree is exact-claim agreement ("flags" vs "silent" style
    vocabularies are normalized by the caller to flags/silent)."""
    agree = (source_says == other_says)
    out: Dict[str, Any] = {"claim": claim, "source_says": source_says,
                           f"{other_lane}_says": other_says,
                           "agree": agree}
    if not agree:
        out["probe_settles"] = True
        out["detail"] = ("lanes disagree on this claim; the live "
                         "read-only probe result settles it when "
                         "present")
        if probe:
            out["probe_status"] = probe.get("status", "")
            out["settled_by"] = "probe" if probe.get("status") \
                else "unsettled"
    return out
