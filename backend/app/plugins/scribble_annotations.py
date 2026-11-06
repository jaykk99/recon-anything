"""Scribble Annotation Audit (Tier 9) - SIM-DERIVED, UNVERIFIED ONLY.

HARD RULE: simulation/spec analysis only. Every finding carries
verdict=UNVERIFIED / sim_derived=True; never VERIFIED_REAL, never
proof. VERIFIED_REAL requires live-chain probes.

Scribble instruments Solidity with specification annotations in
doc-comments: ``/// #if_succeeds ...``, ``/// #if_updated ...``,
``/// #invariant ...``. Teams write the annotation, ship the plain
source, and the asserted property is silently NOT enforced at
runtime (instrumentation is a build step). This plugin parses the
annotation surface and reports, as findings:

- ENFORCEMENT GAP: an annotation asserts a caller restriction
  (``msg.sender == owner`` / ``old(...)``-style postconditions on
  who may call) on a function whose body/signature carries NO
  matching gate - the spec says restricted, the deployed code is
  open;
- CONTRADICTION: two ``#if_succeeds`` annotations on the same
  function assert mutually exclusive postconditions
  (``ensures x`` and ``ensures !x`` over the same expression);
- coverage itself is only reported through these risk findings:
  a contract whose annotations all match real guards is silent.

The eth-scribble binary exists in the operator node-tools tree but
only instruments; it never audits annotation-vs-code agreement,
which is the distinct remainder here.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from . import contract_chain as cc
from .base import Cost, Plugin, PluginResult, Target, Ctx
from .forksim_util import is_gated, run_analyzer_plugin

_ANN = re.compile(
    r"///\s*#(if_succeeds|if_updated|invariant|if_reverts)\b([^\n]*)")
_FUNC_AFTER = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def parse_annotations(source: str) -> List[Dict[str, Any]]:
    """[{kind, text, function}] - annotation attached to the next
    function declared after it (Scribble's own attachment rule)."""
    out: List[Dict[str, Any]] = []
    for m in _ANN.finditer(source):
        tail = source[m.end():m.end() + 1200]
        fm = _FUNC_AFTER.search(tail)
        out.append({"kind": m.group(1), "text": m.group(2).strip(),
                    "function": fm.group(1) if fm else ""})
    return out


def analyze_scribble_source(source: str, item: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    anns = parse_annotations(source)
    if not anns:
        return hits
    fns = {f["name"]: f for f in cc.extract_functions(
        cc._strip_comments(source))}
    # enforcement gap: annotation claims a caller restriction, code open
    for ann in anns:
        text = ann["text"]
        if ann["kind"] not in ("if_succeeds", "invariant"):
            continue
        if not re.search(r"msg\.sender\s*==|caller\s*==|_msgSender\(\)\s*==",
                         text):
            continue
        fn = fns.get(ann["function"])
        if fn is None:
            continue
        if not is_gated(fn["text"], fn["signature"]):
            hits.append({
                "key": "scribble_annotation_unenforced",
                "severity": "high", "check": "annotation_enforcement_gap",
                "function": ann["function"],
                "detail": (f"Scribble annotation on '{ann['function']}' "
                           f"asserts a caller restriction "
                           f"(#{ann['kind']} {text[:90]}), but the "
                           f"function carries no matching gate in its "
                           f"deployed source - the asserted invariant "
                           f"is not enforced at runtime."),
                "confidence": 74})
    # contradiction: ensures X and ensures !X on the same function
    by_fn: Dict[str, List[str]] = {}
    for ann in anns:
        if ann["kind"] == "if_succeeds" and ann["function"]:
            by_fn.setdefault(ann["function"], []).append(
                re.sub(r"\s+", "", ann["text"]))
    for fname, texts in by_fn.items():
        pos = {t.replace("ensures", "", 1) for t in texts
               if not t.startswith("ensures!")}
        neg = {t[len("ensures!"):] for t in texts
               if t.startswith("ensures!")}
        clash = pos & neg
        if clash:
            hits.append({
                "key": "scribble_annotation_contradiction",
                "severity": "medium", "check": "annotation_contradiction",
                "function": fname,
                "detail": (f"Scribble annotations on '{fname}' are "
                           f"mutually contradictory: #if_succeeds "
                           f"asserts both '{sorted(clash)[0][:70]}' and "
                           f"its negation. No execution can satisfy "
                           f"the specification."),
                "confidence": 76})
    return hits


class ScribbleAnnotationsPlugin(Plugin):
    id = "scribble_annotations"
    label = "Scribble Annotations (sim, UNVERIFIED)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Scribble specification-annotation audit: "
                   "asserted caller restrictions with no matching "
                   "runtime gate, and contradictory #if_succeeds "
                   "postconditions. SIM-DERIVED, UNVERIFIED only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_analyzer_plugin(self, target, ctx,
                                         analyze_scribble_source)
