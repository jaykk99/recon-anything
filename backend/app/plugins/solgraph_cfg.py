"""Solgraph remainder: per-function CONTROL-FLOW GRAPH flags.

Coverage map (master dee4763, 853 plugins): graph-shaped lanes on
master are all CALL graphs or structural maps, not control-flow
graphs - cross_contract_call_graph (external edges between
contracts), toolbox's Surya adapter (caller->callee DOT, only when
the surya binary runs), ast_visual_audit (inheritance + per-
function structural map from the solc AST, highlights capped at
low and structural only). No lane builds a per-function CFG or
derives flags from paths through it.

This plugin builds a lightweight CFG per function from the
source (basic blocks split at braces / branches / jumps) and
ships the CFG-derived flags Solgraph-style tooling exists for,
with the CFG summary (block / edge counts per function) attached
as evidence to every flag - the artifact travels with the flag:

- solgraph_unreachable_code: a statement that follows an
  unconditional return / revert at the SAME block depth, before
  the block closes - dead code on every path.
- solgraph_missing_return_path: a function declaring returns(...)
  whose only return statements sit inside conditional blocks and
  which has no return at function level - some path falls through
  to the default (zero) return value.
A third classic CFG flag - external-call paths crossing no
guard block - was built and then DROPPED in this tier's FP pass
(adjudicated 2026-11-05): on the fp_clean corpus it fired on
holder-self withdraw/unwrap flows and proof-/signature-gated
claim paths, whose guards are balance/proof checks rather than
msg.sender gates. Guard coverage of call paths stays with the
gate-aware contract_logic / access-control families, which have
the recipient machinery to judge it; this plugin ships only the
two CFG flags that stay silent on the clean corpus.

Detection only. Never sends a transaction.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from . import contract_chain as cc
from . import tier8_common as t8
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = ("Review the flagged control-flow path in the "
               "function's CFG: remove or fix unreachable code, "
               "and make every path through a returns(...) "
               "function return deliberately.")


def build_cfg(text: str) -> Dict[str, int]:
    """A lightweight CFG summary for one function body: blocks
    split at every brace level change / branch keyword, edges as
    the observed block transitions. Summary only - the flags
    below carry the semantics."""
    blocks = 1
    branches = 0
    for m in re.finditer(r"[{}]|\b(if|else|for|while)\b", text):
        if m.group(0) in "{}":
            blocks += 1
        else:
            branches += 1
    return {"blocks": blocks, "branches": branches,
            "edges": max(0, blocks + branches - 1)}


def _line_depths(lines: List[str]) -> List[int]:
    depths: List[int] = []
    d = 0
    for line in lines:
        depths.append(d)
        d += line.count("{") - line.count("}")
    return depths


def analyze_solgraph_source(src: str) -> List[Dict[str, Any]]:
    """CFG flags over Solidity source (pure)."""
    if not src:
        return []
    clean = cc._strip_comments(src)
    if "contract" not in clean and "library" not in clean:
        return []
    out: List[Dict[str, Any]] = []
    for fn in cc.extract_functions(clean):
        name = fn.get("name") or ""
        sig = fn.get("signature") or ""
        text = fn.get("text") or ""
        if "{" not in text or not name:
            continue
        cfg = build_cfg(text)
        lines = [ln.rstrip() for ln in text.splitlines()]
        depths = _line_depths(lines)
        base = depths[0] if depths else 0

        # -- unreachable code ------------------------------------
        for i, line in enumerate(lines):
            s = line.strip()
            if not re.match(r"(return\b[^;]*;|revert\s*\([^;]*;)",
                            s):
                continue
            for j in range(i + 1, len(lines)):
                nxt = lines[j].strip()
                if not nxt:
                    continue
                if depths[j] < depths[i] or nxt.startswith("}"):
                    break
                if depths[j] == depths[i] and \
                        not nxt.startswith(("else", "catch")):
                    out.append({
                        "kind": "solgraph_unreachable_code",
                        "severity": "low", "function": name,
                        "cfg": cfg,
                        "detail": f"function '{name}': statement "
                                  f"'{nxt[:60]}' follows an "
                                  "unconditional return/revert in "
                                  "the same block - unreachable on "
                                  "every CFG path",
                        "code": text[:600]})
                break

        # -- missing return path ---------------------------------
        if re.search(r"\breturns\s*\(", sig):
            fn_level_return = False
            cond_return = False
            # depth of the function body's first line is base+1
            # inside the opening brace; a return at the shallowest
            # body depth is function-level.
            body_depths = [depths[k] for k, ln in enumerate(lines)
                           if re.search(r"\breturn\b", ln)]
            if body_depths:
                shallow = min(depths[k] for k in range(len(lines))
                              if lines[k].strip())
                for k, ln in enumerate(lines):
                    if re.search(r"\breturn\b[^;]*;", ln):
                        if depths[k] <= shallow + 1:
                            fn_level_return = True
                        else:
                            cond_return = True
            if cond_return and not fn_level_return:
                out.append({
                    "kind": "solgraph_missing_return_path",
                    "severity": "medium", "function": name,
                    "cfg": cfg,
                    "detail": f"function '{name}' declares "
                              "returns(...) but every return sits "
                              "inside a conditional block and no "
                              "function-level return closes the "
                              "body - some CFG path falls through "
                              "to the default return value",
                    "code": text[:600]})

    return out


class SolgraphCfgPlugin(Plugin):
    id = "solgraph_cfg"
    label = "Solgraph CFG Analysis"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Per-function control-flow graph analysis "
                   "over contract source: unreachable code and "
                   "missing return paths. CFG block/edge counts "
                   "ride in each finding's evidence.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            artifacts = await t8.collect_artifacts(target, ctx)
        except Exception as e:
            res = self._degraded(f"artifact collection failed: "
                                 f"{str(e)[:120]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        used = 0
        for art in artifacts:
            src = art.get("source") or ""
            if not src:
                continue
            used += 1
            for hit in analyze_solgraph_source(src):
                ev = {"severity": hit["severity"],
                      "tool": "solgraph", "rule": hit["kind"],
                      "function": hit.get("function", ""),
                      "cfg": hit.get("cfg", {}),
                      "address": art.get("address", ""),
                      "remediation": REMEDIATION}
                findings.append(self._f(
                    "web3", hit["kind"],
                    f"{hit['severity'].upper()}: solgraph cfg: "
                    f"{hit['detail']}\n\nCode:\n{hit['code']}",
                    source="solgraph_cfg (native)",
                    confidence=70, passive=True, evidence=ev))
        if not used:
            res = self._skipped("no contract source supplied or "
                                "found for CFG analysis")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        res = self._ok(findings, f"solgraph cfg over {used} "
                                 f"source artifact(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
