"""SmartCheck remainder: SmartCheck's distinctive XML-rule patterns.

Coverage map (master dee4763, 853 plugins): NO SmartCheck adapter
exists anywhere on master (grep: zero hits - the smartcheck binary
sits in the audit node-tools dir but toolbox.py never wires it).
Most SmartCheck rules duplicate existing lanes and are NOT
repeated here: reentrancy (contract_logic), hardcoded addresses
(contract_chain.analyze_contract_source), strict balance equality
(strict_balance_equality), gas-limit DoS loops
(gas_denial_of_service_loop), hardcoded gas
(system_hardcoded_gas_limits), tx.origin / timestamp / selfdestruct
(contract_audit, smartcontract, deep families).

The genuinely uncovered SmartCheck rule classes shipped here:

- Deprecated constructions: sha3() (renamed keccak256 in 0.5),
  throw; (removed in 0.5), .callcode() (removed in 0.5). No
  existing detector names these; sources using them pin an
  obsolete compiler dialect whose other protections are absent.
- Costly operations in a loop: a STATE-VARIABLE WRITE (an SSTORE)
  or an external value call inside a for/while loop body,
  regardless of what the loop iterates. The gas-DoS plugins
  require a growable-array / push-payout shape; SmartCheck's rule
  is the broader pattern - every iteration pays full storage cost
  and a long loop can price the function out of a block.
- Missing zero-address validation: an address parameter stored
  into state by a runtime setter / initializer with NO
  address(0) check on that parameter in the function. Slither's
  missing-zero-check reaches master only through the external
  binary lane; no native detector covers the pattern.
  Constructors are EXCLUDED (adjudicated 2026-11-05 against the
  fp_clean corpus: every clean-corpus constructor stores a
  cast-typed address parameter unchecked - a one-shot deploy-time
  shape the corpus treats as clean; the runtime-setter remainder
  is the re-callable, stranger-reachable surface).

Detection only. Never sends a transaction.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from . import contract_chain as cc
from . import contract_logic as cl
from . import tier8_common as t8
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = ("Fix the SmartCheck pattern at the flagged site: "
               "replace deprecated constructions with their modern "
               "equivalents, hoist storage writes out of loops (or "
               "cache in memory), and validate address parameters "
               "against address(0) before storing them.")

_DEPRECATED = [
    ("smartcheck_deprecated_sha3", re.compile(r"\bsha3\s*\("),
     "sha3() is a deprecated pre-0.5 alias for keccak256()"),
    ("smartcheck_deprecated_throw", re.compile(r"\bthrow\s*;"),
     "throw; is a deprecated pre-0.5 revert construction"),
    ("smartcheck_deprecated_callcode",
     re.compile(r"\.callcode\s*\("),
     ".callcode() is a deprecated pre-0.5 low-level call"),
]
_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(")
_ADDR_PARAM_RE = re.compile(r"\baddress\s+(?:payable\s+)?([A-Za-z_]"
                            r"[A-Za-z0-9_]*)")
_SETTER_RE = re.compile(r"^(set|init|register|configure|update)",
                        re.I)


def _loop_bodies(text: str) -> List[str]:
    """Bodies of for/while loops in a function text (brace-matched;
    a braceless single-statement loop yields that statement)."""
    out: List[str] = []
    for m in _LOOP_RE.finditer(text):
        i = m.end()
        depth = 1
        while i < len(text) and depth:
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
            i += 1
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
        if i >= len(text):
            continue
        if text[i] != "{":
            end = text.find(";", i)
            out.append(text[i:end if end >= 0 else i + 80])
            continue
        depth = 0
        j = i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append(text[i:j + 1])
    return out


def analyze_smartcheck_source(src: str) -> List[Dict[str, Any]]:
    """SmartCheck remainder rules over Solidity source (pure)."""
    if not src:
        return []
    clean = cc._strip_comments(src)
    if "contract" not in clean and "library" not in clean:
        return []
    out: List[Dict[str, Any]] = []

    for kind, pat, detail in _DEPRECATED:
        m = pat.search(clean)
        if m:
            out.append({
                "kind": kind, "severity": "medium",
                "detail": detail + " - the source is written in "
                         "an obsolete Solidity dialect (SmartCheck "
                         "deprecated-constructions rule)",
                "code": clean[max(0, m.start() - 60):
                              m.end() + 60].strip()[:600]})

    try:
        state = cl.state_variables(clean)
    except Exception:
        state = set()
    fns = cc.extract_functions(clean)

    for fn in fns:
        text = fn.get("text") or ""
        if "{" not in text:
            continue
        for body in _loop_bodies(text):
            costly = None
            for var in sorted(state):
                if re.search(r"\b" + re.escape(var) +
                             r"\s*(?:\[[^\]]*\]\s*)?"
                             r"(?:\+|-|\*|/)?=(?![=>])", body):
                    costly = f"state variable '{var}' is written"
                    break
            if not costly and re.search(
                    r"\.call\s*\{|\.transfer\s*\(|\.send\s*\(", body):
                costly = "an external value call is made"
            if costly:
                out.append({
                    "kind": "smartcheck_costly_op_in_loop",
                    "severity": "medium",
                    "detail": f"in function '{fn.get('name', '')}': "
                              f"{costly} inside a loop body - every "
                              "iteration pays the full storage/call "
                              "cost (SmartCheck costly-operations-"
                              "in-loop rule)",
                    "code": text[:600]})
                break

    for fn in fns:
        name = fn.get("name") or ""
        sig = fn.get("signature") or ""
        text = fn.get("text") or ""
        if "{" not in text:
            continue
        is_ctor = name == "constructor" or \
            sig.strip().startswith("constructor")
        if is_ctor or not _SETTER_RE.match(name):
            continue  # constructors excluded: see module docstring
        for param in _ADDR_PARAM_RE.findall(sig):
            if re.search(r"\b" + re.escape(param) +
                         r"\s*(?:==|!=)\s*address\s*\(\s*0\s*\)",
                         text) or re.search(
                             r"address\s*\(\s*0\s*\)\s*(?:==|!=)\s*\b"
                             + re.escape(param) + r"\b", text):
                continue  # zero-checked in this function
            assigned = re.search(
                r"\b([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*"
                r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\(\s*)?"
                + re.escape(param) + r"\b", text)
            if assigned and assigned.group(1) != param:
                out.append({
                    "kind": "smartcheck_zero_address_unchecked",
                    "severity": "medium",
                    "detail": f"function '{name or 'constructor'}' "
                              f"stores address parameter '{param}' "
                              f"into '{assigned.group(1)}' with no "
                              "address(0) validation (SmartCheck "
                              "zero-address rule) - a zero value "
                              "permanently misconfigures the "
                              "contract",
                    "code": text[:600]})
                break
    return out


class SmartcheckRulesPlugin(Plugin):
    id = "smartcheck_rules"
    label = "SmartCheck Rules (remainder)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Native SmartCheck remainder rules over "
                   "contract source: deprecated constructions "
                   "(sha3/throw/callcode), costly state writes in "
                   "loops, and address parameters stored without "
                   "a zero-address check. No SmartCheck adapter "
                   "exists on master.")
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
            for hit in analyze_smartcheck_source(src):
                ev = {"severity": hit["severity"],
                      "tool": "smartcheck", "rule": hit["kind"],
                      "address": art.get("address", ""),
                      "remediation": REMEDIATION}
                findings.append(self._f(
                    "web3", hit["kind"],
                    f"{hit['severity'].upper()}: smartcheck: "
                    f"{hit['detail']}\n\nCode:\n{hit['code']}",
                    source="smartcheck_rules (native)",
                    confidence=75, passive=True, evidence=ev))
        if not used:
            res = self._skipped("no contract source supplied or "
                                "found for SmartCheck rules")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        res = self._ok(findings, f"smartcheck rules over {used} "
                                 f"source artifact(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
