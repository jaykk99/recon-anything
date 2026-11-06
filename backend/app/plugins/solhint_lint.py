"""Solhint LINT remainder: Solidity style / best-practice lint.

Coverage map (master dee4763, 853 plugins): audit_toolbox runs the
real Solhint binary, but ONLY its security ruleset - toolbox
SOLHINT_CONFIG enables 16 security rules and parse_solhint's own
docstring states "Style rules never reach this parser: the
adapter's config enables the security ruleset only." The security
findings (tx-origin, reentrancy hints, low-level calls, timestamp)
are therefore DUPLICATE-OF audit_toolbox and are NOT repeated here.

The genuinely uncovered remainder is Solhint proper's other half:
the style / best-practice lint rules from its default preset that
no plugin on master implements natively (and the toolbox lane
deliberately drops):

- no-empty-blocks            (empty function / control blocks)
- no-global-import           (import * as ... global imports)
- contract-name-camelcase    (contract/interface/library naming)
- func-name-mixedcase        (function naming)
- const-name-snakecase       (constants must be SCREAMING_SNAKE)
- event-name-camelcase       (event naming)
- visibility-modifier-order  (visibility before virtual/payable)

These are LINT findings: severity low by design, labeled lint -
they say "this source would fail a standard solhint run", never
"this is exploitable". Native implementation: the solhint binary
is not assumed (toolbox already owns the binary lane when it is
installed); this plugin keeps working on supplied source
artifacts when no binary exists.

Detection only. Never sends a transaction.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List

from . import contract_chain as cc
from . import tier8_common as t8
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION = ("Bring the source in line with the standard solhint "
               "style ruleset (naming, ordering, no empty blocks, "
               "no global imports) and run solhint in CI so the "
               "lint gate is enforced before deployment.")

_CONTRACT_RE = re.compile(
    r"\b(?:contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)")
_EVENT_RE = re.compile(r"\bevent\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CONST_RE = re.compile(
    r"\bconstant\b[^;=]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)")
_GLOBAL_IMPORT_RE = re.compile(r"\bimport\s+\*")
_EMPTY_BLOCK_RE = re.compile(r"\{\s*\}")


def _is_camel(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Z][A-Za-z0-9]*", name or ""))


def _is_mixed(name: str) -> bool:
    core = (name or "").lstrip("_")
    return bool(core) and core[0].islower() and \
        not re.search(r"_(?![A-Z0-9])", core) and "_" not in core


def _hit(kind: str, detail: str, code: str = "") -> Dict[str, Any]:
    return {"kind": kind, "severity": "low", "detail": detail,
            "code": code[:600]}


def analyze_lint_source(src: str) -> List[Dict[str, Any]]:
    """Solhint style-lint rules over Solidity source (pure)."""
    if not src or "contract" not in src and "interface" not in src \
            and "library" not in src:
        return []
    clean = cc._strip_comments(src)
    out: List[Dict[str, Any]] = []
    seen = set()

    def add(kind: str, detail: str, code: str = "") -> None:
        if kind not in seen:
            seen.add(kind)
            out.append(_hit(kind, detail, code))

    for m in _GLOBAL_IMPORT_RE.finditer(clean):
        add("lint_no_global_import",
            "global import (import * as ...) pulls every symbol of "
            "the imported file into scope - solhint "
            "no-global-import: import named symbols explicitly",
            clean[max(0, m.start() - 40):m.end() + 60].strip())
        break
    for m in _CONTRACT_RE.finditer(clean):
        if not _is_camel(m.group(1)):
            add("lint_contract_name_camelcase",
                f"contract/interface/library name '{m.group(1)}' is "
                "not CamelCase (solhint contract-name-camelcase)",
                m.group(0))
            break
    for m in _EVENT_RE.finditer(clean):
        if not _is_camel(m.group(1)):
            add("lint_event_name_camelcase",
                f"event name '{m.group(1)}' is not CamelCase "
                "(solhint event-name-camelcase)", m.group(0))
            break
    for m in _CONST_RE.finditer(clean):
        name = m.group(1)
        if name != name.upper() or not re.fullmatch(
                r"[A-Z][A-Z0-9_]*", name):
            add("lint_const_name_snakecase",
                f"constant '{name}' is not SCREAMING_SNAKE_CASE "
                "(solhint const-name-snakecase)", m.group(0))
            break
    for fn in cc.extract_functions(clean):
        name = fn.get("name") or ""
        sig = fn.get("signature") or ""
        text = fn.get("text") or ""
        if name and name not in ("constructor", "fallback",
                                 "receive"):
            if not _is_mixed(name):
                add("lint_func_name_mixedcase",
                    f"function name '{name}' is not mixedCase "
                    "(solhint func-name-mixedcase)", sig)
        # visibility-modifier-order: visibility must come before
        # virtual / override / payable in the signature.
        toks = re.findall(
            r"\b(public|external|internal|private|virtual|override|"
            r"payable|pure|view)\b", sig)
        vis = [i for i, t in enumerate(toks)
               if t in ("public", "external", "internal", "private")]
        early = [i for i, t in enumerate(toks)
                 if t in ("virtual", "override", "payable")]
        if vis and early and min(early) < min(vis):
            add("lint_visibility_modifier_order",
                f"function '{name}': a virtual/override/payable "
                "modifier appears before the visibility modifier "
                "(solhint visibility-modifier-order)", sig)
        if "{" in text:
            body = text[text.index("{") + 1:text.rindex("}")] \
                if "}" in text else ""
            if not body.strip():
                add("lint_no_empty_blocks",
                    f"function '{name}' has an empty body block "
                    "(solhint no-empty-blocks)", sig)
    if _EMPTY_BLOCK_RE.search(clean) and \
            "lint_no_empty_blocks" not in seen:
        # an empty control block outside the function scan above
        m = _EMPTY_BLOCK_RE.search(clean)
        add("lint_no_empty_blocks",
            "an empty block {} appears in the source (solhint "
            "no-empty-blocks)",
            clean[max(0, m.start() - 60):m.end() + 10].strip())
    return out


class SolhintLintPlugin(Plugin):
    id = "solhint_lint"
    label = "Solhint Lint (style rules)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Native Solhint style/best-practice LINT over "
                   "contract source: empty blocks, global imports, "
                   "contract/function/constant/event naming, "
                   "visibility-modifier order. The security ruleset "
                   "is audit_toolbox's lane and is not repeated.")
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
            for hit in analyze_lint_source(src):
                ev = {"severity": "low", "lint": True,
                      "tool": "solhint", "rule": hit["kind"],
                      "address": art.get("address", ""),
                      "remediation": REMEDIATION}
                findings.append(self._f(
                    "web3", hit["kind"],
                    f"LOW: solhint lint: {hit['detail']}"
                    + (f"\n\nCode:\n{hit['code']}" if hit["code"]
                       else ""),
                    source="solhint_lint (native)",
                    confidence=85, passive=True, evidence=ev))
        if not used:
            res = self._skipped("no contract source supplied or "
                                "found for lint")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        res = self._ok(findings, f"solhint lint over {used} "
                                 f"source artifact(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
