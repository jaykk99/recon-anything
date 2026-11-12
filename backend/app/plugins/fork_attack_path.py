"""Complete attack-path detector: the static entry point for the
fork harness (app/fork_attack.py).

A fire means: one function, reachable by any caller (no
onlyOwner / onlyRole / equivalent gate), contains a dangerous
primitive with a caller-controlled input AND value at stake in
the same function - delegatecall to a caller-supplied target,
call{value:} to a caller-supplied address, selfdestruct to a
caller-supplied address, mint to a caller-supplied recipient,
upgradeTo a caller-supplied implementation, or a payout to
msg.sender sized from the contract's balance. That is the exact
shape the fork harness executes, so the finding carries the
hypothesis (function signature + suggested args) the harness
needs: STRANGER for address params, MAX for amount params.

The receive rule applies: a payout landing at a FIXED or
HOLDER-SELF destination is trigger-only at low severity, never
a candidate. Anything else stays candidate-grade - but a
candidate here is NOT proof. The fork harness verdict is ALWAYS
UNVERIFIED; VERIFIED_REAL still requires a live-chain probe
from an unfunded stranger plus live receipt evidence.

Detection only. This plugin never sends a transaction; it reads
verified source. The harness it feeds runs on a local Anvil
fork and refuses any broadcast hypothesis.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import bsc_common as bc
from .bsc_common import S
from . import contract_chain as cc
from . import contract_logic as cl
from .contract_logic import _gated_deep

FAMILY = "forkpath"

SPECS = [
    S("fork_attack_path_complete", FAMILY, severity="high",
      recipient=True,
      detail="Complete stranger attack path (static): an ungated "
             "function holds a dangerous primitive with a "
             "caller-controlled input and value at stake - "
             "delegatecall / value call / selfdestruct / mint / "
             "upgrade to a caller-supplied address, or a payout "
             "to msg.sender. Fork-test this path; a fork payout "
             "is UNVERIFIED by design, never proof.",
      fix="Gate the function behind onlyOwner / onlyRole (or "
          "remove the caller-controlled target/recipient), and "
          "never let a stranger choose where value or code "
          "goes."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}

# Primitives, in the order they are checked per function. Each entry
# is (primitive name, regex finding the primitive, regex finding a
# caller-controlled argument for it). Caller control is judged from
# the primitive's own argument text: a parameter name, msg.sender,
# or a value derived from calldata.
_PRIMITIVES: List[Tuple[str, str]] = [
    ("delegatecall", r"\.delegatecall\s*\("),
    ("value_call", r"\.call\s*\{\s*value\s*:"),
    ("selfdestruct", r"\bselfdestruct\s*\("),
    ("mint_to_caller", r"\b_mint\s*\("),
    ("upgrade_to_caller", r"\bupgradeTo(?:AndCall)?\s*\("),
    ("payout_to_sender", r"payable\s*\(\s*msg\.sender\s*\)"
                          r"\s*\.\s*(?:transfer|send|call)\s*\("),
]


def _param_names(signature: str) -> List[str]:
    """Parameter names from a function signature string."""
    try:
        inner = signature[signature.index("(") + 1:
                          signature.rindex(")")]
    except ValueError:
        return []
    names: List[str] = []
    for part in inner.split(","):
        toks = [t for t in part.strip().split() if t]
        if len(toks) >= 2 and toks[-1] not in ("memory", "calldata",
                                              "storage"):
            names.append(toks[-1])
    return names


def _caller_controlled(arg_text: str, params: List[str]) -> bool:
    """True when the primitive's argument is caller-controlled."""
    if "msg.sender" in arg_text:
        return True
    for p in params:
        if re.search(r"\b" + re.escape(p) + r"\b", arg_text):
            return True
    return False


def _args_template(signature: str) -> List[str]:
    """Suggested fork args: STRANGER for addresses, MAX for uints."""
    try:
        inner = signature[signature.index("(") + 1:
                          signature.rindex(")")]
    except ValueError:
        return []
    out: List[str] = []
    for part in inner.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith("address"):
            out.append("STRANGER")
        elif part.startswith("uint") or part.startswith("int"):
            out.append("MAX")
        elif part.startswith("bytes"):
            out.append("0x")
        elif part.startswith("bool"):
            out.append("true")
        else:
            out.append("STRANGER")
    return out


def _canonical_signature(name: str, signature: str) -> str:
    """Canonical call signature for the fork harness, e.g.
    exec(address,bytes). The harness (cast send) needs types,
    not the raw declaration text."""
    try:
        inner = signature[signature.index("(") + 1:
                          signature.rindex(")")]
    except ValueError:
        return f"{name}()"
    types: List[str] = []
    for part in inner.split(","):
        toks = [t for t in part.strip().split() if t]
        if toks:
            types.append(toks[0])
    return f"{name}({','.join(types)})"


def _modifier_region(fn_text: str) -> str:
    """Everything between the end of the parameter list and the
    opening brace - where onlyRole / onlyOwner live. Same shape
    as deep_audit7._authorize_modifier_region."""
    decl = fn_text.split("{", 1)[0]
    open_p = decl.find("(")
    if open_p < 0:
        return decl
    depth = 0
    for i in range(open_p, len(decl)):
        c = decl[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return decl[i + 1:]
    return ""


_UUPS_AUTH_MODIFIER_RE = re.compile(
    r"\bonly[A-Z]\w*"
    r"|\brequiresAuth\b|\bauthorized\b|\brestricted\b", re.I)


def _upgrade_path_gated(fn: Dict[str, Any], scope) -> bool:
    """Gate check for the upgrade path. The shared _gated_deep
    treats the NAME _authorizeUpgrade as a gate (it is in
    _GATE_RE), so an empty-bodied _authorizeUpgrade with no
    modifier would wrongly look gated - the USDG lesson. Read
    the modifier region instead: an only*/requiresAuth modifier
    on the entry function or on _authorizeUpgrade is a gate;
    anything else is open."""
    if _UUPS_AUTH_MODIFIER_RE.search(
            _modifier_region(fn.get("signature", ""))):
        return True
    helper = scope.helpers.get("_authorizeUpgrade")
    if helper is None:
        return cl._gated_deep(fn, scope)
    return bool(_UUPS_AUTH_MODIFIER_RE.search(
        _modifier_region(helper.get("text", ""))))


# Value payouts sourced from the caller's own recorded balance
# are self-funded, not a drain: burn-first withdrawals, refunds
# of the caller's own pending amount, SuperToken downgrades. A
# stranger with no balance in the contract receives nothing from
# these. The overdraw shape (withdraw MORE than deposited) is a
# different detector family (deep-audit withdraw detectors).
_SELF_FUNDED_PAYOUT_RE = re.compile(
    r"_burn\s*\(\s*msg\.sender"
    r"|balanceOf\s*\[\s*msg\.sender\s*\]\s*-="
    r"|balances\s*\[\s*msg\.sender\s*\]\s*-="
    r"|pendingRefunds\s*\[\s*msg\.sender\s*\]"
    r"|selfBurn\s*\(\s*msg\.sender")


def _mint_args(call_text: str) -> tuple:
    """Split a _mint(...) call's top-level arguments. call_text
    starts at the _mint match; returns the args inside the parens
    with no surrounding punctuation."""
    i = call_text.find("(")
    if i < 0:
        return ()
    depth = 0
    parts: List[str] = []
    cur = ""
    for c in call_text[i:]:
        if c == "(":
            depth += 1
            if depth == 1:
                continue
            cur += c
        elif c == ")":
            depth -= 1
            if depth == 0:
                parts.append(cur.strip())
                break
            cur += c
        elif c == "," and depth == 1:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += c
    return tuple(parts)


def analyze_forkpath_source(src: str, contract_name: str = ""
                            ) -> List[Dict[str, Any]]:
    """Run the fork-path detector over verified source.

    Returns finding dicts {kind, severity, function, code, detail,
    recipient, report_class, gate_analysis, hypothesis} - the same
    validator-ready shape as the deep-audit families.
    """
    scope = cl._Scope(src, contract_name)
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for fn in scope.functions:
        name = fn.get("name") or ""
        if not name or name == "constructor" or name in seen:
            continue
        text = fn.get("text") or ""
        if "{" not in text:
            continue
        sig = fn.get("signature") or ""
        if re.search(r"\b(view|pure)\b", sig):
            continue
        if not re.search(r"\b(public|external)\b", sig):
            continue
        params = _param_names(sig)
        self_funded = bool(_SELF_FUNDED_PAYOUT_RE.search(text))
        hit: Optional[Tuple[str, str]] = None
        for primitive, pat in _PRIMITIVES:
            m = re.search(pat, text)
            if not m:
                continue
            # The primitive's argument text: from the match to the
            # closing paren of that call (bounded slice; a nested
            # call inside the args is still caller-controlled if
            # any param name appears in the slice).
            arg_text = text[m.start():m.start() + 400]
            if primitive == "mint_to_caller":
                # Free mint only: _mint(<recipient>, <caller-chosen
                # amount>). A mint sized from the caller's own
                # deposit (UniswapV2 LP mint: amount is a computed
                # local) or exactly msg.value (deposit wrapper) is
                # self-funded, not a drain. The recipient decides
                # candidate vs trigger-only downstream: a fixed
                # recipient still fires (trigger-only), a
                # caller-chosen one is a candidate.
                call_args = _mint_args(arg_text)
                if len(call_args) < 2:
                    continue
                amount = call_args[1]
                if amount.strip() not in params:
                    continue
                hit = (primitive, arg_text)
                break
            if primitive in ("upgrade_to_caller",
                             "payout_to_sender"):
                # mint/upgrade/payout are caller-controlled when
                # the recipient/implementation is a parameter or
                # msg.sender; the payout shape is msg.sender by
                # construction.
                if primitive == "payout_to_sender" and self_funded:
                    continue
                if primitive == "payout_to_sender" or \
                        _caller_controlled(arg_text, params):
                    hit = (primitive, arg_text)
                    break
            elif primitive == "value_call" and self_funded:
                continue
            elif _caller_controlled(arg_text, params):
                hit = (primitive, arg_text)
                break
        if hit is None:
            continue
        # Gate check, per primitive: the upgrade path reads the
        # _authorizeUpgrade modifier region (the USDG lesson -
        # _gated_deep treats the NAME _authorizeUpgrade as a
        # gate); everything else uses the shared deep check.
        if hit[0] == "upgrade_to_caller":
            if _upgrade_path_gated(fn, scope):
                continue
        elif _gated_deep(fn, scope):
            continue
        seen.add(name)
        primitive, _arg = hit
        recipient, rdetail = cl.classify_recipient(text)
        detail = (
            f"Complete attack path (static): ungated function "
            f"'{name}' holds a {primitive} primitive with a "
            f"caller-controlled input and value at stake. "
            f"Recipient analysis: {recipient} ({rdetail}). "
            f"Fork-test this path with the hypothesis in the "
            f"finding evidence; a fork payout is UNVERIFIED by "
            f"design, never proof.")
        item: Dict[str, Any] = {
            "kind": "fork_attack_path_complete",
            "severity": "high",
            "function": name,
            "code": cc._snip(text),
            "detail": detail,
            "recipient": recipient,
            "gate_analysis": (
                "no caller-identity gate (onlyOwner / onlyRole / "
                "role check) on this function; any caller can "
                f"reach the {primitive} primitive"),
            "hypothesis": {
                "function": _canonical_signature(name, sig),
                "args_template": _args_template(sig),
                "primitive": primitive,
                "value_wei": 0,
                "tokens": [],
            },
        }
        if recipient in ("FIXED", "HOLDER-SELF"):
            item["report_class"] = "trigger_only"
            item["severity"] = "low"
            item["detail"] += (
                " Recipient analysis: moved value lands at a "
                f"{recipient} destination, so a stranger can "
                "trigger this but receives nothing - classified "
                "TRIGGER-ONLY under the receive rule.")
        else:
            item["report_class"] = "candidate"
        out.append(item)
    return out


class ForkAttackPathPlugin(bc.BscDetectorPlugin):
    """One registered plugin for the fork-path spec. Reuses the
    BSC detector's collect / fetch / proxy machinery; only the
    per-contract analysis is the fork-path analyzer above."""

    id = "fork_attack_path_complete"
    label = "Fork Attack Path Complete"
    description = (
        "Complete stranger attack-path detector (fork harness "
        "entry): an ungated function with a dangerous primitive "
        "on a caller-controlled input and value at stake. Static "
        "verified-source analysis, detection only; the finding "
        "carries the fork hypothesis.")
    _spec = SPECS[0]

    def _analyze_contract(self, chain: cc.ChainConfig, addr: str,
                          src: Optional[Dict[str, Any]],
                          findings: List[Finding], role: str,
                          proxy_addr: str = "",
                          impl_addr: str = "") -> bool:
        if src is None:
            return False
        url = cc.explorer_url(chain, addr)
        base_ev = {"address": addr, "chain": chain.id,
                   "chain_id": chain.chain_id,
                   "contract_role": role}
        if role == "implementation":
            base_ev["proxy_address"] = proxy_addr
            base_ev["implementation_address"] = addr
            tag = f" [implementation behind proxy {proxy_addr}]"
        elif role == "proxy_shell":
            base_ev["proxy_address"] = addr
            base_ev["implementation_address"] = impl_addr
            tag = f" [proxy shell; implementation {impl_addr}]"
        else:
            tag = ""
        spec = self._spec
        for item in analyze_forkpath_source(
                src["source"],
                contract_name=src.get("contract_name", "")):
            ev = dict(base_ev)
            ev.update({
                "severity": item["severity"],
                "check": spec.id,
                "kind": spec.id,
                "detector_outcome": spec.outcome,
                "function": item["function"],
                "code": item["code"],
                "detail": item["detail"],
                "bytecode_only": False,
                "source_origin": src.get("origin", ""),
                "contract_name": src.get("contract_name", ""),
                "remediation": spec.fix,
                "gate_analysis": item["gate_analysis"],
                "hypothesis": item["hypothesis"],
            })
            if item.get("report_class"):
                ev["report_class"] = item["report_class"]
                ev["recipient"] = item.get("recipient", "")
            fn_txt = f"function '{item['function']}' " \
                if item["function"] else ""
            findings.append(self._f(
                "web3", spec.id,
                f"{item['severity'].upper()}: {spec.label}: "
                f"{fn_txt}in contract {addr} on {chain.name}{tag}"
                f"\n\n{item['detail']}\n\nCode:\n{item['code']}",
                source="fork attack-path detector "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True
