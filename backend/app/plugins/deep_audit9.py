"""Deep-audit detectors, batch 9: system architecture slices
(2026-11-04).

Eight chain-agnostic EVM detectors for the SYS-001/002/004/
005/006/007/008/009 slices left open by the coverage-e audit,
rebuilt to the batch-4 standard: body / condition parsing
(balanced-paren conditions, brace-balanced loop bodies,
declaration-level state-variable extraction), the exact code
plus a gate analysis on every finding, and a finding shape
the auto-validator can consume unchanged (kind, function,
recipient, report_class, gate).

Disjointness against the existing registry (coverage-e):

- growable_array_loop_no_pagination (SYS-001 slice):
  gas_denial_of_service_loop requires an external call /
  payout per loop element; this is the call-free slice it
  misses - pure iteration / accumulation over a user-growable
  array, with a state write in the loop body, and NO
  pagination parameters on the looping function.
- block_number_as_time (SYS-002 slice): no existing native
  detector parses block.number <-> time conversion semantics
  (smartcontract flags block.timestamp reliance, a different
  intent; the toolbox heavy lane's Arbitrum-only check is not
  native). Pure block-height use stays silent.
- hardcoded_zero_role_address (SYS-004 slice):
  contract_chain's hardcoded_address lane explicitly EXCLUDES
  the zero address; this is the zero-address-in-a-config-role
  slice it cannot see. Mere == address(0) existence checks
  (the clean shape) stay silent.
- state_change_without_event (SYS-005 slice (a)): native
  coverage was transfer-only (bep20_fake_transfer_events);
  this is the general setter slice. Payload completeness
  (slice (b) - events emitted without old/new values) is out
  of scope here, noted in the spec detail.
- private_sensitive_state_var (SYS-006 slice):
  contract_chain's secret-string lane catches secret-shaped
  literal VALUES; this catches the named-variable shape of
  any type (a sensitive-named `private` variable assigned via
  constructor / setter, whose value is world-readable
  on-chain regardless of the visibility keyword).
- assembly_fmp_literal_corruption (SYS-007 slice):
  system_assembly_memory_overwrite fires on ANY
  mstore(0x40, ...) with no value check, over-firing on
  legitimate allocation updates. This is the PRECISION
  subset of that detector: only a literal 0 or < 0x80 stored
  to the free-memory pointer fires; a computed expression
  (the legitimate allocation update) stays silent.
- assembly_returndatacopy_unbounded (SYS-008): no existing
  detector mentions returndatacopy at all (coverage-e GAP).
- coinbase_decision_input (SYS-009): no existing native
  detector flags block.coinbase in contract logic (registry
  'coinbase' hits are the Coinbase exchange, a different
  thing). The direct tip shape (paying coinbase directly)
  stays silent.

Recipient discipline: none of these eight classes hands
value to a stranger - they are DoS, logic-semantics, config,
observability, disclosure, memory-corruption and
miner-influence classes. Findings therefore classify
honestly as TRIGGER-ONLY with recipient NONE (or the FIXED /
HOLDER-SELF class classify_recipient computes) unless the
flagged function ALSO moves value to a caller / caller-
supplied destination, in which case the receive rule
promotes it to candidate. Spec severity is preserved in
both cases: it is calibrated to the flaw's own impact
(a medium false-privacy disclosure does not become low
just because no token transfer is involved).

Detection only: verified-source static analysis in the fast
lane, never sends a transaction, never calls the contract
for value. Fetch failure is reported honestly by the shared
scaffolding (analyzed 0 / no verified source - skipped),
never dressed up as a clean result.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from .bsc_common import DetectorSpec, S

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
FAMILY = "deep9"

SPECS = [
    S("growable_array_loop_no_pagination", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail="Unbounded loop over a growable state array with "
             "no pagination: a non-view function loops bounded "
             "only by a state array's .length, that array is "
             "grown by push() from a public/external function "
             "of the same contract, the looping function takes "
             "no start/end/limit pagination parameters, and the "
             "loop body writes state. Anyone who can grow the "
             "array can push the loop past the block gas limit "
             "and permanently deny the function - no external "
             "call inside the loop is needed for the denial.",
      fix="Paginate the loop (start/end or offset/limit "
          "parameters with a bounded window), cap the array's "
          "growth, or replace full-array iteration with "
          "incremental / indexed processing."),
    S("block_number_as_time", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail="block.number used as a time proxy: block.number "
             "is combined with time semantics (multiplied or "
             "divided by a seconds-magnitude constant, stored "
             "into a time/deadline/expiry-named variable, or "
             "compared against a timestamp-magnitude literal). "
             "Block production is not a clock - block times "
             "vary by chain and by era, so durations, deadlines "
             "and expiries derived from block height drift or "
             "break outright.",
      fix="Use block.timestamp for wall-clock semantics (with "
          "its manipulation bounds understood) and block.number "
          "only as a block height; never convert between the "
          "two with fixed seconds-per-block constants."),
    S("hardcoded_zero_role_address", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail="Config-role address assigned the zero address: "
             "an address state variable with a config-role name "
             "(router / factory / oracle / token / pair / "
             "treasury / owner / admin) is assigned address(0) "
             "or the all-zero literal in a constructor or "
             "setter. The role is left unbound - every call "
             "routed through it reverts, is silently dropped, "
             "or falls into a zero-address edge case - while "
             "mere == address(0) existence checks (the clean "
             "shape) do not fire.",
      fix="Assign the role variable the real deployment "
          "address (or a constructor/setter parameter), and "
          "guard setters with require(newAddr != address(0))."),
    S("state_change_without_event", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail="State-changing setter emits no event: the "
             "contract defines at least one event, yet a "
             "public/external setter-shaped function writes "
             "state with no emit in its body, so indexers, "
             "wallets and monitoring cannot observe the change "
             "off-chain. (Event payload completeness - events "
             "that are emitted but lack old/new values - is "
             "out of scope for this detector.)",
      fix="Emit a dedicated event carrying the changed values "
          "(ideally old and new) from every state-changing "
          "setter, matching the contract's existing event "
          "surface."),
    S("private_sensitive_state_var", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Sensitive data in a 'private' state variable: a "
             "state variable declared private has a sensitive "
             "name (secret / password / api key / private key / "
             "seed / mnemonic / credential). Solidity's private "
             "visibility only restricts other contracts' code - "
             "the value sits in public storage and is readable "
             "by anyone from the chain, so the privacy is "
             "false and any real secret stored here is exposed.",
      fix="Never store secrets on-chain, in any visibility: "
          "keep keys, passwords and credentials off-chain and "
          "store at most a hash commitment on-chain."),
    S("assembly_fmp_literal_corruption", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Free-memory-pointer corruption in inline "
             "assembly: mstore(0x40, <literal>) stores the "
             "literal 0 or a value below 0x80 to the "
             "free-memory pointer (0x40). That overwrites the "
             "allocator's next-free address with a pointer into "
             "reserved / scratch space, corrupting every "
             "subsequent allocation. This is the precision "
             "subset of system_assembly_memory_overwrite: a "
             "computed expression stored to 0x40 (the "
             "legitimate allocation update) does not fire.",
      fix="Only ever store a computed allocation end pointer "
          "to 0x40 (mstore(0x40, add(ptr, size)) with proper "
          "alignment), never a literal."),
    S("assembly_returndatacopy_unbounded", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Unbounded returndatacopy in inline assembly: a "
             "function copies returndata with returndatacopy() "
             "without ever consulting returndatasize() in the "
             "same function, so the copy length is not derived "
             "from - or checked against - the actual returned "
             "size. A callee returning oversized data turns "
             "this into memory corruption or a gas grief "
             "(return bomb) against the caller.",
      fix="Size the copy from returndatasize(), bound it to "
          "the destination buffer / a sane maximum, and revert "
          "or truncate when the callee returns more."),
    S("coinbase_decision_input", FAMILY, severity="low",
      outcome="a", recipient=True,
      detail="block.coinbase used as a decision input: the "
             "block proposer's address feeds a condition, a "
             "hash, a payee/winner selection, or a non-payee "
             "state variable. Post-merge, coinbase is the "
             "proposer / fee recipient chosen by the block "
             "builder, so logic keyed on it is miner/builder-"
             "influenceable and semantically unstable. Paying "
             "coinbase directly (the tip shape) does not fire.",
      fix="Do not key decisions, selection or stored state on "
          "block.coinbase; if the proposer must be paid, pay "
          "it directly without branching logic on its "
          "identity."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirror batch 4)
# ---------------------------------------------------------------------------

def _scope_fns(src: str, contract_name: str):
    scope = cl._Scope(src, contract_name)
    fns = [fn for fn in scope.functions if "{" in fn["text"]]
    return scope, fns


def _hit(spec: DetectorSpec, fn_name: str, code: str,
         detail: str, gate: str) -> Dict[str, Any]:
    return {"kind": spec.id, "severity": spec.severity,
            "function": fn_name, "code": code, "detail": detail,
            "gate_analysis": gate}


def _finish(spec: DetectorSpec, item: Dict[str, Any],
            fn_text: str, why_none: str) -> Dict[str, Any]:
    """Honest recipient classification for quality/config
    classes: promote to candidate only when the flagged
    function ALSO moves value to a caller / caller-supplied
    destination (the receive rule); otherwise trigger-only.
    Spec severity is preserved (see module docstring)."""
    recipient, rdetail = "NONE", why_none
    if fn_text and "{" in fn_text:
        r, rd = cl.classify_recipient(fn_text)
        if r in ("CALLER", "CALLER-SUPPLIED"):
            recipient, rdetail = r, rd
        elif r in ("FIXED", "HOLDER-SELF"):
            recipient, rdetail = r, rd
    item["recipient"] = recipient
    if recipient in ("CALLER", "CALLER-SUPPLIED"):
        item["report_class"] = "candidate"
        item["detail"] += (
            f" Recipient analysis: recipient classified "
            f"{recipient} ({rdetail}) - the flagged function "
            f"also moves value to a stranger-reachable "
            f"destination, classified CANDIDATE under the "
            f"receive rule.")
    else:
        item["report_class"] = "trigger_only"
        item["detail"] += (
            f" Recipient analysis: recipient classified "
            f"{recipient} ({rdetail}) - no stranger value "
            f"destination exists in this class, so a stranger "
            f"can trigger / observe the flaw but receives no "
            f"value from it, classified TRIGGER-ONLY under the "
            f"receive rule at the spec severity.")
    return item


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
    """(inner_text, end_pos) for the paren group at open_pos."""
    depth = 0
    i = open_pos
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
        i += 1
    return text[open_pos + 1:], len(text) - 1


def _conditions(text: str) -> List[str]:
    """Contents of every require(...) / assert(...) / if(...)
    condition in the text (balanced-paren extraction)."""
    out: List[str] = []
    for m in re.finditer(r"\b(?:require|assert|if)\s*\(", text):
        inner, _ = _balanced(text, m.end() - 1)
        out.append(inner)
    return out


def _loops(text: str) -> List[Tuple[str, str]]:
    """(header, body) for every for / while loop: balanced
    header parens, then a brace-balanced block body or a
    single statement body."""
    out: List[Tuple[str, str]] = []
    for m in re.finditer(r"\b(?:for|while)\s*\(", text):
        header, hend = _balanced(text, m.end() - 1)
        i = hend + 1
        while i < len(text) and text[i] in " \t\r\n":
            i += 1
        if i < len(text) and text[i] == "{":
            end = cl._brace_span(text, i)
            out.append((header, text[i:end]))
        else:
            j = text.find(";", i)
            out.append((header,
                        text[i:j + 1] if j >= 0 else text[i:]))
    return out


_DECL_RE = re.compile(
    r"(mapping\s*\([^)]*\)|[A-Za-z_][\w.]*"
    r"(?:\s*\[\s*\d*\s*\])?)\s+"
    r"((?:(?:public|private|internal|constant|immutable)\s+)*)"
    r"([A-Za-z_]\w*)\s*(?:=\s*([^;]+))?;")


def _decls(scoped: str) -> List[Dict[str, Any]]:
    """Contract-level (depth-1) state-variable declarations:
    {type, visibility, name, init}."""
    depths = cl._depth_array(scoped)
    out: List[Dict[str, Any]] = []
    seen = set()
    for m in _DECL_RE.finditer(scoped):
        if depths[m.start()] != 1 or m.group(3) in seen:
            continue
        seen.add(m.group(3))
        out.append({"type": m.group(1),
                    "visibility": m.group(2) or "",
                    "name": m.group(3),
                    "init": (m.group(4) or "").strip(),
                    "pos": m.start()})
    return out


def _fn_params(fn: Dict[str, Any]) -> List[str]:
    sig = fn["signature"]
    i = sig.find("(")
    if i < 0:
        return []
    inner, _ = _balanced(sig, i)
    names = []
    for part in inner.split(","):
        toks = [t for t in part.split()
                if t not in ("memory", "calldata", "storage",
                             "payable")]
        if toks:
            names.append(toks[-1])
    return names


def _is_view(fn: Dict[str, Any]) -> bool:
    return bool(re.search(r"\b(view|pure)\b", fn["signature"]))


# ---------------------------------------------------------------------------
# 1. growable_array_loop_no_pagination (SYS-001 slice)
# ---------------------------------------------------------------------------

_PAGINATION_RE = re.compile(
    r"start|end|limit|offset|page|cursor|max", re.I)


def _analyze_growable_loop(src: str, spec: DetectorSpec,
                           compiler: str = "",
                           contract_name: str = ""
                           ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    decls = _decls(scope.scoped_text)
    state = {d["name"] for d in decls}
    dyn_arrays = {d["name"] for d in decls
                  if re.search(r"\[\s*\]\s*$", d["type"])}
    if not dyn_arrays or not state:
        return []
    growable = set()
    for fn in fns:
        if not re.search(r"\b(public|external)\b",
                         fn["signature"]):
            continue
        for arr in dyn_arrays:
            if re.search(r"\b" + re.escape(arr) +
                         r"\s*\.\s*push\s*\(", fn["text"]):
                growable.add(arr)
    if not growable:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _is_view(fn):
            continue
        if any(_PAGINATION_RE.search(p)
               for p in _fn_params(fn)):
            continue
        for header, body in _loops(fn["text"]):
            arr_hit = next(
                (a for a in sorted(growable)
                 if re.search(r"\b" + re.escape(a) +
                              r"\s*\.\s*length\b", header)),
                None)
            if not arr_hit:
                continue
            writes = cl._state_writes(body, state)
            if not writes and not re.search(
                    r"\b\w+\s*\.\s*(push|pop)\s*\(|"
                    r"\bdelete\s+\w+", body):
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' loops over "
                f"'{arr_hit}.length', '{arr_hit}' is grown by "
                f"push() in a public/external function, the "
                f"signature carries no pagination parameters, "
                f"and the loop body writes state "
                f"({sorted({v for _p, v in writes})}).")
            item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                        detail,
                        "loop bound is the growable array's own "
                        ".length; no pagination parameters and "
                        "no length cap gate this function")
            out.append(_finish(
                spec, item, fn["text"],
                "a gas-denial loop hands no value to its "
                "trigger"))
            break
    return out


# ---------------------------------------------------------------------------
# 2. block_number_as_time (SYS-002 slice)
# ---------------------------------------------------------------------------

_TIME_NAME_RE = re.compile(r"time|deadline|expir", re.I)
_TS_MAGNITUDE = 1_000_000_000


def _block_time_reason(text: str) -> Optional[str]:
    for m in re.finditer(r"block\.number\s*([*/])\s*(\d[\d_]*)",
                         text):
        if int(m.group(2).replace("_", "")) >= 12:
            return (f"block.number {m.group(1)} "
                    f"{m.group(2)} (seconds-magnitude constant)")
    for m in re.finditer(r"(\d[\d_]*)\s*\*\s*block\.number",
                         text):
        if int(m.group(1).replace("_", "")) >= 12:
            return (f"{m.group(1)} * block.number "
                    f"(seconds-magnitude constant)")
    for m in re.finditer(r"block\.number\s*/\s*(\d[\d_]*)", text):
        if int(m.group(1).replace("_", "")) >= 12:
            return (f"block.number / {m.group(1)} "
                    f"(blocks-per-period constant)")
    for m in re.finditer(
            r"([A-Za-z_]\w*)\s*=(?!=)\s*[^;]*block\.number",
            text):
        if _TIME_NAME_RE.search(m.group(1)):
            return (f"block.number assigned into "
                    f"time-named variable '{m.group(1)}'")
    for m in re.finditer(
            r"block\.number\s*(?:==|!=|>=|<=|>|<)\s*(\d[\d_]*)",
            text):
        if int(m.group(1).replace("_", "")) > _TS_MAGNITUDE:
            return (f"block.number compared against "
                    f"timestamp-magnitude literal {m.group(1)}")
    for m in re.finditer(
            r"(\d[\d_]*)\s*(?:==|!=|>=|<=|>|<)\s*block\.number",
            text):
        if int(m.group(1).replace("_", "")) > _TS_MAGNITUDE:
            return (f"timestamp-magnitude literal {m.group(1)} "
                    f"compared against block.number")
    return None


def _analyze_block_time(src: str, spec: DetectorSpec,
                        compiler: str = "",
                        contract_name: str = ""
                        ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if "block.number" not in fn["text"]:
            continue
        reason = _block_time_reason(fn["text"])
        if not reason:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}': {reason}.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "block.number carries time semantics here; "
                    "no chain block-time safeguard is visible")
        out.append(_finish(
            spec, item, fn["text"],
            "a time-semantics flaw hands no value to a "
            "stranger"))
    return out


# ---------------------------------------------------------------------------
# 3. hardcoded_zero_role_address (SYS-004 slice)
# ---------------------------------------------------------------------------

_ROLE_NAME_RE = re.compile(
    r"router|factory|oracle|token|pair|treasury|owner|admin",
    re.I)
_ZERO_ADDR = r"(?:address\s*\(\s*0\s*\)|0x0{1,40}\b)"
_SETTER_NAME_RE = re.compile(
    r"^(set|update|change|configure|init)", re.I)


def _zero_assignments(text: str, name: str):
    return re.finditer(
        r"\b" + re.escape(name) + r"\s*=(?!=)\s*" + _ZERO_ADDR,
        text)


def _analyze_zero_role(src: str, spec: DetectorSpec,
                       compiler: str = "",
                       contract_name: str = ""
                       ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    decls = _decls(scope.scoped_text)
    roles = [d for d in decls
             if d["type"] == "address"
             and _ROLE_NAME_RE.search(d["name"])]
    if not roles:
        return []
    out: List[Dict[str, Any]] = []
    for d in roles:
        if d["init"] and re.fullmatch(_ZERO_ADDR, d["init"]):
            detail = spec.detail + (
                f" Observed: role variable '{d['name']}' is "
                f"declared initialized to the zero address.")
            item = _hit(spec, d["name"],
                        cc._snip(scope.scoped_text[d["pos"]:]),
                        detail,
                        "role variable initialized to address(0) "
                        "at declaration; no non-zero binding")
            out.append(_finish(
                spec, item, "",
                "an unbound config role hands no value to a "
                "stranger"))
    for fn in fns:
        is_ctor = fn["name"] == "constructor"
        if not is_ctor and not _SETTER_NAME_RE.match(fn["name"]):
            continue
        for d in roles:
            if not list(_zero_assignments(fn["text"],
                                          d["name"])):
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' assigns role "
                f"variable '{d['name']}' the zero address.")
            item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                        detail,
                        "zero address assigned to a config role "
                        "in a constructor/setter; comparisons "
                        "against address(0) do not fire")
            out.append(_finish(
                spec, item, fn["text"],
                "an unbound config role hands no value to a "
                "stranger"))
    return out


# ---------------------------------------------------------------------------
# 4. state_change_without_event (SYS-005 slice (a))
# ---------------------------------------------------------------------------

_EVENT_DEF_RE = re.compile(r"\bevent\s+[A-Za-z_]\w*\s*\(")
_SETTER_PREFIX_RE = re.compile(r"^(set|update|change)", re.I)


def _analyze_no_event(src: str, spec: DetectorSpec,
                      compiler: str = "",
                      contract_name: str = ""
                      ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    if not _EVENT_DEF_RE.search(scope.scoped_text):
        return []
    decls = _decls(scope.scoped_text)
    state = {d["name"] for d in decls}
    if not state:
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] == "constructor" or _is_view(fn):
            continue
        if not re.search(r"\b(public|external)\b",
                         fn["signature"]):
            continue
        text = fn["text"]
        if re.search(r"\bemit\s+[A-Za-z_]\w*\s*\(", text):
            continue
        writes = cl._state_writes(text, state)
        extra = bool(re.search(
            r"\b(" + "|".join(re.escape(s) for s in state) +
            r")\s*\.\s*(push|pop)\s*\(", text)) if state \
            else False
        if not writes and not extra:
            continue
        setter_shaped = bool(_SETTER_PREFIX_RE.match(fn["name"]))
        if not setter_shaped:
            # "Body primarily assigns state vars": at least one
            # state write and no external value call - the body
            # exists to mutate state, not to move value.
            if re.search(r"\.(call|transfer|send)\s*[\s({]|"
                         r"delegatecall\s*\(", text):
                continue
            setter_shaped = True
        if not setter_shaped:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' writes state "
            f"({sorted({v for _p, v in writes})}) with no "
            f"emit, in a contract that defines events.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "contract defines events but this setter "
                    "emits none; the write is invisible "
                    "off-chain")
        out.append(_finish(
            spec, item, text,
            "an unlogged state change hands no value to a "
            "stranger"))
        if len(out) >= 3:
            break
    return out[:3]


# ---------------------------------------------------------------------------
# 5. private_sensitive_state_var (SYS-006 slice)
# ---------------------------------------------------------------------------

_SENSITIVE_NAME_RE = re.compile(
    r"secret|password|passwd|api_?key|private_?key|seed|"
    r"mnemonic|credential", re.I)


def _analyze_private_sensitive(src: str, spec: DetectorSpec,
                               compiler: str = "",
                               contract_name: str = ""
                               ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for d in _decls(scope.scoped_text):
        if "private" not in d["visibility"]:
            continue
        if not _SENSITIVE_NAME_RE.search(d["name"]):
            continue
        detail = spec.detail + (
            f" Observed: {d['type']} variable '{d['name']}' "
            f"is declared private with a sensitive name; its "
            f"storage slot is world-readable on-chain.")
        item = _hit(spec, d["name"],
                    cc._snip(scope.scoped_text[d["pos"]:]),
                    detail,
                    "declared private, but storage is public: "
                    "no access control protects an on-chain "
                    "value from being read")
        out.append(_finish(
            spec, item, "",
            "the exposure is a read, not a value transfer to "
            "a recipient"))
    return out


# ---------------------------------------------------------------------------
# 6. assembly_fmp_literal_corruption (SYS-007 precision slice)
# ---------------------------------------------------------------------------

_FMP_LITERAL_RE = re.compile(
    r"mstore\s*\(\s*0x40\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)")


def _analyze_fmp_literal(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if "assembly" not in text:
            continue
        bad: Optional[str] = None
        for m in _FMP_LITERAL_RE.finditer(text):
            lit = m.group(1)
            val = int(lit, 16) if lit.lower().startswith("0x") \
                else int(lit)
            if val == 0 or val < 0x80:
                bad = lit
                break
        if bad is None:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' executes "
            f"mstore(0x40, {bad}) in inline assembly.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "literal below 0x80 stored to the "
                    "free-memory pointer; computed allocation "
                    "updates do not fire")
        out.append(_finish(
            spec, item, text,
            "memory corruption hands no value to a stranger"))
    return out


# ---------------------------------------------------------------------------
# 7. assembly_returndatacopy_unbounded (SYS-008)
# ---------------------------------------------------------------------------

def _analyze_returndatacopy(src: str, spec: DetectorSpec,
                            compiler: str = "",
                            contract_name: str = ""
                            ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if "assembly" not in text:
            continue
        if "returndatacopy(" not in text.replace(" ", "") \
                and not re.search(r"returndatacopy\s*\(", text):
            continue
        if re.search(r"returndatasize\s*\(\s*\)", text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' uses returndatacopy() "
            f"in inline assembly and never consults "
            f"returndatasize() anywhere in the function.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "no returndatasize() consultation in the "
                    "enclosing function; the copy is unsized")
        out.append(_finish(
            spec, item, text,
            "an unsized copy hands no value to a stranger"))
    return out


# ---------------------------------------------------------------------------
# 8. coinbase_decision_input (SYS-009)
# ---------------------------------------------------------------------------

_DIRECT_PAY_RE = re.compile(
    r"[^;{}]*block\.coinbase[^;{}]*"
    r"(?:\.transfer\s*\(|\.send\s*\(|payable\s*\([^)]*\)\s*\."
    r"(?:transfer|send)\s*\()", re.S)
_SELECTION_NAME_RE = re.compile(
    r"winner|payee|recipient|selected|chosen", re.I)
_HASH_FN_RE = re.compile(r"\b(?:keccak256|sha256|ripemd160)\s*\(")


def _coinbase_reason(text: str,
                     state: set) -> Optional[str]:
    cleaned = _DIRECT_PAY_RE.sub("", text)
    if "block.coinbase" not in cleaned:
        return None
    for cond in _conditions(cleaned):
        if "block.coinbase" in cond:
            return "block.coinbase inside a condition"
    for m in _HASH_FN_RE.finditer(cleaned):
        inner, _ = _balanced(cleaned, m.end() - 1)
        if "block.coinbase" in inner:
            return "block.coinbase as a hash input"
    for m in re.finditer(
            r"([A-Za-z_]\w*)\s*=(?!=)\s*[^;]*block\.coinbase",
            cleaned):
        name = m.group(1)
        if _SELECTION_NAME_RE.search(name):
            return (f"block.coinbase assigned into selection "
                    f"variable '{name}'")
        if name in state and not re.search(
                r"coinbase|payee", name, re.I):
            return (f"block.coinbase assigned into non-payee "
                    f"state variable '{name}'")
    if _SELECTION_NAME_RE.search(cleaned) and \
            "block.coinbase" in cleaned:
        return "block.coinbase in a payee/winner selection"
    return None


def _analyze_coinbase(src: str, spec: DetectorSpec,
                      compiler: str = "",
                      contract_name: str = ""
                      ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    state = {d["name"] for d in _decls(scope.scoped_text)}
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if "block.coinbase" not in fn["text"]:
            continue
        reason = _coinbase_reason(fn["text"], state)
        if not reason:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}': {reason}.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "block.coinbase feeds decision logic; the "
                    "direct tip shape (paying coinbase) does "
                    "not fire")
        out.append(_finish(
            spec, item, fn["text"],
            "miner-influenceable logic hands no value to a "
            "stranger"))
    return out


ANALYZERS = {
    "growable_array_loop_no_pagination": _analyze_growable_loop,
    "block_number_as_time": _analyze_block_time,
    "hardcoded_zero_role_address": _analyze_zero_role,
    "state_change_without_event": _analyze_no_event,
    "private_sensitive_state_var": _analyze_private_sensitive,
    "assembly_fmp_literal_corruption": _analyze_fmp_literal,
    "assembly_returndatacopy_unbounded": _analyze_returndatacopy,
    "coinbase_decision_input": _analyze_coinbase,
}


def analyze_deep9_source(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    """Run ONE batch-9 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors batch 4)
# ---------------------------------------------------------------------------

class DeepAudit9Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 9)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = ""
    phase = 2
    timeout_s = 120
    _spec: Optional[DetectorSpec] = None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        spec = self._spec
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        work = self._collect(target, ctx)
        if not work or spec is None:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed, e.g. bsc:0x...) "
                "or a web target whose pages reference one")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        analyzed = 0
        no_source = 0
        pairs_done = 0
        for chain_hint, addr in work:
            if pairs_done >= MAX_CHAIN_PAIRS:
                break
            try:
                pairs, got = await self._scan_address(
                    ctx, key, chain_hint, addr, findings)
            except Exception:
                pairs, got = 0, False
            pairs_done += pairs
            if pairs:
                analyzed += 1
                if not got:
                    no_source += 1
        dur = int((time.monotonic() - t0) * 1000)
        hits = sum(1 for f in findings if f.key == spec.id)
        res = self._ok(
            findings,
            f"{spec.id}: analyzed {analyzed} contract address(es) "
            f"({no_source} without verified source - skipped, no "
            f"guess made), {hits} finding(s)")
        res.duration_ms = dur
        return res

    def _collect(self, target: Target,
                 ctx: Ctx) -> List[Tuple[Optional[str], str]]:
        out: List[Tuple[Optional[str], str]] = []
        seen = set()

        def add(chain_hint: Optional[str], addr: str) -> None:
            addr = (addr or "").strip()
            if not cc.ADDRESS_RE.match(addr):
                return
            if addr.lower() == cc.ZERO_ADDRESS:
                return
            k = addr.lower()
            if k in seen:
                return
            seen.add(k)
            out.append((chain_hint, addr))

        for raw in (target.normalized, target.raw):
            chain_hint, addr = cc.parse_target_address(raw or "")
            if addr:
                add(chain_hint, addr)
                break
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else \
                    str(item.get("address", ""))
                add(None, a)
        for item in ctx.consume("chain_contracts"):
            if isinstance(item, dict):
                hint = item.get("chain")
                add(hint if isinstance(hint, str) and
                    hint in cc.CHAINS else None,
                    str(item.get("address", "")))
        return out[:MAX_ADDRESSES]

    async def _scan_address(self, ctx: Ctx, key: Optional[str],
                            chain_hint: Optional[str], addr: str,
                            findings: List[Finding]
                            ) -> Tuple[int, bool]:
        if chain_hint:
            chain_ids = [chain_hint]
        else:
            chain_ids = list(cc.DEFAULT_CHAIN_ORDER)
        pairs = 0
        got_source = False
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS[cid]
            code = await cc.rpc_get_code(ctx, chain, addr)
            if code is None or code == "0x" or len(code) < 4:
                continue
            pairs += 1
            if await self._scan_on_chain(ctx, key, chain, addr,
                                         code, findings):
                got_source = True
            if chain_hint:
                break
        return pairs, got_source

    async def _scan_on_chain(self, ctx: Ctx, key: Optional[str],
                             chain: cc.ChainConfig, addr: str,
                             code_hex: str,
                             findings: List[Finding]) -> bool:
        src = await cc.fetch_verified_source(ctx, chain, addr, key)
        res = {"implementation": "", "via": "", "beacon": ""}
        try:
            res = await cc.resolve_implementation(
                ctx, chain, addr, code_hex,
                {"implementation": (src or {}).get(
                    "implementation", "")})
        except Exception:
            pass
        impl = res.get("implementation") or ""
        role = "proxy_shell" if impl else "standalone"
        got = self._analyze_contract(chain, addr, src, findings,
                                     role=role, impl_addr=impl)
        if not impl:
            return got
        impl_code = None
        impl_src = None
        try:
            impl_code = await cc.rpc_get_code(ctx, chain, impl)
            impl_src = await cc.fetch_verified_source(
                ctx, chain, impl, key)
        except Exception:
            impl_code, impl_src = None, None
        if not impl_code or impl_code == "0x" or len(impl_code) < 4:
            return got
        return self._analyze_contract(
            chain, impl, impl_src, findings,
            role="implementation", proxy_addr=addr) or got

    def _analyze_contract(self, chain: cc.ChainConfig, addr: str,
                          src: Optional[Dict[str, Any]],
                          findings: List[Finding], role: str,
                          proxy_addr: str = "",
                          impl_addr: str = "") -> bool:
        spec = self._spec
        if spec is None or not src:
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
        for item in analyze_deep9_source(
                src["source"], spec, src.get("compiler", ""),
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
            })
            if item.get("report_class"):
                ev["report_class"] = item["report_class"]
                ev["recipient"] = item.get("recipient", "")
            if item.get("gate_analysis"):
                ev["gate_analysis"] = item["gate_analysis"]
            fn_txt = f"function '{item['function']}' " \
                if item["function"] else ""
            findings.append(self._f(
                "web3", spec.id,
                f"{item['severity'].upper()}: {spec.label}: "
                f"{fn_txt}in contract {addr} on {chain.name}{tag}"
                f"\n\n{item['detail']}\n\nCode:\n{item['code']}",
                source="deep audit detector batch 9 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit9Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 9) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
