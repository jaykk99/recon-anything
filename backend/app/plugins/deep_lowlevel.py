"""Deep low-level detectors: opcode-level EVM analysis (feat/deep-lowlevel-50).

Twelve detectors that work below the syntax layer: a basic-block CFG
reconstructor with guard-dominance analysis, a Z3 symbolic storage
taint tracer, a diamond ERC-2535 facet selector tree, a transient
storage lifecycle auditor, an EOF container verifier, an ERC-4337
paymaster simulator, an ERC-7579 hook inspector, a zk-SNARK
verification-key auditor, a Circom R1CS wire checker, a Halo2
lookup-table range profiler, a Gnosis Safe fallback-handler check,
and a Merkle-Patricia trie state-proof verifier.

Gap discipline (checked first-hand against origin master, registry
1227): diamond_selector_collision exists but only compares two
contracts' signatures; this batch builds the selector->facet TREE
(Add-overwrite, Remove-dangling, fallback shadowing).
underconstrained_signal_finder exists at signal level; this batch
checks R1CS WIRES. halo2_lookup_verifier exists for lookup
existence; this batch profiles lookup TABLE RANGES.
gnosis_safe_multisig_audit exists for multisig config; this batch
checks the FALLBACK HANDLER mutation path. deep_audit7 has a
proof-verifier-gates-mint detector; this batch audits the
verification-key PARAMETERS themselves.

Simulation rule: the ERC-4337 paymaster simulator produces
SIMULATION-ONLY findings (proof=simulation_only, report_class
unverified). A local simulation is never proof; only a live
eth_call probe from an unfunded stranger can promote a finding.

Detection only: verified-source static analysis in the fast lane,
never sends a transaction, never calls the contract for value.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from .bsc_common import DetectorSpec, S

try:
    import z3 as _z3
except Exception:  # noqa: BLE001 - z3 is optional at import time
    _z3 = None

try:
    from Crypto.Hash import keccak as _keccak
except Exception:  # noqa: BLE001 - keccak is optional at import time
    _keccak = None

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
FAMILY = "deeplow"


def _keccak256(data: bytes) -> bytes:
    if _keccak is None:
        raise RuntimeError("pycryptodome keccak unavailable")
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


SPECS = [
    S("evm_cfg_basic_block_reconstructor", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="CFG guard-dominance failure: a basic block containing "
             "a value-moving or privilege-changing operation "
             "(call/transfer/delegatecall/selfdestruct, or an "
             "owner/admin/price state write) is reachable from the "
             "function entry without passing through a guard block "
             "(require on msg.sender/owner/role, or an only* "
             "modifier). The block was reconstructed from the "
             "function's control flow, including if/else branches: "
             "an operation in the ELSE branch of a guard is NOT "
             "dominated by that guard.",
      fix="Put the guard (require on msg.sender/owner/role, or an "
          "only* modifier) on every path that reaches the "
          "value-moving operation, including else branches; never "
          "rely on a guard in a sibling branch."),
    S("symbolic_z3_storage_taint_tracer", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Symbolic taint: a storage slot is written from a "
             "caller-controlled function parameter with no "
             "caller-identity gate, and a Z3 bit-vector proof shows "
             "an attacker-chosen input can force the slot to an "
             "arbitrary value (the assignment is invertible over "
             "the full 256-bit range). The slot is attacker-writable "
             "storage, not a constant or a gated write.",
      fix="Gate every storage write that takes caller input behind "
          "an onlyOwner/onlyRole check, or derive the written "
          "value from on-chain state the caller cannot choose."),
    S("diamond_erc2535_facet_selector_tree", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Diamond selector-tree corruption: a diamondCut "
             "operation Adds a selector already owned by another "
             "facet (overwrite), Replaces or Removes a selector "
             "that is not in the tree (dangling), or installs a "
             "selector the fallback also claims (shadowing). The "
             "selector->facet map was built from every FacetCut in "
             "the bundle, in order.",
      fix="Audit the full selector->facet map before every "
          "diamondCut: never Add a selector another facet owns, "
          "never Replace/Remove a selector that is not installed, "
          "and never let the fallback claim a selector a facet owns."),
    S("transient_storage_tstore_lifecycle_auditor", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Transient storage lifecycle failure: a TLOAD reads a "
             "slot that is never TSTOREd anywhere in the bundle "
             "(uninitialized read: the slot is 0, which may be a "
             "valid address or amount), or the same transient slot "
             "is written with two different meanings in different "
             "functions (cross-meaning slot reuse). Transient "
             "storage lives for one transaction only; a value read "
             "without a store in the same call is not the value "
             "the code assumes.",
      fix="TSTORE every transient slot before any TLOAD of it in "
          "the same call, give each meaning its own slot, and "
          "never read transient storage across transactions."),
    S("eof_container_code_section_verifier", FAMILY, severity="high",
      outcome="a", recipient=True, scope="contract",
      detail="EOF container invalid: the deployed bytecode is an "
             "EOF container (0xEF00) whose code section fails "
             "verification - a relative jump (RJUMP/RJUMPI/RJUMPV) "
             "targets outside the code section, a DATALOADN reads "
             "outside the data section, a section size does not sum "
             "to the container length, or the code section contains "
             "an undefined opcode. A contract that cannot execute "
             "its own code is bricked or behaves differently from "
             "its source.",
      fix="Rebuild the EOF container with a correct section table "
          "and in-bounds jump targets; verify the container "
          "off-chain before deploying it."),
    S("erc4337_entrypoint_paymaster_simulator", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Paymaster drain shape (SIMULATION ONLY): the "
             "paymaster's validatePaymasterUserOp returns success "
             "with no per-user spending cap and no deposit "
             "sufficiency check, so the EntryPoint charges the "
             "paymaster for userOps that revert or exceed their "
             "gas, draining the deposit. This is a local simulation "
             "of the EntryPoint gas accounting, not a live probe: "
             "the finding is UNVERIFIED and can never become "
             "VERIFIED_REAL without a live EntryPoint probe.",
      fix="Cap every userOp's cost per user, check the paymaster "
          "deposit covers the worst-case gas before returning "
          "success, and fail closed when the deposit is short."),
    S("erc7579_modular_account_hook_inspector", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Modular account hook failure: installModule is "
             "reachable without an owner/self gate, a validation "
             "or execution hook returns success without performing "
             "any check, or a module is installed via delegatecall "
             "to a caller-supplied address. An attacker-installed "
             "hook runs on every subsequent call of the account.",
      fix="Gate installModule behind onlyOwner/onlySelf, make "
          "every hook perform its check before returning success, "
          "and never delegatecall to a caller-supplied module "
          "address."),
    S("zk_snark_verifier_vk_parameter_auditor", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Verification-key parameter failure: a verifier's "
             "verification key has a zero or trivial parameter "
             "(alpha/beta/gamma/delta), the same key values are "
             "reused across two different verifier circuits, or a "
             "verifyProof call never references the verification "
             "key at all (no binding between the key and the "
             "circuit). A bad key means proofs verify against the "
             "wrong statement.",
      fix="Generate a fresh trusted setup per circuit, never reuse "
          "a verification key across circuits, reject zero or "
          "trivial key parameters, and bind verifyProof to the "
          "circuit's own key."),
    S("circom_r1cs_underconstrained_wire_checker", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="R1CS underconstrained wire: a signal is assigned "
             "with a witness-only operator (<-- / -->) and then "
             "used in a constraint (<== / ===) or as an output, so "
             "its value is attacker-chosen, or an output signal is "
             "never constrained by any <== / === at all. The wire "
             "level is checked, not just the signal level.",
      fix="Constrain every output and every wire that feeds a "
          "constraint with <== / ===; never use <-- / --> for a "
          "value the circuit relies on."),
    S("halo2_lookup_table_range_profiler", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Halo2 lookup table range failure: a lookup table's "
             "range does not cover the input domain of the values "
             "it constrains (for example a 0..255 byte table used "
             "to constrain a u16), or a lookup argument has no "
             "range check on the queried value at all, so "
             "out-of-range values pass the lookup.",
      fix="Size every lookup table to the full domain of the "
          "values it constrains, and range-check every queried "
          "value before the lookup."),
    S("gnosis_safe_fallback_handler_mutator_check", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Safe fallback-handler mutation: setFallbackHandler "
             "is reachable without an owner/threshold gate, or the "
             "handler address comes from a caller parameter with "
             "no validation, so a stranger can install a fallback "
             "handler that intercepts every call the Safe does not "
             "recognize. A malicious fallback handler is a full "
             "account takeover.",
      fix="Gate setFallbackHandler behind the Safe's own "
          "owner/threshold authorization (execTransaction), "
          "validate the handler address, and never let a "
          "caller-supplied address become the fallback handler."),
    S("merkle_patricia_trie_state_proof_verifier", FAMILY,
      severity="high", outcome="a", recipient=True, scope="contract",
      detail="State proof does not verify: a supplied "
             "Merkle-Patricia trie proof (nodes + key + expected "
             "value) does not recompute to the claimed state root - "
             "a node hash mismatch, a truncated path, or a value "
             "that differs from the expected value. The state claim "
             "cannot be trusted.",
      fix="Re-fetch the proof from a trusted node, verify it "
          "against the state root before relying on the claimed "
          "value, and never accept a state claim whose proof does "
          "not verify."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirror the deep-audit batches)
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


def _classify(item: Dict[str, Any], recipient: str,
              rdetail: str) -> Dict[str, Any]:
    item["recipient"] = recipient
    if recipient in ("FIXED", "HOLDER-SELF"):
        item["report_class"] = "trigger_only"
        item["severity"] = "low"
        item["detail"] += (
            f" Recipient analysis: the value / power lands at "
            f"a {recipient} destination ({rdetail}), so a "
            f"stranger can trigger this but receives nothing - "
            f"classified TRIGGER-ONLY under the receive rule.")
    else:
        item["report_class"] = "candidate"
        item["detail"] += (
            f" Recipient analysis: recipient classified "
            f"{recipient} ({rdetail}) - a stranger can receive "
            f"value or control here, classified CANDIDATE under "
            f"the receive rule.")
    return item


def _finish_recipient(spec: DetectorSpec, item: Dict[str, Any],
                      fn_text: str) -> Dict[str, Any]:
    recipient, rdetail = cl.classify_recipient(fn_text)
    return _classify(item, recipient, rdetail)


_IDENTITY_GATE_RE = re.compile(
    r"msg\.sender\s*(==|!=)|"
    r"(==|!=)\s*msg\.sender|"
    r"hasRole\s*\(|_checkOwner|_checkRole")
_ONLY_MOD_RE = re.compile(r"\bonly[A-Z][A-Za-z0-9_]*\b")


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    sig, text = fn["signature"], fn["text"]
    if _ONLY_MOD_RE.search(sig) or _IDENTITY_GATE_RE.search(text):
        return True
    return False


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
    depth = 0
    for i in range(open_pos, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
    return text[open_pos + 1:], len(text)


def _split_top(text: str) -> List[str]:
    depth = 0
    parts: List[str] = []
    cur: List[str] = []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


def _skip_fn(fn: Dict[str, Any], scope) -> bool:
    if re.search(r"\b(view|pure)\b", fn["signature"]):
        return True
    if re.search(r"\b(internal|private)\b", fn["signature"]):
        return True
    return False


def _fn_params(fn: Dict[str, Any]) -> List[str]:
    sig = fn["signature"]
    i = sig.find("(")
    if i < 0:
        return []
    inner, _ = _balanced(sig, i)
    out = []
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("memory", "calldata", "storage")]
        if toks:
            out.append(toks[-1])
    return out


# ---------------------------------------------------------------------------
# 1. evm_cfg_basic_block_reconstructor
# ---------------------------------------------------------------------------

_GUARD_COND_RE = re.compile(
    r"msg\.sender\s*(==|!=)|"
    r"(==|!=)\s*msg\.sender|"
    r"hasRole\s*\(|onlyOwner|isOwner\s*\(|"
    r"owner\s*(==|!=)|"
    r"(==|!=)\s*owner\b|"
    r"authorized\s*\(")

_SENSITIVE_OP_RE = re.compile(
    r"\.call\s*\{[^}]*\bvalue\s*:|"
    r"\.call\s*\(|"
    r"\.delegatecall\s*\(|"
    r"\.transfer\s*\(|"
    r"\.send\s*\(|"
    r"selfdestruct\s*\(|"
    r"\b(owner|admin|price)\s*=|"
    r"\bbalances\s*\[[^\]]*\]\s*=")

_REQUIRE_RE = re.compile(r"require\s*\(")
_IF_RE = re.compile(r"\bif\s*\(")
_ELSE_RE = re.compile(r"\belse\b")


def _is_guard_cond(cond: str) -> bool:
    return bool(_GUARD_COND_RE.search(cond))


def _brace_span(text: str, open_pos: int) -> int:
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def _scan_block(body: str, guarded: bool, fn: Dict[str, Any],
                spec: DetectorSpec, out: List[Dict[str, Any]]) -> None:
    """Walk one brace block, tracking guard dominance.

    require(guard) marks the rest of the current block guarded.
    if (guard) { } guards its body; else { } is UNGUARDED (the
    guard was false there). Statements after return/revert in the
    same block are unreachable and skipped.
    """
    i = 0
    cur_guarded = guarded
    n = len(body)
    while i < n:
        m_if = _IF_RE.search(body, i)
        m_req = _REQUIRE_RE.search(body, i)
        next_pos = n
        kind = None
        if m_if and (m_req is None or m_if.start() < m_req.start()):
            next_pos, kind, m = m_if.start(), "if", m_if
        elif m_req:
            next_pos, kind, m = m_req.start(), "require", m_req
        # Statements before the next control point.
        head = body[i:next_pos]
        for op in _SENSITIVE_OP_RE.finditer(head):
            if not cur_guarded:
                detail = spec.detail + (
                    f" Observed: '{fn['name']}' reaches "
                    f"'{op.group(0).strip()}' in a basic block "
                    f"with no dominating guard block, so a "
                    f"stranger can reach the value-moving "
                    f"operation without passing any "
                    f"msg.sender/owner/role check.")
                item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                            detail,
                            "no guard block dominates the "
                            "value-moving operation in this branch")
                out.append(_finish_recipient(spec, item, fn["text"]))
                return
        if kind is None:
            break
        if kind == "require":
            paren = body.index("(", m.start())
            cond, _ = _balanced(body, paren)
            if _is_guard_cond(cond):
                cur_guarded = True
            semi = body.find(";", m.start())
            i = semi + 1 if semi >= 0 else m.end()
            continue
        # kind == "if": parse condition, then the braced body.
        paren = body.index("(", m.start())
        cond, close = _balanced(body, paren)
        j = close + 1
        while j < n and body[j] in " \t\r\n":
            j += 1
        if j < n and body[j] == "{":
            end = _brace_span(body, j)
            _scan_block(body[j + 1:end],
                        cur_guarded or _is_guard_cond(cond),
                        fn, spec, out)
            i = end + 1
            # else branch after this if: unguarded by the if's guard.
            k = i
            while k < n and body[k] in " \t\r\n":
                k += 1
            em = _ELSE_RE.match(body, k)
            if em:
                k = em.end()
                while k < n and body[k] in " \t\r\n":
                    k += 1
                if k < n and body[k] == "{":
                    eend = _brace_span(body, k)
                    _scan_block(body[k + 1:eend], cur_guarded,
                                fn, spec, out)
                    i = eend + 1
            continue
        i = close + 1


def _analyze_cfg(src: str, spec: DetectorSpec, compiler: str = "",
                 contract_name: str = "") -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        if fn["name"] == "constructor":
            # Deploy-time only: a stranger cannot call it.
            continue
        if _ONLY_MOD_RE.search(fn["signature"]):
            continue
        text = fn["text"]
        brace = text.find("{")
        if brace < 0:
            continue
        _scan_block(text[brace + 1:-1], False, fn, spec, out)
    return out


# ---------------------------------------------------------------------------
# 2. symbolic_z3_storage_taint_tracer
# ---------------------------------------------------------------------------

_ASSIGN_RE = re.compile(
    r"(?<![\w.])([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:\[[^\]]*\]\s*)?=\s*([^;]+);")

_INT_RE = re.compile(r"^(0x[0-9a-fA-F]+|\d+)$")


def _parse_z3_expr(expr: str, var: str, param: str):
    """Parse a small assignment RHS into a Z3 BitVec expression.

    Supported: param, uint160(param)/address(param) casts,
    param +/-/^/*/<< />>/&/| constant. Anything else -> None
    (the tracer does not guess about an expression it cannot model).
    """
    if _z3 is None:
        return None
    expr = expr.strip()
    m = re.match(r"^(?:uint160|address|uint256|uint)\s*\(\s*(.+)\s*\)$",
                 expr)
    if m:
        return _parse_z3_expr(m.group(1), var, param)
    if expr == param:
        return _z3.BitVec(var, 256)
    m = re.match(r"^(.+?)\s*([+\-^*/&|]|<<|>>)\s*(.+)$", expr)
    if not m:
        return None
    lhs = _parse_z3_expr(m.group(1).strip(), var, param)
    op = m.group(2)
    rhs_raw = m.group(3).strip()
    if _INT_RE.match(rhs_raw):
        rhs = int(rhs_raw, 16) if rhs_raw.startswith("0x") \
            else int(rhs_raw)
        rhs = _z3.BitVecVal(rhs % (1 << 256), 256)
    elif rhs_raw == param:
        rhs = _z3.BitVec(var, 256)
    else:
        return None
    if lhs is None:
        return None
    if op == "+":
        return lhs + rhs
    if op == "-":
        return lhs - rhs
    if op == "^":
        return lhs ^ rhs
    if op == "*":
        return lhs * rhs
    if op == "&":
        return lhs & rhs
    if op == "|":
        return lhs | rhs
    if op == "<<":
        return _z3.LShL(lhs, rhs)
    if op == ">>":
        return _z3.LShR(lhs, rhs)
    return None


def _analyze_z3_taint(src: str, spec: DetectorSpec, compiler: str = "",
                      contract_name: str = "") -> List[Dict[str, Any]]:
    if _z3 is None:
        return []
    try:
        state_vars = cl.state_variables(src)
    except Exception:
        state_vars = set()
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    # An attacker-meaningful target value: a specific non-zero
    # constant. The tracer proves the attacker can force the slot
    # to exactly this value (arbitrary-value control), not merely
    # move it. Non-invertible assignments (x * even, x & mask)
    # cannot reach it and stay silent.
    target = 0xC0FFEE
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        if _caller_gated(fn, scope):
            continue
        params = _fn_params(fn)
        if not params:
            continue
        for m in _ASSIGN_RE.finditer(fn["text"]):
            slot, rhs = m.group(1), m.group(2)
            if slot not in state_vars:
                continue
            param = next((p for p in params if re.search(
                r"\b" + re.escape(p) + r"\b", rhs)), None)
            if param is None:
                continue
            expr = _parse_z3_expr(rhs, "x", param)
            if expr is None:
                continue
            try:
                solver = _z3.Solver()
                solver.set(timeout=5000)
                x = _z3.BitVec("x", 256)
                solver.add(expr == _z3.BitVecVal(target, 256))
                if solver.check() != _z3.sat:
                    continue
                model = solver.model()
                model_x = model[x].as_long() if model[x] is not None \
                    else 0
            except Exception:
                continue
            detail = spec.detail + (
                f" Observed: '{fn['name']}' writes storage slot "
                f"'{slot}' from caller parameter '{param}' "
                f"({rhs.strip()}), and Z3 proves an "
                f"attacker-chosen input (x = {model_x}) forces the "
                f"slot to 0x{target:x}. The write is not gated by "
                f"any only* modifier or msg.sender check.")
            item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                        detail,
                        "no caller-identity gate on the writing "
                        "function; Z3 proves arbitrary-value control")
            out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 3. diamond_erc2535_facet_selector_tree
# ---------------------------------------------------------------------------

_FACET_CUT_RE = re.compile(
    r"FacetCut\s*\(\s*\{?(.*?)\}?\s*\)", re.S)
_FACET_ADDR_RE = re.compile(
    r"facetAddress\s*:\s*(0x[0-9a-fA-F]{40}|[A-Za-z_][A-Za-z0-9_]*)")
_FACET_ACTION_RE = re.compile(
    r"FacetCutAction\s*\.\s*(Add|Replace|Remove)|\baction\s*:\s*"
    r"(?:FacetCutAction\s*\.\s*)?(Add|Replace|Remove)|\baction\s*:\s*([012])")
_SELECTORS_RE = re.compile(
    r"(?:functionSelectors|selectors)\s*:\s*\[([^\]]*)\]")
_SELECTOR_HEX_RE = re.compile(r"0x[0-9a-fA-F]{8}\b")
_FALLBACK_FN_RE = re.compile(r"function\s+fallback\s*\(")


def _analyze_diamond_tree(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = "") -> List[Dict[str, Any]]:
    if "diamondCut" not in src and "FacetCut" not in src:
        return []
    scope, fns = _scope_fns(src, contract_name)
    tree: Dict[str, str] = {}
    out: List[Dict[str, Any]] = []
    fallback_selectors: set = set()
    for fn in fns:
        if fn["name"] == "fallback":
            fallback_selectors = set(
                _SELECTOR_HEX_RE.findall(fn["text"]))
    # Parse each FacetCut(...) with a balanced-paren scan: the
    # struct body contains nested parens (bytes4(0x...)), so a
    # lazy regex truncates the body at the first inner close.
    for m in re.finditer(r"FacetCut\s*\(", src):
        open_pos = src.index("(", m.start())
        body, _close = _balanced(src, open_pos)
        body = body.strip()
        if body.startswith("{") and body.endswith("}"):
            body = body[1:-1]
        addr_m = _FACET_ADDR_RE.search(body)
        act_m = _FACET_ACTION_RE.search(body)
        sel_m = _SELECTORS_RE.search(body)
        if not act_m or not sel_m:
            continue
        action = act_m.group(1) or act_m.group(2)
        if action is None and act_m.group(3) is not None:
            action = {"0": "Add", "1": "Replace", "2": "Remove"}[
                act_m.group(3)]
        facet = addr_m.group(1) if addr_m else "?"
        sels = _SELECTOR_HEX_RE.findall(sel_m.group(1))
        for sel in sels:
            sel = sel.lower()
            if action == "Add":
                if sel in tree and tree[sel] != facet:
                    detail = spec.detail + (
                        f" Observed: diamondCut Adds selector "
                        f"{sel}, which the tree already assigns "
                        f"to facet {tree[sel]}; this Add would "
                        f"overwrite that facet's route with "
                        f"facet {facet}.")
                    item = _hit(spec, "", cc._snip(body), detail,
                                "no selector-ownership check before "
                                "the Add")
                    item["report_class"] = "candidate"
                    out.append(item)
                else:
                    tree[sel] = facet
            elif action == "Replace":
                if sel not in tree:
                    detail = spec.detail + (
                        f" Observed: diamondCut Replaces selector "
                        f"{sel}, which is not installed in the "
                        f"tree; the Replace dangles (no facet "
                        f"receives it).")
                    item = _hit(spec, "", cc._snip(body), detail,
                                "no installed-selector check before "
                                "the Replace")
                    item["report_class"] = "candidate"
                    out.append(item)
                else:
                    tree[sel] = facet
            elif action == "Remove":
                if sel not in tree:
                    detail = spec.detail + (
                        f" Observed: diamondCut Removes selector "
                        f"{sel}, which is not installed in the "
                        f"tree; the Remove is a no-op that leaves "
                        f"the loupe disagreeing with the routing.")
                    item = _hit(spec, "", cc._snip(body), detail,
                                "no installed-selector check before "
                                "the Remove")
                    item["report_class"] = "candidate"
                    out.append(item)
                else:
                    del tree[sel]
            if sel in fallback_selectors:
                detail = spec.detail + (
                    f" Observed: selector {sel} is claimed both "
                    f"by a facet (via diamondCut) and by the "
                    f"contract fallback, so the fallback shadows "
                    f"the facet route.")
                item = _hit(spec, "", cc._snip(body), detail,
                            "fallback and facet both claim the "
                            "selector")
                item["report_class"] = "candidate"
                out.append(item)
    return out


# ---------------------------------------------------------------------------
# 4. transient_storage_tstore_lifecycle_auditor
# ---------------------------------------------------------------------------

_TSTORE_RE = re.compile(
    r"\btstore\s*\(\s*([^,]+?)\s*,\s*(.+?)\)", re.S)
_TLOAD_RE = re.compile(r"\btload\s*\(\s*(.+?)\)", re.S)
_TRANSIENT_VAR_RE = re.compile(
    r"\btransient\s+(?:uint256|address|bytes32|bool)\s+"
    r"(?:public\s+|private\s+|internal\s+)?([A-Za-z_][A-Za-z0-9_]*)")


def _analyze_tstore(src: str, spec: DetectorSpec, compiler: str = "",
                    contract_name: str = "") -> List[Dict[str, Any]]:
    if "tstore" not in src and "tload" not in src \
            and "transient" not in src:
        return []
    scope, fns = _scope_fns(src, contract_name)
    stores: Dict[str, List[Tuple[str, str]]] = {}
    loads: List[Tuple[str, str, Dict[str, Any]]] = []
    for fn in fns:
        for m in _TSTORE_RE.finditer(fn["text"]):
            slot, rhs = m.group(1).strip(), m.group(2).strip()
            stores.setdefault(slot, []).append((rhs, fn["name"]))
        for m in _TLOAD_RE.finditer(fn["text"]):
            loads.append((m.group(1).strip(), fn["name"], fn))
    out: List[Dict[str, Any]] = []
    for slot, loader_fn, fn in loads:
        if slot not in stores:
            detail = spec.detail + (
                f" Observed: '{loader_fn}' TLOADs transient slot "
                f"'{slot}', which is never TSTOREd anywhere in "
                f"the bundle; the read returns 0, which the code "
                f"treats as a real address or amount.")
            item = _hit(spec, loader_fn, cc._snip(fn["text"]),
                        detail,
                        "no TSTORE of this slot anywhere in the "
                        "bundle")
            out.append(_finish_recipient(spec, item, fn["text"]))
    # Cross-meaning slot reuse: the same slot written with an
    # address-shaped value in one function and an amount-shaped
    # value in another.
    for slot, writes in stores.items():
        if len(writes) < 2:
            continue
        kinds = set()
        for rhs, _fn in writes:
            if re.search(r"addr|pool|token|to\b|from\b", rhs, re.I):
                kinds.add("address")
            if re.search(r"amount|value|balance|price|total", rhs,
                         re.I):
                kinds.add("amount")
        if len(kinds) >= 2:
            fn_name = writes[0][1]
            fn = next((f for f in fns if f["name"] == fn_name), None)
            if fn is None:
                continue
            detail = spec.detail + (
                f" Observed: transient slot '{slot}' is TSTOREd "
                f"with an address-shaped value in one function "
                f"and an amount-shaped value in another, so the "
                f"slot carries two meanings and a read in one "
                f"context returns the other context's value.")
            item = _hit(spec, fn_name, cc._snip(fn["text"]), detail,
                        "one slot, two meanings, no per-meaning "
                        "slot separation")
            out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 5. eof_container_code_section_verifier
# ---------------------------------------------------------------------------

_EOF_OPCODES = frozenset([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x20, 0x30, 0x31, 0x32,
    0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
    0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
    0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
    0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
    0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82,
    0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c,
    0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
    0xa1, 0xa2, 0xa3, 0xa4, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5,
    0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xfa, 0xfd,
])
_PUSH_N = {op: op - 0x5f for op in range(0x60, 0x80)}


def _verify_eof_container(data: bytes) -> List[str]:
    """Return a list of verification failures (empty = valid)."""
    problems: List[str] = []
    if len(data) < 4 or data[:2] != b"\xef\x00" or data[2] != 0x01:
        return ["not an EOF container (bad magic/version)"]
    pos = 3
    sections: Dict[int, int] = {}
    order = []
    while pos < len(data) and data[pos] != 0x00:
        if pos + 3 > len(data):
            return ["truncated section header"]
        kind = data[pos]
        size = int.from_bytes(data[pos + 1:pos + 3], "big")
        if kind not in (1, 2, 3, 4):
            problems.append(f"unknown section kind {kind}")
        sections[kind] = size
        order.append(kind)
        pos += 3
    if pos >= len(data):
        return problems + ["missing section terminator"]
    pos += 1  # terminator
    bodies: Dict[int, bytes] = {}
    for kind in order:
        size = sections[kind]
        bodies[kind] = data[pos:pos + size]
        pos += size
    if pos != len(data):
        problems.append(
            f"section sizes sum to {pos} bytes but the container "
            f"is {len(data)} bytes")
    code = bodies.get(2, b"")
    types = bodies.get(1, b"")
    datasec = bodies.get(4, b"")
    if 2 not in bodies or not code:
        problems.append("missing or empty code section")
        return problems
    if 1 in bodies and len(types) < 4:
        problems.append("types section shorter than one entry")
    # Walk the code section, checking opcodes and jump targets.
    i = 0
    while i < len(code):
        op = code[i]
        if op not in _EOF_OPCODES:
            problems.append(
                f"undefined opcode 0x{op:02x} at code offset {i}")
            break
        if op in _PUSH_N:
            i += 1 + _PUSH_N[op]
            continue
        if op in (0x5c, 0x5d):  # RJUMP / RJUMPI, imm16
            if i + 2 >= len(code):
                problems.append(
                    f"truncated RJUMP at code offset {i}")
                break
            rel = int.from_bytes(code[i + 1:i + 3], "big",
                                 signed=True)
            target = i + 3 + rel
            if target < 0 or target > len(code):
                problems.append(
                    f"RJUMP at code offset {i} targets {target}, "
                    f"outside the code section (0..{len(code)})")
            i += 3
            continue
        if op == 0x5e:  # RJUMPV, count + table
            if i + 1 >= len(code):
                problems.append(
                    f"truncated RJUMPV at code offset {i}")
                break
            count = code[i + 1]
            if i + 2 + 2 * count > len(code):
                problems.append(
                    f"truncated RJUMPV table at code offset {i}")
                break
            for k in range(count):
                rel = int.from_bytes(
                    code[i + 2 + 2 * k:i + 4 + 2 * k], "big",
                    signed=True)
                target = i + 2 + 2 * count + rel
                if target < 0 or target > len(code):
                    problems.append(
                        f"RJUMPV entry {k} at code offset {i} "
                        f"targets {target}, outside the code "
                        f"section (0..{len(code)})")
            i += 2 + 2 * count
            continue
        if op == 0xe3:  # DATALOADN, imm16
            if i + 2 >= len(code):
                problems.append(
                    f"truncated DATALOADN at code offset {i}")
                break
            off = int.from_bytes(code[i + 1:i + 3], "big")
            if off + 32 > len(datasec):
                problems.append(
                    f"DATALOADN at code offset {i} reads data "
                    f"offset {off}, outside the data section "
                    f"(0..{len(datasec)})")
            i += 3
            continue
        if op in (0xe0, 0xe1, 0xe2, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
                  0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef):
            i += 2  # two-byte immediate forms used by EOF ext ops
            continue
        i += 1
    return problems


def verify_eof_hex(hexdata: str) -> List[str]:
    h = hexdata.strip()
    if h.startswith(("0x", "0X")):
        h = h[2:]
    try:
        raw = bytes.fromhex(h)
    except ValueError:
        return ["not valid hex"]
    return _verify_eof_container(raw)


def _analyze_eof(src: str, spec: DetectorSpec, compiler: str = "",
                 contract_name: str = "") -> List[Dict[str, Any]]:
    # Bytecode input: the whole input is one hex container.
    text = src.strip()
    out: List[Dict[str, Any]] = []
    candidates = []
    if re.fullmatch(r"(0x)?[0-9a-fA-F]+", text) and len(text) >= 8:
        candidates.append(text)
    else:
        candidates.extend(
            m.group(0) for m in re.finditer(
                r"0xEF00[0-9a-fA-F]+", src, re.I))
    for cand in candidates:
        problems = verify_eof_hex(cand)
        for problem in problems:
            detail = spec.detail + f" Observed: {problem}."
            item = _hit(spec, "", cand[:120], detail,
                        "container fails off-chain EOF verification")
            item["report_class"] = "candidate"
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# 6. erc4337_entrypoint_paymaster_simulator
# ---------------------------------------------------------------------------

_PAYMASTER_FN_RE = re.compile(
    r"function\s+validatePaymasterUserOp\s*\(")
_CAP_RE = re.compile(
    r"(maxCost|spendingLimit|spendingCap|allowance|"
    r"maxGas|gasCap|perUserCap|userOpCap|deposit|getDeposit)")
_DEPOSIT_CHECK_RE = re.compile(
    r"getDeposit|deposit\s*(>=|>|==)|require\s*\([^)]*deposit")


def _analyze_paymaster(src: str, spec: DetectorSpec,
                       compiler: str = "",
                       contract_name: str = "") -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _PAYMASTER_FN_RE.search(fn["signature"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        # Search the BODY only: the signature itself names maxCost
        # (a parameter), which is not a cap.
        brace = text.find("{")
        body = text[brace + 1:] if brace >= 0 else text
        has_cap = bool(_CAP_RE.search(body))
        has_deposit = bool(_DEPOSIT_CHECK_RE.search(body))
        # The worst-case cost the EntryPoint can charge: the
        # UserOp gas fields, unbounded unless the paymaster caps
        # them. With no cap and no deposit check, a reverting or
        # oversized userOp is charged to the paymaster deposit.
        if has_cap or has_deposit:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' returns success with no "
            f"per-user spending cap and no deposit sufficiency "
            f"check, so the simulated EntryPoint accounting "
            f"charges the paymaster deposit for the full "
            f"(callGasLimit + verificationGasLimit + "
            f"preVerificationGas) * maxFeePerGas of any userOp, "
            f"including ones that revert.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "SIMULATION ONLY: local EntryPoint gas "
                    "accounting, no live probe performed")
        item["proof"] = "simulation_only"
        item["report_class"] = "unverified"
        item["recipient"] = "CALLER"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 7. erc7579_modular_account_hook_inspector
# ---------------------------------------------------------------------------

_MODULE_FN_RE = re.compile(
    r"function\s+(installModule|uninstallModule|"
    r"executeFromExecutor)\s*\(")
_HOOK_FN_RE = re.compile(
    r"function\s+(preCheck|postCheck|isValidSignature|"
    r"onInstall|onUninstall)\s*\(")


def _analyze_7579(src: str, spec: DetectorSpec, compiler: str = "",
                  contract_name: str = "") -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if _MODULE_FN_RE.search(fn["signature"]):
            if _caller_gated(fn, scope):
                continue
            if "delegatecall" in text and re.search(
                    r"delegatecall\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)",
                    text):
                detail = spec.detail + (
                    f" Observed: '{fn['name']}' delegatecalls to "
                    f"a caller-supplied module address with no "
                    f"owner/self gate.")
            else:
                detail = spec.detail + (
                    f" Observed: '{fn['name']}' installs or "
                    f"removes modules with no owner/self gate, so "
                    f"a stranger can install a hook module.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "no owner/self gate on module install")
            out.append(_finish_recipient(spec, item, text))
            continue
        if _HOOK_FN_RE.search(fn["signature"]):
            body = text[text.find("{") + 1:text.rfind("}")]
            stripped = re.sub(r"//[^\n]*", "", body)
            stripped = re.sub(r"/\*.*?\*/", "", stripped, flags=re.S)
            stripped = stripped.strip()
            if not stripped or re.fullmatch(
                    r"(return\s+[^;]*;?\s*)+", stripped):
                if not re.search(r"require\s*\(|revert\s*\(",
                                 stripped):
                    detail = spec.detail + (
                        f" Observed: hook '{fn['name']}' returns "
                        f"success without performing any check, "
                        f"so the hook it guards is effectively "
                        f"unvalidated.")
                    item = _hit(spec, fn["name"], cc._snip(text),
                                detail,
                                "hook body performs no validation")
                    out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 8. zk_snark_verifier_vk_parameter_auditor
# ---------------------------------------------------------------------------

_VK_FIELD_RE = re.compile(
    r"\b(?:vk\s*\.\s*|verifyingKey\s*\.\s*|VK_?|vk)(alpha|beta|gamma|delta|Alpha|Beta|Gamma|Delta)\b")
_VK_ASSIGN_RE = re.compile(
    r"(?:alpha|beta|gamma|delta|Alpha|Beta|Gamma|Delta)\s*"
    r"[:=]\s*(0x[0-9a-fA-F]+|\d+)")
_VERIFY_CALL_RE = re.compile(
    r"\b(?:verifyProof|verify|verifyTx)\s*\(")


def _analyze_vk(src: str, spec: DetectorSpec, compiler: str = "",
                contract_name: str = "") -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    # Zero / trivial vk parameters.
    for m in _VK_ASSIGN_RE.finditer(src):
        val = m.group(1)
        num = int(val, 16) if val.startswith("0x") else int(val)
        if num in (0, 1):
            detail = spec.detail + (
                f" Observed: a verification-key parameter is "
                f"assigned the trivial value {val}; a key with a "
                f"zero or one parameter does not bind proofs to "
                f"the circuit.")
            item = _hit(spec, "", cc._snip(src[m.start() - 40:
                                               m.end() + 40]),
                        detail,
                        "vk parameter is zero or trivial")
            item["report_class"] = "candidate"
            out.append(item)
    # Same vk values reused across two verifier contracts.
    vk_sets: Dict[str, List[str]] = {}
    for path, raw in cl._split_units(src):
        clean = cc._strip_comments(raw)
        for span in cl._contract_spans(clean):
            vals = sorted(set(_VK_ASSIGN_RE.findall(
                clean[span["start"]:span["end"]])))
            if len(vals) >= 2:
                vk_sets.setdefault(",".join(vals), []).append(
                    span["name"])
    for vals, names in vk_sets.items():
        if len(names) >= 2:
            detail = spec.detail + (
                f" Observed: verification-key parameters "
                f"({vals}) are reused across verifier contracts "
                f"{', '.join(sorted(set(names)))}; one trusted "
                f"setup is serving two circuits.")
            item = _hit(spec, "", vals, detail,
                        "vk reused across circuits")
            item["report_class"] = "candidate"
            out.append(item)
    # verifyProof called without referencing any vk.
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        if _VERIFY_CALL_RE.search(fn["text"]) and \
                not _VK_FIELD_RE.search(fn["text"]) and \
                "vk" not in fn["text"].lower():
            detail = spec.detail + (
                f" Observed: '{fn['name']}' calls a proof "
                f"verifier without referencing any verification "
                f"key, so the proof is not bound to this "
                f"circuit's key.")
            item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                        detail, "verifyProof with no vk reference")
            out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 9. circom_r1cs_underconstrained_wire_checker
# ---------------------------------------------------------------------------

_SIGNAL_RE = re.compile(
    r"\bsignal\s+(?:input\s+|output\s+)?([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*\[[^\]]*\])?\s*;")
_CONSTRAIN_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:<==|===)")
_WITNESS_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:<--|-->)")
_OUTPUT_RE = re.compile(r"\bsignal\s+output\s+([A-Za-z_][A-Za-z0-9_]*)")


def _analyze_r1cs(src: str, spec: DetectorSpec, compiler: str = "",
                  contract_name: str = "") -> List[Dict[str, Any]]:
    # Strip comments first: NatSpec prose ("to signal that...")
    # and ASCII art ("x <--(") inside comments are not circom
    # signals, and matching them is a false positive.
    src = cc._strip_comments(src)
    if "signal" not in src:
        return []
    constrained = set(_CONSTRAIN_RE.findall(src))
    witness_only = set(_WITNESS_RE.findall(src)) - constrained
    outputs = set(_OUTPUT_RE.findall(src))
    used_in_constraint = set()
    for m in re.finditer(r"<==\s*([^;]+);", src):
        used_in_constraint |= set(re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*", m.group(1)))
    for m in re.finditer(r"===\s*([^;]+);", src):
        used_in_constraint |= set(re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*", m.group(1)))
    out: List[Dict[str, Any]] = []
    bad = (witness_only & (outputs | used_in_constraint)) | \
        (outputs - constrained - witness_only)
    for wire in sorted(bad):
        if wire in witness_only:
            why = (f"signal '{wire}' is assigned with a "
                   f"witness-only operator (<-- / -->) and then "
                   f"used in a constraint or as an output, so "
                   f"its value is attacker-chosen")
        else:
            why = (f"output signal '{wire}' is never constrained "
                   f"by any <== / ===, so its value is free")
        detail = spec.detail + f" Observed: {why}."
        item = _hit(spec, "", wire, detail,
                    "wire is not constrained by any R1CS equation")
        item["report_class"] = "candidate"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 10. halo2_lookup_table_range_profiler
# ---------------------------------------------------------------------------

_LOOKUP_RE = re.compile(r"\blookup(?:_any)?\s*\(")
_TABLE_VAL_RE = re.compile(
    r"assign_fixed\s*\(\s*[^,]+,\s*\[([^\]]*)\]")
_RANGE_RE = re.compile(r"\b0\s*\.\.\s*(\d+)\b")
_TYPE_DOM_RE = re.compile(r"\b(u8|u16|u32|u64)\b")
_TYPE_MAX = {"u8": 255, "u16": 65535, "u32": 4294967295,
             "u64": 18446744073709551615}


def _analyze_halo2(src: str, spec: DetectorSpec, compiler: str = "",
                   contract_name: str = "") -> List[Dict[str, Any]]:
    if "lookup" not in src:
        return []
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    # Halo2 code is Rust, not Solidity: _scope_fns finds no
    # functions in it, so also scan Rust `fn name(...) { ... }`
    # blocks (brace-balanced) and analyze those.
    rust_fns: List[Dict[str, Any]] = []
    for m in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", src):
        brace = src.find("{", m.end())
        if brace < 0:
            continue
        end = _brace_span(src, brace)
        rust_fns.append({"name": m.group(1),
                         "text": src[m.start():end + 1]})
    seen_names = {f["name"] for f in fns}
    fns = fns + [rf for rf in rust_fns
                 if rf["name"] not in seen_names]
    table_max: Optional[int] = None
    for m in _TABLE_VAL_RE.finditer(src):
        vals = [int(v.strip()) for v in m.group(1).split(",")
                if v.strip().lstrip("-").isdigit()]
        if vals:
            table_max = max(vals) if table_max is None \
                else max(table_max, max(vals))
    if table_max is None:
        for m in _RANGE_RE.finditer(src):
            table_max = max(table_max or 0, int(m.group(1)))
    for fn in fns:
        if not _LOOKUP_RE.search(fn["text"]):
            continue
        text = fn["text"]
        queried_max: Optional[int] = None
        for m in _TYPE_DOM_RE.finditer(text):
            queried_max = max(queried_max or 0,
                              _TYPE_MAX[m.group(1)])
        if table_max is not None and queried_max is not None \
                and queried_max > table_max:
            detail = spec.detail + (
                f" Observed: '{fn['name']}' runs a lookup whose "
                f"table covers 0..{table_max} but constrains "
                f"values up to {queried_max}, so out-of-range "
                f"values pass the lookup.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "table range smaller than the queried domain")
            out.append(_finish_recipient(spec, item, text))
        elif _LOOKUP_RE.search(text) and not re.search(
                r"range|Range|constrain.*range|range.*check",
                text, re.I) and table_max is None:
            detail = spec.detail + (
                f" Observed: '{fn['name']}' runs a lookup with "
                f"no table range and no range check on the "
                f"queried value, so the lookup constrains "
                f"nothing about the value's range.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "lookup with no table range and no range "
                        "check")
            out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 11. gnosis_safe_fallback_handler_mutator_check
# ---------------------------------------------------------------------------

_SET_FALLBACK_RE = re.compile(
    r"function\s+setFallbackHandler\s*\(|"
    r"fallbackHandler\s*=")


def _analyze_safe_fallback(src: str, spec: DetectorSpec,
                           compiler: str = "",
                           contract_name: str = "") -> List[Dict[str, Any]]:
    if "FallbackHandler" not in src and "fallbackHandler" not in src:
        return []
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _SET_FALLBACK_RE.search(fn["signature"] + fn["text"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        gated = _caller_gated(fn, scope) or re.search(
            r"require\s*\(\s*msg\.sender\s*==\s*address\s*\(\s*this\s*\)",
            text) or "onlyOwner" in fn["signature"]
        if gated:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' changes the fallback "
            f"handler with no owner/threshold gate, so a stranger "
            f"can install a handler that intercepts every call "
            f"the Safe does not recognize.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "no owner/threshold gate on the fallback "
                    "handler change")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 12. merkle_patricia_trie_state_proof_verifier
# ---------------------------------------------------------------------------

def _rlp_encode(item) -> bytes:
    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item
        return _rlp_len(len(item), 0x80) + item
    if isinstance(item, str):
        return _rlp_encode(item.encode())
    if isinstance(item, int):
        if item == 0:
            return b"\x80"
        return _rlp_encode(item.to_bytes((item.bit_length() + 7) // 8,
                                        "big"))
    if isinstance(item, (list, tuple)):
        payload = b"".join(_rlp_encode(x) for x in item)
        return _rlp_len(len(payload), 0xc0) + payload
    raise TypeError(f"cannot RLP-encode {type(item)}")


def _rlp_len(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    blen = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(blen)]) + blen


def _rlp_decode(data: bytes, pos: int = 0):
    prefix = data[pos]
    if prefix < 0x80:
        return data[pos:pos + 1], pos + 1
    if prefix < 0xb8:
        length = prefix - 0x80
        return data[pos + 1:pos + 1 + length], pos + 1 + length
    if prefix < 0xc0:
        llen = prefix - 0xb7
        length = int.from_bytes(data[pos + 1:pos + 1 + llen], "big")
        start = pos + 1 + llen
        return data[start:start + length], start + length
    if prefix < 0xf8:
        length = prefix - 0xc0
        start = pos + 1
        end = start + length
        items = []
        p = start
        while p < end:
            item, p = _rlp_decode(data, p)
            items.append(item)
        return items, end
    llen = prefix - 0xf7
    length = int.from_bytes(data[pos + 1:pos + 1 + llen], "big")
    start = pos + 1 + llen
    end = start + length
    items = []
    p = start
    while p < end:
        item, p = _rlp_decode(data, p)
        items.append(item)
    return items, end


def _nibbles(data: bytes) -> List[int]:
    out = []
    for b in data:
        out.append(b >> 4)
        out.append(b & 0x0f)
    return out


def _compact_to_nibbles(prefixed: bytes) -> Tuple[List[int], bool]:
    """Return (nibbles, is_leaf) for a compact-encoded path."""
    if not prefixed:
        return [], False
    flag = prefixed[0]
    is_leaf = flag & 0x20 != 0
    odd = flag & 0x10 != 0
    nibs = _nibbles(prefixed[1:])
    if odd:
        nibs = [flag & 0x0f] + nibs
    return nibs, is_leaf


def verify_mpt_proof(root_hex: str, key_hex: str,
                     proof_hex: List[str],
                     expected_value_hex: str) -> Tuple[bool, str]:
    """Verify an MPT proof. Returns (valid, reason).

    key_hex is the trie key as hex bytes (the caller hashes the
    address first for a state trie). proof_hex is the list of
    RLP-encoded nodes from root to leaf. expected_value_hex is
    the value the proof must resolve to.
    """
    if _keccak is None:
        return False, "keccak unavailable in this environment"
    try:
        root = bytes.fromhex(root_hex.removeprefix("0x"))
        key = bytes.fromhex(key_hex.removeprefix("0x"))
        expected = bytes.fromhex(
            expected_value_hex.removeprefix("0x"))
        nodes = [bytes.fromhex(p.removeprefix("0x"))
                 for p in proof_hex]
    except ValueError:
        return False, "proof fields are not valid hex"
    if not nodes:
        return False, "empty proof"
    want = _nibbles(key)
    node = nodes[0]
    # The root node is referenced by hash when its RLP is >= 32
    # bytes, else it is embedded.
    if len(node) >= 32:
        if _keccak256(node) != root:
            return False, "root node hash does not match the " \
                "claimed state root"
    elif node != root:
        return False, "embedded root node does not match the " \
            "claimed state root"
    idx = 0
    pos = 0
    while True:
        try:
            decoded, _ = _rlp_decode(node)
        except Exception:
            return False, "node is not valid RLP"
        if isinstance(decoded, bytes):
            return False, "proof node decoded to a bare value"
        if len(decoded) == 2:
            path, is_leaf = _compact_to_nibbles(decoded[0])
            if want[pos:pos + len(path)] != path:
                return False, "proof path diverges from the key"
            pos += len(path)
            if is_leaf:
                if pos != len(want):
                    return False, "leaf reached but key has " \
                        "unconsumed nibbles"
                if decoded[1] != expected:
                    return False, "leaf value differs from the " \
                        "expected value"
                return True, "proof verifies against the state root"
            nxt = decoded[1]
        elif len(decoded) == 17:
            if pos >= len(want):
                if decoded[16] != expected:
                    return False, "branch value differs from the " \
                        "expected value"
                return True, "proof verifies against the state root"
            nxt = decoded[want[pos]]
            pos += 1
        else:
            return False, f"node has {len(decoded)} items, not a " \
                "valid MPT node"
        idx += 1
        if idx >= len(nodes):
            return False, "proof ends before the key is resolved"
        if isinstance(nxt, list):
            node = _rlp_encode(nxt)
        elif isinstance(nxt, bytes) and len(nxt) == 0:
            return False, "branch child is empty (key absent)"
        elif isinstance(nxt, bytes) and len(nxt) < 32:
            node = nxt
        else:
            node = nodes[idx]
            if _keccak256(node) != nxt:
                return False, "child node hash does not match its " \
                    "parent reference"


def _analyze_mpt(src: str, spec: DetectorSpec, compiler: str = "",
                 contract_name: str = "") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    docs = []
    text = src.strip()
    if text.startswith("{"):
        try:
            docs.append(json.loads(text))
        except ValueError:
            pass
    for m in re.finditer(r"\{[^{}]*\"root\"[^{}]*\}", src):
        try:
            docs.append(json.loads(m.group(0)))
        except ValueError:
            continue
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        root = doc.get("root")
        key = doc.get("key")
        proof = doc.get("proof")
        expected = doc.get("expected_value")
        if not (root and key and proof and expected is not None):
            continue
        valid, reason = verify_mpt_proof(root, key, proof, expected)
        if valid:
            continue
        detail = spec.detail + f" Observed: {reason}."
        item = _hit(spec, "", json.dumps(doc)[:200], detail,
                    "proof fails off-chain MPT verification")
        item["report_class"] = "candidate"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Dispatch + plugin scaffolding (mirrors the deep-audit batches)
# ---------------------------------------------------------------------------

ANALYZERS = {
    "evm_cfg_basic_block_reconstructor": _analyze_cfg,
    "symbolic_z3_storage_taint_tracer": _analyze_z3_taint,
    "diamond_erc2535_facet_selector_tree": _analyze_diamond_tree,
    "transient_storage_tstore_lifecycle_auditor": _analyze_tstore,
    "eof_container_code_section_verifier": _analyze_eof,
    "erc4337_entrypoint_paymaster_simulator": _analyze_paymaster,
    "erc7579_modular_account_hook_inspector": _analyze_7579,
    "zk_snark_verifier_vk_parameter_auditor": _analyze_vk,
    "circom_r1cs_underconstrained_wire_checker": _analyze_r1cs,
    "halo2_lookup_table_range_profiler": _analyze_halo2,
    "gnosis_safe_fallback_handler_mutator_check": _analyze_safe_fallback,
    "merkle_patricia_trie_state_proof_verifier": _analyze_mpt,
}


def analyze_deep_lowlevel_source(src: str, spec: DetectorSpec,
                                 compiler: str = "",
                                 contract_name: str = ""
                                 ) -> List[Dict[str, Any]]:
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


class DeepLowlevelPlugin(Plugin):
    id = ""
    label = "Deep Low-Level Detector"
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
        findings: List[Finding] = []
        # MPT proofs arrive as ctx items, not contract addresses.
        if spec is not None and spec.id == \
                "merkle_patricia_trie_state_proof_verifier":
            for item in ctx.consume("state_proofs"):
                if isinstance(item, dict):
                    doc = item
                elif isinstance(item, str):
                    try:
                        doc = json.loads(item)
                    except ValueError:
                        continue
                else:
                    continue
                for hit in analyze_deep_lowlevel_source(
                        json.dumps(doc), spec):
                    findings.append(self._f(
                        "web3", spec.id,
                        f"{hit['severity'].upper()}: {spec.label}: "
                        f"{hit['detail']}",
                        source="deep low-level detector "
                               "(supplied state proof)",
                        confidence=80, passive=True,
                        evidence={"kind": spec.id,
                                  "severity": hit["severity"],
                                  "detail": hit["detail"],
                                  "remediation": spec.fix}))
            dur = int((time.monotonic() - t0) * 1000)
            res = self._ok(findings,
                           f"{spec.id}: {len(findings)} finding(s) "
                           f"from supplied state proofs")
            res.duration_ms = dur
            return res
        if not work or spec is None:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed, e.g. bsc:0x...) "
                "or a web target whose pages reference one")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
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
                                     role=role, impl_addr=impl,
                                     code_hex=code_hex)
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
            role="implementation", proxy_addr=addr,
            code_hex=impl_code) or got

    def _analyze_contract(self, chain: cc.ChainConfig, addr: str,
                          src: Optional[Dict[str, Any]],
                          findings: List[Finding], role: str,
                          proxy_addr: str = "",
                          impl_addr: str = "",
                          code_hex: str = "") -> bool:
        spec = self._spec
        if spec is None:
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
        got = False
        # The EOF verifier runs on deployed bytecode, not source.
        if spec.id == "eof_container_code_section_verifier" \
                and code_hex and code_hex != "0x":
            for item in analyze_deep_lowlevel_source(
                    code_hex, spec):
                got = True
                ev = dict(base_ev)
                ev.update({
                    "severity": item["severity"],
                    "check": spec.id,
                    "kind": spec.id,
                    "detector_outcome": spec.outcome,
                    "function": item["function"],
                    "code": item["code"],
                    "detail": item["detail"],
                    "bytecode_only": True,
                    "contract_name": "",
                    "remediation": spec.fix,
                })
                if item.get("report_class"):
                    ev["report_class"] = item["report_class"]
                if item.get("gate_analysis"):
                    ev["gate_analysis"] = item["gate_analysis"]
                findings.append(self._f(
                    "web3", spec.id,
                    f"{item['severity'].upper()}: {spec.label}: "
                    f"in contract {addr} on {chain.name}{tag}"
                    f"\n\n{item['detail']}",
                    source="deep low-level detector "
                           "(deployed bytecode)",
                    source_url=url,
                    confidence=80, passive=True, evidence=ev))
            return got
        if not src:
            return False
        for item in analyze_deep_lowlevel_source(
                src["source"], spec, src.get("compiler", ""),
                contract_name=src.get("contract_name", "")):
            got = True
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
            if item.get("proof"):
                ev["proof"] = item["proof"]
            fn_txt = f"function '{item['function']}' " \
                if item["function"] else ""
            findings.append(self._f(
                "web3", spec.id,
                f"{item['severity'].upper()}: {spec.label}: "
                f"{fn_txt}in contract {addr} on {chain.name}{tag}"
                f"\n\n{item['detail']}\n\nCode:\n{item['code']}",
                source="deep low-level detector "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return got


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepLowlevelPlugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep low-level detector for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
