"""Unbounded-loop gas DoS (r100 wave 1).

Solodit / Code4rena finding class: a `for` loop bounded by the length
of a dynamic array (state array or caller-supplied calldata array)
whose body writes state or makes external calls. Every iteration costs
gas, so a growing array eventually makes the function uncallable, and
one failing iteration reverts the whole batch (push-payment DoS).

CWE-400 (Uncontrolled Resource Consumption). Static source detector;
findings are candidates for triage, never VERIFIED_REAL on their own.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_FOR_RE = re.compile(r"\bfor\s*\(", re.S)
_LEN_BOUND_RE = re.compile(
    r"([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)*)\s*\.\s*length\b")
_CALL_RE = re.compile(
    r"\.(call|transfer|send|transferFrom|safeTransfer|delegatecall)"
    r"\s*(?:\{[^}]*\})?\s*\(")
_ASSIGN_RE = re.compile(r"(\+\+|--|\+=|-=|\*=|/=|%=|=(?!=))")


def _writes_state(loop_body: str, state_names) -> set:
    """State vars written in a loop body. A write is a state var on the
    left-hand side of an assignment (including indexed writes like
    `balances[users[i]] += amt`), a `.push()`/`.pop()`, or a `delete`.
    Reads on the right-hand side (`s += balances[x]`) do not count."""
    found = set()
    for stmt in (loop_body or "").split(";"):
        m = _ASSIGN_RE.search(stmt)
        if m:
            lhs = stmt[:m.start()]
            for name in state_names:
                if re.search(r"\b" + re.escape(name) + r"\b", lhs):
                    found.add(name)
        for name in state_names:
            if re.search(r"\b" + re.escape(name)
                         + r"\s*\.\s*(push|pop)\s*\(", stmt):
                found.add(name)
            if re.search(r"\bdelete\s+" + re.escape(name) + r"\b", stmt):
                found.add(name)
    return found


def _brace_body(text: str, brace_pos: int) -> Tuple[str, int]:
    depth = 0
    for i in range(brace_pos, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace_pos + 1:i], i + 1
    return text[brace_pos + 1:], len(text)


def _loop_spans(body: str) -> List[Tuple[str, str, str]]:
    """Yield (header, loop_body, full_text) for each for-loop."""
    out: List[Tuple[str, str, str]] = []
    for m in _FOR_RE.finditer(body):
        open_paren = m.end() - 1
        depth = 0
        j = open_paren
        header = ""
        while j < len(body):
            if body[j] == "(":
                depth += 1
            elif body[j] == ")":
                depth -= 1
                if depth == 0:
                    header = body[open_paren + 1:j]
                    break
            j += 1
        rest = body[j + 1:].lstrip()
        if rest.startswith("{"):
            loop_body, _ = _brace_body(body, j + 1 + (len(body[j + 1:]) - len(rest)))
            out.append((header, loop_body, body[m.start():j + 1]))
        elif rest:
            # single-statement loop body: up to the next semicolon
            semi = rest.find(";")
            stmt = rest[:semi + 1] if semi != -1 else rest[:120]
            out.append((header, stmt, body[m.start():j + 1]))
    return out


def _is_dynamic_array(name: str, fn_args: str, state: List[Dict[str, Any]]
                      ) -> bool:
    base = name.split(".")[0]
    for v in state:
        if v["name"] == base and ("[" in v.get("type", "")):
            return True
    # function parameter declared as a dynamic array: `Type[] name`
    if re.search(r"\b\w+\s*\[\s*\]\s*(?:calldata|memory|storage)?\s*"
                 + re.escape(base) + r"\b", fn_args or ""):
        return True
    if re.search(r"\b\w+\s*\[\s*\]\s+" + re.escape(base) + r"\b",
                 fn_args or ""):
        return True
    return False


def find_unbounded_loops(source: str) -> List[Dict[str, Any]]:
    src = source or ""
    if not src.strip():
        return []
    state = C.state_vars(src)
    state_names = {v["name"] for v in state}
    hits: List[Dict[str, Any]] = []
    for fn in C.functions(src):
        body = fn.get("body") or ""
        if not body.strip():
            continue
        for header, loop_body, _ in _loop_spans(body):
            m = _LEN_BOUND_RE.search(header)
            if not m:
                continue
            coll = m.group(1)
            if not _is_dynamic_array(coll, fn.get("args", ""), state):
                continue
            # constant-bounded loops are fine: `i < 10` has no .length
            has_call = bool(_CALL_RE.search(loop_body))
            writes = _writes_state(loop_body, state_names)
            if not has_call and not writes:
                continue
            what = ("external call" if has_call else "") + (
                (" and " if has_call and writes else "") +
                (f"state writes ({', '.join(sorted(writes)[:3])})"
                 if writes else ""))
            hits.append(C.hit(
                "unbounded_loop_gas_dos",
                f"unbounded loop in {fn['name']}() over `{coll}.length` "
                f"with {what} inside - as `{coll}` grows the loop costs "
                f"more gas until the function cannot run, and one "
                f"failing iteration reverts the whole batch.",
                "medium",
                "Bound the loop (paginate, cap the array, or pull "
                "instead of push) and never put external calls or "
                "state writes in a loop over caller-influenced length.",
                cwe="CWE-400", check="unbounded_loop_dos",
                function=fn["name"], collection=coll))
            break  # one finding per function
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return find_unbounded_loops(data.get("source", ""))


class UnboundedLoopDosPlugin(Plugin):
    id = "unbounded_loop_dos"
    label = "Unbounded Loop Gas DoS"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Flags for-loops over dynamic arrays whose body "
                   "writes state or makes external calls (CWE-400 "
                   "unbounded-loop gas DoS).")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, stamp=False,
            bytecode=False,
            no_input="no contract source to check for unbounded loops")
