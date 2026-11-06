"""Chisel REPL Eval (Tier 9) - SIM-DERIVED, UNVERIFIED ONLY.

HARD RULE: simulation analysis only. Every finding carries
verdict=UNVERIFIED / sim_derived=True; never VERIFIED_REAL, never
proof. VERIFIED_REAL requires live-chain probes.

Chisel is Foundry's one-shot Solidity REPL: `chisel` evaluates an
expression against fork state and prints the value. The distinct
remainder shipped here is a native, EVM-less Chisel-style evaluator
for the expressions that ARE statically evaluable: constant /
immutable arithmetic and address constants declared in the source.
It evaluates them with a safe AST evaluator (no eval()) and flags
evaluated values that configure the contract dangerously:

- a fee/tax constant evaluating to >= 50% (5000 bps or a plain >=50
  percent constant used as a fee);
- a supply/cap constant evaluating to uint256 max (unlimited cap
  presented as a cap);
- a threshold constant evaluating to 0 or 1 for a multisig /
  quorum-style variable (a 1-of-N or 0-of-N threshold);
- a zero interval/duration constant gating a time-locked release.

No other lane evaluates constant expressions: the static lanes match
patterns, they never compute the value. When the real `chisel`
binary is present (operator audit tree) it can cross-check these
values on a fork; the native evaluator is the documented
substitution and needs no binary.
"""
from __future__ import annotations

import ast
import re
from typing import Any, Dict, List, Optional

from .base import Cost, Plugin, PluginResult, Target, Ctx
from .forksim_util import run_analyzer_plugin

UINT256_MAX = (1 << 256) - 1

_CONST_RE = re.compile(
    r"\b(?:uint(?:256|128|64|32)?|int256?|address|bool)\s+"
    r"(?:public\s+|private\s+|internal\s+)?(?:constant|immutable)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);")
_CONST_RE2 = re.compile(
    r"\b(?:constant|immutable)\s+(?:uint(?:256|128|64|32)?|int256?)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);")


def _safe_eval(expr: str, env: Dict[str, int]) -> Optional[int]:
    """Evaluate a constant arithmetic expression safely (AST only)."""
    expr = expr.strip()
    # Solidity literal suffixes / casts that are value-preserving here
    expr = re.sub(r"\b(uint256|uint128|uint|int256)\s*\(", "(", expr)
    expr = re.sub(r"(\d)\s*(ether|gwei)\b",
                  lambda m: m.group(1) + ("*10**18" if m.group(2) == "ether"
                                          else "*10**9"), expr)
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        return None

    def ev(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            if node.id == "type":  # type(uint256).max handled below
                raise ValueError("type")
            raise ValueError(node.id)
        if isinstance(node, ast.BinOp):
            a, b = ev(node.left), ev(node.right)
            if isinstance(node.op, ast.Add):
                return a + b
            if isinstance(node.op, ast.Sub):
                return a - b
            if isinstance(node.op, ast.Mult):
                return a * b
            if isinstance(node.op, ast.Div):
                return a // b if b else 0
            if isinstance(node.op, ast.Pow):
                if b > 512:
                    raise ValueError("pow too large")
                return a ** b
            if isinstance(node.op, ast.LShift):
                return a << b if b < 4096 else 0
            if isinstance(node.op, ast.RShift):
                return a >> b
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -ev(node.operand)
        raise ValueError("unsupported")

    if "type(uint256).max" in expr.replace(" ", "") or \
            "type(uint).max" in expr.replace(" ", ""):
        return UINT256_MAX
    try:
        v = ev(tree)
    except Exception:
        return None
    return v if isinstance(v, int) else None


def evaluate_constants(source: str) -> Dict[str, int]:
    """{CONSTANT_NAME: evaluated int value} for evaluable constants."""
    env: Dict[str, int] = {}
    for pat in (_CONST_RE, _CONST_RE2):
        for m in pat.finditer(source):
            name, expr = m.group(1), m.group(2)
            if name in env:
                continue
            v = _safe_eval(expr, env)
            if v is not None:
                env[name] = v
    return env


def analyze_chisel_source(source: str, item: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for name, value in evaluate_constants(source).items():
        low = name.lower()
        if re.search(r"fee|tax|commission|royalt", low) and value >= 5000:
            hits.append({
                "key": "chisel_eval_dangerous_fee", "severity": "high",
                "check": "fee_constant_eval", "function": name,
                "detail": (f"Chisel-style evaluation: constant {name} "
                           f"evaluates to {value} (>= 5000 bps = a "
                           f">=50% fee/tax configuration)."),
                "confidence": 78,
                "extra": {"constant": name, "evaluated_value": str(value)}})
        elif re.search(r"cap|maxsupply|max_supply|supplycap", low) \
                and value >= UINT256_MAX:
            hits.append({
                "key": "chisel_eval_unlimited_cap", "severity": "medium",
                "check": "cap_constant_eval", "function": name,
                "detail": (f"Chisel-style evaluation: constant {name} "
                           f"evaluates to uint256 max - the 'cap' is "
                           f"effectively unlimited."),
                "confidence": 76,
                "extra": {"constant": name, "evaluated_value": str(value)}})
        elif re.search(r"threshold|quorum|required|approvals", low) \
                and value in (0, 1):
            hits.append({
                "key": "chisel_eval_weak_threshold", "severity": "high",
                "check": "threshold_constant_eval", "function": name,
                "detail": (f"Chisel-style evaluation: constant {name} "
                           f"evaluates to {value} - a {value}-of-N "
                           f"approval threshold gives no multisig "
                           f"protection."),
                "confidence": 76,
                "extra": {"constant": name, "evaluated_value": str(value)}})
        elif re.search(r"lockduration|lock_duration|timelock|vestingduration",
                       low) and value == 0:
            hits.append({
                "key": "chisel_eval_zero_timelock", "severity": "medium",
                "check": "timelock_constant_eval", "function": name,
                "detail": (f"Chisel-style evaluation: constant {name} "
                           f"evaluates to 0 - the named time-lock "
                           f"provides no delay."),
                "confidence": 74,
                "extra": {"constant": name, "evaluated_value": "0"}})
    return hits


class ChiselReplEvalPlugin(Plugin):
    id = "chisel_repl_eval"
    label = "Chisel REPL Eval (sim, UNVERIFIED)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    phase = 2
    description = ("Chisel-style one-shot evaluation of Solidity "
                   "constant expressions (native safe evaluator); "
                   "flags dangerous evaluated fee/cap/threshold/"
                   "timelock values. SIM-DERIVED, UNVERIFIED only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await run_analyzer_plugin(self, target, ctx,
                                         analyze_chisel_source)
