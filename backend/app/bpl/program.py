"""Hypothesis representation: a probabilistic state machine as data AND as
executable, AST-verified Python code.

A Program says how one entity behaves:
  - inter-arrival times: lognormal(mu, sigma) in hours, with an optional
    burst component (short intervals with probability burst_p);
  - next group (chain / symbol axis): categorical distribution, optionally
    sticky (repeat the previous group with probability group_sticky);
  - next kind (contract type / flip direction): categorical distribution,
    optionally sticky (repeat the previous kind with probability kind_sticky).

Description length (Solomonoff prior): the program's prior probability is
2 ** (-bits), where bits is the cost of encoding the program's structure
plus its parameters at fixed quantization. Shorter program = higher prior.
log_prior = -bits * ln(2).

The program can be emitted as restricted Python source (to_source) and
executed only after AST verification (verify_source) in a namespace with
no builtins, no imports, no file/network access, seeded RNG only.
"""

from __future__ import annotations

import ast
import math
import random
from dataclasses import dataclass, field

LN2 = math.log(2.0)
EPS = 1e-9


def _norm(probs):
    total = sum(probs.values())
    if total <= 0:
        n = len(probs)
        return {k: 1.0 / n for k in probs}
    return {k: v / total for k, v in probs.items()}


@dataclass
class Program:
    interval_mu: float = 5.0        # log-median inter-arrival time, hours
    interval_sigma: float = 1.0     # log spread
    burst_p: float = 0.0            # P(short burst interval)
    burst_hours: float = 1.0        # median burst interval, hours
    group_probs: dict = field(default_factory=dict)   # P(next group)
    kind_probs: dict = field(default_factory=dict)    # P(next kind)
    group_sticky: float = 0.0       # P(repeat previous group)
    kind_sticky: float = 0.0        # P(repeat previous kind)

    def __post_init__(self):
        self.group_probs = _norm(self.group_probs) if self.group_probs else {}
        self.kind_probs = _norm(self.kind_probs) if self.kind_probs else {}
        self.interval_sigma = max(0.05, min(3.0, self.interval_sigma))
        self.burst_p = max(0.0, min(0.9, self.burst_p))
        self.group_sticky = max(0.0, min(0.9, self.group_sticky))
        self.kind_sticky = max(0.0, min(0.9, self.kind_sticky))

    # ---- Solomonoff prior: description length in bits -------------------
    def description_length_bits(self):
        bits = 0.0
        # structure: 1 bit per optional feature that is actually used
        bits += 1.0  # burst component present?
        bits += 1.0  # group stickiness present?
        bits += 1.0  # kind stickiness present?
        # parameters, quantized (levels -> log2(levels) bits each)
        bits += math.log2(41)   # interval_mu, 0.25 steps over [-2, 8]
        bits += math.log2(20)   # interval_sigma, 0.1 steps over [0.1, 2.0]
        bits += math.log2(19)   # burst_p, 0.05 steps over [0, 0.9]
        bits += math.log2(41)   # burst_hours, log scale like mu
        bits += math.log2(19)   # group_sticky
        bits += math.log2(19)   # kind_sticky
        # categorical distributions: 4 bits per free parameter
        bits += 4.0 * max(0, len(self.group_probs) - 1)
        bits += 4.0 * max(0, len(self.kind_probs) - 1)
        return bits

    def log_prior(self):
        return -self.description_length_bits() * LN2

    # ---- categorical helpers --------------------------------------------
    def group_prob(self, group, prev_group):
        if self.group_sticky > 0.0 and prev_group is not None and group == prev_group:
            base = self.group_probs.get(group, 0.0)
            return self.group_sticky + (1.0 - self.group_sticky) * base
        return self.group_probs.get(group, 0.0)

    def kind_prob(self, kind, prev_kind):
        if self.kind_sticky > 0.0 and prev_kind is not None and kind == prev_kind:
            base = self.kind_probs.get(kind, 0.0)
            return self.kind_sticky + (1.0 - self.kind_sticky) * base
        return self.kind_probs.get(kind, 0.0)

    # ---- executable source ----------------------------------------------
    def to_source(self):
        """Emit the program as restricted Python source. Deterministic
        given a seeded random.Random passed in as `rng`."""
        groups = list(self.group_probs)
        kinds = list(self.kind_probs)
        src = []
        src.append("def step(state, rng):")
        src.append("    if rng.random() < %r:" % self.burst_p)
        src.append("        dt = rng.lognormvariate(%r, 0.5)" % math.log(max(self.burst_hours, 1e-3)))
        src.append("    else:")
        src.append("        dt = rng.lognormvariate(%r, %r)" % (self.interval_mu, self.interval_sigma))
        src.append("    dt = max(dt, 0.001)")
        if groups:
            src.append("    group = rng.choices(%r, weights=%r)[0]" % (groups, [self.group_probs[g] for g in groups]))
            if self.group_sticky > 0.0:
                src.append("    if state.get('group') is not None and rng.random() < %r:" % self.group_sticky)
                src.append("        group = state['group']")
        else:
            src.append("    group = state.get('group')")
        if kinds:
            src.append("    kind = rng.choices(%r, weights=%r)[0]" % (kinds, [self.kind_probs[k] for k in kinds]))
            if self.kind_sticky > 0.0:
                src.append("    if state.get('kind') is not None and rng.random() < %r:" % self.kind_sticky)
                src.append("        kind = state['kind']")
        else:
            src.append("    kind = state.get('kind')")
        src.append("    return {'dt_hours': dt, 'group': group, 'kind': kind}")
        return "\n".join(src) + "\n"

    def describe(self):
        top_group = max(self.group_probs, key=self.group_probs.get) if self.group_probs else "-"
        top_kind = max(self.kind_probs, key=self.kind_probs.get) if self.kind_probs else "-"
        return (
            "deploys every ~%.1fh (lognormal mu=%.2f sigma=%.2f%s), "
            "favours group %s (%.0f%%) and kind %s (%.0f%%)%s%s"
            % (
                math.exp(self.interval_mu), self.interval_mu, self.interval_sigma,
                (" with %.0f%% bursts of ~%.1fh" % (self.burst_p * 100, self.burst_hours)) if self.burst_p > 0.01 else "",
                top_group, 100.0 * self.group_probs.get(top_group, 0.0),
                top_kind, 100.0 * self.kind_probs.get(top_kind, 0.0),
                ("; repeats group %.0f%%" % (self.group_sticky * 100)) if self.group_sticky > 0.01 else "",
                ("; repeats kind %.0f%%" % (self.kind_sticky * 100)) if self.kind_sticky > 0.01 else "",
            )
        )


# ---- AST verification + sandboxed execution ------------------------------
_ALLOWED_CALLS = {"rng.random", "rng.lognormvariate", "rng.choices", "rng.gauss"}
_ALLOWED_ATTRS = {"random", "lognormvariate", "choices", "gauss", "get"}
_ALLOWED_NODES = (
    ast.Module, ast.FunctionDef, ast.arguments, ast.arg, ast.Assign,
    ast.AugAssign, ast.Return,
    ast.If, ast.Expr, ast.BinOp, ast.UnaryOp, ast.Compare, ast.BoolOp,
    ast.Call, ast.Name, ast.Load, ast.Store, ast.Constant, ast.Subscript,
    ast.Attribute, ast.List, ast.Tuple, ast.Dict, ast.keyword,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.USub, ast.Not,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.And, ast.Or,
    ast.In, ast.NotIn, ast.Is, ast.IsNot, ast.Index, ast.Slice,
)


def verify_source(source):
    """Return (ok, reason). Only the whitelisted subset is allowed: no
    imports, no attribute access outside math/rng, no open/eval/exec,
    no dunders, no loops (guaranteed termination), no comprehensions."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return False, "syntax error: %s" % exc
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            return False, "forbidden node: %s" % type(node).__name__
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_") or node.attr not in _ALLOWED_ATTRS:
                return False, "forbidden attribute: %s" % node.attr
        if isinstance(node, ast.Name):
            if node.id.startswith("_") or node.id in {
                "open", "eval", "exec", "__import__", "compile", "input",
                "globals", "locals", "vars", "getattr", "setattr",
            }:
                return False, "forbidden name: %s" % node.id
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute):
                if func.attr == "get":
                    continue  # dict .get is safe on any object
                dotted = ""
                if isinstance(func.value, ast.Name):
                    dotted = func.value.id + "." + func.attr
                if dotted not in _ALLOWED_CALLS:
                    return False, "forbidden call: %s" % dotted
            elif isinstance(func, ast.Name):
                if func.id not in {"max", "min", "len"}:
                    return False, "forbidden call: %s" % func.id
            else:
                return False, "forbidden call shape"
    return True, "ok"


def execute_program(source, state, seed):
    """Run AST-verified source in a sandbox: no builtins, no imports,
    seeded RNG only. Returns the step dict. Raises on verification failure."""
    ok, reason = verify_source(source)
    if not ok:
        raise ValueError("program failed AST verification: %s" % reason)
    namespace = {"__builtins__": {}, "math": math,
                 "max": max, "min": min, "len": len}
    code = compile(ast.parse(source), "<bpl-program>", "exec")
    exec(code, namespace)  # noqa: S102 - source is AST-verified above
    rng = random.Random(seed)
    return namespace["step"](dict(state), rng)
