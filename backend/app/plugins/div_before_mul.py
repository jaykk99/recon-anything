"""Division-before-multiplication precision loss (r100 wave 1).

Solodit / Code4rena finding class: `amount / divisor * multiplier`
loses the remainder of the division before the multiplication ever sees
it, so small amounts round to zero and every amount loses precision.
`amount * multiplier / divisor` is the correct order.

CWE-682 (Incorrect Calculation). Static source detector; findings are
candidates for triage, never VERIFIED_REAL on their own.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

# operand: identifier, member access, number, or a call; then / then *.
# The `*` must not be part of `**`, and the `/` must not be `//`.
_DIV_MUL_RE = re.compile(
    r"(?<![\w.])([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)?(?:\([^)]*\))?"
    r"|\d[\d_]*(?:\.\d+)?)"
    r"\s*/\s*"
    r"([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)?(?:\([^)]*\))?"
    r"|\d[\d_]*(?:\.\d+)?)"
    r"\s*\*(?!\*)"
    r"\s*([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)?(?:\([^)]*\))?"
    r"|\d[\d_]*(?:\.\d+)?)")
# Parenthesised form: (a / b) * c
_PAREN_DIV_MUL_RE = re.compile(
    r"\(\s*[^()\n;]*?/\s*[^()\n;]*?\)\s*\*(?!\*)")


def _is_trivial(dividend: str, divisor: str) -> bool:
    """Skip shapes that cannot lose value: division by 1, or a literal
    dividend that is a round power-of-ten scale with no value at stake."""
    try:
        if int(divisor) == 1:
            return True
    except ValueError:
        pass
    return False


def find_div_before_mul(source: str) -> List[Dict[str, Any]]:
    src = source or ""
    if not src.strip():
        return []
    hits: List[Dict[str, Any]] = []
    for fn in C.functions(src):
        body = fn.get("body") or ""
        if not body.strip():
            continue
        snippet = ""
        for m in _DIV_MUL_RE.finditer(body):
            if _is_trivial(m.group(1), m.group(2)):
                continue
            snippet = m.group(0).strip()
            break
        if not snippet:
            for m in _PAREN_DIV_MUL_RE.finditer(body):
                snippet = m.group(0).strip()
                break
        if snippet:
            hits.append(C.hit(
                "div_before_mul_precision_loss",
                f"division before multiplication in {fn['name']}(): "
                f"`{snippet}` - the division remainder is discarded "
                f"before the multiplication, so the result loses "
                f"precision and small amounts can round to zero.",
                "medium",
                "Multiply first, then divide: reorder to "
                "`(amount * multiplier) / divisor` so the remainder "
                "survives until the final division.",
                cwe="CWE-682", check="div_before_mul_precision",
                function=fn["name"], snippet=snippet))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return find_div_before_mul(data.get("source", ""))


class DivBeforeMulPrecisionPlugin(Plugin):
    id = "div_before_mul_precision"
    label = "Division Before Multiplication"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Flags `a / b * c` arithmetic where the division "
                   "discards the remainder before the multiplication "
                   "(CWE-682 precision loss).")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, stamp=False,
            bytecode=False,
            no_input="no contract source to check for precision loss")
