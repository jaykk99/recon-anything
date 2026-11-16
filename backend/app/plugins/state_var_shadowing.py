"""State-variable shadowing in inheritance (r100 wave 1).

Solodit / Code4rena finding class: a derived contract redeclares a
state variable with the same name as one in its base contract. The
derived variable shadows the base one, so reads and writes silently
hit the wrong storage slot - the base logic operates on a variable
the child never updates, or vice versa. Storage layout confusion of
exactly this shape has caused real fund losses in upgradeable
contracts.

CWE-710 (Improper Adherence to Coding Standards). Static source
detector; findings are candidates for triage, never VERIFIED_REAL
on their own.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_CONTRACT_RE = re.compile(
    r"\bcontract\s+([A-Za-z_][\w]*)\s*(?:is\s+([^{]+?))?\s*\{", re.S)
_DECL_RE = re.compile(
    r"(?m)^\s*(address|bool|uint\d*|int\d*|bytes\d*|string|bytes|"
    r"mapping\s*\([^;]+?\)|[\w\[\]]+)\s+"
    r"((?:public|private|internal|constant|immutable|override)\s+)*"
    r"([A-Za-z_][\w]*)\s*(?:=[^;]*)?;")


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


def _strip_function_bodies(body: str) -> str:
    """Remove function bodies so locals are not mistaken for state vars."""
    out = []
    i = 0
    func_re = re.compile(
        r"\bfunction\s+[A-Za-z_][\w]*\s*\([^)]*\)[^{;]*\{", re.S)
    while True:
        m = func_re.search(body, i)
        if not m:
            out.append(body[i:])
            break
        out.append(body[i:m.start()])
        _, end = _brace_body(body, m.end() - 1)
        i = end
    return "".join(out)


def _contracts(source: str) -> Dict[str, Dict[str, Any]]:
    """name -> {"bases": [...], "vars": {name: {"type":..., "mods":...}}}"""
    clean = C.strip_comments(source or "")
    out: Dict[str, Dict[str, Any]] = {}
    for m in _CONTRACT_RE.finditer(clean):
        name = m.group(1)
        bases = []
        if m.group(2):
            bases = [b.strip().split("(")[0].strip()
                     for b in m.group(2).split(",")]
            bases = [b for b in bases if b]
        body, _ = _brace_body(clean, m.end() - 1)
        top = _strip_function_bodies(body)
        # strip nested contract/interface/library blocks
        top = re.sub(r"\b(contract|interface|library)\s+[^{]+\{[^}]*\}",
                     " ", top, flags=re.S)
        vars_: Dict[str, Dict[str, str]] = {}
        for d in _DECL_RE.finditer(top):
            mods = (d.group(2) or "").strip()
            vars_[d.group(3)] = {"type": d.group(1), "mods": mods}
        out[name] = {"bases": bases, "vars": vars_}
    return out


def find_shadowed_vars(source: str) -> List[Dict[str, Any]]:
    src = source or ""
    if not src.strip():
        return []
    contracts = _contracts(src)
    hits: List[Dict[str, Any]] = []
    for name, info in contracts.items():
        for base in info["bases"]:
            base_info = contracts.get(base)
            if not base_info:
                continue  # base defined elsewhere, cannot verify
            for var, meta in info["vars"].items():
                if var in base_info["vars"]:
                    if "override" in meta["mods"].split():
                        continue  # explicit override, intentional
                    hits.append(C.hit(
                        "state_var_shadowed",
                        f"state variable `{var}` in {name} shadows the "
                        f"same-named variable in base {base} - reads and "
                        f"writes in the child hit a different storage "
                        f"slot than the base logic expects.",
                        "medium",
                        "Rename the derived variable, or mark it "
                        "`override` if shadowing is genuinely intended "
                        "and the base variable is virtual.",
                        cwe="CWE-710", check="state_var_shadowing",
                        contract=name, base=base, variable=var))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return find_shadowed_vars(data.get("source", ""))


class StateVarShadowingPlugin(Plugin):
    id = "state_var_shadowing"
    label = "State Variable Shadowing"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Flags derived contracts that redeclare a base "
                   "contract's state variable (CWE-710 shadowing).")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze, fetch=True, stamp=False,
            bytecode=False,
            no_input="no contract source to check for shadowing")
