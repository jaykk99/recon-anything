"""AST Visual Audit: a headless, first-party rebuild of what the
Solidity Visual Auditor VS Code extension shows an auditor in the
editor - the inheritance tree, the contract dependency graph, a
per-function structural map (visibility, mutability, modifiers,
state reads/writes, external interactions) and structural risk
highlights - computed from the solc AST over the target's verified
source and emitted as ordinary ReconAnything findings whose
evidence IS the map.

Jay's Nov 3 direction: for VS Code extensions whose function is
real analysis, do not just exclude them - rebuild the analysis
function as a backend plugin the agent can use. The extension
package itself only runs inside the VS Code editor UI and cannot
be hosted by a backend; this plugin is the rebuild. Solidity
Metrics' function is folded in as per-contract counts (functions,
state variables, nSLOC, a cyclomatic-complexity proxy) inside the
same map evidence - no separate plugin for counters.

Discipline:
- Scope follows the FP-fix rules (contract_logic._Scope lineage):
  the bundle is split on `// ==== path ====` markers, test/mock
  units are dropped, and when the target contract name is known
  only the target plus its ancestors are compiled.
- Compile prep dedupes SPDX identifiers and `pragma solidity`
  lines across bundle units (a flattened multi-file bundle carries
  one of each per file; solc rejects the duplicates). This is the
  same failure the fuzz lane hit on real-world bundles.
- Highlights are STRUCTURAL and capped at low severity:
  delegatecall to a non-constant target, tx.origin use, an
  unchecked low-level call (result discarded), selfdestruct
  presence, inline assembly. contract_logic / crypto_drain /
  Slither report confirmed instances of these classes at higher
  severity; this plugin's job is the map, not a second verdict, so
  it never raises them above low.
- If solc is unavailable or the source does not compile, the
  plugin says so in one info finding (ast_map_not_produced) -
  absence is reported, never dressed up as a clean map.
- Keyless and passive: verified source comes only from the
  existing contract_chain routes; no transactions, no keys.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from . import toolbox as tb

MAX_ADDRESSES = 2
MAX_CHAIN_PAIRS = 2
COMPILE_BUDGET_S = 120

# ---------------------------------------------------------------------------
# Compile prep: bundle scoping + SPDX/pragma dedupe
# ---------------------------------------------------------------------------

_SPDX_RE = re.compile(r"^\s*//\s*SPDX-License-Identifier:.*$", re.M)
_PRAGMA_RE = re.compile(r"^\s*pragma\s+solidity\s+[^;]+;.*$", re.M)


def scoped_compile_text(source: str, contract_name: str = "") -> str:
    """The single-file text to hand solc: bundle units selected by
    the FP-fix scope rules (target + ancestors when the name is
    known, otherwise everything outside test/mock units), with
    duplicate SPDX identifiers and `pragma solidity` lines removed
    (first occurrence wins). Import statements are dropped: a
    flattened verified bundle is self-contained by construction,
    and a surviving import would point at a file that does not
    exist in the compile sandbox."""
    units = cl._split_units(source)
    spans_by_unit: List[List[Dict[str, Any]]] = []
    all_spans: List[Dict[str, Any]] = []
    for path, raw in units:
        spans = cl._contract_spans(cc._strip_comments(raw))
        for s in spans:
            s["path"] = path
        spans_by_unit.append(spans)
        all_spans.extend(spans)
    keep_units = set(range(len(units)))
    pool = [s for s in all_spans
            if not cl._TEST_SEGMENT_RE.search(s["path"])] or all_spans
    if contract_name:
        by_name = {s["name"]: s for s in pool if s["name"]}
        if contract_name in by_name:
            keep_names = set()
            stack = [contract_name]
            while stack:
                n = stack.pop()
                if n in keep_names:
                    continue
                keep_names.add(n)
                sp = by_name.get(n)
                if sp:
                    stack.extend(sp["ancestors"])
            keep_units = {i for i, spans in enumerate(spans_by_unit)
                          if any(s["name"] in keep_names
                                 for s in spans)}
            if not keep_units:
                keep_units = set(range(len(units)))
    else:
        test_units = {i for i, (path, _raw) in enumerate(units)
                      if cl._TEST_SEGMENT_RE.search(path)}
        if test_units and len(test_units) < len(units):
            keep_units = set(range(len(units))) - test_units
    text = "\n".join(units[i][1] for i in sorted(keep_units))
    text = re.sub(r"^\s*import\s[^;]+;", "", text, flags=re.M)
    seen_spdx = False

    def _spdx(m: "re.Match[str]") -> str:
        nonlocal seen_spdx
        if seen_spdx:
            return ""
        seen_spdx = True
        return m.group(0)

    text = _SPDX_RE.sub(_spdx, text)
    seen_pragma = False

    def _pragma(m: "re.Match[str]") -> str:
        nonlocal seen_pragma
        if seen_pragma:
            return ""
        seen_pragma = True
        return m.group(0)

    text = _PRAGMA_RE.sub(_pragma, text)
    return text


# ---------------------------------------------------------------------------
# AST walking
# ---------------------------------------------------------------------------

def _src_span(node: Dict[str, Any]) -> Tuple[int, int]:
    """(start, length) from an AST node's "src" field
    ("start:length:fileId"), or (0, 0)."""
    raw = str(node.get("src") or "")
    parts = raw.split(":")
    try:
        return int(parts[0]), int(parts[1])
    except Exception:
        return 0, 0


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _text_of(text: str, node: Dict[str, Any], cap: int = 200) -> str:
    start, length = _src_span(node)
    return text[start:start + length][:cap].strip()


def _children(node: Any):
    """Yield every dict node in an AST subtree (depth-first)."""
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _children(v)
    elif isinstance(node, list):
        for v in node:
            yield from _children(v)


_LOW_LEVEL = {"call", "delegatecall", "staticcall", "send",
              "transfer"}


def _unwrap_call_expr(expr: Dict[str, Any]) -> Dict[str, Any]:
    """FunctionCallOptions (x.call{value:..}(..)) wraps the member
    access; unwrap to it."""
    while isinstance(expr, dict) and \
            expr.get("nodeType") == "FunctionCallOptions":
        expr = expr.get("expression") or {}
    return expr


def _analyze_function(fn: Dict[str, Any], text: str,
                      state_names: set) -> Dict[str, Any]:
    name = fn.get("name") or ""
    kind = fn.get("kind") or "function"
    if kind == "constructor":
        label = "<constructor>"
    elif kind == "fallback":
        label = "<fallback>"
    elif kind == "receive":
        label = "<receive>"
    else:
        label = name
    modifiers = []
    for mod in fn.get("modifiers") or []:
        mname = ((mod.get("modifierName") or {}).get("name") or "")
        if mname:
            modifiers.append(mname)
    info: Dict[str, Any] = {
        "name": label,
        "kind": kind,
        "visibility": fn.get("visibility") or "",
        "mutability": fn.get("stateMutability") or "",
        "modifiers": modifiers,
        "virtual": bool(fn.get("virtual")),
        "reads": set(),
        "writes": set(),
        "interactions": [],
        "tx_origin": False,
        "tx_origin_line": 0,
        "assembly": False,
        "assembly_line": 0,
        "complexity": 1,
    }
    body = fn.get("body")
    if not isinstance(body, dict):
        info["reads"] = []
        info["writes"] = []
        return info

    def record_interaction(member: str, member_node: Dict[str, Any],
                           call_node: Dict[str, Any],
                           parent_type: str) -> None:
        target_node = member_node.get("expression") or {}
        entry: Dict[str, Any] = {
            "kind": ("low_level_call" if member == "call" else
                     member),
            "target": _text_of(text, target_node, 80),
            "line": _line_of(text, _src_span(call_node)[0]),
            "unchecked": parent_type == "ExpressionStatement",
        }
        if member == "delegatecall":
            entry["target_constant"] = _is_constant_expr(
                target_node, text)
        info["interactions"].append(entry)

    def walk(node: Any, parent_type: str = "") -> None:
        if isinstance(node, list):
            for v in node:
                walk(v, parent_type)
            return
        if not isinstance(node, dict):
            return
        nt = node.get("nodeType") or ""
        if nt in ("IfStatement", "ForStatement", "WhileStatement",
                  "DoWhileStatement", "Conditional"):
            info["complexity"] += 1
        if nt == "BinaryOperation" and node.get("operator") in (
                "&&", "||"):
            info["complexity"] += 1
        if nt == "InlineAssembly":
            info["assembly"] = True
            if not info["assembly_line"]:
                info["assembly_line"] = _line_of(
                    text, _src_span(node)[0])
        if nt == "MemberAccess" and node.get("memberName") == "origin":
            base = node.get("expression") or {}
            if base.get("name") == "tx":
                info["tx_origin"] = True
                if not info["tx_origin_line"]:
                    info["tx_origin_line"] = _line_of(
                        text, _src_span(node)[0])
        if nt == "FunctionCall":
            expr = _unwrap_call_expr(node.get("expression") or {})
            if expr.get("nodeType") == "MemberAccess" and \
                    expr.get("memberName") in _LOW_LEVEL:
                record_interaction(str(expr.get("memberName")),
                                   expr, node, parent_type)
            elif expr.get("nodeType") == "Identifier" and \
                    expr.get("name") == "selfdestruct":
                info["interactions"].append({
                    "kind": "selfdestruct",
                    "target": _text_of(
                        text, (node.get("arguments") or [{}])[0], 80)
                    if node.get("arguments") else "",
                    "line": _line_of(text, _src_span(node)[0]),
                    "unchecked": False})
        if nt == "NewExpression":
            type_name = ((node.get("typeName") or {}).get("name")
                         or (node.get("typeName") or {}).get(
                             "pathNode", {}).get("name") or "")
            info["interactions"].append({
                "kind": "create", "target": str(type_name),
                "line": _line_of(text, _src_span(node)[0]),
                "unchecked": False})
        # State reads/writes.
        if nt == "Assignment":
            lhs = node.get("leftHandSide") or {}
            for sub in _children(lhs):
                root = _root_identifier(sub)
                if root and root in state_names:
                    info["writes"].add(root)
            walk(node.get("rightHandSide"), nt)
            return
        if nt == "UnaryOperation" and node.get("operator") in (
                "++", "--"):
            root = _root_identifier(node.get("subExpression") or {})
            if root and root in state_names:
                info["writes"].add(root)
        if nt == "Identifier":
            nm = node.get("name") or ""
            if nm in state_names:
                info["reads"].add(nm)
        for v in node.values():
            if isinstance(v, (dict, list)):
                walk(v, nt)

    walk(body)
    info["reads"] = sorted(info["reads"])
    info["writes"] = sorted(info["writes"])
    return info


def _root_identifier(node: Dict[str, Any]) -> str:
    """The root variable name of an lvalue expression
    (balances[msg.sender] -> balances)."""
    cur = node
    while isinstance(cur, dict):
        nt = cur.get("nodeType")
        if nt == "Identifier":
            return str(cur.get("name") or "")
        if nt in ("MemberAccess", "IndexAccess"):
            cur = cur.get("expression") or {}
            continue
        return ""
    return ""


_CONSTANT_IDENT_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _is_constant_expr(node: Dict[str, Any], text: str) -> bool:
    """Heuristic: a delegatecall target is 'constant' when it is a
    literal, or a single identifier in CONSTANT_CASE (the universal
    convention for immutable/constant addresses) - anything else
    (state var, parameter, computed) is non-constant."""
    if not isinstance(node, dict):
        return False
    if node.get("nodeType") == "Literal":
        return True
    if node.get("nodeType") == "Identifier":
        return bool(_CONSTANT_IDENT_RE.match(str(node.get("name")
                                                 or "")))
    return False


def build_ast_map(combined: Dict[str, Any], text: str
                  ) -> List[Dict[str, Any]]:
    """solc --combined-json ast output + the compiled text ->
    per-contract structural maps (the visual auditor's panels, as
    data). Pure: unit-tested on a saved real compilation."""
    out: List[Dict[str, Any]] = []
    sources = (combined or {}).get("sources") or {}
    id_to_name: Dict[int, str] = {}
    contracts_raw: List[Dict[str, Any]] = []
    for _path, entry in sources.items():
        ast = (entry or {}).get("AST") or {}
        for node in _children(ast):
            if node.get("nodeType") == "ContractDefinition":
                id_to_name[id(node)] = str(node.get("name") or "")
                contracts_raw.append(node)
    # AST node ids (the numeric "id" field) map linearized bases.
    num_id_to_name: Dict[int, str] = {}
    for node in contracts_raw:
        if isinstance(node.get("id"), int):
            num_id_to_name[node["id"]] = str(node.get("name") or "")
    # State variables per contract, then inherited closure.
    own_vars: Dict[str, List[Dict[str, Any]]] = {}
    for node in contracts_raw:
        vars_: List[Dict[str, Any]] = []
        for sub in node.get("nodes") or []:
            if isinstance(sub, dict) and \
                    sub.get("nodeType") == "VariableDeclaration" and \
                    sub.get("stateVariable"):
                vars_.append({
                    "name": str(sub.get("name") or ""),
                    "type": str((sub.get("typeDescriptions") or {})
                                .get("typeString") or ""),
                    "visibility": sub.get("visibility") or "",
                    "constant": bool(sub.get("constant")),
                    "immutable": bool(sub.get("mutability")
                                      == "immutable"),
                })
        own_vars[str(node.get("name") or "")] = vars_
    for node in contracts_raw:
        name = str(node.get("name") or "")
        bases = [num_id_to_name.get(i, str(i))
                 for i in node.get("linearizedBaseContracts") or []
                 if isinstance(i, int)]
        state_names = set()
        for base in bases + [name]:
            for v in own_vars.get(base, []):
                state_names.add(v["name"])
        deps = set()
        for sub in _children(node):
            if sub.get("nodeType") == "UserDefinedTypeName":
                ref = (sub.get("pathNode") or {}).get("name") or \
                    sub.get("namePath")
                if ref:
                    deps.add(str(ref).split(".")[0])
        deps.discard(name)
        functions: List[Dict[str, Any]] = []
        total_complexity = 0
        for sub in node.get("nodes") or []:
            if isinstance(sub, dict) and \
                    sub.get("nodeType") == "FunctionDefinition":
                finfo = _analyze_function(sub, text, state_names)
                total_complexity += finfo["complexity"]
                functions.append(finfo)
        start, length = _src_span(node)
        slice_text = text[start:start + length]
        nsloc = sum(1 for ln in slice_text.splitlines()
                    if ln.strip() and not ln.strip().startswith("//"))
        out.append({
            "name": name,
            "kind": node.get("contractKind") or "contract",
            "abstract": bool(node.get("abstract")),
            "bases": [b for b in bases if b != name],
            "dependencies": sorted(deps),
            "state_variables": own_vars.get(name, []),
            "functions": functions,
            "metrics": {
                "functions": len(functions),
                "state_variables": len(own_vars.get(name, [])),
                "nsloc": nsloc,
                "complexity": total_complexity,
            },
        })
    return out


def extract_highlights(contract_map: Dict[str, Any], text: str
                       ) -> List[Dict[str, Any]]:
    """Structural risk highlights from one contract's map. All low
    severity by design (see module docstring)."""
    out: List[Dict[str, Any]] = []
    cname = contract_map["name"]
    for fn in contract_map["functions"]:
        fname = fn["name"]
        for inter in fn["interactions"]:
            if inter["kind"] == "delegatecall" and \
                    not inter.get("target_constant", True):
                tgt = inter["target"] or "a computed address"
                out.append({
                    "kind": "delegatecall_nonconstant_target",
                    "contract": cname, "function": fname,
                    "line": inter["line"],
                    "message": f"{cname}.{fname} delegatecalls into "
                               f"{tgt}: the target is not a "
                               "constant, so whoever controls it "
                               "controls this contract's storage "
                               "context (structural highlight; "
                               "contract_logic reports confirmed "
                               "ungated instances at high severity)",
                })
            if inter["kind"] == "low_level_call" and \
                    inter.get("unchecked"):
                out.append({
                    "kind": "unchecked_low_level_call",
                    "contract": cname, "function": fname,
                    "line": inter["line"],
                    "message": f"{cname}.{fname} discards the result "
                               "of a low-level call: failure is "
                               "silent and the function continues as "
                               "if the transfer succeeded "
                               "(structural highlight)",
                })
            if inter["kind"] == "selfdestruct":
                out.append({
                    "kind": "selfdestruct_present",
                    "contract": cname, "function": fname,
                    "line": inter["line"],
                    "message": f"{cname}.{fname} can selfdestruct "
                               "the contract, force-sending its "
                               "balance (structural highlight)",
                })
        if fn.get("tx_origin"):
            out.append({
                "kind": "tx_origin_use",
                "contract": cname, "function": fname,
                "line": fn.get("tx_origin_line", 0),
                "message": f"{cname}.{fname} references tx.origin: "
                           "origin is the external account that "
                           "started the transaction, not the caller, "
                           "and must not authorize anything "
                           "(structural highlight)",
            })
        if fn.get("assembly"):
            out.append({
                "kind": "inline_assembly",
                "contract": cname, "function": fname,
                "line": fn.get("assembly_line", 0),
                "message": f"{cname}.{fname} contains inline "
                           "assembly: compiler checks are bypassed "
                           "inside the block, so it needs manual "
                           "review (structural highlight)",
            })
    return out


async def compile_ast(source_text: str, solc: Optional[str]
                      ) -> Optional[Dict[str, Any]]:
    """Compile with solc --combined-json ast,abi; parsed JSON or
    None when the compile did not produce one."""
    if not solc:
        return None
    workdir = tempfile.mkdtemp(prefix="ast-visual-")
    try:
        path = os.path.join(workdir, "Contract.sol")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(source_text)
        _rc, out, _err = await tb.run_tool(
            [solc, "--combined-json", "ast,abi", "Contract.sol"],
            cwd=workdir, budget_s=COMPILE_BUDGET_S)
        try:
            return json.loads(out)
        except Exception:
            return None
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class AstVisualAuditPlugin(Plugin):
    id = "ast_visual_audit"
    label = "AST Visual Audit (structure map + highlights)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = (
        "Headless rebuild of the Solidity Visual Auditor's "
        "analysis function (the extension itself runs only inside "
        "the VS Code editor): compiles the target's verified "
        "source with solc and emits the structural map an auditor "
        "reads first - inheritance tree, contract dependencies, "
        "per-function visibility/mutability/modifiers, state "
        "reads/writes, the external-interaction map, and per-"
        "contract metrics (functions, state vars, nSLOC, "
        "complexity; the Solidity Metrics function) - plus low-"
        "severity structural highlights (non-constant delegatecall "
        "targets, tx.origin, unchecked low-level calls, "
        "selfdestruct, inline assembly). Confirmed instances of "
        "those classes are reported at higher severity by "
        "contract_logic and the audit toolbox; this plugin is the "
        "map, not a second verdict. Keyless, read-only.")
    phase = 2
    timeout_s = 180

    # -- target collection (mirrors contract_logic / toolbox) --------
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

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        work = self._collect(target, ctx)
        if not work:
            res = self._skipped(
                "no contract address to map: scan a contract "
                "address (optionally chain-prefixed) or a web "
                "target whose pages reference one")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        findings: List[Finding] = []
        mapped = 0
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
            if got:
                mapped += 1
        res = self._ok(
            findings,
            f"ast-mapped {mapped} contract address(es)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _scan_address(self, ctx: Ctx, key: Optional[str],
                            chain_hint: Optional[str], addr: str,
                            findings: List[Finding]
                            ) -> Tuple[int, bool]:
        chain_ids = [chain_hint] if chain_hint else \
            list(cc.DEFAULT_CHAIN_ORDER)
        pairs = 0
        done_any = False
        for cid in chain_ids:
            if done_any:
                break
            chain = cc.CHAINS[cid]
            code = await cc.rpc_get_code(ctx, chain, addr)
            if code is None or code == "0x" or len(code) < 4:
                continue
            done_any = True
            pairs += 1
            src = await cc.fetch_verified_source(ctx, chain, addr,
                                                 key)
            res = {"implementation": ""}
            try:
                res = await cc.resolve_implementation(
                    ctx, chain, addr, code,
                    {"implementation": (src or {}).get(
                        "implementation", "")})
            except Exception:
                pass
            impl = res.get("implementation") or ""
            role = "proxy_shell" if impl else "standalone"
            await self._analyze(ctx, chain, addr, src, role,
                                findings)
            if impl:
                impl_src = None
                try:
                    impl_code = await cc.rpc_get_code(ctx, chain,
                                                      impl)
                    if impl_code and impl_code != "0x" and \
                            len(impl_code) >= 4:
                        impl_src = await cc.fetch_verified_source(
                            ctx, chain, impl, key)
                        pairs += 1
                        await self._analyze(ctx, chain, impl,
                                            impl_src,
                                            "implementation",
                                            findings)
                except Exception:
                    pass
        return pairs, done_any

    async def _analyze(self, ctx: Ctx, chain: cc.ChainConfig,
                       addr: str, src: Optional[Dict[str, Any]],
                       role: str,
                       findings: List[Finding]) -> None:
        url = cc.explorer_url(chain, addr)
        base_ev = {"address": addr, "chain": chain.id,
                   "chain_id": chain.chain_id, "contract_role": role}
        source_text = (src or {}).get("source") or ""
        if not source_text:
            ev = dict(base_ev)
            ev.update({
                "severity": "low", "reason": "no_verified_source",
                "remediation": "Verify the contract source on the "
                               "explorer, or run the bytecode "
                               "lanes (heimdall / 4byte in the audit "
                               "toolbox) for this address."})
            findings.append(self._f(
                "web3", "ast_map_not_produced",
                f"LOW: AST visual audit: no verified source for "
                f"{addr} on {chain.name}, so no structural map "
                "could be built",
                source="ast_visual_audit", source_url=url,
                confidence=100, passive=True, evidence=ev))
            return
        contract_name = str((src or {}).get("contract_name") or "")
        compile_text = scoped_compile_text(source_text,
                                           contract_name)
        solc = tb._solc_for(compile_text)
        combined = await compile_ast(compile_text, solc)
        if not combined:
            ev = dict(base_ev)
            ev.update({
                "severity": "low", "reason": "compile_failed" if solc
                else "solc_absent",
                "remediation": "Check the source compiles with the "
                               "pragma-matching solc; the map is "
                               "only produced from a successful "
                               "compilation."})
            findings.append(self._f(
                "web3", "ast_map_not_produced",
                f"LOW: AST visual audit: {'solc could not compile' if solc else 'no solc is installed for'} "
                f"{addr} on {chain.name}; no structural map "
                "produced (this is not a clean bill)",
                source="ast_visual_audit", source_url=url,
                confidence=100, passive=True, evidence=ev))
            return
        maps = build_ast_map(combined, compile_text)
        for cmap in maps:
            ev = dict(base_ev)
            ev.update({
                "severity": "low", "contract": cmap["name"],
                "contract_kind": cmap["kind"],
                "inheritance": cmap["bases"],
                "dependencies": cmap["dependencies"],
                "state_variables": cmap["state_variables"],
                "functions": cmap["functions"],
                "metrics": cmap["metrics"],
                "remediation": "Use this structural map to aim "
                               "manual review: functions that write "
                               "state and make external calls with "
                               "few modifiers are where logic bugs "
                               "live."})
            m = cmap["metrics"]
            findings.append(self._f(
                "web3", "ast_structure_map",
                f"LOW: AST map of {cmap['name']} [{addr} on "
                f"{chain.name}, {role}]: inherits "
                f"{', '.join(cmap['bases']) or 'nothing'}; "
                f"{m['functions']} function(s), "
                f"{m['state_variables']} state variable(s), "
                f"~{m['nsloc']} nSLOC, complexity "
                f"{m['complexity']}; full per-function map in "
                "evidence",
                source="ast_visual_audit", source_url=url,
                confidence=100, passive=True, evidence=ev))
            for hl in extract_highlights(cmap, compile_text):
                ev = dict(base_ev)
                ev.update({
                    "severity": "low", "contract": hl["contract"],
                    "function": hl["function"],
                    "highlight": hl["kind"],
                    "lines": [hl["line"]] if hl["line"] else [],
                    "remediation": "Structural highlight from the "
                                   "AST map: confirm reachability "
                                   "and gating in the logic lanes; "
                                   "this plugin does not raise it "
                                   "above low by design."})
                findings.append(self._f(
                    "web3", f"ast_highlight_{hl['kind']}",
                    f"LOW: {hl['message']} [{addr} on "
                    f"{chain.name}, {role}]",
                    source="ast_visual_audit", source_url=url,
                    confidence=80, passive=True, evidence=ev))
