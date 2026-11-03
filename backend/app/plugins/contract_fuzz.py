"""Contract Fuzz lane: LOCAL exploit confirmation for ONE flagged
contract at a time.

The static lanes (contract_recon, crypto_drain, contract_logic) and
the simulation lane (contract_simulation) READ code or probe it with
read-only eth_call. None of them can prove the one thing Jay's
receive rule actually asks: can a stranger, calling unauthenticated,
walk away with value that was not theirs? This lane answers that by
RUNNING the contract - locally, on this machine, against a mock
balance, never on a live chain:

1. The flagged contract's verified source is scoped the same way
   the FP-fix scope split scopes it (compilation bundle split on
   `// ==== path ====` markers, test/mock units dropped, target
   contract + ancestors kept).
2. The scoped source is compiled with a local solc (the audit-tools
   installs under ~/workspace/tools/audit + ~/.solc-select) and its
   ABI drives generation of an Echidna harness:

   - a HOUSE actor (a helper contract) seeds the target with mock
     ETH - a plain transfer, plus every zero-argument payable
     function - so the target holds value that belongs to nobody
     the fuzzer controls;
   - the harness itself is the STRANGER: it deploys the target, it
     is not the owner, it holds no position at start. Its balance
     is minted locally with the hevm `deal` cheatcode inside the
     fuzz VM only. Every public/external state-changing function
     of the target gets a wrapper the fuzzer can call;
   - wrappers do per-call balance accounting. A wrapper that sends
     value in (a deposit) builds the stranger's legitimate CLAIM;
     value that comes back is first settled against that claim.
     Only a balance increase BEYOND the claim - the stranger
     profiting from other people's money - trips the property.
     The same accounting in token terms: a `balanceOf` increase in
     a call where the stranger sent no value is free tokens.

3. Echidna fuzzes call sequences against two properties,
   `echidna_stranger_no_eth_profit` and
   `echidna_stranger_no_token_profit`. A falsified property is the
   ONLY thing this lane calls confirmed: the finding carries
   Echidna's shrunk counterexample (the ordered wrapper calls with
   arguments, translated back to target function calls) and is
   labeled fuzz_confirmed with recipient CALLER under the receive
   rule - the payout provably landed on the unauthenticated caller,
   because the harness IS an unauthenticated caller and its balance
   is the thing that grew.

Honesty discipline (the mirror of the sim lane's):

- Everything that is not a falsified property is a candidate-grade
  note at low severity, key fuzz_inconclusive, with a machine
  reason: engine_absent, solc_absent, compile_fail,
  constructor_args_unknown, unsupported_compiler (< 0.6),
  unsupported_constructor (array/tuple constructor params),
  target_not_deployable, linked_library, timeout, deploy_failed,
  no_target_contract. A fuzz run that completes with no violation
  is reported as fuzz_no_violation - coverage, not a verdict: the
  property held for the sequences tried, nothing more.
- Self-service shapes cannot confirm BY CONSTRUCTION: a stranger
  withdrawing only their own deposit settles against their own
  claim (canary C in the tests), a properly owner-gated drain
  simply reverts for the stranger (canary B), and a FIXED-recipient
  payout never moves the stranger's balance, so it never trips the
  property. The static recipient class of the culprit function
  (contract_logic.classify_recipient) is still recorded on
  confirmed findings for transparency.
- The profit flags are balance proofs, not impressions: the ETH
  flag is set only in the same transaction where the harness's
  balance grew beyond its recorded claim, and Echidna's
  counterexample is a replayable call sequence. (Echidna's text
  output does not print exact final wei balances; the flag state
  and the claim ledger are the balance evidence.)

EXECUTION-LANE GUARD (binding architecture, same as the toolbox
and the sim lane): this plugin declares lane="heavy" /
heavy_lane=True and self-gates. Heavy work runs only in an
explicitly marked heavy context (module override
contract_fuzz="heavy", a heavy-lane worker context, shared
allow_heavy, or env RECON_HEAVY_LANE=1) under the
RECON_HEAVY_TIMEOUT ceiling (config.HEAVY_TIMEOUT_S, default
1800s). From the default/fast request path it returns ONE info
note immediately: no compiles, no subprocesses. It refuses bulk
sweeps the same way the sim lane does (bulk run ids / several
discovered contracts with no explicit flag).

ENGINE: Echidna (audit tools bin/, PR #75 install). Medusa speaks
a different harness dialect (assertion mode + medusa.json) and is
NOT wired into this lane yet - stated plainly rather than implied.
Tools live OUTSIDE the app image; when the binary or a usable solc
is absent the lane reports inconclusive(engine_absent /
solc_absent) and the deployed backend is unaffected.

KNOWN LIMITS (v1): constructor arguments are defaulted (zero /
empty / the house address is never assumed); a target whose
constructor rejects defaults reports constructor_args_unknown.
solc < 0.6 targets are unsupported (the harness dialect needs
try/catch and receive()). Targets needing a pre-existing ERC20
position or a linked library report inconclusive. Only the ETH
and self-token (balanceOf) profit properties are checked.

KEYLESS / LOCAL ONLY: source comes from ctx.shared (offline
sweeps publish flagged sources) or the keyless Blockscout /
Sourcify routes in contract_chain. No transactions are ever
signed or sent; the fuzz VM is Echidna's in-process EVM.
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import config as app_config
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from . import contract_sim as cs
from . import toolbox as tb
from .cryptopack_util import keccak256

# ---------------------------------------------------------------------------
# Budgets and caps
# ---------------------------------------------------------------------------

MAX_FUZZ_TARGETS = 2         # contracts fuzzed per run, at most
MAX_WRAPPED_FUNCTIONS = 24   # target functions wrapped per harness
DEFAULT_FUZZ_TIMEOUT_S = 300.0
MIN_FUZZ_TIMEOUT_S = 10.0
MAX_FUZZ_TIMEOUT_S = 900.0
DEFAULT_TEST_LIMIT = 5000
DEFAULT_SEQ_LEN = 25

HARNESS_NAME = "ReconFuzzHarness"
HOUSE_NAME = "ReconFuzzHouse"
DEAL_WEI = 1000 * 10**18     # harness balance minted via hevm deal
SEED_WEI = 10 * 10**18       # house money seeded into the target

PROP_ETH = "echidna_stranger_no_eth_profit"
PROP_TOKEN = "echidna_stranger_no_token_profit"

_REMEDIATION_CONFIRMED = (
    "A stranger demonstrably profited from this contract in a "
    "local fuzz run: replay the counterexample sequence on a fork "
    "to double-check, then gate the culprit function the way its "
    "siblings are gated (or remove the unauthenticated payout "
    "path) and re-run the fuzz lane to confirm the fix.")
_REMEDIATION_NOTE = (
    "No action on the contract itself; this note records what "
    "the local fuzz lane did or could not do.")


def fuzz_timeout_s() -> float:
    """Per-contract Echidna budget: env RECON_FUZZ_TIMEOUT,
    default 300s, clamped to [10, 900]."""
    raw = os.environ.get("RECON_FUZZ_TIMEOUT")
    try:
        value = float(raw) if raw not in (None, "") \
            else DEFAULT_FUZZ_TIMEOUT_S
    except (TypeError, ValueError):
        value = DEFAULT_FUZZ_TIMEOUT_S
    return min(max(value, MIN_FUZZ_TIMEOUT_S), MAX_FUZZ_TIMEOUT_S)


def fuzz_test_limit() -> int:
    raw = os.environ.get("RECON_FUZZ_TEST_LIMIT")
    try:
        value = int(raw) if raw not in (None, "") \
            else DEFAULT_TEST_LIMIT
    except (TypeError, ValueError):
        value = DEFAULT_TEST_LIMIT
    return min(max(value, 100), 200000)


def fuzz_seq_len() -> int:
    raw = os.environ.get("RECON_FUZZ_SEQ_LEN")
    try:
        value = int(raw) if raw not in (None, "") else DEFAULT_SEQ_LEN
    except (TypeError, ValueError):
        value = DEFAULT_SEQ_LEN
    return min(max(value, 1), 100)


def heavy_enabled(ctx: Ctx, plugin_id: str = "contract_fuzz") -> bool:
    """Heavy-lane gate: sim-lane markers (module override /
    execution_lane / heavy_lane shared flags) or the toolbox
    markers (env RECON_HEAVY_LANE, shared allow_heavy)."""
    if cs.heavy_lane_context(ctx, plugin_id):
        return True
    if os.environ.get("RECON_HEAVY_LANE", "").lower() in (
            "1", "true", "yes"):
        return True
    shared = getattr(ctx, "shared", {}) or {}
    return bool(shared.get("allow_heavy"))


def fuzz_engine() -> Optional[str]:
    """Path to the fuzz engine binary (Echidna), or None.

    Module-level and toolbox-resolved so tests can simulate
    absence by patching this function."""
    return tb.tool_binary("echidna")


# ---------------------------------------------------------------------------
# solc resolution (audit installs + solc-select artifacts; keyless, local)
# ---------------------------------------------------------------------------

def _solc_candidates() -> List[Tuple[Tuple[int, int, int], str]]:
    """(version, path) for every locally installed solc binary."""
    out: List[Tuple[Tuple[int, int, int], str]] = []
    seen = set()

    def add(version: Tuple[int, int, int], path: str) -> None:
        if path in seen:
            return
        if os.path.isfile(path) and os.access(path, os.X_OK):
            seen.add(path)
            out.append((version, path))

    home = Path(os.path.expanduser("~"))
    for pat in (".solc-select/artifacts/solc-*",
                ".solcx/solc-v*"):
        for d in sorted(home.glob(pat)):
            m = re.search(r"(\d+)\.(\d+)\.(\d+)", d.name)
            if not m:
                continue
            ver = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            for cand in (d / f"solc-{ver[0]}.{ver[1]}.{ver[2]}",
                         d / f"solc-v{ver[0]}.{ver[1]}.{ver[2]}",
                         d / "solc"):
                if cand.is_file():
                    add(ver, str(cand))
                    break
    shim = tb.tool_binary("solc")
    if shim:
        # The solc-select shim's version is whatever `use` selected;
        # record it as newest-unknown so explicit artifacts win for
        # pragma matching and the shim is only a fallback.
        add((0, 0, 0), shim)
    which = shutil.which("solc")
    if which:
        add((0, 0, 0), which)
    return out


_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


def pragma_version(source: str) -> Optional[Tuple[int, int, int]]:
    """First concrete version mentioned by the source's pragma
    (or by a compiler-version hint string like 'v0.8.20+commit')."""
    m = _PRAGMA_RE.search(source or "")
    text = m.group(1) if m else (source or "")[:200]
    vm = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not vm:
        return None
    return (int(vm.group(1)), int(vm.group(2)),
            int(vm.group(3) or 0))


def resolve_solc(source: str = "",
                 compiler_hint: str = "") -> Optional[str]:
    """Best local solc for a source: exact major.minor artifact
    match (highest patch) first, then the newest artifact, then
    the solc-select shim / PATH solc. None when no solc exists."""
    cands = _solc_candidates()
    if not cands:
        return None
    want = pragma_version(source) or pragma_version(compiler_hint)
    real = [(v, p) for v, p in cands if v != (0, 0, 0)]
    if want and real:
        same = [(v, p) for v, p in real if v[:2] == want[:2]]
        if same:
            return max(same)[1]
        newer = [(v, p) for v, p in real if v >= want]
        if newer:
            return min(newer)[1]
    if real:
        return max(real)[1]
    return cands[0][1]


def solc_path_version(path: str) -> Optional[Tuple[int, int, int]]:
    """Version of a specific solc binary (from its artifact path,
    else (0,0,0) for shims whose version we do not parse)."""
    m = re.search(r"solc-v?(\d+)\.(\d+)\.(\d+)", path or "")
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return (0, 0, 0)


def harness_flavor(version: Optional[Tuple[int, int, int]]) -> str:
    """Solidity dialect for generated harness code: 'modern'
    (>= 0.8), 'legacy' (0.6-0.7), or 'unsupported' (< 0.6 / shim
    of unknown version is treated as modern - the VM's shim
    selects 0.8.x)."""
    if version is None or version == (0, 0, 0):
        return "modern"
    if version >= (0, 8, 0):
        return "modern"
    if version >= (0, 6, 0):
        return "legacy"
    return "unsupported"


# ---------------------------------------------------------------------------
# Bundle scope (mirrors the FP-fix scope split in contract_logic)
# ---------------------------------------------------------------------------

def _concrete_contracts(text: str) -> List[Dict[str, Any]]:
    """Concrete (deployable-shaped) contract spans in a source
    text: kind 'contract', not abstract, in declaration order."""
    clean = cc._strip_comments(text)
    out = []
    for span in cl._contract_spans(clean):
        if span["kind"] != "contract":
            continue
        decl = clean[span["start"]:span["start"] + 200]
        if re.search(r"\babstract\s+contract\b", decl):
            continue
        out.append(span)
    return out


def build_scoped_source(source: str,
                        contract_name: str = ""
                        ) -> Tuple[str, Optional[str]]:
    """Reduce a verified-source bundle to the compile unit the
    fuzz lane may build: test/mock file units dropped (same path
    rule as contract_logic), imports stripped (bundles are
    flattened; a surviving import cannot resolve locally), one
    pragma kept. Returns (scoped_source, target_contract_name).

    Target selection: the caller's hint when it names a concrete
    contract in the kept units; otherwise the LAST concrete
    contract declared across the kept units (flattened bundles put
    the deployed contract last, and single-contract sources are
    unambiguous). Ancestor contracts/interfaces/libraries stay -
    the target cannot compile without them."""
    units = cl._split_units(source or "")
    kept: List[Tuple[str, str]] = []
    for path, text in units:
        if path and cl._TEST_SEGMENT_RE.search(path.replace("\\", "/")):
            continue
        kept.append((path, text))
    if not kept:
        return "", None
    # Target name from kept units only.
    target: Optional[str] = None
    all_spans: List[Dict[str, Any]] = []
    for _path, text in kept:
        all_spans.extend(_concrete_contracts(text))
    names = [s["name"] for s in all_spans]
    if contract_name and contract_name in names:
        target = contract_name
    elif names:
        target = names[-1]
    # Assemble: strip imports, keep only the first pragma.
    pragma_seen = False
    parts: List[str] = []
    for _path, text in kept:
        lines = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("import "):
                lines.append("// (import stripped by fuzz lane)")
                continue
            if stripped.startswith("pragma solidity"):
                if pragma_seen:
                    lines.append("// (duplicate pragma stripped)")
                    continue
                pragma_seen = True
            lines.append(line)
        parts.append("\n".join(lines))
    return "\n".join(parts), target


# ---------------------------------------------------------------------------
# ABI-driven wrapper planning (pure)
# ---------------------------------------------------------------------------

SUPPORTED_PARAM_PREFIXES = (
    "address", "bool", "uint", "int", "bytes", "string")


def _param_supported(typ: str) -> bool:
    if "[" in typ or typ.startswith("tuple"):
        return False
    return any(typ == p or typ.startswith(p)
               for p in SUPPORTED_PARAM_PREFIXES)


def plan_wrappers(abi: List[Dict[str, Any]]) -> Tuple[
        List[Dict[str, Any]], List[str]]:
    """From a target ABI, plan the harness wrappers: every
    public/external state-changing function whose parameters the
    harness dialect can express. Returns (wrappers, skipped_names).
    Each wrapper: {name (target fn), signature, inputs, payable,
    wrapper (generated harness fn name)}."""
    wrappers: List[Dict[str, Any]] = []
    skipped: List[str] = []
    for entry in abi or []:
        if entry.get("type") != "function":
            continue
        mut = entry.get("stateMutability", "")
        if mut in ("view", "pure"):
            continue
        name = entry.get("name") or ""
        inputs = entry.get("inputs") or []
        types = [i.get("type", "") for i in inputs]
        if any(not _param_supported(t) for t in types):
            skipped.append(name)
            continue
        if len(wrappers) >= MAX_WRAPPED_FUNCTIONS:
            skipped.append(name)
            continue
        sig = f"{name}({','.join(types)})"
        wrappers.append({
            "name": name,
            "signature": sig,
            "inputs": inputs,
            "payable": mut == "payable",
            "wrapper": f"fz_{re.sub(r'[^A-Za-z0-9_]', '_', name)}"
                       f"_{len(wrappers)}",
        })
    return wrappers, skipped


def constructor_plan(abi: List[Dict[str, Any]]) -> Tuple[
        Optional[List[Dict[str, Any]]], str]:
    """Constructor inputs from the ABI, or (None, reason) when
    the constructor takes parameters the harness cannot default
    (arrays / tuples). Absent constructor -> ([], '')."""
    for entry in abi or []:
        if entry.get("type") == "constructor":
            inputs = entry.get("inputs") or []
            if any(not _param_supported(i.get("type", ""))
                   for i in inputs):
                return None, "unsupported_constructor"
            return inputs, ""
    return [], ""


def _default_arg(inp: Dict[str, Any]) -> str:
    typ = inp.get("type", "")
    if typ == "address":
        return "address(0)"
    if typ == "bool":
        return "false"
    if typ == "string":
        return '""'
    if typ == "bytes":
        return '""'
    if typ.startswith("bytes"):
        return f"{typ}(0)"
    return "0"


def has_balance_of(abi: List[Dict[str, Any]]) -> bool:
    for entry in abi or []:
        if entry.get("type") == "function" \
                and entry.get("name") == "balanceOf":
            ins = entry.get("inputs") or []
            if len(ins) == 1 and ins[0].get("type") == "address" \
                    and entry.get("stateMutability") in (
                        "view", "pure"):
                return True
    return False


def function_selector(sig: str) -> str:
    return "0x" + keccak256(sig.encode())[:4].hex()


# ---------------------------------------------------------------------------
# Harness generation (pure)
# ---------------------------------------------------------------------------

_HEVM_ADDR = "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D"


def _call_with_value(flavor: str, expr: str, value_expr: str,
                     args: str) -> str:
    """A value-carrying call in the harness dialect."""
    if flavor == "legacy":
        return f"{expr}.value({value_expr})({args})"
    return f"{expr}{{value: {value_expr}}}({args})"


def _arg_expr(inp: Dict[str, Any], idx: int) -> str:
    if "payable" in (inp.get("internalType") or ""):
        return f"payable(p{idx})"
    return f"p{idx}"


def generate_harness(target_name: str,
                     wrappers: List[Dict[str, Any]],
                     ctor_inputs: List[Dict[str, Any]],
                     token_mode: bool, flavor: str) -> str:
    """The Echidna project harness: house-seeded target + stranger
    accounting wrappers + the two profit properties. See the
    module docstring for the accounting argument."""
    deal = DEAL_WEI
    seed = SEED_WEI
    house_call = _call_with_value(flavor, "t.call", "msg.value", '""')
    ctor_args = ", ".join(_default_arg(i) for i in ctor_inputs)
    seed_calls = []
    for w in wrappers:
        if w["payable"] and not w["inputs"]:
            sel = function_selector(w["signature"])[2:]
            seed_calls.append(
                f"        seedFunded += "
                f"{_call_with_value(flavor, 'house.fundCall', str(seed), f'address(target), hex\"{sel}\"')};")
    lines = [
        "",
        "// ==== generated by contract_fuzz: local fuzz harness ====",
        "interface IReconHevm {",
        "    function deal(address account, uint256 amount) external;",
        "}",
        "",
        f"contract {HOUSE_NAME} {{",
        "    function fund(address t) external payable returns (uint256) {",
        f"        (bool ok, ) = {house_call};",
        "        return ok ? msg.value : 0;",
        "    }",
        "    function fundCall(address t, bytes memory data) external payable returns (uint256) {",
        f"        (bool ok, ) = {_call_with_value(flavor, 't.call', 'msg.value', 'data')};",
        "        return ok ? msg.value : 0;",
        "    }",
        "}",
        "",
        f"contract {HARNESS_NAME} {{",
        f"    IReconHevm internal constant HEVM = IReconHevm({_HEVM_ADDR});",
        f"    {target_name} public target;",
        f"    {HOUSE_NAME} public house;",
        "    bool public ethProfit;",
        "    bool public tokenProfit;",
        "    uint256 public claim;",
        "    uint256 public seedFunded;",
        f"    bool internal tokenMode = {'true' if token_mode else 'false'};",
        "",
        "    constructor() {",
        f"        HEVM.deal(address(this), {deal});",
        f"        house = new {HOUSE_NAME}();",
        f"        target = new {target_name}({ctor_args});",
        f"        seedFunded += {_call_with_value(flavor, 'house.fund', str(seed), 'address(target)')};",
    ]
    lines.extend(seed_calls)
    if token_mode:
        token_bal_body = [
            "    function _tokenBal() internal view returns (uint256) {",
            "        try target.balanceOf(address(this)) returns (uint256 v) {",
            "            return v;",
            "        } catch {",
            "            return 0;",
            "        }",
            "    }",
        ]
    else:
        # No balanceOf on the target: never reference it (the call
        # would not compile), the token property simply never trips.
        token_bal_body = [
            "    function _tokenBal() internal view returns (uint256) {",
            "        return 0;",
            "    }",
        ]
    lines += ["    }", ""] + token_bal_body + [
        "",
        "    function _settle(uint256 bBefore, uint256 tbBefore, uint256 sent) internal {",
        "        uint256 bAfter = address(this).balance;",
        "        if (bAfter > bBefore) {",
        "            uint256 gain = bAfter - bBefore;",
        "            if (gain > claim) { ethProfit = true; } else { claim -= gain; }",
        "        } else if (bBefore > bAfter) {",
        "            claim += bBefore - bAfter;",
        "        }",
        "        if (tokenMode && sent == 0 && _tokenBal() > tbBefore) {",
        "            tokenProfit = true;",
        "        }",
        "    }",
    ]
    for w in wrappers:
        params = ", ".join(
            f"{inp.get('type', 'uint256')} p{i}"
            for i, inp in enumerate(w["inputs"]))
        args = ", ".join(_arg_expr(inp, i)
                         for i, inp in enumerate(w["inputs"]))
        lines.append("")
        if w["payable"]:
            call = _call_with_value(
                flavor, f"target.{w['name']}", "msg.value", args)
            lines += [
                f"    function {w['wrapper']}({params}) external payable {{",
                "        uint256 _b = address(this).balance;",
                "        uint256 _tb = _tokenBal();",
                f"        {call};",
                "        _settle(_b, _tb, msg.value);",
                "    }",
            ]
        else:
            lines += [
                f"    function {w['wrapper']}({params}) external {{",
                "        uint256 _b = address(this).balance;",
                "        uint256 _tb = _tokenBal();",
                f"        target.{w['name']}({args});",
                "        _settle(_b, _tb, 0);",
                "    }",
            ]
    lines += [
        "",
        f"    function {PROP_ETH}() external view returns (bool) {{",
        "        return !ethProfit;",
        "    }",
        f"    function {PROP_TOKEN}() external view returns (bool) {{",
        "        return !tokenProfit;",
        "    }",
        "    receive() external payable {}",
        "}",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Compilation (local solc) + Echidna output parsing (pure)
# ---------------------------------------------------------------------------

async def compile_source(solc: str, source: str, workdir: str,
                         budget_s: float) -> Tuple[
                             Optional[Dict[str, Any]], str]:
    """Compile one Solidity file with solc --combined-json.
    Returns (contracts dict keyed 'path:Name' -> {abi, bin}, '')
    or (None, error excerpt)."""
    path = os.path.join(workdir, "Target.sol")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(source)
    rc, out, err = await tb.run_tool(
        [solc, "--combined-json", "abi,bin", path],
        cwd=workdir, budget_s=budget_s)
    if rc != 0 or not out.strip():
        return None, (err or out or "solc failed")[-1200:]
    try:
        data = json.loads(out)
        return data.get("contracts") or {}, ""
    except Exception:
        return None, (err or out)[-1200:]


_FAILED_RE = re.compile(r"^([A-Za-z0-9_]+)(?:\(\))?:\s*failed", re.M)
_PASSED_RE = re.compile(r"^([A-Za-z0-9_]+)(?:\(\))?:\s*(?:passed|passing)",
                        re.M)
_SEQ_LINE_RE = re.compile(r"^\s{2,}(\S.*\S)\s*$")
_TOTAL_CALLS_RE = re.compile(r"Total calls:\s*(\d+)")
_SEED_RE = re.compile(r"Seed:\s*(\d+)")


def parse_echidna_output(text: str) -> Dict[str, Any]:
    """Echidna text output -> {failed: {prop: {call_sequence,
    reason}}, passed: [prop], deploy_failed, total_calls, seed}.

    The shrunk counterexample follows a failed property line:
    'Call sequence:' then indented 'Harness.fn(args)' lines."""
    text = text or ""
    failed: Dict[str, Any] = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _FAILED_RE.match(line.strip())
        if not m:
            continue
        prop = m.group(1)
        seq: List[str] = []
        reason = ""
        j = i + 1
        in_seq = False
        while j < len(lines) and j < i + 60:
            cur = lines[j]
            if "Call sequence" in cur:
                in_seq = True
                j += 1
                continue
            if in_seq:
                sm = _SEQ_LINE_RE.match(cur)
                if sm and "(" in cur and ")" in cur:
                    seq.append(sm.group(1).strip())
                    j += 1
                    continue
                if cur.strip() == "":
                    break
                break
            if "Reason:" in cur:
                reason = cur.split("Reason:", 1)[1].strip()
            j += 1
        failed[prop] = {"call_sequence": seq, "reason": reason}
    tc = _TOTAL_CALLS_RE.search(text)
    sd = _SEED_RE.search(text)
    return {
        "failed": failed,
        "passed": sorted(set(_PASSED_RE.findall(text))),
        "deploy_failed": "Deploying the contract" in text
                         and "failed" in text,
        "total_calls": int(tc.group(1)) if tc else 0,
        "seed": int(sd.group(1)) if sd else None,
    }


# ---------------------------------------------------------------------------
# Finding helpers shared by the plugin paths
# ---------------------------------------------------------------------------

def translate_sequence(call_sequence: List[str],
                       wrappers: List[Dict[str, Any]]) -> List[str]:
    """Translate Echidna's shrunk call sequence (harness wrapper
    calls) back to target function calls, keeping the arguments
    Echidna printed. Unknown lines pass through unchanged."""
    by_wrapper = {w["wrapper"]: w for w in wrappers}
    out: List[str] = []
    for call in call_sequence or []:
        m = re.match(r"(?:[A-Za-z0-9_]+\.)?([A-Za-z0-9_]+)\((.*)\)\s*$",
                     call.strip())
        if m and m.group(1) in by_wrapper:
            w = by_wrapper[m.group(1)]
            out.append(f"{w['name']}({m.group(2)})"
                       f" [target {w['signature']} via {m.group(1)}]")
        else:
            out.append(call)
    return out


def static_recipient_of(scoped_source: str,
                        fn_name: str) -> Tuple[str, str]:
    """contract_logic.classify_recipient on one function's source
    text (transparency field on confirmed findings)."""
    if not fn_name:
        return "UNRESOLVED", "no culprit function identified"
    try:
        for fn in cc.extract_functions(scoped_source):
            if fn.get("name") == fn_name:
                return cl.classify_recipient(fn.get("text", ""))
    except Exception:
        pass
    return "UNRESOLVED", "culprit function text not found in scope"


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class ContractFuzzPlugin(Plugin):
    id = "contract_fuzz"
    label = "Contract Fuzz Lane (Local Exploit Confirmation)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = False  # runs the contract locally in a fuzz VM
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []  # keyless: local solc + local Echidna only
    description = (
        "HEAVY LANE ONLY. Local exploit-confirmation fuzzing of "
        "ONE flagged contract: the verified source is scoped "
        "(bundle split, test/mock units dropped), compiled with a "
        "local solc, and deployed inside an Echidna harness where "
        "a HOUSE actor seeds it with mock ETH and an unauthenticated "
        "STRANGER (the harness) fuzz-calls every public "
        "state-changing function under per-call balance accounting. "
        "Only a falsified no-stranger-profit property (ETH or "
        "self-token) is reported, as fuzz_confirmed with Echidna's "
        "shrunk counterexample and recipient CALLER; everything "
        "else is a low-severity fuzz_inconclusive note with a "
        "machine reason (compile fail, constructor args, timeout, "
        "engine absent). Runs only in an explicitly marked heavy "
        "context under the RECON_HEAVY_TIMEOUT ceiling; refuses "
        "bulk sweeps. Local VM only - no transactions, no live "
        "chain calls beyond keyless source fetch.")
    phase = 2
    lane = "heavy"
    heavy_lane = True
    timeout_s = 1800

    # Tests may set instance budgets; production leaves them None
    # and the env/config resolution applies.
    budget_s: Optional[float] = None
    fuzz_timeout_s_attr: Optional[float] = None
    test_limit_attr: Optional[int] = None
    seq_len_attr: Optional[int] = None

    def _budget(self) -> float:
        if self.budget_s is not None:
            return min(max(float(self.budget_s), 1.0), 3600.0)
        return min(max(float(getattr(app_config, "HEAVY_TIMEOUT_S",
                                      1800.0)), 1.0), 3600.0)

    def _fuzz_timeout(self) -> float:
        if self.fuzz_timeout_s_attr is not None:
            return min(max(float(self.fuzz_timeout_s_attr),
                           MIN_FUZZ_TIMEOUT_S), MAX_FUZZ_TIMEOUT_S)
        return fuzz_timeout_s()

    def _test_limit(self) -> int:
        if self.test_limit_attr is not None:
            return min(max(int(self.test_limit_attr), 100), 200000)
        return fuzz_test_limit()

    def _seq_len(self) -> int:
        if self.seq_len_attr is not None:
            return min(max(int(self.seq_len_attr), 1), 100)
        return fuzz_seq_len()

    # -- notes ------------------------------------------------------
    def _note(self, text: str, prefix: str = "LOW") -> Finding:
        return self._f(
            "web3", "contract_fuzz_note", f"{prefix}: {text}",
            source="contract fuzz lane", confidence=70, passive=True,
            evidence={"severity": "low",
                      "remediation": _REMEDIATION_NOTE})

    def _inconclusive(self, label: str, target_name: str,
                      reason_code: str, detail: str,
                      extra: Optional[Dict[str, Any]] = None) -> Finding:
        ev: Dict[str, Any] = {
            "severity": "low",
            "fuzz_attempted": True,
            "fuzz_inconclusive": reason_code,
            "reason": detail,
            "recipient": "UNRESOLVED",
            "report_class": "candidate",
            "review_status": "inconclusive - not a verdict",
            "engine": "echidna",
            "remediation": _REMEDIATION_NOTE,
        }
        if extra:
            ev.update(extra)
        return self._f(
            "web3", "fuzz_inconclusive",
            f"{label}: local fuzzing inconclusive ({reason_code}): "
            f"{detail}", source="contract fuzz lane",
            confidence=60, evidence=ev, passive=False)

    # -- target collection ------------------------------------------
    def _collect(self, target: Target, ctx: Ctx) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        seen = set()

        def add(item: Dict[str, Any]) -> None:
            src = item.get("source") or ""
            addr = (item.get("address") or "").strip()
            key = (addr.lower() if addr else
                   f"src:{hash(src) & 0xffffffff:x}")
            if key in seen:
                return
            seen.add(key)
            items.append(item)

        for kind in ("fuzz_candidates", "sim_candidates"):
            for item in ctx.consume(kind):
                if isinstance(item, dict) and item.get("source"):
                    add({"address": str(item.get("address", "")),
                         "chain": item.get("chain"),
                         "source": str(item["source"]),
                         "contract_name":
                             str(item.get("contract_name", "")),
                         "compiler": str(item.get("compiler", ""))})
        shared = getattr(ctx, "shared", {}) or {}
        fs = shared.get("fuzz_source")
        if isinstance(fs, str) and fs.strip():
            add({"address": "", "chain": None, "source": fs,
                 "contract_name": "", "compiler": ""})
        elif isinstance(fs, dict) and fs.get("source"):
            add({"address": str(fs.get("address", "")),
                 "chain": fs.get("chain"),
                 "source": str(fs["source"]),
                 "contract_name": str(fs.get("contract_name", "")),
                 "compiler": str(fs.get("compiler", ""))})
        for raw in (target.normalized, target.raw):
            _hint, addr = cc.parse_target_address(raw or "")
            if addr:
                add({"address": addr, "chain": _hint, "source": "",
                     "contract_name": "", "compiler": ""})
                break
        return items

    # -- main ---------------------------------------------------------
    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if not heavy_enabled(ctx, self.id):
            text = (
                "fuzz lane stayed off: this run is not marked as a "
                "heavy-lane context, and local contract fuzzing "
                "never runs inside the default request path. Re-run "
                "in the heavy lane (module override "
                "contract_fuzz=\"heavy\", a heavy-lane worker "
                "context, shared allow_heavy, or RECON_HEAVY_LANE=1) "
                "where the RECON_HEAVY_TIMEOUT ceiling applies.")
            res = self._ok([self._note(text, prefix="INFO")], text)
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        deadline = t0 + self._budget()
        items = self._collect(target, ctx)
        if not items:
            res = self._skipped(
                "no contract to fuzz: name a contract address as "
                "the target, or let a static lane flag one with its "
                "source (ctx.shared fuzz_candidates / fuzz_source)")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        rid = (getattr(ctx, "run_id", "") or "").lower()
        has_inline = any(i.get("source") for i in items)
        if not has_inline and any(
                m in rid for m in ("bulk", "sweep", "mass",
                                   "scan-1000", "scan-1m")):
            text = (f"run id '{ctx.run_id}' marks a bulk sweep: "
                    "the fuzz lane never runs inside bulk sweeps. "
                    "Flag a single contract (with source) first.")
            res = self._ok([self._note(text)], text)
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        work = items[:MAX_FUZZ_TARGETS]
        if len(items) > len(work):
            findings.append(self._note(
                f"{len(items)} contracts were flagged for fuzzing; "
                f"the lane runs at most {MAX_FUZZ_TARGETS} per run. "
                "Name one contract to fuzz the rest."))
        for item in work:
            if time.monotonic() > deadline - 10:
                findings.append(self._note(
                    "heavy-lane budget exhausted before every "
                    "flagged contract could be fuzzed."))
                break
            try:
                if item.get("source"):
                    await self._fuzz_source(item, findings, deadline)
                else:
                    await self._fuzz_address(ctx, item, findings,
                                             deadline)
            except Exception as exc:  # a plugin never throws fatally
                label = item.get("address") or "inline source"
                findings.append(self._inconclusive(
                    label, "", "internal_error",
                    f"{type(exc).__name__}: {exc}"))
        res = self._ok(findings,
                       f"fuzz lane: {len(work)} contract(s) processed")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    # -- address path: keyless source fetch, then the source path ----
    async def _fuzz_address(self, ctx: Ctx, item: Dict[str, Any],
                            findings: List[Finding],
                            deadline: float) -> None:
        addr = item["address"]
        chain_ids = [item["chain"]] if item.get("chain") in cc.CHAINS \
            else list(cc.DEFAULT_CHAIN_ORDER)
        for cid in chain_ids:
            chain = cc.CHAINS[cid]
            try:
                code = await cc.rpc_get_code(ctx, chain, addr)
            except Exception:
                code = None
            if code is None or code == "0x" or len(code) < 4:
                continue
            src = await cc.fetch_verified_source(ctx, chain, addr,
                                                 None)
            if not src:
                findings.append(self._inconclusive(
                    addr, "", "no_verified_source",
                    "no verified source on the keyless Blockscout / "
                    "Sourcify routes, so there is nothing to compile "
                    "and fuzz locally"))
                return
            item = dict(item, source=src.get("source", ""),
                        contract_name=src.get("contract_name", ""),
                        compiler=src.get("compiler", ""))
            await self._fuzz_source(item, findings, deadline)
            return
        findings.append(self._inconclusive(
            addr, "", "no_contract_code",
            "no contract code found on any supported chain, or "
            "every chain route failed"))


    # -- source path: scope, compile, harness, fuzz -------------------
    async def _fuzz_source(self, item: Dict[str, Any],
                           findings: List[Finding],
                           deadline: float) -> None:
        label = item.get("address") or "inline source"
        source = item.get("source") or ""
        scoped, target_name = build_scoped_source(
            source, item.get("contract_name", ""))
        if not scoped or not target_name:
            findings.append(self._inconclusive(
                label, "", "no_target_contract",
                "no concrete contract found in the scoped source "
                "(bundle split dropped every unit, or only "
                "interfaces/libraries are present)"))
            return
        solc = resolve_solc(scoped, item.get("compiler", ""))
        if not solc:
            findings.append(self._inconclusive(
                label, target_name, "solc_absent",
                "no local solc binary (audit tools / solc-select "
                "artifacts) is installed on this machine"))
            return
        version = pragma_version(scoped) \
            or solc_path_version(solc)
        flavor = harness_flavor(version)
        if flavor == "unsupported":
            findings.append(self._inconclusive(
                label, target_name, "unsupported_compiler",
                f"source targets solc {version[0]}.{version[1]}."
                f"{version[2]}; the fuzz harness dialect needs "
                ">= 0.6 (try/catch + receive())"))
            return
        engine = fuzz_engine()
        if not engine:
            findings.append(self._inconclusive(
                label, target_name, "engine_absent",
                "Echidna binary not found (audit tools bin/ or "
                "PATH); the deployed backend carries no fuzz "
                "engine, so nothing ran"))
            return

        workdir = tempfile.mkdtemp(prefix="reconfuzz-")
        try:
            remaining = deadline - time.monotonic()
            contracts, err = await compile_source(
                solc, scoped, workdir,
                budget_s=min(120.0, max(10.0, remaining)))
            if contracts is None:
                findings.append(self._inconclusive(
                    label, target_name, "compile_fail",
                    "solc rejected the scoped source: "
                    + (err.splitlines()[-1] if err else "unknown"),
                    {"solc_error_tail": err}))
                return
            entry = None
            for key, val in contracts.items():
                if key.rsplit(":", 1)[-1] == target_name:
                    entry = val
                    break
            if entry is None:
                findings.append(self._inconclusive(
                    label, target_name, "no_target_contract",
                    f"solc output has no contract named "
                    f"{target_name}"))
                return
            bytecode = entry.get("bin") or ""
            if not bytecode:
                findings.append(self._inconclusive(
                    label, target_name, "target_not_deployable",
                    f"{target_name} produced no bytecode (abstract "
                    "contract or interface)"))
                return
            if "__" in bytecode:
                findings.append(self._inconclusive(
                    label, target_name, "linked_library",
                    f"{target_name} needs a linked library; v1 of "
                    "the lane does not deploy library-linked "
                    "targets"))
                return
            abi_raw = entry.get("abi") or []
            abi = json.loads(abi_raw) if isinstance(abi_raw, str) \
                else abi_raw
            ctor_inputs, ctor_reason = constructor_plan(abi)
            if ctor_inputs is None:
                findings.append(self._inconclusive(
                    label, target_name, ctor_reason,
                    "the constructor takes array/tuple parameters "
                    "the harness cannot default"))
                return
            wrappers, skipped = plan_wrappers(abi)
            if not wrappers:
                findings.append(self._inconclusive(
                    label, target_name, "no_wrappable_functions",
                    "no public/external state-changing function "
                    "with harness-expressible parameters exists to "
                    "fuzz"))
                return
            token_mode = has_balance_of(abi)
            harness = generate_harness(target_name, wrappers,
                                       ctor_inputs, token_mode,
                                       flavor)
            project = scoped.rstrip() + "\n" + harness
            with open(os.path.join(workdir, "FuzzProject.sol"),
                      "w", encoding="utf-8") as fh:
                fh.write(project)
            seed = random.getrandbits(48)
            cfg_lines = ["testMode: \"property\"",
                         f"testLimit: {self._test_limit()}",
                         f"seqLen: {self._seq_len()}"]
            if solc_path_version(solc) != (0, 0, 0):
                cfg_lines += ["cryticArgs:", f"  - \"--solc\"",
                              f"  - \"{solc}\""]
            with open(os.path.join(workdir, "echidna.yaml"),
                      "w", encoding="utf-8") as fh:
                fh.write("\n".join(cfg_lines) + "\n")
            remaining = deadline - time.monotonic()
            budget = min(self._fuzz_timeout(),
                         max(10.0, remaining))
            rc, out, err = await tb.run_tool(
                [engine, "FuzzProject.sol", "--contract",
                 HARNESS_NAME, "--config", "echidna.yaml",
                 "--seed", str(seed)],
                cwd=workdir, budget_s=budget)
            text = (out or "") + "\n" + (err or "")
            if rc == -1:
                findings.append(self._inconclusive(
                    label, target_name, "timeout",
                    f"Echidna exceeded its {budget:.0f}s budget "
                    f"(testLimit {self._test_limit()}, seqLen "
                    f"{self._seq_len()}) without a verdict",
                    {"echidna_seed": seed}))
                return
            parsed = parse_echidna_output(text)
            if parsed["deploy_failed"]:
                code = "constructor_args_unknown" if ctor_inputs \
                    else "deploy_failed"
                findings.append(self._inconclusive(
                    label, target_name, code,
                    "the harness deployment reverted: the target "
                    "could not be deployed with defaulted "
                    "constructor arguments"
                    if ctor_inputs else
                    "the harness deployment reverted",
                    {"echidna_seed": seed}))
                return
            if parsed["failed"]:
                for prop, info in parsed["failed"].items():
                    findings.append(self._confirmed(
                        item, target_name, scoped, wrappers, prop,
                        info, seed, parsed, skipped))
                return
            if parsed["total_calls"] or parsed["passed"]:
                ev = {"severity": "low",
                      "fuzz_attempted": True,
                      "fuzz_completed": True,
                      "total_calls": parsed["total_calls"],
                      "echidna_seed": seed,
                      "properties": [PROP_ETH, PROP_TOKEN],
                      "wrapped_functions": len(wrappers),
                      "skipped_functions": skipped,
                      "recipient": "UNRESOLVED",
                      "report_class": "no_violation",
                      "review_status": "property held for the "
                                       "sequences tried - coverage, "
                                       "not a verdict",
                      "remediation": _REMEDIATION_NOTE}
                findings.append(self._f(
                    "web3", "fuzz_no_violation",
                    f"{label} ({target_name}): local fuzzing "
                    f"completed ({parsed['total_calls']} calls, "
                    f"{len(wrappers)} functions wrapped); the "
                    "stranger never profited beyond their own "
                    "deposits", source="contract fuzz lane",
                    confidence=70, evidence=ev, passive=False))
                return
            findings.append(self._inconclusive(
                label, target_name, "echidna_error",
                "Echidna produced no recognizable verdict: "
                + (text.strip().splitlines()[-1]
                   if text.strip() else "empty output"),
                {"echidna_seed": seed,
                 "echidna_output_tail": text[-1200:]}))
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # -- confirmed finding ---------------------------------------------
    def _confirmed(self, item: Dict[str, Any], target_name: str,
                   scoped: str, wrappers: List[Dict[str, Any]],
                   prop: str, info: Dict[str, Any], seed: int,
                   parsed: Dict[str, Any],
                   skipped: List[str]) -> Finding:
        label = item.get("address") or "inline source"
        kind = "ETH" if prop == PROP_ETH else "token"
        translated = translate_sequence(info.get("call_sequence"),
                                        wrappers)
        by_wrapper = {w["wrapper"]: w for w in wrappers}
        culprit_name = ""
        culprit_sig = ""
        for call in reversed(info.get("call_sequence") or []):
            m = re.match(r"(?:[A-Za-z0-9_]+\.)?([A-Za-z0-9_]+)\(",
                         call.strip())
            if m and m.group(1) in by_wrapper:
                culprit_name = by_wrapper[m.group(1)]["name"]
                culprit_sig = by_wrapper[m.group(1)]["signature"]
                break
        recip_static, recip_detail = static_recipient_of(
            scoped, culprit_name)
        seq_text = " -> ".join(translated[:8]) or "(empty sequence)"
        ev = {
            "severity": "high",
            "fuzz_confirmed": True,
            "property": prop,
            "profit_kind": kind,
            "counterexample": translated,
            "counterexample_raw": info.get("call_sequence"),
            "culprit_function": culprit_sig or culprit_name,
            "recipient": "CALLER",
            "recipient_static": recip_static,
            "recipient_static_detail": recip_detail,
            "report_class": "fuzz_confirmed",
            "review_status": "fuzz-confirmed in a local VM - "
                             "human review before external "
                             "reporting",
            "engine": "echidna",
            "echidna_seed": seed,
            "seed_eth_per_attempt": SEED_WEI // 10**18,
            "house_seeded": True,
            "stranger_model": "harness contract: unauthenticated "
                              "caller, no owner role, no starting "
                              "position; house funds are a separate "
                              "actor's money",
            "exploitability": "public_poc",
            "remediation": _REMEDIATION_CONFIRMED,
            "skipped_functions": skipped,
        }
        return self._f(
            "web3", "fuzz_confirmed_stranger_profit",
            f"{label} ({target_name}): STRANGER PROFIT CONFIRMED "
            f"by local fuzzing - an unauthenticated caller took "
            f"{kind} value beyond anything they deposited via "
            f"{culprit_sig or culprit_name or 'a public function'}. "
            f"Counterexample: {seq_text}",
            source="echidna (local fuzz lane)", confidence=95,
            evidence=ev, passive=False, bounty_value="high")
