"""Contract Simulation lane: read-only fuzzing + optional symbolic
execution for ONE explicitly targeted (or static-lane-flagged)
contract at a time.

The static lanes (contract_recon, crypto_drain, the guard hunter)
READ code. This lane is the first one that RUNS it - in simulation
only:

- Fuzzing: every public/external state-changing function from the
  verified source is probed with eth_call (a node's local, read-only
  simulation - it never mines, never persists, never moves value)
  using boundary inputs (0, 1, max uint, the fuzz caller, the
  contract itself) from an unfunded, unrelated caller address with
  value 0. The plugin records which calls unexpectedly SUCCEED
  versus revert, and cross-checks successes against the gate the
  source implies (see below). Success alone is never a finding: a
  legitimately public function succeeding is correct behavior.

- Symbolic execution (optional, OFF by default): when the env flag
  RECON_SIM_SYMBOLIC=1 is set AND an external Mythril binary is
  available (separate venv outside the app image, see find_mythril),
  the verified source is analyzed with bounded search and a hard
  timeout, and Mythril's issues are mapped into the same finding
  schema with source "mythril". Mythril and any compiler toolchain
  are deliberately NOT bundled into the app image; the adapter only
  detects a preinstalled external binary and skips when absent.
  When Mythril is not installed the lane says so in a note finding;
  it never claims symbolic coverage that did not run.

Gate cross-check (false-positive discipline, mirroring
crypto_drain): a fuzz success becomes a candidate only when the
source says the function should NOT be freely callable:

- its name is in a privileged category (mint, withdraw/sweep,
  pause, blacklist, owner/admin - contract_recon's own rules) and
  it carries NO access gate, yet the call succeeded for a random
  caller; or
- it DOES carry a gate in source, is privileged and moves value,
  yet the call still succeeded for a random caller (the gate as
  deployed does not stop an arbitrary caller - e.g. it compares
  against a value the caller controls); or
- it breaks the contract's own gate convention: most sibling
  state-changing functions are gated, this one writes state with
  no gate, and the call succeeded.

Payable purchase flows are excluded the same way crypto_drain
excludes them: when a payable function's payout derives from
msg.value, a value-0 success that does not touch the contract's
pre-existing balance (address(this).balance) is a public purchase
path, not a finding. All fuzz probes send value 0, so a genuine
pay-to-mint/buy path reverts or pays out nothing in simulation.

Every fuzz/symbolic flag is a CANDIDATE: labeled
simulation_candidate, review_status pending human review, severity
capped at high - the same honesty discipline as the zero-day
hunters (PR #72). A candidate is a lead for a fork replay by a
human, never a verdict.

EXECUTION-LANE GUARD (binding architecture): heavy analysis does
not live under the default request-path timeout
(config.DEFAULT_TIMEOUT = RECON_TIMEOUT, 20s by default). This
plugin declares ``heavy_lane`` and, before collecting targets or
touching the chain, checks that the context was explicitly marked
heavy: ``execution_lane == "heavy"`` on the context or shared bus,
``heavy_lane is True`` on the shared bus, or the per-plugin module
override ``contract_simulation == "heavy"``. The runner grants the
separate RECON_HEAVY_TIMEOUT budget (default 120s, hard cap 300s)
only in that context. From any fast/default or bulk context the
plugin returns ONE refusal/info finding immediately and performs
no chain reads and no probes.

COST GUARD (hard rule): even inside the heavy lane, simulation is
expensive, so this lane refuses bulk contexts. It runs only when
the contract is the scan target itself (explicitly targeted), is
named in ctx.shared["sim_candidates"] (flagged by a static lane),
or is the single contract a static lane published for the target.
Bulk markers in the run context (shared bulk/sweep flags,
bulk/sweep run ids) or several discovered contracts with no
explicit target produce ONE note finding (severity low) and no
probes.

KEYLESS BOUNDARY: source is fetched with NO Etherscan key (the
fetch is deliberately called with key=None, so only the keyless
Blockscout and Sourcify routes in contract_chain can answer), and
probes are read-only eth_call calls through public explorer/RPC
HTTPS endpoints. No local node is used. No transactions are ever
signed or sent, no funded key exists in this lane, and probes use
one fixed unfunded caller address with value 0.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import config as app_config
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import crypto_drain as cd
from .cryptopack_util import keccak256
from .zeroday_util import candidate_evidence

# ---------------------------------------------------------------------------
# Budgets and caps (the cost guard)
# ---------------------------------------------------------------------------

DEFAULT_BUDGET_S = 120.0
HARD_CAP_BUDGET_S = 300.0
HEAVY_TIMEOUT_ENV = "RECON_HEAVY_TIMEOUT"


def heavy_timeout_s() -> float:
    """The heavy lane's configured budget (RECON_HEAVY_TIMEOUT).

    Defaults to 120s and is clamped to the 300s hard cap. This is
    intentionally separate from config.DEFAULT_TIMEOUT
    (RECON_TIMEOUT, 20s by default): that fast request-path budget
    never governs this lane.
    """
    raw = os.environ.get(HEAVY_TIMEOUT_ENV)
    try:
        value = float(raw) if raw not in (None, "") \
            else float(getattr(app_config, "HEAVY_TIMEOUT",
                               DEFAULT_BUDGET_S))
    except (TypeError, ValueError):
        value = DEFAULT_BUDGET_S
    return min(max(value, 1.0), HARD_CAP_BUDGET_S)


def heavy_lane_context(ctx: Ctx,
                       plugin_id: str = "contract_simulation") -> bool:
    """Whether `ctx` explicitly marks the heavy execution lane.

    Accepted markers (any one): an ``execution_lane`` attribute or
    shared-bus value of "heavy", a shared ``heavy_lane is True``
    flag, a shared ``lane == "heavy"`` value, or the per-plugin
    module override ``<plugin_id> == "heavy"`` (the existing API's
    queue_meta module_overrides pathway). Ordinary/default contexts
    carry none of these and are fast-lane by definition.
    """
    if getattr(ctx, "execution_lane", "") == "heavy":
        return True
    shared = getattr(ctx, "shared", {}) or {}
    if shared.get("heavy_lane") is True \
            or shared.get("execution_lane") == "heavy" \
            or shared.get("lane") == "heavy":
        return True
    overrides = getattr(ctx, "module_overrides", {}) or {}
    return overrides.get(plugin_id) == "heavy"
MAX_SIM_TARGETS = 2        # contracts simulated per run, at most
MAX_FUZZ_FUNCTIONS = 12    # functions probed per contract
MAX_CASES_PER_FUNCTION = 8
MAX_PROBES_PER_CONTRACT = 48
_PROBE_TIMEOUT_S = 30.0  # one eth_call may walk several routes

# The one and only simulation caller: an unfunded, unrelated address.
# Probes ask "can ANYONE call this?" - the caller must control
# nothing and own nothing.
FUZZ_CALLER = "0x00000000000000000000000000000000deaDBeef"

_REMEDIATION = (
    "Treat this as an unproven lead: replay the call on a fork "
    "from an unrelated address and confirm what it does. If an "
    "arbitrary caller really can invoke it, add the access gate "
    "its siblings use (or the gate its own source implies); if it "
    "is intentionally public, document why next to the function.")

_BULK_MARKERS = ("bulk", "sweep", "mass")


# ---------------------------------------------------------------------------
# ABI encoding (just enough for eth_call fuzz inputs)
# ---------------------------------------------------------------------------

def canonical_signature(name: str, types: List[str]) -> str:
    return f"{name}({','.join(types)})"


def function_selector(signature: str) -> str:
    """0x + first 4 bytes of keccak256(signature)."""
    return "0x" + keccak256(signature.encode())[:4].hex()


def _word(n: int) -> str:
    return "%064x" % (n % (1 << 256))


def _encode_static(typ: str, value: Any) -> str:
    if typ == "address":
        v = str(value).lower()
        if v.startswith("0x"):
            v = v[2:]
        return "0" * 24 + v.rjust(40, "0")[:40]
    if typ == "bool":
        return _word(1 if value else 0)
    if typ.startswith("bytes"):  # bytesN, fixed size
        b = bytes(value)
        return b.hex().ljust(64, "0")[:64]
    # uintN / intN (two's complement via the modulo in _word)
    return _word(int(value))


# Type tree: ("base", name) | ("array", elem_node, size|None)
# | ("tuple", (member_node, ...)). size None = dynamic array.
def _parse_type_at(s: str, i: int):
    if i >= len(s):
        raise ValueError("unexpected end of type")
    if s[i] == "(":
        i += 1
        members = []
        if i < len(s) and s[i] == ")":
            raise ValueError("empty tuple")
        while True:
            member, i = _parse_type_at(s, i)
            members.append(member)
            if i < len(s) and s[i] == ",":
                i += 1
                continue
            if i < len(s) and s[i] == ")":
                i += 1
                break
            raise ValueError("malformed tuple type")
        node: Any = ("tuple", tuple(members))
    elif s.startswith("tuple", i) and i + 5 < len(s) \
            and s[i + 5] == "(":
        node, i = _parse_type_at(s, i + 5)
    else:
        m = re.match(r"[A-Za-z][A-Za-z0-9]*", s[i:])
        if not m:
            raise ValueError("malformed base type")
        name = m.group(0)
        if name == "uint":
            name = "uint256"
        elif name == "int":
            name = "int256"
        elif name == "byte":
            name = "bytes1"
        i += len(m.group(0))
        node = ("base", name)
    while i < len(s) and s[i] == "[":
        j = s.find("]", i)
        if j < 0:
            raise ValueError("malformed array type")
        inside = s[i + 1:j]
        if inside and not inside.isdigit():
            raise ValueError("malformed array size")
        node = ("array", node, None if inside == "" else int(inside))
        i = j + 1
    return node, i


def _validate_node(node: Any) -> bool:
    kind = node[0]
    if kind == "base":
        name = node[1]
        if name in ("address", "bool", "string", "bytes"):
            return True
        if re.fullmatch(r"bytes\d+", name):
            return 1 <= int(name[5:]) <= 32
        if re.fullmatch(r"uint\d+", name):
            n = int(name[4:])
            return 8 <= n <= 256 and n % 8 == 0
        if re.fullmatch(r"int\d+", name):
            n = int(name[3:])
            return 8 <= n <= 256 and n % 8 == 0
        return False
    if kind == "array":
        return _validate_node(node[1])
    if kind == "tuple":
        return bool(node[1]) and all(_validate_node(m) for m in node[1])
    return False


def _parse_type_str(s: str):
    """Parse a canonical type string to a node tree, or None."""
    try:
        compact = "".join(str(s).split())
        if not compact:
            return None
        node, pos = _parse_type_at(compact, 0)
        if pos != len(compact) or not _validate_node(node):
            return None
        return node
    except Exception:
        return None


def _node_str(node: Any) -> str:
    kind = node[0]
    if kind == "base":
        return node[1]
    if kind == "tuple":
        return "(" + ",".join(_node_str(m) for m in node[1]) + ")"
    # array: suffix attaches to the element rendering
    return _node_str(node[1]) + "[" + \
        ("" if node[2] is None else str(node[2])) + "]"


def _is_dynamic(node: Any) -> bool:
    kind = node[0]
    if kind == "base":
        return node[1] in ("bytes", "string")
    if kind == "array":
        return node[2] is None or _is_dynamic(node[1])
    return any(_is_dynamic(m) for m in node[1])  # tuple


def _static_size(node: Any) -> int:
    kind = node[0]
    if kind == "base":
        return 32
    if kind == "array":
        return int(node[2]) * _static_size(node[1])
    return sum(_static_size(m) for m in node[1])  # tuple


def _word_bytes(n: int) -> bytes:
    return (n % (1 << 256)).to_bytes(32, "big")


def _encode_node(node: Any, value: Any) -> bytes:
    kind = node[0]
    if kind == "base":
        name = node[1]
        if name == "string":
            data = value if isinstance(value, bytes) \
                else str(value).encode()
            pad = ((len(data) + 31) // 32) * 32
            return _word_bytes(len(data)) + data.ljust(pad, b"\x00")
        if name == "bytes":
            if isinstance(value, (bytes, bytearray)):
                data = bytes(value)
            elif isinstance(value, str) \
                    and value.startswith("0x"):
                data = bytes.fromhex(value[2:])
            else:
                data = str(value).encode()
            pad = ((len(data) + 31) // 32) * 32
            return _word_bytes(len(data)) + data.ljust(pad, b"\x00")
        return bytes.fromhex(_encode_static(name, value))
    if kind == "array":
        elem, size = node[1], node[2]
        vals = list(value)
        if size is None:
            return _word_bytes(len(vals)) + \
                _encode_seq([elem] * len(vals), vals)
        if len(vals) != size:
            raise ValueError("fixed array length mismatch")
        return _encode_seq([elem] * size, vals)
    # tuple
    return _encode_seq(list(node[1]), list(value))


def _encode_seq(nodes: List[Any], values: List[Any]) -> bytes:
    if len(nodes) != len(values):
        raise ValueError("arity mismatch")
    head_size = sum(32 if _is_dynamic(n) else _static_size(n)
                    for n in nodes)
    heads: List[bytes] = []
    tails: List[bytes] = []
    offset = head_size
    for node, value in zip(nodes, values):
        if _is_dynamic(node):
            heads.append(_word_bytes(offset))
            tail = _encode_node(node, value)
            tails.append(tail)
            offset += len(tail)
        else:
            heads.append(_encode_node(node, value))
    return b"".join(heads + tails)


def encode_call_args(types: List[str], values: List[Any]) -> Optional[str]:
    """ABI-encode arguments. Returns hex (no 0x) or None when a type
    cannot be parsed - those functions are skipped, never probed
    with malformed calldata. Supports base types, bytes/string,
    fixed/dynamic arrays and tuples, arbitrarily nested."""
    if len(types) != len(values):
        return None
    nodes = []
    for typ in types:
        node = _parse_type_str(typ)
        if node is None:
            return None
        nodes.append(node)
    try:
        return _encode_seq(nodes, list(values)).hex()
    except Exception:
        return None


def _default_for_node(node: Any) -> Any:
    kind = node[0]
    if kind == "array":
        if node[2] is None:
            return []
        return [_default_for_node(node[1]) for _ in range(node[2])]
    if kind == "tuple":
        return tuple(_default_for_node(m) for m in node[1])
    return _default_value(node[1])


def _default_value(typ: str) -> Any:
    node = _parse_type_str(typ)
    if node is not None and node[0] != "base":
        return _default_for_node(node)
    if typ == "address":
        return cc.ZERO_ADDRESS
    if typ == "bool":
        return False
    if typ in ("bytes", "string"):
        return b"" if typ == "bytes" else ""
    if typ.startswith("bytes"):
        return b"\x00" * 32
    return 0


def _boundary_values(typ: str, contract_addr: str) -> List[Any]:
    """Boundary inputs per type (the default/zero case is separate)."""
    node = _parse_type_str(typ)
    if node is not None and node[0] == "array":
        elem_default = _default_for_node(node[1])
        if node[2] is None:
            return [[elem_default]]
        return [[elem_default] * node[2]]
    if node is not None and node[0] == "tuple":
        return [tuple(_default_for_node(m) for m in node[1])]
    if typ.startswith("uint"):
        return [1, (1 << 256) - 1]
    if typ.startswith("int"):
        return [1, -1]
    if typ == "address":
        return [FUZZ_CALLER, contract_addr]
    if typ == "bool":
        return [True]
    if typ == "string":
        return ["fuzz"]
    if typ == "bytes":
        return [b"\x00"]
    if typ.startswith("bytes"):
        return [b"\xff" * 32]
    return []


def boundary_cases(types: List[str],
                   contract_addr: str) -> List[Tuple[List[Any], str]]:
    """Probe matrix for one function: the all-defaults call plus,
    per parameter, that parameter pushed to its boundary values
    while the rest stay at defaults. Capped so one function can
    never eat the contract's whole probe budget."""
    defaults = [_default_value(t) for t in types]
    cases: List[Tuple[List[Any], str]] = [(list(defaults),
                                           "default/zero inputs")]
    for i, typ in enumerate(types):
        for val in _boundary_values(typ, contract_addr):
            if len(cases) >= MAX_CASES_PER_FUNCTION:
                return cases
            case = list(defaults)
            case[i] = val
            label = val if not isinstance(val, bytes) else "0x" + val.hex()
            cases.append((case, f"arg{i} ({typ}) = {label}"))
    return cases


# ---------------------------------------------------------------------------
# Source-side candidate extraction + gate cross-check (pure, testable)
# ---------------------------------------------------------------------------

_VIS_RE = re.compile(r"\b(public|external)\b")
_SKIP_VIS_RE = re.compile(r"\b(internal|private)\b")
_VIEW_RE = re.compile(r"\b(view|pure)\b")
_VALUE_MOVING_RE = re.compile(
    r"\.transfer\s*\(|\.transferFrom\s*\(|\.send\s*\(|"
    r"\.call\s*\{|\.call\s*\(|selfdestruct\s*\(|_mint\s*\(|"
    r"\.mint\s*\(|\.burn\s*\(")
_STATE_WRITE_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_.]*(\s*\[[^\]]*\])?\s*(\+=|-=|=(?![=>]))")


def _extract_canonical(fragment: str) -> Optional[str]:
    """Canonical type of one parameter fragment (a type plus an
    optional name / payable / memory / calldata tail), or None
    for a named struct type that cannot be encoded without the
    ABI (dotted like DataTypes.Args, or a bare custom name)."""
    frag = fragment.strip()
    if not frag:
        return None
    if frag.startswith("tuple") and len(frag) > 5 \
            and frag[5:].lstrip().startswith("("):
        return _extract_canonical(frag[5:].lstrip())
    if frag.startswith("("):
        j = cd._matching(frag, 0)
        tuple_inner = frag[1:j]
        rest = frag[j + 1:].lstrip()
        suffixes = ""
        while rest.startswith("["):
            k = rest.find("]")
            if k < 0:
                return None
            inside = rest[1:k]
            if inside and not inside.isdigit():
                return None
            suffixes += rest[:k + 1]
            rest = rest[k + 1:].lstrip()
        if not tuple_inner.strip():
            return None
        members: List[str] = []
        for member_frag in cd._split_top(tuple_inner):
            mc = _extract_canonical(member_frag)
            if mc is None:
                return None
            members.append(mc)
        return "(" + ",".join(members) + ")" + suffixes
    m = re.match(r"([A-Za-z_][A-Za-z0-9_.]*)", frag)
    if not m:
        return None
    base = m.group(1)
    rest = frag[m.end():].lstrip()
    suffixes = ""
    while rest.startswith("["):
        k = rest.find("]")
        if k < 0:
            return None
        inside = rest[1:k]
        if inside and not inside.isdigit():
            return None
        suffixes += rest[:k + 1]
        rest = rest[k + 1:].lstrip()
    if "." in base:
        return None  # dotted named struct: needs the ABI
    if base in ("address", "bool", "string"):
        canon = base
    elif base == "uint":
        canon = "uint256"
    elif base == "int":
        canon = "int256"
    elif base == "byte":
        canon = "bytes1"
    elif re.fullmatch(r"uint\d+", base) \
            or re.fullmatch(r"int\d+", base):
        canon = base
    elif re.fullmatch(r"bytes\d*", base):
        if base != "bytes" and not 1 <= int(base[5:]) <= 32:
            return None
        canon = base
    else:
        return None  # bare custom struct / unknown type
    return canon + suffixes


def _param_types(signature: str) -> Optional[List[str]]:
    """Parameter types of a function signature, canonicalized,
    or None when any parameter is a named struct type (which
    cannot be encoded without the ABI). Array and tuple types
    are accepted and canonicalized recursively (uint->uint256,
    int->int256, names/spaces stripped)."""
    i = signature.find("(")
    if i < 0:
        return []
    inner = signature[i + 1:cd._matching(signature, i)]
    types: List[str] = []
    for part in cd._split_top(inner):
        if not part.strip():
            continue
        canon = _extract_canonical(part)
        if canon is None:
            return None
        types.append(canon)
    return types


def _sensitive_category(name: str) -> Optional[str]:
    for cat, _sev, pat, _eff in cc._PRIV_RULES:
        if pat.search(name):
            return cat
    return None


def extract_probe_functions(source: str) -> List[Dict[str, Any]]:
    """Public/external state-changing functions worth fuzzing,
    each pre-analyzed for the gate cross-check: gated (source gate
    analysis, crypto_drain discipline), sensitive category
    (contract_recon's privileged-function rules), whether it moves
    value or writes state, and whether it is a payable flow whose
    payout derives from msg.value."""
    clean = cc._strip_comments(source)
    out: List[Dict[str, Any]] = []
    for fn in cc.extract_functions(clean):
        name = fn["name"]
        if not name or name in ("constructor", "fallback", "receive"):
            continue
        sig, text = fn["signature"], fn["text"]
        if text.rstrip().endswith(";"):
            continue  # interface declaration: no body to simulate
        if _SKIP_VIS_RE.search(sig) or not _VIS_RE.search(sig):
            continue
        if _VIEW_RE.search(sig):
            continue  # read-only: nothing to fuzz
        types = _param_types(sig)
        if types is None:
            continue  # unsupported parameter types
        out.append({
            "name": name,
            "signature": sig,
            "text": text,
            "types": types,
            "canonical": canonical_signature(name, types),
            "gated": cd._is_gated(sig, text),
            "sensitive": _sensitive_category(name),
            "moves_value": bool(_VALUE_MOVING_RE.search(text)),
            "writes_state": bool(_STATE_WRITE_RE.search(text)),
            "payable": "payable" in sig,
            "payment_context": ("payable" in sig
                                and "msg.value" in text),
            "full_sweep": "address(this).balance" in text,
        })
    return out


# Standard ERC20 operations: public by design, never privileged.
_ERC20_STANDARD = {"transfer", "transferfrom", "approve",
                   "increaseallowance", "decreaseallowance", "permit"}

# Self-service functions that only touch the CALLER's own assets:
# unguarded by design (mirrors zeroday_contract_guards'
# STANDARD_PUBLIC exclusion for its convention check).
_SELF_SERVICE = _ERC20_STANDARD | {
    "deposit", "depositeth", "burn", "withdraw", "redeem", "stake",
    "unstake", "claim", "get", "balanceof", "allowance",
    "totalsupply"}

_OWN_BALANCE_RE = re.compile(r"\[\s*msg\.sender\s*\]")


def flag_reason(fn: Dict[str, Any],
                gated_siblings: int,
                state_changing_siblings: int) -> Optional[Dict[str, Any]]:
    """Decide whether a SUCCESSFUL fuzz probe of `fn` is a
    candidate. Returns {anomaly, confidence, severity} or None when
    the success is legitimate public behavior. Pure FP discipline:
    success alone never flags."""
    if fn["payment_context"] and not fn["full_sweep"]:
        return None  # public purchase path (crypto_drain exclusion)
    if fn["name"].lower() in _ERC20_STANDARD:
        return None  # standard token ops are public by design
    # Own-balance exclusion (crypto_drain discipline): the amount
    # comes out of a mapping indexed by msg.sender and the function
    # never touches the contract's whole balance - the caller is
    # taking back their own money, which is public by design.
    own_balance = bool(_OWN_BALANCE_RE.search(fn["text"])) \
        and not fn["full_sweep"]
    if fn["sensitive"] and fn["moves_value"] and not fn["gated"] \
            and not own_balance:
        return {
            "anomaly": "unguarded privileged function succeeded for "
                       "an arbitrary caller in eth_call simulation",
            "confidence": 62,
            "severity": "high" if fn["full_sweep"] else "medium",
        }
    if fn["sensitive"] and fn["moves_value"] and fn["gated"]:
        return {
            "anomaly": "function carries an access gate in source, "
                       "yet the simulated call from an arbitrary "
                       "caller SUCCEEDED - the gate as deployed "
                       "does not stop an unrelated caller",
            "confidence": 70,
            "severity": "high",
        }
    if fn["name"].lower() in _SELF_SERVICE:
        return None  # self-service: unguarded by design
    if (not fn["gated"] and fn["writes_state"]
            and state_changing_siblings >= 3
            and gated_siblings * 2 >= state_changing_siblings):
        return {
            "anomaly": "ungated state-changing function breaks the "
                       "contract's own gate convention (most "
                       "siblings are gated) and succeeded for an "
                       "arbitrary caller in simulation",
            "confidence": 45,
            "severity": "medium",
        }
    return None


# ---------------------------------------------------------------------------
# eth_call transport: explorer-patch pattern (Blockscout eth-rpc first,
# public JSON-RPC second - this VM's egress blocks the latter, the
# former is plain HTTPS and works)
# ---------------------------------------------------------------------------

async def eth_call(ctx: Ctx, chain: cc.ChainConfig, to_addr: str,
                   data_hex: str, sender: str,
                   value: str = "0x0") -> Dict[str, Any]:
    """One read-only eth_call simulation.

    Returns {"status": "success", "result": hex, "via": route} when
    the call executed, {"status": "revert", "detail": ...} when the
    contract reverted it, or {"status": "transport_error", ...}
    when no route answered. Never a transaction: eth_call is the
    node's local simulation and cannot change state.
    """
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"from": sender, "to": to_addr, "data": data_hex,
                    "value": value}, "latest"],
    }
    routes: List[Tuple[str, str]] = []
    if chain.blockscout_api:
        base = chain.blockscout_api.rsplit("/api", 1)[0]
        routes.append((f"{base}/api/eth-rpc", "Blockscout eth-rpc"))
    for rpc in chain.rpc_urls:
        routes.append((rpc, "public JSON-RPC"))
    for url, label in routes:
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", url,
                            json=payload, timeout=10, max_retries=0)
            if r.status_code != 200:
                continue
            d = r.json()
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        if isinstance(d.get("result"), str):
            return {"status": "success", "result": d["result"],
                    "via": label}
        if d.get("error") is not None:
            return {"status": "revert",
                    "detail": str(d["error"])[:240], "via": label}
    return {"status": "transport_error",
            "detail": "every eth_call route failed (Blockscout "
                      "eth-rpc and public JSON-RPC unreachable)"}


# ---------------------------------------------------------------------------
# Symbolic execution (Mythril, optional): bounded, honest, off by default
# ---------------------------------------------------------------------------

def symbolic_enabled() -> bool:
    return os.environ.get("RECON_SIM_SYMBOLIC", "") == "1"


def find_mythril() -> Optional[str]:
    """Locate an EXTERNAL Mythril binary, or None when absent.

    Mythril lives outside the app image by design (it drags in a
    solver and a Solidity toolchain): this adapter never installs
    anything and the app Dockerfile/requirements never bundle it.
    Search order: the explicit RECON_MYTHRIL_BIN path (authoritative
    when set - a set-but-missing path means "not available", not
    "keep searching"), the dedicated side venv next to the repo
    root (.venv-mythril, the local-dev pattern), the operator's
    audit-tools tree (~/workspace/tools/audit), then PATH for an
    operator-provided install.
    """
    env = os.environ.get("RECON_MYTHRIL_BIN")
    if env:
        return env if Path(env).is_file() else None
    candidates = [
        Path(__file__).resolve().parents[3]
        / ".venv-mythril" / "bin" / "myth",
        Path.home() / "workspace" / "tools" / "audit"
        / "venv-mythril" / "bin" / "myth",
        Path.home() / "workspace" / "tools" / "audit"
        / ".venv-mythril" / "bin" / "myth",
        Path.home() / "workspace" / "tools" / "audit" / "bin" / "myth",
    ]
    for cand in candidates:
        if cand.is_file():
            return str(cand)
    return shutil.which("myth")


def _discover_solc() -> Optional[str]:
    """A solc for Mythril's subprocess, from the operator's own
    toolchain (solc-select artifacts) - never bundled, never
    downloaded by this adapter. SOLC, when already set, wins."""
    if os.environ.get("SOLC"):
        return os.environ["SOLC"]
    artifacts = Path.home() / ".solc-select" / "artifacts"
    if not artifacts.is_dir():
        return None
    found = sorted(p for p in artifacts.glob("solc-*/solc-*")
                   if p.is_file())
    return str(found[-1]) if found else None


async def run_symbolic(source: str,
                       timeout_s: float) -> Tuple[List[Dict[str, Any]],
                                                   Optional[str]]:
    """Run Mythril over verified source with bounded search.

    Returns (issues, error). issues are Mythril's raw issue dicts;
    error is a plain string when the engine could not run (missing
    binary, timeout, unparseable output) - callers must surface it
    as "symbolic lane did not run", never as "no issues found".
    """
    myth = find_mythril()
    if not myth:
        return [], ("external mythril binary not found (it is "
                    "intentionally not bundled in the app image; "
                    "expected in the side venv or "
                    "~/workspace/tools/audit)")
    budget = max(10, int(timeout_s))
    env = dict(os.environ)
    solc = _discover_solc()
    if solc:
        env["SOLC"] = solc
    try:
        with tempfile.TemporaryDirectory(prefix="recon-sim-") as td:
            sol = Path(td) / "contract.sol"
            sol.write_text(source)
            proc = await asyncio.create_subprocess_exec(
                myth, "analyze", str(sol), "-o", "json",
                "--execution-timeout", str(budget),
                "--max-depth", "16", env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            try:
                out, _err = await asyncio.wait_for(
                    proc.communicate(), timeout=budget + 30)
            except asyncio.TimeoutError:
                proc.kill()
                return [], (f"mythril exceeded its {budget}s "
                            "execution budget and was stopped")
            text = out.decode("utf-8", "replace").strip()
    except Exception as e:  # engine failed to even start
        return [], f"mythril failed to run: {e}"
    data: Any = None
    for chunk in (text, text[text.find("{"):], text[text.find("["):]):
        if not chunk:
            continue
        try:
            data = json.loads(chunk)
            break
        except Exception:
            continue
    if data is None:
        return [], "mythril output was not parseable JSON"
    issues: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        if data.get("error"):
            return [], f"mythril reported an error: {data['error']}"
        raw = data.get("issues")
        if isinstance(raw, list):
            issues = [i for i in raw if isinstance(i, dict)]
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) \
                    and isinstance(entry.get("issues"), list):
                issues.extend(i for i in entry["issues"]
                              if isinstance(i, dict))
    return issues, None


def _mythril_severity(issue: Dict[str, Any]) -> str:
    sev = str(issue.get("severity") or "medium").strip().lower()
    return sev if sev in ("low", "medium", "high") else "medium"


# ---------------------------------------------------------------------------
# Bulk guard
# ---------------------------------------------------------------------------

def bulk_refusal_reason(ctx: Ctx, target: Target,
                        explicit: bool, flagged: int,
                        discovered: int) -> Optional[str]:
    """Why this run context is a bulk sweep this lane must refuse,
    or None when the run is a legitimate single-contract simulation.

    Signals: explicit bulk/sweep flags on the shared bus, bulk-ish
    run ids (the 1000-contract harness used run_id "scan-1000"),
    several static-lane-flagged candidates with no explicit target,
    or several discovered contracts with no explicit target and no
    static-lane flag (a miner sweep, not a simulation request).
    """
    shared = getattr(ctx, "shared", {}) or {}
    for key in ("bulk", "bulk_sweep", "sweep", "mass_scan"):
        if shared.get(key):
            return (f"run context carries the '{key}' bulk marker: "
                    "the simulation lane never runs inside bulk "
                    "sweeps (it is per-contract and expensive). "
                    "Re-run it against the single contract address.")
    rid = (getattr(ctx, "run_id", "") or "").lower()
    if any(m in rid for m in _BULK_MARKERS) or "scan-1000" in rid \
            or "scan-1m" in rid:
        return (f"run id '{ctx.run_id}' marks a bulk sweep: the "
                "simulation lane never runs inside bulk sweeps. "
                "Re-run it against the single contract address.")
    if explicit:
        return None
    if flagged > MAX_SIM_TARGETS:
        return (f"{flagged} contracts were flagged for simulation: "
                f"the lane runs at most {MAX_SIM_TARGETS} per run. "
                "Name one contract as the target to simulate it.")
    if not flagged and discovered > 1:
        return (f"{discovered} contracts were discovered on this "
                "target and none was explicitly targeted or flagged "
                "by a static lane: simulation is per-contract only. "
                "Re-run with the contract address as the target, or "
                "flag one via the static lanes first.")
    return None


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class ContractSimPlugin(Plugin):
    id = "contract_simulation"
    label = "Contract Simulation (Fuzz + Symbolic)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = False  # probes are active eth_call simulations
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []  # keyless: Blockscout eth-rpc + public RPC
    description = ("HEAVY LANE ONLY. Read-only on-chain SIMULATION "
                   "of one explicitly targeted or "
                   "static-lane-flagged contract: boundary-input "
                   "eth_call fuzzing of its public state-changing "
                   "functions, cross-checked against the access "
                   "gate its verified source implies, plus optional "
                   "external Mythril symbolic execution behind "
                   "RECON_SIM_SYMBOLIC=1. Runs only in an explicitly "
                   "marked heavy-lane context under the "
                   "RECON_HEAVY_TIMEOUT budget (default 120s, cap "
                   "300s); from the default/fast request path it "
                   "returns an info note immediately. Flags are "
                   "candidates for human review, never verdicts. "
                   "Refuses bulk sweeps outright. Keyless: "
                   "Blockscout/Sourcify source, eth_call only - no "
                   "transactions, no funded key, no local node, no "
                   "state changes.")
    phase = 2
    # Heavy-lane declaration consumed by runner._run_plugin: in an
    # explicitly heavy context the runner grants RECON_HEAVY_TIMEOUT
    # (clamped to 300s) instead of the normal plugin cap; in any
    # other context this plugin returns before doing work, so the
    # nominal 300s request here never governs the fast path.
    heavy_lane = True
    timeout_s = 300

    # Tests may set an instance budget; production leaves it None
    # and the RECON_HEAVY_TIMEOUT resolution below applies.
    budget_s: Optional[float] = None

    def _budget(self) -> float:
        if self.budget_s is not None:
            return max(0.1, min(float(self.budget_s),
                                HARD_CAP_BUDGET_S))
        return heavy_timeout_s()

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        # Heavy-lane gate FIRST: no target collection, no chain
        # reads, no probes from a fast/default or bulk context.
        if not heavy_lane_context(ctx, self.id):
            text = (
                "simulation stayed off: this run is not marked as "
                "a heavy-lane context, and heavy contract analysis "
                "never runs inside the default request path "
                f"(RECON_TIMEOUT={app_config.DEFAULT_TIMEOUT:.0f}s "
                "by default). Re-run in the heavy lane (module "
                "override contract_simulation=\"heavy\", or a "
                "heavy-lane worker context) where the "
                "RECON_HEAVY_TIMEOUT budget applies (default 120s, "
                "hard cap 300s).")
            res = self._ok([self._note(text, prefix="INFO")], text)
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        deadline = t0 + self._budget()
        # Keyless by design: fetch_verified_source is always called
        # with key=None, so only its Blockscout and Sourcify routes
        # can answer. No Etherscan key is read or used in this lane.
        key = None

        explicit_pairs, flagged_pairs, discovered = \
            self._collect(target, ctx)
        explicit = bool(explicit_pairs)
        work = (explicit_pairs + flagged_pairs)[:MAX_SIM_TARGETS]
        if not work and len(discovered) == 1:
            work = discovered  # the one contract a static lane found

        refusal = bulk_refusal_reason(ctx, target, explicit,
                                      len(flagged_pairs),
                                      len(discovered))
        if refusal:
            note = self._note(refusal)
            res = self._ok([note], refusal)
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        if not work:
            res = self._skipped(
                "no contract to simulate: name a contract address "
                "as the target (optionally chain-prefixed, e.g. "
                "bsc:0x...), or let a static lane flag one first")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        stats = {"contracts": 0, "probes": 0, "succeeded": 0,
                 "reverted": 0, "candidates": 0}
        self._symbolic_note_done = False
        for chain_hint, addr in work:
            if time.monotonic() > deadline - 5:
                findings.append(self._note(
                    f"simulation budget exhausted before {addr}: "
                    "per-contract budget is "
                    f"{self._budget():.0f}s (hard cap "
                    f"{HARD_CAP_BUDGET_S:.0f}s)"))
                break
            try:
                await self._simulate_address(
                    ctx, key, chain_hint, addr, findings, stats,
                    deadline)
            except Exception:
                findings.append(self._note(
                    f"simulation of {addr} failed - chain data "
                    "could not be retrieved (explorers/RPC "
                    "unreachable). No conclusion drawn."))
        stats["candidates"] = sum(
            1 for f in findings if f.key == "simulation_candidate")
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"simulated {stats['contracts']} contract(s): "
            f"{stats['probes']} eth_call probes "
            f"({stats['succeeded']} succeeded, "
            f"{stats['reverted']} reverted), "
            f"{stats['candidates']} simulation candidate(s)")
        res.duration_ms = dur
        return res

    def _note(self, text: str, prefix: str = "LOW") -> Finding:
        return self._f(
            "web3", "contract_simulation_note", f"{prefix}: {text}",
            source="contract simulation",
            confidence=70, passive=True,
            evidence={"severity": "low",
                      "remediation": "No action needed on the "
                                     "contract itself; this note "
                                     "explains what the simulation "
                                     "lane did or refused to do."})

    # -- target collection (mirrors contract_recon / crypto_drain) --
    def _collect(self, target: Target, ctx: Ctx
                 ) -> Tuple[List[Tuple[Optional[str], str]],
                            List[Tuple[Optional[str], str]],
                            List[Tuple[Optional[str], str]]]:
        explicit: List[Tuple[Optional[str], str]] = []
        flagged: List[Tuple[Optional[str], str]] = []
        discovered: List[Tuple[Optional[str], str]] = []
        seen = set()

        def add(bucket, chain_hint, addr) -> None:
            addr = (addr or "").strip()
            if not cc.ADDRESS_RE.match(addr):
                return
            if addr.lower() == cc.ZERO_ADDRESS:
                return
            k = addr.lower()
            if k in seen:
                return
            seen.add(k)
            bucket.append((chain_hint, addr))

        for raw in (target.normalized, target.raw):
            chain_hint, addr = cc.parse_target_address(raw or "")
            if addr:
                add(explicit, chain_hint, addr)
                break
        for item in ctx.consume("sim_candidates"):
            if isinstance(item, dict):
                hint = item.get("chain")
                add(flagged,
                    hint if isinstance(hint, str)
                    and hint in cc.CHAINS else None,
                    str(item.get("address", "")))
            else:
                add(flagged, None, str(item))
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else \
                    str(item.get("address", ""))
                add(discovered, None, a)
        for item in ctx.consume("chain_contracts"):
            if isinstance(item, dict):
                hint = item.get("chain")
                add(discovered,
                    hint if isinstance(hint, str)
                    and hint in cc.CHAINS else None,
                    str(item.get("address", "")))
        return explicit, flagged, discovered

    # -- per-address simulation --------------------------------------
    async def _simulate_address(self, ctx: Ctx, key: Optional[str],
                                chain_hint: Optional[str], addr: str,
                                findings: List[Finding],
                                stats: Dict[str, int],
                                deadline: float) -> None:
        chain_ids = [chain_hint] if chain_hint \
            else list(cc.DEFAULT_CHAIN_ORDER)
        for cid in chain_ids:
            chain = cc.CHAINS[cid]
            code = await cc.rpc_get_code(ctx, chain, addr)
            if code is None or code == "0x" or len(code) < 4:
                continue
            src = await cc.fetch_verified_source(ctx, chain, addr, key)
            res = {"implementation": "", "via": "", "beacon": ""}
            try:
                res = await cc.resolve_implementation(
                    ctx, chain, addr, code,
                    {"implementation": (src or {}).get(
                        "implementation", "")})
            except Exception:
                pass
            impl = res.get("implementation") or ""
            role = "proxy_shell" if impl else "standalone"
            await self._simulate_on_chain(
                ctx, chain, addr, src, role, findings, stats,
                deadline, proxy_addr="")
            stats["contracts"] += 1
            if impl and time.monotonic() < deadline - 5:
                impl_src = None
                try:
                    impl_code = await cc.rpc_get_code(
                        ctx, chain, impl)
                    if impl_code and impl_code != "0x" \
                            and len(impl_code) >= 4:
                        impl_src = await cc.fetch_verified_source(
                            ctx, chain, impl, key)
                except Exception:
                    impl_src = None
                if impl_src:
                    await self._simulate_on_chain(
                        ctx, chain, impl, impl_src,
                        "implementation", findings, stats, deadline,
                        proxy_addr=addr)
            return
        findings.append(self._note(
            f"{addr}: no contract code found on any supported "
            "chain, or every chain route failed. Nothing was "
            "simulated."))

    async def _simulate_on_chain(self, ctx: Ctx, chain: cc.ChainConfig,
                                 addr: str,
                                 src: Optional[Dict[str, Any]],
                                 role: str, findings: List[Finding],
                                 stats: Dict[str, int],
                                 deadline: float,
                                 proxy_addr: str) -> None:
        url = cc.explorer_url(chain, addr)
        base_ev = {"address": addr, "chain": chain.id,
                   "chain_id": chain.chain_id, "contract_role": role}
        if proxy_addr:
            base_ev["proxy_address"] = proxy_addr
        if not src:
            findings.append(self._note(
                f"{addr} on {chain.name}: no verified source, so "
                "the gate cross-check cannot run and this lane does "
                "not fuzz blind. Run contract_recon's bytecode "
                "inventory instead."))
            return

        funcs = extract_probe_functions(src["source"])
        state_changing = [f for f in funcs if f["writes_state"]
                          or f["moves_value"]]
        gated_siblings = sum(1 for f in state_changing if f["gated"])
        probes_left = MAX_PROBES_PER_CONTRACT
        budget_hit = False
        for fn in funcs[:MAX_FUZZ_FUNCTIONS]:
            if budget_hit or probes_left <= 0:
                break
            encoded_head = function_selector(fn["canonical"])
            successes: List[Dict[str, Any]] = []
            for values, label in boundary_cases(fn["types"], addr):
                if probes_left <= 0:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    budget_hit = True
                    break
                enc = encode_call_args(fn["types"], values)
                if enc is None:
                    break
                probes_left -= 1
                stats["probes"] += 1
                try:
                    res = await asyncio.wait_for(
                        eth_call(ctx, chain, addr,
                                 encoded_head + enc, FUZZ_CALLER),
                        timeout=min(_PROBE_TIMEOUT_S,
                                    max(0.1, remaining)))
                except asyncio.TimeoutError:
                    if time.monotonic() >= deadline:
                        budget_hit = True
                        break
                    # One slow route ate the per-probe cap but the
                    # contract budget remains: count the probe as a
                    # transport failure and keep fuzzing.
                    res = {"status": "transport_error",
                           "detail": "probe exceeded per-probe cap"}
                except Exception:
                    res = {"status": "transport_error",
                           "detail": "probe raised"}
                if res["status"] == "success":
                    stats["succeeded"] += 1
                    successes.append({"case": label,
                                      "via": res.get("via", "")})
                elif res["status"] == "revert":
                    stats["reverted"] += 1
            if not successes:
                continue
            verdict = flag_reason(fn, gated_siblings,
                                  len(state_changing))
            if verdict is None:
                continue  # legitimate public behavior, not a finding
            ev = candidate_evidence(
                "contract_simulation", verdict["anomaly"],
                verdict["confidence"], extra=dict(base_ev, **{
                    "simulation_candidate": True,
                    "check": "eth_call_fuzz",
                    "function": fn["name"],
                    "signature": fn["canonical"],
                    "code": cc._snip(fn["text"]),
                    "caller": FUZZ_CALLER,
                    "call_value": "0",
                    "successful_cases":
                        [s["case"] for s in successes],
                    "transport": successes[0]["via"],
                    "gated_in_source": fn["gated"],
                    "sensitive_category": fn["sensitive"] or "",
                    "source_origin": src.get("origin", ""),
                    "contract_name": src.get("contract_name", ""),
                    "severity": verdict["severity"],
                    "remediation": _REMEDIATION,
                }), severity=verdict["severity"])
            ev["confidence"] = verdict["confidence"]
            value = (
                f"{verdict['severity'].upper()}: Simulation "
                f"candidate: '{fn['canonical']}' on contract {addr} "
                f"({chain.name}) SUCCEEDED in read-only eth_call "
                f"simulation from unrelated caller {FUZZ_CALLER} "
                f"with value 0, although its source says it should "
                f"not be freely callable "
                f"({verdict['anomaly']}). CANDIDATE - pending human "
                f"review, not a confirmed vulnerability.\n\n"
                f"Code:\n{cc._snip(fn['text'])}")
            findings.append(self._f(
                "web3", "simulation_candidate", value,
                source="contract simulation (eth_call fuzz)",
                source_url=url,
                confidence=verdict["confidence"], passive=False,
                evidence=ev))
        if budget_hit:
            findings.append(self._note(
                f"{addr} on {chain.name}: simulation budget "
                f"exhausted mid-contract; remaining functions were "
                "not probed. Results so far stand, coverage is "
                "partial."))
        await self._symbolic_lane(ctx, chain, addr, src, base_ev,
                                  findings, deadline, url)

    # -- symbolic lane (optional) --------------------------------------
    async def _symbolic_lane(self, ctx: Ctx, chain: cc.ChainConfig,
                             addr: str, src: Dict[str, Any],
                             base_ev: Dict[str, Any],
                             findings: List[Finding],
                             deadline: float, url: str) -> None:
        if not symbolic_enabled():
            return
        remaining = deadline - time.monotonic()
        if remaining < 15:
            if not self._symbolic_note_done:
                self._symbolic_note_done = True
                findings.append(self._note(
                    "symbolic lane enabled but the simulation "
                    "budget ran out before Mythril could run; "
                    "symbolic execution did NOT run on this "
                    "contract."))
            return
        issues, error = await run_symbolic(src["source"],
                                           min(remaining - 5, 120))
        if error:
            if not self._symbolic_note_done:
                self._symbolic_note_done = True
                findings.append(self._note(
                    f"symbolic lane enabled but did not run: "
                    f"{error}. No symbolic coverage is claimed."))
            return
        for issue in issues[:8]:
            title = str(issue.get("title") or
                        issue.get("swc-title") or
                        "symbolic execution issue")
            desc = issue.get("description")
            if isinstance(desc, dict):
                detail = ((desc.get("head") or "") + " "
                          + (desc.get("tail") or "")).strip()
            else:
                detail = str(desc or "")
            ev = candidate_evidence(
                "contract_simulation_mythril",
                "symbolic execution (Mythril) reported: " + title,
                55, extra=dict(base_ev, **{
                    "simulation_candidate": True,
                    "check": "symbolic_execution",
                    "engine": "mythril",
                    "swc_id": str(issue.get("swc-id") or
                                  issue.get("swc_id") or ""),
                    "function": str(issue.get("function") or ""),
                    "detail": detail[:600],
                    "severity": _mythril_severity(issue),
                    "remediation": _REMEDIATION,
                }), severity=_mythril_severity(issue))
            findings.append(self._f(
                "web3", "simulation_candidate",
                f"{_mythril_severity(issue).upper()}: Simulation "
                f"candidate (Mythril): {title} in contract {addr} "
                f"({chain.name}). {detail[:300]} CANDIDATE - "
                "pending human review, not a confirmed "
                "vulnerability.",
                source="mythril", source_url=url, confidence=55,
                passive=True, evidence=ev))
