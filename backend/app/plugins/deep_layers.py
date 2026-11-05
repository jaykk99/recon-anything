"""Phase 2C/2D deep analysis layers (Jay, Nov 4): go deeper than
surface recon, for ALL targets, not just candidates.

Four registry plugins share this module:

1. cross_contract_call_graph - from the target's verified source,
   extract external call targets (hardcoded addresses, interface-
   typed state variables, interface casts) and follow ONE level
   deep: fetch each callee's verified source and check (a) a gated
   function in the target delegating its sensitive action to an
   UNGATED public function in the callee (gate bypass through the
   callee), and (b) a callee path sending value to a
   caller-supplied address parameter that originates from the
   target's caller. A failed callee fetch records the edge as
   DEGRADED - never faked.
2. storage_state_analysis - LIVE storage reads (eth_getStorageAt,
   read-only) for gate-deciding values: the EIP-1967
   implementation/admin/beacon slots plus owner / paused /
   fee / recipient slots derived from the source's state-variable
   layout. Findings fire when live state changes the verdict the
   source shape suggests. Every finding states slot, raw value,
   decoded value, read timestamp and the source line it combines
   with; an underivable layout is stated, never guessed. This
   plugin also runs the token-parameter extractor (decimals,
   totalSupply, cap, totalAssets via read-only eth_call, fee
   parameters from source + layout) and publishes everything into
   the shared per-target record (synergy, below).
3. bytecode_deep_analysis - for contracts with NO verified
   source: pure-Python disassembly over the deployed bytecode
   (PUSH4 selector extraction + opcode scan, reusing
   contract_chain.analyze_bytecode), dangerous-selector and
   DELEGATECALL / SELFDESTRUCT / CALL flow findings at labeled
   lower confidence, recipient classified where the flow
   determines it, else UNRESOLVED with the missing piece named.
   Heimdall availability (audit toolbox) is reported in the depth
   evidence; the fast lane never shells out to it, and no Heimdall
   run is ever faked.
4. candidate_confirmation_queue - HEAVY lane only. Consumes
   candidates other detectors publish on the run bus (contract
   documented below) and reclassifies each as tool-confirmed
   pattern / trigger-only / false-positive / unconfirmed, with
   the tool evidence attached. Confirmation tools: Slither via
   the audit-toolbox lane on the verified source; the contract
   fuzz lane is NOT auto-run (it needs a prepared harness per
   contract - the candidate records that reason instead of a fake
   run). No-simulation rule: tool output can support a
   false-positive or a pattern confirmation; a live VERIFIED-style
   verdict still requires the read-only probe standard, so the
   strongest label emitted here is "tool-confirmed pattern".

SYNERGY (Phase 2D) runs through the EXISTING plumbing only -
ctx.shared, the same per-run bus every plugin already uses. The
shared per-target record lives at ctx.shared["deep_targets"],
keyed "<chain>:<address>", and carries {storage, token_params,
call_edges, callees, candidates, math, depth, probe}. The storage
plugin WRITES it; the detector-side helper
`apply_storage_gate(record, candidate)` READS it to upgrade /
downgrade a candidate flag using live owner/paused values (no
record -> detectors behave exactly as before and the depth
evidence says storage was absent). The call-graph plugin records
its edges + callee list into the record so the confirmation lane
and the step-path builder consume them. Step paths
(step_paths.build_step_path) and corroboration records are
attached to high findings' evidence.

DEPTH-FOR-ALL: every plugin returns, per target, a coverage
finding (key "deep_layer_coverage") whose evidence carries the
depth dict, e.g. depth: {call_graph: "ran", callees: 2,
storage: "ran", bytecode_deep: "source_available_skip",
confirmation: "queued 1"} - a zero-finding target still shows
which layers ran, so run outputs can checkpoint per-target depth
completion.

CANDIDATE BUS CONTRACT (layer 4): a candidate is a dict on
ctx.shared under "deep_candidates" (preferred), "candidates",
"sim_candidates" or "fuzz_candidates" with keys: address, chain,
source (verified source text), contract_name, function, check
(claim id, e.g. "access_control_flaw"), recipient, severity,
code. The deep plugins in this module publish such dicts for
their own high findings; any other detector may publish the same
shape. Candidates without source are recorded unconfirmed with
the reason named (Slither needs source).

Detection only. Read-only chain access (eth_getCode,
eth_getStorageAt, eth_call for view getters). No transactions.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from . import crypto_drain as cd
from . import quant_math as qm
from . import step_paths as sp
from . import toolbox as tb

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
MAX_CALLEES = 4

EIP1967_ADMIN_SLOT = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")
ZERO = cc.ZERO_ADDRESS

_REMEDIATION = (
    "Review the evidenced path end to end (source lines, live "
    "storage values and call-graph edges are in the evidence), "
    "gate or remove the unauthenticated value path, and re-scan.")


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Shared per-target record (synergy plumbing over ctx.shared)
# ---------------------------------------------------------------------------

def record_key(chain_id: str, address: str) -> str:
    return f"{chain_id}:{address.lower()}"


def get_record(ctx: Any, chain_id: str, address: str) -> Dict[str, Any]:
    shared = getattr(ctx, "shared", None)
    if shared is None:
        shared = ctx.shared = {}
    book = shared.setdefault("deep_targets", {})
    rec = book.get(record_key(chain_id, address))
    if rec is None:
        rec = {"address": address, "chain": chain_id, "storage": {},
               "token_params": {}, "call_edges": [], "callees": [],
               "candidates": [], "math": {}, "depth": {},
               "sources": {}}
        book[record_key(chain_id, address)] = rec
    return rec


def peek_record(ctx: Any, chain_id: str, address: str) -> Optional[Dict[str, Any]]:
    shared = getattr(ctx, "shared", {}) or {}
    return (shared.get("deep_targets") or {}).get(
        record_key(chain_id, address))


def apply_storage_gate(record: Optional[Dict[str, Any]],
                       candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Detector-side synergy helper: adjust a source-detector
    candidate using the LIVE storage values in the shared record.

    Returns {adjustment, reason, severity, report_class}:
    - no record / no storage reads -> "none" (detector behaves as
      before; depth evidence elsewhere says storage was absent).
    - live paused == True -> downgrade: the path is currently
      blocked, so the flag is trigger-only at low severity.
    - live paused == False on an ungated candidate -> upgrade:
      the live state confirms the path is open right now.
    - live owner == address(0) on a gated candidate -> upgrade
      note: the gate holder is the zero address (renounced), so a
      nominally gated path is effectively unguarded-or-dead; the
      candidate keeps its class and the note is recorded.
    """
    if not record or not record.get("storage"):
        return {"adjustment": "none",
                "reason": "no live storage data on record",
                "severity": candidate.get("severity", ""),
                "report_class": candidate.get("report_class", "candidate")}
    st = record["storage"]
    paused = st.get("paused")
    if paused is True:
        return {"adjustment": "downgraded_paused",
                "reason": "live paused=true: the path is currently "
                          "blocked on-chain",
                "severity": "low", "report_class": "trigger_only"}
    if paused is False and candidate.get("gated") is False:
        return {"adjustment": "upgraded_live_open",
                "reason": "live paused=false and the function is "
                          "ungated in source: the path is open now",
                "severity": candidate.get("severity", "high"),
                "report_class": "candidate"}
    if st.get("owner") == ZERO and candidate.get("gated"):
        return {"adjustment": "noted_owner_zero",
                "reason": "live owner is address(0) (renounced) "
                          "while source shows a gate",
                "severity": candidate.get("severity", ""),
                "report_class": candidate.get("report_class", "candidate")}
    return {"adjustment": "none",
            "reason": "live storage values do not change the verdict",
            "severity": candidate.get("severity", ""),
            "report_class": candidate.get("report_class", "candidate")}


# ---------------------------------------------------------------------------
# Target collection (mirrors contract_logic / bsc_common)
# ---------------------------------------------------------------------------

def collect_targets(target: Target, ctx: Ctx) -> List[Tuple[Optional[str], str]]:
    out: List[Tuple[Optional[str], str]] = []
    seen = set()

    def add(chain_hint: Optional[str], addr: str) -> None:
        addr = (addr or "").strip()
        if not cc.ADDRESS_RE.match(addr) or addr.lower() == ZERO:
            return
        if addr.lower() in seen:
            return
        seen.add(addr.lower())
        out.append((chain_hint, addr))

    for raw in (target.normalized, target.raw):
        hint, addr = cc.parse_target_address(raw or "")
        if addr:
            add(hint, addr)
            break
    for kind in ("contract_addresses", "crypto_addresses"):
        for item in ctx.consume(kind):
            add(None, item if isinstance(item, str)
                else str(item.get("address", "")))
    for item in ctx.consume("chain_contracts"):
        if isinstance(item, dict):
            hint = item.get("chain")
            add(hint if isinstance(hint, str) and hint in cc.CHAINS
                else None, str(item.get("address", "")))
    return out[:MAX_ADDRESSES]


async def resolve_chain_code(ctx: Ctx, chain_hint: Optional[str],
                             addr: str) -> List[Tuple[cc.ChainConfig, str]]:
    """(chain, code) pairs where the address holds code. Chain
    hint pins one chain; otherwise BSC first (mirrors bsc_common)
    then the default order."""
    ids = [chain_hint] if chain_hint else \
        ["bsc"] + [c for c in cc.DEFAULT_CHAIN_ORDER if c != "bsc"]
    out = []
    for cid in ids:
        if len(out) >= MAX_CHAIN_PAIRS:
            break
        chain = cc.CHAINS[cid]
        code = await cc.rpc_get_code(ctx, chain, addr)
        if code is None or code == "0x" or len(code) < 4:
            continue
        out.append((chain, code))
        if chain_hint:
            break
    return out


class _DeepBase(Plugin):
    id = ""  # abstract base - registry skips falsy ids (bsc_common pattern)
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    phase = 2
    timeout_s = 180

    def _key(self, ctx: Ctx) -> Optional[str]:
        return ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None

    def _coverage(self, chain: cc.ChainConfig, addr: str,
                  depth: Dict[str, Any],
                  record: Optional[Dict[str, Any]] = None) -> Finding:
        ev: Dict[str, Any] = {"severity": "low", "address": addr,
                              "chain": chain.id, "depth": depth,
                              "remediation": "No action: this records "
                                             "which deep layers ran "
                                             "for this target."}
        if record is not None:
            ev["synergy"] = {
                "storage_in_record": bool(record.get("storage")),
                "callees_in_record": len(record.get("callees") or []),
                "candidates_in_record":
                    len(record.get("candidates") or []),
                "token_params_in_record":
                    sorted((record.get("token_params") or {}).keys()),
            }
        return self._f(
            "web3", "deep_layer_coverage",
            f"LOW: deep-layer coverage for {addr} on {chain.name}: "
            f"{depth}", source="deep analysis layers",
            source_url=cc.explorer_url(chain, addr), confidence=90,
            passive=True, evidence=ev)


# ---------------------------------------------------------------------------
# Layer 2 pure helpers: storage layout + token params
# ---------------------------------------------------------------------------

_DECL_LAYOUT_RE = re.compile(
    r"\b(mapping\s*\([^)]*\)|uint\d*|int\d*|address(?:\s+payable)?|"
    r"bool|bytes32|string|bytes)\s+"
    r"(?:(?:public|private|internal|constant|immutable)\s+)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=[^;]*)?;")


def state_layout(src: str, contract_name: str = "") -> List[Dict[str, Any]]:
    """Ordered depth-1 state-variable layout from the scoped
    source: [{name, type, slot}]. Each variable takes one slot
    head (packing of small values into a shared slot is NOT
    modelled - layout_confidence says so; mappings/arrays occupy
    their head slot, which is all the gate-value reads need)."""
    scope = cl._Scope(src, contract_name)
    scoped = scope.scoped_text
    depths = cl._depth_array(scoped)
    out: List[Dict[str, Any]] = []
    slot = 0
    for m in _DECL_LAYOUT_RE.finditer(scoped):
        if depths[m.start()] != 1:
            continue
        out.append({"name": m.group(2), "type": m.group(1).strip(),
                    "slot": slot})
        slot += 1
    return out


_INTERESTING = re.compile(
    r"owner|paused|pause|fee|treasury|recipient|withdraw|admin|"
    r"operator|controller|wallet|dev|marketing|liquidity", re.I)


def slot_hex(n: int) -> str:
    return "0x" + format(n, "064x")


def decode_word(word: Optional[str], typ: str) -> Any:
    """Decode a 32-byte storage word for the layout types we read."""
    if not word:
        return None
    w = word.lower().removeprefix("0x")
    if len(w) != 64:
        return None
    if typ.startswith("address"):
        return cc.address_from_storage_word(word) or ZERO
    if typ == "bool":
        return int(w, 16) != 0
    try:
        return int(w, 16)
    except ValueError:
        return None


_FEE_SRC_RE = re.compile(
    r"(?:fee|tax)(?:Bps|Percent|Percentage|Rate)?\w*\s*=\s*(\d+)", re.I)


def extract_token_params(source: str, live: Dict[str, Any]) -> Dict[str, Any]:
    """Token-parameter extraction (synergy input for the math
    layer): decimals / totalSupply / cap / totalAssets come from
    the LIVE reads dict (eth_call results decoded by the plugin);
    fee parameters come from source constants and layout slots.
    Every value carries its origin."""
    params: Dict[str, Any] = {}
    for k in ("decimals", "totalSupply", "cap", "totalAssets"):
        if live.get(k) is not None:
            params[k] = {"value": live[k], "origin": "eth_call"}
    m = _FEE_SRC_RE.search(cc._strip_comments(source or ""))
    if m:
        params["fee_source_constant"] = {"value": int(m.group(1)),
                                         "origin": "source"}
    return params


async def eth_call_read(ctx: Ctx, chain: cc.ChainConfig, addr: str,
                        signature: str) -> Optional[int]:
    """One read-only eth_call for a zero-arg uint/address getter,
    decoded as int (address getters return the low 160 bits).
    Module-level seam: tests stub this instead of the transport."""
    from . import contract_sim as cs
    from .cryptopack_util import keccak256
    selector = keccak256(signature.encode())[:4].hex()
    res = await cs.eth_call(ctx, chain, addr, "0x" + selector,
                            cs.FUZZ_CALLER)
    if res.get("status") != "success":
        return None
    raw = (res.get("result") or "0x").removeprefix("0x")
    if not raw:
        return None
    try:
        return int(raw[-64:], 16)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Layer 1 pure analysis: cross-contract call graph
# ---------------------------------------------------------------------------

_IFACE_VAR_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*)\s+(?:public\s+|private\s+|internal\s+)?"
    r"([a-z_][A-Za-z0-9_]*)\s*(?:=\s*([A-Z][A-Za-z0-9_]*)\s*\(\s*"
    r"(0x[0-9a-fA-F]{40})\s*\))?\s*;")
_ADDR_VAR_RE = re.compile(
    r"\baddress\s+(?:public\s+|private\s+|internal\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9a-fA-F]{40})\s*;")
_CAST_CALL_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*)\s*\(\s*(0x[0-9a-fA-F]{40})\s*\)\s*\.\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_VAR_CALL_RE = re.compile(r"\b([a-z_][A-Za-z0-9_]*)\s*\.\s*"
                          r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def extract_call_edges(src: str, contract_name: str = "") -> List[Dict[str, Any]]:
    """External call edges out of the target's functions:
    [{from_fn, to_addr, to_fn, via}]. Targets come from interface
    casts with literal addresses, interface/address state vars
    bound to literals, and hardcoded addresses in the body."""
    scope = cl._Scope(src, contract_name)
    scoped = scope.scoped_text
    var_addr: Dict[str, str] = {}
    for m in _IFACE_VAR_RE.finditer(scoped):
        if m.group(4):
            var_addr[m.group(2)] = m.group(4)
    for m in _ADDR_VAR_RE.finditer(scoped):
        var_addr[m.group(1)] = m.group(2)
    edges: List[Dict[str, Any]] = []
    seen = set()
    for fn in scope.functions:
        if "{" not in fn["text"]:
            continue
        text = fn["text"]
        for m in _CAST_CALL_RE.finditer(text):
            key = (fn["name"], m.group(2).lower(), m.group(3))
            if key in seen:
                continue
            seen.add(key)
            edges.append({"from_fn": fn["name"], "to_addr": m.group(2),
                          "to_fn": m.group(3), "via": "interface_cast",
                          "status": "found"})
        for m in _VAR_CALL_RE.finditer(text):
            var, meth = m.group(1), m.group(2)
            if var not in var_addr:
                continue
            key = (fn["name"], var_addr[var].lower(), meth)
            if key in seen:
                continue
            seen.add(key)
            edges.append({"from_fn": fn["name"],
                          "to_addr": var_addr[var], "to_fn": meth,
                          "via": f"state_var:{var}", "status": "found"})
    return edges


_SENSITIVE_CALLEE_RE = re.compile(
    r"withdraw|sweep|drain|rescue|mint|transfer|send|call|claim|"
    r"setowner|upgrade|execute|payout|release", re.I)


def analyze_call_graph(target_src: str,
                       callees: Dict[str, Optional[Dict[str, Any]]],
                       contract_name: str = ""
                       ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(findings, edges) for one target. `callees` maps address ->
    verified-source meta dict (as fetch_verified_source returns)
    or None when the fetch failed (edge DEGRADED)."""
    edges = extract_call_edges(target_src, contract_name)
    t_scope = cl._Scope(target_src, contract_name)
    t_fns = {fn["name"]: fn for fn in t_scope.functions}
    findings: List[Dict[str, Any]] = []
    for e in edges:
        meta = callees.get(e["to_addr"]) or callees.get(e["to_addr"].lower())
        if meta is None:
            e["status"] = "degraded"
            continue
        e["status"] = "ran"
        c_src = meta.get("source", "")
        c_scope = cl._Scope(c_src, meta.get("contract_name", ""))
        c_fns = {fn["name"]: fn for fn in c_scope.functions}
        callee_fn = c_fns.get(e["to_fn"])
        caller_fn = t_fns.get(e["from_fn"])
        if callee_fn is None or caller_fn is None:
            continue
        if "{" not in callee_fn["text"]:
            continue
        caller_gated = cl._gated_deep(caller_fn, t_scope)
        callee_gated = cl._gated_deep(callee_fn, c_scope)
        sensitive = bool(_SENSITIVE_CALLEE_RE.search(e["to_fn"])) or \
            bool(cd._fund_moves(callee_fn["text"]))
        # (a) gated in target -> ungated sensitive in callee
        if caller_gated and not callee_gated and sensitive and \
                not cd._is_skippable(callee_fn["signature"],
                                     callee_fn["text"]):
            recipient, rdetail = cl.classify_recipient(callee_fn["text"])
            findings.append({
                "kind": "call_graph_gate_bypass", "severity": "high",
                "function": e["from_fn"], "callee_function": e["to_fn"],
                "callee": e["to_addr"], "recipient": recipient,
                "report_class": "trigger_only" if recipient in
                ("FIXED", "HOLDER-SELF") else "candidate",
                "code": cc._snip(caller_fn["text"]),
                "callee_code": cc._snip(callee_fn["text"]),
                "detail": (
                    f"gate bypass through callee: '{e['from_fn']}' is "
                    f"gated in the target, but it delegates to "
                    f"'{e['to_fn']}' on {e['to_addr']}, which is "
                    "PUBLIC and UNGATED in the callee and performs a "
                    f"sensitive action. Recipient: {recipient} "
                    f"({rdetail}). Anyone who can reach the callee "
                    "directly skips the target's gate entirely."),
            })
            continue
        # (b) callee sends value to a caller-supplied parameter that
        # the target forwards from its own caller. The callee gate
        # closes this path too: a gated callee is not reachable by
        # a stranger directly, so the route is not a finding.
        recipient, _rd = cl.classify_recipient(callee_fn["text"])
        if recipient == "CALLER-SUPPLIED" and sensitive and \
                not callee_gated:
            t_params = cd._param_names(caller_fn["signature"])
            body = caller_fn["text"]
            forwarded = any(re.search(r"\b" + re.escape(p) + r"\b", body)
                            for p in t_params)
            if forwarded:
                findings.append({
                    "kind": "call_graph_caller_supplied_route",
                    "severity": "high",
                    "function": e["from_fn"],
                    "callee_function": e["to_fn"],
                    "callee": e["to_addr"],
                    "recipient": "CALLER-SUPPLIED",
                    "report_class": "candidate",
                    "code": cc._snip(caller_fn["text"]),
                    "callee_code": cc._snip(callee_fn["text"]),
                    "detail": (
                        f"caller-supplied value route: '{e['from_fn']}'"
                        f" forwards a caller-supplied address into "
                        f"'{e['to_fn']}' on {e['to_addr']}, whose value "
                        "destination is that supplied address "
                        "(recipient CALLER-SUPPLIED)."),
                })
    return findings, edges


# ---------------------------------------------------------------------------
# Layer 3 pure analysis: bytecode deep
# ---------------------------------------------------------------------------

_DANGEROUS_SIG_RES = [
    ("withdraw", re.compile(r"^withdraw", re.I)),
    ("sweep", re.compile(r"^sweep", re.I)),
    ("mint", re.compile(r"^mint", re.I)),
    ("upgrade", re.compile(r"^upgradeTo", re.I)),
    ("rescue", re.compile(r"^rescue", re.I)),
    ("selfdestruct", re.compile(r"^selfdestruct|^destroy|^kill", re.I)),
]


def analyze_bytecode_deep(code_hex: str) -> List[Dict[str, Any]]:
    """Bytecode-level findings for unverified contracts. Pure
    Python over cc.analyze_bytecode (PUSH4 selectors + opcode
    scan). Confidence is labeled lower than source findings;
    recipient is classified only where the selector/flow
    determines it, else UNRESOLVED with the missing piece named."""
    info = cc.analyze_bytecode(code_hex)
    if not info.get("size"):
        return []
    opcodes = info.get("opcodes") or {}
    selectors = info.get("selectors") or []
    sigs = [s.get("signature") or "" for s in selectors]
    out: List[Dict[str, Any]] = []
    if opcodes.get("DELEGATECALL"):
        out.append({
            "kind": "bytecode_delegatecall", "severity": "medium",
            "recipient": "UNRESOLVED",
            "detail": (
                f"bytecode contains DELEGATECALL x{opcodes['DELEGATECALL']}"
                ": foreign code runs in this contract's storage "
                "context. Recipient UNRESOLVED: without verified "
                "source the delegate target and its value flow "
                "cannot be traced - that is the missing piece."),
            "evidence_extra": {"opcodes": opcodes}})
    if opcodes.get("SELFDESTRUCT"):
        out.append({
            "kind": "bytecode_selfdestruct", "severity": "medium",
            "recipient": "UNRESOLVED",
            "detail": (
                f"bytecode contains SELFDESTRUCT x{opcodes['SELFDESTRUCT']}"
                ": the contract can be destroyed and its balance "
                "force-sent. Recipient UNRESOLVED: the beneficiary "
                "is a runtime argument that bytecode alone does "
                "not name - verified source is the missing piece."),
            "evidence_extra": {"opcodes": opcodes}})
    for label, pat in _DANGEROUS_SIG_RES:
        hit_sigs = [s for s in sigs if s and pat.search(s)]
        if not hit_sigs:
            continue
        recipient = "UNRESOLVED"
        missing = "no verified source to trace the destination"
        if any(s.startswith("sweep(address") for s in hit_sigs):
            recipient = "CALLER-SUPPLIED"
            missing = ""
        out.append({
            "kind": f"bytecode_selector_{label}", "severity": "medium",
            "recipient": recipient,
            "detail": (
                f"dangerous function selector(s) present in "
                f"unverified bytecode: {', '.join(hit_sigs[:3])}, "
                f"with CALL opcode present={bool(opcodes.get('CALL'))}. "
                + (f"Recipient {recipient} (the selector's address "
                   "parameter is caller-supplied)." if not missing else
                   f"Recipient UNRESOLVED: {missing}.")),
            "evidence_extra": {"selectors": selectors[:20],
                               "opcodes": opcodes}})
        break  # one selector finding per contract is enough signal
    return out


# ---------------------------------------------------------------------------
# Layer 4 pure classification + tool seams
# ---------------------------------------------------------------------------

async def run_slither_confirmation(source: str) -> Dict[str, Any]:
    """Slither via the audit-toolbox lane. Returns
    {ran: bool, hits: [...], reason}. Module-level seam: tests
    stub this; production uses toolbox._adapt_slither."""
    if not tb.tool_binary("slither"):
        return {"ran": False, "hits": [],
                "reason": "slither binary not installed in the "
                          "audit toolbox"}
    import tempfile
    with tempfile.TemporaryDirectory(prefix="deep-confirm-") as wd:
        hits = await tb._adapt_slither(wd, source, 300.0)
    return {"ran": True, "hits": hits, "reason": ""}


async def run_fuzz_confirmation(candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Fuzz seam: the contract_fuzz lane needs a prepared harness
    per contract and is not auto-run from this queue; the honest
    default is unavailable with the reason named. Tests may stub
    this module function to simulate a fuzz verdict."""
    return {"ran": False, "hits": [],
            "reason": "contract fuzz lane requires a prepared "
                      "Echidna harness for this contract and is "
                      "not auto-run by the confirmation queue"}


_CLAIM_WORDS = {
    "access_control_flaw": ("access", "owner", "unprotected", "mint",
                            "withdraw", "suicidal"),
    "reentrancy": ("reentrancy",),
    "integer_overflow": ("overflow", "underflow", "arithmetic"),
    "call_graph_gate_bypass": ("access", "owner", "unprotected"),
}


def classify_confirmation(candidate: Dict[str, Any],
                          slither: Dict[str, Any],
                          record: Optional[Dict[str, Any]] = None
                          ) -> Dict[str, Any]:
    """Reclassify one candidate from tool evidence. Returns
    {verdict, severity, report_class, reason} where verdict is
    tool_confirmed_pattern | trigger_only | false_positive |
    unconfirmed. Storage synergy applies first (live paused)."""
    adj = apply_storage_gate(record, candidate)
    if adj["adjustment"] == "downgraded_paused":
        return {"verdict": "trigger_only", "severity": "low",
                "report_class": "trigger_only", "reason": adj["reason"]}
    if not slither.get("ran"):
        return {"verdict": "unconfirmed",
                "severity": candidate.get("severity", "medium"),
                "report_class": "candidate",
                "reason": f"confirmation tool unavailable: "
                          f"{slither.get('reason', 'unknown')}"}
    hits = slither.get("hits") or []
    words = _CLAIM_WORDS.get(candidate.get("check", ""), ())
    match = [h for h in hits if any(
        w in (h.get("detector", "") + " " + h.get("message", "")).lower()
        for w in words)] if words else list(hits)
    if match:
        return {"verdict": "tool_confirmed_pattern",
                "severity": candidate.get("severity", "medium"),
                "report_class": candidate.get("report_class",
                                             "candidate"),
                "reason": f"slither detector '{match[0].get('detector')}'"
                          " independently flags the same claim "
                          "(tool-confirmed pattern - not a live-drain "
                          "proof)"}
    if hits:
        return {"verdict": "unconfirmed",
                "severity": candidate.get("severity", "medium"),
                "report_class": "candidate",
                "reason": "slither ran and flagged other issues but "
                          "nothing matching this claim; the claim "
                          "stays unconfirmed, not cleared"}
    return {"verdict": "false_positive", "severity": "low",
            "report_class": "trigger_only",
            "reason": "slither ran clean over the verified source: "
                      "no detector output supports the claim"}


# ---------------------------------------------------------------------------
# Plugins
# ---------------------------------------------------------------------------

class CrossContractCallGraphPlugin(_DeepBase):
    id = "cross_contract_call_graph"
    label = "Cross-Contract Call Graph (Deep)"
    description = ("Follows the target's external calls ONE level "
                   "deep: extracts call targets from verified "
                   "source, fetches each callee's verified source, "
                   "and flags gate bypass through an ungated callee "
                   "function and caller-supplied value routes. "
                   "Edges and callees are recorded in the shared "
                   "per-target record for the confirmation lane and "
                   "step-path builder. Read-only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        work = collect_targets(target, ctx)
        if not work:
            res = self._skipped("no contract address for call-graph analysis")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        key = self._key(ctx)
        for hint, addr in work:
            for chain, _code in await resolve_chain_code(ctx, hint, addr):
                rec = get_record(ctx, chain.id, addr)
                src = await cc.fetch_verified_source(ctx, chain, addr, key)
                if not src:
                    depth = {"call_graph": "degraded_no_source",
                             "storage": "absent" if not rec.get("storage")
                             else "ran"}
                    rec["depth"]["call_graph"] = "degraded_no_source"
                    findings.append(self._coverage(chain, addr, depth, rec))
                    continue
                rec["sources"]["self"] = src.get("contract_name", "")
                edges0 = extract_call_edges(src["source"],
                                            src.get("contract_name", ""))
                callees: Dict[str, Optional[Dict[str, Any]]] = {}
                for e in edges0[:MAX_CALLEES]:
                    ca = e["to_addr"]
                    if ca.lower() == addr.lower():
                        continue
                    try:
                        callees[ca] = await cc.fetch_verified_source(
                            ctx, chain, ca, key)
                    except Exception:
                        callees[ca] = None
                hits, edges = analyze_call_graph(
                    src["source"], callees, src.get("contract_name", ""))
                rec["call_edges"] = edges
                rec["callees"] = sorted({e["to_addr"] for e in edges})
                rec["depth"]["call_graph"] = "ran"
                rec["depth"]["callees"] = len(rec["callees"])
                rec["depth"]["callee_layers"] = [
                    "source" if callees.get(a) else "degraded"
                    for a in rec["callees"]]
                url = cc.explorer_url(chain, addr)
                for item in hits:
                    cand = {"function": item["function"],
                            "code": item["code"], "gated": True,
                            "recipient": item["recipient"],
                            "check": item["kind"],
                            "severity": item["severity"]}
                    adj = apply_storage_gate(rec, cand)
                    sev = adj["severity"] if adj["adjustment"] == \
                        "downgraded_paused" else item["severity"]
                    path = sp.build_step_path(cand, rec)
                    corr = sp.corroborate(
                        item["kind"], "flags", "flags"
                        if item["recipient"] != "UNRESOLVED" else "silent",
                        other_lane="recipient_dataflow")
                    ev = {"severity": sev, "address": addr,
                          "chain": chain.id, "function": item["function"],
                          "callee": item["callee"],
                          "callee_function": item["callee_function"],
                          "code": item["code"],
                          "callee_code": item["callee_code"],
                          "detail": item["detail"],
                          "recipient": item["recipient"],
                          "report_class": item["report_class"],
                          "storage_gate": adj, "steps": path["steps"],
                          "path_verdict": path["verdict"],
                          "corroboration": [corr],
                          "depth": dict(rec["depth"]),
                          "remediation": _REMEDIATION}
                    findings.append(self._f(
                        "web3", item["kind"],
                        f"{sev.upper()}: {item['kind'].replace('_', ' ')}"
                        f": {addr} -> {item['callee']} on {chain.name}"
                        f"\n\n{item['detail']}\n\nTarget code:\n"
                        f"{item['code']}\n\nCallee code:\n"
                        f"{item['callee_code']}",
                        source="cross-contract call graph",
                        source_url=url,
                        confidence=85 if sev == "high" else 60,
                        passive=True, evidence=ev))
                    rec["candidates"].append(cand)
                    ctx.publish("deep_candidates", {
                        "address": addr, "chain": chain.id,
                        "source": src["source"],
                        "contract_name": src.get("contract_name", ""),
                        "function": item["function"],
                        "check": item["kind"],
                        "recipient": item["recipient"],
                        "severity": sev, "code": item["code"],
                        "gated": True})
                depth = {"call_graph": "ran", "callees": len(rec["callees"]),
                         "callee_layers": rec["depth"].get("callee_layers", []),
                         "storage": "ran" if rec.get("storage") else "absent"}
                findings.append(self._coverage(chain, addr, depth, rec))
        res = self._ok(findings, f"call-graph: {len(findings)} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


class StorageStateAnalysisPlugin(_DeepBase):
    id = "storage_state_analysis"
    label = "Storage State Analysis (Deep)"
    description = ("Reads LIVE storage (EIP-1967 slots + the "
                   "source-derived layout) for gate-deciding values "
                   "- owner, implementation, paused, fee/recipient "
                   "- and combines them with source analysis: "
                   "findings fire when live state changes the "
                   "source-shape verdict. Also extracts token "
                   "parameters (decimals/totalSupply/cap/totalAssets "
                   "via eth_call, fee params from source) into the "
                   "shared per-target record for the math layer. "
                   "Read-only eth_getStorageAt / eth_call.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        work = collect_targets(target, ctx)
        if not work:
            res = self._skipped("no contract address for storage analysis")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        key = self._key(ctx)
        for hint, addr in work:
            for chain, code_hex in await resolve_chain_code(ctx, hint, addr):
                rec = get_record(ctx, chain.id, addr)
                src = await cc.fetch_verified_source(ctx, chain, addr, key)
                observed = _now()
                st: Dict[str, Any] = {"observed_at": observed, "slots": {}}
                # standard slots first
                for label, slot in (("implementation", cc.EIP1967_IMPLEMENTATION_SLOT),
                                    ("admin", EIP1967_ADMIN_SLOT),
                                    ("beacon", cc.EIP1967_BEACON_SLOT)):
                    word = await cc.rpc_get_storage_at(ctx, chain, addr, slot)
                    st["slots"][label] = {"slot": slot, "raw": word}
                    if label == "implementation":
                        st["implementation"] = \
                            cc.address_from_storage_word(word) or ""
                layout: List[Dict[str, Any]] = []
                layout_known = False
                if src:
                    layout = state_layout(src["source"],
                                          src.get("contract_name", ""))
                    layout_known = bool(layout)
                    for var in layout:
                        if not _INTERESTING.search(var["name"]):
                            continue
                        slot = slot_hex(var["slot"])
                        word = await cc.rpc_get_storage_at(
                            ctx, chain, addr, slot)
                        val = decode_word(word, var["type"])
                        st["slots"][var["name"]] = {
                            "slot": slot, "raw": word, "value": val,
                            "type": var["type"]}
                        low = var["name"].lower()
                        if "owner" in low and isinstance(val, str):
                            st["owner"] = val
                        if "paus" in low and isinstance(val, bool):
                            st["paused"] = val
                st["layout_known"] = layout_known
                rec["storage"] = st
                rec["depth"]["storage"] = "ran" if layout_known \
                    else "layout_unknown"
                # token params (synergy -> math layer)
                live: Dict[str, Any] = {}
                for sig_name, sig in (("decimals", "decimals()"),
                                      ("totalSupply", "totalSupply()"),
                                      ("cap", "cap()"),
                                      ("totalAssets", "totalAssets()")):
                    v = await eth_call_read(ctx, chain, addr, sig)
                    if v is not None:
                        live[sig_name] = v
                params = extract_token_params(src["source"] if src else "",
                                              live)
                rec["token_params"] = params
                if live.get("totalSupply") is not None and \
                        live.get("totalAssets") is not None:
                    fig = qm.inflation_attack(
                        1, max(1, live["totalAssets"] // 2),
                        max(1, live["totalAssets"]))
                    rec["math"]["inflation_check"] = qm.stamped(
                        fig, {"totalAssets": live["totalAssets"],
                              "totalSupply": live["totalSupply"]},
                        observed)
                rec["depth"]["token_params"] = sorted(params.keys())
                # ---- findings: live state vs source shape --------
                url = cc.explorer_url(chain, addr)
                src_text = src["source"] if src else ""
                ungated_drain = False
                if src_text:
                    for item in cl.analyze_logic_source(
                            src_text, src.get("compiler", ""),
                            contract_name=src.get("contract_name", "")):
                        if item["kind"] == "access_control_flaw":
                            ungated_drain = True
                            break
                def _ev(sev: str, extra: Dict[str, Any]) -> Dict[str, Any]:
                    ev = {"severity": sev, "address": addr,
                          "chain": chain.id, "storage": st,
                          "observed_at": observed,
                          "depth": dict(rec["depth"]),
                          "remediation": _REMEDIATION}
                    ev.update(extra)
                    return ev
                if st.get("implementation") and src_text and \
                        "1967" not in src_text and \
                        "proxy" not in src_text.lower():
                    findings.append(self._f(
                        "web3", "storage_impl_mismatch",
                        f"MEDIUM: live EIP-1967 implementation slot of "
                        f"{addr} holds {st['implementation']} but the "
                        f"verified source shows no proxy pattern - the "
                        f"deployed logic may differ from the verified "
                        f"source's expectation\n\nslot "
                        f"{cc.EIP1967_IMPLEMENTATION_SLOT} = "
                        f"{st['slots']['implementation']['raw']}",
                        source="storage state analysis", source_url=url,
                        confidence=70, passive=True, evidence=_ev(
                            "medium", {"slot": cc.EIP1967_IMPLEMENTATION_SLOT,
                                       "decoded": st["implementation"]})))
                if ungated_drain and st.get("paused") is False:
                    findings.append(self._f(
                        "web3", "storage_ungated_drain_live",
                        f"HIGH: {addr} has an ungated drain-class "
                        f"function in source AND live paused=false - "
                        f"the drain path is open right now\n\npaused "
                        f"slot raw={st['slots'].get('paused', {}).get('raw')}",
                        source="storage state analysis", source_url=url,
                        confidence=85, passive=True, evidence=_ev(
                            "high", {"paused": False,
                                     "recipient": "UNRESOLVED"})))
                if ungated_drain and st.get("owner") == ZERO:
                    findings.append(self._f(
                        "web3", "storage_owner_zero_ungated",
                        f"HIGH: {addr}: live owner is address(0) while "
                        f"an ungated privileged function exists in "
                        f"source\n\nowner slot raw="
                        f"{st['slots'].get('owner', {}).get('raw')}",
                        source="storage state analysis", source_url=url,
                        confidence=80, passive=True, evidence=_ev(
                            "high", {"owner": ZERO})))
                if st.get("owner") and st["owner"] != ZERO:
                    ocode = await cc.rpc_get_code(ctx, chain, st["owner"])
                    if ocode and ocode != "0x" and len(ocode) > 4 and \
                            ungated_drain:
                        findings.append(self._f(
                            "web3", "storage_owner_is_contract",
                            f"MEDIUM: {addr}: live owner {st['owner']} is "
                            f"a CONTRACT address and an ungated "
                            f"privileged function exists - control sits "
                            f"with code, not a person",
                            source="storage state analysis",
                            source_url=url, confidence=65, passive=True,
                            evidence=_ev("medium",
                                         {"owner": st["owner"],
                                          "owner_is_contract": True})))
                if not layout_known:
                    findings.append(self._f(
                        "web3", "storage_layout_unknown",
                        f"LOW: {addr}: storage layout could not be "
                        f"derived (no verified source); only the "
                        f"standard EIP-1967 slots were read - owner/"
                        f"paused values are UNVERIFIED, not guessed",
                        source="storage state analysis", source_url=url,
                        confidence=60, passive=True, evidence=_ev(
                            "low", {"layout_known": False})))
                depth = {"storage": rec["depth"]["storage"],
                         "token_params": rec["depth"].get("token_params", []),
                         "call_graph": rec["depth"].get("call_graph", "absent")}
                findings.append(self._coverage(chain, addr, depth, rec))
        res = self._ok(findings, f"storage: {len(findings)} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


class BytecodeDeepAnalysisPlugin(_DeepBase):
    id = "bytecode_deep_analysis"
    label = "Bytecode Deep Analysis (Deep)"
    description = ("Deep bytecode lane for contracts with NO "
                   "verified source: pure-Python disassembly "
                   "(PUSH4 selectors + DELEGATECALL/SELFDESTRUCT/"
                   "CALL opcode scan), dangerous-selector findings "
                   "at labeled lower confidence with recipient "
                   "classification or UNRESOLVED + the missing "
                   "piece named. Heimdall availability is reported, "
                   "never faked.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        work = collect_targets(target, ctx)
        if not work:
            res = self._skipped("no contract address for bytecode analysis")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        key = self._key(ctx)
        heimdall = tb.tool_binary("heimdall")
        for hint, addr in work:
            for chain, code_hex in await resolve_chain_code(ctx, hint, addr):
                rec = get_record(ctx, chain.id, addr)
                src = await cc.fetch_verified_source(ctx, chain, addr, key)
                if src:
                    rec["depth"]["bytecode_deep"] = "source_available_skip"
                    findings.append(self._coverage(
                        chain, addr,
                        {"bytecode_deep": "source_available_skip",
                         "heimdall_available": bool(heimdall)}, rec))
                    continue
                rec["depth"]["bytecode_deep"] = "ran"
                url = cc.explorer_url(chain, addr)
                for item in analyze_bytecode_deep(code_hex):
                    ev = {"severity": item["severity"], "address": addr,
                          "chain": chain.id, "bytecode_only": True,
                          "confidence_label": "bytecode-level (lower)",
                          "recipient": item["recipient"],
                          "detail": item["detail"],
                          "heimdall_available": bool(heimdall),
                          "depth": dict(rec["depth"]),
                          "remediation": _REMEDIATION}
                    ev.update(item.get("evidence_extra") or {})
                    findings.append(self._f(
                        "web3", item["kind"],
                        f"{item['severity'].upper()}: bytecode-deep: "
                        f"{item['kind'].replace('_', ' ')} in {addr} on "
                        f"{chain.name} (no verified source)\n\n"
                        f"{item['detail']}",
                        source="bytecode deep analysis (pure python)",
                        source_url=url, confidence=50, passive=True,
                        evidence=ev))
                findings.append(self._coverage(
                    chain, addr,
                    {"bytecode_deep": "ran",
                     "heimdall_available": bool(heimdall)}, rec))
        res = self._ok(findings, f"bytecode-deep: {len(findings)} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


class CandidateConfirmationQueuePlugin(_DeepBase):
    id = "candidate_confirmation_queue"
    label = "Candidate Confirmation Queue (Deep, Heavy Lane)"
    lane = "heavy"
    phase = 3
    timeout_s = 1800
    description = ("HEAVY lane only. Consumes candidates published "
                   "on the run bus (deep_candidates / candidates / "
                   "sim_candidates / fuzz_candidates dicts with "
                   "source) and reclassifies each with Slither via "
                   "the audit-toolbox lane: tool-confirmed pattern / "
                   "trigger-only / false-positive / unconfirmed "
                   "(tool unavailable - reason named, never silently "
                   "confirmed). Storage synergy and step paths are "
                   "attached; tool output never becomes a live "
                   "VERIFIED verdict (no-simulation rule).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        from . import contract_fuzz as cf
        if not cf.heavy_enabled(ctx, self.id):
            res = self._ok([], "confirmation queue stayed off: not a "
                               "heavy-lane context (module override "
                               "candidate_confirmation_queue='heavy', "
                               "shared allow_heavy, or RECON_HEAVY_LANE=1); "
                               "candidates remain unconfirmed")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        cands: List[Dict[str, Any]] = []
        seen = set()
        for kind in ("deep_candidates", "candidates", "sim_candidates",
                     "fuzz_candidates"):
            for item in ctx.consume(kind):
                if not isinstance(item, dict):
                    continue
                k = (str(item.get("address", "")).lower(),
                     item.get("check", ""), item.get("function", ""))
                if k in seen:
                    continue
                seen.add(k)
                cands.append(item)
        findings: List[Finding] = []
        for cand in cands[:4]:
            addr = str(cand.get("address", ""))
            chain_id = cand.get("chain") if cand.get("chain") in cc.CHAINS \
                else "ethereum"
            rec = peek_record(ctx, chain_id, addr) if addr else None
            if rec is not None:
                rec["depth"]["confirmation"] = \
                    f"queued {len(cands[:4])}"
            source = cand.get("source") or ""
            if not source:
                verdict = {"verdict": "unconfirmed",
                           "severity": cand.get("severity", "medium"),
                           "report_class": "candidate",
                           "reason": "candidate carries no verified "
                                     "source; Slither cannot run"}
                slither = {"ran": False, "hits": [],
                           "reason": "no source on candidate"}
            else:
                slither = await run_slither_confirmation(source)
                verdict = classify_confirmation(cand, slither, rec)
            fuzz = await run_fuzz_confirmation(cand)
            path = sp.build_step_path(
                {"function": cand.get("function", ""),
                 "code": cand.get("code", ""),
                 "gated": cand.get("gated"),
                 "recipient": cand.get("recipient", ""),
                 "check": cand.get("check", "")}, rec)
            bytecode_says = "unknown"
            if rec and rec["depth"].get("bytecode_deep") == "ran":
                bytecode_says = "flags"
            corr = sp.corroborate(cand.get("check", "claim"), "flags",
                                  bytecode_says, other_lane="bytecode")
            ev = {"severity": verdict["severity"], "address": addr,
                  "chain": chain_id, "function": cand.get("function", ""),
                  "check": cand.get("check", ""),
                  "confirmation": verdict["verdict"],
                  "confirmation_kind": "tool-confirmed pattern"
                  if verdict["verdict"] == "tool_confirmed_pattern"
                  else verdict["verdict"],
                  "report_class": verdict["report_class"],
                  "recipient": cand.get("recipient", "UNRESOLVED"),
                  "reason": verdict["reason"],
                  "slither": {"ran": slither.get("ran"),
                              "hits": (slither.get("hits") or [])[:6],
                              "reason": slither.get("reason", "")},
                  "fuzz": {"ran": fuzz.get("ran"),
                           "reason": fuzz.get("reason", "")},
                  "steps": path["steps"], "path_verdict": path["verdict"],
                  "corroboration": [corr],
                  "depth": {"confirmation": verdict["verdict"],
                            "storage": "ran" if rec and rec.get("storage")
                            else "absent",
                            "call_graph": (rec or {}).get("depth", {}).get(
                                "call_graph", "absent")},
                  "remediation": _REMEDIATION}
            findings.append(self._f(
                "web3", "candidate_confirmation",
                f"{verdict['severity'].upper()}: candidate "
                f"'{cand.get('check', '')}' on {addr}: "
                f"{verdict['verdict'].replace('_', ' ')} - "
                f"{verdict['reason']}",
                source="candidate confirmation queue (slither)",
                confidence=75 if verdict["verdict"] ==
                "tool_confirmed_pattern" else 55,
                passive=True, evidence=ev))
        res = self._ok(findings,
                       f"confirmation: {len(cands[:4])} candidate(s) "
                       "processed")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
