"""Deep-audit detectors, batch 4: scaffold port (2026-11-04).

Three chain-agnostic EVM detectors ported from a plugin scaffold
Jay pasted on 2026-11-04, rebuilt to the batch-1/2/3 standard:
recipient classification computed inside the detector and carried
on the finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

The pasted scaffold had five rule sets. Three were already fully
covered by the existing registry and were NOT ported (duplicates
help no one): ACC-001's generic ungated-function regex (covered
by contract_logic's access_control_flaw lane, the bsc_access
family and the recipient-first family - and the pasted regex
false-positives on any legitimate ungated function), REC-001
reentrancy (covered by contract_logic's reentrancy lane,
contract_audit's reentrancy check and five specialized
reentrancy detectors - and the pasted pattern is formatting-
crippled: its trailing word-boundary kills the canonical
"call{value: <space>" spelling), and SIG-001 unchecked
ecrecover (covered by deep_audit's ecrecover_zero_signer, a
body-parsing analyzer; the pasted pattern also literally reads
"fecrecover", so as pasted it can never fire). PRC-002 / ORC-001
spot pricing is covered for getReserves (pancake_price_oracle_
manipulation) and balance-ratio shapes (cp_proto_single_source_
oracle); the slice below is the part neither owns.

- bridge_proof_length_unvalidated (from BRG-001): a bridge
  verify / claim path consumes a caller-supplied bytes32[]
  Merkle proof with NO length validation anywhere - no require /
  assert / if condition ever compares the proof's .length
  against an expected depth, a bound, or anything else. The
  pasted rule tried to see this with a negative lookahead for
  "request.depth" in the function header, which regex
  backtracking defeats (the lazy match hops over the modifier's
  closing paren) and which misses the body, where real checks
  live. This analyzer extracts every require / assert / if
  condition in the contract and looks for the proof parameter's
  .length inside one - the check counts wherever it actually
  is, and a loop bound (i < proof.length) does NOT count.
- bridge_root_zero_assertion (from BRG-002): a require / assert
  / if condition in a value-moving or verification function
  asserts a Merkle/root state variable EQUALS the zero hash
  (root == 0x00..00 or bytes32(0)). As a validation gate that
  is mute: it passes exactly when no root is committed, so the
  "check" proves nothing about the proof being verified. The
  one-shot setter shape (require(root == 0) guarding the first
  assignment of that same root, in an initializer / setter
  function) is the legitimate use and stays silent, as does
  the correct require(root != bytes32(0)).
- spot_price_own_balance (the uncovered slice of PRC-002 /
  ORC-001): a price / rate / valuation is computed from a
  token's balanceOf(address(this)) - the contract's OWN spot
  balance - with arithmetic on the balance (a bare reserve
  getter does not fire). Anyone can move that balance in one
  transaction (a direct donation, a flash-minted deposit), so
  every decision priced off it is manipulable. Disjoint from
  cp_proto_single_source_oracle (reserve ratios and
  balanceOf/balanceOf division), pancake_price_oracle_
  manipulation (getReserves consumption) and
  flash_loan_spot_balance_check (the same balance read inside
  a flash-loan function, as a repayment check): TWAP / oracle
  markers anywhere in the contract suppress, as do the ratio
  shape and flash-loan functions. Unlike the pasted ORC-001,
  the token identifier is unrestricted (pairToken, vaultToken,
  any expression) - the pasted token\\d* prefix missed most
  real code. No caller-gate suppression: a gated price getter
  still feeds ungated consumers, so the price source itself
  is the audited mechanism.

Gate discipline: for the two bridge detectors, a caller-
identity gate (only* modifier, msg.sender identity comparison,
role check) on the consuming function suppresses the finding -
a stranger cannot reach the path. The verification under
analysis itself never counts as a gate.

Detection only: verified-source static analysis in the fast
lane, never sends a transaction, never calls the contract
for value. Fetch failure is reported honestly by the shared
scaffolding (analyzed 0 / no verified source - skipped),
never dressed up as a clean result.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from .bsc_common import DetectorSpec, S

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
FAMILY = "deep4"

SPECS = [
    S("bridge_proof_length_unvalidated", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Bridge Merkle proof length never validated: a "
             "caller-supplied bytes32[] proof is consumed by "
             "the verify / claim path and NO require, assert "
             "or if condition anywhere in the contract "
             "compares the proof's length against an expected "
             "depth or any bound. Proof length is part of the "
             "statement being proven (leaf position and tree "
             "shape derive from it); accepting arbitrary-"
             "length proofs lets a caller replay proofs across "
             "trees of different depths and probe the verifier "
             "with shapes the bridge never committed to.",
      fix="Bind the proof length to the committed tree: "
          "require(proof.length == expectedDepth) (or compare "
          "it against the depth recorded with the root / "
          "request) inside the verifier or the claim path, "
          "and reject empty proofs."),
    S("bridge_root_zero_assertion", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Mute root assertion: a validation condition "
             "asserts the Merkle/root variable EQUALS the "
             "zero hash. As a gate in a verify / claim path "
             "that check passes exactly when NO root is "
             "committed, so it validates nothing - a proof "
             "checked under it is checked against an unset "
             "root. (The one-shot setter guard, require(root "
             "== 0) in the function that first assigns that "
             "root, is the legitimate shape and does not "
             "fire.)",
      fix="Assert the committed root is SET and matches the "
          "stored value: require(root != bytes32(0)) and "
          "compare the computed hash against the committed "
          "root state variable, never against a zero literal."),
    S("spot_price_own_balance", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Spot price derived from the contract's own "
             "token balance: a price / rate / valuation is "
             "computed from balanceOf(address(this)) with "
             "arithmetic on the balance. The contract's own "
             "spot balance is movable by anyone in a single "
             "transaction (direct donation, flash-minted "
             "deposit, skim), so every mint / borrow / "
             "settlement priced off it can be manipulated at "
             "near-zero cost. No TWAP, oracle feed or "
             "multi-source safeguard is visible.",
      fix="Price from a manipulation-resistant source: a "
          "TWAP over pair reserves, a vetted oracle feed "
          "(with staleness checks), or internal accounting "
          "that cannot be moved by an unaccounted transfer - "
          "never the live balanceOf(address(this))."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirror batch 3)
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
    """The Nov 2 receive rule, carried on the finding."""
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


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
    """(inner_text, end_pos) for the paren group at open_pos."""
    depth = 0
    i = open_pos
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
        i += 1
    return text[open_pos + 1:], len(text) - 1


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (mirror of batch 3).

    Only an only* modifier, a msg.sender identity comparison,
    or a role check suppresses. The proof verification under
    analysis is NOT a gate here.
    """
    sig, text = fn["signature"], fn["text"]
    if _ONLY_MOD_RE.search(sig) or _IDENTITY_GATE_RE.search(text):
        return True
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i >= 0:
        _, pend = _balanced(stripped, i)
        tail = stripped[pend + 1:]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
            body = scope.modifiers.get(tok)
            if body and ("msg.sender" in body and
                         ("==" in body or "!=" in body)):
                return True
    return False


def _conditions(text: str) -> List[str]:
    """Contents of every require(...) / assert(...) / if(...)
    condition in the text (balanced-paren extraction)."""
    out: List[str] = []
    for m in re.finditer(r"\b(?:require|assert|if)\s*\(", text):
        inner, _ = _balanced(text, m.end() - 1)
        out.append(inner)
    return out


# ---------------------------------------------------------------------------
# 1. bridge_proof_length_unvalidated
# ---------------------------------------------------------------------------

_PROOF_PARAM_RE = re.compile(
    r"bytes32\[\]\s+(?:memory|calldata)\s+(\w+)")
_VALUE_MOVE_RE = re.compile(
    r"\.transfer\s*\(|\.call\s*\{\s*value|_mint\s*\(|\bmint\s*\(|"
    r"safeTransfer|safeMint\s*\(")


def _proof_length_validated(text_all: str,
                            proof_params: List[str]) -> bool:
    """True when some require / assert / if condition in the
    contract actually inspects a proof parameter's .length
    (comparison against anything, or against a depth value).
    A for-loop bound never reaches this scan: loop headers are
    not require / assert / if conditions."""
    conds = _conditions(text_all)
    for name in proof_params:
        len_re = re.compile(r"\b" + re.escape(name) + r"\.length\b")
        for cond in conds:
            if len_re.search(cond) and re.search(
                    r"==|!=|<=|>=|<|>|[Dd]epth", cond):
                return True
    return False


def _analyze_proof_length(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    text_all = scope.scoped_text
    proof_params = sorted(set(_PROOF_PARAM_RE.findall(text_all)))
    if not proof_params:
        return []
    if _proof_length_validated(text_all, proof_params):
        return []
    consumers: List[Dict[str, Any]] = []
    verifiers: List[Dict[str, Any]] = []
    for fn in fns:
        text, sig = fn["text"], fn["signature"]
        uses_proof = any(
            re.search(r"\b" + re.escape(name) + r"\b", sig)
            or re.search(r"\b" + re.escape(name) + r"\s*\[", text)
            or re.search(r"\w*[Vv]erify\w*\s*\([^)]*\b"
                         + re.escape(name) + r"\b", text)
            for name in proof_params)
        if not uses_proof:
            continue
        if _caller_gated(fn, scope):
            continue
        if _VALUE_MOVE_RE.search(text):
            consumers.append(fn)
        elif ("verify" in fn["name"].lower()
              or re.search(r"==\s*\w*[Rr]oot\b", text)
              or "MerkleProof" in text):
            verifiers.append(fn)
    targets = consumers or verifiers
    out: List[Dict[str, Any]] = []
    for fn in targets:
        detail = spec.detail + (
            f" Observed: '{fn['name']}' consumes proof "
            f"parameter(s) {proof_params} and no condition in "
            f"the contract validates their length.")
        item = _hit(spec, fn["name"], cc._snip(fn["text"]),
                    detail,
                    "no proof-length validation found in any "
                    "require / assert / if condition in the "
                    "contract (loop bounds do not count); the "
                    "verifier accepts arbitrary-length proofs")
        out.append(_finish_recipient(spec, item, fn["text"]))
    return out


# ---------------------------------------------------------------------------
# 2. bridge_root_zero_assertion
# ---------------------------------------------------------------------------

_ZERO_HASH = r"(?:0x0{1,64}\b|bytes32\s*\(\s*0\s*\))"
_ROOT_EQ_ZERO_RE = re.compile(
    r"(\w*[Rr]oot\w*)\s*==\s*" + _ZERO_HASH)
_ZERO_EQ_ROOT_RE = re.compile(
    _ZERO_HASH + r"\s*==\s*(\w*[Rr]oot\w*)")
_SETTER_NAME_RE = re.compile(
    r"^(initialize|init|setup|set|commit|update|rotate|store|"
    r"publish)\w*$", re.I)


def _analyze_root_zero(src: str, spec: DetectorSpec,
                       compiler: str = "",
                       contract_name: str = ""
                       ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        ident: Optional[str] = None
        for cond in _conditions(text):
            m = _ROOT_EQ_ZERO_RE.search(cond) or \
                _ZERO_EQ_ROOT_RE.search(cond)
            if m:
                ident = m.group(1)
                break
        if not ident:
            continue
        # Legitimate one-shot setter: this function IS the
        # first assignment of that root (guard + assignment).
        if _SETTER_NAME_RE.match(fn["name"]) or re.search(
                r"\b" + re.escape(ident) + r"\s*=[^=]", text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' asserts "
            f"{ident} == zero-hash in a validation condition "
            f"and never assigns {ident}; the assertion is the "
            f"gate, and it passes only while no root is "
            f"committed.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "root asserted equal to the zero hash in a "
                    "validation path; no committed-root "
                    "comparison gates this function")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. spot_price_own_balance
# ---------------------------------------------------------------------------

_OWN_BALANCE_RE = re.compile(
    r"[\w.]+\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)")
_OWN_BALANCE_ASSIGN_RE = re.compile(
    r"(\w+)\s*=\s*[\w.]+\.balanceOf\s*\(\s*address\s*\(\s*this"
    r"\s*\)\s*\)")
_PRICEY_NAME_RE = re.compile(
    r"price|rate|value|worth|quote|spot|exchange|valuation",
    re.I)
_ORACLE_MARKER_RE = re.compile(
    r"latestRoundData|consult\s*\(|observe\s*\(|TWAP|twap|"
    r"priceCumulative|timeWeighted|sequencerUptime")
_FLASH_NAME_RE = re.compile(
    r"flashLoan|onFlashLoan|executeOperation|flashBorrow", re.I)


def _analyze_spot_own_balance(src: str, spec: DetectorSpec,
                              compiler: str = "",
                              contract_name: str = ""
                              ) -> List[Dict[str, Any]]:
    scope, fns = _scope_fns(src, contract_name)
    if _ORACLE_MARKER_RE.search(scope.scoped_text):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if _FLASH_NAME_RE.search(fn["name"]):
            continue
        if not _OWN_BALANCE_RE.search(text):
            continue
        # Ratio shape (reserve0 / reserve1 from two balance
        # reads) belongs to cp_proto_single_source_oracle.
        if len(re.findall(r"balanceOf\s*\(", text)) >= 2:
            continue
        assigned = _OWN_BALANCE_ASSIGN_RE.findall(text)
        arith = any(
            re.search(r"\b" + re.escape(v) + r"\b\s*[*/]"
                      r"|" r"[*/]\s*\b" + re.escape(v) + r"\b",
                      text)
            for v in assigned)
        # Inline use: balanceOf(address(this)) itself inside a
        # multiplication / division expression.
        if not arith:
            arith = bool(re.search(
                r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
                r"\s*[*/]|[*/]\s*[\w.]*\.?balanceOf\s*\("
                r"\s*address\s*\(\s*this\s*\)\s*\)", text))
        if not (arith or _PRICEY_NAME_RE.search(fn["name"])):
            continue  # bare reserve getter / accounting read
        if not arith:
            continue  # a price-named getter returning the raw
            # balance is a reserve view, not a derived price
        detail = spec.detail + (
            f" Observed: '{fn['name']}' derives a value from "
            f"balanceOf(address(this))"
            + (f" via variable(s) {assigned}" if assigned
               else " inline")
            + " with arithmetic on the live balance.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "price source is the contract's own live "
                    "balance; no TWAP / oracle marker anywhere "
                    "in the contract")
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "bridge_proof_length_unvalidated": _analyze_proof_length,
    "bridge_root_zero_assertion": _analyze_root_zero,
    "spot_price_own_balance": _analyze_spot_own_balance,
}


def analyze_deep4_source(src: str, spec: DetectorSpec,
                         compiler: str = "",
                         contract_name: str = ""
                         ) -> List[Dict[str, Any]]:
    """Run ONE batch-4 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-3 collection / fetch /
# proxy resolution; analysis is analyze_deep4_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit4Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 4)"
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
        if not work or spec is None:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed, e.g. bsc:0x...) "
                "or a web target whose pages reference one")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
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
                                     role=role, impl_addr=impl)
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
            role="implementation", proxy_addr=addr) or got

    def _analyze_contract(self, chain: cc.ChainConfig, addr: str,
                          src: Optional[Dict[str, Any]],
                          findings: List[Finding], role: str,
                          proxy_addr: str = "",
                          impl_addr: str = "") -> bool:
        spec = self._spec
        if spec is None or not src:
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
        for item in analyze_deep4_source(
                src["source"], spec, src.get("compiler", ""),
                contract_name=src.get("contract_name", "")):
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
            fn_txt = f"function '{item['function']}' " \
                if item["function"] else ""
            findings.append(self._f(
                "web3", spec.id,
                f"{item['severity'].upper()}: {spec.label}: "
                f"{fn_txt}in contract {addr} on {chain.name}{tag}"
                f"\n\n{item['detail']}\n\nCode:\n{item['code']}",
                source="deep audit detector batch 4 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit4Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 4) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
