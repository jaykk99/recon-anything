"""Deep-audit detectors, batch 19: signatures and randomness.

Four chain-agnostic EVM detectors from the standing backlog queue,
built to the batch-11 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- ecrecover_no_malleability_guard: a function recovers a signer
  with raw ecrecover() and never bounds the s value. A
  malleable signature (s, 2^256 - s) recovers the same signer,
  so one authorization can be replayed as a second, distinct
  signature - the SWC-117 shape. OpenZeppelin ECDSA
  (ECDSA.recover / tryRecover) or an explicit s <= n/2 guard in
  the function is the protected shape.
- signature_replay_no_nonce: a function recovers a signer and
  then changes state or moves value, with no nonce consumed
  anywhere on the path (no nonces[] read/write, no nonce++,
  no used-signature / executed / spent marker). The same
  signature authorizes the action again, forever - the
  meta-transaction / forwarder replay shape. A consumed nonce
  (nonces[owner]++, usedSignatures[hash]) is the protected
  shape. Distinct from the malleability detector: this one is
  about the signature being reusable at all, not about a
  second valid form of the same signature.
- permit_no_domain_separator: an EIP-2612-style permit()
  function (v, r, s params) that builds its digest with
  keccak256(abi.encodePacked(...)) and no domain binding - no
  DOMAIN_SEPARATOR, no block.chainid, no EIP-712 typed-data
  hash. The same signature is valid on every chain and every
  contract that copies the digest layout, so an approval
  signed for one deployment can be replayed on another. A
  domain separator (EIP712 / _hashTypedDataV4 / block.chainid)
  is the protected shape.
- weak_onchain_randomness: block.timestamp / blockhash /
  block.difficulty / block.prevrandao feeds a random outcome -
  hashed and modded, or assigned to a random/winner/lucky
  variable. Miners / validators choose the timestamp and the
  blockhash is public before the block is mined, so the
  outcome is predictable - the SWC-120 shape. Chainlink VRF
  (requestRandomWords / fulfillRandomWords) is the protected
  shape. Plain timestamp use (deadlines, locks, vesting
  checks) stays silent: only a hash/modulo/random-named
  assignment counts, and a bare require/assert condition
  never fires.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path. The signature
check under analysis itself does NOT count as such a gate.

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
FAMILY = "deep19"

SPECS = [
    S("ecrecover_no_malleability_guard", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Raw ecrecover() with no s-value bound: a function "
             "recovers a signer with ecrecover() and never checks "
             "that s is in the lower half of the curve order, so "
             "the malleable twin (s -> n - s) recovers the same "
             "signer and one authorization counts as two distinct "
             "signatures - the SWC-117 shape. OpenZeppelin ECDSA "
             "(ECDSA.recover / tryRecover) or an explicit "
             "require(s <= n/2) guard is the protected shape.",
      fix="Use OpenZeppelin ECDSA.recover / tryRecover, which "
          "rejects malleable s values, or add an explicit "
          "require(s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
          "5D576E7357A4501DDFE92F46681B20A0) guard before "
          "calling ecrecover()."),
    S("signature_replay_no_nonce", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Signature verified once, reusable forever: a "
             "function recovers a signer and then changes state "
             "or moves value, with no nonce consumed on the path "
             "(no nonces[] read/write, no nonce++, no "
             "used-signature / executed / spent marker). The same "
             "signature authorizes the action again on every "
             "replay - the meta-transaction / forwarder replay "
             "shape. A consumed nonce (nonces[owner]++, "
             "usedSignatures[hash]) is the protected shape.",
      fix="Bind every signed action to a nonce: read and "
          "increment a per-signer nonces[] counter (or mark the "
          "signature hash used) inside the function, and include "
          "the nonce in the signed digest."),
    S("permit_no_domain_separator", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="EIP-2612-style permit() with no domain binding: the "
             "function builds its digest with "
             "keccak256(abi.encodePacked(...)) and no "
             "DOMAIN_SEPARATOR, no block.chainid, no EIP-712 "
             "typed-data hash. The same signature is valid on "
             "every chain and every contract that copies the "
             "digest layout, so an approval signed for one "
             "deployment replays on another. A domain separator "
             "(EIP712 / _hashTypedDataV4 / block.chainid) is the "
             "protected shape.",
      fix="Build the permit digest with EIP-712 typed data "
          "(_hashTypedDataV4 / DOMAIN_SEPARATOR including "
          "block.chainid), or include block.chainid and the "
          "contract address in the hashed digest."),
    S("weak_onchain_randomness", FAMILY, severity="medium",
      outcome="a", recipient=False,
      detail="Block entropy used as randomness: block.timestamp / "
             "blockhash / block.difficulty / block.prevrandao "
             "feeds a random outcome (hashed and modded, or "
             "assigned to a random / winner / lucky variable). "
             "Validators choose the timestamp and the blockhash "
             "is public before mining, so the outcome is "
             "predictable - the SWC-120 shape. Chainlink VRF "
             "(requestRandomWords / fulfillRandomWords) is the "
             "protected shape. Plain timestamp use (deadlines, "
             "locks, vesting) stays silent.",
      fix="Use Chainlink VRF (requestRandomWords / "
          "fulfillRandomWords) for on-chain randomness, or a "
          "commit-reveal scheme. Never derive a random outcome "
          "from block.timestamp, blockhash, block.difficulty or "
          "block.prevrandao."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep16)
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
            "stranger can trigger this but receives nothing - "
            "classified TRIGGER-ONLY under the receive rule.")
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


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (see module docstring).

    Only an only* modifier, a msg.sender identity comparison,
    or a role check suppresses. The signature check and the
    _msgSender() gate under analysis are NOT gates here.
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


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
    """(inner_text, end_pos) for the paren group at open_pos."""
    depth = 0
    for i in range(open_pos, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
    return text[open_pos + 1:], len(text)


def _split_top(text: str) -> List[str]:
    depth = 0
    parts: List[str] = []
    cur: List[str] = []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]


def _skip_fn(fn: Dict[str, Any], scope) -> bool:
    if re.search(r"\b(view|pure)\b", fn["signature"]):
        return True
    return _caller_gated(fn, scope)


def _fn_params(fn: Dict[str, Any]) -> List[str]:
    """Parameter names from a function signature."""
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:
                sig.rindex(")") if ")" in sig else len(sig)]
    out: List[str] = []
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2:
            out.append(toks[-1])
    return out


# ---------------------------------------------------------------------------
# Signature / randomness patterns
# ---------------------------------------------------------------------------

_ECRECOVER_RE = re.compile(r"\becrecover\s*\(")
# Raw ecrecover() as a free call, NOT the ECDSA.recover() method:
# "ECDSA.recover(" must not count as a raw recovery (BoldToken's
# inherited OZ permit calls ECDSA.recover, which enforces the
# s-bound internally; flagging it was a live-run false positive).
_RAW_ECRECOVER_RE = re.compile(r"(?<!\.)\becrecover\s*\(")
_ECDSA_RECOVER_RE = re.compile(r"\bECDSA\.(?:recover|tryRecover)\s*\(")
_OZ_ECDSA_RE = re.compile(
    r"import\s+[^;]*ECDSA|ECDSA\.(?:recover|tryRecover)\s*\(")

# An s-value bound on the signature's s component, in any of the
# spellings contracts use: require(s <= ...), s < 0x7fff...,
# s <= HALF_N / secp256k1n/2, or a malleability check by name.
_S_GUARD_RES = (
    re.compile(r"require\s*\(\s*s\s*(<=|<)\s*0x7[fF]"),
    re.compile(r"\bs\s*(<=|<)\s*0x7[fF][0-9a-fA-F]*"),
    re.compile(r"\bs\s*(<=|<)\s*(?:HALF_N|halfN|HALF_ORDER|"
               r"SECP256K1_N_HALF|n\s*/\s*2|secp256k1n\s*/\s*2)"),
    re.compile(r"require\s*\(\s*s\s*(<=|<)\s*[A-Za-z_][A-Za-z0-9_]*"
               r"\s*/\s*2"),
    re.compile(r"if\s*\(\s*s\s*>\s*[^)]+\)\s*revert", re.I),
    re.compile(r"malleab", re.I),
    # Cast-wrapped s bound (Axelar live-run FP): the check is
    # spelled `if (uint256(s) > 0x7FFF...B20A0) revert InvalidS();`
    # rather than a bare `s <= ...`, so the plain `s <= 0x7f`
    # spellings above miss it.
    re.compile(r"uint256\s*\(\s*_?s\s*\)\s*(>|>=|<|<=)\s*0x7[fF]"),
    re.compile(r"\(\s*_?s\s*\)\s*(>|>=)\s*0x7[fF]"),
)

# A nonce consumed on the signature path: a nonces[] read/write,
# a nonce counter increment, a used-signature / executed / spent
# marker, or the OZ useNonce() helper.
_NONCE_USE_RES = (
    # Leading underscore allowed: dYdX/WrappedLYX spell the mapping
    # `_nonces[...]`, and `\bnonces` never matches after `_`.
    re.compile(r"\b_?nonces?\s*\["),
    # A write to the nonce mapping consumes it even when the
    # increment is a read-into-local + write-back
    # (`_nonces[owner] = currentValidNonce.add(1)`, dYdX) or a
    # boolean mark (`_nonces[bridgeNonce] = true`, WrappedLYX).
    re.compile(r"_?nonces?\s*\[[^\]]*\]\s*="),
    re.compile(r"\bnonce\s*\+\+"),
    re.compile(r"\+\+\s*nonce\b"),
    re.compile(r"\bnonce\s*\+=\s*1\b"),
    re.compile(r"\bnonce\s*=\s*nonce\s*\+"),
    re.compile(r"\bused\w*\s*\["),
    re.compile(r"\bexecuted\w*\s*\["),
    re.compile(r"\bconsumed\w*\s*\["),
    re.compile(r"\bspent\w*\s*\["),
    re.compile(r"\buseNonce\s*\("),
    re.compile(r"require\s*\(\s*!\s*used\w*"),
)

# A domain binding on a signed digest: EIP-712 domain separator,
# chain id, or the OZ typed-data helper.
_DOMAIN_BIND_RES = (
    # Substring, not \b-bounded: the Dollar permit binds via
    # `LibEIP712.hashEIP712Message(EIP712_DOMAIN_SEPARATOR, ...)`
    # and `\bDOMAIN_SEPARATOR\b` never matches inside the
    # `EIP712_`-prefixed identifier.
    re.compile(r"DOMAIN_SEPARATOR"),
    re.compile(r"hashEIP712Message"),
    re.compile(r"\bdomainSeparator\b"),
    re.compile(r"\bblock\.chainid\b"),
    re.compile(r"\bEIP712\b"),
    re.compile(r"_hashTypedDataV4\s*\("),
    re.compile(r"\bhashTypedData\b"),
)

# Block entropy sources a contract can read.
_BLOCK_ENTROPY_RE = re.compile(
    r"\bblock\.(?:timestamp|difficulty|prevrandao)\b|"
    r"\bblockhash\s*\(")

# Chainlink VRF: the protected randomness shape.
_VRF_RE = re.compile(
    r"\bVRFConsumerBase\b|requestRandomWords\s*\(|"
    r"fulfillRandomWords\s*\(|VRFCoordinator")


def _uses_oz_ecdsa(scoped: str) -> bool:
    return bool(_OZ_ECDSA_RE.search(scoped))


def _s_guard_present(text: str) -> bool:
    return any(p.search(text) for p in _S_GUARD_RES)


def _nonce_consumed(text: str) -> bool:
    return any(p.search(text) for p in _NONCE_USE_RES)


def _domain_bound(text: str) -> bool:
    return any(p.search(text) for p in _DOMAIN_BIND_RES)


def _recovers_signer(text: str) -> Optional[int]:
    """Position of the first signature-recovery call, or None."""
    m = _ECRECOVER_RE.search(text)
    if m:
        return m.start()
    m = _ECDSA_RECOVER_RE.search(text)
    if m:
        return m.start()
    return None


def _acts_after(text: str, pos: int, state: set) -> bool:
    """A state write or external call after `pos` in the function."""
    for p, _v in cl._state_writes(text, state):
        if p > pos:
            return True
    for c in cl._external_calls(text):
        if c["pos"] > pos:
            return True
    return False


# ---------------------------------------------------------------------------
# 1. ecrecover_no_malleability_guard (SWC-117)
# ---------------------------------------------------------------------------

def _analyze_ecrecover_malleability(src, spec, compiler,
                                    contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    if _uses_oz_ecdsa(scoped):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if not _RAW_ECRECOVER_RE.search(text):
            continue
        if _s_guard_present(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' calls raw ecrecover() "
            f"with no s <= n/2 guard and no OpenZeppelin ECDSA "
            f"in the contract, so the malleable twin signature "
            f"(s -> n - s) recovers the same signer. Gate "
            f"analysis: no caller-identity gate, no s-value "
            f"bound on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated ecrecover: raw recovery with no "
                    "s-value bound, no OZ ECDSA")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 2. signature_replay_no_nonce
# ---------------------------------------------------------------------------

def _analyze_signature_replay(src, spec, compiler,
                              contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    state = cl.state_variables(scoped)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        pos = _recovers_signer(text)
        if pos is None:
            continue
        if not _acts_after(text, pos, state):
            continue
        if _nonce_consumed(text):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' recovers a signer and "
            f"then changes state / moves value, with no nonce "
            f"consumed anywhere in the function (no nonces[] "
            f"read/write, no nonce++, no used-signature marker), "
            f"so the same signature authorizes the action again "
            f"on every replay. Gate analysis: no "
            f"caller-identity gate, no nonce on the path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated signature action: signer recovered, "
                    "state changed, no nonce consumed")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 3. permit_no_domain_separator
# ---------------------------------------------------------------------------

def _analyze_permit_no_domain(src, spec, compiler,
                              contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"].lower() != "permit":
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        if not ({"v", "r", "s"} <= set(params) or
                "signature" in params):
            continue
        if _recovers_signer(text) is None:
            continue
        if "keccak256" not in text:
            continue
        if _domain_bound(text) or _domain_bound(scoped):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' builds its permit "
            f"digest with keccak256(abi.encodePacked(...)) and "
            f"verifies it with ecrecover, with no "
            f"DOMAIN_SEPARATOR, block.chainid or EIP-712 "
            f"typed-data hash anywhere in the contract, so the "
            f"same signature is valid on every chain and every "
            f"contract copying this digest layout. Gate "
            f"analysis: no caller-identity gate, no domain "
            f"binding on the digest.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated permit: digest has no domain "
                    "separator, no chain id, no EIP-712 binding")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 4. weak_onchain_randomness (SWC-120)
# ---------------------------------------------------------------------------

_RANDOM_NAME_RE = re.compile(
    r"\b(?:random|rand|winner|winning|lucky|draw\w*)\b", re.I)


def _statement_of(text: str, pos: int) -> str:
    """The ;-terminated statement containing `pos`."""
    start = max(text.rfind(";", 0, pos), text.rfind("{", 0, pos))
    end = text.find(";", pos)
    if end < 0:
        end = len(text)
    return text[start + 1:end + 1]


def _randomness_legs(text: str) -> List[str]:
    """Evidence strings for block entropy feeding a random outcome.

    Leg A: a % operator whose statement assigns / returns a value
    derived from block entropy (or a hash of it). A bare
    require/assert condition never counts: a day-boundary check
    (block.timestamp % 86400 == 0) is not randomness.
    Leg B: an assignment to a random/winner/lucky-named variable
    whose right-hand side contains block entropy (or a hash of
    it).
    """
    legs: List[str] = []
    for m in re.finditer(r"%", text):
        stmt = _statement_of(text, m.start())
        left = stmt[:stmt.find("%")]
        # Block entropy must appear on the left of the modulo
        # (directly, or inside the hashed input). A bare keccak
        # of user data is not block randomness.
        if not _BLOCK_ENTROPY_RE.search(left):
            continue
        if re.match(r"\s*(require|assert)\s*\(", stmt):
            continue
        if "=" not in stmt and not re.search(r"\breturn\b", stmt):
            continue
        legs.append(f"modulo on block entropy: "
                    f"'{stmt.strip()[:120]}'")
    for m in _RANDOM_NAME_RE.finditer(text):
        # assignment to a random-named variable: `random = ...;`
        # (also `uint256 random = ...;` - the name is the last
        # token before `=` on the statement's left side)
        tail = text[m.end():m.end() + 80]
        eq = re.match(r"\s*(?:\[[^\]]*\]\s*)?=\s*[^=]", tail)
        if not eq:
            continue
        semi = text.find(";", m.end())
        rhs = text[m.end():semi if semi >= 0 else len(text)]
        if _BLOCK_ENTROPY_RE.search(rhs):
            legs.append(f"random-named assignment from block "
                        f"entropy: '{rhs.strip()[:120]}'")
    return legs


def _analyze_weak_randomness(src, spec, compiler,
                             contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    if _VRF_RE.search(scoped):
        return []
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        if not _BLOCK_ENTROPY_RE.search(text):
            continue
        legs = _randomness_legs(text)
        if not legs:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' derives a random "
            f"outcome from block entropy - "
            f"{'; '.join(legs)}. Gate analysis: no "
            f"caller-identity gate, no VRF in the contract.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated randomness: block entropy hashed / "
                    "modded into a random outcome, no VRF")
        out.append(item)
    return out


ANALYZERS = {
    "ecrecover_no_malleability_guard": _analyze_ecrecover_malleability,
    "signature_replay_no_nonce": _analyze_signature_replay,
    "permit_no_domain_separator": _analyze_permit_no_domain,
    "weak_onchain_randomness": _analyze_weak_randomness,
}


def analyze_deep19_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-19 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep16 collection /
# fetch / proxy resolution; analysis is analyze_deep19_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit19Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 17)"
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
        for item in analyze_deep19_source(
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
                source="deep audit detector batch 19 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit19Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 19) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
