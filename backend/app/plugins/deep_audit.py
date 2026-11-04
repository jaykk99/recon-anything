"""Deep-audit detectors: AI plugin dev, day 1 (2026-11-03).

Five chain-agnostic EVM detectors built from fresh hunting
research (see the AI dev research log), each one a class the
commodity template scanners do not cover and the existing
registry does not duplicate:

- vault_share_inflation: ERC-4626 first-depositor / donation
  share inflation. Cross-function dataflow: totalAssets() backed
  by the raw token balance (donation-sensitive) while the share
  conversion divides by it with NO virtual offset, dead-share
  bootstrap or minimum-shares guard. (contract_logic has no
  vault coverage; cp_proto_rounding_order is about rounding
  direction only.)
- readonly_reentrancy_gap: read-only reentrancy. View / pricing
  functions that read pool state WITHOUT the reentrancy lock
  their state-changing siblings carry, on a contract with an
  external-call surface (the dForce / Curve pattern).
  contract_logic flags call-before-write in state-changing
  functions; it never checks guard COVERAGE of the views other
  protocols price against.
- diamond_cut_ungated: EIP-2535 diamondCut reachable with no
  owner gate - no gate modifier or helper, and no
  LibDiamond.enforceIsContractOwner anywhere in the compilation.
  Gate-aware: the canonical gate inside LibDiamond.diamondCut
  suppresses the finding.
- aa_validation_ungated: ERC-4337 validateUserOp /
  validatePaymasterUserOp with no EntryPoint caller check and/or
  no signature validation at all (accept-all validator = account
  takeover; unvalidated paymaster = sponsorship drain).
- ecrecover_zero_signer: raw ecrecover compared against a stored
  or caller-supplied signer with NO address(0) check. ecrecover
  returns address(0) on ANY invalid signature, so while the
  signer slot is unset (or set to zero) a garbage signature
  authenticates. Distinct from the ecdsa_* plugins (malleability,
  nonce reuse, cross-chain replay); OpenZeppelin ECDSA.recover,
  which reverts on bad signatures, stays silent.

Same discipline as the BSC-100 train: verified-source static
analysis in the fast lane, scope / gate / recipient machinery
imported from contract_logic, findings carry the exact code,
gated or protected shapes stay silent. Detection only: never
sends a transaction, never calls the contract.
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
FAMILY = "deep"

SPECS = [
    S("vault_share_inflation", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="ERC-4626 share inflation (first-depositor / "
             "donation attack): totalAssets() is the vault's raw "
             "asset balance, so anyone can move it with a direct "
             "transfer, and the share conversion divides by that "
             "balance with no virtual-share offset, no dead-share "
             "bootstrap mint and no minimum-shares guard. The "
             "first depositor mints 1 share, donates a large sum "
             "directly to the vault, and later depositors are "
             "minted 0 (or dust) shares for real money, which "
             "the attacker then redeems against their deposits.",
      fix="Price shares off internal accounting or add the "
          "OpenZeppelin virtual-shares offset (_decimalsOffset / "
          "totalAssets + 1, totalSupply + 10**offset), mint "
          "dead shares at bootstrap, and reject zero-share "
          "deposits."),
    S("readonly_reentrancy_gap", FAMILY, severity="high",
      outcome="a",
      detail="Read-only reentrancy guard gap: state-changing "
             "functions carry a reentrancy lock and the contract "
             "makes external calls, but a view / pricing function "
             "reads the same pool state WITHOUT the lock. During "
             "a callback (token hook, ETH receive, flash-loan "
             "callback) the pool is mid-update, and any protocol "
             "pricing off this view reads the stale, manipulated "
             "state - the dForce / Curve read-only reentrancy "
             "shape. The view itself cannot be reentered for "
             "writes; the victim is whoever trusts its answer "
             "mid-transaction.",
      fix="Extend the reentrancy lock to the pricing views "
          "(nonReentrant / nonReentrantView on view functions "
          "that read pool state), or make consumers check the "
          "lock status before trusting the view."),
    S("diamond_cut_ungated", FAMILY, severity="high",
      outcome="a",
      detail="Unprotected diamondCut (EIP-2535): the facet "
             "replacement entry point performs the cut with no "
             "owner gate - no gate modifier, no gated helper, "
             "and no LibDiamond.enforceIsContractOwner call in "
             "the facet or the library path. Any stranger can "
             "point any function selector at any facet, including "
             "replacing diamondCut itself: full, permanent "
             "takeover of the diamond.",
      fix="Gate diamondCut with contract ownership "
          "(LibDiamond.enforceIsContractOwner inside the cut "
          "path, or an onlyOwner / role modifier on the facet "
          "entry point)."),
    S("aa_validation_ungated", FAMILY, severity="high",
      outcome="a",
      detail="ERC-4337 validation without gates: a "
             "validateUserOp / validatePaymasterUserOp that the "
             "EntryPoint does not exclusively own and/or that "
             "performs no signature validation accepts every "
             "operation it is shown. An account validator like "
             "this lets anyone execute as the account through "
             "the real EntryPoint (full wallet drain); a "
             "paymaster validator like this lets anyone spend "
             "the paymaster's deposit on their own operations.",
      fix="Require the EntryPoint as the only caller "
          "(_requireFromEntryPoint / msg.sender == entryPoint) "
          "and actually verify the signature in validation, "
          "returning SIG_VALIDATION_FAILED on mismatch (the "
          "OpenZeppelin BaseAccount / verifying paymaster "
          "shape)."),
    S("ecrecover_zero_signer", FAMILY, severity="high",
      outcome="a",
      detail="ecrecover zero-address signer bypass: the "
             "recovered address is compared against a signer "
             "stored in state (or supplied by the caller) with "
             "no address(0) check on the recovery. ecrecover "
             "returns address(0) for ANY malformed signature, "
             "so whenever the signer slot is unset, zeroed by "
             "rotation, or attacker-supplied as zero, a garbage "
             "signature authenticates as the signer.",
      fix="Require the recovered address to be non-zero "
          "(require(recovered != address(0))) before comparing "
          "it, or use OpenZeppelin ECDSA.recover, which reverts "
          "on invalid signatures instead of returning "
          "address(0)."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _scope_fns(src: str, contract_name: str):
    scope = cl._Scope(src, contract_name)
    fns = [fn for fn in scope.functions if "{" in fn["text"]]
    return scope, fns


def _hit(spec: DetectorSpec, fn_name: str, code: str,
         detail: str) -> Dict[str, Any]:
    return {"kind": spec.id, "severity": spec.severity,
            "function": fn_name, "code": code, "detail": detail}


def _finish_recipient(spec: DetectorSpec, item: Dict[str, Any],
                      fn_text: str) -> Dict[str, Any]:
    """The Nov 2 receive rule, same as the BSC train: value that
    lands at a FIXED / HOLDER-SELF destination is trigger-only."""
    if not fn_text:
        return item
    recipient, rdetail = cl.classify_recipient(fn_text)
    item["recipient"] = recipient
    if recipient in ("FIXED", "HOLDER-SELF"):
        item["report_class"] = "trigger_only"
        item["severity"] = "low"
        item["detail"] += (
            f" Recipient analysis: moved value lands at a "
            f"{recipient} destination ({rdetail}), so a stranger "
            "can trigger this but receives nothing - classified "
            "TRIGGER-ONLY under the receive rule.")
    else:
        item["report_class"] = "candidate"
    return item


# ---------------------------------------------------------------------------
# 1. ERC-4626 share inflation
# ---------------------------------------------------------------------------

def _analyze_vault_inflation(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    scoped = scope.scoped_text
    by_name: Dict[str, Dict[str, Any]] = {}
    for fn in fns:
        by_name.setdefault(fn["name"], fn)
    ta = by_name.get("totalAssets")
    deposit = by_name.get("deposit") or by_name.get("mint")
    if ta is None or deposit is None:
        return []
    conv = (by_name.get("_convertToShares")
            or by_name.get("convertToShares"))
    conv_text = conv["text"] if conv else deposit["text"]
    conv_name = conv["name"] if conv else deposit["name"]
    # totalAssets must be donation-sensitive: the RAW balance.
    if not re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)",
                     ta["text"]):
        return []
    # The conversion must price shares off that balance.
    if "totalAssets" not in conv_text or "/" not in conv_text:
        return []
    if not re.search(r"totalSupply|totalShares", conv_text):
        return []
    # Protections (any one suppresses): virtual offset in the
    # OZ shape, totalAssets()+1 in the conversion, a 10**offset
    # term in the conversion, a dead-share bootstrap mint, or a
    # minimum-shares constant actually used on the deposit path.
    if "_decimalsOffset" in scoped:
        return []
    if re.search(r"totalAssets\s*\(\s*\)\s*\+\s*1\b", conv_text):
        return []
    if re.search(r"\+\s*10\s*\*\*", conv_text):
        return []
    if re.search(r"_mint\s*\(\s*address\s*\(\s*0\s*\)", scoped):
        return []
    if re.search(r"MINIMUM_(SHARES|LIQUIDITY|DEPOSIT)", scoped) \
            and "MINIMUM" in (conv_text + deposit["text"]):
        return []
    detail = spec.detail + (
        f" Observed: totalAssets() returns the raw asset "
        f"balance and '{conv_name}' divides by it with no "
        "virtual offset, dead-share bootstrap or minimum-shares "
        "guard in scope.")
    item = _hit(spec, "totalAssets", cc._snip(ta["text"]), detail)
    pay_fn = (by_name.get("redeem") or by_name.get("withdraw")
              or deposit)
    # Recipient classification for this class needs the
    # cross-function fact the generic classifier cannot see:
    # the payout leg meters the caller's own shares (a
    # HOLDER-SELF shape in isolation), but the payout is priced
    # off the donation-sensitive totalAssets proven above, so
    # the redeeming stranger receives assets BEYOND their own
    # deposit - the excess is caller-received value taken from
    # later depositors. A FIXED payout destination stays
    # trigger-only under the receive rule.
    recipient, rdetail = cl.classify_recipient(pay_fn["text"])
    item["recipient"] = recipient
    if recipient == "FIXED":
        item["report_class"] = "trigger_only"
        item["severity"] = "low"
        item["detail"] += (
            f" Recipient analysis: the payout destination is "
            f"FIXED ({rdetail}), so a stranger can trigger "
            "this but receives nothing - classified "
            "TRIGGER-ONLY under the receive rule.")
    else:
        item["report_class"] = "candidate"
        if recipient == "HOLDER-SELF":
            item["detail"] += (
                " Recipient analysis: the payout leg meters "
                "the caller's own shares (HOLDER-SELF shape), "
                "but it is priced off the donation-sensitive "
                "totalAssets above, so the redeeming stranger "
                "receives assets beyond their own deposit - "
                "the excess is CALLER-received, classified "
                "CANDIDATE under the receive rule.")
    return [item]


# ---------------------------------------------------------------------------
# 2. Read-only reentrancy guard gap
# ---------------------------------------------------------------------------

_PRICING_FN_RE = re.compile(
    r"price|virtual|rate|ratio|reserve|exchange|index|accru|"
    r"oracle|quote", re.I)
_LOCK_BODY_RE = re.compile(
    r"(locked|_status|reentrancy|entered)\w*\s*=\s*"
    r"(true|2|_ENTERED|ENTERED)", re.I)


def _guard_names(scope) -> set:
    names = {"nonReentrant", "nonReentrantView"}
    for name, body in scope.modifiers.items():
        if _LOCK_BODY_RE.search(body):
            names.add(name)
    return names


def _sig_has_guard(sig: str, guards: set) -> bool:
    return any(re.search(r"\b" + re.escape(g) + r"\b", sig)
               for g in guards if g)


def _analyze_readonly_reentrancy(src, spec, compiler,
                                 contract_name):
    scope, fns = _scope_fns(src, contract_name)
    guards = _guard_names(scope)
    locked = [fn for fn in fns
              if not re.search(r"\b(view|pure)\b", fn["signature"])
              and _sig_has_guard(fn["signature"], guards)]
    if not locked:
        return []  # no lock anywhere: plain-reentrancy territory
    surface = [fn for fn in fns if cl._external_calls(fn["text"])]
    if not surface:
        return []  # no way to be mid-callback
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        sig = fn["signature"]
        if not re.search(r"\bview\b", sig):
            continue
        if _sig_has_guard(sig, guards):
            continue
        reads = sorted(
            v for v in state
            if re.search(r"\b" + re.escape(v) + r"\b", fn["text"]))
        pricing = bool(_PRICING_FN_RE.search(fn["name"])) or \
            ("/" in fn["text"] and len(reads) >= 2)
        if not pricing:
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' reads pool state "
            f"({', '.join(reads[:4]) or 'derived balances'}) "
            f"with no reentrancy lock, while "
            f"'{locked[0]['name']}' carries one and "
            f"'{surface[0]['name']}' makes external calls.")
        out.append(_hit(spec, fn["name"], cc._snip(fn["text"]),
                        detail))
        if len(out) >= 3:
            break
    return out


# ---------------------------------------------------------------------------
# 3. Unprotected diamondCut (EIP-2535)
# ---------------------------------------------------------------------------

def _analyze_diamond_cut(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    # The canonical gate lives inside LibDiamond.diamondCut,
    # which may sit in a different unit of the same compilation
    # than the scoped facet: check the whole source.
    enforces = "enforceIsContractOwner" in cc._strip_comments(src)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"].lower() != "diamondcut":
            continue
        text = fn["text"]
        routes_cut = "diamondCut(" in text
        writes_facets = bool(re.search(
            r"facetAddress|selectorToFacet|facetFunctionSelectors",
            text))
        if not (routes_cut or writes_facets):
            continue
        if enforces:
            continue  # canonical LibDiamond gate in the path
        if cl._gated_deep(fn, scope):
            continue
        detail = spec.detail + (
            " Observed: this diamondCut performs facet "
            "replacement with no owner gate in the function, "
            "its modifiers, its internal helpers, or a "
            "LibDiamond.enforceIsContractOwner call anywhere "
            "in the compilation.")
        out.append(_hit(spec, fn["name"], cc._snip(text), detail))
    return out


# ---------------------------------------------------------------------------
# 4. ERC-4337 validation gates
# ---------------------------------------------------------------------------

def _entrypoint_checked(fn, scope) -> bool:
    sig, text = fn["signature"], fn["text"]
    if "_requireFromEntryPoint" in text or \
            "_requireFromEntryPoint" in sig:
        return True
    if re.search(r"msg\.sender\s*(?:==|!=)\s*[^\n;]{0,40}"
                 r"entrypoint", text, re.I):
        return True
    if re.search(r"entrypoint[^\n;]{0,40}(?:==|!=)\s*msg\.sender",
                 text, re.I):
        return True
    for name, body in scope.modifiers.items():
        if re.search(r"\b" + re.escape(name) + r"\b", sig) and \
                re.search(r"entrypoint", body, re.I) and \
                "msg.sender" in body:
            return True
    return False


_VALIDATION_RE = re.compile(
    r"ecrecover|ECDSA\.recover|tryRecover|SIG_VALIDATION_FAILED|"
    r"\.recover\s*\(")


def _validation_present(fn, scope) -> bool:
    if _VALIDATION_RE.search(fn["text"]):
        return True
    for name, helper in scope.helpers.items():
        if name == fn["name"]:
            continue
        if re.search(r"\b" + re.escape(name) + r"\s*\(",
                     fn["text"]) and \
                _VALIDATION_RE.search(helper["text"]):
            return True
    return False


def _analyze_aa_validation(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if fn["name"] not in ("validateUserOp",
                              "validatePaymasterUserOp"):
            continue
        ep = _entrypoint_checked(fn, scope)
        val = _validation_present(fn, scope)
        if ep and val:
            continue
        missing = []
        if not ep:
            missing.append("no EntryPoint caller check")
        if not val:
            missing.append("no signature validation")
        detail = spec.detail + (
            f" Observed: {fn['name']} has "
            f"{' and '.join(missing)}.")
        out.append(_hit(spec, fn["name"], cc._snip(fn["text"]),
                        detail))
    return out


# ---------------------------------------------------------------------------
# 5. ecrecover zero-address signer
# ---------------------------------------------------------------------------

def _fn_param_names(sig: str) -> set:
    i = sig.find("(")
    if i < 0:
        return set()
    j = sig.rfind(")")
    inner = sig[i + 1:j] if j > i else ""
    names = set()
    for part in inner.split(","):
        toks = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", part)
        if toks:
            names.add(toks[-1])
    return names


def _analyze_ecrecover_zero(src, spec, compiler, contract_name):
    scope, fns = _scope_fns(src, contract_name)
    state = cl.state_variables(scope.scoped_text)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        text = fn["text"]
        if "ecrecover(" not in text:
            continue
        params = _fn_param_names(fn["signature"])
        recovered_vars = set(re.findall(
            r"(\w+)\s*=\s*(?:[\w\.]+\s*)?ecrecover\s*\(", text))
        fired = False
        for var in recovered_vars:
            if re.search(r"\b" + re.escape(var) +
                         r"\b\s*!=\s*address\s*\(\s*0\s*\)", text):
                continue  # zero-checked recovery
            if re.search(r"address\s*\(\s*0\s*\)\s*!=\s*\b" +
                         re.escape(var) + r"\b", text):
                continue
            # OpenZeppelin ECDSA shape: an == comparison in an
            # if whose body bails out is also a zero check.
            if re.search(
                    r"if\s*\([^)]*(\b" + re.escape(var) +
                    r"\b\s*==\s*address\s*\(\s*0\s*\)|"
                    r"address\s*\(\s*0\s*\)\s*==\s*\b" +
                    re.escape(var) + r"\b)[^)]*\)\s*"
                    r"(\{[^}]*(return|revert)|return|revert)",
                    text):
                continue  # zero-checked recovery (== if-bail)
            targets = set()
            for m in re.finditer(
                    r"\b" + re.escape(var) +
                    r"\b\s*(?:==|!=)\s*([A-Za-z_][\w\.]*)", text):
                targets.add(m.group(1))
            for m in re.finditer(
                    r"([A-Za-z_][\w\.]*)\s*(?:==|!=)\s*\b" +
                    re.escape(var) + r"\b", text):
                targets.add(m.group(1))
            for tgt in targets:
                base = tgt.split(".")[-1]
                if base == "address":
                    continue  # the address(0) cast, not a signer
                if base not in state and base not in params:
                    continue
                if re.search(re.escape(base) +
                             r"\s*!=\s*address\s*\(\s*0\s*\)",
                             text):
                    continue  # signer itself zero-checked
                detail = spec.detail + (
                    f" Observed: '{fn['name']}' compares the "
                    f"ecrecover result '{var}' against "
                    f"'{base}' with no address(0) check on "
                    "either side.")
                out.append(_hit(spec, fn["name"],
                                cc._snip(text), detail))
                fired = True
                break
            if fired:
                break
    return out


ANALYZERS = {
    "vault_share_inflation": _analyze_vault_inflation,
    "readonly_reentrancy_gap": _analyze_readonly_reentrancy,
    "diamond_cut_ungated": _analyze_diamond_cut,
    "aa_validation_ungated": _analyze_aa_validation,
    "ecrecover_zero_signer": _analyze_ecrecover_zero,
}


def analyze_deep_source(src: str, spec: DetectorSpec,
                        compiler: str = "",
                        contract_name: str = ""
                        ) -> List[Dict[str, Any]]:
    """Run ONE deep-audit detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail} (+ recipient / report_class where classified)."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors contract_logic's collection / fetch /
# proxy resolution; analysis is analyze_deep_source per spec)
# ---------------------------------------------------------------------------

class DeepAuditPlugin(Plugin):
    id = ""
    label = "Deep Audit Detector"
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
        for item in analyze_deep_source(
                src["source"], spec, src.get("compiler", ""),
                contract_name=src.get("contract_name", "")):
            ev = dict(base_ev)
            ev.update({
                "severity": item["severity"],
                "check": spec.id,
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
            fn_txt = f"function '{item['function']}' " \
                if item["function"] else ""
            findings.append(self._f(
                "web3", spec.id,
                f"{item['severity'].upper()}: {spec.label}: "
                f"{fn_txt}in contract {addr} on {chain.name}{tag}"
                f"\n\n{item['detail']}\n\nCode:\n{item['code']}",
                source="deep audit detector (verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAuditPlugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector for {spec.label.lower()}: "
            f"{spec.detail} Static verified-source analysis, "
            "fast lane, detection only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
