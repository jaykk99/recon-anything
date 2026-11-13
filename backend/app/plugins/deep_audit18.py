"""Deep-audit detector, batch 18: multi-token vault deposit length mismatch.

One chain-agnostic EVM detector from the standing backlog queue,
built to the batch-11 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- multitoken_deposit_length_mismatch: a multi-token vault's
  deposit function takes an amounts array (or amount0/amount1
  inputs) and never checks its length against the vault's token
  count, values the deposit (and the vault's existing holdings)
  using token0 only, mints shares against that fraction of true
  value, and lets withdraw pay out pro-rata across ALL vault
  tokens. A tiny token0-only deposit mints shares against a
  fraction of the vault, then withdraw pays out both tokens -
  repeatable round after round. The ACryptoS shape (8 Nov 2026,
  ~$665k, 77 vaults, 5 chains): depositMulti(amounts) never
  checked amounts.length against the token count, and both the
  deposit and the vault's holdings were valued using token0
  only.

Legs (ALL required):
  (a) a deposit/mint entry function taking an amounts array
      (uint256[] amounts) or amount0/amount1-style inputs, for
      a vault holding >= 2 tokens;
  (b) NO length check anywhere in the deposit path (no
      amounts.length compared against the token count, no
      require(amounts.length == 2), no equivalent);
  (c) the share-minting valuation reads only token0 (or a
      strict subset): the minted amount resolves to an
      expression mentioning token0-side references only
      (amounts[0] / tokens[0] / token0 / amount0), with no
      token1-side reference in the resolved amount;
  (d) the withdraw/redeem path in the same contract distributes
      pro-rata across ALL vault tokens (a token0-side transfer
      AND a token1-side transfer, sized by shares/totalSupply).

Silent by construction: a length check anywhere in the deposit
path; a single-token vault; a valuation reading all vault
tokens; a withdraw that also only pays token0 (no asymmetry,
no drain).

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path.

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
FAMILY = "deep18"

SPECS = [
    S("multitoken_deposit_length_mismatch", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Multi-token vault deposit with no amounts-length "
             "check: the deposit function takes an amounts array "
             "(or amount0/amount1 inputs) for a vault holding two "
             "or more tokens, never checks amounts.length against "
             "the token count, values the deposit (and the vault's "
             "existing holdings) using token0 only, and mints "
             "shares against that fraction of true value, while "
             "withdraw pays out pro-rata across ALL vault tokens - "
             "so a tiny token0-only deposit mints shares against a "
             "fraction of the vault and withdraw returns both "
             "tokens, repeatable round after round (the ACryptoS "
             "shape, ~$665k). A length check "
             "(require(amounts.length == tokens.length)) or a "
             "valuation reading every vault token is the protected "
             "shape.",
      fix="Require amounts.length == tokens.length (or the "
          "vault's token count) at the top of every multi-token "
          "deposit, and value shares from every vault token (sum "
          "amounts[i] * price[i] over all tokens, or price the "
          "deposit against total holdings across all tokens). "
          "Never mint shares from a single token's value while "
          "withdraw pays out all of them."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 12 / deep17)
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


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (see module docstring).

    Only an only* modifier, a msg.sender identity comparison,
    or a role check suppresses. The deposit / valuation logic
    under analysis is NOT a gate here.
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
# Multi-token deposit length-mismatch patterns
# ---------------------------------------------------------------------------

# Token-side references: index-0 / token0-side vs index-1 /
# token1-side. A vault holding >= 2 tokens mentions the second
# token somewhere (tokens[1], token1, amount1); a valuation
# that reads only token0 never mentions it in the deposit
# function.
_TOKEN0_RE = re.compile(
    r"amounts\s*\[\s*0\s*\]|tokens\s*\[\s*0\s*\]|"
    r"underlyings\s*\[\s*0\s*\]|\btoken0\b|\bamount0\b|"
    r"\bamounts0\b")
_TOKEN1_RE = re.compile(
    r"amounts\s*\[\s*1\s*\]|tokens\s*\[\s*1\s*\]|"
    r"underlyings\s*\[\s*1\s*\]|\btoken1\b|\bamount1\b|"
    r"\bamounts1\b")

_DEPOSIT_NAME_RE = re.compile(r"^(deposit|mint)")
_WITHDRAW_NAME_RE = re.compile(
    r"^(withdraw|redeem|exit|removeLiquidity)")

# A length guard on the amounts array: amounts.length compared
# with == / != against the vault's token count (tokens.length,
# a *Count variable, another .length, or the literal 2). A
# non-empty check (amounts.length > 0) or a loop bound
# (i < amounts.length) is NOT a guard: the array can still be
# shorter than the token list.
_LENGTH_GUARD_RES = (
    re.compile(
        r"amounts\s*\.length\s*(?:==|!=)\s*(?:tokens\.length|"
        r"tokenCount|numTokens|numUnderlyings|underlyings\.length|"
        r"assets\.length|[A-Za-z_][A-Za-z0-9_]*\.length|2\b)"),
    re.compile(
        r"(?:tokens\.length|tokenCount|numTokens|numUnderlyings|"
        r"underlyings\.length|assets\.length|[A-Za-z_][A-Za-z0-9_]*"
        r"\.length)\s*(?:==|!=)\s*amounts\s*\.length"),
)

_MINT_CALL_RE = re.compile(r"\b_mint\s*\(([^)]*)\)")
_LEDGER_CREDIT_RE = re.compile(
    r"\b(?:balanceOf|balances|_balances)\s*\[\s*[^\]]+\s*\]\s*"
    r"\+=\s*([^;]+);")
_SUPPLY_UP_RE = re.compile(
    r"\b_?totalSupply\s*(?:\+=|=\s*_?totalSupply\s*\+)")

_SOLIDITY_WORDS = {
    "uint256", "uint", "uint8", "uint128", "address", "bool",
    "int256", "int", "bytes32", "string", "memory", "calldata",
    "storage", "true", "false", "this",
}


def _statement_of(text: str, pos: int) -> str:
    """The ;-terminated statement containing `pos`."""
    start = max(text.rfind(";", 0, pos), text.rfind("{", 0, pos))
    end = text.find(";", pos)
    if end < 0:
        end = len(text)
    return text[start + 1:end + 1]


def _length_guard_present(path_text: str) -> bool:
    return any(p.search(path_text) for p in _LENGTH_GUARD_RES)


def _amounts_input(fn: Dict[str, Any]) -> Optional[str]:
    """'array' | 'split' | None for a deposit function.

    'array': a uint256[] amounts parameter (the depositMulti
    shape). 'split': amount0 + amount1 (or amounts0 +
    amounts1) parameters. Anything else is not a multi-amount
    deposit.
    """
    sig = fn["signature"]
    if re.search(r"uint256\s*\[\s*\]\s*(?:calldata|memory)?\s*"
                 r"amounts\b", sig):
        return "array"
    params = _fn_params(fn)
    if ({"amount0", "amount1"} <= set(params) or
            {"amounts0", "amounts1"} <= set(params)):
        return "split"
    return None


def _expand(fn_text: str, expr: str, depth: int = 0) -> str:
    """Expand bare identifiers in `expr` through their
    assignments in the function (shares -> value0 * ... ->
    amounts[0] * price0), bounded depth. Identifiers with no
    in-function assignment (state variables, parameters) stay
    as-is.
    """
    if depth > 3:
        return expr
    out = expr
    for ident in sorted(set(re.findall(r"[A-Za-z_]\w*", expr))):
        if ident in _SOLIDITY_WORDS:
            continue
        am = re.search(r"\b" + re.escape(ident) +
                       r"\s*=(?![=<>!])\s*([^;]+);", fn_text)
        if not am:
            continue
        rhs = am.group(1).strip()
        if rhs == ident:
            continue
        out = re.sub(r"\b" + re.escape(ident) + r"\b",
                     "(" + rhs + ")", out)
    if out != expr:
        return _expand(fn_text, out, depth + 1)
    return out


def _mint_amount_source(fn_text: str) -> Optional[str]:
    """The expression sizing the shares mint, identifiers
    expanded: the _mint amount argument, or a direct ledger
    credit amount. None when the function mints nothing;
    "" when totalSupply rises but no amount expression can be
    judged.
    """
    m = _MINT_CALL_RE.search(fn_text)
    if m:
        args = _split_top(m.group(1))
        if len(args) >= 2:
            return _expand(fn_text, args[1])
    m = _LEDGER_CREDIT_RE.search(fn_text)
    if m:
        return _expand(fn_text, m.group(1))
    if _SUPPLY_UP_RE.search(fn_text):
        return ""
    return None


def _valuation_token0_only(fn_text: str) -> Optional[str]:
    """The minted amount resolves to a token0-side expression
    with no token1-side reference in it. Returns the resolved
    amount expression, or None when the valuation reads more
    than token0 (or no mint can be judged). The rest of the
    deposit body may mention the second token (a transferFrom
    pulling amounts[1] does not fix the valuation: the caller
    can pass 0 for it)."""
    body = fn_text.split("{", 1)[1] if "{" in fn_text else fn_text
    src = _mint_amount_source(body)
    if src is None or not src:
        return None
    if not _TOKEN0_RE.search(src):
        return None
    if _TOKEN1_RE.search(src):
        return None
    return src


def _withdraw_pays_all_tokens(fn_text: str) -> bool:
    """A token0-side transfer AND a token1-side transfer in the
    same withdraw/redeem function, sized pro-rata by
    shares/totalSupply, paid to the caller. A withdraw that
    only pays token0 is not an asymmetry and never counts.
    """
    if "totalSupply" not in fn_text:
        return False
    if "shares" not in fn_text and "balanceOf" not in fn_text:
        return False
    if "msg.sender" not in fn_text:
        return False
    sides = set()
    for m in re.finditer(r"\.\s*transfer\s*\(", fn_text):
        stmt = _statement_of(fn_text, m.start())
        if _TOKEN0_RE.search(stmt):
            sides.add(0)
        if _TOKEN1_RE.search(stmt):
            sides.add(1)
    return sides == {0, 1}


# ---------------------------------------------------------------------------
# multitoken_deposit_length_mismatch
# ---------------------------------------------------------------------------

def _analyze_multitoken_deposit(src, spec, compiler,
                                contract_name):
    scope, fns = _scope_fns(src, contract_name)
    by_contract: Dict[str, List[Dict[str, Any]]] = {}
    for fn in fns:
        by_contract.setdefault(fn.get("contract", ""), []).append(fn)
    out: List[Dict[str, Any]] = []
    for cname, cfns in by_contract.items():
        contract_text = "\n".join(fn["text"] for fn in cfns)
        if not _TOKEN1_RE.search(contract_text):
            # Single-token vault: no second token anywhere in
            # the contract, so there is no multi-token asymmetry.
            continue
        withdraws = [fn for fn in cfns
                     if _WITHDRAW_NAME_RE.search(fn["name"])
                     and not re.search(
                         r"\b(internal|private)\b",
                         fn["signature"])
                     and _withdraw_pays_all_tokens(fn["text"])]
        if not withdraws:
            continue
        for fn in cfns:
            if not _DEPOSIT_NAME_RE.search(fn["name"]):
                continue
            if re.search(r"\b(internal|private)\b",
                         fn["signature"]):
                continue
            if _skip_fn(fn, scope):
                continue
            shape = _amounts_input(fn)
            if shape is None:
                continue
            text = fn["text"]
            if shape == "array":
                # No length check anywhere in the deposit path
                # (the function plus the internal helpers it
                # calls, arguments bound).
                path_text = cl.bound_path_text(scope, fn)
                if _length_guard_present(path_text):
                    continue
            value_src = _valuation_token0_only(text)
            if value_src is None:
                continue
            wfn = withdraws[0]
            detail = spec.detail + (
                f" Observed: '{fn['name']}' takes a multi-token "
                f"amounts input with no length check against the "
                f"vault's token count, mints shares sized from "
                f"token0 only ({value_src.strip()[:140]}), and "
                f"'{wfn['name']}' in the same contract pays out "
                f"pro-rata across all vault tokens, so a tiny "
                f"token0-only deposit mints shares against a "
                f"fraction of true value and withdraw pays both "
                f"tokens - repeatable round after round. Gate "
                f"analysis: no caller-identity gate on the "
                f"deposit path, no amounts-length guard.")
            item = _hit(spec, fn["name"], cc._snip(text), detail,
                        "ungated multi-token deposit: no "
                        "amounts-length guard, token0-only "
                        "valuation, pro-rata multi-token withdraw")
            out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "multitoken_deposit_length_mismatch": _analyze_multitoken_deposit,
}


def analyze_deep18_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-18 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-12 / deep17 collection /
# fetch / proxy resolution; analysis is analyze_deep18_source
# per spec)
# ---------------------------------------------------------------------------

class DeepAudit18Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 18)"
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
        for item in analyze_deep18_source(
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
                source="deep audit detector batch 18 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit18Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 18) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
