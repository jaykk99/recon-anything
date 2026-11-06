"""Spot-oracle payout analyzer (100x lane L1, 2026-11-06).

The depth benchmark's one detector miss: a borrow whose payout is
priced off an AMM pair's SPOT reserves -

    (uint112 r0, uint112 r1, ) = pair.getReserves();
    uint256 price = (uint256(r1) * 1e18) / uint256(r0);
    uint256 amount = (collateralTokens * price) / 1e18;
    payable(msg.sender).transfer(amount);

Spot reserves are movable by anyone inside a single transaction
(donate / swap / flash-loan against the pair, then call the payout
in the same block), so every value-out sized from that price is
manipulable at near-zero cost. The existing coverage of this
shape lives in chain-specific / live-data plugins (bsc_pancake,
deep_audit4/6) that the pure-source detector set never exercises
for a generic borrow/mint/redeem; this module is the chain-
agnostic, pure-source analyzer for it.

Detection (all on the argument-bound internal call path of a
public entry function, so a pricing helper the entry calls is
read in the entry's frame):

(a) the path reads AMM spot state - pair.getReserves(), direct
    reserve0 / reserve1 reads, or a balanceOf-based pair ratio;
(b) a price / ratio is DERIVED from that spot state (a division
    over reserve-derived values or spot balances) and that price
    (or a value tainted by it, transitively through assignments)
    sizes a value-out amount: a native/token transfer, a
    call{value:...}, or a mint credit;
(c) NO manipulation protection exists on the same price path:
    no TWAP markers (priceCumulative*, observe(), consult(),
    time-weighted windows), no Chainlink feed (latestRoundData /
    AggregatorV3Interface / latestAnswer), no sanity bounds on
    the derived price (a require / assert / if condition that
    compares the price variable against a min/max bound, a
    two-sided bound, or a deviation tolerance). Any of those on
    the SAME path silences the finding - that is what keeps the
    TWAP twin and Chainlink-priced contracts clean. A spot read
    used only for a non-payout purpose (a display / quote getter
    with no value-out on its path) also stays silent, because
    step (b) requires a payout sized by the price.

Caller-gated entries stay silent (a stranger cannot reach the
path), and payouts landing at FIXED / HOLDER-SELF destinations
come out trigger-only under the receive rule, never candidates.

Detection only: pure verified-source static analysis, no live
calls, never sends a transaction. Whether a candidate is
VERIFIED_REAL is the auto-validator's job, not this lane's.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import chain_data
from . import contract_chain as cc
from . import contract_logic as cl

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
FAMILY = "spot_oracle"
SPEC_ID = "spot_oracle_payout"

DETAIL = (
    "Payout priced off AMM spot reserves with no manipulation "
    "protection: the value-out amount is derived from a spot "
    "price computed by dividing a pair's live reserves (or spot "
    "balances), and the same price path carries no TWAP, no "
    "oracle feed (Chainlink), no min/max sanity bound and no "
    "deviation check against a second source. Spot reserves can "
    "be moved by anyone inside one transaction (swap, donation "
    "or flash loan against the pair), so a stranger can distort "
    "the price, take the oversized payout, and unwind - all "
    "atomically.")

FIX = ("Price payouts from a manipulation-resistant source: a "
       "TWAP over pair reserves (priceCumulative / observe over "
       "a real window), a vetted oracle feed with staleness "
       "checks (Chainlink latestRoundData), or at minimum bound "
       "the derived spot price against a stored min/max and a "
       "deviation check versus a second source before sizing "
       "any payout from it.")

# ---------------------------------------------------------------------------
# Spot-state reads and price derivation
# ---------------------------------------------------------------------------

_GETRESERVES_RE = re.compile(r"\.getReserves\s*\(")
_RESERVE_TOKEN_RE = re.compile(r"\breserve[01]\b")
_BALANCEOF_RE = re.compile(r"\bbalanceOf\s*\(")
_ASSIGN_RE = re.compile(r"([A-Za-z_]\w*)\s*=(?![=])\s*([^;]+);")
_DESTRUCTURE_RE = re.compile(
    r"\(([^()]*)\)\s*=\s*[^;]*?\.getReserves\s*\(", re.S)
_RETURN_RE = re.compile(r"\breturn\s+([^;]+);")
_COND_RE = re.compile(r"\b(?:require|assert|if)\s*\(")

_TWAP_RE = re.compile(
    r"price0CumulativeLast|price1CumulativeLast|priceCumulative|"
    r"\bobserve\s*\(|\bconsult\s*\(|\btwap\b|time[\s_-]?weighted",
    re.I)
_CHAINLINK_RE = re.compile(
    r"latestRoundData|AggregatorV3Interface|latestAnswer", re.I)
_BOUND_TOKEN_RE = re.compile(
    r"[A-Za-z_]*(?:min|max|bound|deviation|tolerance|limit)"
    r"[A-Za-z_]*", re.I)

_PAYOUT_NAMED_RE = re.compile(
    r"\.\s*(transfer|send)\s*\(|"
    r"\b(_mint|_safeMint|safeMint|mint)\s*\(")
_CALL_VALUE_RE = re.compile(r"\.call\s*\{\s*value\s*:\s*([^}]+)\}")
_LEDGER_CREDIT_RE = re.compile(
    r"\b(?:balanceOf|balances|shares|entitlement)\s*\[[^\]]+\]"
    r"\s*\+=\s*([^;]+);")


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
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


def _split_top(inner: str) -> List[str]:
    out, depth, cur = [], 0, ""
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [a.strip() for a in out]


def _conditions(text: str) -> List[str]:
    out = []
    for m in _COND_RE.finditer(text):
        inner, _ = _balanced(text, m.end() - 1)
        out.append(inner)
    return out


def _mentions(expr: str, names) -> bool:
    return any(re.search(r"\b" + re.escape(n) + r"\b", expr)
               for n in names)


def _assignments(text: str) -> List[Tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in
            _ASSIGN_RE.finditer(text)]


def _reserve_vars(text: str,
                  assigns: List[Tuple[str, str]]) -> set:
    """Variables holding raw spot reserve values: the names bound
    by a getReserves() tuple destructuring, variables assigned
    straight from a getReserves() call, and the canonical
    reserve0 / reserve1 identifiers when they appear at all."""
    out = set()
    for m in _DESTRUCTURE_RE.finditer(text):
        for part in m.group(1).split(","):
            toks = part.split()
            if toks:
                out.add(toks[-1])
    for var, rhs in assigns:
        if "getReserves" in rhs:
            out.add(var)
    if _RESERVE_TOKEN_RE.search(text):
        out.update(("reserve0", "reserve1"))
    return out


def _is_price_rhs(rhs: str, reserve_vars: set) -> bool:
    """A price/ratio derivation: a division over reserve-derived
    values, the reserve0/reserve1 ratio, or spot balances."""
    if "/" not in rhs:
        return False
    return bool(_mentions(rhs, reserve_vars) or
                _RESERVE_TOKEN_RE.search(rhs) or
                _BALANCEOF_RE.search(rhs))


def _helper_price_returns(scope) -> set:
    """Internal helpers whose return value is a spot-derived
    price (their bodies are inlined into the call path, but the
    return-to-caller variable rename breaks plain taint flow)."""
    out = set()
    for name, helper in scope.helpers.items():
        text = helper["text"]
        assigns = _assignments(text)
        rvars = _reserve_vars(text, assigns)
        if any(_is_price_rhs(rhs, rvars) for _, rhs in assigns):
            out.add(name)
            continue
        if any(_is_price_rhs(m.group(1), rvars)
               for m in _RETURN_RE.finditer(text)):
            out.add(name)
    return out


def _spot_source(text: str, assigns: List[Tuple[str, str]]) -> Optional[str]:
    """The spot-state read on this path, or None."""
    if _GETRESERVES_RE.search(text) or _RESERVE_TOKEN_RE.search(text):
        return "pair spot reserves"
    # balanceOf-based pricing: a division over spot balances.
    for _, rhs in assigns:
        if "/" in rhs and _BALANCEOF_RE.search(rhs):
            return "spot token balances"
    for m in _RETURN_RE.finditer(text):
        if "/" in m.group(1) and _BALANCEOF_RE.search(m.group(1)):
            return "spot token balances"
    return None


def _price_vars(text: str, assigns: List[Tuple[str, str]],
                reserve_vars: set, helper_prices: set
                ) -> Tuple[set, str]:
    """(price variables, price-deriving expression snippet)."""
    price_vars, snippet = set(), ""
    for var, rhs in assigns:
        if _is_price_rhs(rhs, reserve_vars):
            price_vars.add(var)
            if not snippet:
                snippet = rhs.strip()
        elif any(re.search(r"\b" + re.escape(h) + r"\s*\(", rhs)
                 for h in helper_prices):
            # price = _spotPrice(...) - the helper returns a
            # spot-derived price (its body is on this path).
            price_vars.add(var)
            if not snippet:
                snippet = rhs.strip()
    if not snippet:
        for m in _RETURN_RE.finditer(text):
            if _is_price_rhs(m.group(1), reserve_vars):
                snippet = m.group(1).strip()
                break
    return price_vars, snippet


def _tainted(assigns: List[Tuple[str, str]], price_vars: set) -> set:
    """Variables transitively derived from a price variable."""
    out = set(price_vars)
    changed = True
    while changed:
        changed = False
        for var, rhs in assigns:
            if var not in out and _mentions(rhs, out):
                out.add(var)
                changed = True
    return out


def _protection(text: str, price_vars: set) -> Optional[str]:
    """Manipulation protection on the SAME price path, or None.

    TWAP / Chainlink markers anywhere on the path count (the
    price the payout uses comes from that path). A price bound
    counts only when a require/assert/if condition actually
    compares a price variable (or a variable named *price*)
    against a min/max-style bound, both sides of a range, or a
    deviation tolerance."""
    if _TWAP_RE.search(text):
        return "twap"
    if _CHAINLINK_RE.search(text):
        return "chainlink"
    for cond in _conditions(text):
        named = _mentions(cond, price_vars) or \
            re.search(r"\b\w*[Pp]rice\w*\b", cond)
        if not named:
            continue
        if _BOUND_TOKEN_RE.search(cond):
            return "price bound"
        if ">=" in cond and "<=" in cond:
            return "price bound"
    return None


def _payout_amounts(text: str) -> List[str]:
    """Amount expressions of every value-out on the path:
    transfer/send (last argument), mint calls (last argument),
    call{value: ...}, and ledger credits (+=)."""
    out: List[str] = []
    for m in _PAYOUT_NAMED_RE.finditer(text):
        inner, _ = _balanced(text, m.end() - 1)
        args = _split_top(inner)
        if args:
            out.append(args[-1])
    for m in _CALL_VALUE_RE.finditer(text):
        out.append(m.group(1).strip())
    for m in _LEDGER_CREDIT_RE.finditer(text):
        out.append(m.group(1).strip())
    return out


def _public(fn: Dict[str, Any]) -> bool:
    sig = fn["signature"]
    if re.search(r"\b(internal|private)\b", sig):
        return False
    return bool(re.search(r"\b(public|external)\b", sig))


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

def analyze_spot_oracle_source(source: str, address: str = "",
                               contract_name: str = ""
                               ) -> List[Dict[str, Any]]:
    """Run the spot-oracle payout detector over verified source.

    Returns finding dicts in the recipient-first / contract_logic
    shape ({kind, id, severity, function, code, detail, recipient,
    report_class, remediation}) plus the oracle evidence fields
    (pricing_source, protection, price_expression, and an
    `evidence` dict carrying the same). Candidate-grade only when
    the payout lands at a CALLER / CALLER-SUPPLIED destination;
    FIXED / HOLDER-SELF / UNRESOLVED destinations come out
    trigger-only at low severity under the receive rule.
    """
    if not source or "{" not in source:
        return []
    try:
        scope = cl._Scope(source, contract_name)
    except Exception:
        return []
    helper_prices = _helper_price_returns(scope)
    out: List[Dict[str, Any]] = []
    seen = set()
    for fn in scope.functions:
        if "{" not in fn["text"] or not _public(fn):
            continue
        if fn["name"] in seen:
            continue
        try:
            hit = _analyze_fn(scope, fn, helper_prices)
        except Exception:
            hit = None
        if hit:
            seen.add(fn["name"])
            out.append(hit)
    return out


def _analyze_fn(scope, fn: Dict[str, Any],
                helper_prices: set) -> Optional[Dict[str, Any]]:
    path = cl.bound_path_text(scope, fn)
    assigns = _assignments(path)
    if _spot_source(path, assigns) is None:
        return None
    pricing_source = _spot_source(path, assigns)
    reserve_vars = _reserve_vars(path, assigns)
    price_vars, price_expr = _price_vars(
        path, assigns, reserve_vars, helper_prices)
    if not price_expr:
        return None
    if _protection(path, price_vars) is not None:
        return None
    if cl._gated_deep(fn, scope):
        return None
    tainted = _tainted(assigns, price_vars)
    sized = None
    for amt in _payout_amounts(path):
        if _mentions(amt, tainted) or _is_price_rhs(amt, reserve_vars):
            sized = amt
            break
    if sized is None:
        return None
    recipient, rdetail = cl.classify_recipient(path)
    candidate = recipient in ("CALLER", "CALLER-SUPPLIED")
    ev = {"pricing_source": pricing_source,
          "protection": "none found",
          "price_expression": price_expr,
          "payout_amount": sized,
          "recipient": recipient}
    detail = (
        DETAIL +
        f" Observed: '{fn['name']}' derives price from "
        f"`{price_expr}` ({pricing_source}), sizes a payout from "
        f"it (`{sized}`), protection: none found. Recipient "
        f"analysis: recipient classified {recipient} "
        f"({rdetail}).")
    item = {"kind": SPEC_ID, "id": SPEC_ID,
            "severity": "high" if candidate else "low",
            "function": fn["name"],
            "code": cc._snip(fn["text"]),
            "detail": detail,
            "recipient": recipient,
            "report_class": "candidate" if candidate
            else "trigger_only",
            "remediation": FIX,
            "pricing_source": pricing_source,
            "protection": "none found",
            "price_expression": price_expr,
            "evidence": ev}
    if not candidate:
        item["detail"] += (
            " Recipient analysis: the value destination is not "
            "caller-reachable, so a stranger can trigger this but "
            "receives nothing - TRIGGER-ONLY under the receive "
            "rule.")
    return item


# ---------------------------------------------------------------------------
# Plugin wrapper (mirrors the recipient_first collection / fetch path;
# the analysis is analyze_spot_oracle_source only)
# ---------------------------------------------------------------------------

class SpotOraclePayoutPlugin(Plugin):
    id = SPEC_ID
    label = "Spot Oracle Payout"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = DETAIL + " Static verified-source analysis, " \
                           "fast lane, detection only."
    phase = 2
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        work = self._collect(target, ctx)
        if not work:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed, e.g. "
                "bsc:0x...) or a web target whose pages reference "
                "one")
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
        hits = sum(1 for f in findings
                   if f.key == SPEC_ID and
                   (f.evidence or {}).get("report_class") == "candidate")
        res = self._ok(
            findings,
            f"{SPEC_ID}: analyzed {analyzed} contract address(es) "
            f"({no_source} without verified source - skipped, no "
            f"guess made), {hits} candidate finding(s)")
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
        rpc_all_failed = True
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS[cid]
            code = await chain_data.get_code(ctx, chain, addr)
            if code is None:
                continue
            rpc_all_failed = False
            if code == "0x" or len(code) < 4:
                continue
            pairs += 1
            src = await chain_data.get_source(ctx, chain, addr,
                                              key)
            if src:
                got_source = True
                items = analyze_spot_oracle_source(
                    src["source"], addr,
                    src.get("contract_name", ""))
                url = cc.explorer_url(chain, addr)
                for item in items:
                    ev = {"severity": item["severity"],
                          "address": addr, "chain": chain.id,
                          "chain_id": chain.chain_id,
                          "check": SPEC_ID,
                          "function": item["function"],
                          "code": item["code"],
                          "detail": item["detail"],
                          "recipient": item["recipient"],
                          "report_class": item["report_class"],
                          "pricing_source": item["pricing_source"],
                          "protection": item["protection"],
                          "price_expression": item["price_expression"],
                          "source_origin": src.get("origin", ""),
                          "remediation": item["remediation"]}
                    findings.append(self._f(
                        "web3", SPEC_ID,
                        f"{item['severity'].upper()}: "
                        f"{item['detail']}",
                        source=f"verified source ({src.get('origin', '')})",
                        source_url=url, confidence=85, evidence=ev,
                        passive=True))
            if chain_hint:
                break
        if pairs == 0 and rpc_all_failed:
            findings.append(self._f(
                "web3", f"{SPEC_ID}_failed",
                f"MEDIUM: {addr}: every public RPC endpoint "
                "failed, so no chain data could be retrieved. No "
                "conclusion drawn.",
                source="public JSON-RPC eth_getCode",
                confidence=60, passive=True,
                evidence={"severity": "medium", "address": addr,
                          "remediation": "Retry later; the public "
                                         "RPC endpoints for this "
                                         "chain were "
                                         "unreachable."}))
        return pairs, got_source
