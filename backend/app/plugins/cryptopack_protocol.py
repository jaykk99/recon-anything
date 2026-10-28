"""Crypto-protocol static detectors (detection ONLY).

Gap this fills, without duplicating the existing audit:
- ``contract_audit`` audits VERIFIED source fetched from Etherscan/Sourcify
  for addresses discovered on a target, and covers reentrancy, tx.origin,
  delegatecall to an untrusted target, unchecked low-level calls,
  selfdestruct, missing access control, pre-0.8 overflow, front-running
  shapes, flash-loan callbacks and unprotected initializers.
- ``smartcontract`` / ``defi`` only flag generic pattern presence on the
  homepage and its same-domain JS bundles.

This pack audits Solidity / contract-artifact text ALREADY SERVED BY THE
TARGET ITSELF (homepage, same-domain JS bundles, and same-domain
``.sol`` / artifact links found on that page). It never fetches verified
source from an explorer, never contacts an RPC endpoint, never sends a
transaction, never brute-forces, never bypasses auth, and never touches
private data. A finding is a statically visible protocol shape, not proof
of exploitability: every finding says "detection only" and carries
exploitability "theoretical" unless the shape itself is the whole flaw.

Checks (one plugin per check, so the registry grows by 8):
1. cp_proto_unlimited_approval  - contract-side approve() to uint max, or
   setApprovalForAll(true), with no allowance cap in sight.
2. cp_proto_rounding_order      - division before multiplication in
   share / price / reward math (a / b * c truncates before scaling).
3. cp_proto_single_source_oracle - spot price taken from a single DEX
   pair's reserves / balances, with no TWAP, multi-source or staleness
   safeguard visible.
4. cp_proto_unbounded_slippage  - swap with an explicit zero minimum-out
   (amountOutMin == 0) or a max / missing deadline.
5. cp_proto_permit_signature_replay - permit() / ecrecover() auth with
   no nonce and no deadline visible (replayable signature shape).
6. cp_proto_unchecked_erc20_return - token.transfer / transferFrom whose
   bool return is neither required, checked, nor routed through
   SafeERC20 (breaks on non-standard tokens that return false).
7. cp_proto_centralized_mint_fee - owner mint with no visible supply cap,
   or an owner fee setter with no visible upper bound.
8. cp_proto_timestamp_randomness - block.timestamp / prevrandao /
   difficulty / blockhash used to pick a random value, winner or lottery
   outcome.

Secret-like values are never emitted: findings carry only the check name,
function name, a truncated non-secret code snippet (max 200 chars, no
private key / seed / address material beyond the function context), the
severity, and a remediation. No full secret is ever included.
"""

from __future__ import annotations

import re
import time
from typing import Dict, List, Tuple
from urllib.parse import urljoin

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import same_domain

# ---------------------------------------------------------------- helpers

FUNC_RE = re.compile(
    r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*"
    r"((?:public|external|internal|private|pure|view|payable|"
    r"virtual|override|[A-Za-z_][A-Za-z0-9_]*)\s*)*",
    re.S)


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def _split_functions(src: str) -> List[Tuple[str, str, str]]:
    """Return (name, signature, body) triples via brace matching."""
    out = []
    for m in FUNC_RE.finditer(src):
        name = m.group(1)
        sig = m.group(0)
        i = m.end()
        while i < len(src) and src[i] != "{":
            i += 1
        if i >= len(src):
            continue
        depth, start, j = 0, i, i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((name, sig, src[start:j + 1]))
    return out


def _snippet(src: str, pos: int, width: int = 200) -> str:
    """One truncated, whitespace-collapsed line around pos. No secrets:
    callers only pass positions of protocol patterns, never key material,
    and the snippet is capped so a long literal cannot ride along."""
    s = re.sub(r"\s+", " ", src[max(0, pos - 80):pos + 120]).strip()
    return s[:width]


def _is_public(sig: str) -> bool:
    return "public" in sig or "external" in sig


def _guarded(sig: str, body: str) -> bool:
    return bool(re.search(
        r"onlyOwner|onlyRole|onlyAdmin|require\s*\(\s*msg\.sender", sig + body))


def audit_protocol_source(src: str) -> List[Dict[str, str]]:
    """Pure static checks over one Solidity / artifact text.

    Returns [{check, severity, function, detail, snippet}]. Every check
    is a shape, not an exploit claim; severity is low/medium/high only.
    """
    clean = _strip_comments(src)
    funcs = _split_functions(clean)
    findings: List[Dict[str, str]] = []

    def add(check: str, severity: str, fn: str, detail: str, pos: int = 0):
        if not any(f["check"] == check and f["function"] == fn
                   for f in findings):
            findings.append({"check": check, "severity": severity,
                             "function": fn, "detail": detail,
                             "snippet": _snippet(clean, pos)})

    # --- 1. unlimited approval -----------------------------------------
    for m in re.finditer(
            r"\.approve\s*\([^)]*(?:type\s*\(\s*uint(?:256)?\s*\)\s*\.\s*max"
            r"|2\s*\*\*\s*256\s*-\s*1|0x[fF]{40,64})[^)]*\)", clean):
        add("unlimited_approval", "medium", "",
            "Contract-side approve() grants a maximum / unlimited "
            "allowance. If the spender is ever compromised, the full "
            "balance is spendable until the allowance is revoked.",
            m.start())
        break
    for m in re.finditer(r"setApprovalForAll\s*\([^)]*,\s*true\s*\)", clean):
        add("unlimited_approval", "medium", "",
            "setApprovalForAll(true) grants an operator control over "
            "every token of a holder. Detection only; check who the "
            "operator is and whether revocation is documented.",
            m.start())
        break

    # --- 2. rounding: division before multiplication --------------------
    for name, sig, body in funcs:
        m = re.search(r"\b[A-Za-z_][\w.]*\s*/\s*[A-Za-z_][\w.]*\s*\*",
                      body)
        if m and re.search(
                r"share|price|reward|amount|balance|supply|fee|portion",
                body, re.I):
            add("rounding_order", "medium", name,
                f"Function '{name}' divides before it multiplies in "
                "share / price / reward math. Integer division truncates "
                "first, so small holders can lose dust every round and "
                "the last claimer can sweep the remainder. Multiply, "
                "then divide (or use fixed-point math).", m.start())
            break

    # --- 3. single-source spot oracle -----------------------------------
    spot = re.search(
        r"getReserves\s*\(|reserve0\s*/\s*reserve1|reserve1\s*/\s*reserve0"
        r"|balanceOf\s*\([^)]*\)\s*/\s*[^;]*balanceOf\s*\(",
        clean)
    if spot and not re.search(
            r"TWAP|timeWeighted|time-weighted|latestRoundData|"
            r"consult\s*\(|observe\s*\(", clean, re.I):
        add("single_source_oracle", "medium", "",
            "Spot price is taken from a single DEX pair's reserves or "
            "token balances, with no TWAP, multi-source oracle or "
            "staleness safeguard visible. A large swap in the same block "
            "moves that price before it is read. Detection only.",
            spot.start())

    # --- 4. unbounded slippage / deadline --------------------------------
    for m in re.finditer(
            r"amountOutMin\s*[:=]\s*0\b|minAmountOut\s*[:=]\s*0\b"
            r"|amountOutMin\s*,\s*0\b", clean):
        add("unbounded_slippage", "medium", "",
            "Swap accepts an explicit zero minimum-out. Any price move "
            "between submission and execution is accepted, including a "
            "sandwiched price. Set a real slippage bound per trade.",
            m.start())
        break
    for m in re.finditer(r"deadline\s*[:=]\s*type\s*\(\s*uint(?:256)?\s*\)"
                         r"\s*\.\s*max", clean):
        add("unbounded_slippage", "medium", "",
            "Swap deadline is set to the uint maximum, so a pending "
            "transaction stays valid indefinitely and can execute at a "
            "far worse price later. Use a short, per-trade deadline.",
            m.start())
        break

    # --- 5. permit / signature replay ------------------------------------
    for name, sig, body in funcs:
        if re.search(r"\bpermit\s*\(|\becrecover\s*\(", body):
            has_nonce = bool(re.search(r"nonces?\s*\[", body)) or \
                "nonce" in body.lower()
            has_deadline = "deadline" in body.lower()
            has_domain = bool(re.search(
                r"DOMAIN_SEPARATOR|EIP712|domainSeparator", body))
            if not (has_nonce and has_deadline) and not has_domain:
                add("permit_signature_replay", "medium", name,
                    f"Function '{name}' authenticates with permit() / "
                    "ecrecover() but no nonce AND deadline (and no "
                    "EIP-712 domain separator) is visible in the same "
                    "function. A captured signature may be replayable. "
                    "Detection only; verify the full auth path.",
                    0)
                break

    # --- 6. unchecked ERC20 return ----------------------------------------
    for name, sig, body in funcs:
        if "safeTransfer" in body or "SafeERC20" in clean:
            continue
        for line in body.splitlines():
            s = line.strip()
            if re.search(r"\.\s*transfer(?:From)?\s*\(", s) and \
                    not re.search(r"require\s*\(|if\s*\(|bool\s+\w+\s*=",
                                  s):
                add("unchecked_erc20_return", "medium", name,
                    f"Function '{name}' calls token.transfer / "
                    "transferFrom without requiring or checking its bool "
                    "return. Non-standard tokens return false instead of "
                    "reverting, so the call can silently fail while the "
                    "contract records success. Use SafeERC20 or require "
                    "the return value.", 0)
                break
        if any(f["check"] == "unchecked_erc20_return" for f in findings):
            break

    # --- 7. centralized mint / fee -----------------------------------------
    for name, sig, body in funcs:
        if name.lower() == "mint" and _is_public(sig) and _guarded(sig, body):
            if not re.search(r"maxSupply|MAX_SUPPLY|\bcap\b|"
                             r"require\s*\(\s*totalSupply", clean, re.I):
                add("centralized_mint_fee", "medium", name,
                    f"Owner-only mint '{name}' has no visible supply cap. "
                    "A compromised or rogue owner key can inflate supply "
                    "without bound. Cap supply, or gate minting behind a "
                    "timelock / multisig.", 0)
        if re.search(r"set(Fee|Tax|fee|tax)", name) and _is_public(sig):
            # A bound is a require() with <= or a < 100/1000/10000 cap,
            # whatever the local variable is called (f, fee, tax, bps).
            if not re.search(r"require\s*\([^)]*(?:<=|<\s*(?:100|1000|10000))",
                             body, re.I):
                add("centralized_mint_fee", "medium", name,
                    f"Owner fee setter '{name}' has no visible upper "
                    "bound. A fee set to 100% traps user funds in the "
                    "contract. Bound the fee and document the maximum.",
                    0)

    # --- 8. timestamp randomness --------------------------------------------
    for name, sig, body in funcs:
        m = re.search(
            r"block\.(?:timestamp|prevrandao|difficulty)\b|blockhash\s*\(",
            body)
        if m and re.search(r"random|winner|lottery|rand\b|pick", body, re.I):
            add("timestamp_randomness", "medium", name,
                f"Function '{name}' uses block.timestamp / prevrandao / "
                "difficulty / blockhash to pick a random value, winner "
                "or lottery outcome. Block producers can influence these "
                "values. Use a verifiable randomness source (VRF) for "
                "anything with value at stake.", m.start())
            break

    return findings


REMEDIATION = {
    "unlimited_approval": "Approve only the amount a spender needs, "
        "per trade, and revoke stale allowances. Never hardcode uint max.",
    "rounding_order": "Multiply before dividing, use fixed-point math, "
        "and sweep dust to a documented address instead of the last claimer.",
    "single_source_oracle": "Price from a TWAP, a multi-source oracle, or "
        "a Chainlink feed with a staleness check, never a single spot pair.",
    "unbounded_slippage": "Set a real per-trade minimum-out and a short "
        "deadline on every swap.",
    "permit_signature_replay": "Bind every signature to a per-owner nonce, a "
        "deadline, and an EIP-712 domain separator, and consume the nonce.",
    "unchecked_erc20_return": "Use OpenZeppelin SafeERC20, or require() the "
        "bool return of every transfer / transferFrom.",
    "centralized_mint_fee": "Cap supply, bound fees, and gate owner powers "
        "behind a timelock and multisig.",
    "timestamp_randomness": "Use verifiable randomness (e.g. Chainlink VRF) "
        "for winners, lotteries and random draws.",
}


async def _collect_texts(ctx: Ctx, target: Target, domain: str) -> Tuple[List[str], str]:
    """Homepage + same-domain JS bundles + same-domain .sol / artifact
    links found on that page. Nothing else is fetched: no explorer, no
    RPC, no off-target host."""
    base = await web_base(ctx, target, domain)
    page = await ctx.fetch_page(base, timeout=25)
    if page is None:
        raise RuntimeError("homepage fetch failed")
    html = page["text"][:400000]
    page_url = page["url"]
    texts = [html]
    for m in re.finditer(r'<(?:script|link)[^>]+(?:src|href)=["\']([^"\']+)["\']',
                         html, re.I):
        full = urljoin(page_url, m.group(1))
        if not same_domain(full, domain):
            continue
        if not (full.lower().endswith((".js", ".sol", ".json")) or
                ".sol" in full.lower() or "artifact" in full.lower()):
            continue
        try:
            jr = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=15)
            if jr.status_code == 200:
                texts.append(jr.text[:500000])
        except Exception:
            continue
        if len(texts) > 10:
            break
    return texts, page_url


class _ProtoPlugin(Plugin):
    """One check per plugin id, sharing audit_protocol_source()."""
    id = None  # abstract helper: must NOT register in the registry
    check: str = ""
    label: str = ""
    check_desc: str = ""
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ""

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        passive = (self.module_mode(ctx) == "passive")
        try:
            texts, page_url = await _collect_texts(ctx, target, domain)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        for text in texts:
            for iss in audit_protocol_source(text):
                if iss["check"] != self.check:
                    continue
                findings.append(self._f(
                    "web3", f"proto_{iss['check']}",
                    f"{iss['severity'].upper()}: {iss['detail']} "
                    f"Detection only; statically visible shape, not a "
                    f"proven exploit.",
                    source="target-served source static audit",
                    source_url=page_url, confidence=60, passive=passive,
                    evidence={"severity": iss["severity"],
                              "check": iss["check"],
                              "function": iss["function"],
                              "snippet": iss["snippet"],
                              "exploitability": "theoretical",
                              "remediation": REMEDIATION[iss["check"]],
                              "scope_note": ("Static analysis of code and "
                                             "metadata already served by "
                                             "the target itself. No RPC, "
                                             "no transaction, no exploit "
                                             "attempt.")}))
        res = self._ok(findings,
                       f"{len(findings)} {self.check} finding(s) in "
                       f"target-served source")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


def _make(check: str, label: str, desc: str):
    return type(f"Proto{check.title().replace('_', '')}Plugin",
                (_ProtoPlugin,), {
                    "id": f"cp_proto_{check}", "label": label,
                    "check": check, "check_desc": desc,
                    "description": (desc + " Detection only: static "
                                    "analysis of code already served by "
                                    "the target. No RPC, no transaction, "
                                    "no exploit attempt.")})


# Registry order is the order below; each class is one new plugin.
class ProtoUnlimitedApprovalPlugin(_make(
    "unlimited_approval", "Protocol: Unlimited Approval",
    "Contract-side approve() to uint max or setApprovalForAll(true).")):
    pass


class ProtoRoundingOrderPlugin(_make(
    "rounding_order", "Protocol: Rounding Order",
    "Division before multiplication in share / price / reward math.")):
    pass


class ProtoSingleSourceOraclePlugin(_make(
    "single_source_oracle", "Protocol: Single-Source Oracle",
    "Spot price from a single DEX pair with no TWAP safeguard.")):
    pass


class ProtoUnboundedSlippagePlugin(_make(
    "unbounded_slippage", "Protocol: Unbounded Slippage",
    "Swap with zero minimum-out or a maximum deadline.")):
    pass


class ProtoPermitSignatureReplayPlugin(_make(
    "permit_signature_replay", "Protocol: Permit Signature Replay",
    "permit() / ecrecover() auth with no nonce and no deadline.")):
    pass


class ProtoUncheckedErc20ReturnPlugin(_make(
    "unchecked_erc20_return", "Protocol: Unchecked ERC20 Return",
    "token.transfer / transferFrom return value not checked.")):
    pass


class ProtoCentralizedMintFeePlugin(_make(
    "centralized_mint_fee", "Protocol: Centralized Mint / Fee",
    "Owner mint with no supply cap, or fee setter with no bound.")):
    pass


class ProtoTimestampRandomnessPlugin(_make(
    "timestamp_randomness", "Protocol: Timestamp Randomness",
    "block.timestamp / prevrandao used to pick a random outcome.")):
    pass
