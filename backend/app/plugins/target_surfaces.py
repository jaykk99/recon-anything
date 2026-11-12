"""Target-surface detectors (Jay, 2026-11-11): aim the scanner at ten
named surfaces. One detector per surface, all in this file so they do
not collide with the separate 0-day agent's deep_audit numbering.

Contract side (verified-source static analysis, fast lane, via the
bsc_common spec system + custom handlers where a regex cannot tell
the safe shape from the abusive one):
  1 hardcoded_key_mnemonic_in_source - private keys / seed phrases
    in contract source. GAP: every cp secret plugin is web-only
    (accepts domain/url); no plugin scans verified contract source
    for keys. Custom handler: 0x 64-hex keys, WIF, BIP-39 checksum
    verified mnemonics. Secrets are REDACTED in every finding.
  2 malicious_token_approval - approve()/permit() granting
    unlimited allowance to a caller-supplied spender, or permit()
    with caller-supplied spender + signature parts. GAP: only
    bep20_allowance_double_spend exists (approve race), no
    approval-abuse detector.
  3 cex_api_key_in_contract - CEX API keys in contract source +
    contracts impersonating an exchange. GAP: cp_apikey_* and
    cp_phish_fake_exchange are web-only.
  6 permit2_allowance_abuse - Permit2 permit()/transferFrom()
    with a caller-supplied spender. GAP: zero Permit2 detector
    specs in the registry (only phishing/hygiene mentions).
  7 bridge_trust_concentration - bridge gated by a single relayer
    (no quorum) or mint/release gated but never verifying the
    source-chain lock/burn. GAP: bsc_mev_bridge covers ungated
    mint, quorum-counting and payload injection, not these two.
  8 governance_delegate_guardian_bypass - delegate() setting
    ANOTHER account's delegate, and execute() gated only by a
    guardian/emergency role. GAP: flash-loan voting is covered
    (flash_loan_governance_takeover), double delegation is covered
    (vote_double_delegation), early execution is covered
    (early_execution_race); these two shapes are not.
  9 multisig_threshold_weakness - threshold 1-of-N, single-owner
    multisig, unguarded owner/threshold changes, delegatecall in
    a multisig, owner changes with no timelock. GAP: only
    access_control_multi_sig_threshold_bypass exists (execute
    without comparing the count); no dedicated multisig detector.

Web side (homepage + same-domain JS, detection only):
  4 bank_login_phishing - page claims a bank brand + login form,
    served off the bank's real domain (or posting creds
    off-domain). GAP: no "phish" match in bank.py, bank_surface.py
    or bankpack_*.
  5 hardware_wallet_blind_sign_trap - JS building a signing
    request whose displayed intent contradicts the calldata
    (approve/transfer to a hardcoded address), EIP-712 domain
    spoofing, chain-id confusion. GAP: signature_request_inspector
    is a payload DECODER, walletcheck is a general checker;
    neither flags the trap.
 10 emv_js_skimmer - JS reading card fields AND exfiltrating to
    an off-domain host (not a known processor), plus skimmer
    obfuscation markers. GAP: fin_card_form_action covers HTML
    form actions only; no JS skimmer detector.

Detection only, everywhere. No account, key or device is ever
accessed; no transaction is ever broadcast; no money is ever
moved. Contract findings that hand value to a caller go through
the existing live-probe validator; the rest are trigger-only.
Secrets are redacted (first/last 4 chars only) in every finding
value, code snip and evidence field.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import bsc_common as bc
from .bsc_common import DetectorSpec, S, register_family
from . import contract_chain as cc
from . import contract_logic as cl
from .cryptopack_secrets import BIP39_WORD_INDEX
from .cryptopack_util import collect_texts
from .secretutils import redact

FAMILY = "target_surfaces"

# ---------------------------------------------------------------------------
# Shared helpers for the custom handlers
# ---------------------------------------------------------------------------

# EIP-1967-style storage-slot constants: well-known keccak-derived
# slot identifiers, not secrets. L1ChugSplashProxy / OpenZeppelin
# proxies declare IMPLEMENTATION_KEY / ADMIN_KEY / OWNER_KEY as
# bytes32(uint256(keccak256('eip1967.proxy.*')) - 1); the same values
# appear identically in every deployment of the pattern, which is
# exactly what a real leaked key never does.
_SLOT_KEY_NAMES = {
    "IMPLEMENTATION_KEY", "ADMIN_KEY", "OWNER_KEY", "BEACON_KEY",
    "LOGIC_KEY", "PROXY_KEY",
}
_PLACEHOLDER_HEX = {
    "0x" + "00" * 32,
    "0x" + "11" * 32,
    "0x" + "22" * 32,
    "0x" + "ff" * 32,
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f3ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b786",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca9c2289c028c082bdf29",
    "0x7c2c50c0f16f0c7a3e1a0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0",
    "0x0000000000000000000000000000000000000000000000000000000000000001",
    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
}


def _is_placeholder_key(hexkey: str) -> bool:
    h = hexkey.lower()
    if h in _PLACEHOLDER_HEX:
        return True
    body = h[2:]
    if len(set(body)) <= 2:
        return True
    if body.startswith("deadbeef") or body.startswith("1234567890abcdef"):
        return True
    return False


def _redact_code(text: str) -> str:
    """Mask every secret-shaped substring in a code snip."""
    out = text
    out = re.sub(r"0x[0-9a-fA-F]{64}",
                 lambda m: redact(m.group(0), show=4), out)
    out = re.sub(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b",
                 lambda m: redact(m.group(0), show=4), out)
    out = re.sub(r"(BINANCE_API_KEY|BINANCE_KEY|KRAKEN_API_KEY|"
                 r"KRAKEN_KEY|KUCOIN_API_KEY|KUCOIN_KEY|BYBIT_API_KEY|"
                 r"BYBIT_KEY|OKX_API_KEY|OK_ACCESS_KEY|COINBASE_API_KEY)"
                 r"(\s*[:=]\s*[\"']?)([A-Za-z0-9+/=_-]{16,})",
                 lambda m: m.group(1) + m.group(2)
                 + redact(m.group(3), show=4), out)
    # BIP-39-shaped word runs (12-24 lowercase words): a seed phrase
    # must never survive into a finding snip.
    out = re.sub(r"\b(?:[a-z]{3,12}[ \t]+){11,23}[a-z]{3,12}\b",
                 lambda m: redact(m.group(0), show=6), out)
    return out


def _bip39_valid(words: List[str]) -> bool:
    """True if the word list is a BIP-39 mnemonic with a valid
    SHA-256 checksum (same check as CpSecretBip39Sequence)."""
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    if not all(w in BIP39_WORD_INDEX for w in words):
        return False
    bits = "".join(format(BIP39_WORD_INDEX[w], "011b") for w in words)
    ent_len = len(bits) * 32 // 33
    ent = int(bits[:ent_len], 2).to_bytes(ent_len // 8, "big")
    cs = bits[ent_len:]
    digest = hashlib.sha256(ent).digest()
    return cs == format(digest[0], "08b")[:len(cs)]


def _mk(spec: DetectorSpec, fn_name: str, code: str,
        detail: str) -> Dict[str, Any]:
    return {"kind": spec.id, "severity": spec.severity,
            "function": fn_name, "code": code, "detail": detail}


def _finish_approval(spec: DetectorSpec, item: Dict[str, Any],
                     text: str) -> Dict[str, Any]:
    """bc._finish, then fix the recipient: approve()/permit() grant
    spending power to the spender, but classify_recipient only sees
    transfers/mints/ledger credits as destinations, so it returns
    UNRESOLVED for an approval-only function. The handler already
    proved the spender is a caller parameter, so the recipient is
    CALLER-SUPPLIED by construction."""
    out = bc._finish(spec, item, text)
    if out.get("recipient") == "UNRESOLVED":
        out["recipient"] = "CALLER-SUPPLIED"
    return out


def _fn_params(signature: str) -> List[str]:
    """Parameter names from a function signature string."""
    m = re.search(r"\((.*)\)", signature or "", re.S)
    if not m:
        return []
    params = []
    for part in m.group(1).split(","):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        if toks:
            name = toks[-1].strip()
            # drop array / location suffixes: `spender_`, `v_`, etc.
            name = re.sub(r"[^A-Za-z0-9_]", "", name)
            if name and name not in ("memory", "calldata", "storage"):
                params.append(name)
    return params


def _public_functions(src: str, contract_name: str):
    """(scope, [non-view public/external functions]) for handlers
    that need per-function analysis with gating."""
    scope, fns = bc._scope_and_fns(src, contract_name)
    out = []
    for fn in fns:
        sig = fn.get("signature", "")
        if re.search(r"\b(view|pure)\b", sig):
            continue
        if not re.search(r"\b(public|external)\b", sig):
            continue
        out.append(fn)
    return scope, out

# ---------------------------------------------------------------------------
# Custom handlers (registered into bsc_common._CUSTOMS at import time).
# A regex spec cannot tell "spender is a caller parameter" from
# "spender is a hardcoded router", and it cannot redact a secret
# from the code snip - so these six go through custom code.
# ---------------------------------------------------------------------------

_KEY_NAME_RE = re.compile(
    r"(?i)\b([A-Za-z_][A-Za-z0-9_]*(?:key|priv|secret|seed|mnemonic)"
    r"[A-Za-z0-9_]*)\b[^;=\n]{0,80}?[:=]\s*[\"']?"
    r"(0x[0-9a-fA-F]{64})[\"']?")
_WIF_RE = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")
_WORD_RUN_RE = re.compile(r"[\"']([a-z]+(?:\s+[a-z]+){11,23})[\"']")
_ARRAY_WORDS_RE = re.compile(r"[\"']([a-z]{3,12})[\"']")


def _custom_key_mnemonic(src, spec, compiler, contract_name):
    """#1: private keys / seed phrases in verified contract source."""
    out = []
    seen = set()
    clean = cc._strip_comments(src)
    # 0x 64-hex keys assigned to a key-named variable. A public key
    # is not a secret: skip names that say public.
    for m in _KEY_NAME_RE.finditer(clean):
        varname, hexkey = m.group(1), m.group(2)
        if "public" in varname.lower() or "pubkey" in varname.lower():
            continue
        if varname.upper() in _SLOT_KEY_NAMES:
            continue
        if _is_placeholder_key(hexkey):
            continue
        red = redact(hexkey, show=4)
        if red in seen:
            continue
        seen.add(red)
        line = clean[max(0, m.start() - 40):m.end() + 20].strip()
        out.append(_mk(spec, "", _redact_code(cc._snip(line)),
                       "Hardcoded private key in verified contract "
                       "source: a 64-hex key is assigned to a "
                       f"key-named variable ({red}). Anyone reading "
                       "this source controls the key - rotate it and "
                       "remove it from the contract."))
    # WIF private keys (base58, 5/K/L prefix) anywhere in code.
    for m in _WIF_RE.finditer(clean):
        wif = m.group(0)
        red = redact(wif, show=4)
        if red in seen:
            continue
        seen.add(red)
        line = clean[max(0, m.start() - 40):m.end() + 20].strip()
        out.append(_mk(spec, "", _redact_code(cc._snip(line)),
                       "Hardcoded WIF private key in verified "
                       f"contract source ({red}). Anyone reading "
                       "this source controls the key - rotate it and "
                       "remove it from the contract."))
    # BIP-39 mnemonics: 12/24-word runs with a valid checksum.
    low = clean.lower()
    for m in _WORD_RUN_RE.finditer(low):
        words = m.group(1).split()
        for n in (24, 12):
            if len(words) < n:
                continue
            cand = words[:n]
            if not _bip39_valid(cand):
                continue
            red = redact(" ".join(cand), show=6)
            if red in seen:
                continue
            seen.add(red)
            out.append(_mk(spec, "", _redact_code(cc._snip(
                clean[max(0, m.start() - 30):m.end() + 10])),
                f"BIP-39 seed phrase ({n} words, checksum valid) "
                f"in verified contract source ({red}). Anyone "
                "reading this source controls the wallet - move "
                "the funds and abandon the phrase."))
            break
    return out


_MAX_AMOUNT_RE = re.compile(
    r"type\s*\(\s*uint256\s*\)\s*\.\s*max|uint256\s*\(\s*-1\s*\)|"
    r"2\s*\*\*\s*256\s*-\s*1|~\s*uint256\s*\(\s*0\s*\)|"
    r"0x[fF]{64}|type\s*\(\s*uint\s*\)\s*\.\s*max")
_APPROVE_RE = re.compile(
    r"\.approve\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*([^;)]{0,120})\)")
_PERMIT_RE = re.compile(r"\.permit\s*\(([^;]{0,400}?)\)", re.S)


def _custom_approval_abuse(src, spec, compiler, contract_name):
    """#2: approve()/permit() granting unlimited allowance to a
    caller-supplied spender, or permit() with caller-supplied
    spender + signature parts."""
    scope, fns = _public_functions(src, contract_name)
    out = []
    for fn in fns:
        if cl._gated_deep(fn, scope):
            continue
        text = fn["text"]
        params = set(_fn_params(fn.get("signature", "")))
        name = fn["name"]
        for m in _APPROVE_RE.finditer(text):
            spender, amount = m.group(1), m.group(2)
            if spender not in params:
                continue
            if not _MAX_AMOUNT_RE.search(amount):
                continue
            item = _mk(spec, name, cc._snip(text[m.start():m.end()]),
                       "Unlimited token approval to a caller-"
                       "supplied spender: this function calls "
                       f"approve({spender}, <max>) where {spender} "
                       "is a caller parameter, so any stranger can "
                       "approve the contract's whole token balance "
                       "to their own address and drain it with "
                       "transferFrom. Approve only to a fixed, "
                       "trusted spender, or a bounded amount.")
            out.append(_finish_approval(spec, item, text))
        for m in _PERMIT_RE.finditer(text):
            args = [a.strip() for a in m.group(1).split(",")]
            if len(args) < 7:
                continue
            spender = args[1].strip()
            if spender not in params:
                continue
            # The signature parts (v/r/s) must also be caller params:
            # this function exists to execute someone else's permit.
            sig_parts = [a.strip() for a in args[4:7]]
            if not sig_parts or not all(
                    re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", p)
                    and p in params for p in sig_parts):
                continue
            item = _mk(spec, name, cc._snip(text[m.start():m.end()]),
                       "EIP-2612 permit with a caller-supplied "
                       f"spender: this function executes permit() "
                       f"with spender {spender} and signature parts "
                       "supplied by the caller, so any stranger can "
                       "have a victim's allowance set to an attacker "
                       "address. Only execute permits for a fixed, "
                       "trusted spender.")
            out.append(_finish_approval(spec, item, text))
    return out


_CEX_KEY_RES = [
    ("Binance", re.compile(
        r"(?:BINANCE_API_KEY|BINANCE_KEY)\s*[:=]\s*[\"']?"
        r"([A-Za-z0-9]{64})")),
    ("Kraken", re.compile(
        r"(?:KRAKEN_API_KEY|KRAKEN_KEY)\s*[:=]\s*[\"']?"
        r"([A-Za-z0-9+/=]{56,88})")),
    ("KuCoin", re.compile(
        r"(?:KUCOIN_API_KEY|KUCOIN_KEY)\s*[:=]\s*[\"']?([0-9a-f]{24})")),
    ("Bybit", re.compile(
        r"(?:BYBIT_API_KEY|BYBIT_KEY)\s*[:=]\s*[\"']?"
        r"([A-Za-z0-9]{36})")),
    ("OKX", re.compile(
        r"(?:OKX_API_KEY|OK_ACCESS_KEY)\s*[:=]\s*[\"']?"
        r"([0-9a-fA-F\-]{36})")),
    ("Coinbase", re.compile(
        r"(?:COINBASE_API_KEY|organizations/[a-f0-9\-]{36}/apiKeys/)"
        r"\s*[:=]?\s*[\"']?([A-Za-z0-9\-]{36,})")),
]
_CEX_SECRET_RE = re.compile(
    r"(?:BINANCE|KRAKEN|KUCOIN|BYBIT|OKX|COINBASE)[_ ]?(?:API_)?SECRET"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9+/=]{32,})")
_CEX_BRANDS = ("Binance", "Coinbase", "Kraken", "Bybit", "OKX", "KuCoin")
_IMPERSONATE_RE = re.compile(
    r"(?:function\s+(?:name|symbol)\s*\(\s*\)[^{]{0,200}?return\s+[\"']|"
    r"string\s+(?:public\s+)?(?:name|symbol)\s*=\s*[\"'])"
    r"(Binance|Coinbase|Kraken|Bybit|OKX|KuCoin)[\"']", re.I | re.S)


def _custom_cex_key(src, spec, compiler, contract_name):
    """#3: CEX API keys/secrets in contract source + contracts
    impersonating an exchange."""
    out = []
    seen = set()
    clean = cc._strip_comments(src)
    for brand, rx in _CEX_KEY_RES:
        for m in rx.finditer(clean):
            key = m.group(1)
            red = redact(key, show=4)
            if red in seen:
                continue
            seen.add(red)
            line = clean[max(0, m.start() - 30):m.end() + 10].strip()
            out.append(_mk(spec, "", _redact_code(cc._snip(line)),
                           f"Leaked {brand} API key in verified "
                           f"contract source ({red}). Anyone reading "
                           "this source can use the exchange account "
                           "- revoke the key and remove it from the "
                           "contract."))
    for m in _CEX_SECRET_RE.finditer(clean):
        key = m.group(1)
        red = redact(key, show=4)
        if red in seen:
            continue
        seen.add(red)
        line = clean[max(0, m.start() - 30):m.end() + 10].strip()
        out.append(_mk(spec, "", _redact_code(cc._snip(line)),
                       "Leaked exchange API secret in verified "
                       f"contract source ({red}). Revoke it and "
                       "remove it from the contract."))
    for m in _IMPERSONATE_RE.finditer(clean):
        brand = m.group(1)
        if brand in seen:
            continue
        seen.add(brand)
        line = clean[max(0, m.start() - 20):m.end() + 10].strip()
        out.append(_mk(spec, "", cc._snip(line),
                       f"Contract impersonates {brand}: its name()/ "
                       "symbol() claims to be the exchange. The real "
                       "exchange has no such token contract - this "
                       "is a fake-exchange token meant to trick "
                       "holders."))
    return out

_PERMIT2_ADDR = "0x000000000022d473030f116ddee9f6b43ac78ba3"
_PERMIT2_REF_RE = re.compile(
    r"0x000000000022D473030F116dDEE9F6B43aC78BA3|IPermit2|"
    r"\bpermit2\b", re.I)
_PERMIT2_CALL_RE = re.compile(
    r"\.\s*(permit|transferFrom)\s*\(([^;]{0,400}?)\)", re.S)


def _custom_permit2_abuse(src, spec, compiler, contract_name):
    """#6: Permit2 permit()/transferFrom() with a caller-supplied
    spender, letting a stranger set or spend allowances."""
    if not _PERMIT2_REF_RE.search(src):
        return []
    scope, fns = _public_functions(src, contract_name)
    out = []
    for fn in fns:
        if cl._gated_deep(fn, scope):
            continue
        text = fn["text"]
        params = set(_fn_params(fn.get("signature", "")))
        name = fn["name"]
        for m in _PERMIT2_CALL_RE.finditer(text):
            kind, argstr = m.group(1), m.group(2)
            args = [a.strip() for a in argstr.split(",")]
            if kind == "permit":
                # permit(owner, spender, ...): spender is arg 2.
                if len(args) < 2:
                    continue
                spender = args[1]
                if spender not in params:
                    continue
                what = (f"Permit2 permit() with caller-supplied "
                        f"spender {spender}")
            else:
                # transferFrom(from, to, amount, token): both ends
                # caller-controlled moves anyone's allowance.
                if len(args) < 2:
                    continue
                frm, to = args[0], args[1]
                if frm not in params or to not in params:
                    continue
                what = (f"Permit2 transferFrom() with caller-"
                        f"supplied from {frm} and to {to}")
            item = _mk(spec, name, cc._snip(text[m.start():m.end()]),
                       what + ": this function calls the Permit2 "
                       "contract with a spender / destination the "
                       "caller chooses, so any stranger can set an "
                       "allowance over the contract's tokens or move "
                       "tokens another address approved to Permit2. "
                       "Permit2 calls must target a fixed, trusted "
                       "spender.")
            out.append(_finish_approval(spec, item, text))
    return out


_RELAYER_GATE_RE = re.compile(
    r"msg\.sender\s*==\s*relayer|require\s*\(\s*msg\.sender\s*==\s*"
    r"relayer|onlyRelayer\b")
_QUORUM_RE = re.compile(
    r"quorum|threshold|validator|signatures|requiredSignatures|"
    r"hasRole\s*\(\s*VALIDATOR", re.I)
_MINT_FN_RE = re.compile(r"\bmint\b|\brelease\b|\bunlock\b")
_VERIFY_RE = re.compile(
    r"merkle|ecrecover|verify|proof|validateSignatures|"
    r"checkSignatures", re.I)
_GATE_RE = re.compile(
    r"onlyRelayer|onlyRole|onlyValidator|onlyAdmin|onlyOwner|"
    r"require\s*\(\s*msg\.sender\s*==", re.I)
# Shape B only fires on a contract that actually looks like a
# bridge. A plain mintable token has a gated mint() too; without
# this gate every ERC-20 with onlyOwner mint is a false positive
# (24 of them in the first live smoke run). Word boundaries matter:
# the second smoke run's last FP matched only because the string
# literal "NOT_RELAYER" contains "relayer" (a lending protocol's
# error string, not a bridge).
_BRIDGE_CONTEXT_RE = re.compile(
    r"\bbridge\b|\brelayer\b|onlyRelayer\b|cross[- ]?chain", re.I)


def _custom_bridge_trust(src, spec, compiler, contract_name):
    """#7: bridge gated by a single relayer, or mint/release gated
    but never verifying the source-chain lock/burn."""
    scope, fns = _public_functions(src, contract_name)
    out = []
    clean = cc._strip_comments(src)
    has_quorum = bool(_QUORUM_RE.search(clean))
    is_bridge = bool(_BRIDGE_CONTEXT_RE.search(clean))
    for fn in fns:
        text = fn["text"]
        name = fn["name"]
        # Shape A: single-relayer gate, no quorum anywhere.
        if _RELAYER_GATE_RE.search(text) and not has_quorum:
            out.append(_mk(
                spec, name, cc._snip(text[:400]),
                "Bridge relies on a single relayer: this function "
                "is gated only by msg.sender == relayer and the "
                "contract has no quorum, threshold or validator "
                "set. One compromised or rogue relayer key is the "
                "whole bridge - it can release funds alone. "
                "Require a quorum of distinct validators."))
            continue
        # Shape B: gated mint/release with no backing verification.
        # Only on a bridge-shaped contract: a plain token's gated
        # mint() is not a bridge and must not fire here.
        if is_bridge and _MINT_FN_RE.search(name) \
                and _GATE_RE.search(text) \
                and not _VERIFY_RE.search(text):
            out.append(_mk(
                spec, name, cc._snip(text[:400]),
                "Bridge mint/release never verifies backing: this "
                "function is gated by a role/relayer but never "
                "checks a merkle proof, validator signatures or "
                "any source-chain lock/burn event, so the gate "
                "alone is the only thing stopping unbacked mints. "
                "Verify the lock/burn proof on every mint."))
    return out


_DELEGATE_SET_RE = re.compile(
    r"delegates\s*\[\s*([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*=")
_GUARDIAN_RE = re.compile(
    r"onlyGuardian|onlyEmergency|guardian\s*==\s*msg\.sender|"
    r"msg\.sender\s*==\s*guardian|emergency\s*==\s*msg\.sender|"
    r"require\s*\(\s*msg\.sender\s*==\s*guardian", re.I)
_STATE_CHECK_RE = re.compile(
    r"state\s*\(|ProposalState|succeeded|eta|timelock|"
    r"getPastVotes|votingDelay", re.I)


def _custom_governance_bypass(src, spec, compiler, contract_name):
    """#8: delegate() setting another account's delegate, and
    execute() gated only by a guardian/emergency role."""
    scope, fns = _public_functions(src, contract_name)
    out = []
    for fn in fns:
        text = fn["text"]
        name = fn["name"]
        if re.search(r"delegate", name, re.I):
            params = set(_fn_params(fn.get("signature", "")))
            for m in _DELEGATE_SET_RE.finditer(text):
                acct = m.group(1)
                if acct not in params:
                    continue
                if re.search(
                        r"require\s*\(\s*msg\.sender\s*==\s*"
                        + re.escape(acct), text):
                    continue
                out.append(_mk(
                    spec, name, cc._snip(text[m.start():m.end() + 40]),
                    "Delegate-by-anyone: delegate() sets the "
                    f"delegate of {acct}, a caller-supplied "
                    "account, with no check that the caller is "
                    "that account. Any stranger can re-point "
                    "another holder's voting power to an attacker "
                    "delegate. Require msg.sender == account."))
        if re.search(r"execute", name, re.I):
            if _GUARDIAN_RE.search(text) \
                    and not _STATE_CHECK_RE.search(text):
                out.append(_mk(
                    spec, name, cc._snip(text[:400]),
                    "Guardian execute bypass: execute() is gated "
                    "only by a guardian/emergency role, with no "
                    "check that the proposal passed a vote or "
                    "cleared its timelock. One guardian can execute "
                    "any proposal - including one that failed - "
                    "alone. Execution must require a passed vote "
                    "and a cleared timelock."))
    return out


_THRESHOLD_ONE_RE = re.compile(
    r"(?:threshold|required|requiredConfirmations|"
    r"confirmationsRequired)\s*=\s*1\s*[;,\n]")
_SINGLE_OWNER_RE = re.compile(
    r"owners\s*=\s*\[\s*0x[0-9a-fA-F]{40}\s*\]|"
    r"new\s+address\s*\[\s*\]\s*\(\s*1\s*\)")
_MEMBERSHIP_FN_RE = re.compile(
    r"^(addOwner|removeOwner|replaceOwner|changeThreshold|"
    r"setThreshold|addOwners?)$", re.I)
_CONFIRM_GATE_RE = re.compile(
    r"onlyWallet|onlyOwner|confirmations\s*\[|isConfirmed|"
    r"require\s*\(\s*confirmations", re.I)
# A real multisig has an owners SET plus a threshold /
# confirmations mechanism. Loose words match proxies: a proxy's
# OWNER_KEY / owner() is not an owners set, and a lone "threshold"
# in a comment is not a multisig. Both must be present as words.
_MULTISIG_STRUCT_RE = re.compile(r"\bowners\b", re.I)
_MULTISIG_THRESHOLD_RE = re.compile(
    r"\bthreshold\b|\bconfirmations\b", re.I)
_TIMELOCK_RE = re.compile(r"timelock|delay|eta|scheduled", re.I)


def _custom_multisig_weakness(src, spec, compiler, contract_name):
    """#9: threshold 1-of-N, single-owner multisig, unguarded
    owner/threshold changes, delegatecall in a multisig."""
    clean = cc._strip_comments(src)
    out = []
    if not (_MULTISIG_STRUCT_RE.search(clean)
            and _MULTISIG_THRESHOLD_RE.search(clean)):
        return []
    if _THRESHOLD_ONE_RE.search(clean):
        m = _THRESHOLD_ONE_RE.search(clean)
        out.append(_mk(spec, "", cc._snip(
            clean[max(0, m.start() - 30):m.end() + 20]),
            "Multisig threshold is 1: the wallet executes with a "
            "single owner's approval, so one compromised key "
            "controls all funds. A multisig with threshold 1 is "
            "a single-sig wallet. Raise the threshold."))
    if _SINGLE_OWNER_RE.search(clean):
        m = _SINGLE_OWNER_RE.search(clean)
        out.append(_mk(spec, "", cc._snip(
            clean[max(0, m.start() - 30):m.end() + 20]),
            "Multisig has a single owner: the owners set holds "
            "one address, so one key controls all funds. Add "
            "independent owners and raise the threshold."))
    scope, fns = _public_functions(src, contract_name)
    for fn in fns:
        text = fn["text"]
        name = fn["name"]
        if _MEMBERSHIP_FN_RE.match(name or ""):
            if not _CONFIRM_GATE_RE.search(text):
                out.append(_mk(
                    spec, name, cc._snip(text[:400]),
                    f"Unguarded multisig membership change: "
                    f"{name}() changes owners/threshold with no "
                    "multi-sig confirmation gate (no onlyWallet / "
                    "confirmations check), so one owner can rewrite "
                    "the wallet's owners or threshold alone. "
                    "Membership changes must require the threshold "
                    "of confirmations."))
        if re.search(r"delegatecall", text, re.I):
            out.append(_mk(
                spec, name, cc._snip(text[:400]),
                "Delegatecall in a multisig: this wallet "
                "delegatecalls to a target, so an owner (or a "
                "compromised implementation) can execute arbitrary "
                "code in the wallet's context and drain it. A "
                "multisig must never delegatecall to an "
                "attacker-chosen target."))
    return out


SPECS = [
    S("hardcoded_key_mnemonic_in_source", FAMILY, severity="high",
      outcome="a", custom="ts_key_mnemonic",
      detail="Hardcoded private key or seed phrase in verified "
             "contract source.",
      fix="Remove the key/phrase from the contract, rotate it, "
          "and never store secrets in published source."),
    S("malicious_token_approval", FAMILY, severity="high",
      outcome="a", custom="ts_approval_abuse", recipient=True,
      detail="Unlimited token approval (or permit) granted to a "
             "caller-supplied spender.",
      fix="Approve only to a fixed, trusted spender, or a bounded "
          "amount; never let the caller choose the spender."),
    S("cex_api_key_in_contract", FAMILY, severity="high",
      outcome="a", custom="ts_cex_key",
      detail="Centralized-exchange API key/secret in verified "
             "contract source, or a contract impersonating an "
             "exchange.",
      fix="Revoke the key, remove it from the contract, and never "
          "ship exchange credentials in published source."),
    S("permit2_allowance_abuse", FAMILY, severity="high",
      outcome="a", custom="ts_permit2_abuse", recipient=True,
      detail="Permit2 permit()/transferFrom() with a "
             "caller-supplied spender.",
      fix="Permit2 calls must target a fixed, trusted spender; "
          "never let the caller choose it."),
    S("bridge_trust_concentration", FAMILY, severity="high",
      outcome="a", custom="ts_bridge_trust",
      detail="Bridge gated by a single relayer, or mint/release "
             "that never verifies source-chain backing.",
      fix="Require a quorum of distinct validators and verify "
          "the lock/burn proof on every mint/release."),
    S("governance_delegate_guardian_bypass", FAMILY, severity="high",
      outcome="a", custom="ts_governance_bypass",
      detail="Delegate() setting another account's delegate, or "
             "execute() gated only by a guardian/emergency role.",
      fix="Require msg.sender == account for delegation, and "
          "require a passed vote plus a cleared timelock for "
          "execution."),
    S("multisig_threshold_weakness", FAMILY, severity="high",
      outcome="a", custom="ts_multisig_weakness",
      detail="Multisig with threshold 1, a single owner, "
             "unguarded membership changes, or delegatecall.",
      fix="Raise the threshold, add independent owners, gate "
          "membership changes behind confirmations, and remove "
          "delegatecall."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}

# Register the custom handlers, then one plugin class per spec.
bc._CUSTOMS["ts_key_mnemonic"] = _custom_key_mnemonic
bc._CUSTOMS["ts_approval_abuse"] = _custom_approval_abuse
bc._CUSTOMS["ts_cex_key"] = _custom_cex_key
bc._CUSTOMS["ts_permit2_abuse"] = _custom_permit2_abuse
bc._CUSTOMS["ts_bridge_trust"] = _custom_bridge_trust
bc._CUSTOMS["ts_governance_bypass"] = _custom_governance_bypass
bc._CUSTOMS["ts_multisig_weakness"] = _custom_multisig_weakness

register_family(globals(), SPECS)

# ---------------------------------------------------------------------------
# Web-side detectors (homepage + same-domain JS, detection only).
# ---------------------------------------------------------------------------

_BANK_DOMAINS = {
    "chase": {"chase.com"},
    "bank of america": {"bankofamerica.com"},
    "wells fargo": {"wellsfargo.com"},
    "citibank": {"citi.com", "citibank.com"},
    "citi": {"citi.com", "citibank.com"},
    "hsbc": {"hsbc.com"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "td bank": {"td.com"},
    "rbc": {"rbc.com", "rbcroyalbank.com"},
    "scotiabank": {"scotiabank.com"},
    "bmo": {"bmo.com"},
    "capital one": {"capitalone.com"},
    "american express": {"americanexpress.com"},
    "discover": {"discover.com"},
    "us bank": {"usbank.com"},
    "pnc": {"pnc.com"},
    "santander": {"santander.com", "santander.co.uk"},
    "lloyds": {"lloydsbank.com"},
    "natwest": {"natwest.com"},
    "deutsche bank": {"db.com", "deutsche-bank.com"},
}
_PASSWORD_INPUT_RE = re.compile(
    r'<input[^>]+type\s*=\s*["\']password["\']', re.I)
_FORM_RE = re.compile(r"<form[^>]*>.*?</form>", re.I | re.S)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_HEADING_RE = re.compile(r"<h[12][^>]*>(.*?)</h[12]>", re.I | re.S)


def _host_of(url: str) -> str:
    from urllib.parse import urlparse
    return (urlparse(url or "").netloc or "").lower().split(":")[0]


def _is_real_bank_host(brand: str, host: str) -> bool:
    for real in _BANK_DOMAINS.get(brand, set()):
        if host == real or host.endswith("." + real):
            return True
    return False


class BankLoginPhishingPlugin(Plugin):
    """#4: a page claiming a bank brand + a login form, served off
    the bank's real domain (or posting creds off-domain)."""
    id = "bank_login_phishing"
    label = "Bank Login Phishing Page"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Bank-brand login pages served off-brand, or "
                   "posting credentials off-domain. Detection only; "
                   "forms are read, never submitted.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            res = self._degraded("homepage fetch failed")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        seen = set()
        html, page_url = "", ""
        for where, text, url in texts:
            if where == "homepage HTML":
                html, page_url = text, url
        if not html:
            res = self._ok([], "no homepage HTML")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        host = _host_of(page_url)
        low = re.sub(r"<[^>]+>", " ", html.lower())
        title = " ".join(_TITLE_RE.findall(html)).lower()
        heads = " ".join(_HEADING_RE.findall(html)).lower()
        forms = _FORM_RE.findall(html)
        has_password_form = any(
            _PASSWORD_INPUT_RE.search(f) for f in forms)
        for brand in _BANK_DOMAINS:
            if brand not in low:
                continue
            # The brand must be presented as the page's own
            # identity (title / heading / near the form), not a
            # passing mention in an article.
            branded = brand in title or brand in heads or any(
                brand in re.sub(r"<[^>]+>", " ", f).lower()
                for f in forms)
            if not branded:
                continue
            if _is_real_bank_host(brand, host):
                continue
            if not has_password_form:
                continue
            key = ("bank", brand)
            if key in seen:
                continue
            seen.add(key)
            # Off-domain credential post?
            off = ""
            for f in forms:
                if not _PASSWORD_INPUT_RE.search(f):
                    continue
                m = re.search(
                    r'action\s*=\s*["\']([^"\']+)["\']', f, re.I)
                if m:
                    ah = _host_of(m.group(1))
                    if ah and ah != host:
                        off = m.group(1)
            findings.append(self._f(
                "web", "bank_login_phishing",
                f"Bank login phishing: page claims to be "
                f"{brand.title()} with a password form, served "
                f"from {host or 'unknown host'} (not the bank's "
                f"real domain)"
                + (f"; the form posts credentials to {off}" if off
                   else "") + ".",
                source="bank login phishing detector",
                source_url=page_url, confidence=85,
                evidence={"brand": brand, "host": host,
                          "off_domain_post": off or None,
                          "severity": "high",
                          "remediation": "Do not enter credentials. "
                          "Report the domain to the bank's fraud "
                          "team and to the registrar."}))
        res = self._ok(findings,
                       f"{len(findings)} bank phishing finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


_APPROVE_SELECTOR = "0x095ea7b3"
_TRANSFER_SELECTOR = "0xa9059cbb"
_INTENT_RE = re.compile(
    r"\bclaim\b|\bmint\b|\bverify\b|\bairdrop\b|free\s+(reward|mint|"
    r"tokens?)|connect\s+wallet|check\s+eligibility", re.I)
_SIGN_CALL_RE = re.compile(
    r"eth_sendTransaction|eth_sign|eth_signTypedData|"
    r"signTypedData|personal_sign|request\s*\(\s*\{[^}]{0,200}?"
    r"method\s*:\s*[\"']eth_", re.I)
_EIP712_DOMAIN_RE = re.compile(
    r"domain\s*[:=]\s*\{([^}]{0,400}?)\}", re.I | re.S)
_EIP712_NAME_RE = re.compile(r"name\s*:\s*[\"']([^\"']+)[\"']", re.I)
_EIP712_CONTRACT_RE = re.compile(
    r"verifyingContract\s*:\s*[\"'](0x[0-9a-fA-F]{40})[\"']", re.I)
_EIP712_CHAIN_RE = re.compile(r"chainId\s*:\s*(\d+)", re.I)
_BRAND_HOSTS = {
    "metamask": {"metamask.io"}, "ledger": {"ledger.com"},
    "trezor": {"trezor.io"}, "coinbase": {"coinbase.com"},
    "binance": {"binance.com"}, "opensea": {"opensea.io"},
    "uniswap": {"uniswap.org", "app.uniswap.org"},
    "blur": {"blur.io"},
}
_CHAIN_IDS = {1: "ethereum", 56: "bsc", 137: "polygon",
              42161: "arbitrum", 10: "optimism", 43114: "avalanche",
              8453: "base"}
_CHAIN_WORDS = {
    "ethereum": 1, "bsc": 56, "binance smart chain": 56,
    "polygon": 137, "arbitrum": 42161, "optimism": 10,
    "avalanche": 43114, "base": 8453,
}


class HardwareWalletBlindSignTrapPlugin(Plugin):
    """#5: signing requests whose displayed intent contradicts the
    calldata, EIP-712 domain spoofing, chain-id confusion."""
    id = "hardware_wallet_blind_sign_trap"
    label = "Hardware Wallet Blind-Sign Trap"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Pages that trick hardware-wallet signing: a "
                   "claim/mint button whose calldata is an approval "
                   "or transfer, a spoofed EIP-712 domain, or a "
                   "payload for the wrong chain. Detection only; "
                   "nothing is ever signed.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            res = self._degraded("homepage fetch failed")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        seen = set()
        for where, text, url in texts:
            host = _host_of(url)
            low = text.lower()
            # (a) intent vs calldata: a claim/mint/verify lure near
            # an approve/transfer selector or call.
            if _INTENT_RE.search(text) and _SIGN_CALL_RE.search(text):
                for sel, what in ((_APPROVE_SELECTOR, "approve"),
                                  (_TRANSFER_SELECTOR, "transfer")):
                    if sel in low:
                        key = ("intent", what)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(self._f(
                            "web", "hardware_wallet_blind_sign_trap",
                            "Blind-sign trap: the page lures a "
                            "claim/mint/verify action but its signing "
                            f"request encodes {what}() ({sel}) - "
                            "the hardware wallet would sign a token "
                            "approval/transfer, not the displayed "
                            "action.",
                            source="hardware-wallet trap detector",
                            source_url=url, confidence=80,
                            evidence={"shape": "intent_vs_calldata",
                                      "call": what,
                                      "severity": "high",
                                      "remediation": "Do not sign. "
                                      "Read the calldata on the "
                                      "device before approving "
                                      "anything."}))
            # (b) EIP-712 domain spoofing: a brand name in the
            # signing domain, served off-brand.
            for dm in _EIP712_DOMAIN_RE.finditer(text):
                body = dm.group(1)
                nm = _EIP712_NAME_RE.search(body)
                if not nm:
                    continue
                name = nm.group(1).strip().lower()
                for brand, hosts in _BRAND_HOSTS.items():
                    if brand not in name:
                        continue
                    if host in hosts or any(
                            host.endswith("." + h) for h in hosts):
                        continue
                    key = ("domain", brand)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._f(
                        "web", "hardware_wallet_blind_sign_trap",
                        "EIP-712 domain spoofing: the signing "
                        f"domain claims to be {brand.title()} but "
                        "this page is served from "
                        f"{host or 'unknown host'}. The device "
                        "would show a trusted brand while the "
                        "contract is the attacker's.",
                        source="hardware-wallet trap detector",
                        source_url=url, confidence=85,
                        evidence={"shape": "eip712_domain_spoof",
                                  "brand": brand, "host": host,
                                  "severity": "high",
                                  "remediation": "Do not sign. A "
                                  "real brand never asks you to sign "
                                  "from another domain."}))
            # (c) chain-id confusion: payload chain differs from
            # the chain the page claims.
            claimed = None
            for word, cid in _CHAIN_WORDS.items():
                if word in low:
                    claimed = cid
                    break
            if claimed is not None:
                for cm in _EIP712_CHAIN_RE.finditer(text):
                    cid = int(cm.group(1))
                    if cid in _CHAIN_IDS and cid != claimed:
                        key = ("chain", cid)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(self._f(
                            "web", "hardware_wallet_blind_sign_trap",
                            "Chain-id confusion: the page presents "
                            f"itself as {_CHAIN_IDS.get(claimed)} "
                            "but its signing payload carries chainId "
                            f"{cid} ({_CHAIN_IDS[cid]}). A signature "
                            "meant for one chain would be valid on "
                            "another.",
                            source="hardware-wallet trap detector",
                            source_url=url, confidence=75,
                            evidence={"shape": "chain_id_confusion",
                                      "claimed_chain": claimed,
                                      "payload_chain": cid,
                                      "severity": "high",
                                      "remediation": "Do not sign. "
                                      "Check the chainId on the "
                                      "device matches the chain you "
                                      "are on."}))
        res = self._ok(findings,
                       f"{len(findings)} blind-sign trap finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


_CARD_FIELD_RE = re.compile(
    r"cardNumber|card_number|card-number|cc-number|cc_number|"
    r"cardNum|card_num|\bpan\b|cardPan|cvv|cvc|cvv2|"
    r"security.?code|card.?expir|expir\w*\s*(?:date|month|year)|"
    r"expMonth|expYear|exp.?date", re.I)
_EXFIL_RE = re.compile(
    r"(?:fetch|axios\.(?:post|get)|(?:new\s+)?XMLHttpRequest|"
    r"sendBeacon|\$\.ajax|\$\.post)\s*\(\s*[\"']([^\"']+)[\"']",
    re.I)
_KNOWN_PROCESSORS = (
    "stripe.com", "stripe.network", "braintreegateway.com",
    "braintreeapi.com", "checkout.com", "adyen.com", "paypal.com",
    "square.com", "worldpay.com", "authorize.net",
    "chasepaymentech.com", "globalpay.com", "checkout.com")
_OBFUSCATION_RES = (
    re.compile(r"String\.fromCharCode\s*\(", re.I),
    re.compile(r"atob\s*\(\s*[\"'][A-Za-z0-9+/=]{100,}[\"']", re.I),
    re.compile(r"eval\s*\(\s*[A-Za-z0-9_.$]+\s*\(", re.I),
    re.compile(r"document\.write\s*\(\s*[\"']<script", re.I),
    re.compile(r"[\"'][A-Za-z0-9+/=]{200,}[\"']"),
)


class EmvJsSkimmerPlugin(Plugin):
    """#10: Magecart-style JS skimmer - reads card fields and
    exfiltrates to an off-domain host, or hides behind
    obfuscation. Form actions alone are NOT this detector's job
    (fin_card_form_action covers those)."""
    id = "emv_js_skimmer"
    label = "EMV / Card Skimmer (JS)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("JavaScript that reads card fields and sends "
                   "them to a third-party host, or obfuscated "
                   "card-harvesting code. Detection only; nothing "
                   "is executed.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target, max_js=12)
        if not texts:
            res = self._degraded("homepage fetch failed")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        seen = set()
        for where, text, url in texts:
            if not _CARD_FIELD_RE.search(text):
                continue
            host = _host_of(url)
            # Off-domain exfiltration to a non-processor host.
            for m in _EXFIL_RE.finditer(text):
                dest = m.group(1)
                if dest.startswith("/") or dest.startswith("."):
                    continue
                dh = _host_of(dest)
                if not dh or dh == host:
                    continue
                if any(dh == p or dh.endswith("." + p)
                       for p in _KNOWN_PROCESSORS):
                    continue
                key = ("exfil", dh)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._f(
                    "web", "emv_js_skimmer",
                    "Card skimmer: JavaScript reads card fields "
                    f"(number/CVV/expiry) and sends data to {dh}, "
                    "an off-domain host that is not a known payment "
                    "processor.",
                    source="EMV skimmer detector",
                    source_url=url, confidence=85,
                    evidence={"shape": "card_read_plus_exfil",
                              "exfil_host": dh, "severity": "high",
                              "remediation": "Remove the script, "
                              "rotate any exposed processor keys, "
                              "and audit recent card transactions."}))
            # Obfuscated card harvesting (no exfil host visible).
            markers = sum(
                1 for rx in _OBFUSCATION_RES if rx.search(text))
            if markers >= 2:
                key = ("obf", url)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._f(
                    "web", "emv_js_skimmer",
                    "Obfuscated card harvester: JavaScript "
                    f"reads card fields and carries {markers} "
                    "skimmer obfuscation markers (encoded "
                    "strings / eval / dynamic script writes).",
                    source="EMV skimmer detector",
                    source_url=url, confidence=75,
                    evidence={"shape": "obfuscated_harvester",
                              "markers": markers,
                              "severity": "high",
                              "remediation": "Remove the script "
                              "and audit recent card "
                              "transactions."}))
        res = self._ok(findings,
                       f"{len(findings)} skimmer finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
