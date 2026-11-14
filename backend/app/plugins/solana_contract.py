"""Solana + pump.fun Contract Recon.

Given a Solana address - a raw base58 mint or program id, a
``solana:``/``sol:`` prefixed address, or a pump.fun coin URL - this
pulls the account READ-ONLY from public chain data and turns what it
finds into vulnerability / risk findings:

- SPL token mints (Token + Token-2022): mint authority still set
  (unlimited minting), freeze authority still set (balances can be
  frozen), REAL holder distribution (every token account pulled
  via getProgramAccounts and aggregated by owner wallet - pool /
  curve accounts labeled, ex-pool top holder computed; the largest
  -accounts read is only a fallback, and it returns empty for
  Token-2022 mints on the public RPC), supply/decimals, a full
  Token-2022 dangerous-extension audit (permanent delegate,
  transfer hook, default-frozen accounts, non-transferable,
  transfer fees, memo / confidential transfers, plus one audit
  summary of everything checked and clean), a creator deep-dive
  (exact creator share from the aggregation, creator SOL balance),
  a DexScreener sell-side read (no-sells honeypot proxy, pair age,
  dump / volatility moves), and an authority map: one finding
  listing who holds every power over the mint.
- pump.fun coins: still on the bonding curve vs graduated, mutable
  metadata / creator-held update authority, and the creator's share
  of supply. All of this is derived ON-CHAIN (the bonding curve PDA
  account and the Metaplex metadata PDA, read via the same Solana
  RPC): the pump.fun single-coin API endpoint is dead (see
  fetch_pump_coin), so the API is optional enrichment only and no
  finding depends on it.
- Solana programs: BPF upgradeable-loader programs whose upgrade
  authority is still set can have their code replaced by one key;
  revoked authority / non-upgradeable loaders are reported as such.

Everything is keyless and read-only: Solana JSON-RPC
(``getAccountInfo`` / ``getTokenLargestAccounts`` - both plain reads),
the pump.fun public frontend API (list endpoint / enrichment only),
and DexScreener as enrichment.
NEVER sends a transaction, never calls anything that mutates state.
Detection only.

Evidence is shown IN FULL in findings, per Jay's order (2026-10-29):
authority addresses, holder wallets, and API payloads are never
masked.

Thresholds (documented, chosen 2026-11-01):
- top-1 holder:  >20% of supply = medium, >=50% = high
- top-5 holders: >40% of supply = medium, >=75% = high
- top-10 holders: >60% of supply = medium, >=90% = high
- creator/dev share of a pump.fun coin: >1% = medium, >10% = high
- creator SOL balance below 0.05 SOL = near-zero / drained note
- DexScreener pair younger than 24h = medium freshness note,
  younger than 7 days = low note (exact creation time reported)
- 24h price change at or beyond -90% = dump note (high),
  at or beyond +1000% = volatility note (medium)
- buys > 0 with sells == 0 on the widest reported DexScreener
  window (h24, then h6, then h1) = high "no sells recorded" flag
Distribution severities are scored on the pool-excluded owner
shares whenever a pool / curve account is among the holders (a
liquidity pool holding most of the supply is normal; an insider
wallet holding it is not), and on the raw owner shares otherwise.
Pools are matched by token account address OR by owner wallet:
an AMM pair address (DexScreener) is not its vault's token
account address - it OWNS that account - and the pump.fun
bonding curve PDA likewise owns its associated token account.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

SOLANA_RPC = "https://api.mainnet-beta.solana.com"
PUMP_API = "https://frontend-api-v3.pump.fun/coins"
DEX_API = "https://api.dexscreener.com/latest/dex/tokens"
SOLSCAN_ACCOUNT = "https://solscan.io/account/{addr}"

PUMP_PROGRAM = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
MPL_TOKEN_METADATA_PROGRAM = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s"
ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
BPF_UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
BPF_LOADER_V2 = "BPFLoader211111111111111111111111111111111"
BPF_LOADER_V1 = "BPFLoader111111111111111111111111111111111"
SYSTEM_PROGRAM = "11111111111111111111111111111111"

MAX_ADDRESSES = 3
ENRICH_OWNERS = 5      # token accounts whose owner wallet we resolve
MAX_HOLDER_ACCOUNTS = 5000   # getProgramAccounts processing cap

# Documented concentration thresholds (share of total supply).
TOP1_MEDIUM = 0.20
TOP1_HIGH = 0.50
TOP5_MEDIUM = 0.40
TOP5_HIGH = 0.75
TOP10_MEDIUM = 0.60
TOP10_HIGH = 0.90
CREATOR_MEDIUM = 0.01
CREATOR_HIGH = 0.10
CREATOR_DRAINED_LAMPORTS = 50_000_000   # 0.05 SOL: near-zero wallet
PAIR_FRESH_MEDIUM_HOURS = 24
PAIR_FRESH_LOW_HOURS = 24 * 7
PRICE_DUMP_PCT = -90.0        # 24h change at/beyond this = dump note
PRICE_PUMP_PCT = 1000.0       # 24h change at/beyond this = vol note

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}
_B58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


# ---------------------------------------------------------------------------
# Base58 + target parsing (pure)
# ---------------------------------------------------------------------------

def b58decode(s: str) -> Optional[bytes]:
    try:
        n = 0
        for ch in s:
            n = n * 58 + _B58_INDEX[ch]
        body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        pad = len(s) - len(s.lstrip("1"))
        return b"\x00" * pad + body
    except (KeyError, OverflowError):
        return None


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def is_solana_address(s: str) -> bool:
    """True for a base58 string that decodes to exactly 32 bytes."""
    s = (s or "").strip()
    if not _B58_RE.match(s):
        return False
    decoded = b58decode(s)
    return decoded is not None and len(decoded) == 32


# ---------------------------------------------------------------------------
# Program Derived Addresses (pure stdlib: sha256 + ed25519 on-curve check)
# ---------------------------------------------------------------------------

_ED25519_P = 2 ** 255 - 19
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) \
    % _ED25519_P


def _ed25519_on_curve(data: bytes) -> bool:
    """True when a 32-byte compressed ed25519 point is on the curve,
    i.e. some x satisfies -x^2 + y^2 = 1 + d*x^2*y^2 for its y.
    Existence of x is a Legendre-symbol check on x^2."""
    if not data or len(data) != 32:
        return False
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    if y >= _ED25519_P:
        return False
    y2 = (y * y) % _ED25519_P
    denom = (_ED25519_D * y2 + 1) % _ED25519_P
    if denom == 0:
        return False
    x2 = ((y2 - 1) * pow(denom, _ED25519_P - 2, _ED25519_P)) \
        % _ED25519_P
    if x2 == 0:
        return True
    return pow(x2, (_ED25519_P - 1) // 2, _ED25519_P) == 1


def create_program_address(seeds: List[bytes],
                           program_id: str) -> Optional[str]:
    """Solana createProgramAddress: sha256(seeds || program_id ||
    "ProgramDerivedAddress"); valid only when the digest is OFF the
    ed25519 curve (a PDA has no private key). None when on-curve or
    the inputs are malformed."""
    pid = b58decode(program_id)
    if pid is None or len(pid) != 32:
        return None
    h = hashlib.sha256()
    for seed in seeds:
        h.update(seed)
    h.update(pid)
    h.update(b"ProgramDerivedAddress")
    digest = h.digest()
    if _ed25519_on_curve(digest):
        return None
    return b58encode(digest)


def find_program_address(seeds: List[bytes], program_id: str
                         ) -> Tuple[Optional[str], Optional[int]]:
    """findProgramAddress: try bump 255 down to 0, first off-curve
    digest wins. Returns (address, bump) or (None, None)."""
    for bump in range(255, -1, -1):
        addr = create_program_address(list(seeds) + [bytes([bump])],
                                      program_id)
        if addr is not None:
            return addr, bump
    return None, None


def bonding_curve_address(mint: str) -> Optional[str]:
    """The pump.fun bonding curve PDA for a mint:
    seeds [b"bonding-curve", mint] under the pump program."""
    mint_bytes = b58decode(mint)
    if mint_bytes is None or len(mint_bytes) != 32:
        return None
    addr, _ = find_program_address([b"bonding-curve", mint_bytes],
                                   PUMP_PROGRAM)
    return addr


def metaplex_metadata_address(mint: str) -> Optional[str]:
    """The Metaplex metadata PDA for a mint:
    seeds [b"metadata", metadata program, mint]."""
    mint_bytes = b58decode(mint)
    mpl_bytes = b58decode(MPL_TOKEN_METADATA_PROGRAM)
    if mint_bytes is None or mpl_bytes is None:
        return None
    addr, _ = find_program_address(
        [b"metadata", mpl_bytes, mint_bytes],
        MPL_TOKEN_METADATA_PROGRAM)
    return addr


def associated_token_address(owner: str, mint: str,
                             token_program: str = TOKEN_PROGRAM
                             ) -> Optional[str]:
    """Associated token account address: PDA with seeds
    [owner, token program, mint] under the ATA program. Used to
    identify the bonding curve's own token account among the largest
    holders by exact derivation - never guessed."""
    owner_b = b58decode(owner)
    mint_b = b58decode(mint)
    prog_b = b58decode(token_program)
    if owner_b is None or mint_b is None or prog_b is None:
        return None
    addr, _ = find_program_address([owner_b, prog_b, mint_b],
                                   ASSOCIATED_TOKEN_PROGRAM)
    return addr


def parse_solana_target(raw: str) -> Optional[str]:
    """Extract a Solana address from a scan target, or None.

    Accepts: a raw base58 address, ``solana:<addr>`` / ``sol:<addr>``,
    and pump.fun coin URLs (``pump.fun/coin/<mint>``, ``pump.fun/<mint>``).
    """
    s = (raw or "").strip()
    if not s:
        return None
    low = s.lower()
    for prefix in ("solana:", "sol:"):
        if low.startswith(prefix):
            rest = s[len(prefix):].strip()
            return rest if is_solana_address(rest) else None
    if is_solana_address(s):
        return s
    if re.match(r"(?i)^https?://", s):
        try:
            p = urlparse(s)
        except Exception:
            return None
        if (p.netloc or "").lower() in ("pump.fun", "www.pump.fun"):
            parts = [seg for seg in (p.path or "").split("/") if seg]
            if len(parts) == 2 and parts[0] == "coin" \
                    and is_solana_address(parts[1]):
                return parts[1]
            if len(parts) == 1 and is_solana_address(parts[0]):
                return parts[0]
    return None


# ---------------------------------------------------------------------------
# Read-only chain / API access (shared rate-limited fetch; reads only)
# ---------------------------------------------------------------------------

async def sol_rpc(ctx: Any, method: str,
                  params: List[Any]) -> Optional[Any]:
    """One Solana JSON-RPC read. Returns the ``result`` or None when
    every attempt failed (transport error, bad status, RPC error)."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": method,
               "params": params}
    try:
        r = await fetch(ctx.http, ctx.limiter, "POST", SOLANA_RPC,
                        json=payload, timeout=15, max_retries=0)
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None
    if not isinstance(d, dict) or "error" in d:
        return None
    return d.get("result")


async def get_account_info(ctx: Any, address: str) -> Optional[Dict]:
    """getAccountInfo (jsonParsed). Returns the full result dict -
    ``result["value"]`` is None for a nonexistent account - or None
    when the RPC itself failed."""
    result = await sol_rpc(ctx, "getAccountInfo",
                           [address, {"encoding": "jsonParsed"}])
    return result if isinstance(result, dict) else None


async def get_account_info_base64(ctx: Any,
                                  address: str) -> Optional[Dict]:
    """getAccountInfo (base64) for accounts jsonParsed cannot decode
    (pump.fun bonding curve, Metaplex metadata): raw account bytes
    are parsed by the layout parsers below. Same contract as
    get_account_info: result dict, value None = no such account,
    None = the RPC itself failed."""
    result = await sol_rpc(ctx, "getAccountInfo",
                           [address, {"encoding": "base64"}])
    return result if isinstance(result, dict) else None


async def get_largest_accounts(ctx: Any, mint: str) -> Optional[List]:
    """getTokenLargestAccounts: the 20 biggest token accounts.

    NOTE: on the public RPC this returns an EMPTY list for
    Token-2022 mints, so it is only a fallback - the real holder
    distribution comes from getProgramAccounts below."""
    result = await sol_rpc(ctx, "getTokenLargestAccounts", [mint])
    if not isinstance(result, dict):
        return None
    value = result.get("value")
    return value if isinstance(value, list) else None


async def get_program_accounts(ctx: Any, token_program: str,
                               mint: str) -> Optional[List]:
    """getProgramAccounts on the token program that owns the mint,
    memcmp filter offset 0 = mint (the first 32 bytes of every SPL
    token account are its mint). Returns the raw result list of
    {pubkey, account} entries, or None when the RPC failed. This is
    the heavy read the largest-accounts endpoint cannot do for
    Token-2022 mints; callers cap how much of it they process."""
    result = await sol_rpc(ctx, "getProgramAccounts", [
        token_program,
        {"encoding": "jsonParsed",
         "filters": [{"memcmp": {"offset": 0, "bytes": mint}}]}])
    return result if isinstance(result, list) else None


async def get_balance(ctx: Any, address: str) -> Optional[int]:
    """getBalance: the account's SOL balance in lamports, or None
    when the RPC failed."""
    result = await sol_rpc(ctx, "getBalance", [address])
    if isinstance(result, dict):
        value = result.get("value")
        return value if isinstance(value, int) else None
    return result if isinstance(result, int) else None


async def fetch_pump_coin(ctx: Any, mint: str) -> Optional[Dict]:
    """pump.fun public frontend API coin record, or None.

    BEST-EFFORT ENRICHMENT ONLY. The single-coin endpoint
    (frontend-api-v3.pump.fun/coins/<mint>) returned 404 for EVERY
    mint tested on 2026-11-01, including long-lived coins like
    Fartcoin and WIF - the endpoint shape has changed or died. That
    is why pump.fun coverage (bonding curve, creator, metadata) is
    derived ON-CHAIN from the bonding curve PDA and the Metaplex
    metadata PDA instead: no finding depends on this call. Anything
    unexpected - non-200, non-dict, an error body - degrades to None
    and the on-chain checks carry on without it. No conclusion is
    drawn from its absence.
    """
    try:
        r = await fetch(ctx.http, ctx.limiter, "GET",
                        f"{PUMP_API}/{mint}", timeout=15, max_retries=0)
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None
    if not isinstance(d, dict) or d.get("error"):
        return None
    if d.get("mint") and d["mint"] != mint:
        return None
    return d


async def fetch_dex_pairs(ctx: Any, mint: str) -> List[Dict]:
    """DexScreener pairs for a token mint ([] when none / on failure)."""
    try:
        r = await fetch(ctx.http, ctx.limiter, "GET",
                        f"{DEX_API}/{mint}", timeout=15, max_retries=0)
        if r.status_code != 200:
            return []
        d = r.json()
    except Exception:
        return []
    pairs = d.get("pairs") if isinstance(d, dict) else None
    return [p for p in pairs if isinstance(p, dict)] \
        if isinstance(pairs, list) else []


# ---------------------------------------------------------------------------
# Account normalization (jsonParsed first, raw-layout fallback)
# ---------------------------------------------------------------------------

def normalize_account(value: Optional[Dict]) -> Dict[str, Any]:
    """Normalize a getAccountInfo ``value`` into a flat dict:
    {owner, executable, lamports, parsed_type, info, raw_bytes}."""
    out: Dict[str, Any] = {"owner": "", "executable": False,
                           "lamports": 0, "parsed_type": "",
                           "info": {}, "raw_bytes": None}
    if not isinstance(value, dict):
        return out
    out["owner"] = str(value.get("owner") or "")
    out["executable"] = bool(value.get("executable"))
    try:
        out["lamports"] = int(value.get("lamports") or 0)
    except (TypeError, ValueError):
        out["lamports"] = 0
    data = value.get("data")
    if isinstance(data, dict):
        parsed = data.get("parsed")
        if isinstance(parsed, dict):
            out["parsed_type"] = str(parsed.get("type") or "")
            info = parsed.get("info")
            if isinstance(info, dict):
                out["info"] = info
    elif isinstance(data, list) and data and isinstance(data[0], str):
        try:
            out["raw_bytes"] = base64.b64decode(data[0])
        except Exception:
            out["raw_bytes"] = None
    return out


def parse_mint_raw(raw: bytes) -> Optional[Dict[str, Any]]:
    """SPL mint layout fallback (fixed offsets, base 82 bytes):
    mintAuthority COption<u32+32B> @0, supply u64 @36, decimals u8
    @44, isInitialized u8 @45, freezeAuthority COption @46."""
    if not raw or len(raw) < 82:
        return None

    def _coption(off: int) -> Optional[str]:
        flag = int.from_bytes(raw[off:off + 4], "little")
        if flag == 0:
            return None
        return b58encode(raw[off + 4:off + 36])

    return {
        "mintAuthority": _coption(0),
        "supply": str(int.from_bytes(raw[36:44], "little")),
        "decimals": raw[44],
        "isInitialized": bool(raw[45]),
        "freezeAuthority": _coption(46),
    }


# Token-2022 extension TLV type id -> the jsonParsed camelCase name the
# extension audit already understands. Only the ids that matter to the audit
# (or that we want surfaced) are mapped; others are reported by number.
_T22_EXT_NAMES = {
    1: "transferFeeConfig",
    2: "transferFeeAmount",
    3: "mintCloseAuthority",
    4: "confidentialTransferMint",
    5: "confidentialTransferAccount",
    6: "defaultAccountState",
    7: "immutableOwner",
    8: "memoTransfer",
    9: "nonTransferable",
    10: "interestBearingConfig",
    11: "cpiGuard",
    12: "permanentDelegate",
    13: "nonTransferableAccount",
    14: "transferHook",
    15: "transferHookAccount",
    16: "confidentialTransferFeeConfig",
    17: "confidentialTransferFeeAmount",
    18: "metadataPointer",
    19: "tokenMetadata",
    20: "groupPointer",
    21: "tokenGroup",
    22: "groupMemberPointer",
    23: "tokenGroupMember",
    24: "confidentialMintBurn",
    25: "scaledUiAmount",
    26: "pausable",
}

# Token-2022 account-type discriminator at offset 165: 1 = Mint, 2 = Account.
_T22_ACCOUNT_TYPE_MINT = 1
_T22_BASE_LEN = 165  # base + padding; account_type sits at this offset


def _b58_nonzero(raw: bytes) -> Optional[str]:
    """A 32-byte OptionalNonZeroPubkey: all-zero means None/unset."""
    if len(raw) != 32 or not any(raw):
        return None
    return b58encode(raw)


def parse_token2022_extensions_raw(raw: bytes) -> List[Dict[str, Any]]:
    """Decode a Token-2022 mint's extension TLV from its raw account bytes
    into the same ``[{extension, state}]`` shape jsonParsed returns.

    Many public RPCs don't parse Token-2022 mints and hand back raw base64,
    which blinds the jsonParsed extension audit. This reads the extension
    TLV directly so the dangerous extensions (permanent delegate, transfer
    hook, frozen-by-default, transfer fee) are still caught. Read-only; it
    decodes bytes already fetched and makes no new request.

    Returns [] when the account has no extension TLV (plain/legacy mint) or
    the bytes are malformed - never raises.
    """
    out: List[Dict[str, Any]] = []
    if not raw or len(raw) <= _T22_BASE_LEN:
        return out
    if raw[_T22_BASE_LEN] != _T22_ACCOUNT_TYPE_MINT:
        return out
    off = _T22_BASE_LEN + 1
    n = len(raw)
    while off + 4 <= n:
        ext_type = int.from_bytes(raw[off:off + 2], "little")
        length = int.from_bytes(raw[off + 2:off + 4], "little")
        off += 4
        if ext_type == 0:  # uninitialized padding -> end of TLV
            break
        val = raw[off:off + length]
        if len(val) < length:  # truncated / malformed
            break
        off += length
        name = _T22_EXT_NAMES.get(ext_type, f"extensionType{ext_type}")
        state: Any = _decode_t22_ext_state(name, val)
        out.append({"extension": name, "state": state})
    return out


def _decode_t22_ext_state(name: str, val: bytes) -> Any:
    """Best-effort state for a Token-2022 extension's raw value, shaped to
    match what the audit reads. Unknown layouts return {} (presence only)."""
    try:
        if name == "permanentDelegate" and len(val) >= 32:
            return {"delegate": _b58_nonzero(val[:32])}
        if name == "transferHook" and len(val) >= 64:
            return {"authority": _b58_nonzero(val[:32]),
                    "programId": _b58_nonzero(val[32:64])}
        if name == "defaultAccountState" and len(val) >= 1:
            st = {0: "uninitialized", 1: "initialized",
                  2: "frozen"}.get(val[0], str(val[0]))
            return {"accountState": st}
        if name == "mintCloseAuthority" and len(val) >= 32:
            return {"closeAuthority": _b58_nonzero(val[:32])}
        if name == "transferFeeConfig" and len(val) >= 108:
            # authorities(32+32) + withheld u64(8) + older fee(18) +
            # newer fee: epoch u64 @90, maximumFee u64 @98, bps u16 @106
            return {
                "transferFeeConfigAuthority": _b58_nonzero(val[0:32]),
                "withdrawWithheldAuthority": _b58_nonzero(val[32:64]),
                "newerTransferFee": {
                    "maximumFee": int.from_bytes(val[98:106], "little"),
                    "transferFeeBasisPoints":
                        int.from_bytes(val[106:108], "little"),
                },
            }
    except Exception:
        return {}
    return {}


def parse_token_account_raw(raw: bytes) -> Optional[Dict[str, Any]]:
    """SPL token account layout fallback (jsonParsed normally
    decodes these): mint pubkey @0 (32 bytes), owner pubkey @32
    (32 bytes), amount u64 @64. Returns {mint, owner, amount} with
    amount as a string, mirroring the jsonParsed shape."""
    if not raw or len(raw) < 72:
        return None
    return {
        "mint": b58encode(raw[0:32]),
        "owner": b58encode(raw[32:64]),
        "amount": str(int.from_bytes(raw[64:72], "little")),
    }


def parse_loader_raw(raw: bytes) -> Optional[Dict[str, Any]]:
    """BPF upgradeable-loader layout fallback.

    Loader state is a u32 enum: 2 = Program (followed by the 32-byte
    ProgramData address), 3 = ProgramData (u64 slot, then a COption
    upgrade authority: 1 byte flag + 32-byte pubkey when set)."""
    if not raw or len(raw) < 4:
        return None
    kind = int.from_bytes(raw[0:4], "little")
    if kind == 2 and len(raw) >= 36:
        return {"type": "program",
                "info": {"programData": b58encode(raw[4:36])}}
    if kind == 3 and len(raw) >= 13:
        authority = None
        if raw[12] == 1 and len(raw) >= 45:
            authority = b58encode(raw[13:45])
        return {"type": "programData",
                "info": {"slot": int.from_bytes(raw[4:12], "little"),
                         "upgradeAuthority": authority}}
    return None


def parse_bonding_curve(raw: bytes) -> Optional[Dict[str, Any]]:
    """pump.fun BondingCurve account layout (Anchor):
    8-byte discriminator, then u64 LE x5 (virtual_token_reserves,
    virtual_sol_reserves, real_token_reserves, real_sol_reserves,
    token_total_supply), then complete bool at offset 48, then the
    creator pubkey (32 bytes, offset 49) when the account is long
    enough (>= 81 bytes). Defensive by length: an account too short
    to hold the complete flag (< 49 bytes) does not parse at all; a
    shorter-than-81 account parses with creator=None."""
    if not raw or len(raw) < 49:
        return None

    def _u64(off: int) -> int:
        return int.from_bytes(raw[off:off + 8], "little")

    creator = None
    if len(raw) >= 81:
        creator = b58encode(raw[49:81])
    return {
        "virtual_token_reserves": _u64(8),
        "virtual_sol_reserves": _u64(16),
        "real_token_reserves": _u64(24),
        "real_sol_reserves": _u64(32),
        "token_total_supply": _u64(40),
        "complete": bool(raw[48]),
        "creator": creator,
    }


def parse_metaplex_metadata(raw: bytes) -> Optional[Dict[str, Any]]:
    """Metaplex Token Metadata account layout, parsed sequentially:
    key(1), updateAuthority(32), mint(32), then the Data struct -
    name / symbol / uri (each u32-LE length-prefixed, NUL-padded),
    sellerFeeBasisPoints(u16), creators option byte (0 = none,
    1 = u32 count + count*(32 address + 1 verified + 1 share)) -
    then primarySaleHappened(1) and isMutable(1). Any truncation or
    malformed length returns None (no conclusion drawn)."""
    if not raw or len(raw) < 65:
        return None
    try:
        off = 0
        key = raw[off]
        off += 1
        update_authority = b58encode(raw[off:off + 32])
        off += 32
        mint = b58encode(raw[off:off + 32])
        off += 32

        def _string() -> str:
            nonlocal off
            if off + 4 > len(raw):
                raise ValueError("truncated string length")
            n = int.from_bytes(raw[off:off + 4], "little")
            off += 4
            if n > len(raw) - off:
                raise ValueError("string overruns account")
            s = raw[off:off + n].decode("utf-8", errors="replace")
            off += n
            return s.rstrip("\x00")

        name = _string()
        symbol = _string()
        uri = _string()
        if off + 2 > len(raw):
            return None
        seller_fee = int.from_bytes(raw[off:off + 2], "little")
        off += 2
        creators: Optional[List[Dict[str, Any]]] = None
        if off >= len(raw):
            return None
        opt = raw[off]
        off += 1
        if opt == 1:
            if off + 4 > len(raw):
                return None
            count = int.from_bytes(raw[off:off + 4], "little")
            off += 4
            if count > 32 or off + count * 34 > len(raw):
                return None
            creators = []
            for _ in range(count):
                creators.append({
                    "address": b58encode(raw[off:off + 32]),
                    "verified": bool(raw[off + 32]),
                    "share": raw[off + 33],
                })
                off += 34
        elif opt != 0:
            return None
        if off + 2 > len(raw):
            return None
        primary_sale = bool(raw[off])
        is_mutable = bool(raw[off + 1])
    except Exception:
        return None
    return {
        "key": key,
        "update_authority": update_authority,
        "mint": mint,
        "name": name,
        "symbol": symbol,
        "uri": uri,
        "seller_fee_basis_points": seller_fee,
        "creators": creators,
        "primary_sale_happened": primary_sale,
        "is_mutable": is_mutable,
    }


async def fetch_bonding_curve(ctx: Any, mint: str
                              ) -> Tuple[str, Optional[Dict], Optional[str]]:
    """On-chain pump.fun bonding curve state for a mint.

    Returns (state, curve, curve_address): state is "found" (parsed
    curve dict, with its PDA address), "missing" (the RPC answered
    and no curve account exists - the mint is not on a pump.fun
    bonding curve now), or "unknown" (RPC failed / account did not
    parse - no conclusion drawn)."""
    curve_addr = bonding_curve_address(mint)
    if curve_addr is None:
        return "unknown", None, None
    result = await get_account_info_base64(ctx, curve_addr)
    if result is None:
        return "unknown", None, curve_addr
    value = result.get("value")
    if value is None:
        return "missing", None, curve_addr
    account = normalize_account(value)
    parsed = parse_bonding_curve(account["raw_bytes"]) \
        if account["raw_bytes"] else None
    if parsed is None:
        return "unknown", None, curve_addr
    parsed["address"] = curve_addr
    return "found", parsed, curve_addr


async def fetch_metaplex_metadata(ctx: Any, mint: str
                                  ) -> Tuple[str, Optional[Dict], Optional[str]]:
    """On-chain Metaplex metadata state for a mint. Same state
    contract as fetch_bonding_curve: "found" (parsed metadata dict,
    with its PDA address), "missing" (no metadata account), or
    "unknown" (RPC failed / unparseable - no conclusion)."""
    meta_addr = metaplex_metadata_address(mint)
    if meta_addr is None:
        return "unknown", None, None
    result = await get_account_info_base64(ctx, meta_addr)
    if result is None:
        return "unknown", None, meta_addr
    value = result.get("value")
    if value is None:
        return "missing", None, meta_addr
    account = normalize_account(value)
    parsed = parse_metaplex_metadata(account["raw_bytes"]) \
        if account["raw_bytes"] else None
    if parsed is None:
        return "unknown", None, meta_addr
    parsed["address"] = meta_addr
    return "found", parsed, meta_addr


def mint_info(account: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Mint info dict from a normalized account, or None if the
    account is not a mint (jsonParsed type wins; raw layout is the
    fallback when the RPC did not parse the account)."""
    if account.get("parsed_type") == "mint":
        return dict(account.get("info") or {})
    if account.get("owner") in (TOKEN_PROGRAM, TOKEN2022_PROGRAM) \
            and account.get("raw_bytes"):
        parsed = parse_mint_raw(account["raw_bytes"])
        if parsed is not None:
            return parsed
    return None


def program_data_info(account: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """ProgramData info from a normalized account (parsed or raw)."""
    if account.get("parsed_type") == "programData":
        return dict(account.get("info") or {})
    if account.get("raw_bytes"):
        parsed = parse_loader_raw(account["raw_bytes"])
        if parsed and parsed["type"] == "programData":
            return parsed["info"]
    return None


def program_data_address(account: Dict[str, Any]) -> Optional[str]:
    """The ProgramData address of an upgradeable program account."""
    info = account.get("info") or {}
    pd = info.get("programData")
    if isinstance(pd, str) and is_solana_address(pd):
        return pd
    if account.get("raw_bytes"):
        parsed = parse_loader_raw(account["raw_bytes"])
        if parsed and parsed["type"] == "program":
            return parsed["info"]["programData"]
    return None


# ---------------------------------------------------------------------------
# Analysis (pure: account dicts in, finding dicts out)
# ---------------------------------------------------------------------------

_REMEDIATION = {
    "solana_mint_authority_active": (
        "Revoke the mint authority (set it to None) once the intended "
        "supply exists, or move it behind a multisig. Until then the "
        "holder of that one key can inflate the supply without limit."),
    "solana_freeze_authority_active": (
        "Revoke the freeze authority, or move it behind a multisig "
        "with published freeze criteria. A single key that can freeze "
        "any holder's balance is a rug vector."),
    "solana_holder_concentration": (
        "Concentrated supply can be dumped by a few wallets. Look for "
        "vesting/lock evidence for the top wallets before trusting "
        "the token; treat unlocked insider wallets as exit liquidity "
        "risk."),
    "solana_program_upgrade_authority": (
        "Revoke the upgrade authority to make the program immutable, "
        "or move it behind a timelock + multisig and publish the "
        "policy. One key that can replace the program code owns every "
        "asset the program controls."),
    "pump_metadata_mutable": (
        "Burn / revoke the metadata update authority so the coin's "
        "name, symbol and image can no longer be swapped after "
        "launch."),
    "pump_bonding_curve_active": (
        "Until graduation the price is set entirely by the bonding "
        "curve and there is no DEX liquidity to exit into. Size any "
        "position accordingly."),
    "pump_creator_holdings": (
        "A large unlocked creator wallet is the classic dump risk. "
        "Look for lock/vesting proof for the creator wallet."),
    "solana_metadata_mutable": (
        "Burn / revoke the Metaplex metadata update authority so the "
        "token's name, symbol and image can no longer be swapped "
        "after launch."),
    "pump_bonding_curve_not_found": (
        "The mint is not trading on a pump.fun bonding curve right "
        "now. If it is presented as a live pump.fun launch, verify "
        "where its liquidity actually lives before sizing anything."),
    "solana_token2022_permanent_delegate": (
        "A permanent delegate can transfer or burn tokens from ANY "
        "holder account at any time. Only legitimate for regulated "
        "instruments with published terms; otherwise treat as a "
        "critical red flag."),
    "solana_token2022_transfer_fee": (
        "Transfer fees skim every transfer and the fee config can be "
        "changed by its authority. Check the current fee and who can "
        "raise it before holding this token."),
    "solana_token2022_non_transferable": (
        "Non-transferable tokens can never be sold or moved once "
        "received. Confirm that is the intent before accepting any."),
    "solana_token2022_default_frozen": (
        "New token accounts start frozen under this mint; holders "
        "depend on the freeze authority to ever move their tokens."),
    "solana_token2022_default_account_state": (
        "New token accounts start frozen under this mint; holders "
        "depend on the freeze authority to ever move their tokens."),
    "solana_holder_distribution": (
        "Concentrated supply outside the liquidity pool can be "
        "dumped by a few wallets. Look for vesting/lock evidence "
        "for the top non-pool wallets before trusting the token."),
    "solana_holder_distribution_unavailable": (
        "Holder concentration is UNKNOWN for this mint, not low. "
        "Re-run the scan when the RPC is healthy, or check the "
        "holder list on Solscan before sizing anything."),
    "solana_creator_wallet": (
        "A creator wallet that still holds a large unlocked share "
        "is the classic dump setup. Look for lock/vesting proof; a "
        "dev who is fully out and whose wallet is drained has no "
        "tokens left to dump, which is the safer shape."),
    "solana_token2022_transfer_hook": (
        "Every transfer runs an external hook program that can "
        "approve, tax or block the transfer - including blocking "
        "sells. Read the hook program before holding this token."),
    "solana_no_sells_recorded": (
        "Buys are happening but no sells are recorded - treat as a "
        "honeypot until a small test sell proves otherwise. Never "
        "size a position you cannot exit."),
    "solana_pair_freshness": (
        "A brand-new pair has no trading history to judge. Let it "
        "age and re-scan before sizing anything real."),
    "solana_price_volatility": (
        "A move this size in 24h means the book is thin or being "
        "manipulated. Do not chase it; re-check liquidity and "
        "holder concentration first."),
    "solana_authority_map": (
        "This is the control map for the mint: every power and who "
        "holds it. Powers held by one wallet should be revoked or "
        "moved behind a multisig before the token is trusted."),
    "solana_token2022_memo_transfer": (
        "Transfers into accounts under this mint must carry a memo. "
        "Mostly a compliance feature; it can break naive integrations "
        "and some exchange deposits."),
    "solana_token2022_confidential_transfer_mint": (
        "Confidential transfers let holders move tokens with "
        "encrypted balances, so flows cannot be fully audited from "
        "public chain data while the extension is in play."),
    "solana_token2022_extension_audit": (
        "Summary of the Token-2022 extension audit. Any extension "
        "listed as PRESENT has its own finding with the details."),
}


def _fd(key: str, severity: str, value: str,
        evidence: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ev = dict(evidence or {})
    ev["severity"] = severity
    if key in _REMEDIATION:
        ev["remediation"] = _REMEDIATION[key]
    return {"key": key, "severity": severity, "value": value,
            "evidence": ev}


def _ui_amount(raw_amount: int, decimals: int) -> str:
    if decimals <= 0:
        return f"{raw_amount:,}"
    whole, frac = divmod(raw_amount, 10 ** decimals)
    frac_s = f"{frac:0{decimals}d}".rstrip("0")
    return f"{whole:,}" + (f".{frac_s}" if frac_s else "")


def _pct(share: float) -> str:
    return f"{share * 100:.2f}%"


def holder_shares(largest: List[Dict], supply_raw: int) -> Dict[str, Any]:
    """Top-1 / top-10 shares of supply from getTokenLargestAccounts
    entries ({address, amount, owner?}). Shares are fractions."""
    amounts: List[Tuple[str, int, Optional[str]]] = []
    for entry in largest or []:
        if not isinstance(entry, dict):
            continue
        try:
            amt = int(entry.get("amount") or 0)
        except (TypeError, ValueError):
            continue
        amounts.append((str(entry.get("address") or ""), amt,
                        entry.get("owner")))
    amounts.sort(key=lambda t: t[1], reverse=True)
    top1 = amounts[0][1] / supply_raw if amounts and supply_raw else 0.0
    top10 = sum(a for _, a, _ in amounts[:10]) / supply_raw \
        if supply_raw else 0.0
    return {"top1_share": top1, "top10_share": top10,
            "holders": amounts, "count": len(amounts)}


def aggregate_holders(accounts: List[Dict[str, Any]], supply_raw: int,
                      pool_labels: Optional[Dict[str, str]] = None,
                      pool_owners: Optional[Dict[str, str]] = None
                      ) -> Dict[str, Any]:
    """Aggregate token accounts BY OWNER WALLET (pure).

    ``accounts`` entries: {address, owner, amount(int raw)} - one
    per token account. ``pool_labels`` maps known pool / curve
    TOKEN ACCOUNT addresses to a label ("DEX pool (pumpswap)",
    "pump.fun bonding curve"): a top account matching one is
    labeled pool, and an ex-pool owner ranking (pool accounts
    excluded) is computed alongside the raw one.

    ``pool_owners`` maps known pool OWNER WALLET addresses to a
    label, matched against each account's owner. This is the
    common AMM case: a DexScreener pair address is the pool
    account, and the pool's token vault is a separate token
    account OWNED BY the pair address - so matching by token
    account address alone misses the pool entirely and its share
    gets scored as whale concentration. An account is pool when
    EITHER its own address is in ``pool_labels`` OR its owner is
    in ``pool_owners``.

    Returns holder_count (distinct owners holding > 0),
    account_count (non-zero token accounts), owner-aggregated
    top1/top5/top10 supply shares, the same shares ex-pool, the
    top token accounts and top owners (with pool labels), and the
    full per-owner totals map for creator lookups."""
    pool_labels = pool_labels or {}
    pool_owners = pool_owners or {}

    def _pool_label(a: Dict[str, Any]) -> Optional[str]:
        return pool_labels.get(a["address"]) \
            or pool_owners.get(a["owner"])

    def _share(amount: int) -> float:
        return amount / supply_raw if supply_raw else 0.0

    nonzero = [a for a in accounts
               if a.get("owner") and (a.get("amount") or 0) > 0]
    by_owner: Dict[str, int] = {}
    for a in nonzero:
        by_owner[a["owner"]] = by_owner.get(a["owner"], 0) \
            + int(a["amount"])
    owners_sorted = sorted(by_owner.items(), key=lambda kv: kv[1],
                           reverse=True)
    accounts_sorted = sorted(nonzero, key=lambda a: a["amount"],
                             reverse=True)

    def _top_share(pairs: List[Tuple[str, int]], n: int) -> float:
        return _share(sum(amt for _, amt in pairs[:n]))

    # Ex-pool owner totals: pool token accounts removed (matched
    # by token account address OR by owner wallet).
    by_owner_ex: Dict[str, int] = {}
    for a in nonzero:
        if _pool_label(a):
            continue
        by_owner_ex[a["owner"]] = by_owner_ex.get(a["owner"], 0) \
            + int(a["amount"])
    owners_ex_sorted = sorted(by_owner_ex.items(),
                              key=lambda kv: kv[1], reverse=True)
    has_pool = any(_pool_label(a) for a in nonzero)

    top_accounts = []
    for a in accounts_sorted[:20]:
        top_accounts.append({
            "address": a["address"], "owner": a["owner"],
            "amount": a["amount"], "share": round(_share(a["amount"]), 6),
            "pool": _pool_label(a)})
    top_owners = [{"owner": o, "amount": amt,
                   "share": round(_share(amt), 6),
                   "pool": pool_owners.get(o)}
                  for o, amt in owners_sorted[:20]]
    ex_top_owner = None
    if owners_ex_sorted:
        o, amt = owners_ex_sorted[0]
        ex_top_owner = {"owner": o, "amount": amt,
                        "share": round(_share(amt), 6)}
    return {
        "holder_count": len(by_owner),
        "account_count": len(nonzero),
        "top1_share": _top_share(owners_sorted, 1),
        "top5_share": _top_share(owners_sorted, 5),
        "top10_share": _top_share(owners_sorted, 10),
        "ex_pool_top1_share": _top_share(owners_ex_sorted, 1),
        "ex_pool_top5_share": _top_share(owners_ex_sorted, 5),
        "ex_pool_top10_share": _top_share(owners_ex_sorted, 10),
        "has_pool": has_pool,
        "top_accounts": top_accounts,
        "top_owners": top_owners,
        "ex_pool_top_owner": ex_top_owner,
        "owner_totals": by_owner,
    }


def owner_share(dist: Dict[str, Any], wallet: str,
                supply_raw: int) -> Tuple[int, float]:
    """(raw amount, supply share) one wallet holds across ALL its
    token accounts in an aggregated distribution."""
    raw = int((dist.get("owner_totals") or {}).get(wallet, 0))
    return raw, (raw / supply_raw if supply_raw else 0.0)


def owner_rank(dist: Dict[str, Any], wallet: str) -> Optional[int]:
    """1-based rank of a wallet among owners by balance, or None
    when the wallet holds nothing."""
    for i, entry in enumerate(dist.get("top_owners") or []):
        if entry.get("owner") == wallet:
            return i + 1
    totals = dist.get("owner_totals") or {}
    if not totals.get(wallet):
        return None
    ranked = sorted(totals.items(), key=lambda kv: kv[1],
                    reverse=True)
    for i, (owner, _amt) in enumerate(ranked):
        if owner == wallet:
            return i + 1
    return None


async def fetch_holder_distribution(
        ctx: Any, mint: str, token_program: str, supply_raw: int,
        pool_labels: Optional[Dict[str, str]] = None,
        pool_owners: Optional[Dict[str, str]] = None
        ) -> Optional[Dict[str, Any]]:
    """REAL holder distribution for a mint via getProgramAccounts
    on the token program that owns it. Returns the aggregate_holders
    dict (plus capped / total_returned bookkeeping), or None when
    the RPC failed - callers then fall back to the largest-accounts
    read and, failing that, say concentration could not be
    measured. Processing is capped at MAX_HOLDER_ACCOUNTS accounts
    and the cap is disclosed in the result, never silent."""
    entries = await get_program_accounts(ctx, token_program, mint)
    if entries is None:
        return None
    total_returned = len(entries)
    capped = total_returned > MAX_HOLDER_ACCOUNTS
    accounts: List[Dict[str, Any]] = []
    for entry in entries[:MAX_HOLDER_ACCOUNTS]:
        if not isinstance(entry, dict):
            continue
        pubkey = entry.get("pubkey")
        acct_value = entry.get("account")
        if not isinstance(pubkey, str) or not isinstance(acct_value, dict):
            continue
        acct = normalize_account(acct_value)
        owner = None
        amount = 0
        if acct["parsed_type"] == "account":
            info = acct["info"]
            owner = info.get("owner")
            token_amount = info.get("tokenAmount") or {}
            try:
                amount = int(token_amount.get("amount") or 0)
            except (TypeError, ValueError):
                amount = 0
        elif acct["raw_bytes"]:
            parsed = parse_token_account_raw(acct["raw_bytes"])
            if parsed is not None:
                owner = parsed["owner"]
                amount = int(parsed["amount"])
        if isinstance(owner, str) and owner:
            accounts.append({"address": pubkey, "owner": owner,
                             "amount": amount})
    dist = aggregate_holders(accounts, supply_raw, pool_labels,
                             pool_owners)
    dist["capped"] = capped
    dist["total_returned"] = total_returned
    dist["processed"] = min(total_returned, MAX_HOLDER_ACCOUNTS)
    return dist


def _distribution_severity(dist: Dict[str, Any]) -> str:
    """Score the distribution on the ex-pool owner shares when a
    pool / curve account is among the holders, else the raw owner
    shares (documented in the module docstring)."""
    if dist.get("has_pool"):
        top1 = dist["ex_pool_top1_share"]
        top5 = dist["ex_pool_top5_share"]
        top10 = dist["ex_pool_top10_share"]
    else:
        top1 = dist["top1_share"]
        top5 = dist["top5_share"]
        top10 = dist["top10_share"]
    if top1 >= TOP1_HIGH or top5 >= TOP5_HIGH or top10 >= TOP10_HIGH:
        return "high"
    if top1 > TOP1_MEDIUM or top5 > TOP5_MEDIUM \
            or top10 > TOP10_MEDIUM:
        return "medium"
    return "low"


def analyze_holder_distribution(address: str, dist: Dict[str, Any],
                                supply_raw: int, decimals: int
                                ) -> List[Dict[str, Any]]:
    """The real holder-distribution finding: holder count, owner
    shares, pool labeling, ex-pool top holder, top accounts in
    full."""
    base = {"address": address, "chain": "solana"}
    sev = _distribution_severity(dist)
    scored = "pool-excluded" if dist.get("has_pool") else "raw"
    lines = []
    for a in dist["top_accounts"][:10]:
        line = (f"  {a['address']}: "
                f"{_ui_amount(a['amount'], decimals)} "
                f"({_pct(a['share'])} of supply) owned by wallet "
                f"{a['owner']}")
        if a.get("pool"):
            line += f" [POOL: {a['pool']}]"
        lines.append(line)
    cap_note = ""
    if dist.get("capped"):
        cap_note = (f" NOTE: the RPC returned "
                    f"{dist.get('total_returned')} token accounts; "
                    f"processing was capped at "
                    f"{dist.get('processed')} (cap "
                    f"{MAX_HOLDER_ACCOUNTS}), so the shares below "
                    f"cover the processed accounts only.")
    ex_note = ""
    if dist.get("has_pool") and dist.get("ex_pool_top_owner"):
        top = dist["ex_pool_top_owner"]
        ex_note = (f" Excluding pool/curve accounts, the top holder "
                   f"is wallet {top['owner']} with "
                   f"{_pct(top['share'])} of supply.")
    value = (
        f"{sev.upper()}: {address}: REAL holder distribution from "
        f"every token account on-chain (aggregated by owner "
        f"wallet): {dist['holder_count']} holder wallet(s) across "
        f"{dist['account_count']} funded token account(s). Top "
        f"owner holds {_pct(dist['top1_share'])}, top 5 hold "
        f"{_pct(dist['top5_share'])}, top 10 hold "
        f"{_pct(dist['top10_share'])} of supply (severity scored on "
        f"{scored} shares; thresholds: top-1 >20% medium / >=50% "
        f"high, top-5 >40% / >=75%, top-10 >60% / >=90%).{ex_note}"
        f"{cap_note} Largest token accounts, in full:\n"
        + "\n".join(lines))
    ev = {**base, "holder_count": dist["holder_count"],
          "account_count": dist["account_count"],
          "capped": bool(dist.get("capped")),
          "total_returned": dist.get("total_returned"),
          "top1_share": round(dist["top1_share"], 6),
          "top5_share": round(dist["top5_share"], 6),
          "top10_share": round(dist["top10_share"], 6),
          "ex_pool_top1_share": round(dist["ex_pool_top1_share"], 6),
          "ex_pool_top5_share": round(dist["ex_pool_top5_share"], 6),
          "ex_pool_top10_share": round(dist["ex_pool_top10_share"], 6),
          "scored_on": scored,
          "top_accounts": dist["top_accounts"][:10],
          "top_owners": dist["top_owners"][:10]}
    return [_fd("solana_holder_distribution", sev, value, ev)]


def analyze_holder_unavailable(address: str) -> List[Dict[str, Any]]:
    """Emitted when BOTH the program-accounts read and the
    largest-accounts fallback failed: concentration is unknown,
    and the finding says exactly that instead of staying silent."""
    return [_fd(
        "solana_holder_distribution_unavailable", "low",
        f"LOW: {address}: holder distribution could NOT be "
        f"measured this run - the public RPC returned neither the "
        f"mint's token accounts (getProgramAccounts) nor its "
        f"largest accounts. Holder concentration for this mint is "
        f"UNKNOWN, not low.",
        {"address": address, "chain": "solana"})]


def analyze_mint(address: str, info: Dict[str, Any], owner_program: str,
                 largest: Optional[List[Dict]],
                 raw_bytes: Optional[bytes] = None) -> List[Dict[str, Any]]:
    """Vulnerability/risk findings for one SPL token mint."""
    out: List[Dict[str, Any]] = []
    base = {"address": address, "chain": "solana",
            "token_program": owner_program}

    # Token-2022 blind-spot fallback: if the RPC didn't parse the mint's
    # extensions (jsonParsed gave none) but we have the raw account bytes
    # for a Token-2022 mint, decode the extension TLV ourselves so the
    # dangerous-extension audit below still runs. Marked so the audit can
    # note the source.
    if (owner_program == TOKEN2022_PROGRAM and raw_bytes
            and not info.get("extensions")):
        decoded = parse_token2022_extensions_raw(raw_bytes)
        if decoded:
            info = dict(info)
            info["extensions"] = decoded
            info["_extensions_source"] = "raw_tlv"
    try:
        supply_raw = int(info.get("supply") or 0)
    except (TypeError, ValueError):
        supply_raw = 0
    try:
        decimals = int(info.get("decimals") or 0)
    except (TypeError, ValueError):
        decimals = 0

    mint_auth = info.get("mintAuthority")
    if isinstance(mint_auth, str) and mint_auth:
        out.append(_fd(
            "solana_mint_authority_active", "critical",
            f"CRITICAL: {address}: mint authority is still set to "
            f"{mint_auth} - that wallet can mint unlimited new tokens "
            f"and inflate the supply at any time. Authority shown in "
            f"full: {mint_auth}",
            {**base, "mint_authority": mint_auth}))
    else:
        out.append(_fd(
            "solana_mint_authority_revoked", "low",
            f"LOW: {address}: mint authority is revoked (null) - the "
            f"supply cannot be inflated by minting.",
            {**base, "mint_authority": None}))

    freeze_auth = info.get("freezeAuthority")
    if isinstance(freeze_auth, str) and freeze_auth:
        out.append(_fd(
            "solana_freeze_authority_active", "high",
            f"HIGH: {address}: freeze authority is still set to "
            f"{freeze_auth} - that wallet can freeze any holder's "
            f"token account and trap their balance. Authority shown "
            f"in full: {freeze_auth}",
            {**base, "freeze_authority": freeze_auth}))
    else:
        out.append(_fd(
            "solana_freeze_authority_revoked", "low",
            f"LOW: {address}: freeze authority is revoked (null) - "
            f"no one can freeze holder balances.",
            {**base, "freeze_authority": None}))

    out.append(_fd(
        "solana_token_supply", "low",
        f"LOW: {address}: supply {_ui_amount(supply_raw, decimals)} "
        f"tokens (raw supply {supply_raw}, {decimals} decimals), "
        f"token program {owner_program}"
        + (" (Token-2022)" if owner_program == TOKEN2022_PROGRAM
           else ""),
        {**base, "supply_raw": supply_raw, "decimals": decimals,
         "supply_ui": _ui_amount(supply_raw, decimals)}))

    if largest:
        shares = holder_shares(largest, supply_raw)
        top1, top10 = shares["top1_share"], shares["top10_share"]
        if top1 >= TOP1_HIGH or top10 >= TOP10_HIGH:
            sev = "high"
        elif top1 > TOP1_MEDIUM or top10 > TOP10_MEDIUM:
            sev = "medium"
        else:
            sev = "low"
        lines = []
        for addr, amt, owner in shares["holders"][:10]:
            share = amt / supply_raw if supply_raw else 0.0
            line = (f"  {addr}: {_ui_amount(amt, decimals)} "
                    f"({_pct(share)} of supply)")
            if owner:
                line += f" owned by wallet {owner}"
            lines.append(line)
        out.append(_fd(
            "solana_holder_concentration", sev,
            f"{sev.upper()}: {address}: holder concentration - top "
            f"holder controls {_pct(top1)} of supply, top 10 control "
            f"{_pct(top10)} (thresholds: top-1 >20% medium / >=50% "
            f"high, top-10 >60% medium / >=90% high). Largest token "
            f"accounts, in full:\n" + "\n".join(lines),
            {**base, "top1_share": round(top1, 6),
             "top10_share": round(top10, 6),
             "largest_accounts": [
                 {"address": a, "amount": str(amt), "owner": o}
                 for a, amt, o in shares["holders"][:10]]}))

    out.extend(analyze_token2022_extensions(address, info, base))
    return out


def _ext_key(name: str) -> str:
    return "solana_token2022_" + re.sub(
        r"(?<!^)(?=[A-Z])", "_", name).lower()


# The dangerous / relevant Token-2022 extensions the audit checks
# explicitly, every mint. metadataPointer and tokenMetadata are
# deliberately NOT in this set: they already get their own
# findings from the generic pass below and must not duplicate.
_AUDITED_EXTENSIONS = (
    "permanentDelegate", "transferHook", "defaultAccountState",
    "transferFeeConfig", "nonTransferable", "memoTransfer",
    "confidentialTransferMint", "confidentialTransferAccount",
)


def _fee_parts(state: Any) -> Dict[str, Any]:
    """Transfer-fee numbers from a transferFeeConfig state, in
    either the flat shape or the real nested shape (current fee
    under newerTransferFee)."""
    if not isinstance(state, dict):
        return {}
    newer = state.get("newerTransferFee")
    newer = newer if isinstance(newer, dict) else {}
    return {
        "bps": state.get("transferFeeBasisPoints",
                         newer.get("transferFeeBasisPoints")),
        "maximum_fee": state.get("maximumFee",
                                 newer.get("maximumFee")),
        "config_authority": state.get("transferFeeConfigAuthority"),
        "withdraw_authority": state.get("withdrawWithheldAuthority"),
        "withheld_amount": state.get("withheldAmount"),
    }


def analyze_token2022_extensions(address: str, info: Dict[str, Any],
                                 base: Dict[str, Any]
                                 ) -> List[Dict[str, Any]]:
    """Full Token-2022 extension audit from jsonParsed mint info
    (info.extensions: [{extension, state}]).

    Every dangerous extension gets its OWN explicit finding with
    its authority shown in full; the ones checked and absent (or
    present-but-benign) roll into ONE summary finding,
    solana_token2022_extension_audit. State is always shown in
    full."""
    out: List[Dict[str, Any]] = []
    extensions = info.get("extensions")
    if not isinstance(extensions, list):
        return out
    present: Dict[str, Any] = {}
    for ext in extensions:
        if isinstance(ext, dict) and ext.get("extension"):
            present[str(ext["extension"])] = ext.get("state")

    def _state_json(state: Any) -> str:
        return json.dumps(state, sort_keys=True, default=str)

    audit_status: Dict[str, str] = {}

    # -- permanent delegate: one wallet can move/burn ANY holder's
    # tokens. The single worst extension a mint can carry.
    if "permanentDelegate" in present:
        state = present["permanentDelegate"]
        delegate = state.get("delegate") \
            if isinstance(state, dict) else None
        out.append(_fd(
            "solana_token2022_permanent_delegate", "critical",
            f"CRITICAL: {address}: Token-2022 PERMANENT DELEGATE "
            f"is set to {delegate} - that wallet can transfer or "
            f"BURN tokens from ANY holder's account at any time, "
            f"without the holder's approval. Extension state, in "
            f"full: {_state_json(state)}",
            {**base, "extension": "permanentDelegate",
             "extension_state": state, "delegate": delegate}))
        audit_status["permanentDelegate"] = \
            f"PRESENT - delegate {delegate} (see finding)"
    else:
        audit_status["permanentDelegate"] = "absent - clean"

    # -- transfer hook: every transfer calls an external program.
    if "transferHook" in present:
        state = present["transferHook"]
        program_id = state.get("programId") \
            if isinstance(state, dict) else None
        hook_auth = state.get("authority") \
            if isinstance(state, dict) else None
        out.append(_fd(
            "solana_token2022_transfer_hook", "high",
            f"HIGH: {address}: Token-2022 TRANSFER HOOK is set - "
            f"every transfer of this token calls the external "
            f"program {program_id}, which can approve, tax or "
            f"BLOCK any transfer, including blocking sells. Hook "
            f"authority: {hook_auth}. Extension state, in full: "
            f"{_state_json(state)}",
            {**base, "extension": "transferHook",
             "extension_state": state, "program_id": program_id,
             "authority": hook_auth}))
        audit_status["transferHook"] = \
            f"PRESENT - program {program_id} (see finding)"
    else:
        audit_status["transferHook"] = "absent - clean"

    # -- default account state: only dangerous when frozen.
    if "defaultAccountState" in present:
        state = present["defaultAccountState"]
        acct_state = str((state or {}).get("accountState", "")) \
            if isinstance(state, dict) else ""
        if acct_state.lower() == "frozen":
            out.append(_fd(
                "solana_token2022_default_account_state", "high",
                f"HIGH: {address}: Token-2022 DEFAULT ACCOUNT "
                f"STATE is FROZEN - every new token account for "
                f"this mint starts frozen and its owner cannot "
                f"move the tokens until the mint's freeze "
                f"authority thaws the account. Extension state, "
                f"in full: {_state_json(state)}",
                {**base, "extension": "defaultAccountState",
                 "extension_state": state}))
            audit_status["defaultAccountState"] = \
                "PRESENT - accounts start FROZEN (see finding)"
        else:
            audit_status["defaultAccountState"] = (
                f"present - accounts start {acct_state or 'initialized'}"
                f" (not frozen) - clean")
    else:
        audit_status["defaultAccountState"] = "absent - clean"

    # -- transfer fee config: a skim on every transfer.
    if "transferFeeConfig" in present:
        state = present["transferFeeConfig"]
        fee = _fee_parts(state)
        bps = fee.get("bps")
        pct = None
        if isinstance(bps, (int, float)):
            pct = f"{bps / 100:.2f}%"
        out.append(_fd(
            "solana_token2022_transfer_fee_config", "medium",
            f"MEDIUM: {address}: Token-2022 TRANSFER FEE is "
            f"active - every transfer is skimmed {bps} basis "
            f"points ({pct}), up to a maximum fee of "
            f"{fee.get('maximum_fee')} raw units per transfer. "
            f"Fee config authority: {fee.get('config_authority')}; "
            f"withdraw-withheld authority: "
            f"{fee.get('withdraw_authority')}; currently withheld: "
            f"{fee.get('withheld_amount')}. Extension state, in "
            f"full: {_state_json(state)}",
            {**base, "extension": "transferFeeConfig",
             "extension_state": state, **fee}))
        audit_status["transferFeeConfig"] = \
            f"PRESENT - {bps} bps (see finding)"
    else:
        audit_status["transferFeeConfig"] = "absent - clean"

    # -- non-transferable: soulbound, can never be sold or moved.
    if "nonTransferable" in present:
        state = present["nonTransferable"]
        out.append(_fd(
            "solana_token2022_non_transferable", "high",
            f"HIGH: {address}: Token-2022 NON-TRANSFERABLE is set "
            f"- tokens under this mint can NEVER be transferred, "
            f"sold or moved once received (soulbound). Anyone "
            f"buying this expecting to trade it is trapped. "
            f"Extension state, in full: {_state_json(state)}",
            {**base, "extension": "nonTransferable",
             "extension_state": state}))
        audit_status["nonTransferable"] = "PRESENT (see finding)"
    else:
        audit_status["nonTransferable"] = "absent - clean"

    # -- memo transfer: friction / compliance, low.
    if "memoTransfer" in present:
        state = present["memoTransfer"]
        out.append(_fd(
            "solana_token2022_memo_transfer", "low",
            f"LOW: {address}: Token-2022 MEMO TRANSFER is active "
            f"on this mint - transfers into enabled accounts must "
            f"carry a memo. Extension state, in full: "
            f"{_state_json(state)}",
            {**base, "extension": "memoTransfer",
             "extension_state": state}))
        audit_status["memoTransfer"] = "PRESENT (see finding)"
    else:
        audit_status["memoTransfer"] = "absent - clean"

    # -- confidential transfers: balances can be hidden, info-level.
    for name in ("confidentialTransferMint",
                 "confidentialTransferAccount"):
        if name in present:
            state = present[name]
            out.append(_fd(
                _ext_key(name), "low",
                f"LOW: {address}: Token-2022 extension '{name}' "
                f"is active on this mint - confidential transfers "
                f"are supported, so holder balances/flows can be "
                f"encrypted and are not fully auditable from "
                f"public chain data. Extension state, in full: "
                f"{_state_json(state)}",
                {**base, "extension": name,
                 "extension_state": state}))
            audit_status[name] = "PRESENT (see finding)"
        else:
            audit_status[name] = "absent - clean"

    # -- everything else present (metadataPointer, tokenMetadata,
    # group pointers, pausable, ...): one generic finding each,
    # state in full, exactly as before.
    _GENERIC_SEVERITY = {"metadataPointer": "low",
                         "tokenMetadata": "low"}
    for name, state in present.items():
        if name in _AUDITED_EXTENSIONS:
            continue
        sev = _GENERIC_SEVERITY.get(name, "low")
        out.append(_fd(
            _ext_key(name), sev,
            f"{sev.upper()}: {address}: Token-2022 extension "
            f"'{name}' is active on this mint. Extension state, in "
            f"full: {_state_json(state)}",
            {**base, "extension": name, "extension_state": state}))

    # -- the one audit summary: what was checked, what was clean.
    checked = "; ".join(f"{name}: {audit_status[name]}"
                        for name in _AUDITED_EXTENSIONS)
    dangerous_present = [
        n for n in ("permanentDelegate", "transferHook",
                    "transferFeeConfig", "nonTransferable")
        if n in present] + (
            ["defaultAccountState"]
            if audit_status["defaultAccountState"].startswith(
                "PRESENT") else [])
    verdict = ("all checked extensions are absent or benign"
               if not dangerous_present else
               "dangerous extension(s) present: "
               + ", ".join(dangerous_present)
               + " (each has its own finding above)")
    out.append(_fd(
        "solana_token2022_extension_audit", "low",
        f"LOW: {address}: Token-2022 extension audit - {verdict}. "
        f"Checked, in full: {checked}.",
        {**base, "audit": audit_status,
         "dangerous_present": dangerous_present}))
    return out


def analyze_pump_coin(address: str, pump: Dict[str, Any],
                      largest: Optional[List[Dict]],
                      supply_raw: int) -> List[Dict[str, Any]]:
    """pump.fun-specific findings from the frontend API record.

    Only called when the pump API (or the mint's pump.fun origin)
    identifies the coin. The full API record is attached as evidence.
    """
    out: List[Dict[str, Any]] = []
    base = {"address": address, "chain": "solana", "pump_fun": True}
    name = str(pump.get("name") or "")
    symbol = str(pump.get("symbol") or "")
    creator = pump.get("creator")
    creator = creator if isinstance(creator, str) else None
    label = f"{name} (${symbol})" if name or symbol else address

    out.append(_fd(
        "pump_coin_info", "low",
        f"LOW: {address}: pump.fun coin {label}, creator "
        f"{creator or 'unknown'}, created "
        f"{pump.get('created_timestamp')}, market cap (SOL terms) "
        f"{pump.get('market_cap')}, USD market cap "
        f"{pump.get('usd_market_cap')}. Full pump.fun record is in "
        f"the evidence.",
        {**base, "name": name, "symbol": symbol, "creator": creator,
         "pump_record": pump}))

    complete = pump.get("complete")
    if complete is False:
        out.append(_fd(
            "pump_bonding_curve_active", "medium",
            f"MEDIUM: {address}: {label} has NOT graduated - it is "
            f"still trading on the pump.fun bonding curve (complete="
            f"false). Bonding curve account "
            f"{pump.get('bonding_curve')}, associated curve account "
            f"{pump.get('associated_bonding_curve')}, virtual SOL "
            f"reserves {pump.get('virtual_sol_reserves')}, virtual "
            f"token reserves {pump.get('virtual_token_reserves')}. "
            f"There is no DEX pool yet; the curve sets the price and "
            f"the creator can still abandon it here.",
            {**base, "creator": creator,
             "bonding_curve": pump.get("bonding_curve"),
             "associated_bonding_curve":
                 pump.get("associated_bonding_curve")}))
    elif complete is True:
        out.append(_fd(
            "pump_graduated", "low",
            f"LOW: {address}: {label} has graduated off the pump.fun "
            f"bonding curve (complete=true); liquidity pool "
            f"{pump.get('raydium_pool')}.",
            {**base, "creator": creator,
             "raydium_pool": pump.get("raydium_pool")}))

    is_mutable = pump.get("is_mutable")
    if is_mutable is True:
        out.append(_fd(
            "pump_metadata_mutable", "high",
            f"HIGH: {address}: {label} metadata is MUTABLE "
            f"(is_mutable=true) and the metadata update authority is "
            f"the creator {creator} - the coin's name, symbol and "
            f"image can be swapped after launch (a common bait-and-"
            f"switch rug pattern). Metadata URI: "
            f"{pump.get('metadata_uri')}",
            {**base, "creator": creator, "is_mutable": True,
             "metadata_uri": pump.get("metadata_uri")}))
    elif is_mutable is False:
        out.append(_fd(
            "pump_metadata_immutable", "low",
            f"LOW: {address}: {label} metadata is immutable "
            f"(is_mutable=false) - name, symbol and image are locked.",
            {**base, "creator": creator, "is_mutable": False}))
    elif creator:
        out.append(_fd(
            "pump_metadata_mutable", "medium",
            f"MEDIUM: {address}: {label} - the pump.fun API did not "
            f"report is_mutable; pump.fun launches set the creator "
            f"{creator} as the Metaplex metadata update authority, "
            f"so treat the metadata as changeable by that wallet "
            f"until an explorer shows it revoked. Metadata URI: "
            f"{pump.get('metadata_uri')}",
            {**base, "creator": creator, "is_mutable": None,
             "metadata_uri": pump.get("metadata_uri")}))

    # Creator / dev share of supply, from the largest token accounts
    # (entries carry owner wallets when the plugin resolved them).
    if creator and largest and supply_raw:
        dev_raw = 0
        for entry in largest:
            if isinstance(entry, dict) and entry.get("owner") == creator:
                try:
                    dev_raw += int(entry.get("amount") or 0)
                except (TypeError, ValueError):
                    continue
        if dev_raw > 0:
            share = dev_raw / supply_raw
            sev = "high" if share > CREATOR_HIGH else \
                "medium" if share > CREATOR_MEDIUM else "low"
            out.append(_fd(
                "pump_creator_holdings", sev,
                f"{sev.upper()}: {address}: pump.fun creator wallet "
                f"{creator} holds {dev_raw} raw units = "
                f"{_pct(share)} of this coin's supply in its largest "
                f"token accounts. Creator wallet shown in full: "
                f"{creator}",
                {**base, "creator": creator,
                 "creator_raw_amount": dev_raw,
                 "creator_share": round(share, 6)}))
    return out


def creator_holdings(largest: Optional[List[Dict]], creator: str,
                     supply_raw: int) -> Tuple[int, float]:
    """Sum the creator-owned raw amount + supply share across the
    largest token accounts (entries carry owner wallets when the
    plugin resolved them). Returns (raw, share)."""
    dev_raw = 0
    for entry in largest or []:
        if isinstance(entry, dict) and entry.get("owner") == creator:
            try:
                dev_raw += int(entry.get("amount") or 0)
            except (TypeError, ValueError):
                continue
    share = dev_raw / supply_raw if supply_raw else 0.0
    return dev_raw, share


def analyze_bonding_curve(address: str, curve: Dict[str, Any],
                          largest: Optional[List[Dict]],
                          supply_raw: int,
                          curve_token_account: Optional[str] = None,
                          creator_override: Optional[Tuple[int, float]]
                          = None
                          ) -> List[Dict[str, Any]]:
    """pump.fun findings from the ON-CHAIN bonding curve account
    (the primary source - the pump API is enrichment only).

    Emits pump_bonding_curve_active / pump_graduated, plus a
    pump_creator_holdings finding whenever the curve names a
    creator: the creator wallet is always reported, with its share
    of supply summed over the largest token accounts."""
    out: List[Dict[str, Any]] = []
    base = {"address": address, "chain": "solana", "pump_fun": True,
            "source_detail": "on-chain bonding curve PDA"}
    curve_addr = curve.get("address")
    creator = curve.get("creator")
    ev = {**base, "bonding_curve": curve_addr, "creator": creator,
          "virtual_token_reserves": curve.get("virtual_token_reserves"),
          "virtual_sol_reserves": curve.get("virtual_sol_reserves"),
          "real_token_reserves": curve.get("real_token_reserves"),
          "real_sol_reserves": curve.get("real_sol_reserves"),
          "token_total_supply": curve.get("token_total_supply"),
          "complete": curve.get("complete")}

    # The curve's own token share, identified by exact ATA
    # derivation (never guessed): only reported when the derived
    # associated curve token account actually appears among the
    # largest accounts.
    curve_share: Optional[float] = None
    if curve_token_account and largest and supply_raw:
        for entry in largest:
            if isinstance(entry, dict) \
                    and entry.get("address") == curve_token_account:
                try:
                    curve_share = int(entry.get("amount") or 0) \
                        / supply_raw
                except (TypeError, ValueError):
                    curve_share = None
                break
    if curve_share is not None:
        ev["associated_bonding_curve"] = curve_token_account
        ev["curve_token_share"] = round(curve_share, 6)

    share_note = ""
    if curve_share is not None:
        share_note = (f" The curve's own token account "
                      f"{curve_token_account} holds "
                      f"{_pct(curve_share)} of supply.")
    if curve.get("complete") is False:
        out.append(_fd(
            "pump_bonding_curve_active", "medium",
            f"MEDIUM: {address}: this coin has NOT graduated - it "
            f"is still trading on the pump.fun bonding curve, read "
            f"directly on-chain from curve account {curve_addr} "
            f"(complete=false). Virtual SOL reserves "
            f"{curve.get('virtual_sol_reserves')}, virtual token "
            f"reserves {curve.get('virtual_token_reserves')}, real "
            f"SOL reserves {curve.get('real_sol_reserves')}, real "
            f"token reserves {curve.get('real_token_reserves')}. "
            f"There is no DEX pool yet; the curve sets the price "
            f"and the creator can still abandon it here.{share_note}",
            ev))
    elif curve.get("complete") is True:
        out.append(_fd(
            "pump_graduated", "low",
            f"LOW: {address}: the on-chain bonding curve account "
            f"{curve_addr} is marked complete=true - this coin has "
            f"graduated off the pump.fun bonding curve.{share_note}",
            ev))

    if creator:
        if creator_override is not None:
            # Exact share from the full holder aggregation (every
            # token account, summed by owner) - strictly better
            # than the largest-accounts estimate below.
            dev_raw, share = creator_override
            sev = "high" if share > CREATOR_HIGH else \
                "medium" if share > CREATOR_MEDIUM else "low"
            out.append(_fd(
                "pump_creator_holdings", sev,
                f"{sev.upper()}: {address}: pump.fun creator "
                f"wallet {creator} (read from the on-chain "
                f"bonding curve account) holds {dev_raw} raw "
                f"units = {_pct(share)} of this coin's supply "
                f"across EVERY token account it owns (full holder "
                f"aggregation, not just the largest accounts). "
                f"Creator wallet shown in full: {creator}",
                {**base, "creator": creator,
                 "creator_raw_amount": dev_raw,
                 "creator_share": round(share, 6),
                 "share_source": "holder_aggregation"}))
        elif largest is None:
            out.append(_fd(
                "pump_creator_holdings", "low",
                f"LOW: {address}: pump.fun creator wallet (read "
                f"from the on-chain bonding curve account) is "
                f"{creator}. Its share of supply could not be "
                f"measured this run because the largest token "
                f"accounts were unavailable. Creator wallet shown "
                f"in full: {creator}",
                {**base, "creator": creator,
                 "creator_raw_amount": None, "creator_share": None}))
        else:
            dev_raw, share = creator_holdings(largest, creator,
                                              supply_raw)
            sev = "high" if share > CREATOR_HIGH else \
                "medium" if share > CREATOR_MEDIUM else "low"
            out.append(_fd(
                "pump_creator_holdings", sev,
                f"{sev.upper()}: {address}: pump.fun creator wallet "
                f"{creator} (read from the on-chain bonding curve "
                f"account) holds {dev_raw} raw units = "
                f"{_pct(share)} of this coin's supply across the "
                f"largest token accounts. Creator wallet shown in "
                f"full: {creator}",
                {**base, "creator": creator,
                 "creator_raw_amount": dev_raw,
                 "creator_share": round(share, 6)}))
    return out


def analyze_curve_not_found(address: str, curve_addr: Optional[str],
                            pump: Optional[Dict[str, Any]]
                            ) -> List[Dict[str, Any]]:
    """Careful finding for when the pump.fun bonding curve PDA does
    not exist on-chain: the mint is not on a pump curve NOW. That
    alone does NOT prove graduation - a graduated coin's curve
    account is closed, and a mint that was never a pump coin has no
    curve either - so no graduated claim is made here."""
    base = {"address": address, "chain": "solana", "pump_fun": True,
            "bonding_curve": curve_addr,
            "pump_api_complete": (pump or {}).get("complete")}
    return [_fd(
        "pump_bonding_curve_not_found", "low",
        f"LOW: {address}: no pump.fun bonding curve account exists "
        f"on-chain at the derived curve address {curve_addr} - this "
        f"mint is not trading on a pump.fun bonding curve right "
        f"now. That does not by itself prove graduation: a "
        f"graduated coin's curve account is closed, and a mint that "
        f"was never launched on pump.fun has no curve either. "
        f"Check where its liquidity actually lives before treating "
        f"it as graduated.",
        base)]


def analyze_metaplex_metadata(address: str, metadata: Dict[str, Any]
                              ) -> List[Dict[str, Any]]:
    """Metadata mutability from the ON-CHAIN Metaplex metadata
    account. Mutable metadata means the update authority (shown in
    full) can swap the token's name, symbol and image at any time."""
    out: List[Dict[str, Any]] = []
    base = {"address": address, "chain": "solana",
            "metadata_account": metadata.get("address"),
            "metadata": {k: metadata.get(k) for k in (
                "update_authority", "name", "symbol", "uri",
                "seller_fee_basis_points", "creators",
                "primary_sale_happened", "is_mutable")}}
    update_auth = metadata.get("update_authority")
    label = (f"{metadata.get('name')} "
             f"(${metadata.get('symbol')})").strip()
    if metadata.get("is_mutable"):
        out.append(_fd(
            "solana_metadata_mutable", "high",
            f"HIGH: {address}: Metaplex metadata is MUTABLE "
            f"(isMutable=1, read on-chain from metadata account "
            f"{metadata.get('address')}) and the update authority "
            f"is {update_auth} - that wallet can swap the token's "
            f"name, symbol and image at any time (a common "
            f"bait-and-switch rug pattern). Token presents as "
            f"{label}, metadata URI {metadata.get('uri')}. Update "
            f"authority shown in full: {update_auth}",
            {**base, "update_authority": update_auth,
             "is_mutable": True}))
    else:
        out.append(_fd(
            "solana_metadata_immutable", "low",
            f"LOW: {address}: Metaplex metadata is immutable "
            f"(isMutable=0, read on-chain from metadata account "
            f"{metadata.get('address')}) - name, symbol and image "
            f"are locked. Token presents as {label}.",
            {**base, "update_authority": update_auth,
             "is_mutable": False}))
    return out


def analyze_creator_wallet(address: str, creator: str,
                           dist: Optional[Dict[str, Any]],
                           supply_raw: int,
                           sol_lamports: Optional[int]
                           ) -> List[Dict[str, Any]]:
    """Creator deep-dive: the creator's exact token share from the
    full holder aggregation (0% = the dev is fully out, said
    plainly), its rank among holders (aggregation is BY OWNER, so a
    creator holding through several token accounts is still caught
    as one wallet), and the creator wallet's SOL balance (near-zero
    = drained / throwaway wallet note)."""
    base = {"address": address, "chain": "solana",
            "creator": creator}
    parts: List[str] = []
    share: Optional[float] = None
    rank: Optional[int] = None
    dev_raw: Optional[int] = None
    if dist is not None:
        dev_raw, share = owner_share(dist, creator, supply_raw)
        rank = owner_rank(dist, creator)
        if dev_raw == 0:
            parts.append(
                f"the creator holds 0 of this token across every "
                f"token account on-chain - the dev is FULLY OUT of "
                f"this token and has no tokens left to dump")
        else:
            text = (f"the creator holds {dev_raw} raw units = "
                    f"{_pct(share)} of supply across all its token "
                    f"accounts")
            if rank is not None and rank <= 10:
                text += (f", making it the #{rank} largest holder "
                         f"wallet overall (aggregation is by owner, "
                         f"so split accounts do not hide it)")
            parts.append(text)
    else:
        parts.append(
            "the creator's token share could not be measured this "
            "run (holder distribution unavailable)")
    sol_note = None
    sol_value: Optional[float] = None
    if sol_lamports is None:
        parts.append("the creator wallet's SOL balance could not "
                     "be read this run")
    else:
        sol_value = sol_lamports / 1_000_000_000
        if sol_lamports < CREATOR_DRAINED_LAMPORTS:
            sol_note = "near-zero/drained"
            parts.append(
                f"its SOL balance is {sol_value:.9f} SOL "
                f"({sol_lamports} lamports) - near zero, consistent "
                f"with a drained or throwaway dev wallet")
        else:
            parts.append(
                f"its SOL balance is {sol_value:.9f} SOL "
                f"({sol_lamports} lamports)")
    if share is not None and share > CREATOR_HIGH:
        sev = "high"
    elif share is not None and share > CREATOR_MEDIUM:
        sev = "medium"
    else:
        sev = "low"
    value = (f"{sev.upper()}: {address}: creator deep-dive on "
             f"wallet {creator}: " + "; ".join(parts)
             + f". Creator wallet shown in full: {creator}")
    ev = {**base, "creator_raw_amount": dev_raw,
          "creator_share": (round(share, 6)
                            if share is not None else None),
          "creator_rank": rank,
          "creator_sol_lamports": sol_lamports,
          "creator_sol_balance": sol_value,
          "creator_sol_note": sol_note}
    return [_fd("solana_creator_wallet", sev, value, ev)]


def analyze_authority_map(address: str, info: Dict[str, Any],
                          metadata: Optional[Dict[str, Any]]
                          ) -> List[Dict[str, Any]]:
    """The authority map: ONE at-a-glance finding listing who
    holds every power over this mint - mint authority, freeze
    authority, metadata update authority, permanent delegate,
    transfer hook (upgrade authority is a program power, marked
    not-applicable for a mint). Holders shown IN FULL, or
    "revoked / none". A single wallet holding 3+ active powers
    bumps the finding to medium."""
    base = {"address": address, "chain": "solana"}
    ext: Dict[str, Any] = {}
    extensions = info.get("extensions")
    if isinstance(extensions, list):
        for e in extensions:
            if isinstance(e, dict) and e.get("extension"):
                ext[str(e["extension"])] = e.get("state")

    def _holder(v: Any) -> Optional[str]:
        return v if isinstance(v, str) and v else None

    mint_auth = _holder(info.get("mintAuthority"))
    freeze_auth = _holder(info.get("freezeAuthority"))
    delegate = None
    if isinstance(ext.get("permanentDelegate"), dict):
        delegate = _holder(ext["permanentDelegate"].get("delegate"))
    hook_program = None
    hook_authority = None
    if isinstance(ext.get("transferHook"), dict):
        hook_program = _holder(ext["transferHook"].get("programId"))
        hook_authority = _holder(ext["transferHook"].get("authority"))
    meta_auth = None
    meta_source = None
    if isinstance(ext.get("tokenMetadata"), dict):
        meta_auth = _holder(ext["tokenMetadata"].get(
            "updateAuthority"))
        if meta_auth:
            meta_source = "Token-2022 in-mint metadata"
    if meta_auth is None and metadata is not None:
        meta_auth = _holder(metadata.get("update_authority"))
        if meta_auth:
            meta_source = "Metaplex metadata account"

    def _line(label: str, holder: Optional[str],
              extra: str = "") -> str:
        shown = holder if holder else "revoked / none"
        return f"  {label}: {shown}{extra}"

    lines = [
        _line("mint authority (can mint new supply)", mint_auth),
        _line("freeze authority (can freeze holder accounts)",
              freeze_auth),
        _line("metadata update authority (can change name/symbol/"
              "image)", meta_auth,
              f" [{meta_source}]" if meta_source else
              " [not read this run]" if meta_auth is None else ""),
        _line("permanent delegate (can move/burn ANY holder's "
              "tokens)", delegate),
        _line("transfer hook (program every transfer must obey)",
              hook_program,
              f", hook authority {hook_authority}"
              if hook_authority else ""),
        "  program upgrade authority: not applicable - this is a "
        "token mint, not a program",
    ]
    powers: Dict[str, List[str]] = {}
    for label, holder in (("mint authority", mint_auth),
                          ("freeze authority", freeze_auth),
                          ("metadata update authority", meta_auth),
                          ("permanent delegate", delegate),
                          ("transfer hook authority", hook_authority)):
        if holder:
            powers.setdefault(holder, []).append(label)
    concentrated = {w: ps for w, ps in powers.items()
                    if len(ps) >= 3}
    sev = "medium" if concentrated else "low"
    conc_note = ""
    if concentrated:
        detail = "; ".join(
            f"wallet {w} holds {len(ps)} powers "
            f"({', '.join(ps)})"
            for w, ps in concentrated.items())
        conc_note = (f" CONCENTRATION: {detail} - one key controls "
                     f"this token end to end.")
    value = (f"{sev.upper()}: {address}: AUTHORITY MAP - who "
             f"holds every power over this mint:\n"
             + "\n".join(lines) + conc_note)
    ev = {**base, "mint_authority": mint_auth,
          "freeze_authority": freeze_auth,
          "metadata_update_authority": meta_auth,
          "metadata_authority_source": meta_source,
          "permanent_delegate": delegate,
          "transfer_hook_program": hook_program,
          "transfer_hook_authority": hook_authority,
          "powers_by_wallet": powers}
    return [_fd("solana_authority_map", sev, value, ev)]


def analyze_dex_pairs(address: str, pairs: List[Dict],
                      now_s: Optional[float] = None
                      ) -> List[Dict[str, Any]]:
    """Sell-side / honeypot-proxy findings from DexScreener pair
    data (the pairs the plugin already fetches): no-sells flag,
    pair-age freshness, dump / volatility moves. Only fields
    actually returned are read - a missing field draws NO
    conclusion."""
    out: List[Dict[str, Any]] = []
    if not pairs:
        return out
    base = {"address": address, "chain": "solana"}

    def _liq(p: Dict) -> float:
        try:
            return float((p.get("liquidity") or {}).get("usd") or 0)
        except (TypeError, ValueError):
            return 0.0

    top = max(pairs, key=_liq)
    pair_addr = top.get("pairAddress")
    dex = top.get("dexId")
    ev_top = {**base, "pair_address": pair_addr, "dex": dex}

    # -- no sells recorded while buys happen (honeypot proxy).
    txns = top.get("txns") or {}
    for window in ("h24", "h6", "h1"):
        w = txns.get(window)
        if not isinstance(w, dict):
            continue
        buys, sells = w.get("buys"), w.get("sells")
        if buys is None and sells is None:
            continue
        try:
            buys_i, sells_i = int(buys or 0), int(sells or 0)
        except (TypeError, ValueError):
            continue
        if buys_i > 0 and sells_i == 0:
            out.append(_fd(
                "solana_no_sells_recorded", "high",
                f"HIGH: {address}: NO SELLS RECORDED on the "
                f"deepest DexScreener pair {pair_addr} ({dex}) in "
                f"the {window} window, against {buys_i} buys. "
                f"Either nobody has tried to exit, or sells are "
                f"being blocked (honeypot shape). Do not buy what "
                f"you cannot sell; prove the exit with a small "
                f"test sell first.",
                {**ev_top, "window": window, "buys": buys_i,
                 "sells": sells_i}))
        break  # only the widest window with data decides

    # -- pair age / freshness.
    created_ms = top.get("pairCreatedAt")
    if isinstance(created_ms, (int, float)) and created_ms > 0:
        created_s = created_ms / 1000.0
        now = now_s if now_s is not None else time.time()
        age_h = (now - created_s) / 3600.0
        if 0 <= age_h < PAIR_FRESH_LOW_HOURS:
            created_iso = datetime.datetime.fromtimestamp(
                created_s, tz=datetime.timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC")
            sev = "medium" if age_h < PAIR_FRESH_MEDIUM_HOURS \
                else "low"
            age_txt = (f"{age_h:.1f} hours" if age_h < 48
                       else f"{age_h / 24:.1f} days")
            out.append(_fd(
                "solana_pair_freshness", sev,
                f"{sev.upper()}: {address}: the deepest "
                f"DexScreener pair {pair_addr} ({dex}) is "
                f"BRAND NEW - created {created_iso} "
                f"({age_txt} ago). New pairs have no exit history "
                f"and are where most rugs happen.",
                {**ev_top, "pair_created_at_ms": created_ms,
                 "pair_created_iso": created_iso,
                 "pair_age_hours": round(age_h, 2)}))

    # -- 24h dump / extreme volatility.
    change = top.get("priceChange") or {}
    h24 = change.get("h24")
    if isinstance(h24, (int, float)):
        extra = ", ".join(
            f"{k} {change[k]}%" for k in ("h1", "h6")
            if isinstance(change.get(k), (int, float)))
        suffix = f" ({extra})" if extra else ""
        if h24 <= PRICE_DUMP_PCT:
            out.append(_fd(
                "solana_price_volatility", "high",
                f"HIGH: {address}: this token has DUMPED "
                f"{h24}% in the last 24h on pair {pair_addr} "
                f"({dex}){suffix}. A fall past -90% in a day is "
                f"a collapse, not a dip - check whether liquidity "
                f"is still there at all before touching it.",
                {**ev_top, "price_change_h24": h24,
                 "price_change": change}))
        elif h24 >= PRICE_PUMP_PCT:
            out.append(_fd(
                "solana_price_volatility", "medium",
                f"MEDIUM: {address}: this token is up {h24}% in "
                f"the last 24h on pair {pair_addr} ({dex})"
                f"{suffix}. A vertical move past +1000% in a day "
                f"is manipulation or a blow-off top far more "
                f"often than it is organic demand.",
                {**ev_top, "price_change_h24": h24,
                 "price_change": change}))
    return out


def analyze_program(address: str, account: Dict[str, Any],
                    program_data: Optional[Dict[str, Any]]
                    ) -> List[Dict[str, Any]]:
    """Findings for an executable account (a Solana program).

    ``program_data`` is the normalized ProgramData account when the
    program uses the BPF upgradeable loader, else None."""
    out: List[Dict[str, Any]] = []
    base = {"address": address, "chain": "solana",
            "owner_program": account.get("owner")}
    owner = account.get("owner") or ""
    if owner == BPF_UPGRADEABLE_LOADER and program_data is not None:
        info = program_data_info(program_data) or {}
        # Live RPC jsonParsed names it "authority" (verified against
        # mainnet 2026-11-01); some shapes use "upgradeAuthority".
        authority = info.get("upgradeAuthority") or \
            info.get("authority")
        if isinstance(authority, dict):  # some RPC shapes nest it
            authority = authority.get("address") or \
                authority.get("pubkey")
        pd_addr = program_data_address(account)
        if isinstance(authority, str) and authority:
            out.append(_fd(
                "solana_program_upgrade_authority", "critical",
                f"CRITICAL: {address}: this program is UPGRADEABLE "
                f"and its upgrade authority is still set to "
                f"{authority} - that single wallet can replace the "
                f"program's code at any time, changing every rule "
                f"the program enforces. ProgramData account "
                f"{pd_addr}, deployed at slot {info.get('slot')}. "
                f"Authority shown in full: {authority}",
                {**base, "upgrade_authority": authority,
                 "program_data": pd_addr, "slot": info.get("slot")}))
        else:
            out.append(_fd(
                "solana_program_immutable", "low",
                f"LOW: {address}: upgrade authority is REVOKED "
                f"(null) on ProgramData account {pd_addr} - this "
                f"program's code can no longer be changed by anyone. "
                f"Deployed at slot {info.get('slot')}.",
                {**base, "upgrade_authority": None,
                 "program_data": pd_addr, "slot": info.get("slot")}))
    elif owner == BPF_UPGRADEABLE_LOADER:
        out.append(_fd(
            "solana_program_upgradeable_unparsed", "medium",
            f"MEDIUM: {address}: program uses the BPF upgradeable "
            f"loader but its ProgramData account could not be read, "
            f"so the upgrade authority is UNKNOWN. Treat the program "
            f"as upgradeable until verified otherwise.",
            {**base}))
    else:
        loader_name = {BPF_LOADER_V2: "BPF loader v2",
                       BPF_LOADER_V1: "BPF loader v1"}.get(
                           owner, owner or "unknown loader")
        out.append(_fd(
            "solana_program_non_upgradeable", "low",
            f"LOW: {address}: executable program on the non-"
            f"upgradeable {loader_name} - deployed code cannot be "
            f"replaced through an upgrade authority.",
            {**base, "loader": loader_name}))
    return out


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class SolanaContractPlugin(Plugin):
    id = "solana_contract"
    label = "Solana Contract Recon"
    accepts = ["solana_contract", "crypto_wallet", "url", "domain"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []  # keyless: public RPC + pump.fun + DexScreener
    description = ("Reads Solana contracts from public chain data: "
                   "SPL token mints (mint/freeze authority still "
                   "set, REAL holder distribution by owner wallet, "
                   "full Token-2022 dangerous-extension audit, "
                   "creator deep-dive, authority map), pump.fun "
                   "coins (bonding curve, mutable metadata, creator "
                   "holdings), DexScreener sell-side checks "
                   "(no-sells, pair age, dumps), and programs (BPF "
                   "upgrade authority). Read-only, never sends a "
                   "transaction.")
    phase = 2  # also consumes addresses discovered by phase-1 miners
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        work = self._collect(target, ctx)
        if not work:
            res = self._skipped(
                "no Solana address to recon: scan a Solana mint or "
                "program address, a solana:<address> target, or a "
                "pump.fun coin URL")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        reconned = 0
        for address in work:
            try:
                done = await self._recon_address(ctx, address, findings)
            except Exception:
                done = False
                findings.append(self._f(
                    "web3", "solana_recon_failed",
                    f"MEDIUM: {address}: Solana recon failed - chain "
                    "data could not be retrieved (public RPC "
                    "unreachable). No conclusion drawn.",
                    source="Solana JSON-RPC",
                    confidence=60, passive=True,
                    evidence={"severity": "medium", "address": address,
                              "chain": "solana",
                              "remediation": "Retry the scan; if the "
                                             "public RPC stays down, "
                                             "check the account on "
                                             "Solscan manually."}))
            if done:
                reconned += 1

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"reconned {reconned} Solana "
                                 f"address(es), {len(findings)} "
                                 f"findings")
        res.duration_ms = dur
        return res

    # -- target collection --------------------------------------------
    def _collect(self, target: Target, ctx: Ctx) -> List[str]:
        out: List[str] = []
        seen = set()

        def add(raw: Any) -> None:
            addr = parse_solana_target(str(raw or ""))
            if addr and addr not in seen:
                seen.add(addr)
                out.append(addr)

        for raw in (target.normalized, target.raw):
            add(raw)
        for kind in ("solana_addresses", "crypto_addresses",
                     "contract_addresses"):
            for item in ctx.consume(kind):
                add(item if isinstance(item, str)
                    else str((item or {}).get("address", "")))
        return out[:MAX_ADDRESSES]

    # -- per-address recon ---------------------------------------------
    async def _recon_address(self, ctx: Ctx, address: str,
                             findings: List[Finding]) -> bool:
        url = SOLSCAN_ACCOUNT.format(addr=address)
        result = await get_account_info(ctx, address)
        if result is None:
            findings.append(self._f(
                "web3", "solana_recon_failed",
                f"MEDIUM: {address}: the public Solana RPC did not "
                "answer, so no account data could be retrieved. No "
                "conclusion drawn.",
                source="Solana JSON-RPC getAccountInfo",
                source_url=url, confidence=60, passive=True,
                evidence={"severity": "medium", "address": address,
                          "chain": "solana",
                          "remediation": "Retry later; the public "
                                         "RPC endpoint was "
                                         "unreachable."}))
            return False

        value = result.get("value")
        if value is None:
            findings.append(self._f(
                "web3", "solana_account_not_found",
                f"MEDIUM: {address}: no account exists on Solana "
                "mainnet for this address - it has never been funded "
                "or created. It is not a live token or program.",
                source="Solana JSON-RPC getAccountInfo",
                source_url=url, confidence=90, passive=True,
                evidence={"severity": "medium", "address": address,
                          "chain": "solana",
                          "remediation": "Confirm the address and "
                                         "chain; a wrong-network or "
                                         "typo'd address shows up "
                                         "exactly like this."}))
            return False

        account = normalize_account(value)
        ctx.publish("solana_addresses", address)

        info = mint_info(account)
        if info is not None:
            await self._recon_mint(ctx, address, account, info, url,
                                   findings)
            return True

        if account["executable"]:
            program_data = None
            pd_addr = program_data_address(account)
            if account["owner"] == BPF_UPGRADEABLE_LOADER and pd_addr:
                pd_result = await get_account_info(ctx, pd_addr)
                if pd_result and pd_result.get("value") is not None:
                    program_data = normalize_account(
                        pd_result["value"])
            for fd in analyze_program(address, account, program_data):
                findings.append(self._to_finding(fd, url))
            return True

        # Neither mint nor program: name what it actually is.
        parsed_type = account["parsed_type"]
        detail = ""
        if parsed_type == "account":  # an SPL token account
            tinfo = account["info"]
            detail = (f" It is an SPL token account holding mint "
                      f"{tinfo.get('mint')} for wallet "
                      f"{tinfo.get('owner')}. Scan the mint address "
                      f"for the token's own risk findings.")
        elif account["owner"] == SYSTEM_PROGRAM:
            detail = " It is a plain wallet (system account)."
        findings.append(self._f(
            "web3", "solana_not_token_or_program",
            f"LOW: {address}: this account is not a token mint or "
            f"an executable program (owner program "
            f"{account['owner']}, parsed type "
            f"{parsed_type or 'unparsed'}).{detail}",
            source="Solana JSON-RPC getAccountInfo",
            source_url=url, confidence=88, passive=True,
            evidence={"severity": "low", "address": address,
                      "chain": "solana",
                      "owner_program": account["owner"],
                      "parsed_type": parsed_type,
                      "remediation": "Scan the mint or program "
                                     "address itself for contract "
                                     "risk findings."}))
        return True

    async def _recon_mint(self, ctx: Ctx, address: str,
                          account: Dict[str, Any],
                          info: Dict[str, Any], url: str,
                          findings: List[Finding]) -> None:
        owner_program = account["owner"]
        try:
            supply_raw = int(info.get("supply") or 0)
        except (TypeError, ValueError):
            supply_raw = 0
        try:
            decimals = int(info.get("decimals") or 0)
        except (TypeError, ValueError):
            decimals = 0

        # DexScreener pairs are fetched FIRST now: the deepest
        # pair's address joins the pool-label set for the holder
        # distribution, and the same pairs feed the sell-side
        # analysis at the end.
        pairs = await fetch_dex_pairs(ctx, address)

        # Fallback holder read (empty for Token-2022 mints on the
        # public RPC - the distribution below is the real one).
        largest = await get_largest_accounts(ctx, address)
        if largest:
            await self._enrich_owners(ctx, largest)

        # The bonding curve is read NOW (its full analysis happens
        # further down): when it exists on-chain, its associated
        # token account joins the pool-label set for the holder
        # distribution, so curve-held supply is labeled pool
        # instead of being scored as insider concentration.
        curve_state, curve, curve_addr = await fetch_bonding_curve(
            ctx, address)
        curve_token_acct = None
        if curve_state == "found" and curve_addr:
            curve_token_acct = associated_token_address(
                curve_addr, address, owner_program)
        pool_labels: Dict[str, str] = {}
        pool_owners: Dict[str, str] = {}
        for p in pairs:
            pa = p.get("pairAddress")
            if isinstance(pa, str) and pa:
                label = f"DEX pool ({p.get('dexId')})"
                pool_labels[pa] = label
                # A pair address is the pool account; the pool's
                # token vault is a DIFFERENT token account owned
                # BY the pair address. Register the pair as a pool
                # owner too, or owner-aggregated scoring reads the
                # pool's share as whale concentration.
                pool_owners[pa] = label
        if curve_token_acct:
            pool_labels[curve_token_acct] = "pump.fun bonding curve"
            # The curve PDA owns its associated token account.
            pool_owners[curve_addr] = "pump.fun bonding curve"
        # REAL holder distribution: every token account, by owner.
        dist = await fetch_holder_distribution(
            ctx, address, owner_program, supply_raw, pool_labels,
            pool_owners)

        # When the distribution exists it REPLACES the
        # largest-accounts concentration inside analyze_mint (pass
        # None there); the richer finding is emitted separately.
        for fd in analyze_mint(address, info, owner_program,
                               None if dist is not None else largest,
                               raw_bytes=account.get("raw_bytes")):
            findings.append(self._to_finding(fd, url))
        if dist is not None:
            for fd in analyze_holder_distribution(
                    address, dist, supply_raw, decimals):
                findings.append(self._to_finding(fd, url))
        elif not largest:
            for fd in analyze_holder_unavailable(address):
                findings.append(self._to_finding(fd, url))

        # pump.fun layer, ON-CHAIN first: the bonding curve PDA and
        # the Metaplex metadata PDA are read via the Solana RPC and
        # are the primary source for curve state, creator holdings
        # and metadata mutability. The pump.fun single-coin API
        # endpoint returned 404 for every mint tested on 2026-11-01,
        # so fetch_pump_coin is optional enrichment only - no finding
        # depends on it (its record is attached as pump_coin_info
        # when it does answer, and it only carries the pump bundle
        # when the on-chain reads themselves failed).
        pump = await fetch_pump_coin(ctx, address)
        pump_url = f"https://pump.fun/coin/{address}"

        # Metaplex metadata (classic SPL path). Token-2022 mints
        # with an in-mint tokenMetadata extension already surface it
        # via analyze_mint - do not double-report those.
        ext_names = {str(e.get("extension") or "")
                     for e in (info.get("extensions") or [])
                     if isinstance(e, dict)}
        meta_state, metadata, _ = "unknown", None, None
        if "tokenMetadata" not in ext_names:
            meta_state, metadata, _ = await fetch_metaplex_metadata(
                ctx, address)
        if metadata is not None:
            for fd in analyze_metaplex_metadata(address, metadata):
                findings.append(self._to_finding(fd, url))

        if curve_state == "found" and curve is not None:
            # Exact creator share from the holder aggregation when
            # it exists - strictly better than the largest-accounts
            # estimate analyze_bonding_curve falls back to.
            creator_override = None
            if dist is not None and curve.get("creator"):
                creator_override = owner_share(
                    dist, curve["creator"], supply_raw)
            for fd in analyze_bonding_curve(address, curve, largest,
                                            supply_raw,
                                            curve_token_acct,
                                            creator_override):
                findings.append(self._to_finding(fd, pump_url))
            if pump:
                # Enrichment only: the coin info record, nothing a
                # finding depends on (curve / creator / metadata all
                # came from on-chain above).
                for fd in analyze_pump_coin(address, pump, largest,
                                            supply_raw):
                    if fd["key"] == "pump_coin_info":
                        findings.append(self._to_finding(fd, pump_url))
        elif curve_state == "missing":
            if pump:
                for fd in analyze_pump_coin(address, pump, largest,
                                            supply_raw):
                    if fd["key"] == "pump_coin_info":
                        findings.append(self._to_finding(fd, pump_url))
                for fd in analyze_curve_not_found(address, curve_addr,
                                                  pump):
                    findings.append(self._to_finding(fd, pump_url))
            # No API record and no curve account: an ordinary mint,
            # not a pump claim - nothing to report.
        elif pump:
            # On-chain read failed (unknown): degrade to the API
            # enrichment bundle as before, minus any metadata claim
            # the on-chain metadata read already settled.
            skip = {"pump_metadata_mutable",
                    "pump_metadata_immutable"} \
                if metadata is not None else set()
            for fd in analyze_pump_coin(address, pump, largest,
                                        supply_raw):
                if fd["key"] not in skip:
                    findings.append(self._to_finding(fd, pump_url))

        # Creator deep-dive: creator resolved from the on-chain
        # curve first, then the pump API record, then the Metaplex
        # metadata creators list. Exact share comes from the
        # holder aggregation; the SOL balance is a separate read.
        creator = None
        if curve is not None and curve.get("creator"):
            creator = curve["creator"]
        elif pump and isinstance(pump.get("creator"), str):
            creator = pump["creator"]
        elif metadata is not None:
            creators = metadata.get("creators") or []
            if creators and isinstance(creators[0], dict):
                creator = creators[0].get("address")
        if isinstance(creator, str) and creator:
            sol_lamports = await get_balance(ctx, creator)
            for fd in analyze_creator_wallet(address, creator, dist,
                                             supply_raw,
                                             sol_lamports):
                findings.append(self._to_finding(fd, url))

        # Authority map: one at-a-glance finding over every power.
        for fd in analyze_authority_map(address, info, metadata):
            findings.append(self._to_finding(fd, url))

        # DexScreener enrichment: live pairs / liquidity, in full,
        # plus the sell-side read (no-sells, pair age, dumps) on
        # the same pairs fetched at the top of this recon.
        if pairs:
            def _liq(p: Dict) -> float:
                try:
                    return float((p.get("liquidity") or {}).get("usd")
                                 or 0)
                except (TypeError, ValueError):
                    return 0.0
            top = max(pairs, key=_liq)
            findings.append(self._f(
                "web3", "solana_dex_liquidity",
                f"LOW: {address}: {len(pairs)} DexScreener pair(s); "
                f"deepest is {top.get('dexId')} pair "
                f"{top.get('pairAddress')} "
                f"({(top.get('baseToken') or {}).get('symbol')}/"
                f"{(top.get('quoteToken') or {}).get('symbol')}) "
                f"with ${_liq(top):,.0f} liquidity and market cap "
                f"${float(top.get('marketCap') or 0):,.0f}.",
                source="DexScreener token pairs",
                source_url=f"https://dexscreener.com/solana/{address}",
                confidence=75, passive=True,
                evidence={"severity": "low", "address": address,
                          "chain": "solana", "pair_count": len(pairs),
                          "top_pair": top,
                          "remediation": "Thin liquidity means small "
                                         "sells move the price hard; "
                                         "check it again before "
                                         "sizing any position."}))
            dex_url = f"https://dexscreener.com/solana/{address}"
            for fd in analyze_dex_pairs(address, pairs):
                findings.append(self._to_finding(fd, dex_url))

    async def _enrich_owners(self, ctx: Ctx,
                             largest: List[Dict]) -> None:
        """Resolve the owner wallet of the top token accounts (in
        place, best-effort) so creator/dev holdings can be measured.
        Read-only getAccountInfo per account, capped."""
        ranked = sorted(
            (e for e in largest if isinstance(e, dict)),
            key=lambda e: int(e.get("amount") or 0)
            if str(e.get("amount") or "").isdigit() else 0,
            reverse=True)
        for entry in ranked[:ENRICH_OWNERS]:
            token_acct = entry.get("address")
            if not isinstance(token_acct, str) or not token_acct:
                continue
            try:
                result = await get_account_info(ctx, token_acct)
            except Exception:
                continue
            if not result or result.get("value") is None:
                continue
            acct = normalize_account(result["value"])
            if acct["parsed_type"] == "account":
                owner = acct["info"].get("owner")
                if isinstance(owner, str):
                    entry["owner"] = owner

    def _to_finding(self, fd: Dict[str, Any],
                    url: Optional[str]) -> Finding:
        return self._f(
            "web3", fd["key"], fd["value"],
            source="Solana JSON-RPC + public chain data",
            source_url=url, confidence=90, passive=True,
            evidence=fd["evidence"])
