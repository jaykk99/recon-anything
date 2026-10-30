"""Smart-contract chain access + code analysis helpers.

Backs the contract_recon plugin. Everything here is READ-ONLY public
chain data:

- verified source from keyless Blockscout instances and the keyless
  Sourcify repository (Etherscan only when a key is already configured,
  as an enhancement - never a requirement);
- deployed bytecode via public JSON-RPC ``eth_getCode``.

No transactions, no eth_call, no state-changing anything. Detection
only: static analysis of published source and deployed bytecode.

Chains are CONFIG, not code: adding an EVM chain is one CHAINS entry
(chain id, public RPCs, keyless Blockscout instance, explorer URL).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from ..ratelimit import fetch
from .cryptopack_util import keccak256

SOURCIFY_REPO = "https://repo.sourcify.dev/contracts"
ETH_V2_API = "https://api.etherscan.io/v2/api"

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
ZERO_ADDRESS = "0x" + "0" * 40


# ---------------------------------------------------------------------------
# Chain configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChainConfig:
    id: str                      # canonical id used in targets/findings
    name: str                    # display name
    chain_id: int                # EVM chain id (Sourcify / Etherscan v2)
    rpc_urls: Tuple[str, ...]    # public JSON-RPC endpoints (read-only)
    blockscout_api: Optional[str]  # keyless Blockscout API base or None
    explorer_address: str        # address page URL, {addr} placeholder
    native: str                  # native asset symbol


CHAINS: Dict[str, ChainConfig] = {
    "ethereum": ChainConfig(
        id="ethereum", name="Ethereum", chain_id=1,
        rpc_urls=("https://ethereum-rpc.publicnode.com",
                  "https://eth.llamarpc.com"),
        blockscout_api="https://eth.blockscout.com/api",
        explorer_address="https://etherscan.io/address/{addr}",
        native="ETH"),
    "bsc": ChainConfig(
        id="bsc", name="BNB Chain", chain_id=56,
        rpc_urls=("https://bsc-rpc.publicnode.com",
                  "https://bsc-dataseed.bnbchain.org"),
        blockscout_api="https://bsc.blockscout.com/api",
        explorer_address="https://bscscan.com/address/{addr}",
        native="BNB"),
    "polygon": ChainConfig(
        id="polygon", name="Polygon", chain_id=137,
        rpc_urls=("https://polygon-rpc.com",
                  "https://polygon-bor-rpc.publicnode.com"),
        blockscout_api="https://polygon.blockscout.com/api",
        explorer_address="https://polygonscan.com/address/{addr}",
        native="MATIC"),
    "arbitrum": ChainConfig(
        id="arbitrum", name="Arbitrum One", chain_id=42161,
        rpc_urls=("https://arb1.arbitrum.io/rpc",
                  "https://arbitrum-one-rpc.publicnode.com"),
        blockscout_api="https://arbitrum.blockscout.com/api",
        explorer_address="https://arbiscan.io/address/{addr}",
        native="ETH"),
}

# Target prefixes Jay can type: "bsc:0x...", "eth:0x...", ...
CHAIN_ALIASES = {
    "eth": "ethereum", "ethereum": "ethereum", "mainnet": "ethereum",
    "bsc": "bsc", "bnb": "bsc", "bnbchain": "bsc", "binance": "bsc",
    "polygon": "polygon", "matic": "polygon",
    "arbitrum": "arbitrum", "arb": "arbitrum",
}

# Order used when a bare address target does not name a chain: probe
# each chain's eth_getCode and recon the contract where code exists.
DEFAULT_CHAIN_ORDER = ("ethereum", "bsc", "polygon", "arbitrum")


def parse_target_address(raw: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse a scan target into (chain_id, address).

    Accepts a bare ``0x...`` address (chain None = probe all) or a
    ``<chain>:0x...`` prefix using CHAINS ids or CHAIN_ALIASES.
    Returns (None, None) when the target is not an EVM address.
    """
    s = (raw or "").strip()
    chain: Optional[str] = None
    if ":" in s:
        prefix, _, rest = s.partition(":")
        alias = CHAIN_ALIASES.get(prefix.strip().lower())
        if alias and ADDRESS_RE.match(rest.strip()):
            return alias, rest.strip()
    if ADDRESS_RE.match(s):
        return chain, s
    return None, None


def explorer_url(chain: ChainConfig, address: str) -> str:
    return chain.explorer_address.format(addr=address)


# ---------------------------------------------------------------------------
# Read-only chain access (all through the shared rate-limited fetch)
# ---------------------------------------------------------------------------

async def rpc_get_code(ctx: Any, chain: ChainConfig,
                       address: str) -> Optional[str]:
    """eth_getCode via public JSON-RPC. Read-only.

    Returns the deployed bytecode hex ("0x..." - "0x" itself when the
    address holds no code), or None when every RPC endpoint failed.
    """
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
               "params": [address, "latest"]}
    for rpc in chain.rpc_urls:
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", rpc,
                            json=payload, timeout=12, max_retries=0)
            if r.status_code != 200:
                continue
            d = r.json()
        except Exception:
            continue
        if isinstance(d, dict) and isinstance(d.get("result"), str):
            return d["result"]
    return None


def _unwrap_source(raw: str) -> str:
    """Explorer SourceCode fields sometimes wrap multi-file sources in
    a JSON object ({"sources": {path: {"content": ...}}}). Flatten to
    plain concatenated Solidity; return raw text otherwise."""
    s = (raw or "").strip()
    if s.startswith("{{") and s.endswith("}}"):
        s = s[1:-1]
    if s.startswith("{"):
        try:
            d = json.loads(s)
        except Exception:
            return raw
        sources = d.get("sources") if isinstance(d, dict) else None
        if isinstance(sources, dict):
            parts = []
            for path in sorted(sources):
                entry = sources[path]
                content = entry.get("content") if isinstance(entry, dict) \
                    else None
                if content:
                    parts.append(f"\n// ==== {path} ====\n{content}")
            if parts:
                return "\n".join(parts)
    return raw


async def _source_blockscout(ctx: Any, chain: ChainConfig,
                             address: str) -> Optional[Dict[str, Any]]:
    """Keyless verified source from a public Blockscout instance
    (Etherscan-compatible getsourcecode action, no API key)."""
    if not chain.blockscout_api:
        return None
    from urllib.parse import urlencode
    url = f"{chain.blockscout_api}?{urlencode({'module': 'contract', 'action': 'getsourcecode', 'address': address})}"
    try:
        r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=20,
                        max_retries=0)
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None
    res = d.get("result") if isinstance(d, dict) else None
    if not res or not isinstance(res, list):
        return None
    info = res[0] or {}
    src = _unwrap_source(info.get("SourceCode") or "")
    if len(src) < 60:
        return None
    impl = info.get("Implementation") or ""
    return {
        "source": src,
        "contract_name": info.get("ContractName") or "",
        "compiler": info.get("CompilerVersion") or "",
        "proxy": str(info.get("Proxy") or "") == "1",
        "implementation": impl if ADDRESS_RE.match(impl) else "",
        "origin": "Blockscout",
    }


async def _source_sourcify(ctx: Any, chain: ChainConfig,
                           address: str) -> Optional[Dict[str, Any]]:
    """Keyless verified source from the Sourcify repository."""
    for match in ("full_match", "partial_match"):
        meta_url = (f"{SOURCIFY_REPO}/{match}/{chain.chain_id}/"
                    f"{address}/metadata.json")
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", meta_url,
                            timeout=20, max_retries=0)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            meta = r.json()
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        sources = meta.get("sources") or {}
        sol_paths = [p for p in sources.keys()
                     if isinstance(p, str) and p.endswith(".sol")]
        if not sol_paths:
            continue
        parts: List[str] = []
        for sp in sol_paths[:12]:
            furl = (f"{SOURCIFY_REPO}/{match}/{chain.chain_id}/{address}"
                    f"/sources/{sp}")
            try:
                fr = await fetch(ctx.http, ctx.limiter, "GET", furl,
                                 timeout=20, max_retries=0)
            except Exception:
                continue
            if fr.status_code == 200 and fr.text:
                parts.append(f"\n// ==== {sp} ====\n{fr.text}")
        if not parts:
            continue
        name = ""
        targets = ((meta.get("settings") or {}).get("compilationTarget")
                   or {})
        if isinstance(targets, dict) and targets:
            name = str(next(iter(targets.values())) or "")
        return {
            "source": "\n".join(parts),
            "contract_name": name,
            "compiler": str((meta.get("compiler") or {}).get("version")
                            or ""),
            "proxy": False,
            "implementation": "",
            "origin": "Sourcify",
        }
    return None


async def _source_etherscan(ctx: Any, chain: ChainConfig, address: str,
                            key: str) -> Optional[Dict[str, Any]]:
    """Verified source via Etherscan v2 (multichain). Only used when a
    key is already configured; the keyless routes above run first."""
    from urllib.parse import urlencode
    url = f"{ETH_V2_API}?{urlencode({'chainid': chain.chain_id, 'module': 'contract', 'action': 'getsourcecode', 'address': address, 'apikey': key})}"
    try:
        r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=20,
                        max_retries=0)
        if r.status_code != 200:
            return None
        d = r.json()
    except Exception:
        return None
    res = d.get("result") if isinstance(d, dict) else None
    if not res or not isinstance(res, list):
        return None
    info = res[0] or {}
    src = _unwrap_source(info.get("SourceCode") or "")
    if len(src) < 60:
        return None
    impl = info.get("Implementation") or ""
    return {
        "source": src,
        "contract_name": info.get("ContractName") or "",
        "compiler": info.get("CompilerVersion") or "",
        "proxy": str(info.get("Proxy") or "") == "1",
        "implementation": impl if ADDRESS_RE.match(impl) else "",
        "origin": "Etherscan",
    }


async def fetch_verified_source(ctx: Any, chain: ChainConfig, address: str,
                                etherscan_key: Optional[str] = None
                                ) -> Optional[Dict[str, Any]]:
    """Verified source for a contract, keyless routes first.

    Returns {source, contract_name, compiler, proxy, implementation,
    origin} or None when no explorer has verified source.
    """
    for route in (_source_blockscout, _source_sourcify):
        try:
            got = await route(ctx, chain, address)
        except Exception:
            got = None
        if got:
            return got
    if etherscan_key:
        try:
            return await _source_etherscan(ctx, chain, address,
                                           etherscan_key)
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Verified-source analysis: pull the code out and show it
# ---------------------------------------------------------------------------

def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


_FUNC_START = re.compile(
    r"\b(function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|"
    r"(constructor)\s*\(|(fallback)\s*\(|(receive)\s*\()")


def extract_functions(src: str) -> List[Dict[str, str]]:
    """Extract functions with signature + full body text.

    Returns [{name, signature, text}] where text is the complete code
    of the function (signature through the closing brace), so findings
    can SHOW the code. Interface declarations (no body) are included
    with their declaration as text.
    """
    out: List[Dict[str, str]] = []
    for m in _FUNC_START.finditer(src):
        name = m.group(2) or m.group(3) or m.group(4) or m.group(5) or ""
        start = m.start()
        i = m.end()
        # walk to the body's opening brace or the ';' of a declaration
        while i < len(src) and src[i] not in "{;":
            i += 1
        if i >= len(src):
            continue
        signature = src[start:i].strip()
        if src[i] == ";":
            out.append({"name": name, "signature": signature,
                        "text": src[start:i + 1].strip()})
            continue
        depth = 0
        j = i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append({"name": name, "signature": signature,
                    "text": src[start:j + 1].strip()})
    return out


def _line_context(src: str, pos: int, before: int = 1,
                  after: int = 1) -> str:
    """The source lines around a character offset (for snippets)."""
    lines = src.splitlines()
    idx = src[:pos].count("\n")
    lo = max(0, idx - before)
    hi = min(len(lines), idx + after + 1)
    return "\n".join(lines[lo:hi]).strip()


_GATE_RE = re.compile(
    r"onlyOwner|onlyAdmin|onlyRole|onlyMinter|onlyPauser|authorized|"
    r"require\s*\(\s*msg\.sender\s*==")

# Privileged-function categories, checked in order; first match wins so
# a function yields one inventory finding (the most specific role).
_PRIV_RULES: List[Tuple[str, str, "re.Pattern[str]", str]] = [
    ("mint", "high",
     re.compile(r"mint", re.I),
     "can create new tokens"),
    ("withdraw_sweep", "high",
     re.compile(r"withdraw|sweep|drain|rescue|emergency|claimfunds|"
                r"collect", re.I),
     "can move funds out of the contract"),
    ("pause", "medium",
     re.compile(r"pause|unpause", re.I),
     "can pause or unpause the contract"),
    ("blacklist", "medium",
     re.compile(r"blacklist|black_list|blocklist|denylist|deny_list|"
                r"freez|banned", re.I),
     "can blacklist or freeze addresses"),
    ("owner_admin", "medium",
     re.compile(r"owner|admin|role|operator|controller|governance|"
                r"setfee|settax|setlimit|setwallet|setrouter", re.I),
     "is an owner/admin control"),
]

_SNIP_CAP = 1400


def _snip(text: str, cap: int = _SNIP_CAP) -> str:
    text = (text or "").strip()
    if len(text) <= cap:
        return text
    return text[:cap] + "\n// ... [truncated]"


# Secret-looking string patterns. Per Jay's order (2026-10-29) these
# are shown IN FULL in findings - never masked - so the owner sees
# exactly what is sitting in the published contract code.
_SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("ethereum_private_key",
     re.compile(r"(?<![0-9a-fA-F])0x[0-9a-fA-F]{64}(?![0-9a-fA-F])")),
    ("pem_private_key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("named_secret_assignment",
     re.compile(r"(?i)(private[_ ]?key|secret|mnemonic|seed[_ ]?phrase|"
                r"api[_ ]?key|password)\s*[:=]\s*[\"']([^\"']{8,})[\"']")),
]

_PLACEHOLDER_WORDS = ("example", "sample", "test", "placeholder",
                      "changeme", "your", "xxxx", "todo")

# 32-byte constants that are structural, not secrets: the EIP-1967
# storage slots (implementation / admin / beacon) appear in every
# proxy and must not be reported as private keys.
_KNOWN_CONSTANTS = {
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
}


def find_secret_strings(src: str) -> List[Dict[str, str]]:
    """Secret-looking strings in contract source, values IN FULL."""
    out: List[Dict[str, str]] = []
    seen = set()
    for kind, pat in _SECRET_PATTERNS:
        for m in pat.finditer(src):
            value = m.group(2) if (kind == "named_secret_assignment"
                                   and m.lastindex and m.lastindex >= 2) \
                else m.group(0)
            value = (value or "").strip()
            if not value or value.lower() == "0x" + "0" * 64:
                continue
            if value.lower() in _KNOWN_CONSTANTS:
                continue
            if any(w in value.lower() for w in _PLACEHOLDER_WORDS):
                continue
            if value in seen:
                continue
            seen.add(value)
            out.append({"kind": kind, "value": value,
                        "code": _line_context(src, m.start(), 1, 1)})
    return out


_PROXY_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("ERC1967 proxy", re.compile(
        r"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505"
        r"d382bbc|ERC1967Proxy|ERC1967Upgrade")),
    ("Transparent upgradeable proxy", re.compile(
        r"TransparentUpgradeableProxy")),
    ("UUPS proxy", re.compile(r"UUPSUpgradeable|proxiableUUID")),
    ("Beacon proxy", re.compile(r"BeaconProxy|UpgradeableBeacon")),
    ("Diamond (EIP-2535)", re.compile(r"diamondCut|IDiamondCut|"
                                      r"LibDiamond")),
    ("Minimal proxy factory (EIP-1167 clones)", re.compile(
        r"Clones\.clone|createClone|cloneDeterministic")),
]


def analyze_contract_source(src: str,
                            meta: Optional[Dict[str, Any]] = None
                            ) -> List[Dict[str, Any]]:
    """Static code inventory over verified Solidity source.

    Returns finding dicts {kind, severity, title, function, code,
    detail}. Every dict carries the actual code (function body or line
    context) so the finding SHOWS the code, per Jay's order. Detection
    only - nothing here interacts with the contract.
    """
    meta = meta or {}
    findings: List[Dict[str, Any]] = []
    clean = _strip_comments(src)
    funcs = extract_functions(clean)

    # --- identity: name, compiler, pragma, declaration code ----------
    pragma_m = re.search(r"pragma\s+solidity\s*[^;]+;", clean)
    decl_m = re.search(
        r"\b(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)"
        r"[^{;]*\{", clean)
    name = meta.get("contract_name") or (decl_m.group(2) if decl_m
                                         else "")
    compiler = meta.get("compiler") or ""
    decl_code = ""
    if decl_m:
        decl_code = clean[decl_m.start():decl_m.end()].strip()
    if pragma_m:
        decl_code = (pragma_m.group(0) + "\n" + decl_code).strip()
    findings.append({
        "kind": "identity", "severity": "low", "function": "",
        "title": (f"Contract code: {name or 'unknown name'} "
                  f"(compiler {compiler or 'unknown'}, "
                  f"{len(src)} bytes of verified source)"),
        "code": _snip(decl_code),
        "detail": (f"contract_name={name or 'unknown'}; "
                   f"compiler={compiler or 'unknown'}; "
                   f"functions={len(funcs)}"),
        "contract_name": name, "compiler": compiler,
        "function_count": len(funcs),
    })

    # --- proxy / implementation pattern ------------------------------
    for label, pat in _PROXY_PATTERNS:
        pm = pat.search(clean)
        if not pm:
            continue
        impl = meta.get("implementation") or ""
        if not impl:
            im = re.search(
                r"implementation\w*\s*=\s*(0x[0-9a-fA-F]{40})", clean, re.I)
            if im:
                impl = im.group(1)
        findings.append({
            "kind": "proxy", "severity": "medium", "function": "",
            "title": (f"Proxy pattern: {label}"
                      + (f"; implementation {impl}" if impl else "")),
            "code": _snip(_line_context(clean, pm.start(), 2, 2)),
            "detail": ("Upgradeable/proxy structure: the code at this "
                       "address can be swapped by whoever controls the "
                       "proxy admin."
                       + (f" Implementation: {impl}." if impl else "")),
            "implementation": impl, "pattern": label,
        })
        break  # one proxy finding per contract

    # --- privileged functions (owner/admin, mint, withdraw, ...) -----
    for fn in funcs:
        name_l = fn["name"]
        if not name_l or name_l in ("constructor",):
            continue
        sig = fn["signature"]
        body = fn["text"]
        gated = bool(_GATE_RE.search(sig) or _GATE_RE.search(body))
        category = None
        sev = "medium"
        effect = ""
        for cat, s2, pat, eff in _PRIV_RULES:
            if pat.search(name_l):
                category, sev, effect = cat, s2, eff
                break
        if category is None and gated and re.search(
                r"\b(public|external)\b", sig):
            category, sev, effect = ("owner_admin", "medium",
                                     "is access-controlled (gated)")
        if category is None:
            continue
        findings.append({
            "kind": "privileged_function", "severity": sev,
            "function": name_l,
            "title": (f"Privileged function '{name_l}' {effect}"
                      + (" (access-gated)" if gated else
                         " (NO access gate found)")),
            "code": _snip(body),
            "detail": (f"category={category}; gated={gated}; "
                       f"signature: {sig[:200]}"),
            "priv_category": category, "gated": gated,
        })

    # --- powerful code patterns, with the enclosing function ---------
    def _enclosing(pos: int) -> Dict[str, str]:
        # find the function whose text spans this offset in `clean`;
        # positions are recomputed against function texts.
        for fn in funcs:
            idx = clean.find(fn["text"][:80])
            if idx >= 0 and idx <= pos <= idx + len(fn["text"]):
                return fn
        return {"name": "", "text": _line_context(clean, pos, 3, 3)}

    for dm in re.finditer(r"\.delegatecall\s*\(", clean):
        fn = _enclosing(dm.start())
        findings.append({
            "kind": "delegatecall", "severity": "high",
            "function": fn["name"],
            "title": ("delegatecall in "
                      + (f"function '{fn['name']}'" if fn["name"]
                         else "contract code")
                      + ": executes other code in this contract's "
                        "storage context"),
            "code": _snip(fn["text"]),
            "detail": "delegatecall runs foreign code with this "
                      "contract's storage and balance.",
        })
        break  # one finding; the snippet shows the function

    for sm in re.finditer(r"\bselfdestruct\s*\(|\bsuicide\s*\(", clean):
        fn = _enclosing(sm.start())
        findings.append({
            "kind": "selfdestruct", "severity": "high",
            "function": fn["name"],
            "title": ("selfdestruct in "
                      + (f"function '{fn['name']}'" if fn["name"]
                         else "contract code")
                      + ": can destroy the contract and force-send "
                        "its balance"),
            "code": _snip(fn["text"]),
            "detail": "selfdestruct permanently removes the code and "
                      "sends the balance to an arbitrary address.",
        })
        break

    for tm in re.finditer(r"tx\.origin", clean):
        findings.append({
            "kind": "tx_origin", "severity": "high", "function": "",
            "title": "tx.origin used in contract code (phishing-prone "
                     "authorization primitive)",
            "code": _snip(_line_context(clean, tm.start(), 2, 2)),
            "detail": "tx.origin is the externally-owned account that "
                      "started the transaction chain; using it for auth "
                      "lets phishing contracts impersonate the user.",
        })
        break

    # --- unchecked external calls ------------------------------------
    for um in re.finditer(r"\.(call|send)\s*[( {]", clean):
        before = clean[max(0, um.start() - 120):um.start()]
        after = clean[um.end():um.end() + 120]
        handled = bool(re.search(r"(bool|require|assert|if|success)",
                                 before[-60:] + after[:60]))
        if handled:
            continue
        fn = _enclosing(um.start())
        findings.append({
            "kind": "unchecked_call", "severity": "medium",
            "function": fn["name"],
            "title": (f"Unchecked low-level .{um.group(1)}() "
                      + (f"in function '{fn['name']}'" if fn["name"]
                         else "in contract code")
                      + ": return value not checked nearby"),
            "code": _snip(fn["text"]),
            "detail": "A failed external call would go unnoticed; "
                      "state may update as if the transfer succeeded.",
        })
        break

    # --- Ethernaut "Fallback"-pattern ownership takeover ------------
    # Detection models the public Ethernaut-style walkthrough pattern
    # (reel reference in the PR description): a plain ETH transfer or
    # a small deposit flips ownership, then a full-balance withdraw
    # drains the contract. DETECTION ONLY - the findings show the
    # vulnerable code and explain the path in words; nothing here
    # performs any step of it.
    fb_funcs = [fn for fn in funcs
                if fn["name"] in ("receive", "fallback")]
    _owner_assign = re.compile(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?:payable\s*\(\s*)?msg\.sender\s*\)?\s*;")
    _state_write = re.compile(
        r"\b[A-Za-z_][A-Za-z0-9_]*(\s*\[[^\]]*\])?\s*(\+=|=(?![=>]))")

    # 1. receive()/fallback() that hands ownership to the sender.
    d1_funcs: List[Dict[str, str]] = []
    for fn in fb_funcs:
        if _owner_assign.search(fn["text"]):
            d1_funcs.append(fn)
            findings.append({
                "kind": "ownership_takeover_fallback",
                "severity": "high", "function": fn["name"],
                "title": (f"Ownership takeover via {fn['name']}(): "
                          "a plain ETH transfer to this contract "
                          "makes the sender the owner"),
                "code": _snip(fn["text"]),
                "detail": (f"{fn['name']}() assigns msg.sender to the "
                           "owner variable. Anyone who sends ETH to "
                           "the contract address becomes its owner - "
                           "no credentials, no exploit code, just a "
                           "transfer."),
            })

    # 2. Deposit-to-own: per-sender deposits tracked in a mapping AND
    #    an ownership comparison against that same mapping.
    d2_pieces: List[Dict[str, str]] = []
    for fn in funcs:
        tm = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*msg\.sender"
                       r"\s*\]\s*\+=", fn["text"])
        if not tm:
            continue
        mapping = tm.group(1)
        cm = re.search(
            r"\b" + re.escape(mapping) +
            r"\s*\[\s*msg\.sender\s*\]\s*>\s*" +
            re.escape(mapping) + r"\s*\[", clean)
        if not cm:
            continue
        enc = _enclosing(cm.start())
        if not _owner_assign.search(enc["text"]):
            continue
        d2_pieces = [fn, enc] if enc["name"] != fn["name"] else [fn]
        findings.append({
            "kind": "deposit_to_own", "severity": "high",
            "function": fn["name"],
            "title": (f"Deposit-to-own setup in '{fn['name']}': "
                      f"deposits are tracked per sender in "
                      f"'{mapping}' and out-depositing the owner "
                      f"transfers ownership"),
            "code": _snip("\n\n".join(p["text"] for p in d2_pieces),
                          2200),
            "detail": (f"'{fn['name']}' records each sender's total "
                       f"in {mapping}[msg.sender], and the ownership "
                       f"logic compares {mapping}[msg.sender] > "
                       f"{mapping}[owner]. A deposit larger than the "
                       "owner's recorded contribution seizes "
                       "ownership."),
            "mapping": mapping,
        })
        break

    # 3. Full-balance withdraw guarded only by the owner check.
    d3_funcs: List[Dict[str, str]] = []
    for fn in funcs:
        if not re.search(r"withdraw|drain", fn["name"], re.I):
            continue
        if "address(this).balance" not in fn["text"]:
            continue
        if not re.search(r"\.(transfer|send|call)\b", fn["text"]):
            continue
        gated = bool(_GATE_RE.search(fn["signature"]) or
                     _GATE_RE.search(fn["text"]))
        d3_funcs.append(fn)
        findings.append({
            "kind": "full_balance_withdraw", "severity": "medium",
            "function": fn["name"],
            "title": (f"Full-balance withdraw in '{fn['name']}': "
                      "sends the contract's ENTIRE balance, guarded "
                      + ("only by the owner check" if gated
                         else "by no access check at all")),
            "code": _snip(fn["text"]),
            "detail": ("The only thing between an attacker and the "
                       "full balance is the owner variable - whoever "
                       "controls 'owner' at call time takes "
                       "everything."),
            "gated": gated,
        })

    # 1 or 2 + 3 in one contract = a complete takeover path. Highest
    # severity tier (high) as ONE combined finding showing all the
    # code pieces together.
    if (d1_funcs or d2_pieces) and d3_funcs:
        steps: List[str] = []
        seen_names = set()
        for fn in d2_pieces + d1_funcs + d3_funcs:
            if fn["name"] in seen_names:
                continue
            seen_names.add(fn["name"])
            steps.append(f"// ---- {fn['name']}() ----\n{fn['text']}")
        findings.append({
            "kind": "ownership_takeover_path", "severity": "high",
            "function": "",
            "title": ("COMPLETE OWNERSHIP TAKEOVER PATH: acquire "
                      "ownership via "
                      + ("receive()/fallback() transfer"
                         if d1_funcs else "deposit comparison")
                      + f", then drain the full balance via "
                        f"'{d3_funcs[0]['name']}'"),
            "code": _snip("\n\n".join(steps), 2800),
            "detail": ("All three pieces are present in one "
                       "contract: (1) ownership can be acquired by "
                       "an arbitrary sender, (2) the owner gate is "
                       "therefore no protection, (3) the owner's "
                       "withdraw sends the entire balance. Anyone "
                       "can walk this path with ordinary transfers "
                       "and calls."),
        })

    # 4. Payable receive()/fallback() that writes state at all.
    for fn in fb_funcs:
        if fn in d1_funcs:
            continue  # already reported as the takeover finding
        if "payable" not in fn["text"]:
            continue
        body = fn["text"][fn["text"].find("{"):]
        if _state_write.search(body):
            findings.append({
                "kind": "fallback_state_write", "severity": "medium",
                "function": fn["name"],
                "title": (f"Payable {fn['name']}() writes state: "
                          "a bare ETH transfer changes contract "
                          "state"),
                "code": _snip(fn["text"]),
                "detail": ("receive()/fallback() runs on every "
                           "plain transfer, including accidental "
                           "ones. State changes there are easy to "
                           "trigger unintentionally and hard to "
                           "audit."),
            })

    # --- hardcoded addresses -----------------------------------------
    addrs: List[str] = []
    for am in re.finditer(r"0x[0-9a-fA-F]{40}", src):
        a = am.group(0)
        if a.lower() != ZERO_ADDRESS and a not in addrs:
            addrs.append(a)
    if addrs:
        samples = []
        for a in addrs[:5]:
            pos = src.find(a)
            samples.append(_line_context(src, pos, 0, 0))
        findings.append({
            "kind": "hardcoded_address", "severity": "low",
            "function": "",
            "title": (f"{len(addrs)} hardcoded address(es) in the "
                      f"code: {', '.join(addrs[:5])}"
                      + (" ..." if len(addrs) > 5 else "")),
            "code": _snip("\n".join(samples)),
            "detail": "Hardcoded addresses are fixed trust anchors: "
                      "whoever controls them matters.",
            "addresses": addrs[:20],
        })

    # --- embedded URLs / IPs (raw source, comments included) ---------
    urls = sorted(set(re.findall(r"https?://[^\s\"'\)\]]+", src)))
    ips = sorted(set(re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b", src)))
    ips = [ip for ip in ips
           if all(int(p) <= 255 for p in ip.split(":")[0].split("."))]
    if urls or ips:
        samples = []
        for u in (urls + ips)[:5]:
            pos = src.find(u)
            if pos >= 0:
                samples.append(_line_context(src, pos, 0, 0))
        findings.append({
            "kind": "embedded_endpoint", "severity": "low",
            "function": "",
            "title": (f"Embedded endpoints in code: "
                      f"{len(urls)} URL(s), {len(ips)} IP(s)"
                      + (f": {', '.join((urls + ips)[:4])}"
                         if (urls or ips) else "")),
            "code": _snip("\n".join(samples)),
            "detail": "Off-chain endpoints baked into on-chain code.",
            "urls": urls[:10], "ips": ips[:10],
        })

    # --- secret-looking strings (FULL value, per Jay's order) --------
    for sec in find_secret_strings(src):
        findings.append({
            "kind": "secret_string", "severity": "high",
            "function": "",
            "title": (f"Secret-looking string in published contract "
                      f"code ({sec['kind']}): {sec['value']}"),
            "code": _snip(sec["code"]),
            "detail": ("Shown in full per Jay's order. Anything in "
                       "verified source is public to the whole chain; "
                       "if this is a live key, rotate it and sweep "
                       "funds to a fresh wallet."),
            "secret_kind": sec["kind"], "secret_value": sec["value"],
        })

    return findings


# ---------------------------------------------------------------------------
# Bytecode analysis (no verified source needed)
# ---------------------------------------------------------------------------

_KNOWN_SIGNATURES = [
    # ERC20
    "transfer(address,uint256)", "transferFrom(address,address,uint256)",
    "approve(address,uint256)", "balanceOf(address)",
    "allowance(address,address)", "totalSupply()", "name()",
    "symbol()", "decimals()", "increaseAllowance(address,uint256)",
    "decreaseAllowance(address,uint256)",
    # ERC721 / ERC1155
    "ownerOf(uint256)", "safeTransferFrom(address,address,uint256)",
    "safeTransferFrom(address,address,uint256,uint256,bytes)",
    "setApprovalForAll(address,bool)", "getApproved(uint256)",
    "isApprovedForAll(address,address)", "balanceOf(address,uint256)",
    # Ownable / AccessControl / Pausable
    "owner()", "transferOwnership(address)", "renounceOwnership()",
    "hasRole(bytes32,address)", "grantRole(bytes32,address)",
    "revokeRole(bytes32,address)", "getRoleAdmin(bytes32)",
    "DEFAULT_ADMIN_ROLE()", "pause()", "unpause()", "paused()",
    # Token admin / money movement
    "mint(address,uint256)", "mint(address)", "mint(uint256)",
    "burn(uint256)", "burnFrom(address,uint256)", "withdraw()",
    "withdraw(uint256)", "withdrawAll()", "deposit()",
    "sweep(address)", "blacklist(address)", "setPaused(bool)",
    "claim()", "rescueTokens(address,uint256)", "setOwner(address)",
    "getOwner()",
    # Proxy / upgradeable
    "upgradeTo(address)", "upgradeToAndCall(address,bytes)",
    "implementation()", "proxiableUUID()", "admin()",
    "changeAdmin(address)", "initialize()", "initialize(address)",
]

SELECTOR_TABLE: Dict[str, str] = {
    keccak256(sig.encode())[:4].hex(): sig for sig in _KNOWN_SIGNATURES
}

_SENSITIVE_OPCODES = {
    0xF1: "CALL", 0xF2: "CALLCODE", 0xF4: "DELEGATECALL",
    0xF5: "CREATE2", 0xFF: "SELFDESTRUCT",
}

# EIP-1167 minimal proxy runtime:
# 363d3d373d3d3d363d73 <20-byte impl> 5af43d82803e903d91602b57fd5bf3
_MINIMAL_PROXY_RE = re.compile(
    r"^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$")


def analyze_bytecode(code_hex: str) -> Dict[str, Any]:
    """Static analysis of deployed runtime bytecode.

    Returns size, SHA-256 hash, known function selectors (PUSH4
    immediates matched against SELECTOR_TABLE), sensitive opcode
    presence, EIP-1167 minimal-proxy detection, and the Solidity
    metadata (IPFS/swarm hash, compiler version) from the CBOR tail.
    """
    h = (code_hex or "").strip().lower()
    if h.startswith("0x"):
        h = h[2:]
    try:
        code = bytes.fromhex(h) if h else b""
    except ValueError:
        code = b""
    out: Dict[str, Any] = {
        "size": len(code),
        "sha256": hashlib.sha256(code).hexdigest() if code else "",
        "selectors": [],
        "opcodes": {},
        "metadata": {"ipfs": None, "swarm": None, "solc": None},
        "minimal_proxy_impl": None,
    }
    if not code:
        return out

    m = _MINIMAL_PROXY_RE.match(h)
    if m:
        out["minimal_proxy_impl"] = "0x" + m.group(1)

    # Linear disassembly walk: PUSHn immediates are data, not opcodes.
    selectors: Dict[str, Optional[str]] = {}
    opcodes: Dict[str, int] = {}
    i = 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            n = op - 0x5F
            data = code[i + 1:i + 1 + n]
            if op == 0x63 and len(data) == 4:  # PUSH4: selector
                sel = data.hex()
                if sel not in selectors:
                    selectors[sel] = SELECTOR_TABLE.get(sel)
            i += 1 + n
            continue
        if op in _SENSITIVE_OPCODES:
            name = _SENSITIVE_OPCODES[op]
            opcodes[name] = opcodes.get(name, 0) + 1
        i += 1
    out["selectors"] = [
        {"selector": "0x" + sel, "signature": sig}
        for sel, sig in sorted(selectors.items())]
    out["opcodes"] = opcodes

    # CBOR metadata tail: last 2 bytes = big-endian length of the
    # CBOR map that precedes them.
    if len(code) > 4:
        cbor_len = int.from_bytes(code[-2:], "big")
        if 0 < cbor_len <= len(code) - 2:
            cbor = code[len(code) - 2 - cbor_len:len(code) - 2]
            idx = cbor.find(b"ipfs")
            if idx >= 0:
                seg = cbor[idx + 4:idx + 4 + 2 + 34]
                if len(seg) == 36 and seg[0] == 0x58 and seg[1] == 0x22:
                    out["metadata"]["ipfs"] = seg[2:].hex()
            idx = cbor.find(b"bzzr1")
            if idx >= 0:
                seg = cbor[idx + 5:idx + 5 + 2 + 32]
                if len(seg) == 34 and seg[0] == 0x58 and seg[1] == 0x20:
                    out["metadata"]["swarm"] = seg[2:].hex()
            idx = cbor.find(b"solc")
            if idx >= 0:
                seg = cbor[idx + 4:idx + 4 + 1 + 3]
                if len(seg) == 4 and seg[0] == 0x43:
                    out["metadata"]["solc"] = ".".join(
                        str(b) for b in seg[1:])
    return out
