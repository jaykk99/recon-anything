"""Crypto pack gap-fillers: coins, contracts, and wallets, detection only.

Audit (2026-10-27, registry 616 plugins, 211 cp_*): the existing pack
already covers validated per-chain wallet addresses, ENS/lightning/payment
URIs, miners, drainer/clipboard patterns, leaked secrets/keystores, Web3
infra inventory (known RPC hosts, chain IDs, token/NFT contracts in
context, known DEX routers, bridges, Solana programs, oracles, Safe
refs, hardhat artifacts, WalletConnect IDs, SIWE), canonical contracts
(WETH, USDT, USDC, DAI, Permit2, Seaport, ENS registry), and the
verified-source auditors (contract_audit, defi_risk, smartcontract)
already cover reentrancy, tx.origin, delegatecall, selfdestruct, proxy
patterns, pause, mint, fees and oracles on verified source fetched
through chain APIs.

What was NOT covered, and what this file adds, all from the target's
own public homepage + same-domain JS (the PackPlugin surface, one
cached fetch shared by the whole pack):

1. cp_web3_token_abi -- token ABI/metadata served to the browser:
   symbol/decimals pairs and privileged ABI function names (mint, burn,
   pause, blacklist, ...). token_contracts only reports the address;
   this reports what the token's interface says it can do.
2. cp_web3_wallet_roles -- role-attributed wallet addresses:
   owner=/treasury=/feeRecipient=/devWallet=/vault= 0x... in served
   text. Address plugins report bare addresses with no role; this
   reports who the address is for.
3. cp_web3_rpc_misconfig -- RPC misconfiguration in served text:
   non-TLS (http) RPC URLs, RPC URLs on known RPC ports, and
   localhost/127.0.0.1 RPC endpoints shipped in client code. Known
   provider hosts are already inventoried by cp_web3_rpc_endpoints;
   this flags the insecure/local shape, not the provider. It never
   probes the RPC endpoint.
4. cp_web3_rpc_method_refs -- dangerous JSON-RPC method names
   referenced in public JS (eth_sendTransaction, personal_unlockAccount,
   eth_sign). A reference, not a call: nothing here sends a request
   to any RPC endpoint.
5. cp_web3_proxy_slots -- EIP-1967 proxy slot constants and proxy
   admin contract names in served artifacts. defi_risk only flags
   proxy patterns on verified source; this flags the slot constants
   in the browser-served artifact itself. Slot values are computed
   from keccak("eip1967.proxy.<name>") - 1, not copied from memory.

Deliberately NOT built here:
- Credential-bearing RPC URLs (http://user:pass@host) are left out:
  PackPlugin redaction is per-class, and a credential URL needs
  value-level redaction. cp_secret_* / cp_node_rpc_creds already cover
  RPC credentials. The http patterns below refuse to match any URL
  containing userinfo (negative lookahead for '@' before the path).
- Live chain reads (balances, holders, on-chain admin) are left to
  chain_osint / contract_audit, which already do them read-only.
  Nothing here signs, sends, sweeps, derives keys, or touches a wallet.
- Full private keys / seed phrases are never output: no pattern here
  matches a secret shape, and the secret plugins redact theirs.
"""
from __future__ import annotations

import re
import time
from typing import List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from .cryptopack_util import PackPlugin, collect_texts

# EIP-1967 slots, computed as keccak(label) - 1 (see module docstring).
# implementation: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
# admin:          0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
# beacon:         0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
_EIP1967_IMPL = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
_EIP1967_ADMIN = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
_EIP1967_BEACON = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

_ADDR = r"(0x[0-9a-fA-F]{40})"


class CpWeb3TokenAbi(Plugin):
    """Token ABI/metadata served to the browser (symbol, decimals, privileged fns)."""

    id = "cp_web3_token_abi"
    label = "Token ABI metadata"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Token symbol/decimals pairs and privileged ABI function "
                   "names (mint, burn, pause, blacklist) served in the "
                   "target's pages/JS. Detection only; no chain calls.")
    timeout_s = 45

    _PRIVILEGED = ("mint", "burn", "pause", "unpause", "blacklist",
                   "setFee", "setTreasury", "grantRole", "renounceOwnership")
    _FN_RE = re.compile(r'"name"\s*:\s*"(' + "|".join(_PRIVILEGED) + r')"')
    _SYMBOL_RE = re.compile(r'"symbol"\s*:\s*"([A-Z0-9]{2,10})"')
    _DECIMALS_RE = re.compile(r'"decimals"\s*:\s*(\d{1,2})')

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        findings: List = []
        seen = set()
        for where, text, url in texts:
            abi_context = ('"abi"' in text
                           or '"type": "function"' in text
                           or '"type":"function"' in text)
            for m in self._SYMBOL_RE.finditer(text):
                window = text[m.start():m.start() + 300]
                dm = self._DECIMALS_RE.search(window)
                if not dm:
                    window2 = text[max(0, m.start() - 300):m.start()]
                    dm = self._DECIMALS_RE.search(window2)
                if not dm:
                    continue
                value = f"{m.group(1)} (decimals {dm.group(1)})"
                if ("token_abi_metadata", value) in seen:
                    continue
                seen.add(("token_abi_metadata", value))
                findings.append(self._f(
                    "crypto", "token_abi_metadata",
                    f"Token metadata: {value}", source=self.label,
                    source_url=url, confidence=75,
                    evidence={"detector": self.id, "where": where,
                              "abi_context": abi_context}))
            if abi_context:
                for m in self._FN_RE.finditer(text):
                    fn = m.group(1)
                    if ("token_abi_privileged_fn", fn) in seen:
                        continue
                    seen.add(("token_abi_privileged_fn", fn))
                    findings.append(self._f(
                        "crypto", "token_abi_privileged_fn",
                        f"Privileged ABI function: {fn}", source=self.label,
                        source_url=url, confidence=70,
                        evidence={"detector": self.id, "where": where,
                                  "function": fn}))
            if len(findings) >= 25:
                break
        res = self._ok(findings, f"{len(findings)} {self.label} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


class CpWeb3WalletRoles(PackPlugin):
    """Wallet addresses with a role label in served text/config."""

    id = "cp_web3_wallet_roles"
    label = "Wallet role addresses"
    description = ("Role-attributed wallet addresses in the target's "
                   "pages/JS: owner, treasury, fee recipient, dev wallet, "
                   "vault, admin. Public identifiers only, never secrets.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"\bowner\s*[:=]\s*[\"']?" + _ADDR + r"\b",
         "wallet_role_owner", "Owner wallet address", 75, None),
        (r"\btreasury\s*[:=]\s*[\"']?" + _ADDR + r"\b",
         "wallet_role_treasury", "Treasury wallet address", 75, None),
        (r"\bfeeRecipient\s*[:=]\s*[\"']?" + _ADDR + r"\b",
         "wallet_role_fee_recipient", "Fee recipient wallet address", 75, None),
        (r"\bdevWallet\s*[:=]\s*[\"']?" + _ADDR + r"\b",
         "wallet_role_dev", "Dev wallet address", 75, None),
        (r"\bvault\s*[:=]\s*[\"']?" + _ADDR + r"\b",
         "wallet_role_vault", "Vault wallet address", 70, None),
        (r"\badmin(?:Wallet)?\s*[:=]\s*[\"']?" + _ADDR + r"\b",
         "wallet_role_admin", "Admin wallet address", 70, None),
        (r"\bbeneficiary\s*[:=]\s*[\"']?" + _ADDR + r"\b",
         "wallet_role_beneficiary", "Beneficiary wallet address", 70, None),
    ]


class CpWeb3RpcMisconfig(PackPlugin):
    """Insecure/local RPC endpoint shapes in served text. Never probed."""

    id = "cp_web3_rpc_misconfig"
    label = "RPC endpoint misconfiguration"
    description = ("Non-TLS http RPC URLs, RPC URLs on known RPC ports, "
                   "and localhost/loopback RPC endpoints shipped in "
                   "client code. Detected from text only; the endpoint "
                   "is never contacted. URLs with credentials are "
                   "deliberately not matched (see module docstring).")
    PATTERNS = [
        # http RPC host (host contains "rpc", or path is an rpc path):
        # the (?!...@) guard refuses any URL carrying userinfo.
        (r"http://(?![^/\s\"'<>]*@)[a-z0-9.\-]*rpc[a-z0-9.\-]*"
         r"(?::\d{2,5})?(?:/[^\s\"'<>]*)?",
         "rpc_http_endpoint", "Non-TLS RPC endpoint (http)", 75, None),
        # http URL on a known RPC port, any host.
        (r"http://(?![^/\s\"'<>]*@)[a-z0-9.\-]+:(?:8545|8546|8547|30303)"
         r"(?:/[^\s\"'<>]*)?",
         "rpc_http_port_endpoint", "RPC port over plain http", 70, None),
        # localhost / loopback RPC endpoint shipped in client code.
        (r"https?://(?:localhost|127\.0\.0\.1)(?::\d{2,5})?"
         r"(?:/[^\s\"'<>]*)?",
         "rpc_localhost_endpoint", "Localhost RPC endpoint in client code",
         70, None),
        (r"\b(?:localhost|127\.0\.0\.1):(?:8545|8546)\b",
         "rpc_localhost_endpoint", "Localhost RPC endpoint in client code",
         70, None),
    ]


class CpWeb3RpcMethodRefs(PackPlugin):
    """Dangerous JSON-RPC method names referenced in public JS."""

    id = "cp_web3_rpc_method_refs"
    label = "Dangerous RPC method references"
    description = ("JSON-RPC method names referenced in the target's "
                   "public JS that must never be exposed to a browser "
                   "(eth_sendTransaction, personal_unlockAccount, "
                   "eth_sign). A reference only: no RPC call is made.")
    PATTERNS = [
        (r"\beth_sendTransaction\b", "rpc_dangerous_method_ref",
         "Dangerous RPC method reference: eth_sendTransaction", 75, None),
        (r"\bpersonal_unlockAccount\b", "rpc_dangerous_method_ref",
         "Dangerous RPC method reference: personal_unlockAccount", 80, None),
        (r"\beth_sign\b", "rpc_dangerous_method_ref",
         "Dangerous RPC method reference: eth_sign", 70, None),
    ]


class CpWeb3ProxySlots(PackPlugin):
    """EIP-1967 proxy slot constants and proxy admin names in artifacts."""

    id = "cp_web3_proxy_slots"
    label = "EIP-1967 proxy slots"
    description = ("EIP-1967 implementation/admin/beacon slot constants "
                   "and proxy admin contract names in browser-served "
                   "artifacts. Slot values are keccak(label)-1, computed, "
                   "not recalled. Detection only.")
    PATTERNS = [
        (r"0x" + _EIP1967_IMPL, "proxy_eip1967_implementation_slot",
         "EIP-1967 implementation slot", 80, None),
        (r"0x" + _EIP1967_ADMIN, "proxy_eip1967_admin_slot",
         "EIP-1967 admin slot", 80, None),
        (r"0x" + _EIP1967_BEACON, "proxy_eip1967_beacon_slot",
         "EIP-1967 beacon slot", 80, None),
        (r"\b(?:ProxyAdmin|TransparentUpgradeableProxy|BeaconProxy)\b",
         "proxy_admin_ref", "Proxy admin contract reference", 70, None),
    ]
