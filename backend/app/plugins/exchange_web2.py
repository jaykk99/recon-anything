"""Exchange-web detectors, block 2: wallet infrastructure exposure
in web assets.

Ten detectors for wallet/custody configuration an exchange site
ships to browsers: hot-wallet roles, custody-provider secrets,
client-side deposit-address generation, key material handling in
frontend code. Detection only, masked evidence (see
_exchange_common).
"""
from __future__ import annotations

from ._exchange_common import ExchSpec, S, analyze, register

FAMILY = "exchange_web2"

SPECS = [
    S("exch_hot_wallet_role_disclosure", "Hot Wallet Address and Role Disclosed in Frontend Config",
      "medium",
      "Frontend config names a hot wallet address together with its hot-wallet role, handing attackers the exact address to watch and target for the exchange's operational funds.",
      "Keep wallet role/address mapping server-side; the frontend needs deposit addresses for the signed-in user only, never the treasury wallet map.",
      patterns=[r"(?:hotWallet|hot_wallet)\s*[:=]\s*\{[^}]{0,200}?(?:address\s*[:=]\s*['\"]0x[0-9a-fA-F]{40}['\"]|role\s*[:=]\s*['\"]hot)",
                r"['\"]hotWalletAddress['\"]\s*[:=]\s*['\"]0x[0-9a-fA-F]{40}['\"]"],
      category="web3"),
    S("exch_custody_provider_secret_client", "Custody Provider API Secret in Client Code",
      "high",
      "A custody provider (Fireblocks/BitGo/Copper-style) API secret or access token is assigned in client code, exposing the credential that guards the exchange's custody integration.",
      "Rotate the custody credential, move the integration fully server-side, and scope provider keys to the server IPs that use them.",
      patterns=[r"(?:fireblocks|bitgo|copper|custody)[A-Za-z]*[_-]?(?:api[_-]?secret|secret|access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"(?:FIREBLOCKS|BITGO|COPPER)_[A-Z_]*SECRET\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
    S("exch_deposit_address_gen_client", "Deposit Address Generation From xpub in Client Code",
      "medium",
      "An extended public key (xpub/ypub/zpub literal) is embedded in client code that derives deposit addresses in the browser, disclosing the whole deposit-address tree and letting anyone enumerate every deposit address the exchange will ever issue from it.",
      "Derive deposit addresses server-side from an xpub the browser never sees; the frontend should receive only the signed-in user's own address.",
      patterns=[r"['\"](?:xpub|ypub|zpub)[1-9A-HJ-NP-Za-km-z]{100,}['\"]",
                r"(?:xpub|extendedPublicKey)\s*[:=]\s*['\"][A-Za-z0-9]{100,}['\"][\s\S]{0,300}?(?:derive|deposit)"],
      category="web3"),
    S("exch_mnemonic_handling_client", "Mnemonic Generated or Stored in Client Code",
      "high",
      "Frontend code generates a mnemonic and persists it (localStorage / storage write in the same flow), so the seed behind user or operational wallets sits in browser storage readable by any script on the page.",
      "Never generate or store seed material in the browser for exchange flows; use hardware/server-side key management and session keys with narrow scope.",
      patterns=[r"(?:generateMnemonic|mnemonicToSeed|fromMnemonic)\s*\([\s\S]{0,400}?(?:localStorage|sessionStorage)\.setItem",
                r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*(?:mnemonic|seed)[^'\"]*['\"]"],
      category="leak"),
    S("exch_keystore_decrypt_client", "Keystore Decryption in Client Code",
      "high",
      "Frontend code decrypts a wallet keystore (decrypt/fromEncryptedJson/Web3 Secret Storage handling), meaning encrypted private-key material and its unlock flow live in the browser bundle.",
      "Move keystore handling to a dedicated signer service; the trading frontend should request signatures, never hold decryptable key material.",
      patterns=[r"(?:\.decrypt\s*\(\s*keystore|fromEncryptedJson|wallet\.decrypt|keystore\.decrypt|decryptKeystore)",
                r"['\"]UTC--[^'\"]+['\"][\s\S]{0,200}?(?:password|decrypt)"],
      category="leak"),
    S("exch_walletconnect_project_secret", "WalletConnect Project Secret in Bundle",
      "medium",
      "A WalletConnect project secret (as opposed to the public project ID) is assigned in the bundle, exposing the privileged project credential used to manage relay access.",
      "Rotate the project secret, keep it server-side, and ship only the public projectId to the frontend.",
      patterns=[r"(?:walletConnect|walletconnect|WALLETCONNECT)[A-Za-z_]*[_-]?secret\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"projectSecret\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env|projectId"],
      category="leak"),
    S("exch_rpc_admin_method_client", "RPC Endpoint With Admin/Debug Methods in Frontend Config",
      "high",
      "Frontend config pairs an RPC endpoint with admin/debug/personal method names, advertising a node endpoint whose dangerous namespaces the operator believes are reachable - a map for anyone probing the node.",
      "Never expose node RPC to browsers; put a method-allowlisting proxy in front of any public RPC and disable admin/debug/personal namespaces on it.",
      patterns=[r"(?:rpc|RPC)[A-Za-z_]*\s*[:=]\s*['\"]https?://[^'\"]+['\"][\s\S]{0,400}?(?:debug_traceTransaction|admin_|personal_unlockAccount|debug_)",
                r"(?:debug_traceTransaction|admin_addPeer|personal_unlockAccount)[\s\S]{0,400}?(?:rpc|RPC)[A-Za-z_]*\s*[:=]\s*['\"]https?://"],
      category="web3"),
    S("exch_signer_endpoint_frontend", "Remote Signer Endpoint Disclosed in Frontend Config",
      "medium",
      "Frontend config names the remote signer / signing-service endpoint URL, disclosing the location of the service that holds signing power for the exchange.",
      "Keep signer endpoints out of client config entirely; the browser should talk to the API tier, which alone knows where the signer lives.",
      patterns=[r"(?:signerUrl|signerEndpoint|signingService|remoteSigner)\s*[:=]\s*['\"]https?://[^'\"]+['\"]",
                r"SIGNER_(?:URL|ENDPOINT)\s*[:=]\s*['\"]https?://[^'\"]+['\"]"],
      category="web3"),
    S("exch_keystore_password_hardcoded", "Keystore Password Hardcoded in Client Code",
      "high",
      "A keystore/wallet password is assigned as a literal in client code near keystore handling, defeating the encryption on any keystore the same bundle ships or fetches.",
      "Remove the password from code, rotate it and the keys it protects, and never pair keystore material with its password in the same artifact.",
      patterns=[r"(?:keystorePassword|walletPassword|keystore_password)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                r"decrypt\s*\([\s\S]{0,200}?password\s*[:=]\s*['\"][^'\"]{8,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env|placeholder|example"],
      category="leak"),
    S("exch_multisig_owner_keys_config", "Multisig Owner/Signer Key Material in Config",
      "high",
      "Config in the bundle lists multisig owner/signer keys as 64-hex private-key material, which would hand control of the multisig to anyone who downloads the bundle.",
      "Treat the keys as burned: rotate every signer, rebuild the multisig with fresh keys generated offline, and keep signer material out of any shipped artifact.",
      patterns=[r"(?:signerKeys|ownerKeys|signerPrivateKeys)\s*[:=]\s*\[[^\]]*0x[0-9a-fA-F]{64}",
                r"(?:signerKeys|ownerKeys)\s*[:=]\s*\[[^\]]*['\"][0-9a-fA-F]{64}['\"]"],
      category="leak"),
]

SPECS_BY_ID = register(SPECS, __name__, globals())


def analyze_exchange_web2(text: str, spec: ExchSpec, headers=None):
    return analyze(text, spec, headers)
