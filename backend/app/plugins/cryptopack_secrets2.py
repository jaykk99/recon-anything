"""Crypto pack wave 2: more leaked secrets - exchange/infra keys,
WIF and BIP-38 private keys, BIP-32 extended keys, bot tokens in
crypto context, and private keys hiding in JS comments.

Wave 1 covered the first tier of exchanges and the env/Hardhat/
ethers assignment shapes. Wave 2 adds the second exchange tier,
RPC infrastructure providers, and the key formats themselves:
a WIF string or an xprv in served content is a wallet compromise
regardless of what variable name it sits next to. All checksum
formats are verified (Base58Check, RIPEMD-160 where relevant).
Secrets are redacted in findings.
"""
from __future__ import annotations

from .cryptopack_util import PackPlugin
from .cryptopack_util2 import (
    bip38_verify, solana_keypair_b58_verify, wif_verify, xprv_verify,
    xpub_verify,
)


def _exchange2(id_, label, brand, key_re, key_desc):
    return type(id_, (PackPlugin,), {
        "id": id_, "label": label,
        "description": f"{brand} API credentials in served content.",
        "CATEGORY": "leak", "SECRET": True, "VALUE_GROUP": 1,
        "__module__": __name__,
        "PATTERNS": [(key_re, id_.replace("cp_apikey_", "") + "_api_key",
                      key_desc, 88, None)],
    })


CpApiKeyGemini = _exchange2(
    "cp_apikey_gemini", "Leaked Gemini API key", "Gemini",
    r"(?:GEMINI_API_KEY|GEMINI_KEY)\s*[:=]\s*[\"']?([A-Za-z0-9]{20,28})",
    "Gemini API key assignment")

CpApiKeyBitstamp = _exchange2(
    "cp_apikey_bitstamp", "Leaked Bitstamp API key", "Bitstamp",
    r"(?:BITSTAMP_API_KEY|BITSTAMP_KEY)\s*[:=]\s*[\"']?([A-Za-z0-9]{32,64})",
    "Bitstamp API key assignment")

CpApiKeyBitfinex = _exchange2(
    "cp_apikey_bitfinex", "Leaked Bitfinex API key", "Bitfinex",
    r"(?:BITFINEX_API_KEY|BITFINEX_KEY)\s*[:=]\s*[\"']?([A-Za-z0-9]{43})",
    "Bitfinex API key assignment")

CpApiKeyDeribit = _exchange2(
    "cp_apikey_deribit", "Leaked Deribit API credentials", "Deribit",
    r"(?:DERIBIT_CLIENT_ID|DERIBIT_API_KEY|DERIBIT_KEY)\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9_\-]{20,43})",
    "Deribit API credential assignment")

CpApiKeyGateio = _exchange2(
    "cp_apikey_gateio", "Leaked Gate.io API key", "Gate.io",
    r"(?:GATE_API_KEY|GATEIO_API_KEY|GATE_KEY)\s*[:=]\s*"
    r"[\"']?([0-9a-fA-F]{64})",
    "Gate.io API key assignment")

CpApiKeyMexc = _exchange2(
    "cp_apikey_mexc", "Leaked MEXC API key", "MEXC",
    r"(?:MEXC_API_KEY|MEXC_KEY)\s*[:=]\s*[\"']?(mx0[A-Za-z0-9]{30,})",
    "MEXC API key assignment")

CpApiKeyHtx = _exchange2(
    "cp_apikey_htx", "Leaked HTX (Huobi) API key", "HTX",
    r"(?:HTX_API_KEY|HUOBI_API_KEY|HTX_KEY)\s*[:=]\s*"
    r"[\"']?([A-Za-z0-9\-]{40,60})",
    "HTX API key assignment")

CpApiKeyBingx = _exchange2(
    "cp_apikey_bingx", "Leaked BingX API key", "BingX",
    r"(?:BINGX_API_KEY|BINGX_KEY)\s*[:=]\s*[\"']?([A-Za-z0-9]{64,88})",
    "BingX API key assignment")


def _infra(id_, label, brand, patterns):
    return type(id_, (PackPlugin,), {
        "id": id_, "label": label,
        "description": f"{brand} infrastructure credentials/endpoints "
                       "in served content.",
        "CATEGORY": "leak", "SECRET": True, "VALUE_GROUP": 1,
        "__module__": __name__,
        "PATTERNS": patterns,
    })


CpApiKeyBlockdaemon = _infra(
    "cp_apikey_blockdaemon", "Leaked Blockdaemon API key",
    "Blockdaemon",
    [(r"(?:BLOCKDAEMON_API_KEY|BLOCKDAEMON_KEY)\s*[:=]\s*"
      r"[\"']?([A-Za-z0-9]{32,64})",
      "blockdaemon_api_key", "Blockdaemon API key assignment", 88, None),
     (r"svc\.blockdaemon\.com/[^\s\"'<>]*?[?&]api[-_]?key=([A-Za-z0-9]{20,})",
      "blockdaemon_api_key", "Blockdaemon API key in URL", 85, None)])

CpApiKeyTenderly = _infra(
    "cp_apikey_tenderly", "Leaked Tenderly access token", "Tenderly",
    [(r"(?:TENDERLY_ACCESS_TOKEN|TENDERLY_ACCESS_KEY|TENDERLY_API_KEY)"
      r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{32,64})",
      "tenderly_access_token", "Tenderly access token assignment",
      88, None),
     (r"api\.tenderly\.co/[^\s\"'<>]*?access[-_]?token=([A-Za-z0-9_\-]{20,})",
      "tenderly_access_token", "Tenderly token in URL", 85, None)])

CpApiKeyChainstack = _infra(
    "cp_apikey_chainstack", "Leaked Chainstack endpoint/key",
    "Chainstack",
    [(r"([a-z0-9\-]+\.p2pify\.com/[0-9a-f]{32,})",
      "chainstack_endpoint", "Chainstack endpoint with key", 85, None),
     (r"(?:CHAINSTACK_API_KEY)\s*[:=]\s*[\"']?([0-9a-f]{32,64})",
      "chainstack_api_key", "Chainstack API key assignment", 88, None)])

CpApiKeyAnkr = _infra(
    "cp_apikey_ankr", "Leaked Ankr endpoint token", "Ankr",
    [(r"rpc\.ankr\.com/[a-z0-9_]+/([0-9a-f]{64})",
      "ankr_endpoint_token", "Ankr RPC endpoint token", 85, None),
     (r"(?:ANKR_API_KEY)\s*[:=]\s*[\"']?([0-9a-f]{64})",
      "ankr_api_key", "Ankr API key assignment", 88, None)])

CpApiKeyInfstones = _infra(
    "cp_apikey_infstones", "Leaked InfStones API key", "InfStones",
    [(r"(?:INFSTONES_API_KEY|INFSTONES_KEY)\s*[:=]\s*"
      r"[\"']?([A-Za-z0-9]{32,64})",
      "infstones_api_key", "InfStones API key assignment", 88, None)])


# ---------------------------------------------------------------------------
# Bot tokens in crypto context (trading/alert bots are wallet-adjacent)
# ---------------------------------------------------------------------------

class CpSecretTelegramBot(PackPlugin):
    id = "cp_secret_telegram_bot"
    label = "Telegram bot token in crypto context"
    description = ("Telegram bot API tokens in served JS/config near "
                   "crypto keywords - these bots typically control "
                   "trading alerts, sniper bots or wallet trackers "
                   "with users' funds in the loop.")
    CATEGORY = "leak"
    SECRET = True
    CONTEXT_RE = (r"wallet|trad(?:e|ing)|bot|alert|price|token|"
                  r"signal|sniper|crypto|buy|sell")
    PATTERNS = [(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b",
                 "telegram_bot_token", "Telegram bot token", 85, None)]


class CpSecretDiscordWebhook(PackPlugin):
    id = "cp_secret_discord_webhook"
    label = "Discord webhook in crypto context"
    description = ("Discord webhook URLs near crypto/trading "
                   "keywords - the exfil/alert channel of trading "
                   "bots and drainer kits alike.")
    CATEGORY = "leak"
    SECRET = True
    CONTEXT_RE = r"trad(?:e|ing)|wallet|alert|signal|bot|price|sniper"
    VALUE_GROUP = 1
    PATTERNS = [
        (r"(https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/"
         r"\d{17,20}/[A-Za-z0-9_\-]{60,})",
         "discord_webhook", "Discord webhook URL", 82, None),
    ]


# ---------------------------------------------------------------------------
# Private keys in their own formats (any context)
# ---------------------------------------------------------------------------

class CpSecretWifCompressed(PackPlugin):
    id = "cp_secret_wif_compressed"
    label = "Leaked WIF private key (compressed)"
    description = ("Wallet Import Format private keys for "
                   "compressed public keys (K/L...) - checksum-"
                   "verified; anyone holding this string owns the "
                   "wallet.")
    CATEGORY = "leak"
    SECRET = True
    PATTERNS = [(r"\b[KL][1-9A-HJ-NP-Za-km-z]{51}\b", "wif_private_key",
                 "WIF private key (compressed)", 95,
                 lambda s: wif_verify(s, 0x80, True))]


class CpSecretWifUncompressed(PackPlugin):
    id = "cp_secret_wif_uncompressed"
    label = "Leaked WIF private key (uncompressed)"
    description = ("Wallet Import Format private keys for "
                   "uncompressed public keys (5...) - checksum-"
                   "verified full wallet compromise.")
    CATEGORY = "leak"
    SECRET = True
    PATTERNS = [(r"\b5[1-9A-HJ-NP-Za-km-z]{50}\b", "wif_private_key",
                 "WIF private key (uncompressed)", 95,
                 lambda s: wif_verify(s, 0x80, False))]


class CpSecretWifTestnet(PackPlugin):
    id = "cp_secret_wif_testnet"
    label = "Leaked testnet WIF private key"
    description = ("Testnet WIF keys (0xEF) in production content - "
                   "no direct funds, but a loud test/prod hygiene "
                   "failure that often travels with real keys.")
    CATEGORY = "leak"
    SECRET = True
    PATTERNS = [(r"\b[9c][1-9A-HJ-NP-Za-km-z]{50,51}\b",
                 "wif_testnet_key", "Testnet WIF private key", 80,
                 lambda s: wif_verify(s, 0xEF, True)
                 or wif_verify(s, 0xEF, False))]


class CpSecretBip38(PackPlugin):
    id = "cp_secret_bip38"
    label = "Leaked BIP-38 encrypted private key"
    description = ("BIP-38 passphrase-encrypted private keys "
                   "(6P...) - checksum-verified; brute-forceable "
                   "offline against weak passphrases.")
    CATEGORY = "leak"
    SECRET = True
    PATTERNS = [(r"\b6P[1-9A-HJ-NP-Za-km-z]{56}\b", "bip38_key",
                 "BIP-38 encrypted private key", 92, bip38_verify)]


class CpSecretXprv(PackPlugin):
    id = "cp_secret_xprv"
    label = "Leaked BIP-32 extended private key (xprv family)"
    description = ("Extended private keys (xprv/yprv/zprv) - one "
                   "string derives every address in the wallet.")
    CATEGORY = "leak"
    SECRET = True
    PATTERNS = [(r"\b[xyzYZ]prv[1-9A-HJ-NP-Za-km-z]{100,110}\b",
                 "extended_private_key", "BIP-32 extended private key",
                 96, xprv_verify)]


class CpWeb3Xpub(PackPlugin):
    id = "cp_web3_xpub"
    label = "BIP-32 extended public key (xpub family)"
    description = ("Extended public keys (xpub/ypub/zpub) - not "
                   "spendable, but they expose the wallet's entire "
                   "address history and balances to anyone.")
    PATTERNS = [(r"\b[xyzYZ]pub[1-9A-HJ-NP-Za-km-z]{100,110}\b",
                 "extended_public_key", "BIP-32 extended public key",
                 80, xpub_verify)]


class CpSecretSignHexCtx(PackPlugin):
    id = "cp_secret_signer_hex_ctx"
    label = "Private key (64-hex) with signer context"
    description = ("Bare 64-hex keys sitting near signer/deployer/"
                   "private-key words outside the named assignments "
                   "wave 1 covers - JSON dumps, config objects, "
                   "frontend bundle constants.")
    CATEGORY = "leak"
    SECRET = True
    CONTEXT_RE = (r"private[ _]?key|signer|deployer|hot[ _]?wallet|"
                  r"wallet[ _]?key|owner[ _]?key")
    VALUE_GROUP = 1
    PATTERNS = [(r"(0x[0-9a-fA-F]{64}|[0-9a-fA-F]{64})",
                 "signer_hex_key", "Private key near signer context",
                 88, None)]


class CpSecretJsCommentKeys(PackPlugin):
    id = "cp_secret_js_comment_keys"
    label = "Private keys inside JS comments"
    description = ("Keys developers left in // and /* */ comments "
                   "of shipped JS ('temp', 'test only', 'remove "
                   "before launch') - the bundle ships them anyway.")
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"//[^\n]{0,160}?(?:private|secret|seed|deployer|signer)"
         r"[^\n]{0,80}?(0x[0-9a-fA-F]{64})",
         "comment_private_key", "Private key in line comment", 90,
         None),
        (r"/\*[^*]{0,400}?(?:private[ _]?key|seed phrase|mnemonic)"
         r"[^*]{0,200}?(0x[0-9a-fA-F]{64})",
         "comment_private_key", "Private key in block comment", 88,
         None),
    ]


class CpSecretEnvPrivkey2(PackPlugin):
    id = "cp_secret_env_privkey2"
    label = "Leaked private key in config assignment (wave-2 names)"
    description = ("More assignment names wave 1 missed: deployer/"
                   "hot-wallet/treasury/faucet/relayer keys, plus "
                   "Solana base58 keypairs in env-style assignments.")
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"(?mi)(?:DEPLOYER_KEY|HOT_WALLET_KEY|HOT_WALLET_PRIVATE_KEY|"
         r"TREASURY_PRIVATE_KEY|FAUCET_PRIVATE_KEY|FAUCET_KEY|"
         r"RELAYER_PRIVATE_KEY|BOT_PRIVATE_KEY|KEEPER_PRIVATE_KEY|"
         r"OPERATOR_PRIVATE_KEY)\s*[:=]\s*[\"']?"
         r"(0x[0-9a-fA-F]{64}|[0-9a-fA-F]{64})\b",
         "env_private_key_2", "Private key in config assignment "
         "(wave-2 name)", 95, None),
        (r"(?mi)(?:SOLANA_PRIVATE_KEY|SOL_PRIVATE_KEY|SOLANA_SECRET_KEY)"
         r"\s*[:=]\s*[\"']?([1-9A-HJ-NP-Za-km-z]{80,90})\b",
         "solana_private_key_b58", "Solana private key (base58) in "
         "assignment", 95, solana_keypair_b58_verify),
    ]


class CpSecretKeystorePathRefs(PackPlugin):
    id = "cp_secret_keystore_path_refs"
    label = "Keystore file paths/names in served content"
    description = ("References to actual keystore files (the UTC-- "
                   "filename format is unique to Ethereum keystores) "
                   "and keystore paths in configs the target serves.")
    CATEGORY = "leak"
    VALUE_GROUP = 1
    PATTERNS = [
        (r"\b(UTC--\d{4}-\d{2}-\d{2}T[0-9.\-]+Z?--[0-9a-fA-F]{40})\b",
         "keystore_filename", "Ethereum keystore filename (UTC--)",
         88, None),
        (r"([\"']?/[\w./\-]*keystore[\w./\-]*[\"']?)",
         "keystore_path_ref", "Keystore path reference", 65, None),
    ]
