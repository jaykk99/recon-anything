"""Exchange-web detectors, block 1: frontend secret exposure.

Ten detectors for credential material shipped inside an exchange
site's own public JS bundles and bundle-embedded config. Detection
only: the analyzer reads text the site serves to any visitor; a
finding carries a masked snippet plus a SHA-256 fingerprint, never
the full secret (see _exchange_common).
"""
from __future__ import annotations

from ._exchange_common import ExchSpec, S, analyze, register

FAMILY = "exchange_web1"

SPECS = [
    S("exch_api_key_secret_pair_js", "Exchange API Key and Secret Pair in JS Bundle",
      "high",
      "A JS bundle assigns both an exchange apiKey and an apiSecret as string literals, so anyone who downloads the bundle owns a working credential pair for that account.",
      "Remove the pair from client code, rotate it, and sign requests server-side; the browser should only ever hold short-lived session tokens.",
      patterns=[r"apiKey\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"][\s\S]{0,300}?apiSecret\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"api_secret\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{16,}['\"][\s\S]{0,300}?api_key\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env|publishable|public[_-]?key"],
      category="leak"),
    S("exch_testnet_key_prod_bundle", "Testnet API Key Literal in Production Bundle",
      "medium",
      "A testnet API key is assigned as a literal inside the shipped bundle. Testnet keys in production code prove key material is routinely hardcoded, and the same pipeline usually ships the mainnet pair the same way.",
      "Move testnet keys to environment config injected at build time per environment, and audit the bundle pipeline for literal credentials.",
      patterns=[r"testnet[_-]?api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]",
                r"TESTNET_API_KEY\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
    S("exch_withdrawal_key_client_side", "Withdrawal API Key in Client Code",
      "high",
      "A withdrawal-capable API key is assigned in client-side code. A key that can move funds must never reach a browser; anyone can extract it from the bundle and drain the account it belongs to.",
      "Revoke the withdrawal key, issue read/trade-only keys for any client-adjacent use, and keep withdrawal keys on an isolated server with IP allowlisting.",
      patterns=[r"withdraw[a-zA-Z]*[_-]?(?:api[_-]?)?key\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"WITHDRAW_API_KEY\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
    S("exch_sourcemap_embedded_secret", "Secret Inside Sourcemap sourcesContent",
      "high",
      "A shipped sourcemap embeds the original source (sourcesContent) and that embedded source assigns an API secret, so the secret is public even though the minified bundle hides it.",
      "Stop shipping sourcesContent for production bundles, rotate the exposed secret, and treat every published sourcemap as published source code.",
      patterns=[r"\"sourcesContent\"\s*:\s*\[[\s\S]{0,4000}?(?:apiSecret|api_secret|client_secret|hmacSecret)\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
    S("exch_env_config_bundle_leak", "Env-Style Secret Lines Embedded in Bundle",
      "high",
      "Bundle text carries raw .env-style lines (NAME=value) for exchange/API secrets, the classic sign that a server .env file was bundled or inlined into the frontend build.",
      "Rebuild the frontend so only explicitly public variables are inlined, rotate every secret named in the leaked lines, and add a bundle scan for env-style assignments to CI.",
      patterns=[r"(?m)^\s*(?:EXCHANGE|API|BINANCE|CRYPTO|KUCOIN|COINBASE)_[A-Z_]*SECRET[A-Z_]*\s*=\s*[A-Za-z0-9+/=_~\-]{12,}\s*$",
                r"(?m)^\s*[A-Z_]*API_SECRET\s*=\s*[A-Za-z0-9+/=_~\-]{12,}\s*$"],
      negatives=[r"example|placeholder|changeme|your[_-]"],
      category="leak"),
    S("exch_request_signing_secret_js", "Request Signing Secret Used in Client Code",
      "high",
      "Client code holds a signing secret (signingSecret / hmacSecret variable, or a literal passed to createHmac), so any visitor can forge correctly signed API requests for that credential.",
      "Sign requests on the server only. Rotate the signing secret and audit signed-request logs for use from unexpected origins.",
      patterns=[r"(?:signingSecret|signSecret|hmacSecret|sign_key)\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"createHmac\s*\(\s*['\"]sha(?:256|512)['\"]\s*,\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
    S("exch_subaccount_key_js", "Subaccount API Key in JS Bundle",
      "high",
      "A subaccount API key/secret is assigned in the bundle. Subaccount keys are often overlooked in rotation and can carry trade or transfer rights over the subaccount's balances.",
      "Rotate the subaccount credential, remove it from client code, and inventory subaccount keys with the same handling as master-account keys.",
      patterns=[r"sub[_-]?account[a-zA-Z]*[_-]?(?:api[_-]?)?(?:key|secret)\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"SUBACCOUNT_(?:KEY|SECRET)\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
    S("exch_partner_affiliate_secret_key", "Partner/Affiliate Secret Key in Frontend",
      "medium",
      "A partner, affiliate or broker secret key is assigned in frontend code. These keys attribute order flow and can pay out referral balances, so a leaked one invites commission theft and account confusion.",
      "Rotate the partner secret, keep it server-side, and give the frontend only the public partner ID.",
      patterns=[r"(?:partner|affiliate|broker)[_-]?(?:secret|api[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"(?:PARTNER|BROKER)_SECRET\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
    S("exch_webhook_secret_frontend", "Webhook Secret in Frontend Code",
      "high",
      "A webhook signing secret is assigned in frontend code, so anyone can forge webhook callbacks (deposit confirmations, payment events) that the backend will accept as genuine.",
      "Rotate the webhook secret, keep it only on the receiving server, and verify webhook signatures against a secret the browser never sees.",
      patterns=[r"(?:webhook|whSecret|callback)[_-]?secret\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"WEBHOOK_SECRET\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
    S("exch_listenkey_leak_handling", "User Data Stream listenKey Hardcoded or Persisted",
      "medium",
      "A listenKey (the user-data-stream key that authorizes an account's private stream) is hardcoded in the bundle or persisted to localStorage, where any script on the page can read another session's stream key.",
      "Fetch listenKeys per session from the authenticated API, keep them in memory only, and never ship a literal or stored listenKey.",
      patterns=[r"listenKey\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]",
                r"localStorage\.setItem\s*\(\s*['\"][^'\"]*listenKey[^'\"]*['\"]"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
]

SPECS_BY_ID = register(SPECS, __name__, globals())


def analyze_exchange_web1(text: str, spec: ExchSpec, headers=None):
    return analyze(text, spec, headers)
