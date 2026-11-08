"""Exchange-web detectors, block 10: withdrawal / payment flow
logic in frontend code.

Ten detectors for money-movement logic an exchange frontend
implements (or trusts) in the browser: client-only whitelist and
limit checks, memo/tag handling, chain-config mismatches, onramp
secrets, QR address handling, confirmation tokens in URLs.
Code-pattern detection only (see _exchange_common).
"""
from __future__ import annotations

from ._exchange_common import ExchSpec, S, analyze, register

FAMILY = "exchange_web10"

SPECS = [
    S("exch_whitelist_check_client_only", "Withdrawal Address Whitelist Check Implemented in Client Code",
      "high",
      "The withdrawal flow checks the destination against the address whitelist in client code (validateWhitelist / isWhitelisted in the browser), which an attacker bypasses by calling the withdrawal API directly.",
      "Enforce the whitelist server-side on every withdrawal request; treat any client check as UX only.",
      patterns=[r"(?:validateWhitelist|isWhitelisted|checkWhitelist|whitelistCheck)\s*\([^)]*\)\s*\{[^}]{0,300}?(?:address|whitelist)",
                r"(?:whitelist|whiteList)\s*[:=]\s*\[[^\]]*0x[0-9a-fA-F]{40}[^\]]*\][\s\S]{0,200}?withdraw"],
      category="web"),
    S("exch_memo_tag_optional_flow", "Memo/Destination Tag Marked Optional in Withdrawal Flow",
      "medium",
      "The withdrawal form config marks the memo/destination tag optional for chains that require it (XRP/XLM-style), a flow that strands user funds at custodial destinations that need the tag to credit an account.",
      "Require the memo/destination tag whenever the destination is a known custodial address, and warn hard when it is left empty for tag-based chains.",
      patterns=[r"(?:memo|destinationTag|destTag)[A-Za-z]*\s*[:=]\s*\{[^}]{0,200}?(?:optional\s*[:=]\s*true|required\s*[:=]\s*false)",
                r"(?:memo|destinationTag)[A-Za-z]*\s*[:=]\s*['\"]optional['\"]"],
      category="web"),
    S("exch_testnet_chainid_prod_config", "Testnet Chain ID in Production Network Config",
      "medium",
      "Production network config contains a testnet chain ID (97 / 11155111 / 80001 / 5), so the client can be steered to sign or submit against a test network while presenting it as production.",
      "Ship production builds with mainnet chain IDs only and validate the connected chain server-side per request.",
      patterns=[r"chainId\s*[:=]\s*(?:97|11155111|80001|5)\b[\s\S]{0,200}?(?:network|rpc|chain)",
                r"(?:network|networks)\s*[:=]\s*\[[^\]]*chainId\s*[:=]\s*(?:97|11155111|80001)\b"],
      category="web3"),
    S("exch_fee_constant_client_trust", "Withdrawal Fee/Limit Constants Hardcoded for Client Validation",
      "medium",
      "Withdrawal fee and minimum constants are hardcoded in client code and used for validation, inviting the client - not the server - to be the source of truth for what a withdrawal costs and allows.",
      "Compute fees and limits server-side per request; the client may display server-provided values only.",
      patterns=[r"(?:withdrawFee|withdrawalFee|minWithdraw|minWithdrawal)\s*[:=]\s*(?:0\.\d+|\d+(?:\.\d+)?)\b[\s\S]{0,200}?(?:validate|check|fee)",
                r"(?:WITHDRAW_FEE|MIN_WITHDRAW)\s*[:=]\s*(?:0\.\d+|\d+(?:\.\d+)?)\b"],
      category="web"),
    S("exch_fiat_onramp_secret_key", "Fiat Onramp Provider Secret Key in Bundle",
      "high",
      "A fiat onramp provider secret key (MoonPay/Ramp/Wyre-style secret, as opposed to the publishable key) is assigned in the bundle, exposing the credential that signs purchase orders and payout instructions.",
      "Rotate the onramp secret, sign onramp orders server-side, and ship only the publishable key to the browser.",
      patterns=[r"(?:moonpay|ramp|wyre|transak)[A-Za-z_]*[_-]?secret(?:[_-]?key)?\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"(?:MOONPAY|RAMP|WYRE|TRANSAK)_[A-Z_]*SECRET\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env|publishable"],
      category="leak"),
    S("exch_qr_address_from_url_param", "Deposit QR Code Built From URL-Parameter Address",
      "high",
      "Deposit QR code generation takes the address from a URL parameter, so a crafted link can substitute an attacker's address into the QR a user scans to deposit.",
      "Build deposit QR codes only from the signed-in user's server-issued deposit address; never from URL input.",
      patterns=[r"(?:qr|QRCode|qrcode)[\s\S]{0,300}?(?:URLSearchParams|location\.search|searchParams\.get)\s*\(\s*['\"]address['\"]\s*\)",
                r"URLSearchParams\s*\(\s*location\.search\s*\)[\s\S]{0,200}?\.get\s*\(\s*['\"]address['\"]\s*\)[\s\S]{0,300}?(?:qr|QRCode|deposit)",
                r"searchParams\.get\s*\(\s*['\"]address['\"]\s*\)[\s\S]{0,300}?(?:qr|QRCode|deposit)"],
      category="web"),
    S("exch_withdrawal_confirm_token_url", "Withdrawal Confirmation Token Carried in URL",
      "medium",
      "Withdrawal confirmation links/routes carry the confirmation token in the URL query string, so the token that authorizes a withdrawal lands in history, logs and referrers.",
      "Move confirmation tokens out of URLs (POST body or a one-time, short-lived code entered on the page) and expire them on first use.",
      patterns=[r"['\"][^'\"]*/withdraw[a-z/]*confirm[^'\"]*\?[^'\"]*token=",
                r"['\"]/confirm-withdrawal\?token=[^'\"]*['\"]"],
      category="web"),
    S("exch_daily_limit_check_client", "Daily Withdrawal Limit Checked Only in Client Code",
      "high",
      "A daily withdrawal limit check function lives in client code, so the limit that is supposed to slow down a drain can be skipped by calling the API directly.",
      "Enforce daily limits server-side per account with a hard counter; client checks are display only.",
      patterns=[r"(?:checkDailyLimit|validateDailyLimit|dailyLimitCheck|isWithinDailyLimit)\s*\([^)]*\)\s*\{[^}]{0,300}?(?:limit|amount|withdraw)",
                r"dailyLimit\s*[:=]\s*\{[^}]{0,200}?check\s*\("],
      category="web"),
    S("exch_address_validation_weak_client", "Weak Client-Side Address Validation for Withdrawals",
      "medium",
      "Withdrawal address validation in client code is a length-only or loose-regex check, so malformed or wrong-network addresses pass the UI and rely entirely on later layers to catch them.",
      "Validate addresses server-side with full checksum and network checks; keep client validation as a first-pass UX hint only.",
      patterns=[r"(?:isValidAddress|validateAddress)\s*\([^)]*\)\s*\{\s*return\s+(?:address|addr)\.length\s*(?:===|==|>=|<=)\s*\d+",
                r"(?:isValidAddress|validateAddress)\s*\([^)]*\)\s*\{\s*return\s*/\^\[a-zA-Z0-9\]\{\d+,\}\$/\.test"],
      category="web"),
    S("exch_testnet_network_listed_prod", "Testnet Network Listed in Production Networks Config",
      "medium",
      "The production networks list includes a named testnet (BSC Testnet / Sepolia / Mumbai style entry), so the network picker can route production users to test networks.",
      "Ship production builds with a mainnet-only network list and reject testnet chain IDs at the API tier.",
      patterns=[r"(?:networks|chains)\s*[:=]\s*\[[^\]]*(?:Testnet|Sepolia|Goerli|Mumbai|Amoy)[^\]]*\]",
                r"name\s*[:=]\s*['\"][^'\"]*(?:Testnet|Sepolia|Goerli|Mumbai)['\"][\s\S]{0,200}?(?:chainId|rpc)"],
      category="web3"),
]

SPECS_BY_ID = register(SPECS, __name__, globals())


def analyze_exchange_web10(text: str, spec: ExchSpec, headers=None):
    return analyze(text, spec, headers)
