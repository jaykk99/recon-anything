"""Canary fixtures for the exchange-key-leak pack.

Planted values are FAKE but format-valid (they match k.py's regexes).
They are never real credentials: Binance/Bybit/OKX/KuCoin keys below
were invented for this test and have never existed on any exchange.
The validation endpoints are mocked in test_exchange_key_leak.py, so no
live exchange call is ever made with them.
"""

BIN_KEY = "a1b2c3d4" * 8            # 64 alphanumerics
BIN_SEC = "e5f6a7b8" * 8            # 64 alphanumerics
ROT_BIN_KEY = "c1d2e3f4" * 8        # 64, mocked 401 -> ROTATED
IP_BIN_KEY = "d1e2f3a4" * 8         # 64, mocked ipRestrict -> IP-BOUND
RO_BIN_KEY = "e1f2a3b4" * 8         # 64, mocked withdrawals off -> READ-ONLY
FAKE_BIN_KEY = "example" * 8 + "12345678"   # 64, contains "example" -> skipped
FAKE_BIN_SEC = "example" * 8 + "87654321"   # 64, contains "example" -> skipped

BYB_KEY = "BybitKey1234567890"               # 19 chars
BYB_SEC = "BybitSecret1234567890AbCdEfGhIj"  # 31 chars
BYB_ACTION_KEY = "ActionKey1234567890"       # 19, mocked Withdraw -> ACTIONABLE
BYB_ACTION_SEC = "ActionSecret1234567890AbCdEfGh"  # 30 chars

OKX_KEY = "123e4567-e89b-12d3-a456-426614174000"  # 36 uuid-shaped
OKX_SEC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"     # 32
OKX_PASS = "TestPass123"
OKX_ROT_KEY = "123e4567-e89b-12d3-a456-426614174099"  # mocked 50111 -> ROTATED

KC_KEY = "abcdef0123456789abcdef01"           # 24 hex
KC_SEC = "123e4567-e89b-12d3-a456-426614174001"  # 36 uuid-shaped
KC_PASS = "TestPass123"

PLANTED = [
    BIN_KEY, BIN_SEC, ROT_BIN_KEY, IP_BIN_KEY, RO_BIN_KEY,
    FAKE_BIN_KEY, FAKE_BIN_SEC,
    BYB_KEY, BYB_SEC, BYB_ACTION_KEY, BYB_ACTION_SEC,
    OKX_KEY, OKX_SEC, OKX_PASS, OKX_ROT_KEY,
    KC_KEY, KC_SEC, KC_PASS,
]

CANARY_HOMEPAGE = f"""<html><head><title>canary</title></head><body>
<script src="/config.js"></script>
<script>
const BYBIT_API_KEY = "{BYB_KEY}";
const BYBIT_API_SECRET = "{BYB_SEC}";
</script>
</body></html>"""

CANARY_ENV = (
    f"BINANCE_API_KEY={BIN_KEY}\n"
    f"BINANCE_SECRET={BIN_SEC}\n"
)

# Only the fake pair lives here, with exact variable names: the plugin
# must find it, recognise "example" as a placeholder, and skip it, so
# the Binance plugin still reports exactly one finding from /.env.
CANARY_ENV_LOCAL = (
    f"BINANCE_API_KEY={FAKE_BIN_KEY}\n"
    f"BINANCE_SECRET={FAKE_BIN_SEC}\n"
)

CANARY_CONFIG_JS = "console.log('no secrets here');\n"

# Bare variable names (not JSON-quoted keys): k.py's regexes anchor on the
# exact names followed by : or =, so quoted "OKX_API_KEY": would not match.
CANARY_CONFIG_JSON = (
    "const config = {\n"
    f"  OKX_API_KEY: \"{OKX_KEY}\",\n"
    f"  OKX_SECRET_KEY: \"{OKX_SEC}\",\n"
    f"  OKX_PASSPHRASE: \"{OKX_PASS}\",\n"
    f"  KUCOIN_API_KEY: \"{KC_KEY}\",\n"
    f"  KUCOIN_API_SECRET: \"{KC_SEC}\",\n"
    f"  KUCOIN_API_PASSPHRASE: \"{KC_PASS}\"\n"
    "};\n"
)

CANARY_ROUTES = {
    "/": ("text/html", CANARY_HOMEPAGE),
    "/.env": ("text/plain", CANARY_ENV),
    "/.env.local": ("text/plain", CANARY_ENV_LOCAL),
    "/config.js": ("text/javascript", CANARY_CONFIG_JS),
    "/config.json": ("application/json", CANARY_CONFIG_JSON),
}

CLEAN_HOMEPAGE = """<html><head><title>clean</title></head><body>
<script src="/config.js"></script>
<p>hello</p>
</body></html>"""

CLEAN_ROUTES = {
    "/": ("text/html", CLEAN_HOMEPAGE),
    "/.env": ("text/plain", "# no secrets here\nDEBUG=false\n"),
    "/.env.local": ("text/plain", "# no secrets here\nDEBUG=false\n"),
    "/config.js": ("text/javascript", "console.log('clean');\n"),
    "/config.json": ("application/json", "{}\n"),
}
