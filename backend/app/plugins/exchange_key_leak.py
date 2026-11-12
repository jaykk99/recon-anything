"""Exchange API-key leak detectors (binance/bybit/okx/kucoin_leaked_api_key).

Ports Jay's k.py detectors into ReconAnything plugins. k.py dorks public
code for leaked Binance / Bybit / OKX / KuCoin API key+secret pairs,
dedupes on the secret's SHA-256, and validates each pair with ONE
read-only signed permission call per provider:

  binance  GET /sapi/v1/account/apiRestrictions (+ /api/v3/account balances
           when reading is enabled)   -> ACTIONABLE / READ-ONLY / IP-BOUND
  bybit    GET /v5/user/query-api                        -> ACTIONABLE / READ-ONLY
  okx      GET /api/v5/account/config (needs passphrase) -> ACTIONABLE / READ-ONLY
  kucoin   k.py has no validation branch                 -> UNVERIFIED always

Tags (same as k.py): ACTIONABLE = live key, withdrawals enabled, no IP
bind. READ-ONLY = live key, withdrawals off. IP-BOUND = live key, IP
restricted. ROTATED = 401 / dead key. UNVERIFIED = could not validate
(network error, or no passphrase for OKX / no validation branch for KuCoin).

Sources scanned (all read-only GETs, same host as the target unless the
target is a GitHub repo URL): the target homepage + inline scripts +
same-domain script sources + discovery-bus text assets + a small set of
public config paths (/.env, /config.json, ...). When the target IS a
github.com/<owner>/<repo> URL and a GitHub token is configured, the
plugin also runs k.py's dorks scoped to that repo and raw-fetches the
hits (commit SHA from html_url, never the blob SHA).

EVIDENCE RULE (non-negotiable, same as the sec_* pack): no finding ever
carries a full key, secret, or passphrase in `value`, `evidence`, or
`raw`. Findings carry a masked key plus SHA-256 fingerprints of the key
and the secret so the owner can confirm rotation. Validation calls are
read-only permission/balance reads only: NEVER withdraw, trade, transfer,
or move funds.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, safe_json_dict
from .secretpack import (
    SCOPE_NOTE,
    _looks_fake,
    fingerprint,
    mask_secret,
    safe_evidence,
)
from .secretutils import is_placeholder

EXCHANGE_KEY_IDS = [
    "binance_leaked_api_key",
    "bybit_leaked_api_key",
    "okx_leaked_api_key",
    "kucoin_leaked_api_key",
]

# k.py dorks, kept per provider so the GitHub branch reuses them verbatim.
DORKS = {
    "binance": [
        '"BINANCE_API_KEY" "BINANCE_SECRET"',
        '"BINANCE_SECRET_KEY" extension:env',
        '"binance" "apiKey" "secret" filename:.env',
    ],
    "bybit": ['"BYBIT_API_KEY" "BYBIT_API_SECRET"'],
    "okx": ['"OKX_API_KEY" "OKX_SECRET_KEY"'],
    "kucoin": ['"KUCOIN_API_KEY" "KUCOIN_API_SECRET"'],
}

# k.py extraction patterns, compiled. (key_re, secret_re, passphrase_re)
PATTERNS = {
    "binance": (
        re.compile(r"BINANCE_API_KEY\s*[:=]\s*[\"']?([A-Za-z0-9]{64})"),
        re.compile(r"BINANCE_(?:SECRET|SECRET_KEY|API_SECRET)\s*[:=]\s*[\"']?([A-Za-z0-9]{64})"),
        None,
    ),
    "bybit": (
        re.compile(r"BYBIT_API_KEY\s*[:=]\s*[\"']?([A-Za-z0-9]{16,24})"),
        re.compile(r"BYBIT_API_SECRET\s*[:=]\s*[\"']?([A-Za-z0-9]{30,48})"),
        None,
    ),
    "okx": (
        re.compile(r"OKX_API_KEY\s*[:=]\s*[\"']?([0-9a-f-]{36})"),
        re.compile(r"OKX_SECRET_KEY\s*[:=]\s*[\"']?([A-Z0-9]{32})"),
        re.compile(r"OKX_PASSPHRASE\s*[:=]\s*[\"']?(\w{6,})"),
    ),
    "kucoin": (
        re.compile(r"KUCOIN_API_KEY\s*[:=]\s*[\"']?([0-9a-f]{24})"),
        re.compile(r"KUCOIN_API_SECRET\s*[:=]\s*[\"']?([0-9a-f-]{36})"),
        re.compile(r"KUCOIN_API_PASSPHRASE\s*[:=]\s*[\"']?(\w{6,})"),
    ),
}

# Public config paths worth a read-only probe on the target host.
# (Mirrors sec_committed_config; probe cache is shared per run, so a path
# already fetched by another plugin costs nothing extra.)
CONFIG_PATHS = ["/.env", "/.env.local", "/.env.production",
                "/config.json", "/config.js"]

SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]+src=)[^>]*>(.*?)</script>", re.I | re.S)

TAG_SEVERITY = {
    "ACTIONABLE": "high",
    "READ-ONLY": "high",
    "IP-BOUND": "medium",
    "UNVERIFIED": "medium",
    "ROTATED": "low",
}
TAG_CONFIDENCE = {
    "ACTIONABLE": 95,
    "READ-ONLY": 90,
    "IP-BOUND": 90,
    "UNVERIFIED": 70,
    "ROTATED": 60,
}

# Hard cap on validation calls per run: each pair costs one signed
# read-only call (two for Binance when reading is enabled).
MAX_VALIDATIONS_PER_RUN = 5

STABLECOINS = ("USDT", "USDC", "BUSD", "FDUSD")


def _is_fake_value(value: str) -> bool:
    """k.py exclusions: placeholder values and the dork XCL terms."""
    if not value or is_placeholder(value) or _looks_fake(value):
        return True
    low = value.lower()
    return "your_api_key_here" in low or "xxx" in low


def _github_repo_from_target(target: Target) -> Optional[Tuple[str, str]]:
    try:
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+)",
                     (target.normalized or "").strip())
        if not m:
            return None
        return m.group(1), m.group(2).removesuffix(".git")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Validation: one read-only signed permission call per provider, exactly as
# in k.py. Returns (tag, usd_stablecoin_balance, extra evidence fields).
# Any transport/parse failure -> UNVERIFIED, never an exception.
# ---------------------------------------------------------------------------

async def validate_binance(http, key: str, secret: str):
    try:
        ts = int(time.time() * 1000)
        q = f"timestamp={ts}"
        sig = hmac.new(secret.encode(), q.encode(),
                       hashlib.sha256).hexdigest()
        r = await http.get(
            "https://api.binance.com/sapi/v1/account/apiRestrictions"
            f"?{q}&signature={sig}",
            headers={"X-MBX-APIKEY": key}, timeout=8)
        if r.status_code == 401:
            return "ROTATED", 0, {}
        j = safe_json_dict(r)
        ip = j.get("ipRestrict")
        wd = j.get("enableWithdrawals")
        usd = 0
        if j.get("enableReading"):
            ts2 = int(time.time() * 1000)
            q2 = f"timestamp={ts2}"
            s2 = hmac.new(secret.encode(), q2.encode(),
                          hashlib.sha256).hexdigest()
            a = await http.get(
                "https://api.binance.com/api/v3/account"
                f"?{q2}&signature={s2}",
                headers={"X-MBX-APIKEY": key}, timeout=8)
            aj = safe_json_dict(a)
            usd = sum(
                float(b.get("free", 0) or 0) + float(b.get("locked", 0) or 0)
                for b in aj.get("balances", [])
                if isinstance(b, dict) and b.get("asset") in STABLECOINS)
        extra = {"ip_restrict": ip, "withdrawals_enabled": wd}
        if ip is True:
            return "IP-BOUND", usd, extra
        if wd is False:
            return "READ-ONLY", usd, extra
        return "ACTIONABLE", usd, extra
    except Exception:
        return "UNVERIFIED", 0, {}


async def validate_bybit(http, key: str, secret: str):
    try:
        ts = str(int(time.time() * 1000))
        sig = hmac.new(secret.encode(), (ts + key + "5000").encode(),
                       hashlib.sha256).hexdigest()
        r = await http.get(
            "https://api.bybit.com/v5/user/query-api",
            headers={"X-BAPI-API-KEY": key, "X-BAPI-TIMESTAMP": ts,
                     "X-BAPI-SIGN": sig, "X-BAPI-RECV-WINDOW": "5000"},
            timeout=8)
        if r.status_code in (401, 403):
            return "ROTATED", 0, {}
        wd = "Withdraw" in (r.text or "")
        return ("ACTIONABLE", 0, {"withdrawals_enabled": True}) if wd else (
            "READ-ONLY", 0, {"withdrawals_enabled": False})
    except Exception:
        return "UNVERIFIED", 0, {}


async def validate_okx(http, key: str, secret: str,
                       passphrase: Optional[str]):
    if not passphrase:
        # k.py only validates OKX when a passphrase was found alongside.
        return "UNVERIFIED", 0, {"note": "no passphrase found with key"}
    try:
        ts = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        sig = base64.b64encode(hmac.new(
            secret.encode(), (ts + "GET/api/v5/account/config").encode(),
            hashlib.sha256).digest()).decode()
        r = await http.get(
            "https://www.okx.com/api/v5/account/config",
            headers={"OK-ACCESS-KEY": key, "OK-ACCESS-SIGN": sig,
                     "OK-ACCESS-TIMESTAMP": ts,
                     "OK-ACCESS-PASSPHRASE": passphrase},
            timeout=8)
        j = safe_json_dict(r)
        if j.get("code") in ("50111", "50113"):
            return "ROTATED", 0, {}
        wd = "withdraw" in (r.text or "")
        return ("ACTIONABLE", 0, {"withdrawals_enabled": True}) if wd else (
            "READ-ONLY", 0, {"withdrawals_enabled": False})
    except Exception:
        return "UNVERIFIED", 0, {}


async def validate_kucoin(http, key: str, secret: str,
                          passphrase: Optional[str]):
    # k.py has no KuCoin validation branch: a detected pair is reported
    # UNVERIFIED (liveness not probed), never guessed at.
    return "UNVERIFIED", 0, {
        "note": "k.py has no KuCoin validation branch; pair detected, "
                "liveness not probed"}


VALIDATORS = {
    "binance": validate_binance,
    "bybit": validate_bybit,
    "okx": validate_okx,
    "kucoin": validate_kucoin,
}


class _ExchangeKeyBase(Plugin):
    """Shared plumbing for the exchange-key-leak pack."""

    # Empty id so the registry never registers this abstract base itself.
    id = ""
    cost = Cost.FREE
    group = "web"
    accepts = ["domain", "url"]
    provider = "binance"  # overridden per subclass

    async def _base(self, target: Target, ctx: Ctx):
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return None, None, None
        base = await web_base(ctx, target, domain)
        return domain, base, (ctx.mode == "passive")

    def _extract_pairs(self, text: str, url: str, kind: str,
                       pairs: List[Dict], seen: Set[str]) -> None:
        """k.py extraction: key+secret (+passphrase) in one text blob."""
        key_re, secret_re, pass_re = PATTERNS[self.provider]
        km, sm = key_re.search(text or ""), secret_re.search(text or "")
        if not (km and sm):
            return
        key, secret = km.group(1), sm.group(1)
        if _is_fake_value(key) or _is_fake_value(secret):
            return
        fp = fingerprint(secret)
        if fp in seen:
            return
        seen.add(fp)
        pair: Dict = {"key": key, "secret": secret, "fp": fp,
                      "url": url, "kind": kind}
        if pass_re is not None:
            pm = pass_re.search(text or "")
            pair["passphrase"] = pm.group(1) if pm else None
        pairs.append(pair)

    async def _github_pairs(self, target: Target, ctx: Ctx,
                            pairs: List[Dict], seen: Set[str]) -> None:
        """k.py dork path, scoped to the target repo. Needs a GitHub token."""
        if not ctx.keys.get("github"):
            return
        repo = _github_repo_from_target(target)
        if not repo:
            return
        owner, name = repo
        for dork in DORKS[self.provider]:
            try:
                r = await ctx.http.get(
                    "https://api.github.com/search/code",
                    params={"q": f"{dork} repo:{owner}/{name}",
                            "per_page": 10},
                    headers={"Authorization": f"Bearer {ctx.keys['github']}",
                             "Accept": "application/vnd.github+json"},
                    timeout=20)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            items = safe_json_dict(r).get("items", [])
            if not isinstance(items, list):
                continue
            for it in items[:5]:
                if not isinstance(it, dict):
                    continue
                try:
                    # Fixed k.py bug: search "sha" is the blob SHA;
                    # raw.githubusercontent.com needs the commit SHA.
                    ref = it["html_url"].split("/blob/")[1].split("/")[0]
                    path = it["path"]
                except Exception:
                    continue
                try:
                    raw = await ctx.http.get(
                        f"https://raw.githubusercontent.com/{owner}/{name}"
                        f"/{ref}/{path}", timeout=8)
                except Exception:
                    continue
                if raw.status_code == 200:
                    self._extract_pairs(
                        raw.text or "",
                        f"https://raw.githubusercontent.com/{owner}/{name}"
                        f"/{ref}/{path}",
                        "github code", pairs, seen)

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base, passive = await self._base(target, ctx)
        if not domain:
            return self._skipped("no domain for this target type")
        pairs: List[Dict] = []
        seen: Set[str] = set()
        texts: List[Tuple[str, str, str]] = []

        page = await ctx.fetch_page(base, timeout=12)
        if page:
            html = page.get("text", "") or ""
            for sm in INLINE_SCRIPT_RE.finditer(html):
                body = sm.group(1).strip()
                if len(body) > 20:
                    texts.append((body[:500000], base, "inline script"))
            js_urls: Set[str] = set()
            for sm in SCRIPT_SRC_RE.finditer(html):
                full = urljoin(base, sm.group(1))
                try:
                    if domain in urlparse(full).netloc:
                        js_urls.add(full)
                except Exception:
                    continue
            for ju in ctx.consume("js_files"):
                if isinstance(ju, str):
                    try:
                        if domain in urlparse(ju).netloc:
                            js_urls.add(ju)
                    except Exception:
                        continue
            for ju in sorted(js_urls)[:15]:
                try:
                    jr = await ctx.fetch_page(ju, timeout=12)
                    if jr and jr.get("status_code") == 200:
                        texts.append((jr.get("text", "")[:500000], ju,
                                      "JS bundle"))
                except Exception:
                    continue
            texts.append((html[:500000], base, "homepage"))

        for path in CONFIG_PATHS:
            url = base.rstrip("/") + path
            try:
                r = await ctx.probe(url, timeout=8)
            except Exception:
                continue
            if not r or r.get("status") != 200:
                continue
            body = r.get("text", "") or ""
            if body.strip():
                texts.append((body[:500000], url, f"public file {path}"))

        await self._github_pairs(target, ctx, pairs, seen)

        for text, url, kind in texts:
            self._extract_pairs(text, url, kind, pairs, seen)

        findings: List[Finding] = []
        validated = 0
        for pair in pairs:
            if validated >= MAX_VALIDATIONS_PER_RUN:
                break
            validated += 1
            validator = VALIDATORS[self.provider]
            if self.provider in ("okx", "kucoin"):
                tag, usd, extra = await validator(
                    ctx.http, pair["key"], pair["secret"],
                    pair.get("passphrase"))
            else:
                tag, usd, extra = await validator(
                    ctx.http, pair["key"], pair["secret"])
            fp = pair["fp"]
            ev = safe_evidence(
                TAG_SEVERITY[tag],
                f"{self.provider} api key leak",
                mask_secret(pair["key"]),
                fp,
                "Rotate this API key immediately in the exchange "
                "dashboard, revoke the leaked pair, remove the file "
                "from the public web root and from version control "
                "history, and move secrets to a vault. Check the "
                "account's API activity / withdrawal history for misuse.",
                {"provider": self.provider,
                 "tag": tag,
                 "key_fingerprint_sha256": fingerprint(pair["key"]),
                 "secret_fingerprint16": fp[:16],
                 "source_url": pair["url"],
                 "source_kind": pair["kind"],
                 "usd_stablecoin_balance": usd,
                 "scope_note": SCOPE_NOTE,
                 **extra})
            usd_note = (f" Stablecoin balance ${usd:,.0f}."
                        if usd else "")
            findings.append(self._f(
                "leak", f"{self.provider}_leaked_api_key",
                f"{tag}: leaked {self.provider} API key pair in public "
                f"{pair['kind']} (secret fingerprint {fp[:16]})."
                f"{usd_note}",
                "Exchange API-key leak detector",
                source_url=pair["url"],
                confidence=TAG_CONFIDENCE[tag], evidence=ev,
                passive=passive))
        return self._ok(
            findings,
            f"scanned {len(texts)} sources, {len(pairs)} pair(s), "
            f"{validated} validated")


class BinanceLeakedApiKeyPlugin(_ExchangeKeyBase):
    id = "binance_leaked_api_key"
    label = "Leaked Binance API Key"
    provider = "binance"
    description = (
        "Binance API key+secret pair exposed in publicly fetched source "
        "or config text, validated with one read-only signed "
        "apiRestrictions call (plus a balance read when reading is "
        "enabled). Tags ACTIONABLE / READ-ONLY / IP-BOUND / ROTATED. "
        "Findings carry fingerprints only, never the key or secret.")
    passive = True


class BybitLeakedApiKeyPlugin(_ExchangeKeyBase):
    id = "bybit_leaked_api_key"
    label = "Leaked Bybit API Key"
    provider = "bybit"
    description = (
        "Bybit API key+secret pair exposed in publicly fetched source "
        "or config text, validated with one read-only signed query-api "
        "call. Tags ACTIONABLE / READ-ONLY / ROTATED. Findings carry "
        "fingerprints only, never the key or secret.")
    passive = True


class OkxLeakedApiKeyPlugin(_ExchangeKeyBase):
    id = "okx_leaked_api_key"
    label = "Leaked OKX API Key"
    provider = "okx"
    description = (
        "OKX API key+secret+passphrase exposed in publicly fetched "
        "source or config text, validated with one read-only signed "
        "account/config call (passphrase required; without one the pair "
        "is UNVERIFIED). Tags ACTIONABLE / READ-ONLY / ROTATED. "
        "Findings carry fingerprints only, never the key or secret.")
    passive = True


class KucoinLeakedApiKeyPlugin(_ExchangeKeyBase):
    id = "kucoin_leaked_api_key"
    label = "Leaked KuCoin API Key"
    provider = "kucoin"
    description = (
        "KuCoin API key+secret+passphrase exposed in publicly fetched "
        "source or config text. k.py has no KuCoin validation branch, "
        "so a detected pair is reported UNVERIFIED (liveness not "
        "probed). Findings carry fingerprints only, never the key or "
        "secret.")
    passive = True
