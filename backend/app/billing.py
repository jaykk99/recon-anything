"""ReconAnything as a sellable product: plans, GitHub sign-in sessions,
free-tier finding reveals, and BTC-only checkout.

Design rules (Jay's orders, 2026-10-23):
  - GitHub OAuth sign-in for customers; env-gated on GITHUB_CLIENT_ID /
    GITHUB_CLIENT_SECRET. When unset, sign-in shows an honest
    "sign-in opens soon" state and the rest of the app is unchanged.
    When set, the app flips to sign-in mode (see signin_mode): the
    legacy access code is retired and GitHub sign-in is the only door.
  - The owner (GitHub login from OWNER_GITHUB_LOGIN, default "jaykk99")
    has full access to everything and is NEVER shown payment UI:
    /api/me reports show_payment_ui=False for the owner, and plan
    payloads carry no checkout data for them.
  - Free tier: exactly 1 revealed finding per calendar day. The day
    boundary is UTC midnight (documented on /pricing). Scans still run
    (detection-only scope rules unchanged); the rest of a run's
    findings are returned as locked counts with values masked.
  - Paid plans are BTC only (no third-party card processors). An order
    pins the BTC amount at the live rate when it is created. Activation
    is owner-approved from /admin/orders after payment confirms - there
    is no automatic on-chain watcher in this build, and the checkout
    page says so honestly.
  - RECON_BTC_ADDRESS unset => checkout reports "checkout opens soon".
    A wallet address is NEVER invented.

Env is read at call time (not import time) so tests and dashboard
changes take effect without code edits.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from decimal import ROUND_DOWN, Decimal
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------- plans

PLANS: Dict[str, Dict] = {
    "free": {
        "id": "free", "name": "Free", "price_usd": 0,
        "scans_per_day": 3, "full_findings": False,
        "crypto_pack": False, "api_access": False,
        "auth_scans": False,
        "bulk_targets": False, "white_label": False,
        "features": [
            "3 scans per day",
            "1 revealed finding per day (UTC)",
            "Core detection plugins",
            "Locked findings shown as counts",
        ],
    },
    "starter": {
        "id": "starter", "name": "Starter", "price_usd": 19,
        "scans_per_day": 10, "full_findings": True,
        "crypto_pack": False, "api_access": False,
        "auth_scans": False,
        "bulk_targets": False, "white_label": False,
        "features": [
            "10 scans per day",
            "Full findings, nothing locked",
            "Core detection plugins",
            "JSON / CSV / Markdown / HTML export",
        ],
    },
    "pro": {
        "id": "pro", "name": "Pro", "price_usd": 49,
        "scans_per_day": None, "full_findings": True,
        "crypto_pack": True, "api_access": True,
        "auth_scans": True,
        "bulk_targets": False, "white_label": False,
        "features": [
            "Unlimited scans",
            "Full findings, nothing locked",
            "All plugins, including the Crypto Pack (110 checks)",
            "API access",
            "Authenticated scans (your own sites, behind login). "
            "For authorized testing only.",
        ],
    },
    "agency": {
        "id": "agency", "name": "Agency", "price_usd": 149,
        "scans_per_day": None, "full_findings": True,
        "crypto_pack": True, "api_access": True,
        "auth_scans": True,
        "bulk_targets": True, "white_label": True,
        "features": [
            "Everything in Pro",
            "Bulk targets",
            "White-label report export",
            "Priority scan queue",
            "Authenticated scans (your own sites, behind login). "
            "For authorized testing only.",
        ],
    },
}

# The owner's effective plan: everything on, no limits, and the flag
# that suppresses every scrap of payment UI.
OWNER_PLAN: Dict = {
    "id": "owner", "name": "Owner", "price_usd": 0,
    "scans_per_day": None, "full_findings": True,
    "crypto_pack": True, "api_access": True,
    "auth_scans": True,
    "bulk_targets": True, "white_label": True,
    "features": ["Full access (owner account)"],
}

FREE_REVEALS_PER_DAY = 1
PLAN_DURATION_DAYS = 30


def owner_login() -> str:
    return os.environ.get("OWNER_GITHUB_LOGIN", "jaykk99").strip().lower()


def is_owner_login(login: Optional[str]) -> bool:
    return bool(login) and login.strip().lower() == owner_login()


def plan_for(plan_id: Optional[str]) -> Dict:
    return PLANS.get((plan_id or "free").lower(), PLANS["free"])


def effective_plan(user) -> Dict:
    """The plan a signed-in user actually gets right now.

    Owner login => OWNER_PLAN regardless of the stored plan. A paid plan
    whose plan_expires_at has passed falls back to free.
    """
    if user is None:
        return PLANS["free"]
    if is_owner_login(getattr(user, "github_login", None)):
        return OWNER_PLAN
    plan = plan_for(getattr(user, "plan", "free"))
    if plan["id"] != "free":
        exp = getattr(user, "plan_expires_at", None)
        if exp is not None:
            import datetime as dt
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=dt.timezone.utc)
            if exp < dt.datetime.now(dt.timezone.utc):
                return PLANS["free"]
    return plan


def public_plans() -> List[Dict]:
    """Plan data safe to show anyone (drives /pricing)."""
    return [dict(p) for p in PLANS.values()]


# ------------------------------------------------------------- day math

def today_key(now: Optional[float] = None) -> str:
    """UTC calendar day, YYYY-MM-DD. Free-tier reveals reset at UTC
    midnight; this is stated plainly on the pricing page."""
    return time.strftime("%Y-%m-%d", time.gmtime(now or time.time()))


def today_start_utc():
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


# ------------------------------------------------------- GitHub + env

def github_enabled() -> bool:
    return bool(os.environ.get("GITHUB_CLIENT_ID")
                and os.environ.get("GITHUB_CLIENT_SECRET"))


def signin_mode() -> bool:
    """True when GitHub sign-in is the app's only door.

    The mode flips on configuration alone: the moment GITHUB_CLIENT_ID
    and GITHUB_CLIENT_SECRET are both set, the app runs in sign-in
    mode and the legacy access code is RETIRED - it is not accepted
    anywhere (API or UI) and a GitHub session is required for every
    gated route. While either var is unset, sign-in mode is off and
    the access-code gate behaves exactly as it always has, so the app
    is never left ungated mid-transition. Read at call time, like
    github_enabled(), so flipping the env flips the mode on the next
    request after a redeploy.
    """
    return github_enabled()


def btc_address() -> str:
    return os.environ.get("RECON_BTC_ADDRESS", "").strip()


def checkout_enabled() -> bool:
    return bool(btc_address())


# ------------------------------------------------------------ sessions
# Server-side identity, cookie-carried: an HMAC-signed token holding the
# user id + expiry. No new dependencies (stdlib hmac/hashlib). The
# signing secret comes from RECON_SESSION_SECRET, falling back to the
# existing RECON_MASTER_KEY / RECON_ACCESS_CODE so a single-service
# deploy works with zero extra config; if none is set a dev fallback is
# used (sessions still work, secret is just guessable - set the env).

SESSION_COOKIE = "recon_session"
SESSION_TTL_S = 30 * 24 * 3600


def _session_secret() -> str:
    secret = (os.environ.get("RECON_SESSION_SECRET")
              or os.environ.get("RECON_MASTER_KEY")
              or os.environ.get("RECON_ACCESS_CODE"))
    if secret:
        return secret
    if github_enabled():
        # Sign-in mode is the app's only door (see signin_mode()): every
        # customer session cookie is an HMAC over this secret. Falling
        # back to a hardcoded string here would let anyone forge a
        # session for any user_id/login (including the owner's), since
        # the access code is retired the moment GitHub creds land and
        # can no longer act as the real secret either. Fail loudly
        # instead of silently shipping a forgeable auth system.
        raise RuntimeError(
            "GITHUB_CLIENT_ID/SECRET are set (sign-in mode) but none of "
            "RECON_SESSION_SECRET, RECON_MASTER_KEY, or RECON_ACCESS_CODE "
            "are - set RECON_SESSION_SECRET to a long random value before "
            "customers can sign in.")
    # No GitHub sign-in and no access code: the app is already in fully
    # open local-dev mode (resolve_actor treats every request as
    # "owner"), so a fixed dev secret here grants nothing extra.
    return "recon-dev-session-secret"


def _sign(payload_b64: str) -> str:
    mac = hmac.new(_session_secret().encode(), payload_b64.encode(),
                   hashlib.sha256)
    return base64.urlsafe_b64encode(mac.digest()).decode().rstrip("=")


def make_session_token(user_id: int, now: Optional[float] = None) -> str:
    now = now or time.time()
    payload = {"uid": int(user_id), "exp": int(now) + SESSION_TTL_S}
    b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()).decode().rstrip("=")
    return f"{b64}.{_sign(b64)}"


def parse_session_token(token: Optional[str],
                        now: Optional[float] = None) -> Optional[int]:
    """User id from a session token, or None if invalid/expired."""
    if not token or "." not in token:
        return None
    b64, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(b64)):
        return None
    try:
        pad = "=" * (-len(b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(b64 + pad))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < int(now or time.time()):
        return None
    uid = payload.get("uid")
    return int(uid) if uid is not None else None


def make_state_pair() -> Tuple[str, str]:
    """OAuth CSRF state: returns (state value for the authorize URL,
    signed cookie token carrying it, 10-minute life)."""
    import secrets as _secrets
    state = _secrets.token_urlsafe(18)
    payload = {"s": state, "exp": int(time.time()) + 600}
    b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode()).decode().rstrip("=")
    return state, f"{b64}.{_sign(b64)}"


def check_state_token(token: Optional[str], state: Optional[str]) -> bool:
    if not token or not state or "." not in token:
        return False
    b64, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(b64)):
        return False
    try:
        pad = "=" * (-len(b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(b64 + pad))
    except Exception:
        return False
    return (int(payload.get("exp", 0)) >= int(time.time())
            and payload.get("s") == state)


# ------------------------------------------------------- plugin gating

def is_crypto_plugin(plugin_id: str) -> bool:
    return plugin_id.startswith("cp_")


def filter_plugins_for_plan(plan: Dict, selected: Optional[List[str]]
                            ) -> Tuple[Optional[List[str]], List[str]]:
    """Split an explicit plugin selection into (allowed, stripped).

    Only the Crypto Pack is plan-gated today: cp_* plugins require a
    plan with crypto_pack=True. Returns selected unchanged when the
    plan allows everything.
    """
    if not selected:
        return selected, []
    if plan.get("crypto_pack"):
        return list(selected), []
    allowed = [p for p in selected if not is_crypto_plugin(p)]
    stripped = [p for p in selected if is_crypto_plugin(p)]
    return allowed, stripped


def excluded_plugins_for_plan(plan: Dict,
                              all_plugin_ids: List[str]) -> List[str]:
    """Plugins to exclude from an unfiltered (full) scan for this plan.

    Kept OUT of the run's explicit selection on purpose: an explicit
    selection means "selected means run" (exempt from time-budget
    skips), while an exclusion just narrows the default set.
    """
    if plan.get("crypto_pack"):
        return []
    return [p for p in all_plugin_ids if is_crypto_plugin(p)]


# ------------------------------------------------------- reveal masking

LOCKED_VALUE = "Locked - upgrade to reveal this finding"


def mask_rows(rows: List[Dict], revealed_id) -> Tuple[List[Dict], int]:
    """Mask every finding except the revealed one (free tier).

    Metadata (plugin, category, key, confidence) stays visible so the
    locked count is meaningful; the value, evidence and raw payload -
    the actual finding - are replaced.
    """
    out: List[Dict] = []
    locked = 0
    for row in rows:
        if revealed_id is not None and row.get("id") == revealed_id:
            out.append({**row, "locked": False})
            continue
        locked += 1
        out.append({**row, "value": LOCKED_VALUE, "evidence": None,
                    "raw": None, "source_url": None, "locked": True})
    return out, locked


def apply_reveal(session, user, run_id: str, rows: List[Dict],
                 plan: Dict) -> Tuple[List[Dict], Dict]:
    """Free-tier reveal enforcement for one run's findings.

    Exactly FREE_REVEALS_PER_DAY finding per UTC day is revealed per
    user, across all their runs. The first full finding a free user
    opens on a day becomes that day's reveal (recorded in
    finding_reveals); later views the same day show only that finding
    unmasked, wherever it lives. Paid/owner plans pass rows through.
    """
    from .models import FindingReveal
    total = len(rows)
    if plan.get("full_findings"):
        return rows, {"plan": plan["id"], "full_findings": True,
                      "total_findings": total, "locked_count": 0,
                      "revealed_finding_id": None,
                      "reveals_used_today": 0,
                      "reveals_per_day": FREE_REVEALS_PER_DAY}
    day = today_key()
    existing = (session.query(FindingReveal)
                .filter_by(user_id=user.id, day=day).first())
    revealed_id = existing.finding_id if existing else None
    if revealed_id is None and rows:
        first = rows[0]
        revealed_id = first.get("id")
        if revealed_id is not None:
            session.add(FindingReveal(user_id=user.id, run_id=run_id,
                                       finding_id=revealed_id, day=day))
            session.commit()
    masked, locked = mask_rows(rows, revealed_id)
    return masked, {"plan": plan["id"], "full_findings": False,
                    "total_findings": total, "locked_count": locked,
                    "revealed_finding_id": revealed_id,
                    "reveals_used_today": 1 if existing or revealed_id else 0,
                    "reveals_per_day": FREE_REVEALS_PER_DAY,
                    "day_boundary": "UTC"}


# ------------------------------------------------------------ BTC math

_btc_rate_cache: Dict = {"rate": None, "ts": 0.0}
BTC_RATE_TTL_S = 60


def btc_amount_for_usd(amount_usd: float, rate_usd_per_btc: float) -> Decimal:
    """Exact order math: USD price / BTC rate, 8 decimal places,
    rounded down so a rounding edge never short-changes the buyer."""
    if rate_usd_per_btc <= 0:
        raise ValueError("BTC rate must be positive")
    amt = (Decimal(str(amount_usd)) / Decimal(str(rate_usd_per_btc)))
    return amt.quantize(Decimal("0.00000001"), rounding=ROUND_DOWN)


def fetch_btc_usd() -> Optional[float]:
    """Live BTC/USD from CoinGecko (keyless), 60s in-process cache.

    Returns None when the rate cannot be fetched - callers must fail
    the order honestly rather than invent a rate.
    """
    now = time.time()
    if _btc_rate_cache["rate"] and now - _btc_rate_cache["ts"] < BTC_RATE_TTL_S:
        return _btc_rate_cache["rate"]
    try:
        import httpx
        r = httpx.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": "bitcoin", "vs_currencies": "usd"},
            timeout=10)
        rate = float(r.json()["bitcoin"]["usd"])
        if rate <= 0:
            return None
        _btc_rate_cache.update({"rate": rate, "ts": now})
        return rate
    except Exception:
        return None
