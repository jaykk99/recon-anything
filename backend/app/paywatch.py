"""DIY crypto payment watcher for ReconAnything's BTC checkout.

Jay's DIY payment method, end to end:
  1. A signed-in buyer picks a tier. The order pins the BTC amount at
     the live CoinGecko rate (see app/billing.py) and shows Jay's
     receive address from RECON_BTC_ADDRESS (never invented; when it
     is unset the watcher reports disabled and checkout stays closed).
  2. The buyer inputs the public wallet address they will send FROM,
     then pays manually from their own wallet app. No wallet
     connection, no signing, no private keys anywhere, ever. The app
     never sends crypto anywhere and never takes custody.
  3. The watcher polls the public mempool.space explorer API (no key,
     read-only) for transactions to Jay's receive address and unlocks
     the picked tier when a qualifying payment confirms.

Policies (stated here, in the buyer copy, and on the status payload):
  - Confirmation policy: 2 confirmations before unlock. A transaction
    seen with 0-1 confirmations is recorded but does NOT unlock.
  - Invoice expiry: 60 minutes from order creation. A payment that
    confirms after expiry does NOT unlock; the transaction is recorded
    on the watch row so the owner can resolve it manually.
  - Tolerance: 1%. A payment qualifies when the amount sent to Jay's
    address is at least 99% of the pinned amount (dust/rounding slack).
    Below that it is an underpayment: no unlock, and the status shows
    the shortfall in sats.
  - Change addresses: BTC wallets usually send change back to the
    payer, so the "from the declared address" check is: at least one
    transaction input spends from the declared address. The binding
    check is the amount sent TO Jay's address. A payment from an
    exchange hot wallet, or from any address other than the declared
    one, does NOT match: the buyer must send from a wallet they
    control, from the declared address.
  - Single use: one transaction unlocks one purchase. A txid already
    claimed by another watch is never reused (unique constraint on
    the watch table plus a pre-unlock check).
  - Overpayments unlock the picked tier only; the excess is NOT
    refunded automatically (stated in the buyer copy).
  - Wrong recipient: a transaction to any address other than Jay's
    receive address never unlocks anything.

Explorer pagination note: mempool.space returns 25 transactions per
page. The watcher pages up to 5 pages (125 recent transactions) on
Jay's receive address. A payment older than that window is missed by
the automatic watcher and falls back to owner manual approval at
/admin/orders, which still works exactly as before.

This module never asks for, stores, displays, or logs a private key,
seed phrase, or wallet connection. Payer addresses are public
on-chain data the buyer voluntarily provides for payment matching.
"""
from __future__ import annotations

import datetime as dt
import os
import time
from decimal import Decimal, ROUND_DOWN
from typing import Dict, List, Optional

# ------------------------------------------------------------ policies

REQUIRED_CONFIRMATIONS = 2
INVOICE_EXPIRY_MINUTES = 60
TOLERANCE_PCT = 1.0
MEMPOOL_BASE = "https://mempool.space/api"
MEMPOOL_PAGES = 5
MEMPOOL_PAGE_SIZE = 25

# Bech32 character set (BIP-173).
_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: List[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i, g in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA,
                               0x3D4233DD, 0x2A1462B3)):
            if (top >> i) & 1:
                chk ^= g
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data: List[int], frombits: int, tobits: int,
                 pad: bool = True) -> Optional[List[int]]:
    acc = 0
    bits = 0
    out: List[int] = []
    maxv = (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return out


def valid_btc_address(addr: Optional[str]) -> bool:
    """Format + checksum validation for a BTC payment address.

    Accepts bech32/bech32m segwit addresses (bc1q / bc1p, checksum
    verified, witness program 20 or 32 bytes) and legacy base58
    addresses (1... / 3..., charset + length format check only).
    This is a UX guard: mempool.space is the authority on whether an
    address exists on chain.
    """
    if not addr or not isinstance(addr, str):
        return False
    s = addr.strip()
    if s.startswith("bc1"):
        low = s.lower()
        if low != s and s.upper() != s:
            return False
        pos = low.rfind("1")
        if pos < 1 or pos + 7 > len(low):
            return False
        hrp, part = low[:pos], low[pos + 1:]
        if hrp != "bc":
            return False
        try:
            data = [_B32.index(c) for c in part]
        except ValueError:
            return False
        pm = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
        if pm not in (1, 0x2BC830A3):
            return False
        # data[0] is the witness version; the rest is the program.
        version = data[0]
        if (s.startswith("bc1q") and version != 0) or \
           (s.startswith("bc1p") and version != 1):
            return False
        prog = _convertbits(data[1:-6], 5, 8, pad=False)
        if prog is None:
            return False
        if version == 0:
            return len(prog) in (20, 32)
        return len(prog) == 32
    if s[0] in ("1", "3") and 26 <= len(s) <= 35:
        b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        return all(c in b58 for c in s)
    return False


# ------------------------------------------------------------ amounts

def btc_to_sats(amount_btc: str) -> int:
    """Exact BTC decimal string -> sats (rounded down, never up)."""
    return int((Decimal(str(amount_btc)) * Decimal(100_000_000))
               .to_integral_value(rounding=ROUND_DOWN))


def threshold_sats(expected_sats: int) -> int:
    """Qualifying amount: expected minus the 1% tolerance."""
    return expected_sats - expected_sats // 100


def _as_utc(moment) -> dt.datetime:
    if moment is None:
        return dt.datetime.now(dt.timezone.utc)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=dt.timezone.utc)
    return moment


def expires_at(order) -> dt.datetime:
    return _as_utc(order.created_at) + dt.timedelta(
        minutes=INVOICE_EXPIRY_MINUTES)


# ------------------------------------------------------------ explorer

class MempoolFetcher:
    """Read-only mempool.space client (no key). Injectable for tests:
    any object with address_txs(addr) -> list[dict] and
    tip_height() -> int works in its place."""

    def __init__(self, base: Optional[str] = None, timeout: float = 15.0):
        self.base = (base or os.environ.get("MEMPOOL_API_BASE")
                     or MEMPOOL_BASE).rstrip("/")
        self.timeout = timeout

    def _get(self, path: str):
        import httpx
        r = httpx.get(f"{self.base}{path}", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def address_txs(self, address: str) -> List[Dict]:
        """Recent transactions for an address, newest first, paged."""
        out: List[Dict] = []
        page = self._get(f"/address/{address}/txs")
        out.extend(page or [])
        last_txid = page[-1]["txid"] if page else None
        for _ in range(MEMPOOL_PAGES - 1):
            if not page or len(page) < MEMPOOL_PAGE_SIZE or not last_txid:
                break
            page = self._get(f"/address/{address}/txs/chain/{last_txid}")
            out.extend(page or [])
            last_txid = page[-1]["txid"] if page else None
        return out

    def tip_height(self) -> int:
        return int(self._get("/blocks/tip/height"))


def watcher_enabled() -> bool:
    from . import billing
    return bool(billing.btc_address())


def receive_address() -> str:
    from . import billing
    return billing.btc_address()


def cron_secret() -> str:
    return os.environ.get("PAYWATCH_CRON_SECRET", "").strip()


# ------------------------------------------------------------ matching

def match_payment(txs: List[Dict], payer_address: Optional[str],
                  receive_addr: str, expected_sats: int,
                  tip_height: int) -> Dict:
    """Pure payment matcher over one explorer transaction list.

    Returns {"match": candidate|None, "best_seen_sats": int,
    "best_seen_txid": str|None}. A candidate must spend from the
    declared payer address AND send at least the threshold amount to
    the receive address. Confirmations come from the chain tip; an
    unconfirmed transaction reports 0.
    """
    need = threshold_sats(expected_sats)
    best_seen_sats = 0
    best_seen_txid: Optional[str] = None
    candidates: List[Dict] = []
    for tx in txs or []:
        vouts = tx.get("vout") or []
        to_receive = sum(
            int(v.get("value") or 0) for v in vouts
            if v.get("scriptpubkey_address") == receive_addr)
        if to_receive <= 0:
            continue
        from_payer = False
        if payer_address:
            for vin in tx.get("vin") or []:
                prev = vin.get("prevout") or {}
                if prev.get("scriptpubkey_address") == payer_address:
                    from_payer = True
                    break
        if not from_payer:
            continue
        if to_receive > best_seen_sats:
            best_seen_sats = to_receive
            best_seen_txid = tx.get("txid")
        if to_receive < need:
            continue
        status = tx.get("status") or {}
        if status.get("confirmed") and status.get("block_height") is not None:
            confs = tip_height - int(status["block_height"]) + 1
        else:
            confs = 0
        candidates.append({
            "txid": tx.get("txid"),
            "received_sats": to_receive,
            "confirmations": max(confs, 0),
        })
    candidates.sort(key=lambda c: (c["confirmations"], c["received_sats"]),
                    reverse=True)
    return {"match": candidates[0] if candidates else None,
            "best_seen_sats": best_seen_sats,
            "best_seen_txid": best_seen_txid}


# ------------------------------------------------------------ activation

def activate_order(session, order, now: dt.datetime) -> None:
    """Mark an order paid and activate the buyer's plan for 30 days.
    Shared by the watcher unlock and the owner manual-approval route
    so the two can never drift apart."""
    from . import billing
    order.status = "paid"
    order.paid_at = now
    buyer = session.query(_User).filter_by(id=order.user_id).first()
    if buyer is not None:
        buyer.plan = order.plan
        buyer.plan_expires_at = now + dt.timedelta(
            days=billing.PLAN_DURATION_DAYS)


# Imported lazily to avoid a models import cycle at module load.
from .models import PaymentWatch, User as _User  # noqa: E402


def watch_payload(watch, order) -> Dict:
    """Buyer-safe watch status (no secrets exist on this path)."""
    if watch is None:
        return {"status": "none", "watcher_enabled": watcher_enabled()}
    need = watch.threshold_sats
    seen = watch.seen_sats or 0
    return {
        "status": watch.status,
        "watcher_enabled": watcher_enabled(),
        "payer_address": watch.payer_address,
        "expected_sats": watch.expected_sats,
        "threshold_sats": need,
        "seen_sats": seen,
        "shortfall_sats": max(need - seen, 0) if seen else need,
        "txid": watch.txid,
        "confirmations": watch.confirmations,
        "required_confirmations": REQUIRED_CONFIRMATIONS,
        "expires_at": expires_at(order).isoformat(),
        "last_checked_at": (watch.last_checked_at.isoformat()
                            if watch.last_checked_at else None),
        "late_payment_note": watch.late_payment_note,
    }


def check_order(session, order, fetcher=None,
                now: Optional[dt.datetime] = None) -> Dict:
    """Run one watcher check for one order. Idempotent: a confirmed
    watch, or an already-paid order, is never re-processed.

    Returns a small result dict; the caller commits via the session.
    Raises ValueError when the watch row is missing, RuntimeError
    when the watcher is disabled (no receive address configured).
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    watch = session.query(PaymentWatch).filter_by(
        order_id=order.id).first()
    if watch is None:
        raise ValueError("no payment watch for this order")
    if watch.status == "confirmed" or order.status == "paid":
        return {"action": "already_paid", "watch": watch_payload(watch, order)}
    if not watcher_enabled():
        return {"action": "watcher_disabled",
                "watch": watch_payload(watch, order)}
    fetcher = fetcher or MempoolFetcher()
    expired = now > expires_at(order)
    try:
        txs = fetcher.address_txs(receive_address())
        tip = fetcher.tip_height()
    except Exception as exc:
        watch.last_checked_at = now
        return {"action": "explorer_error", "error": str(exc)[:200],
                "watch": watch_payload(watch, order)}
    res = match_payment(txs, watch.payer_address, receive_address(),
                        watch.expected_sats, tip)
    cand = res["match"]
    watch.seen_sats = max(watch.seen_sats or 0, res["best_seen_sats"])
    if res["best_seen_txid"]:
        watch.seen_txid = res["best_seen_txid"]
    watch.last_checked_at = now
    if cand is not None:
        watch.confirmations = cand["confirmations"]
        if cand["confirmations"] >= REQUIRED_CONFIRMATIONS:
            if expired:
                # Paid late: recorded for manual resolution, never
                # auto-unlocked.
                watch.status = "expired"
                watch.late_payment_note = (
                    f"qualifying tx {cand['txid']} confirmed after "
                    f"invoice expiry; owner manual resolution required")
                return {"action": "paid_late",
                        "watch": watch_payload(watch, order)}
            clash = (session.query(PaymentWatch)
                     .filter(PaymentWatch.txid == cand["txid"],
                             PaymentWatch.order_id != order.id)
                     .first())
            if clash is not None:
                watch.status = "underpaid"
                watch.late_payment_note = (
                    f"tx {cand['txid']} already claimed by another "
                    f"purchase; not reused")
                return {"action": "txid_reused",
                        "watch": watch_payload(watch, order)}
            watch.txid = cand["txid"]
            watch.tx_received_sats = cand["received_sats"]
            watch.status = "confirmed"
            activate_order(session, order, now)
            return {"action": "unlocked",
                    "watch": watch_payload(watch, order)}
        return {"action": "confirming",
                "watch": watch_payload(watch, order)}
    if expired:
        watch.status = "expired"
        return {"action": "expired", "watch": watch_payload(watch, order)}
    if res["best_seen_sats"] > 0:
        watch.status = "underpaid"
        return {"action": "underpaid", "watch": watch_payload(watch, order)}
    watch.status = "pending"
    return {"action": "pending", "watch": watch_payload(watch, order)}


def sweep_pending(session, fetcher=None,
                  now: Optional[dt.datetime] = None) -> Dict:
    """Check every still-open watch. Skips orders already paid and
    watches already terminal. Returns action counts."""
    from .models import Order
    now = now or dt.datetime.now(dt.timezone.utc)
    counts = {"checked": 0, "unlocked": 0, "confirming": 0,
              "underpaid": 0, "pending": 0, "expired": 0,
              "paid_late": 0, "errors": 0}
    if not watcher_enabled():
        return {"watcher_enabled": False, **counts}
    fetcher = fetcher or MempoolFetcher()
    rows = (session.query(PaymentWatch)
            .filter(PaymentWatch.status.in_(["pending", "underpaid"]))
            .all())
    for watch in rows:
        order = session.query(Order).filter_by(id=watch.order_id).first()
        if order is None or order.status != "pending":
            continue
        counts["checked"] += 1
        try:
            res = check_order(session, order, fetcher=fetcher, now=now)
        except Exception:
            counts["errors"] += 1
            continue
        action = res["action"]
        if action in counts:
            counts[action] += 1
        elif action in ("already_paid", "watcher_disabled", "txid_reused"):
            pass
        else:
            counts["errors"] += 1
    session.commit()
    return {"watcher_enabled": True, **counts}


def get_or_create_watch(session, order, payer_address: Optional[str]):
    """Create the watch row for a fresh order (idempotent)."""
    from .models import PaymentWatch
    watch = session.query(PaymentWatch).filter_by(
        order_id=order.id).first()
    if watch is not None:
        return watch
    expected = btc_to_sats(order.amount_btc)
    watch = PaymentWatch(
        order_id=order.id, user_id=order.user_id,
        payer_address=payer_address, expected_sats=expected,
        threshold_sats=threshold_sats(expected), status="pending")
    session.add(watch)
    return watch
