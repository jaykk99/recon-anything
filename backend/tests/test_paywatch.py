"""Tests for the DIY BTC payment watcher (app/paywatch.py + wiring).

Covers the buyer flow end to end with mocked explorer responses:
exact payment unlocks, underpayment does not unlock, a replayed txid
does not double-unlock, an expired invoice does not unlock, a
wrong-recipient transaction does not unlock, and the cron endpoint's
auth. Network-free except one skip-safe live read-only check against
mempool.space proving the explorer path works.

Mirrors test_billing.py: temp SQLite DB via FastAPI TestClient, BTC
rate monkeypatched. No real money moves anywhere in this file.
"""
import datetime as dt
import os
import sys
import tempfile

if "DATABASE_URL" not in os.environ:
    _tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    _tmp.close()
    os.environ["DATABASE_URL"] = "sqlite:///" + _tmp.name

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import billing, paywatch  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Order, PaymentWatch, User, get_session, init_db  # noqa: E402

RECEIVE = None  # filled by _addr() below (valid bech32, generated)
PAYER = None


def _bech32_encode(hrp: str, prog: bytes) -> str:
    data5 = paywatch._convertbits(list(prog), 8, 5, pad=True)
    values = paywatch._bech32_hrp_expand(hrp) + [0] + data5 + [0] * 6
    pm = paywatch._bech32_polymod(values) ^ 1
    chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    body = [0] + data5 + chk
    return hrp + "1" + "".join(paywatch._B32[d] for d in body)


RECEIVE = _bech32_encode("bc", b"\x11" * 20)
PAYER = _bech32_encode("bc", b"\x22" * 20)
OTHER = _bech32_encode("bc", b"\x33" * 20)

os.environ["RECON_BTC_ADDRESS"] = RECEIVE
os.environ["PAYWATCH_CRON_SECRET"] = "test-cron-secret"


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _rate(monkeypatch):
    monkeypatch.setattr(billing, "fetch_btc_usd", lambda: 100000.0)


_counter = {"n": 900000}


def _mk_user(login, plan="free"):
    _counter["n"] += 1
    session = get_session()
    try:
        u = User(github_id=_counter["n"], github_login=login, plan=plan)
        session.add(u)
        session.commit()
        uid = u.id
    finally:
        session.close()
    return uid


def _cookie(uid):
    return {"Cookie": f"{billing.SESSION_COOKIE}="
                      f"{billing.make_session_token(uid)}"}


class FakeFetcher:
    def __init__(self, txs, tip=800000):
        self.txs = txs
        self.tip = tip

    def address_txs(self, addr):
        assert addr == RECEIVE
        return self.txs

    def tip_height(self):
        return self.tip


def _tx(txid, vin_addrs, vouts, confirmed=True, height=799999):
    return {
        "txid": txid,
        "status": {"confirmed": confirmed, "block_height": height
                   if confirmed else None},
        "vin": [{"prevout": {"scriptpubkey_address": a, "value": 50000}}
                for a in vin_addrs],
        "vout": [{"scriptpubkey_address": a, "value": v} for a, v in vouts],
    }


def _mk_order(client, uid, plan="starter", payer=None):
    body = {"plan": plan}
    if payer:
        body["payer_address"] = payer
    r = client.post("/api/orders", json=body, headers=_cookie(uid))
    assert r.status_code == 200, r.text
    assert r.json()["checkout_open"] is True
    return r.json()["order"]


# ------------------------------------------------------------ pure match

def test_valid_btc_address():
    assert paywatch.valid_btc_address(RECEIVE) is True
    assert paywatch.valid_btc_address(PAYER) is True
    assert paywatch.valid_btc_address("not-an-address") is False
    assert paywatch.valid_btc_address(RECEIVE[:-1] + "x") is False
    assert paywatch.valid_btc_address("") is False
    assert paywatch.valid_btc_address(None) is False


def test_threshold_math():
    assert paywatch.btc_to_sats("0.00019000") == 19000
    assert paywatch.threshold_sats(19000) == 18810
    assert paywatch.threshold_sats(100) == 99


def test_match_exact_qualifies():
    txs = [_tx("tx1", [PAYER], [(RECEIVE, 19000)])]
    res = paywatch.match_payment(txs, PAYER, RECEIVE, 19000, 800000)
    assert res["match"]["txid"] == "tx1"
    assert res["match"]["confirmations"] == 2
    assert res["best_seen_sats"] == 19000


def test_match_change_outputs_still_qualify():
    txs = [_tx("tx1", [PAYER], [(RECEIVE, 19000), (PAYER, 30000)])]
    res = paywatch.match_payment(txs, PAYER, RECEIVE, 19000, 800000)
    assert res["match"]["txid"] == "tx1"


def test_match_unconfirmed_does_not_qualify():
    txs = [_tx("tx1", [PAYER], [(RECEIVE, 19000)], confirmed=False)]
    res = paywatch.match_payment(txs, PAYER, RECEIVE, 19000, 800000)
    assert res["match"]["confirmations"] == 0


def test_match_one_confirmation_does_not_qualify():
    txs = [_tx("tx1", [PAYER], [(RECEIVE, 19000)], height=800000)]
    res = paywatch.match_payment(txs, PAYER, RECEIVE, 19000, 800000)
    assert res["match"]["confirmations"] == 1


def test_match_wrong_recipient_no_match():
    txs = [_tx("tx1", [PAYER], [(OTHER, 19000)])]
    res = paywatch.match_payment(txs, PAYER, RECEIVE, 19000, 800000)
    assert res["match"] is None
    assert res["best_seen_sats"] == 0


def test_match_wrong_sender_no_match():
    txs = [_tx("tx1", [OTHER], [(RECEIVE, 19000)])]
    res = paywatch.match_payment(txs, PAYER, RECEIVE, 19000, 800000)
    assert res["match"] is None


def test_match_underpayment_no_candidate_but_best_seen():
    txs = [_tx("tx1", [PAYER], [(RECEIVE, 10000)])]
    res = paywatch.match_payment(txs, PAYER, RECEIVE, 19000, 800000)
    assert res["match"] is None
    assert res["best_seen_sats"] == 10000
    assert res["best_seen_txid"] == "tx1"


def test_match_overpayment_qualifies():
    txs = [_tx("tx1", [PAYER], [(RECEIVE, 50000)])]
    res = paywatch.match_payment(txs, PAYER, RECEIVE, 19000, 800000)
    assert res["match"]["received_sats"] == 50000


# ------------------------------------------------------------ API flow

def test_full_flow_unlocks(client, monkeypatch):
    uid = _mk_user("buyer-full")
    order = _mk_order(client, uid, payer=PAYER)
    assert order["watch"]["status"] == "pending"
    assert order["watch"]["expected_sats"] == 19000
    fake = FakeFetcher([_tx("tx-full", [PAYER], [(RECEIVE, 19000)])])
    monkeypatch.setattr(paywatch, "MempoolFetcher", lambda: fake)
    r = client.post(f"/api/orders/{order['id']}/check-payment",
                    headers=_cookie(uid))
    assert r.status_code == 200, r.text
    assert r.json()["action"] == "unlocked"
    assert r.json()["order"]["status"] == "paid"
    session = get_session()
    try:
        u = session.query(User).filter_by(id=uid).first()
        assert u.plan == "starter"
        assert u.plan_expires_at is not None
        w = session.query(PaymentWatch).filter_by(
            order_id=order["id"]).first()
        assert w.status == "confirmed" and w.txid == "tx-full"
    finally:
        session.close()


def test_underpayment_does_not_unlock(client, monkeypatch):
    uid = _mk_user("buyer-short")
    order = _mk_order(client, uid, payer=PAYER)
    fake = FakeFetcher([_tx("tx-short", [PAYER], [(RECEIVE, 10000)])])
    monkeypatch.setattr(paywatch, "MempoolFetcher", lambda: fake)
    r = client.post(f"/api/orders/{order['id']}/check-payment",
                    headers=_cookie(uid))
    assert r.json()["action"] == "underpaid"
    w = r.json()["order"]["watch"]
    assert w["status"] == "underpaid"
    assert w["seen_sats"] == 10000
    assert w["shortfall_sats"] == 18810 - 10000
    assert r.json()["order"]["status"] == "pending"


def test_replayed_txid_does_not_double_unlock(client, monkeypatch):
    uid_a = _mk_user("buyer-replay-a")
    order_a = _mk_order(client, uid_a, payer=PAYER)
    fake = FakeFetcher([_tx("tx-replay", [PAYER], [(RECEIVE, 19000)])])
    monkeypatch.setattr(paywatch, "MempoolFetcher", lambda: fake)
    r = client.post(f"/api/orders/{order_a['id']}/check-payment",
                    headers=_cookie(uid_a))
    assert r.json()["action"] == "unlocked"
    uid_b = _mk_user("buyer-replay-b")
    order_b = _mk_order(client, uid_b, payer=PAYER)
    r = client.post(f"/api/orders/{order_b['id']}/check-payment",
                    headers=_cookie(uid_b))
    assert r.json()["action"] == "txid_reused"
    assert r.json()["order"]["status"] == "pending"


def test_expired_invoice_does_not_unlock(client, monkeypatch):
    uid = _mk_user("buyer-expired")
    order = _mk_order(client, uid, payer=PAYER)
    session = get_session()
    try:
        o = session.query(Order).filter_by(id=order["id"]).first()
        o.created_at = (dt.datetime.now(dt.timezone.utc)
                        - dt.timedelta(minutes=61))
        session.commit()
    finally:
        session.close()
    fake = FakeFetcher([_tx("tx-late", [PAYER], [(RECEIVE, 19000)])])
    monkeypatch.setattr(paywatch, "MempoolFetcher", lambda: fake)
    r = client.post(f"/api/orders/{order['id']}/check-payment",
                    headers=_cookie(uid))
    assert r.json()["action"] == "paid_late"
    assert r.json()["order"]["status"] == "pending"
    assert r.json()["order"]["watch"]["status"] == "expired"
    assert r.json()["order"]["watch"]["late_payment_note"]


def test_wrong_recipient_does_not_unlock(client, monkeypatch):
    uid = _mk_user("buyer-wrong")
    order = _mk_order(client, uid, payer=PAYER)
    fake = FakeFetcher([_tx("tx-wrong", [PAYER], [(OTHER, 19000)])])
    monkeypatch.setattr(paywatch, "MempoolFetcher", lambda: fake)
    r = client.post(f"/api/orders/{order['id']}/check-payment",
                    headers=_cookie(uid))
    assert r.json()["action"] == "pending"
    assert r.json()["order"]["status"] == "pending"


def test_unconfirmed_does_not_unlock(client, monkeypatch):
    uid = _mk_user("buyer-unconf")
    order = _mk_order(client, uid, payer=PAYER)
    fake = FakeFetcher([_tx("tx-unconf", [PAYER], [(RECEIVE, 19000)],
                             confirmed=False)])
    monkeypatch.setattr(paywatch, "MempoolFetcher", lambda: fake)
    r = client.post(f"/api/orders/{order['id']}/check-payment",
                    headers=_cookie(uid))
    assert r.json()["action"] == "confirming"
    assert r.json()["order"]["status"] == "pending"


def test_payer_address_endpoint(client):
    uid = _mk_user("buyer-payer")
    order = _mk_order(client, uid)
    assert order["watch"]["payer_address"] is None
    r = client.post(f"/api/orders/{order['id']}/payer-address",
                    json={"payer_address": PAYER}, headers=_cookie(uid))
    assert r.status_code == 200, r.text
    assert r.json()["order"]["watch"]["payer_address"] == PAYER
    r = client.post(f"/api/orders/{order['id']}/payer-address",
                    json={"payer_address": "garbage"}, headers=_cookie(uid))
    assert r.status_code == 400
    other = _mk_user("buyer-payer-other")
    r = client.post(f"/api/orders/{order['id']}/payer-address",
                    json={"payer_address": PAYER}, headers=_cookie(other))
    assert r.status_code == 404


def test_cron_endpoint_auth(client, monkeypatch):
    monkeypatch.setattr(paywatch, "MempoolFetcher",
                        lambda: FakeFetcher([]))
    r = client.post("/api/cron/paywatch")
    assert r.status_code == 403
    r = client.post("/api/cron/paywatch",
                    headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 403
    r = client.post("/api/cron/paywatch",
                    headers={"Authorization": "Bearer test-cron-secret"})
    assert r.status_code == 200, r.text
    assert r.json()["watcher_enabled"] is True
    owner = _mk_user("jaykk99")
    r = client.post("/api/cron/paywatch", headers=_cookie(owner))
    assert r.status_code == 200, r.text


def test_cron_disabled_without_receive_address(client, monkeypatch):
    monkeypatch.setenv("RECON_BTC_ADDRESS", "")
    r = client.post("/api/cron/paywatch",
                    headers={"Authorization": "Bearer test-cron-secret"})
    assert r.status_code == 200
    assert r.json()["watcher_enabled"] is False


def test_admin_approve_still_works(client):
    uid = _mk_user("buyer-manual")
    order = _mk_order(client, uid, payer=PAYER)
    owner = _mk_user("jaykk99")
    r = client.post(f"/api/admin/orders/{order['id']}/approve",
                    headers=_cookie(owner))
    assert r.status_code == 200, r.text
    assert r.json()["order"]["status"] == "paid"
    session = get_session()
    try:
        u = session.query(User).filter_by(id=uid).first()
        assert u.plan == "starter"
    finally:
        session.close()


def test_live_mempool_readonly():
    """One live read-only check: mempool.space serves address txs
    without a key. Skipped when the network is unavailable so CI
    without egress never goes red on it."""
    import httpx
    try:
        r = httpx.get(
            "https://mempool.space/api/address/"
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa/txs", timeout=15)
    except Exception as exc:
        pytest.skip(f"no egress to mempool.space: {exc}")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
