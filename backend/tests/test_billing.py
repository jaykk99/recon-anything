"""Tests for the sellable-product layer (app/billing.py + main.py wiring).

Covers: owner bypass (jaykk99 gets full access and NO payment UI data),
the free-tier reveal cap (exactly 1 finding per UTC day, resetting the
next day), plan gating (scan limits, crypto-pack gating, run
ownership), and BTC order math + the owner-approval activation flow.

Network-free: temp SQLite DB via FastAPI TestClient; the BTC rate
fetcher is monkeypatched where an order is created.
"""
import datetime as dt
import os
import sys
import tempfile
from decimal import Decimal

# Env must be set before app.main is imported (engine binds at import).
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ["DATABASE_URL"] = "sqlite:///" + _tmp.name

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import billing  # noqa: E402
from app.main import app  # noqa: E402
from app.models import (Finding, FindingReveal, Order, Run, User,  # noqa: E402
                        get_session, init_db)

BTC_ADDR = "bc1qtestaddress0000000000000000000000000"


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


_counter = {"n": 1000}


def _mk_user(login, plan="free", expires=None):
    _counter["n"] += 1
    session = get_session()
    try:
        u = User(github_id=_counter["n"], github_login=login, plan=plan,
                 plan_expires_at=expires)
        session.add(u)
        session.commit()
        uid = u.id
    finally:
        session.close()
    return uid


def _cookie(uid):
    return {"Cookie": f"{billing.SESSION_COOKIE}="
                      f"{billing.make_session_token(uid)}"}


def _mk_run(run_id, user_id=None, n_findings=3):
    session = get_session()
    try:
        session.add(Run(id=run_id, mode="passive", status="done",
                        source_type="website", user_id=user_id, summary={}))
        for j in range(n_findings):
            session.add(Finding(run_id=run_id, target_id="t",
                                plugin_id="dns", category="infra",
                                key="record", value=f"secret-value-{j}",
                                source="test"))
        session.commit()
    finally:
        session.close()


def _cleanup():
    session = get_session()
    try:
        session.query(FindingReveal).delete()
        session.query(Order).delete()
        session.query(Finding).delete()
        session.query(Run).delete()
        session.query(User).delete()
        session.commit()
    finally:
        session.close()


# ------------------------------------------------------------ owner bypass

def test_owner_bypass_no_payment_ui(client):
    _cleanup()
    uid = _mk_user("jaykk99")
    r = client.get("/api/me", headers=_cookie(uid))
    assert r.status_code == 200
    body = r.json()
    assert body["is_owner"] is True
    assert body["show_payment_ui"] is False
    # No payment UI data at all for the owner account.
    assert "checkout_enabled" not in body
    assert body["plan"]["id"] == "owner"
    assert body["plan"]["full_findings"] is True


def test_owner_needs_no_order(client):
    _cleanup()
    uid = _mk_user("jaykk99")
    r = client.post("/api/orders", json={"plan": "pro"},
                    headers=_cookie(uid))
    assert r.status_code == 400


def test_owner_plan_ignores_expiry_and_free_plan(client):
    _cleanup()
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    uid = _mk_user("jaykk99", plan="free", expires=past)
    session = get_session()
    try:
        user = session.query(User).filter_by(id=uid).first()
        assert billing.effective_plan(user)["id"] == "owner"
    finally:
        session.close()


def test_anonymous_me_is_free_with_payment_ui(client):
    _cleanup()
    r = client.get("/api/me")
    body = r.json()
    assert body["signed_in"] is False
    assert body["is_owner"] is False
    assert body["show_payment_ui"] is True
    assert body["plan"]["id"] == "free"


# ------------------------------------------------------- free reveal cap

def test_free_tier_reveals_exactly_one_per_day(client):
    _cleanup()
    uid = _mk_user("free-user-1")
    _mk_run("bill-run-a", user_id=uid, n_findings=3)
    r = client.get("/api/runs/bill-run-a", headers=_cookie(uid))
    assert r.status_code == 200
    body = r.json()
    assert body["access"]["full_findings"] is False
    assert body["access"]["total_findings"] == 3
    assert body["access"]["locked_count"] == 2
    revealed = [f for f in body["findings"] if not f.get("locked")]
    assert len(revealed) == 1
    assert revealed[0]["value"] != billing.LOCKED_VALUE
    assert body["access"]["revealed_finding_id"] == revealed[0]["id"]
    locked = [f for f in body["findings"] if f.get("locked")]
    assert all(f["value"] == billing.LOCKED_VALUE for f in locked)
    assert all(f["evidence"] is None for f in locked)


def test_free_tier_cap_is_per_day_across_runs_and_resets(client):
    _cleanup()
    uid = _mk_user("free-user-2")
    _mk_run("bill-run-b1", user_id=uid, n_findings=2)
    _mk_run("bill-run-b2", user_id=uid, n_findings=2)
    r1 = client.get("/api/runs/bill-run-b1", headers=_cookie(uid)).json()
    assert r1["access"]["locked_count"] == 1
    # Same day, second run: the day's one reveal is already spent.
    r2 = client.get("/api/runs/bill-run-b2", headers=_cookie(uid)).json()
    assert r2["access"]["locked_count"] == 2
    assert all(f.get("locked") for f in r2["findings"])
    # Next day: age the reveal row, and a fresh finding is revealed.
    session = get_session()
    try:
        row = session.query(FindingReveal).filter_by(user_id=uid).first()
        row.day = "2000-01-01"
        session.commit()
    finally:
        session.close()
    r3 = client.get("/api/runs/bill-run-b2", headers=_cookie(uid)).json()
    assert r3["access"]["locked_count"] == 1
    revealed = [f for f in r3["findings"] if not f.get("locked")]
    assert len(revealed) == 1


def test_paid_plan_sees_full_findings(client):
    _cleanup()
    uid = _mk_user("pro-user-1", plan="pro")
    _mk_run("bill-run-c", user_id=uid, n_findings=3)
    body = client.get("/api/runs/bill-run-c", headers=_cookie(uid)).json()
    assert body["access"]["full_findings"] is True
    assert body["access"]["locked_count"] == 0
    assert all(f["value"].startswith("secret-value-")
               for f in body["findings"])


def test_expired_paid_plan_falls_back_to_free(client):
    _cleanup()
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    uid = _mk_user("expired-pro", plan="pro", expires=past)
    _mk_run("bill-run-d", user_id=uid, n_findings=2)
    body = client.get("/api/runs/bill-run-d", headers=_cookie(uid)).json()
    assert body["access"]["full_findings"] is False
    assert body["access"]["locked_count"] == 1


# ------------------------------------------------------------ plan gating

def test_customer_cannot_open_another_users_run(client):
    _cleanup()
    owner_uid = _mk_user("run-owner")
    other_uid = _mk_user("run-peeker")
    _mk_run("bill-run-e", user_id=owner_uid, n_findings=1)
    r = client.get("/api/runs/bill-run-e", headers=_cookie(other_uid))
    assert r.status_code == 404


def test_free_scan_daily_limit(client):
    _cleanup()
    uid = _mk_user("scan-limited")
    for i in range(3):  # free plan: 3 scans/day
        _mk_run(f"bill-scan-{i}", user_id=uid, n_findings=0)
    r = client.post("/api/runs",
                    json={"targets": "example.com", "mode": "passive"},
                    headers=_cookie(uid))
    assert r.status_code == 429


def test_crypto_pack_blocked_for_free_user(client):
    _cleanup()
    uid = _mk_user("crypto-free")
    r = client.post("/api/runs",
                    json={"targets": "example.com", "mode": "passive",
                          "plugins": ["cp_wallet_exposure"]},
                    headers=_cookie(uid))
    assert r.status_code == 403


def test_plugin_filter_pure():
    free = billing.PLANS["free"]
    pro = billing.PLANS["pro"]
    allowed, stripped = billing.filter_plugins_for_plan(
        free, ["dns", "cp_wallet_exposure", "tls"])
    assert allowed == ["dns", "tls"]
    assert stripped == ["cp_wallet_exposure"]
    allowed, stripped = billing.filter_plugins_for_plan(
        pro, ["dns", "cp_wallet_exposure"])
    assert allowed == ["dns", "cp_wallet_exposure"]
    assert stripped == []
    excl = billing.excluded_plugins_for_plan(
        free, ["dns", "cp_a", "tls", "cp_b"])
    assert excl == ["cp_a", "cp_b"]
    assert billing.excluded_plugins_for_plan(pro, ["cp_a"]) == []


# --------------------------------------------------------------- BTC orders

def test_btc_order_math():
    assert billing.btc_amount_for_usd(49, 100000) == Decimal("0.00049000")
    assert billing.btc_amount_for_usd(19, 65000) == Decimal("0.00029230")
    assert billing.btc_amount_for_usd(149, 50000) == Decimal("0.00298000")
    with pytest.raises(ValueError):
        billing.btc_amount_for_usd(49, 0)


def test_order_creation_and_owner_approval(client, monkeypatch):
    _cleanup()
    monkeypatch.setenv("RECON_BTC_ADDRESS", BTC_ADDR)
    monkeypatch.setattr(billing, "fetch_btc_usd", lambda: 100000.0)
    buyer = _mk_user("buyer-1")
    r = client.post("/api/orders", json={"plan": "pro"},
                    headers=_cookie(buyer))
    assert r.status_code == 200
    body = r.json()
    assert body["checkout_open"] is True
    order = body["order"]
    assert order["amount_usd"] == 49
    assert order["amount_btc"] == "0.00049000"
    assert order["btc_address"] == BTC_ADDR
    assert order["status"] == "pending"

    # A non-owner cannot use the admin endpoints.
    r = client.get("/api/admin/orders", headers=_cookie(buyer))
    assert r.status_code == 403

    # The owner sees the order and approves it: plan activates ~30 days.
    owner = _mk_user("jaykk99")
    r = client.get("/api/admin/orders", headers=_cookie(owner))
    assert r.status_code == 200
    assert any(o["id"] == order["id"] for o in r.json()["orders"])
    r = client.post(f"/api/admin/orders/{order['id']}/approve",
                    headers=_cookie(owner))
    assert r.status_code == 200
    assert r.json()["order"]["status"] == "paid"
    session = get_session()
    try:
        u = session.query(User).filter_by(id=buyer).first()
        assert u.plan == "pro"
        exp = u.plan_expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=dt.timezone.utc)
        assert exp > dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=29)
    finally:
        session.close()


def test_checkout_closed_without_btc_address(client, monkeypatch):
    _cleanup()
    monkeypatch.delenv("RECON_BTC_ADDRESS", raising=False)
    buyer = _mk_user("buyer-2")
    r = client.post("/api/orders", json={"plan": "starter"},
                    headers=_cookie(buyer))
    assert r.status_code == 200
    body = r.json()
    assert body["checkout_open"] is False
    assert body["status"] == "checkout_closed"
    session = get_session()
    try:
        assert session.query(Order).count() == 0
    finally:
        session.close()


def test_plans_endpoint_shape(client):
    r = client.get("/api/plans")
    assert r.status_code == 200
    plans = {p["id"]: p for p in r.json()["plans"]}
    assert plans["free"]["price_usd"] == 0
    assert plans["starter"]["price_usd"] == 19
    assert plans["pro"]["price_usd"] == 49
    assert plans["agency"]["price_usd"] == 149
    assert plans["pro"]["crypto_pack"] is True
    assert plans["free"]["full_findings"] is False


def test_github_signin_opens_soon_when_unconfigured(client, monkeypatch):
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_CLIENT_SECRET", raising=False)
    r = client.get("/api/auth/github", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/pricing?signin=soon"
    me = client.get("/api/me").json()
    assert me["github_enabled"] is False


def test_github_signin_redirects_when_configured(client, monkeypatch):
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-secret")
    r = client.get("/api/auth/github", follow_redirects=False)
    assert r.status_code == 303
    loc = r.headers["location"]
    assert loc.startswith("https://github.com/login/oauth/authorize?")
    assert "client_id=test-client-id" in loc
    assert "state=" in loc
    assert "recon_oauth_state" in r.headers.get("set-cookie", "")


def test_pricing_page_renders_tiers(client):
    r = client.get("/pricing")
    assert r.status_code == 200
    for text in ("Starter", "$19/mo", "Pro", "$49/mo", "Agency",
                 "$149/mo", "1 revealed finding per day"):
        assert text in r.text
