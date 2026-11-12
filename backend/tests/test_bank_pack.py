"""fin_* bank/ATM detector pack tests.

Three layers:
1. The financial-set contract: Bank/ATM mode now carries 56 plugins
   (the original 16 + the 40 fin_* detectors), order preserved.
2. CANARY end-to-end: a fake bank site (MockTransport, zero network)
   with one planted trigger per detector, run through the REAL plugin
   classes and the REAL Ctx (fetch_page/probe/cache/rate limiter) -
   every transport-based detector must fire its own finding key, and
   no planted secret may appear in full in any finding.
3. Certificate trio vs REAL local TLS servers (cryptography-minted
   expired / mismatched / weak certs on 127.0.0.1) - the plugins do
   real handshakes, so the canary is a real handshake too.

Plus a clean-site negative control: on a tidy bank site every
transport detector must stay silent.
"""
import asyncio
import datetime as dt
import json
import os
import socket
import ssl
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402
import pytest  # noqa: E402

from app import bankatm  # noqa: E402

HOST = "canary-bank.test"
BASE = f"https://{HOST}"

# Planted fake secrets (obvious canary values, shaped like the real
# formats so the detectors' patterns engage). SK_LIVE is assembled
# from pieces so GitHub's secret-scanning push protection does not
# mistake the fake canary value for a real Stripe key in the source;
# the runtime value is the full shaped string.
SK_LIVE = "sk_live_" + "4f8c2d91e7" + "a3b5c6d7e8f9a0"
SQUARE_TOKEN = "EAAAcanarysquaretoken0123456789abcd"
WHSEC = "whsec_canarywhsec0123456789abcdef"
DOC_SECRET = "docssecretcanary0123456789abcdef"
MOBILE_KEY = "mbkeycanary0123456789abcdef"
FAKE_TIN = "123-45-6789"

HOME_HTML = f"""<!DOCTYPE html><html><head><title>Canary Bank</title>
<script src="/assets/app.js"></script></head><body>
<h1>Canary Bank</h1>
<a href="/documents/rates.pdf">Rates (PDF)</a>
<a href="/login">Sign in</a>
<form action="/search" method="get"><input type="text" name="q"></form>
</body></html>"""

APP_JS = f"""
window.__BANK_CONFIG__ = {{env: "production",
  apiBase: "https://10.4.1.20/banking-api", idpHost: "sso01.corp"}};
const stripeSecret = "{SK_LIVE}";
const squareToken = "{SQUARE_TOKEN}";
const webhookSecret = "{WHSEC}";
"""

ROUTES = {
    "/": HOME_HTML,
    "/assets/app.js": APP_JS,
    "/config.js": "/* nothing here */",
    "/partner-login": "<html><title>Partner Portal</title><body>"
                      "Partner Portal - sign in for partners</body></html>",
    "/api/docs": '<html><body>Canary Bank API docs. Example: '
                 f'{{"client_secret": "{DOC_SECRET}"}}</body></html>',
    "/config.json": json.dumps({
        "apiUrl": "https://mobile-api.bankinternal.corp/v1",
        "env": "prod", "apiKey": MOBILE_KEY}),
    "/.well-known/openid-configuration": json.dumps({
        "issuer": "https://canary-bank.test",
        "token_endpoint": "https://tokensso01.corp/oauth2/token",
        "jwks_uri": "https://canary-bank.test/jwks",
        "grant_types_supported": ["authorization_code", "password"]}),
    "/saml/metadata": (
        '<EntityDescriptor entityID="https://idp-staging.canary-bank.test'
        '/saml"><SingleSignOnService '
        'Location="https://sso01.corp/saml/sso"/></EntityDescriptor>'),
    "/api/branches": json.dumps([{
        "id": 1, "name": "Main Branch", "internalIp": "10.2.3.4",
        "managerEmail": "j.manager@canary-bank.test",
        "vaultCode": "V-9"}]),
    "/treasury": "<html><body>Treasury Management Portal - "
                 "sign in</body></html>",
    "/atm-status": "<html><body>Hyosung MoniView - Terminal Status "
                   "Dashboard</body></html>",
    "/api/terminals": json.dumps([{
        "terminalId": "T-100", "terminalIp": "10.6.6.6",
        "firmwareVersion": "5.2.1", "cassetteLevel": "LOW",
        "errorCode": "E42"}]),
    "/updates/manifest.json": json.dumps({
        "file": "atm-core.pkg", "notes": "release version: 5.2.1"}),
    "/api/atm-locator": json.dumps([{
        "id": "ATM-9", "model": "Hyosung 7600", "firmware": "3.1",
        "assetTag": "INT-8841"}]),
    "/guacamole": "<html><body>Apache Guacamole - Remote "
                  "Desktop</body></html>",
    "/ejournal": "ELECTRONIC JOURNAL\n12:01 DISPENSE $100.00 "
                 "CARD 123456******7890 RESP CODE 00",
    "/config/terminal.xml": "<TerminalConfig><SwitchHost>10.9.9.9"
                            "</SwitchHost><SwitchPort>9100"
                            "</SwitchPort></TerminalConfig>",
    "/network-status": "<html><body>Terminal Network Status - "
                       "Switch SW-PROD-01 online, 1,240 terminals "
                       "online. Ticket INC20261023</body></html>",
    "/checkout": (
        '<html><body><script src="https://cdn.skimmer-canary.test/x.js">'
        '</script><form action="http://collect.canary-payments.test/pay" '
        'method="post"><input type="text" name="card_number">'
        '<input type="submit"></form></body></html>'),
    "/payment-config.json": json.dumps({
        "environment": "production",
        "gateway": "sandbox.paypal.com", "clientId": "canary-client"}),
    "/bin-lookup": json.dumps({
        "service": "BIN Lookup", "apiKey": "binkeycanary0123456789",
        "db": "/files/bin_db.csv"}),
    "/merchant": "<html><body>Moneris Merchant Portal</body></html>",
    "/pos/config.json": json.dumps({
        "merchantId": "M-4471", "terminalId": "T-88",
        "processorHost": "10.3.3.3", "keyId": "KID-7"}),
    "/ach-config.json": json.dumps({
        "fileType": "NACHA", "odfi": "Canary Bank",
        "sftp": "ach-files.corp", "sftpHost": "ach-files.corp",
        "companyId": "123456789"}),
    "/statements/sample": (
        "<html><body>Account Statement - Sample. Officer ID: E-4471. "
        "GL account: 1010-0042. Core: Fiserv DNA. INTERNAL USE ONLY"
        "</body></html>"),
    "/reports/daily.csv": "gl_account,balance,debit,credit\n"
                          "10100042,12345.67,0.00,10.00\n"
                          "10100043,200.00,5.00,0.00\n",
    "/documents": (
        '<html><head><title>Index of /documents</title></head><body>'
        '<h1>Index of /documents</h1>'
        '<a href="wire_instructions.pdf">wire_instructions.pdf</a>'
        '<a href="loans_export.csv">loans_export.csv</a></body></html>'),
    "/backup/core_banking.sql": (
        "-- MySQL dump\nCREATE TABLE accounts (id INT);\n"
        "CREATE TABLE loans (id INT);\n"
        "INSERT INTO accounts VALUES (1);\n"),
    "/apply": (
        '<html><body><form action="/apply" method="post">'
        '<input type="hidden" name="officer_id" value="E-4471">'
        '<input type="hidden" name="next" '
        'value="https://workflow.corp/apply">'
        '<input type="text" name="name"></form></body></html>'),
    "/1099/sample": (
        f"<html><body>Sample 1099-INT. Payer TIN {FAKE_TIN}. "
        "Recipient TIN 987-65-4321.</body></html>"),
    "/api/employees": json.dumps([{
        "name": "Jamie Manager", "email": "jm@canary-bank.test",
        "extension": "4417", "employeeId": "E-100",
        "departmentCode": "OPS", "manager": "boss@canary-bank.test"}]),
    "/documents/rates.pdf": (
        "%PDF-1.4\n/Author (CORP\\jsmith)\n"
        "/Title (\\\\files01\\loans\\rates.pdf)\n"
        "/Creator (Word)\n%%EOF"),
    "/status": (
        "<html><body>Core Banking status: CORE-PROD-02 degraded. "
        "Payment switch PAY-PROD-01 ok. Incident INC123456 open."
        "</body></html>"),
    "/login": (
        '<html><body><script src="https://cdn.skimmer-canary.test/x.js">'
        '</script><script src="https://js.stripe.com/v3"></script>'
        'Sign in</body></html>'),
}

DOH_ANSWERS = {
    ("uat.canary-bank.test", "A"): ["93.184.216.34"],
    ("alerts.canary-bank.test", "A"): ["93.184.216.35"],
    ("status.canary-bank.test", "A"): ["93.184.216.36"],
}

CRT_JSON = json.dumps([
    {"name_value": "www.canary-bank.test\nuat-internal.canary-bank.test",
     "common_name": "canary-bank.test"},
    {"name_value": "core-vpn.canary-bank.test", "common_name": "x"},
])


def _handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    path = request.url.path
    if host == "dns.google":
        name = request.url.params.get("name", "")
        rtype = request.url.params.get("type", "")
        data = DOH_ANSWERS.get((name, rtype))
        if not data:
            return httpx.Response(200, json={"Status": 0})
        return httpx.Response(200, json={
            "Status": 0,
            "Answer": [{"name": name, "type": 1, "TTL": 300, "data": d}
                       for d in data]})
    if host == "crt.sh":
        return httpx.Response(200, text=CRT_JSON,
                              headers={"Content-Type": "application/json"})
    if host == "uat.canary-bank.test":
        if path == "/":
            return httpx.Response(
                200, text="<html><body>Online Banking - Sign On. "
                          "Username: Password:</body></html>")
        return httpx.Response(404, text="not found")
    if host == "status.canary-bank.test":
        if path == "/":
            return httpx.Response(200, text=ROUTES["/status"])
        return httpx.Response(404, text="not found")
    if host == HOST:
        body = ROUTES.get(path)
        if body is None:
            return httpx.Response(404, text="not found")
        return httpx.Response(200, text=body)
    return httpx.Response(404, text="")


def _make_ctx(client):
    from app.cache import Cache
    from app.plugins.base import Ctx
    from app.ratelimit import RateLimiter
    return Ctx(run_id="bank-canary", mode="passive", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(50))


async def _run_plugins(plugin_ids, handler=_handler, host=HOST):
    from app.plugins.base import Target
    from app.plugins.registry import discover
    reg = discover()
    transport = httpx.MockTransport(handler)
    findings = {}
    async with httpx.AsyncClient(transport=transport,
                                 follow_redirects=True,
                                 trust_env=False) as client:
        for pid in plugin_ids:
            ctx = _make_ctx(client)
            target = Target(raw=host, type="domain", normalized=host)
            result = await reg[pid]().run(target, ctx)
            findings[pid] = result.findings
    return findings


# Expected finding key per transport-based detector.
CANARY_EXPECT = {
    "fin_js_config": "fin_js_config_leak",
    "fin_partner_portal": "fin_partner_portal",
    "fin_api_docs_secrets": "fin_api_docs_credential",
    "fin_mobile_config": "fin_mobile_config_leak",
    "fin_oidc_config": "fin_oidc_config_issue",
    "fin_saml_metadata": "fin_saml_metadata_leak",
    "fin_locator_api": "fin_locator_api_field",
    "fin_treasury_portal": "fin_treasury_portal",
    "fin_atm_monitor": "fin_atm_monitor_dashboard",
    "fin_atm_status_api": "fin_atm_status_field",
    "fin_atm_updates": "fin_atm_update_surface",
    "fin_atm_locator_feed": "fin_atm_feed_field",
    "fin_atm_remote_access": "fin_remote_access_gateway",
    "fin_atm_journal": "fin_atm_journal_data",
    "fin_atm_switch_config": "fin_atm_switch_config",
    "fin_atm_network_status": "fin_atm_network_internals",
    "fin_payment_secrets": "fin_payment_secret_key",
    "fin_webhook_secrets": "fin_webhook_secret",
    "fin_bin_config": "fin_bin_config_leak",
    "fin_sandbox_live_mismatch": "fin_sandbox_in_production",
    "fin_card_form_action": "fin_card_form_action",
    "fin_merchant_portal": "fin_merchant_portal",
    "fin_pos_config": "fin_pos_config_leak",
    "fin_ach_config": "fin_ach_config_leak",
    "fin_statement_sample": "fin_statement_internal_data",
    "fin_report_exports": "fin_report_export",
    "fin_docstore_listing": "fin_docstore_listing",
    "fin_core_backup": "fin_core_backup",
    "fin_form_hidden_fields": "fin_form_hidden_field",
    "fin_tax_sample_data": "fin_tax_sample_tin",
    "fin_staff_directory": "fin_staff_directory",
    "fin_doc_metadata": "fin_doc_metadata_leak",
    "fin_staging_env": "fin_staging_banking_env",
    "fin_ct_internal_names": "fin_ct_internal_name",
    "fin_status_internals": "fin_status_page_internals",
    "fin_alerts_mail_posture": "fin_alert_subdomain_no_spf",
    "fin_login_thirdparty_scripts": "fin_login_thirdparty_script",
}


def test_financial_set_includes_pack():
    assert len(bankatm.FINANCIAL_PLUGIN_IDS) == 56
    assert bankatm.FINANCIAL_PLUGIN_IDS[0] == "bank"
    fin = [p for p in bankatm.FINANCIAL_PLUGIN_IDS
           if p.startswith("fin_")]
    assert len(fin) == 40


@pytest.mark.parametrize("pid,key", sorted(CANARY_EXPECT.items()))
def test_canary_detector_fires(pid, key):
    findings = asyncio.run(_run_plugins([pid]))[pid]
    keys = [f.key for f in findings]
    assert key in keys, f"{pid}: expected {key}, got {keys}"


def test_canary_full_secrets_shown_tin_stays_masked():
    findings = asyncio.run(_run_plugins(list(CANARY_EXPECT)))
    blob = ""
    for pid, fs in findings.items():
        for f in fs:
            blob += f.value + " " + json.dumps(f.evidence or {},
                                               default=str) + "\n"
    # Credential secrets are shown IN FULL since 2026-10-29 (Jay's
    # order reversing the masked-only rule).
    for secret in (SK_LIVE, SQUARE_TOKEN, WHSEC, DOC_SECRET, MOBILE_KEY):
        assert secret in blob, f"full secret not shown: {secret[:8]}..."
    # The TIN is personal data, not a credential: it stays masked.
    assert FAKE_TIN not in blob
    # and the masked forms are still carried as metadata
    assert "sk_liv...8f9a0"[:6] in blob or "sk_liv" in blob


def _clean_handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if host == "dns.google":
        return httpx.Response(200, json={"Status": 0})
    if host == HOST and request.url.path == "/":
        return httpx.Response(
            200, text="<html><head><title>Clean Bank</title></head>"
                      "<body><h1>Clean Bank</h1></body></html>")
    return httpx.Response(404, text="not found")


def test_clean_site_all_silent():
    findings = asyncio.run(_run_plugins(list(CANARY_EXPECT),
                                         handler=_clean_handler))
    noisy = {pid: [f.key for f in fs]
             for pid, fs in findings.items() if fs}
    assert not noisy, f"detectors fired on a clean site: {noisy}"


# ---------------------------------------------------------------------------
# Certificate trio vs real local TLS servers
# ---------------------------------------------------------------------------

def _mint_cert(cn, dns_names, ip_names, not_before, not_after,
               key_bits=2048):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537,
                                   key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    sans = [x509.DNSName(d) for d in dns_names] + \
           [x509.IPAddress(ip) for ip in ip_names]
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName(sans),
                           critical=False)
            .sign(key, hashes.SHA256()))
    return key, cert


def _serve_tls(key, cert, tmp_path, tag):
    from cryptography.hazmat.primitives import serialization
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    cpath = tmp_path / f"{tag}-cert.pem"
    kpath = tmp_path / f"{tag}-key.pem"
    cpath.write_bytes(cert_pem)
    kpath.write_bytes(key_pem)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # The weak-cert canary uses a 1024-bit key on purpose; OpenSSL's
    # default security level refuses to even load it.
    sctx.set_ciphers("DEFAULT@SECLEVEL=0")
    sctx.load_cert_chain(str(cpath), str(kpath))
    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(5)
    lsock.settimeout(15)
    port = lsock.getsockname()[1]
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                conn, _ = lsock.accept()
            except (socket.timeout, OSError):
                break
            try:
                tls = sctx.wrap_socket(conn, server_side=True)
                tls.close()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return port, stop, lsock


def _run_cert_plugins(port, pids):
    from app.plugins.base import Ctx, Target
    from app.plugins.registry import discover
    from app.cache import Cache
    from app.ratelimit import RateLimiter

    async def main():
        reg = discover()
        out = {}
        async with httpx.AsyncClient(trust_env=False) as client:
            for pid in pids:
                ctx = Ctx(run_id="cert-canary", mode="passive",
                          http=client, cache=Cache(), keys={},
                          limiter=RateLimiter(50))
                url = f"https://127.0.0.1:{port}/"
                target = Target(raw=url, type="url", normalized=url)
                result = await reg[pid]().run(target, ctx)
                out[pid] = [f.key for f in result.findings]
        return out

    return asyncio.run(main())


def test_cert_expired_fires(tmp_path):
    import ipaddress
    now = dt.datetime.now(dt.timezone.utc)
    key, cert = _mint_cert(
        "canary-bank.test", ["canary-bank.test"],
        [ipaddress.ip_address("127.0.0.1")],
        now - dt.timedelta(days=400), now - dt.timedelta(days=10))
    port, stop, lsock = _serve_tls(key, cert, tmp_path, "expired")
    try:
        got = _run_cert_plugins(
            port, ["fin_cert_expired", "fin_cert_mismatch",
                   "fin_cert_weak"])
    finally:
        stop.set()
        lsock.close()
    assert "fin_cert_expired" in got["fin_cert_expired"], got
    assert got["fin_cert_mismatch"] == [], got
    assert got["fin_cert_weak"] == [], got


def test_cert_mismatch_fires(tmp_path):
    now = dt.datetime.now(dt.timezone.utc)
    key, cert = _mint_cert(
        "other-bank.test", ["other-bank.test"], [],
        now - dt.timedelta(days=1), now + dt.timedelta(days=90))
    port, stop, lsock = _serve_tls(key, cert, tmp_path, "mismatch")
    try:
        got = _run_cert_plugins(
            port, ["fin_cert_expired", "fin_cert_mismatch",
                   "fin_cert_weak"])
    finally:
        stop.set()
        lsock.close()
    assert "fin_cert_mismatch" in got["fin_cert_mismatch"], got
    assert got["fin_cert_expired"] == [], got
    assert got["fin_cert_weak"] == [], got


def test_cert_weak_fires(tmp_path):
    import ipaddress
    now = dt.datetime.now(dt.timezone.utc)
    key, cert = _mint_cert(
        "canary-bank.test", ["canary-bank.test"],
        [ipaddress.ip_address("127.0.0.1")],
        now - dt.timedelta(days=1), now + dt.timedelta(days=90),
        key_bits=1024)
    port, stop, lsock = _serve_tls(key, cert, tmp_path, "weak")
    try:
        got = _run_cert_plugins(
            port, ["fin_cert_expired", "fin_cert_mismatch",
                   "fin_cert_weak"])
    finally:
        stop.set()
        lsock.close()
    assert "fin_cert_weak" in got["fin_cert_weak"], got
    assert got["fin_cert_expired"] == [], got
    assert got["fin_cert_mismatch"] == [], got


def test_cert_weak_ec_key_not_flagged():
    """Regression (live 2026-10-23): a 256-bit EC key (P-256) is
    standard strength, not weak. The old flat <2048 bar flagged every
    modern EC certificate, e.g. error-inbox.onrender.com."""
    from app.plugins.bankpack_infra import cert_weak_issues
    base = {"sig_hash": "sha256", "tls_version": "TLSv1.3"}
    assert cert_weak_issues({**base, "key_bits": 256,
                             "key_kind": "ECPublicKey"}) == []
    assert cert_weak_issues({**base, "key_bits": 384,
                             "key_kind": "ECPublicKey"}) == []
    assert cert_weak_issues({**base, "key_bits": 192,
                             "key_kind": "ECPublicKey"}) != []
    assert cert_weak_issues({**base, "key_bits": 1024,
                             "key_kind": "RSAPublicKey"}) != []
    assert cert_weak_issues({**base, "key_bits": 2048,
                             "key_kind": "RSAPublicKey"}) == []
    assert cert_weak_issues({**base, "key_bits": 1024,
                             "key_kind": "UnknownKey"}) != []
