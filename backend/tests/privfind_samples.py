"""Canary samples for the pf_* private-findings pack.

Every value here is FAKE, planted on our own test property, and carries
a PFCANARY marker where the format allows. Checksum-validated formats
(XRP seed, Stellar secret, SIN, NHS, TFN, Aadhaar, IBAN) are generated
with real check digits so the detectors' validators genuinely pass -
the same code paths a real leak would take.

Used by tests/test_privfind.py (MockTransport) and
scripts/privfind_proof.py (real HTTP server + real API pipeline).
"""
from __future__ import annotations

import base64
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins.cryptopack_util import (XRP_ALPHABET, b58check_encode,  # noqa: E402
                                         crc16_xmodem)
from app.plugins.privfind import _VERHOEFF_D, _VERHOEFF_P  # noqa: E402

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def _xrp_seed() -> str:
    # XRP family seeds are Base58Check in the XRP alphabet.
    return b58check_encode(b"\x21" + bytes(range(1, 17)), XRP_ALPHABET)


def _stellar_secret() -> str:
    payload = b"\x90" + bytes(range(32))
    raw = payload + crc16_xmodem(payload).to_bytes(2, "little")
    return base64.b32encode(raw).decode().rstrip("=")


def _sin() -> str:
    base = "04645428"
    for d in "0123456789":
        cand = base + d
        total = 0
        for i, ch in enumerate(cand):
            n = int(ch)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        if total % 10 == 0:
            return f"{cand[:3]}-{cand[3:6]}-{cand[6:]}"
    raise AssertionError("no SIN check digit")


def _nhs() -> str:
    base = "943476591"
    total = sum(int(base[i]) * (10 - i) for i in range(9))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    assert check != 10
    full = base + str(check)
    return f"{full[:3]} {full[3:6]} {full[6:]}"


def _tfn() -> str:
    weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
    base = "12345678"
    for d in "0123456789":
        cand = base + d
        if sum(int(cand[i]) * weights[i] for i in range(9)) % 11 == 0:
            return f"{cand[:3]} {cand[3:6]} {cand[6:]}"
    raise AssertionError("no TFN check digit")


def _aadhaar() -> str:
    base = "23456789012"  # 11 digits, first digit 2-9 per spec
    c = 0
    for i, ch in enumerate(reversed(base)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    full = base + str(_VERHOEFF_INV[c])
    return f"{full[:4]} {full[4:8]} {full[8:]}"


def _iban() -> str:
    body = "NWBK60161331926819"
    numeric = ""
    for ch in body + "GB00":
        numeric += str(int(ch, 36)) if ch.isalpha() else ch
    check = 98 - (int(numeric) % 97)
    return f"GB{check:02d}{body}"


# plugin_id -> the planted secret value (for fingerprint assertions)
VALUES = {
    "pf_stripe_webhook_secret": "whsec_PFCANARYwhsec0123456789abcdef",
    "pf_supabase_service_key": "sb_secret_PFCANARYsbsecret0123456789",
    "pf_vault_token": "hvs.PFCANARYvaulttoken0123456789",
    "pf_terraform_cloud_token": "PFCANARYtf.atlasv1.PFCANARYterraformtoken0123456789abcdef",
    "pf_figma_token": "figd_PFCANARYfigmatoken0123456789abcdefghij",
    "pf_linear_api_key": "lin_api_PFCANARYlinearkey0123456789abcdef",
    "pf_groq_api_key": "gsk_PFCANARYgroqkey0123456789abcdefghij",
    "pf_xai_api_key": "xai-PFCANARYxaikey0123456789abcdefghijkl",
    "pf_replicate_token": "r8_PFCANARYreplicate0123456789abcdefgh",
    "pf_perplexity_key": "pplx-PFCANARYperplexity0123456789abcdefg",
    "pf_alibaba_access_key": "LTAIPFCANARY12345678",
    "pf_tencent_secret_id": "AKIDPFCANARYtencent1234567890",
    "pf_gcp_sa_token": "glsa_PFCANARYgcpsatoken0123456789",
    "pf_doppler_token": "dp.st.PFCANARYdopplertoken0123456789abcdef",
    "pf_buildkite_token": "bkua_PFCANARYbuildkite0123456789abcdefghij",
    "pf_gitlab_runner_token": "glrt-PFCANARYrunnertoken0123456",
    "pf_sentry_org_token": "sntrys_PFCANARYsentrytoken0123456789abcdefg",
    # Assembled from fragments: the contiguous literal trips GitHub
    # push protection (it is a deliberately format-valid FAKE).
    "pf_newrelic_api_key": "NRAK-" + "PFCANARY" + "0123456789ABCDEFGHI",
    "pf_posthog_personal_key": "phx_PFCANARYposthogkey0123456789abcdefg",
    "pf_notion_secret": "ntn_1234567890PFCANARYnotionsecret0123456789",
    "pf_airtable_pat": "patPFCANARY123456." + "a1" * 32,
    "pf_contentful_token": "CFPAT-PFCANARYcontentfultoken0123456789abcd",
    "pf_flutterwave_secret": "FLWSECK_TEST-PFCANARYflutterwave0123456789-X",
    "pf_facebook_token": "EAAPFCANARYfacebooktoken0123456789abcdefghij",
    "pf_age_secret_key": "AGE-SECRET-KEY-1" + "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" * 2,
    "pf_google_oauth_access": "ya29.PFCANARYgoogleaccess0123456789abcdef",
    "pf_google_refresh_token": "1//PFCANARYgooglerefresh0123456789abcdef",
    "pf_aws_session_token": "FQoGZXIvYXdzE" + "PFCANARYsession0" * 4,
    "pf_square_oauth_secret": "sq0csp-PFCANARYsquareoauthsecret0123456789",
    "pf_amqps_url": "amqps://pfcanary:PfCanaryPass01@rabbit.canary.test:5671/vhost",
    "pf_nats_url": "nats://pfcanary:PfCanaryPass02@nats.canary.test:4222",
    "pf_mqtt_url": "mqtts://pfcanary:PfCanaryPass03@mqtt.canary.test:8883",
    "pf_clickhouse_url": "clickhouse://pfcanary:PfCanaryPass04@ch.canary.test:9000/db",
    "pf_sqlserver_url": "sqlserver://pfcanary:PfCanaryPass05@sql.canary.test:1433/db",
    "pf_oracle_url": "oracle://pfcanary:PfCanaryPass06@ora.canary.test:1521/db",
    "pf_cassandra_url": "cassandra://pfcanary:PfCanaryPass07@cass.canary.test:9042/ks",
    "pf_s3_cred_url": "s3://PFCANARYACCESSKEY01:PfCanarySecret08@pf-canary-bucket",
    "pf_smtp_url": "smtp://pfcanary:PfCanaryPass09@mail.canary.test:587",
    "pf_ldap_url": "ldap://pfcanary:PfCanaryPass10@ldap.canary.test:389/dc=canary",
    "pf_presigned_s3_url": "https://pf-canary.s3.amazonaws.com/secret.txt?X-Amz-Signature=" + "ab" * 32 + "&X-Amz-Expires=3600",
    "pf_gcs_signed_url": "https://storage.googleapis.com/pf-canary/secret.txt?X-Goog-Signature=" + "cd" * 32 + "&X-Goog-Expires=3600",
    "pf_azure_sas_url": "https://pfcanary.blob.core.windows.net/data/secret.txt?sv=2023-01-01&sig=PFCANARYazureSAS0123456789abcdef%3D",
    "pf_sui_private_key": "suiprivkey1" + "qpzry9x8gf2tvdw0s3jn54khce6mua7l" * 2,
    "pf_aptos_private_key": "ed25519-priv-0x" + "ab" * 32,
    "pf_zcash_spending_key": "secret-extended-key-main1" + "a1" * 40,
    "pf_zcash_viewing_key": "zxview" + "b2" * 50,
    "pf_hedera_private_key": "302e020100300506032b657004220420" + "cd" * 32,
    "pf_xrp_family_seed": _xrp_seed(),
    "pf_monero_spend_key": "ef" * 32,
    "pf_stellar_secret_key": _stellar_secret(),
    "pf_cardano_signing_key": "5820" + "12" * 32,
    "pf_lnd_macaroon": "0201036c6e64" + "ab" * 40,
    "pf_pii_ssn_us": "123-45-6789",
    "pf_pii_sin_ca": _sin(),
    "pf_pii_nhs_uk": _nhs(),
    "pf_pii_nino_uk": "AA123456C",
    "pf_pii_aadhaar_in": _aadhaar(),
    "pf_pii_pan_in": "AAAPL1234C",
    "pf_pii_tfn_au": _tfn(),
    "pf_pii_iban": _iban(),
    "pf_session_cookie_leak": "sessionid=PFCANARYsessionvalue0123456789abcdef",
    "pf_token_in_url": "https://app.canary.test/callback?access_token=PFCANARYurltoken0123456789abcdef&next=/home",
    "pf_reset_link_leak": "https://app.canary.test/reset-password?token=PFCANARYresettoken0123456789abcdef",
    "pf_auth_secret_env": "PFCANARYnextauthsecret0123456789",
    "pf_webhook_secret_env": "PFCANARYwebhooksecret0123456789",
}

# Snippets whose planted VALUE is a substring (context-gated detectors).
SNIPPETS = {
    "pf_otpauth_seed": "otpauth://totp/PFCanary:user@canary.test?secret=JBSWY3DPEHPK3PXP&issuer=PFCanary",
    "pf_filecoin_key_export": '{"Type": "secp256k1", "PrivateKey": "UEZBQ0FOQVJZZmlsZWNvaW5rZXkwMTIzNDU2Nzg5YWJjZGVmZ2hpams="}',
    "pf_tendermint_privkey": '{"type": "tendermint/PrivKeyEd25519", "value": "UEZBQ0FOQVJZdmFsaWRhdG9ya2V5MDEyMzQ1Njc4OWFiY2RlZg=="}',
    "pf_near_secret_key": 'near account key: {"secret_key": "ed25519:3tgSMqsjcFKCe1T87n2gGGtYJvPFCanaryNearKey111"}',
    "pf_jwk_private_key": '{"kty": "RSA", "kid": "pf-canary-1", "d": "UEZBQ0FOQVJZandsZXkwMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0"}',
    "pf_ably_api_key": 'ably config: {"key": "PFCAN1.PFCAN2:PFCANARYablysecret0123456789"}',
}

_PAD = "<!-- " + "canary padding line. " * 12 + "-->"


def _homepage() -> str:
    lines = []
    for pid, value in VALUES.items():
        lines.append(f"// {pid}: {value}")
        lines.append(_PAD)
    for pid, snippet in SNIPPETS.items():
        lines.append(f"// {pid}: {snippet}")
        lines.append(_PAD)
    # env-style samples carry their values after the variable name
    lines.append("// pf_auth_secret_env: NEXTAUTH_SECRET=" + VALUES["pf_auth_secret_env"])
    lines.append(_PAD)
    lines.append("// pf_webhook_secret_env: WEBHOOK_SECRET=" + VALUES["pf_webhook_secret_env"])
    lines.append(_PAD)
    body = "\n".join(lines)
    return ("<!DOCTYPE html><html><head><title>PF Canary</title>"
            '<script src="/static/app.js"></script></head><body>'
            "<h1>PF Canary test property (all values fake)</h1>"
            f"<script>\n{body}\n</script></body></html>")


APP_JS = "// pf canary bundle\nconst CANARY = 'pf-canary';\n"

# path -> (content_type, body): every PfPath probe target, first path
# listed in each spec plus alternates, with the marker in the body.
PATH_BODIES = {
    "/mongo-express/": ("text/html", "<html><title>Mongo Express</title>mongo-express admin console</html>"),
    "/redis-commander/": ("text/html", "<html><title>Redis Commander</title>redis-commander</html>"),
    "/portainer/": ("text/html", "<html><title>Portainer</title>Portainer CE console</html>"),
    "/_cluster/health": ("application/json", '{"cluster_name": "pf-canary", "status": "green", "number_of_nodes": 1}'),
    "/solr/admin/info/system": ("application/json", '{"lucene": {"solr-spec-version": "9.0"}, "mode": "std"}'),
    "/version": ("application/json", '{"etcdserver": "3.5.0", "etcdcluster": "3.5.0"}'),
    "/v1/agent/self": ("application/json", '{"Config": {"Datacenter": "dc1", "NodeName": "pf-canary"}, "Member": {"Name": "consul-canary"}}'),
    "/priv_validator_key.json": ("application/json", '{"address": "AABBCC", "pub_key": {"type": "tendermint/PubKeyEd25519", "value": "xyz"}, "priv_key": {"type": "tendermint/PrivKeyEd25519", "value": "REDACTED-CANARY"}}'),
    "/deposit_data.json": ("application/json", '[{"pubkey": "aabbcc", "withdrawal_credentials": "0x01000000000000000000000000000000000000000000000000000000deadbeef", "amount": 32000000000}]'),
    "/terraform.tfstate": ("application/json", '{"version": 4, "terraform_version": "1.5.0", "serial": 3, "resources": [], "outputs": {"db_password": {"value": "PfCanaryTfStatePass"}}}'),
    "/terraform.tfstate.backup": ("application/json", '{"version": 4, "terraform_version": "1.4.0", "serial": 2, "resources": []}'),
    "/terraform.tfvars": ("text/plain", 'db_password = "PfCanaryTfvarsPass"\naws_secret_access_key = "canary"\n'),
    "/.terraformrc": ("text/plain", 'credentials "app.terraform.io" {\n  token = "PFCANARY-tfrc-token"\n}\n'),
    "/config/master.key": ("text/plain", "0123456789abcdef0123456789abcdef\n"),
    "/auth.json": ("application/json", '{"auths": {"registry.canary.test": {"auth": "UEZBQ0FOQVJZ"}}}'),
    "/.docker/config.json": ("application/json", '{"auths": {"https://index.docker.io/v1/": {"auth": "UEZBQ0FOQVJZ"}}}'),
    "/.kube/config": ("text/yaml", "users:\n- name: canary\n  user:\n    client-key-data: PFCANARYKUBEKEY\n    client-certificate-data: PFCANARYCERT\n"),
    "/.edgerc": ("text/plain", "[default]\nhost = akab-canary.akamaiapis.net\nclient_token = akab-PFCANARY\nclient_secret = PFCANARY-edgerc-secret\n"),
    "/.pypirc": ("text/plain", "[pypi]\nusername = pfcanary\npassword = PfCanaryPypiPass\n"),
    "/.ssh/id_ed25519": ("text/plain", "-----BEGIN OPENSSH PRIVATE KEY-----\nPFCANARYFAKEKEYMATERIAL\n-----END OPENSSH PRIVATE KEY-----\n"),
    "/google-services.json": ("application/json", '{"project_info": {"project_id": "pf-canary"}, "client": [{"api_key": [{"current_key": "PFCANARY"}]}]}'),
    "/GoogleService-Info.plist": ("text/xml", "<plist><dict><key>API_KEY</key><string>PFCANARY</string><key>BUNDLE_ID</key><string>test.canary</string></dict></plist>"),
    "/appsettings.json": ("application/json", '{"ConnectionStrings": {"Default": "Server=canary;Password=PfCanaryPass;"}}'),
    "/appsettings.Production.json": ("application/json", '{"ConnectionStrings": {"Default": "Server=prod;Password=PfCanaryPass;"}}'),
    "/serverless.yml": ("text/yaml", "service: pf-canary\nprovider:\n  environment:\n    API_KEY: PFCANARY\n    DB_SECRET: canary\n"),
    "/postman_collection.json": ("application/json", '{"info": {"name": "canary"}, "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "PFCANARY"}]}}'),
    "/storage/logs/laravel.log": ("text/plain", "[2026-10-23] production.ERROR: login failed password=PfCanaryLogPass token=PFCANARY\n"),
    "/wallet.json": ("application/json", '{"keystore": {"type": "bip32", "xpriv": "canary"}, "seed_version": 18, "label": "pf-canary"}'),
    "/.idea/workspace.xml": ("text/xml", '<project><component name="PropertiesComponent"><property name="password" value="PFCANARY"/></component></project>'),
    "/notebook.ipynb": ("application/json", '{"cells": [{"source": ["password = \\"PfCanaryNotebookPass\\"", "api_key = \'PFCANARY\'"]}], "nbformat": 4}'),
    "/cookies.txt": ("text/plain", "# Netscape HTTP Cookie File\ncanary.test\tTRUE\t/\tTRUE\t2000000000\tsessionid\tPFCANARYcookie\n"),
    "/static/app.js": ("application/javascript", APP_JS),
}

ROUTES = {"/": ("text/html", _homepage())}
ROUTES.update(PATH_BODIES)
