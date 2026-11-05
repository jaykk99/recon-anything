"""Canary + clean fixtures for the sec_* pack tests.

Every planted value is a FAKE secret minted for this test only: each
one carries a "cnry" marker and none of them is a real credential.
The tests assert no planted value ever appears in a finding (masked
plus fingerprint only).
"""

from __future__ import annotations

import io
import zipfile

AWS_KEY = "AKIACNRY1234567890AB"
APK_AWS_KEY = "AKIACNRY9876543210ZY"
APK_SECRET = "cnry_apk_7xQ2mZ9wR4vT1yH6jD3sA8pL5k"
GENERIC_SECRET = "cnry_sk_9f2K7xQ1mZ4w8vT6yH3jD5sA2pL"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
       ".eyJzdWIiOiJjbnJ5dXNlciJ9"
       ".cnrySig1a2b3c4d5e6f7g8h9j0k")
BEARER = "cnry_bearer_9f2K7xQ1mZ4w8vT6yH3jD5sA"
SEED_PHRASE = ("ocean river mountain cnry silver copper iron marble "
               "crystal harbor willow falcon")
SEED_WORDS = SEED_PHRASE.split()
PEM_BODY = ("Q0FOQVJZIEZBS0UgS0VZIEJPRElIU0ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0\n"
            "ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0ZBU0\n")
DB_PASSWORD = "cnryDbPass9f2K7xQ1mZ"
ENV_SECRET = "cnryW2xQ7mZ4vT8sA3pL6jH9fD"
MD5_DIGEST = "9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"
SHA1_DIGEST = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

CANARY_HTML = """<!DOCTYPE html>
<html><head><title>Canary Corp</title>
<script src="/static/app.js"></script>
</head><body><h1>Canary Corp</h1>
<a href="/app.apk">Android app</a>
</body></html>"""

CANARY_JS = f"""
const AWS_KEY = "{AWS_KEY}";
const api_key = "{GENERIC_SECRET}";
const session = "{JWT}";
const hash = md5(password);
const legacy = sha1(token);
const user = {{password_hash: "{MD5_DIGEST}"}};
const old = {{sha1_hash: "{SHA1_DIGEST}"}};
const mnemonic = "{SEED_PHRASE}";
const pem = `-----BEGIN RSA PRIVATE KEY-----
{PEM_BODY}-----END RSA PRIVATE KEY-----`;
"""

CANARY_ENV = (f"AWS_ACCESS_KEY_ID={AWS_KEY}\n"
              f"AWS_SECRET_ACCESS_KEY={ENV_SECRET}\n"
              f"DB_PASSWORD={DB_PASSWORD}\n")

CANARY_PEM = ("-----BEGIN RSA PRIVATE KEY-----\n" + PEM_BODY +
              "-----END RSA PRIVATE KEY-----\n")

CANARY_LOG = (f"[2026-10-24] ERROR auth failed: "
              f"Authorization: Bearer {BEARER}\n"
              f"[2026-10-24] DEBUG api_key=\"{GENERIC_SECRET}\" retry\n")

CANARY_BUCKET_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Contents><Key>backup.zip</Key></Contents>
<Contents><Key>.env</Key></Contents>
<Contents><Key>wallet.json</Key></Contents>
</ListBucketResult>"""

CANARY_BACKUPS_LISTING = """<html><head><title>Index of /backups/</title></head>
<body><h1>Index of /backups/</h1>
<a href="backup.zip">backup.zip</a>
<a href="db.sql">db.sql</a>
</body></html>"""

CANARY_LOGS_LISTING = """<html><head><title>Index of /logs/</title></head>
<body><h1>Index of /logs/</h1>
<a href="app.log">app.log</a>
</body></html>"""


def _stored_zip() -> bytes:
    """A real ZIP with STORED (uncompressed) entries, so raw-byte
    scanning of the readable archive finds the planted env markers."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(".env", CANARY_ENV)
    return buf.getvalue()


CANARY_ZIP = _stored_zip()

CANARY_APK = (f"FAKE APK BYTES\nAWS_KEY={APK_AWS_KEY}\n"
              f"api_key={APK_SECRET}\n").encode()

CANARY_ROUTES = {
    "/": ("text/html", CANARY_HTML),
    "/static/app.js": ("application/javascript", CANARY_JS),
    "/.env": ("text/plain", CANARY_ENV),
    "/id_rsa": ("text/plain", CANARY_PEM),
    "/server.key": ("text/plain", CANARY_PEM),
    "/logs/app.log": ("text/plain", CANARY_LOG),
    "/logs/": ("text/html", CANARY_LOGS_LISTING),
    "/storage/": ("application/xml", CANARY_BUCKET_XML),
    "/backups/": ("text/html", CANARY_BACKUPS_LISTING),
    "/backup.zip": ("application/zip", CANARY_ZIP),
    "/app.apk": ("application/octet-stream", CANARY_APK),
}

CLEAN_HTML = """<!DOCTYPE html>
<html><head><title>Clean Corp</title>
<script src="/static/app.js"></script>
</head><body><h1>Clean Corp</h1></body></html>"""

CLEAN_JS = """
const api_key = "example";
const placeholder = "changeme";
const public_id = "clean-corp-website";
"""

CLEAN_ROUTES = {
    "/": ("text/html", CLEAN_HTML),
    "/static/app.js": ("application/javascript", CLEAN_JS),
}

PLANTED = [AWS_KEY, GENERIC_SECRET, JWT, BEARER, SEED_PHRASE,
           DB_PASSWORD, ENV_SECRET, MD5_DIGEST, SHA1_DIGEST,
           APK_AWS_KEY, APK_SECRET]
