"""Authenticated Mode: one-time attestation + run-scoped credentials.

An authenticated run fetches the target with credentials the user
supplies for targets they own or have written permission to test, so
the existing detection plugins can see behind the target's login.

Attestation model (Jay's design): the warning is accepted ONCE per
account, not re-shown on every run. The acceptance - identity,
timestamp, the exact text version accepted, client IP - is stored
server-side in `auth_acceptances`. After that, creating an
authenticated run needs no repeated warning; each authenticated run
is stamped with a reference to the acceptance (RunAuth.acceptance_id)
plus who created it and when, and carries an "Authenticated" badge.
The server REJECTS authenticated runs from identities with no stored
acceptance.

Credential rules:
- Credentials live in exactly one place: the run's RunAuth row, Fernet-
  encrypted (RECON_AUTH_SECRET preferred; RECON_MASTER_KEY via
  app.keys; a key derived from the access code as the last fallback -
  never plaintext at rest on the gated production deployment).
- They are decrypted only inside the worker when the run's context is
  built, held in memory on that context, and the encrypted copy is
  WIPED (secret_enc=NULL, wiped_at stamped) when the run finishes.
- Credentials are attached to requests ONLY when the request host is
  one of the run's seed target hosts. Hunter-expanded hosts, third-
  party APIs and every other host never see them; the httpx request
  hook built in runner.py enforces this per request.
- Credentials never appear in logs, findings, events, exports or API
  responses. The API exposes only a presence label like
  "auth: cookie (set)" plus attestation metadata.

There is deliberately NO login machinery here: no form submission, no
credential testing, no brute force, no bypass. The user hands over a
session cookie / token / basic-auth pair they already hold for their
own target; plugins just replay it on that host.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

AUTH_TYPES = ("cookie", "bearer", "basic", "headers")
MAX_CUSTOM_HEADERS = 5

# The warning shown once, at acceptance time (UI disclaimer copy).
WARNING_TEXT = (
    "Authenticated scans run with YOUR credentials on targets YOU own "
    "or have written permission to test. Attestations are logged.")
# The exact statement the user accepts. Versioned: if the text ever
# changes materially, bump the version and old acceptances stop
# counting, so everyone re-accepts the new text once.
ACCEPTANCE_TEXT = (
    "I own my targets or have written permission to test them; "
    "my attestations are logged.")
ACCEPTANCE_TEXT_VERSION = "v1"
# Short disclaimer used across the Authenticated UI surfaces.
DISCLAIMER_TEXT = (
    "Authenticated: scans behind the login of your own systems. "
    "For authorized testing only.")

_TYPE_LABELS = {
    "cookie": "cookie",
    "bearer": "bearer token",
    "basic": "basic auth",
    "headers": "custom headers",
}

# Header names a custom-headers config may never set: hop-by-hop and
# framing headers that would corrupt the shared client rather than
# authenticate anything.
_FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding",
                      "connection", "cookie2", "te", "trailer", "upgrade"}


def type_label(auth_type: str) -> str:
    return _TYPE_LABELS.get(auth_type, auth_type)


def presence_label(auth_type: str) -> str:
    """The only credential description the API ever returns."""
    return f"auth: {type_label(auth_type)} (set)"


# ------------------------------------------------------------------ #
# Identity + one-time acceptance                                      #
# ------------------------------------------------------------------ #

def identity_for_actor(actor: Optional[Dict]) -> Tuple[str, str]:
    """(identity_key, identity_label) for a gate actor dict.

    The owner identity covers both the access-code caller and the
    owner GitHub login - both are Jay. Signed-in customers key off
    their user id, so a login rename never forks the audit trail.
    """
    actor = actor or {"kind": "open", "user": None}
    kind = actor.get("kind")
    user = actor.get("user")
    if kind == "user" and user is not None:
        return f"user:{user.id}", (user.github_login or f"user:{user.id}")
    if user is not None:  # owner GitHub account
        return "owner", (user.github_login or "owner")
    return "owner", "owner"


def get_acceptance(session, identity_key: str):
    """The stored acceptance for an identity, or None.

    Only acceptances of the CURRENT text version count: a version bump
    means the account must accept the new text once before its next
    authenticated run.
    """
    from .models import AuthAcceptance
    row = (session.query(AuthAcceptance)
           .filter_by(identity_key=identity_key,
                      text_version=ACCEPTANCE_TEXT_VERSION)
           .first())
    return row


def record_acceptance(session, identity_key: str, identity_label: str,
                      client_ip: Optional[str] = None):
    """Store (or refresh) an identity's one-time acceptance."""
    from .models import AuthAcceptance
    row = (session.query(AuthAcceptance)
           .filter_by(identity_key=identity_key).first())
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    if row is None:
        row = AuthAcceptance(identity_key=identity_key,
                             identity_label=identity_label)
        session.add(row)
    row.identity_label = identity_label
    row.text_version = ACCEPTANCE_TEXT_VERSION
    row.accepted_at = now
    row.client_ip = client_ip
    session.commit()
    return row


def acceptance_public(row) -> Optional[Dict]:
    if row is None:
        return None
    return {
        "accepted": True,
        "identity": row.identity_label,
        "accepted_at": (row.accepted_at.isoformat()
                        if row.accepted_at else None),
        "text_version": row.text_version,
        "text": ACCEPTANCE_TEXT,
        "warning": WARNING_TEXT,
    }


# ------------------------------------------------------------------ #
# Auth config validation                                              #
# ------------------------------------------------------------------ #

def validate_auth_config(raw: Optional[Dict]) -> Tuple[Optional[Dict], str]:
    """Validate a run-creation auth payload.

    Returns (clean_config, "") on success or (None, error_message).
    The clean config keeps ONLY the fields the chosen type needs, so
    stray secrets typed into the wrong field never get stored.
    """
    if not isinstance(raw, dict):
        return None, "auth config required"
    atype = str(raw.get("type") or "").strip().lower()
    if atype not in AUTH_TYPES:
        return None, ("auth.type must be one of: "
                      + ", ".join(AUTH_TYPES))
    if atype == "cookie":
        cookie = str(raw.get("cookie") or "").strip()
        if not cookie:
            return None, "auth.cookie is required for cookie auth"
        if "\n" in cookie or "\r" in cookie:
            return None, "auth.cookie must be a single header value"
        return {"type": "cookie", "cookie": cookie}, ""
    if atype == "bearer":
        token = str(raw.get("token") or "").strip()
        if not token:
            return None, "auth.token is required for bearer auth"
        if "\n" in token or "\r" in token:
            return None, "auth.token must be a single header value"
        return {"type": "bearer", "token": token}, ""
    if atype == "basic":
        username = str(raw.get("username") or "")
        password = str(raw.get("password") or "")
        if not username or not password:
            return None, ("auth.username and auth.password are both "
                          "required for basic auth")
        return {"type": "basic", "username": username,
                "password": password}, ""
    # custom headers
    headers = raw.get("headers")
    if not isinstance(headers, list) or not headers:
        return None, "auth.headers must be a non-empty list for header auth"
    if len(headers) > MAX_CUSTOM_HEADERS:
        return None, (f"at most {MAX_CUSTOM_HEADERS} custom headers "
                      "are allowed")
    clean: List[Dict[str, str]] = []
    seen = set()
    for item in headers:
        if not isinstance(item, dict):
            return None, "each custom header must be {name, value}"
        name = str(item.get("name") or "").strip()
        value = str(item.get("value") or "")
        if not name or not value:
            return None, "each custom header needs a name and a value"
        if name.lower() in _FORBIDDEN_HEADERS:
            return None, f"header {name!r} cannot be set"
        if any(c in name for c in " :\r\n") or "\n" in value or "\r" in value:
            return None, f"header {name!r} is not a valid header"
        if name.lower() in seen:
            return None, f"duplicate header {name!r}"
        seen.add(name.lower())
        clean.append({"name": name, "value": value})
    return {"type": "headers", "headers": clean}, ""


def normalize_host(raw: str) -> str:
    """Reduce a host/URL string to a bare lowercase hostname."""
    h = (raw or "").strip().lower()
    if not h:
        return ""
    if "://" in h:
        h = urlparse(h).netloc or h
    h = h.split("/")[0].split("@")[-1]
    if h.startswith("["):  # IPv6 literal
        return h.split("]")[0].lstrip("[")
    return h.split(":")[0]


def seed_hosts(classified: List[Dict]) -> List[str]:
    """Hosts of the run's seed targets (the only hosts auth may touch)."""
    from .classifier import domain_from_target
    hosts: List[str] = []
    for c in classified:
        host = domain_from_target(c.get("type", ""), c.get("normalized", ""))
        if not host and c.get("type") == "ip":
            host = (c.get("normalized") or "").strip().lower()
        if host and host not in hosts:
            hosts.append(host)
    return hosts


# ------------------------------------------------------------------ #
# Encryption at rest                                                  #
# ------------------------------------------------------------------ #

def _derived_fernet():
    """Fernet from RECON_AUTH_SECRET (preferred) or the access code.

    The access-code fallback keeps credentials encrypted at rest on
    deployments that have not set a dedicated secret yet; the key
    never leaves the server.
    """
    from cryptography.fernet import Fernet
    secret = os.environ.get("RECON_AUTH_SECRET", "")
    if not secret:
        from . import config
        secret = config.ACCESS_CODE or ""
    if not secret:
        return None
    digest = hashlib.sha256(("recon-authscan:" + secret).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(config_dict: Dict) -> str:
    raw = json.dumps(config_dict)
    f = _derived_fernet()
    if f is not None:
        return "auth1:" + f.encrypt(raw.encode()).decode()
    # No AUTH_SECRET and no access code (open local dev): route through
    # the app key store (RECON_MASTER_KEY). On the gated production
    # deployment the access code is always set, so the branch above is
    # the one that runs there.
    from .keys import encrypt as _keys_encrypt
    return "key1:" + _keys_encrypt(raw)


def decrypt_secret(stored: str) -> Dict:
    if stored.startswith("auth1:"):
        f = _derived_fernet()
        if f is None:
            raise RuntimeError(
                "no RECON_AUTH_SECRET/access code available to decrypt "
                "run credentials")
        raw = f.decrypt(stored[len("auth1:"):].encode()).decode()
        return json.loads(raw)
    if stored.startswith("key1:"):
        from .keys import decrypt as _keys_decrypt
        return json.loads(_keys_decrypt(stored[len("key1:"):]))
    raise RuntimeError("unknown run credential format")


# ------------------------------------------------------------------ #
# Request headers                                                     #
# ------------------------------------------------------------------ #

def build_headers(config_dict: Dict) -> Dict[str, str]:
    """The actual headers injected for seed-target-host requests."""
    atype = config_dict.get("type")
    if atype == "cookie":
        return {"Cookie": config_dict["cookie"]}
    if atype == "bearer":
        return {"Authorization": f"Bearer {config_dict['token']}"}
    if atype == "basic":
        creds = f"{config_dict['username']}:{config_dict['password']}"
        token = base64.b64encode(creds.encode()).decode()
        return {"Authorization": f"Basic {token}"}
    if atype == "headers":
        return {h["name"]: h["value"]
                for h in config_dict.get("headers", [])}
    return {}


# ------------------------------------------------------------------ #
# API-facing blocks (presence + stamps only, never values)            #
# ------------------------------------------------------------------ #

def public_auth_block(row, acceptance=None) -> Optional[Dict]:
    """The run detail's auth block for an authenticated run.

    Carries the per-run stamp (who created the run, when, which hosts
    the credentials were scoped to) and the reference to the one-time
    acceptance it relied on. Never any credential material.
    """
    if row is None:
        return None
    stamp = {
        "attested_by": row.attested_by,
        "attested_at": (row.attested_at.isoformat()
                        if row.attested_at else None),
        "hosts": list(row.target_hosts or []),
        "acceptance_id": row.acceptance_id,
    }
    if acceptance is not None:
        stamp["accepted_at"] = (acceptance.accepted_at.isoformat()
                                if acceptance.accepted_at else None)
        stamp["text_version"] = acceptance.text_version
    return {
        "type": row.auth_type,
        "label": presence_label(row.auth_type),
        "attestation": stamp,
        "disclaimer": DISCLAIMER_TEXT,
    }
