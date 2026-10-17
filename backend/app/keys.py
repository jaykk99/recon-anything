"""API key storage with encryption at rest.

Secrets are Fernet-encrypted when RECON_MASTER_KEY is set, otherwise
stored with a plaintext marker (and the UI warns). Keys are never
shipped to the browser; plugins receive decrypted values server-side.
"""
from __future__ import annotations

from typing import Dict, Optional

from .config import MASTER_KEY

_PREFIX_ENC = "fernet:"
_PREFIX_PLAIN = "plain:"


def _fernet():
    if not MASTER_KEY:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(MASTER_KEY.encode()[:44].ljust(44, b"=")[:44])
    except Exception:
        return None


def encrypt(secret: str) -> str:
    f = _fernet()
    if f is None:
        return _PREFIX_PLAIN + secret
    return _PREFIX_ENC + f.encrypt(secret.encode()).decode()


def decrypt(stored: str) -> str:
    if stored.startswith(_PREFIX_ENC):
        f = _fernet()
        if f is None:
            raise RuntimeError("RECON_MASTER_KEY not set, cannot decrypt")
        return f.decrypt(stored[len(_PREFIX_ENC):].encode()).decode()
    if stored.startswith(_PREFIX_PLAIN):
        return stored[len(_PREFIX_PLAIN):]
    return stored  # legacy


def load_all(session) -> Dict[str, str]:
    from .models import ApiKey
    out = {}
    for row in session.query(ApiKey).all():
        try:
            out[row.name] = decrypt(row.secret_enc)
        except Exception:
            continue
    return out


def key_status(session) -> Dict[str, Dict]:
    from .models import ApiKey
    from .plugins.registry import all_plugins
    configured = {r.name for r in session.query(ApiKey).all()}
    needed: Dict[str, set] = {}
    for p in all_plugins():
        for k in p.requires_keys:
            needed.setdefault(k, set()).add(p.id)
    return {k: {"configured": k in configured, "used_by": sorted(v)}
            for k, v in needed.items()}
