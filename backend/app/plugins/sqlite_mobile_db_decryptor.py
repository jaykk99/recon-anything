"""Mobile SQLite/SQLCipher posture check (Cat-7 #204, SHIP).

Input: operator-supplied mobile database file. Detects plaintext
SQLite vs SQLCipher headers and cipher posture. Tests ONLY a tiny
fixed list of well-known vendor default keys (via the sqlcipher
library/CLI when present) - NO dictionary, NO brute force. If a DB
opens with a default key, that fact is the finding (masked).
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import tempfile
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding, mask_value

SQLITE_MAGIC = b"SQLite format 3\x00"
# Tiny fixed list of well-known vendor DEFAULT keys only.
DEFAULT_KEYS = ["", "password", "1234", "changeme", "default", "secret"]


def _opens_as_plaintext(data: bytes) -> bool:
    if not data or not data.startswith(SQLITE_MAGIC):
        return False
    try:
        with tempfile.NamedTemporaryFile(suffix=".db",
                                         delete=False) as tf:
            tf.write(data)
            path = tf.name
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            con.execute("SELECT count(*) FROM sqlite_master")
            con.close()
            return True
        finally:
            os.unlink(path)
    except Exception:
        return False


def _try_default_keys(data: bytes) -> str | None:
    """Try the fixed vendor-default key list via sqlcipher if present.

    Returns the key that opened the DB, else None. No other keys are
    ever attempted."""
    cli = shutil.which("sqlcipher")
    if not cli or not data or data.startswith(SQLITE_MAGIC):
        return None
    try:
        with tempfile.NamedTemporaryFile(suffix=".db",
                                         delete=False) as tf:
            tf.write(data)
            path = tf.name
        try:
            for key in DEFAULT_KEYS:
                try:
                    r = subprocess.run(
                        [cli, path, f"PRAGMA key = '{key}';",
                         "SELECT count(*) FROM sqlite_master;"],
                        capture_output=True, text=True, timeout=10)
                    if r.returncode == 0 and "Error" not in (r.stderr or ""):
                        return key
                except Exception:
                    continue
        finally:
            os.unlink(path)
    except Exception:
        return None
    return None


def analyze_sqlite_db(data: bytes, name: str = "database") -> List[Dict]:
    if not data:
        return []
    if _opens_as_plaintext(data):
        return [finding(
            "mobile_db_plaintext",
            f"Mobile database {name} is PLAINTEXT SQLite (header "
            f"'SQLite format 3', opens with no key) - app data is "
            f"readable by anyone with the file",
            "high", source=name, confidence=92, encryption="none")]
    key = _try_default_keys(data)
    if key is not None:
        return [finding(
            "mobile_db_default_key",
            f"Mobile database {name} is SQLCipher-encrypted but opens "
            f"with a well-known vendor DEFAULT key: {mask_value(key)}",
            "high", source=name, confidence=90,
            encryption="sqlcipher-default-key",
            masked_key=mask_value(key))]
    if len(data) >= 16 and not data.startswith(SQLITE_MAGIC):
        # Encrypted (or foreign) header: strong posture, no finding -
        # but report nothing rather than guess at the format.
        return []
    return []


class SqliteMobileDbDecryptorPlugin(Cat7Plugin):
    id = "sqlite_mobile_db_decryptor"
    label = "SQLite Mobile DB Decryptor (default keys only)"
    description = ("Posture check of an operator-supplied mobile DB: "
                   "plaintext vs SQLCipher; tests only a tiny fixed "
                   "list of vendor default keys. No brute force.")

    def analyze(self, art: Dict) -> List[Dict]:
        out: List[Dict] = []
        if art.get("kind") == "file" and art.get("data"):
            out.extend(analyze_sqlite_db(art["data"],
                                         art.get("name", "database")))
        for name, blob in (art.get("files") or {}).items():
            if name.lower().endswith((".db", ".sqlite", ".sqlite3")):
                out.extend(analyze_sqlite_db(blob, name))
        return out
