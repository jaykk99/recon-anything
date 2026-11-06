"""iOS keychain item audit (Cat-7 #192, SHIP).

Input: operator-supplied iOS backup folder or keychain-db.sqlite.
Enumerates keychain item classes/accounts (metadata only) and flags
items stored with weak accessibility classes. Values are reported
MASKED/fingerprinted, never in full. No device or third-party access.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding, fingerprint

# pdmn (accessibility) codes seen in keychain.db.
ACCESSIBILITY = {
    "dk": ("kSecAttrAccessibleAlways", "high"),
    "ak": ("kSecAttrAccessibleWhenUnlocked", None),
    "aku": ("kSecAttrAccessibleWhenUnlockedThisDeviceOnly", None),
    "ck": ("kSecAttrAccessibleAfterFirstUnlock", "medium"),
    "cku": ("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly", None),
    "always": ("kSecAttrAccessibleAlways", "high"),
    "afterfirstunlock": ("kSecAttrAccessibleAfterFirstUnlock", "medium"),
    "whenunlocked": ("kSecAttrAccessibleWhenUnlocked", None),
}


def analyze_keychain_rows(rows: List[Dict]) -> List[Dict]:
    out: List[Dict] = []
    for row in rows or []:
        pdmn = str(row.get("pdmn", "") or "").strip().lower()
        label, sev = ACCESSIBILITY.get(
            pdmn, (pdmn or "unknown", None))
        if not sev:
            continue
        acct = str(row.get("acct", "") or "")[:60]
        svce = str(row.get("svce", "") or "")[:60]
        data = row.get("data") or b""
        fp = fingerprint(data if isinstance(data, (bytes, str)) else b"")
        out.append(finding(
            "keychain_weak_accessibility",
            f"Keychain item (table {row.get('table', '?')}, "
            f"service '{svce}', account '{acct}') stored with weak "
            f"accessibility {label}; value fingerprint sha256:{fp[:16]}",
            sev, source="keychain-db.sqlite", confidence=88,
            account=acct, service=svce, accessibility=label,
            value_fingerprint=fp[:16]))
        if len(out) >= 40:
            break
    return out


def rows_from_keychain_db(path: str) -> List[Dict]:
    rows: List[Dict] = []
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for table in ("genp", "inet", "cert", "keys"):
            if table not in tables:
                continue
            cols = [c[1] for c in con.execute(f"PRAGMA table_info({table})")]
            wanted = [c for c in ("acct", "svce", "agrp", "pdmn", "data")
                      if c in cols]
            if "pdmn" not in wanted:
                continue
            for rec in con.execute(
                    f"SELECT {', '.join(wanted)} FROM {table} LIMIT 500"):
                row = dict(zip(wanted, rec))
                row["table"] = table
                rows.append(row)
        con.close()
    except Exception:
        return rows
    return rows


class IosKeychainItemScraperPlugin(Cat7Plugin):
    id = "ios_keychain_item_scraper"
    label = "iOS Keychain Item Scraper (masked)"
    description = ("Audits an operator-supplied keychain-db.sqlite / "
                   "iOS backup: item metadata plus weak accessibility "
                   "classes, values masked only.")

    def analyze(self, art: Dict) -> List[Dict]:
        rows: List[Dict] = []
        path = art.get("path") or ""
        candidates = []
        if art.get("kind") == "file" and path:
            candidates.append(path)
        if art.get("kind") == "dir":
            for name in (art.get("files") or {}):
                if "keychain" in name.lower() and name.endswith(
                        (".sqlite", ".db")):
                    candidates.append(os.path.join(path, name))
        for cand in candidates:
            rows.extend(rows_from_keychain_db(cand))
        # Single loose DB handed over as bytes: go through a temp file.
        if not rows and art.get("kind") == "file" and art.get("data"):
            try:
                with tempfile.NamedTemporaryFile(
                        suffix=".sqlite", delete=False) as tf:
                    tf.write(art["data"])
                    tmp = tf.name
                rows.extend(rows_from_keychain_db(tmp))
                os.unlink(tmp)
            except Exception:
                pass
        return analyze_keychain_rows(rows)
