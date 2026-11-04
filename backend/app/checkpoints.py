"""Hash checkpoints for resumable scan units.

Long scans lose work when the process dies mid-run. The PluginJob
queue (models.py) already recovers jobs WITHIN one run across a
restart; this module adds the cross-invocation half: every unit of
work - one scanner module over one target with one set of args -
gets a deterministic checkpoint keyed by

    sha256(target + scanner_module + canonical(args))

with a status (pending / running / done / failed) and, for done
units, the full result payload (status, reason, findings). The
runner consults the store before executing a unit: a unit already
done is skipped and its stored findings are replayed into the new
run instead of being re-scanned, so re-running an interrupted scan
picks up exactly where it stopped instead of starting over.

Stored in SQLite (same file as the knowledge store by default;
RECON_CHECKPOINT_DB overrides, RECON_CHECKPOINTS=0 disables the
runner integration). Failed units are NOT skipped - they retry on
resume. Nothing here changes what a unit does when it runs; it
only decides whether it needs to run at all.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cp_units (
    key TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    module TEXT NOT NULL,
    args TEXT DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    result TEXT,
    error TEXT DEFAULT '',
    attempts INTEGER DEFAULT 0,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cp_units_status ON cp_units(status);
"""


def unit_key(target: str, module: str, args: Optional[Dict] = None) -> str:
    """hash(target + scanner_module + args), args canonicalized so
    dict ordering never changes the key."""
    canon = json.dumps(args or {}, sort_keys=True, default=str)
    raw = f"{target}|{module}|{canon}"
    return hashlib.sha256(raw.encode()).hexdigest()


def checkpoints_enabled() -> bool:
    return os.environ.get("RECON_CHECKPOINTS", "1") != "0"


def default_db_path() -> str:
    if os.environ.get("RECON_CHECKPOINT_DB"):
        return os.environ["RECON_CHECKPOINT_DB"]
    from .knowledge_store import default_db_path as ks_path
    return ks_path()


class CheckpointStore:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or default_db_path()
        self._lock = threading.Lock()
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def lookup(self, key: str) -> Optional[Dict[str, Any]]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM cp_units WHERE key = ?",
                               (key,)).fetchone()
            if row is None:
                return None
            d = dict(row)
            if d.get("result"):
                try:
                    d["result"] = json.loads(d["result"])
                except (TypeError, ValueError):
                    d["result"] = None
            return d
        finally:
            conn.close()

    def is_done(self, key: str) -> bool:
        rec = self.lookup(key)
        return bool(rec and rec["status"] == "done")

    def begin(self, key: str, target: str, module: str,
              args: Optional[Dict] = None) -> bool:
        """Mark a unit running. Returns False (do not execute) when
        the unit is already done; True otherwise."""
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                rec = conn.execute(
                    "SELECT status FROM cp_units WHERE key = ?",
                    (key,)).fetchone()
                if rec is not None and rec["status"] == "done":
                    return False
                conn.execute(
                    "INSERT INTO cp_units (key, target, module, args,"
                    " status, attempts, created_at, updated_at) VALUES"
                    " (?, ?, ?, ?, 'running', 1, ?, ?)"
                    " ON CONFLICT (key) DO UPDATE SET status = 'running',"
                    " attempts = cp_units.attempts + 1, updated_at = ?",
                    (key, target, module,
                     json.dumps(args or {}, sort_keys=True, default=str),
                     now, now, now))
                conn.commit()
                return True
            finally:
                conn.close()

    def complete(self, key: str, result: Dict[str, Any]) -> None:
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE cp_units SET status = 'done', result = ?,"
                    " error = '', updated_at = ? WHERE key = ?",
                    (json.dumps(result, default=str), now, key))
                conn.commit()
            finally:
                conn.close()

    def fail(self, key: str, error: str = "") -> None:
        now = time.time()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE cp_units SET status = 'failed', error = ?,"
                    " updated_at = ? WHERE key = ?",
                    (str(error)[:500], now, key))
                conn.commit()
            finally:
                conn.close()

    def stats(self) -> Dict[str, int]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM cp_units"
                " GROUP BY status").fetchall()
            return {r["status"]: r["n"] for r in rows}
        finally:
            conn.close()


_default_store: Optional[CheckpointStore] = None
_default_lock = threading.Lock()


def get_default_store() -> CheckpointStore:
    global _default_store
    with _default_lock:
        if _default_store is None:
            _default_store = CheckpointStore()
        return _default_store
