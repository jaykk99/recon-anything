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

# Storing the full findings payload per done unit is what fills a tight disk
# quota on a long continuous scan: once writes start failing, completions are
# lost and finished work gets redone. Cap the stored result so the DB stays
# small; resumability only needs the "done" status, the replayed findings are
# a bonus we drop when they are oversized.
_MAX_RESULT_BYTES = int(os.environ.get("RECON_CHECKPOINT_MAX_RESULT", "65536"))
# A unit another worker marked "running" this recently is assumed in progress,
# so a second concurrent batch skips it instead of rescanning the same
# contract. 0 disables the lease (old behaviour: only "done" is skipped).
_LEASE_S = float(os.environ.get("RECON_CHECKPOINT_LEASE_S", "600"))
# Truncate the WAL every N writes so it can't grow unbounded on disk.
_WAL_TRUNCATE_EVERY = int(os.environ.get("RECON_CHECKPOINT_WAL_EVERY", "500"))


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
        # In-process fallback: keys marked done when the DB itself can't be
        # written (disk full / quota). Keeps the CURRENT run from redoing a
        # unit even when nothing can be persisted. self._degraded flips true
        # when the backing DB is unusable, so we stop hammering a dead disk.
        self._mem_done: set = set()
        self._degraded = False
        self._writes = 0
        try:
            conn = self._connect()
            try:
                conn.executescript(_SCHEMA)
                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error:
            # Disk full / unwritable at startup: run degraded (in-memory
            # done-set only) rather than crashing the whole scanner.
            self._degraded = True

    def _maybe_truncate_wal(self, conn: sqlite3.Connection) -> None:
        self._writes += 1
        if _WAL_TRUNCATE_EVERY and self._writes % _WAL_TRUNCATE_EVERY == 0:
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def lookup(self, key: str) -> Optional[Dict[str, Any]]:
        try:
            conn = self._connect()
        except sqlite3.Error:
            return None
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
        except sqlite3.Error:
            return None
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def is_done(self, key: str) -> bool:
        if key in self._mem_done:
            return True
        rec = self.lookup(key)
        return bool(rec and rec["status"] == "done")

    def begin(self, key: str, target: str, module: str,
              args: Optional[Dict] = None) -> bool:
        """Mark a unit running. Returns False (do not execute) when the
        unit is already done, OR when another worker marked it running
        within the lease window (so two concurrent batches don't rescan
        the same contract). Returns True otherwise. Never raises on disk
        pressure - it degrades to letting the unit run."""
        if key in self._mem_done:
            return False
        if self._degraded:
            return True  # can't coordinate via DB; run it
        now = time.time()
        with self._lock:
            try:
                conn = self._connect()
            except sqlite3.Error:
                self._degraded = True
                return True
            try:
                rec = conn.execute(
                    "SELECT status, updated_at FROM cp_units WHERE key = ?",
                    (key,)).fetchone()
                if rec is not None:
                    if rec["status"] == "done":
                        return False
                    if (rec["status"] == "running" and _LEASE_S > 0
                            and (now - (rec["updated_at"] or 0)) < _LEASE_S):
                        # Another batch holds a fresh lease on this unit.
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
            except sqlite3.Error:
                # Disk pressure: let the unit run; completion will try to
                # persist a minimal done-marker.
                return True
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def complete(self, key: str, result: Dict[str, Any]) -> None:
        """Record a unit done, durably even under disk pressure. The full
        result is stored when it fits; when it is oversized or the disk is
        full, a minimal done-marker is written instead - and if even that
        fails, the key is held in memory so the current run won't redo it."""
        blob = json.dumps(result, default=str)
        if len(blob) > _MAX_RESULT_BYTES:
            # Keep the verdict, drop the oversized findings payload.
            blob = json.dumps({"status": (result or {}).get("status"),
                               "reason": (result or {}).get("reason"),
                               "_truncated": True}, default=str)
        now = time.time()
        with self._lock:
            if self._degraded or not self._write_done(key, blob, now):
                # Retry with no result at all - a bare 'done' is tiny and
                # far more likely to fit than the findings.
                if self._degraded or not self._write_done(key, "", now):
                    self._mem_done.add(key)

    def _write_done(self, key: str, blob: str, now: float) -> bool:
        """UPDATE ... status='done'. Returns False on any sqlite error
        (e.g. disk full) so the caller can fall back."""
        try:
            conn = self._connect()
        except sqlite3.Error:
            return False
        try:
            conn.execute(
                "UPDATE cp_units SET status = 'done', result = ?,"
                " error = '', updated_at = ? WHERE key = ?",
                (blob, now, key))
            conn.commit()
            self._maybe_truncate_wal(conn)
            return True
        except sqlite3.Error:
            return False
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def fail(self, key: str, error: str = "") -> None:
        now = time.time()
        with self._lock:
            if self._degraded:
                return
            try:
                conn = self._connect()
            except sqlite3.Error:
                return
            try:
                conn.execute(
                    "UPDATE cp_units SET status = 'failed', error = ?,"
                    " updated_at = ? WHERE key = ?",
                    (str(error)[:500], now, key))
                conn.commit()
            except sqlite3.Error:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

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
