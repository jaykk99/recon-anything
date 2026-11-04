"""Unified scan knowledge store (SQLite, cross-run).

The per-run tables in models.py (runs / findings / nodes / edges) answer
"what did THIS run see". They cannot answer cross-run questions like
"which assets run Nginx on non-CDN IPs" or "what showed up since
yesterday" without re-scanning every run's rows, and the hunters'
known_assets table tracks asset identity only - no observations
(tech stack, resolved IPs, certs, ports, status) and no findings.

This module is the additive cross-run layer:

- ks_assets: one row per (scope, kind, value) with first_seen /
  last_seen timestamps, first/last run linkage, and DENORMALIZED
  queryable columns - domain, ip, ports (JSON list), tech_stack
  (JSON list), is_cdn (1 / 0 / NULL=unknown) - so the attack-surface
  query shape works directly:

      SELECT domain, ip, ports FROM ks_assets
      WHERE tech_stack LIKE '%Nginx%' AND is_cdn = 0

- ks_observations: every observed fact per asset per run
  (resolved_ip, tech, tls_certificate, tls_issuer, tls_expires,
  http_status, port, cdn_provider). The delta engine diffs these
  per run; the denormalized asset columns are a rollup of them.

- ks_asset_runs: which run saw which asset (presence matrix the
  delta engine uses for NEW / REMOVED).

- ks_findings: findings copied at ingest with run + scope linkage
  for cross-run finding queries.

- ks_runs: run registry per scope (the delta engine's "previous
  completed run" lookup).

Written by ingest_run(), which the runner calls at finalize time
(best-effort, idempotent: re-finalizing a run re-ingests cleanly).
Existing run storage is untouched. The store lives in its own
SQLite file (RECON_KNOWLEDGE_DB, default ./knowledge.db) so it
works the same whether the main DB is SQLite or Postgres.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Cloudflare's published IPv4 ranges (public constants, used ONLY to
# set the is_cdn flag on assets whose hostnames resolve into them).
CLOUDFLARE_V4 = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "104.16.0.0/13", "108.162.192.0/18", "131.0.72.0/22",
    "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
    "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
    "197.234.240.0/22", "198.41.128.0/17",
]
_CF_NETS = [ipaddress.ip_network(c) for c in CLOUDFLARE_V4]

# Finding keys (app/plugins + app/graph.py NODE_KIND) mapped to
# knowledge-store semantics.
TECH_KEYS = {"tech", "server_header", "tech_deep"}
IP_KEYS = {"a", "aaaa"}
SUBDOMAIN_KEYS = {"subdomain", "tls_san"}
ENDPOINT_KEYS = {"api_endpoint", "endpoint", "graphql_path",
                 "apk_url", "mobile_url"}
STATUS_KEYS = {"http_status", "status"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ks_runs (
    run_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    status TEXT DEFAULT 'done',
    finished_at REAL,
    PRIMARY KEY (run_id, scope)
);
CREATE TABLE IF NOT EXISTS ks_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    domain TEXT,
    ip TEXT,
    ports TEXT DEFAULT '[]',
    tech_stack TEXT DEFAULT '[]',
    is_cdn INTEGER,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    first_run_id TEXT,
    last_run_id TEXT,
    UNIQUE (scope, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_ks_assets_scope ON ks_assets(scope);
CREATE INDEX IF NOT EXISTS idx_ks_assets_first_seen ON ks_assets(first_seen);
CREATE TABLE IF NOT EXISTS ks_asset_runs (
    asset_id INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    PRIMARY KEY (asset_id, run_id)
);
CREATE TABLE IF NOT EXISTS ks_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    run_id TEXT,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT DEFAULT '',
    ts REAL NOT NULL,
    UNIQUE (asset_id, run_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_ks_obs_asset ON ks_observations(asset_id, kind);
CREATE TABLE IF NOT EXISTS ks_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    scope TEXT,
    target_id TEXT,
    plugin_id TEXT,
    category TEXT,
    key TEXT,
    value TEXT,
    confidence INTEGER,
    ts REAL
);
CREATE INDEX IF NOT EXISTS idx_ks_findings_scope ON ks_findings(scope, plugin_id);
"""


def default_db_path() -> str:
    return os.environ.get("RECON_KNOWLEDGE_DB", "./knowledge.db")


def _is_cloudflare_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CF_NETS)


class KnowledgeStore:
    """SQLite knowledge store. One instance per path; thread-safe
    via a lock + per-call connections (WAL mode)."""

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

    # -- writes ------------------------------------------------------
    def register_run(self, run_id: str, scope: str, status: str = "done",
                     finished_at: Optional[float] = None) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO ks_runs (run_id, scope, status,"
                    " finished_at) VALUES (?, ?, ?, ?)",
                    (run_id, scope, status,
                     finished_at if finished_at is not None else time.time()))
                conn.commit()
            finally:
                conn.close()

    def upsert_asset(self, scope: str, kind: str, value: str,
                     run_id: Optional[str], ts: Optional[float] = None,
                     domain: Optional[str] = None,
                     ip: Optional[str] = None) -> int:
        """Insert or touch an asset; returns its id. first_seen and
        first_run_id are set once; last_seen / last_run_id advance."""
        ts = ts if ts is not None else time.time()
        value = (value or "").strip()
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO ks_assets (scope, kind, value, domain, ip,"
                    " first_seen, last_seen, first_run_id, last_run_id)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT (scope, kind, value) DO UPDATE SET"
                    " last_seen = excluded.last_seen,"
                    " last_run_id = excluded.last_run_id,"
                    " domain = COALESCE(ks_assets.domain, excluded.domain),"
                    " ip = COALESCE(ks_assets.ip, excluded.ip)",
                    (scope, kind, value, domain, ip, ts, ts, run_id, run_id))
                row = conn.execute(
                    "SELECT id FROM ks_assets WHERE scope = ? AND kind = ?"
                    " AND value = ?", (scope, kind, value)).fetchone()
                asset_id = int(row["id"])
                if run_id:
                    conn.execute(
                        "INSERT OR IGNORE INTO ks_asset_runs (asset_id,"
                        " run_id) VALUES (?, ?)", (asset_id, run_id))
                conn.commit()
                return asset_id
            finally:
                conn.close()

    def add_observation(self, asset_id: int, run_id: Optional[str],
                        kind: str, value: str, source: str = "",
                        ts: Optional[float] = None) -> None:
        """Record one observed fact and roll it into the asset's
        denormalized queryable columns (tech_stack / ports / ip /
        is_cdn)."""
        ts = ts if ts is not None else time.time()
        value = str(value)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO ks_observations (asset_id,"
                    " run_id, kind, value, source, ts) VALUES (?, ?, ?, ?,"
                    " ?, ?)", (asset_id, run_id, kind, value, source, ts))
                conn.commit()
            finally:
                conn.close()
        if kind in ("tech", "port", "resolved_ip", "cdn_provider"):
            self._rollup(asset_id)

    def _rollup(self, asset_id: int) -> None:
        """Recompute an asset's denormalized columns from its
        observations. Called on ingest; cheap and idempotent."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT kind, value FROM ks_observations"
                    " WHERE asset_id = ?", (asset_id,)).fetchall()
                tech = sorted({r["value"] for r in rows
                               if r["kind"] == "tech"})
                ports = sorted({int(r["value"]) for r in rows
                                if r["kind"] == "port"
                                and str(r["value"]).isdigit()})
                ips = [r["value"] for r in rows
                       if r["kind"] == "resolved_ip"]
                has_cdn = any(r["kind"] == "cdn_provider" for r in rows)
                is_cdn: Optional[int] = None
                if has_cdn or any(_is_cloudflare_ip(i) for i in ips):
                    is_cdn = 1
                elif ips:
                    # Resolved, and nothing points at a CDN: the
                    # honest negative the attack-surface query wants
                    # (is_cdn = FALSE). No IP data at all stays NULL
                    # (unknown), never a fabricated FALSE.
                    is_cdn = 0
                conn.execute(
                    "UPDATE ks_assets SET tech_stack = ?, ports = ?,"
                    " is_cdn = ? WHERE id = ?",
                    (json.dumps(tech), json.dumps(ports), is_cdn,
                     asset_id))
                conn.commit()
            finally:
                conn.close()

    def add_finding(self, run_id: str, scope: str, target_id: str,
                    plugin_id: str, category: str, key: str, value: str,
                    confidence: int, ts: Optional[float] = None) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO ks_findings (run_id, scope, target_id,"
                    " plugin_id, category, key, value, confidence, ts)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (run_id, scope, target_id, plugin_id, category, key,
                     value, confidence,
                     ts if ts is not None else time.time()))
                conn.commit()
            finally:
                conn.close()

    # -- queries -----------------------------------------------------
    def query_assets(self, *, scope: Optional[str] = None,
                     kind: Optional[str] = None,
                     tech_contains: Optional[str] = None,
                     is_cdn: Optional[bool] = None,
                     ip: Optional[str] = None,
                     since: Optional[float] = None,
                     limit: int = 500) -> List[Dict[str, Any]]:
        """Cross-run asset query. tech_contains is a substring match
        over the tech_stack list (the '%Nginx%' LIKE shape); is_cdn
        filters the CDN flag (True / False; unknown excluded either
        way); since returns assets FIRST seen at or after the epoch
        timestamp."""
        sql = ["SELECT * FROM ks_assets WHERE 1 = 1"]
        args: List[Any] = []
        if scope:
            sql.append("AND scope = ?")
            args.append(scope)
        if kind:
            sql.append("AND kind = ?")
            args.append(kind)
        if tech_contains:
            sql.append("AND tech_stack LIKE ?")
            args.append(f"%{tech_contains}%")
        if is_cdn is not None:
            sql.append("AND is_cdn = ?")
            args.append(1 if is_cdn else 0)
        if ip:
            sql.append("AND ip = ?")
            args.append(ip)
        if since is not None:
            sql.append("AND first_seen >= ?")
            args.append(float(since))
        sql.append("ORDER BY first_seen LIMIT ?")
        args.append(max(1, min(int(limit), 5000)))
        conn = self._connect()
        try:
            rows = conn.execute(" ".join(sql), args).fetchall()
            return [_asset_dict(r) for r in rows]
        finally:
            conn.close()

    def assets_first_seen_since(self, since: float,
                                scope: Optional[str] = None,
                                limit: int = 500) -> List[Dict[str, Any]]:
        return self.query_assets(scope=scope, since=since, limit=limit)

    def query_findings(self, *, scope: Optional[str] = None,
                       run_id: Optional[str] = None,
                       plugin_id: Optional[str] = None,
                       limit: int = 500) -> List[Dict[str, Any]]:
        sql = ["SELECT * FROM ks_findings WHERE 1 = 1"]
        args: List[Any] = []
        if scope:
            sql.append("AND scope = ?")
            args.append(scope)
        if run_id:
            sql.append("AND run_id = ?")
            args.append(run_id)
        if plugin_id:
            sql.append("AND plugin_id = ?")
            args.append(plugin_id)
        sql.append("ORDER BY ts LIMIT ?")
        args.append(max(1, min(int(limit), 5000)))
        conn = self._connect()
        try:
            return [dict(r) for r in conn.execute(" ".join(sql), args)]
        finally:
            conn.close()

    def runs_for_scope(self, scope: str) -> List[Dict[str, Any]]:
        """Completed runs for a scope, oldest first (delta lookup)."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM ks_runs WHERE scope = ? AND status = 'done'"
                " ORDER BY COALESCE(finished_at, 0)", (scope,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def asset_presence(self, scope: str, run_id: str) -> Dict[int, Dict]:
        """asset_id -> asset row for assets a run observed."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT a.* FROM ks_assets a JOIN ks_asset_runs ar"
                " ON ar.asset_id = a.id WHERE a.scope = ? AND ar.run_id = ?",
                (scope, run_id)).fetchall()
            return {int(r["id"]): _asset_dict(r) for r in rows}
        finally:
            conn.close()

    def observation_snapshot(self, asset_id: int,
                             run_id: str) -> Dict[str, List[str]]:
        """kind -> sorted values observed for an asset IN one run."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT kind, value FROM ks_observations WHERE asset_id = ?"
                " AND run_id = ?", (asset_id, run_id)).fetchall()
            snap: Dict[str, set] = {}
            for r in rows:
                snap.setdefault(r["kind"], set()).add(r["value"])
            return {k: sorted(v) for k, v in snap.items()}
        finally:
            conn.close()

    def stats(self) -> Dict[str, int]:
        conn = self._connect()
        try:
            out = {}
            for tbl in ("ks_assets", "ks_observations", "ks_findings",
                        "ks_runs"):
                out[tbl] = conn.execute(
                    f"SELECT COUNT(*) AS n FROM {tbl}").fetchone()["n"]
            return out
        finally:
            conn.close()


def _asset_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    for col in ("ports", "tech_stack"):
        try:
            d[col] = json.loads(d.get(col) or "[]")
        except (TypeError, ValueError):
            d[col] = []
    if d.get("is_cdn") is not None:
        d["is_cdn"] = bool(d["is_cdn"])
    return d


_default_store: Optional[KnowledgeStore] = None
_default_lock = threading.Lock()


def get_default_store() -> KnowledgeStore:
    global _default_store
    with _default_lock:
        if _default_store is None:
            _default_store = KnowledgeStore()
        return _default_store


# ---------------------------------------------------------------------------
# Ingest: one finalized run -> knowledge store
# ---------------------------------------------------------------------------

def _host_for_target(trow) -> str:
    """Scope/host key for a Target row (mirrors runner conventions)."""
    try:
        from .classifier import domain_from_target
        d = domain_from_target(trow.type, trow.normalized)
        if d:
            return d
    except Exception:
        pass
    if trow.type == "ip":
        return (trow.normalized or "").strip()
    host = urlparse(trow.normalized or "").hostname
    return host or (trow.normalized or "").strip()


def _port_from_finding(f) -> Optional[int]:
    ev = f.evidence or {}
    if isinstance(ev, dict) and ev.get("port"):
        try:
            return int(ev["port"])
        except (TypeError, ValueError):
            pass
    m = re.search(r"Port (\d+)", f.value or "")
    return int(m.group(1)) if m else None


def ingest_run(session, run_id: str,
               store: Optional[KnowledgeStore] = None) -> Dict[str, int]:
    """Fold one run's targets + findings into the knowledge store.

    Idempotent: assets upsert on (scope, kind, value), observations
    and asset-run links are INSERT OR IGNORE, findings are cleared
    for the run and re-copied, so a re-finalize never duplicates.
    Returns ingest counts. Raises on real failure - the runner calls
    this best-effort inside try/except like the Mongo archive.
    """
    from .models import Finding as FindingRow, Run, Target as TargetRow

    store = store or get_default_store()
    now = time.time()
    run = session.query(Run).filter_by(id=run_id).first()
    finished = None
    if run is not None and run.finished_at is not None:
        try:
            finished = run.finished_at.timestamp()
        except Exception:
            finished = None

    targets = session.query(TargetRow).filter_by(run_id=run_id).all()
    scopes: Dict[str, Dict[str, Any]] = {}  # target_id -> {scope, host_id}
    for t in targets:
        scope = _host_for_target(t)
        if not scope:
            continue
        kind = "ip" if t.type == "ip" else "host"
        host_id = store.upsert_asset(
            scope, kind, scope, run_id, ts=now, domain=scope,
            ip=scope if t.type == "ip" else None)
        scopes[t.id] = {"scope": scope, "host_id": host_id}

    findings = session.query(FindingRow).filter_by(run_id=run_id).all()
    # Findings copy: clear this run's prior copy first (idempotence).
    conn = store._connect()
    try:
        with store._lock:
            conn.execute("DELETE FROM ks_findings WHERE run_id = ?",
                         (run_id,))
            conn.commit()
    finally:
        conn.close()

    n_assets = len(scopes)
    n_obs = 0
    cert_parts: Dict[int, Dict[str, str]] = {}
    for f in findings:
        info = scopes.get(f.target_id)
        if info is None:
            continue
        scope, host_id = info["scope"], info["host_id"]
        store.add_finding(run_id, scope, f.target_id, f.plugin_id,
                          f.category, f.key, f.value, f.confidence, ts=now)
        key, val = f.key, (f.value or "").strip()
        if not val:
            continue
        if key in SUBDOMAIN_KEYS:
            store.upsert_asset(scope, "subdomain", val, run_id, ts=now,
                               domain=val)
            n_assets += 1
        elif key in IP_KEYS:
            store.upsert_asset(scope, "ip", val, run_id, ts=now, ip=val)
            store.add_observation(host_id, run_id, "resolved_ip", val,
                                  source=f.plugin_id, ts=now)
            n_assets += 1
            n_obs += 1
        elif key in TECH_KEYS:
            store.add_observation(host_id, run_id, "tech", val,
                                  source=f.plugin_id, ts=now)
            n_obs += 1
        elif key in ENDPOINT_KEYS:
            store.upsert_asset(scope, "endpoint", val, run_id, ts=now)
            n_assets += 1
        elif key in STATUS_KEYS:
            store.add_observation(host_id, run_id, "http_status", val,
                                  source=f.plugin_id, ts=now)
            n_obs += 1
        elif key == "cdn_detected":
            providers: List[str] = []
            if isinstance(f.evidence, dict):
                providers = list(f.evidence.get("providers") or [])
            for p in providers or ["cdn"]:
                store.add_observation(host_id, run_id, "cdn_provider",
                                      str(p), source=f.plugin_id, ts=now)
                n_obs += 1
        elif key == "port_open":
            port = _port_from_finding(f)
            if port is not None:
                store.add_observation(host_id, run_id, "port", str(port),
                                      source=f.plugin_id, ts=now)
                n_obs += 1
        elif key in ("tls_subject", "tls_issuer", "tls_expires"):
            cert_parts.setdefault(host_id, {})[key] = val
            store.add_observation(
                host_id, run_id,
                {"tls_subject": "tls_subject", "tls_issuer": "tls_issuer",
                 "tls_expires": "tls_expires"}[key], val,
                source=f.plugin_id, ts=now)
            n_obs += 1
    for host_id, parts in cert_parts.items():
        if "tls_subject" in parts:
            composite = "|".join([parts.get("tls_subject", ""),
                                  parts.get("tls_issuer", ""),
                                  parts.get("tls_expires", "")])
            store.add_observation(host_id, run_id, "tls_certificate",
                                  composite, source="tls", ts=now)
            n_obs += 1
    # Rollups for hosts touched via cdn/port observations (add_observation
    # already rolls up tech/port/resolved_ip/cdn; cert/status do not
    # change denormalized columns).
    for info in scopes.values():
        store.register_run(run_id, info["scope"], status="done",
                           finished_at=finished)
    return {"assets_touched": n_assets, "observations": n_obs,
            "findings": len(findings),
            "scopes": len(scopes)}
