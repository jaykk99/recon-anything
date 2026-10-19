"""Multi-database manager: 5 DBs, all optional, all degrade gracefully.

1. Postgres (primary)  - DATABASE_URL        - runs/findings (SQLAlchemy, models.py)
2. Postgres (backup)   - DATABASE_URL_BACKUP - failover for primary
3. Redis               - REDIS_URL            - shared cache (cache.py)
4. MongoDB             - MONGO_URL            - findings archive
5. Neo4j               - NEO4J_URL            - asset graph sink

Every function here is best-effort: missing env var, missing driver,
or unreachable host -> silent no-op / None. The app must boot and
scan fine with zero of these configured.
"""
from __future__ import annotations

import datetime as dt
import logging
from typing import Any, Dict, List, Optional

from .config import DATABASE_URL_BACKUP, MONGO_URL, NEO4J_PASSWORD, NEO4J_URL, NEO4J_USER

log = logging.getLogger("recon.dbs")


# ---------------------------------------------------------------- MongoDB ---
_mongo_client = None
_mongo_ok: Optional[bool] = None


def mongo_enabled() -> bool:
    """True when MONGO_URL is set and pymongo imports."""
    global _mongo_ok
    if _mongo_ok is not None:
        return _mongo_ok
    if not MONGO_URL:
        _mongo_ok = False
        return False
    try:
        import pymongo  # noqa: F401
        _mongo_ok = True
    except Exception:
        _mongo_ok = False
    return _mongo_ok


def _mongo_db():
    global _mongo_client
    if not mongo_enabled():
        return None
    try:
        if _mongo_client is None:
            from pymongo import MongoClient
            _mongo_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=8000)
            _mongo_client.admin.command("ping")
        return _mongo_client["recon"]
    except Exception as exc:
        log.warning("mongo unavailable: %s", exc)
        _mongo_client = None
        return None


def mongo_archive_findings(run_id: str, findings: List[Dict[str, Any]]) -> int:
    """Archive a run's findings to MongoDB recon.findings. Returns count written."""
    db = _mongo_db()
    if db is None or not findings:
        return 0
    try:
        docs = []
        now = dt.datetime.now(dt.timezone.utc)
        for f in findings:
            docs.append({
                "run_id": run_id,
                "target_id": f.get("target_id"),
                "plugin_id": f.get("plugin_id"),
                "category": f.get("category"),
                "key": f.get("key"),
                "value": f.get("value"),
                "source": f.get("source"),
                "source_url": f.get("source_url"),
                "confidence": f.get("confidence"),
                "evidence": f.get("evidence"),
                "bounty_value": f.get("bounty_value"),
                "archived_at": now,
            })
        res = db["findings"].insert_many(docs, ordered=False)
        try:
            db["findings"].create_index([("run_id", 1), ("plugin_id", 1)])
            db["findings"].create_index("archived_at")
        except Exception:
            pass
        return len(res.inserted_ids)
    except Exception as exc:
        log.warning("mongo archive failed: %s", exc)
        return 0


# ------------------------------------------------------------------- Neo4j ---
_neo4j_driver = None
_neo4j_ok: Optional[bool] = None


def neo4j_enabled() -> bool:
    global _neo4j_ok
    if _neo4j_ok is not None:
        return _neo4j_ok
    if not NEO4J_URL:
        _neo4j_ok = False
        return False
    try:
        import neo4j  # noqa: F401
        _neo4j_ok = True
    except Exception:
        _neo4j_ok = False
    return _neo4j_ok


def _neo4j_session():
    global _neo4j_driver
    if not neo4j_enabled():
        return None
    try:
        if _neo4j_driver is None:
            from neo4j import GraphDatabase
            auth = (NEO4J_USER, NEO4J_PASSWORD) if NEO4J_PASSWORD else None
            _neo4j_driver = GraphDatabase.driver(NEO4J_URL, auth=auth)
            _neo4j_driver.verify_connectivity()
        return _neo4j_driver.session()
    except Exception as exc:
        log.warning("neo4j unavailable: %s", exc)
        try:
            if _neo4j_driver is not None:
                _neo4j_driver.close()
        except Exception:
            pass
        _neo4j_driver = None
        return None


def neo4j_push_graph(run_id: str, nodes: List[Dict[str, Any]],
                     edges: List[Dict[str, Any]]) -> int:
    """Push the asset graph to Neo4j. Returns edge count written."""
    session = _neo4j_session()
    if session is None or not nodes:
        return 0
    try:
        with session:
            session.run(
                "MERGE (r:Run {id: $run_id}) SET r.pushed_at = datetime()",
                run_id=run_id,
            )
            for n in nodes[:500]:
                session.run(
                    "MERGE (a:Asset {rid: $rid, nid: $nid}) "
                    "SET a.type=$type, a.label=$label "
                    "MERGE (r:Run {id: $run_id}) MERGE (r)-[:HAS]->(a)",
                    rid=run_id, nid=n.get("id"), type=n.get("type"),
                    label=str(n.get("label", ""))[:500], run_id=run_id,
                )
            written = 0
            for e in edges[:1000]:
                session.run(
                    "MATCH (r:Run {id: $run_id}) "
                    "MATCH (a:Asset {rid: $run_id, nid: $from}) "
                    "MATCH (b:Asset {rid: $run_id, nid: $to}) "
                    "MERGE (a)-[rel:LINKED {kind: $kind}]->(b)",
                    run_id=run_id, **{"from": e.get("from"),
                                      "to": e.get("to"),
                                      "kind": e.get("kind", "linked")},
                )
                written += 1
        return written
    except Exception as exc:
        log.warning("neo4j push failed: %s", exc)
        return 0


# ------------------------------------------------- Postgres backup engine ---
_backup_engine = None


def get_backup_engine():
    """SQLAlchemy engine for DATABASE_URL_BACKUP, or None."""
    global _backup_engine
    if _backup_engine is not None:
        return _backup_engine
    if not DATABASE_URL_BACKUP:
        return None
    try:
        from sqlalchemy import create_engine
        _backup_engine = create_engine(
            DATABASE_URL_BACKUP, pool_pre_ping=True, pool_size=2)
        with _backup_engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return _backup_engine
    except Exception as exc:
        log.warning("backup postgres unavailable: %s", exc)
        _backup_engine = None
        return None


def db_status() -> Dict[str, Any]:
    """Which of the 5 DBs are configured/usable. For the status endpoint."""
    out = {
        "postgres_primary": True,  # app fails fast at boot if unreachable
        "postgres_backup": bool(DATABASE_URL_BACKUP),
        "redis": False,
        "mongodb": mongo_enabled(),
        "neo4j": neo4j_enabled(),
    }
    try:
        from .config import REDIS_URL
        out["redis"] = bool(REDIS_URL)
    except Exception:
        pass
    return out
