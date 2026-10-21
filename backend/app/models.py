"""SQLAlchemy data model.

Tables: runs, targets, plugins, findings, nodes, edges, evidence,
api_keys, snapshots, schedules. Every finding stores run_id + plugin_id +
timestamp so any result is reproducible and diffable.

Storage: DATABASE_URL comes from the environment (see config.py). SQLite is
the local-dev default; on Render's free tier the SQLite file lives on an
ephemeral disk and is wiped on every redeploy, so production must point
DATABASE_URL at a persistent Postgres (Neon or Supabase free tier both work;
psycopg2 is already in requirements.txt).
"""
from __future__ import annotations

import datetime as dt
import logging

from sqlalchemy import (Boolean, Column, DateTime, ForeignKey, Integer,
                        JSON, String, Text, create_engine)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from .config import DATABASE_URL as _RAW_DATABASE_URL

log = logging.getLogger("recon-anything.db")


def _normalize_database_url(url: str) -> str:
    """Normalize provider URLs for this stack (SQLAlchemy 2.x + psycopg2).

    - Some providers (Heroku-style) hand out ``postgres://`` URLs, which
      SQLAlchemy 2.x rejects outright. Rewrite to ``postgresql://``.
    - A bare ``postgresql://`` URL makes SQLAlchemy 2.x reach for the
      ``psycopg`` (v3) driver, which is NOT installed (requirements ship
      ``psycopg2-binary``). Pin the driver explicitly so a pasted Neon /
      Supabase / Render connection string just works.
    - URLs that already name a driver (``postgresql+psycopg2://``,
      ``postgresql+psycopg://``) are left untouched.
    """
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


DATABASE_URL = _normalize_database_url(_RAW_DATABASE_URL)
IS_SQLITE = DATABASE_URL.startswith("sqlite")

Base = declarative_base()


def _utcnow():
    return dt.datetime.now(dt.timezone.utc)


class Run(Base):
    __tablename__ = "runs"
    id = Column(String, primary_key=True)
    # Indexed: GET /api/runs orders by created_at desc on every poll; without
    # the index the list endpoint did a full-table sort (~6s idle wart,
    # fixed 2026-10-20). Fresh DBs get it via init_db/create_all.
    created_at = Column(DateTime(timezone=True), default=_utcnow, index=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    mode = Column(String, default="passive")  # passive | active
    source_type = Column(String, default="website")  # website | bank | atm
    status = Column(String, default="running")  # running | done | error
    summary = Column(JSON, default=dict)
    targets = relationship("Target", back_populates="run", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="run", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "targets"
    id = Column(String, primary_key=True)
    run_id = Column(String, ForeignKey("runs.id"), index=True)
    raw = Column(Text)
    type = Column(String)
    normalized = Column(Text)
    run = relationship("Run", back_populates="targets")


class PluginRec(Base):
    __tablename__ = "plugins"
    id = Column(String, primary_key=True)  # plugin id, e.g. "dns"
    label = Column(String)
    group = Column(String)
    cost = Column(String)
    last_seen = Column(DateTime(timezone=True), default=_utcnow)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String, ForeignKey("runs.id"), index=True)
    target_id = Column(String, index=True)
    plugin_id = Column(String, index=True)
    category = Column(String, index=True)
    key = Column(String, index=True)
    value = Column(Text)
    source = Column(String)
    source_url = Column(String, nullable=True)
    confidence = Column(Integer, default=80)
    evidence = Column(JSON, nullable=True)
    passive = Column(Boolean, default=True)
    first_seen = Column(DateTime(timezone=True), default=_utcnow)
    raw = Column(JSON, nullable=True)
    bounty_value = Column(String, default="low")  # critical | high | medium | low
    run = relationship("Run", back_populates="findings")


class Node(Base):
    __tablename__ = "nodes"
    id = Column(String, primary_key=True)
    run_id = Column(String, index=True)
    kind = Column(String, index=True)  # domain, ip, subdomain, cert, endpoint, ...
    label = Column(Text)
    interesting = Column(Boolean, default=False)
    meta = Column(JSON, default=dict)


class Edge(Base):
    __tablename__ = "edges"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String, index=True)
    src = Column(String, index=True)
    dst = Column(String, index=True)
    relation = Column(String)
    confidence = Column(Integer, default=80)
    provenance = Column(String, default="")


class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(String, primary_key=True)
    run_id = Column(String, index=True)
    kind = Column(String)  # html | headers | json | text
    label = Column(String)
    path = Column(String)  # file on disk under EVIDENCE_DIR
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class ApiKey(Base):
    __tablename__ = "api_keys"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True)  # e.g. "shodan"
    label = Column(String)
    secret_enc = Column(Text)  # Fernet or plaintext w/ prefix
    updated_at = Column(DateTime(timezone=True), default=_utcnow)


class Snapshot(Base):
    __tablename__ = "snapshots"
    id = Column(String, primary_key=True)
    run_id = Column(String, index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    blob = Column(JSON)  # frozen findings summary for diffing


class Schedule(Base):
    __tablename__ = "schedules"
    id = Column(String, primary_key=True)
    target_raw = Column(Text)
    cron = Column(String)
    mode = Column(String, default="passive")
    enabled = Column(Boolean, default=True)
    last_run_id = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class AIHunter(Base):
    __tablename__ = "aihunter"
    run_id = Column(String, primary_key=True)
    status = Column(String, default="idle")  # idle | analyzing | ready | failed
    provider = Column(String, default="")  # which keyless provider answered
    results = Column(JSON, default=dict)  # parsed test plan + local playbooks
    error = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow)


class RunEvent(Base):
    # Durable SSE event log per run. The in-memory bus (RUN_EVENT_BUFFER)
    # is per-process and dies on restart/deploy, which silently broke live
    # UI updates. Persisting events here makes /stream replay + follow
    # work across worker processes and restarts.
    __tablename__ = "run_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String, index=True)
    seq = Column(Integer, index=True)  # per-run ordering
    event = Column(String)  # run_start | plugin_start | plugin_done | progress | finding | run_done ...
    data = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class PluginJob(Base):
    # DB-backed plugin job queue. Every (plugin x target) pair of a scan is
    # a row here. A background worker claims queued rows, runs them, and
    # writes results back. If the server restarts mid-scan (deploy/crash),
    # jobs left in queued/running are picked back up on boot - the scan
    # resumes instead of dying. The frontend polls run state from these
    # rows (via run_progress), never from in-memory state.
    __tablename__ = "plugin_jobs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String, ForeignKey("runs.id"), index=True)
    target_id = Column(String, index=True)
    plugin_id = Column(String, index=True)
    phase = Column(Integer, default=1)  # 1 = main pass, 2 = chain consumers
    priority = Column(Integer, default=2)  # 1 = HIGH, 2 = MEDIUM, 3 = LOW
    # Estimated seconds for this plugin (from PLUGIN_TIME_ESTIMATES at
    # enqueue). The claim query orders by (priority, phase, estimate_s) so
    # fast plugins stream their findings first *within* each tier -
    # Jay's priority policy is untouched, quick wins just land earlier.
    estimate_s = Column(Integer, default=12)
    status = Column(String, default="queued", index=True)  # queued|running|done|skipped|failed
    attempts = Column(Integer, default=0)
    result = Column(JSON, nullable=True)  # {status, reason, findings, ms}
    worker = Column(String, nullable=True)  # worker id holding the claim
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)


connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args=connect_args,
                           pool_pre_ping=True)
else:
    # Postgres: the default pool (5 + 10 overflow, 30s wait) starved under
    # the queue worker's concurrency and every API request 500'd after a
    # 30s pool wait. Size the pool for the worker + API + SSE load and
    # fail faster when it is genuinely exhausted.
    engine = create_engine(DATABASE_URL, connect_args=connect_args,
                           pool_pre_ping=True, pool_size=20, max_overflow=20,
                           pool_timeout=10, pool_recycle=1800)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    if not IS_SQLITE:
        return  # create_all handles schema on real DBs; the backfill below is sqlite-only
    # Lightweight migration for pre-existing SQLite DBs: create_all does not
    # add columns to tables that already exist, so backfill source_type when
    # missing.
    try:
        with engine.connect() as conn:
            cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(runs)")]
            if "source_type" not in cols:
                conn.exec_driver_sql(
                    "ALTER TABLE runs ADD COLUMN source_type VARCHAR DEFAULT 'website'")
                conn.commit()
    except Exception as exc:  # corrupted/legacy sqlite file; keep booting
        log.warning("sqlite schema backfill skipped: %s", exc)


def _safe_url(url: str) -> str:
    """DATABASE_URL with the password masked, for log/error output."""
    try:
        from sqlalchemy.engine import make_url
        u = make_url(url)
        return str(u.set(password="***")) if u.password else str(u)
    except Exception:
        return "<database url>"


def check_db() -> None:
    """Fail fast when the database is unreachable.

    Called once at startup: a DATABASE_URL pointing at a Postgres that
    refuses connections (wrong host, bad password, SSL off) must crash the
    deploy with a clear log line instead of surfacing later as empty scans
    and "run not found" errors.
    """
    global engine, SessionLocal
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return
    except Exception as exc:
        from .config import DATABASE_URL_BACKUP
        if DATABASE_URL_BACKUP:
            log.warning("primary database unreachable, failing over to DATABASE_URL_BACKUP")
            try:
                backup_url = _normalize_database_url(DATABASE_URL_BACKUP)
                engine = create_engine(
                    backup_url,
                    connect_args={"check_same_thread": False}
                    if backup_url.startswith("sqlite") else {},
                    pool_pre_ping=True,
                )
                SessionLocal = sessionmaker(
                    bind=engine, autoflush=False, autocommit=False)
                with engine.connect() as conn:
                    conn.exec_driver_sql("SELECT 1")
                log.warning("failover to backup database succeeded")
                return
            except Exception as exc2:
                raise RuntimeError(
                    f"cannot connect to database ({_safe_url(DATABASE_URL)}): {exc2}. "
                    "Set DATABASE_URL to a reachable Postgres (Neon/Supabase free tier) "
                    "or unset it to use the local SQLite default."
                ) from exc2
        raise RuntimeError(
            f"cannot connect to database ({_safe_url(DATABASE_URL)}): {exc}. "
            "Set DATABASE_URL to a reachable Postgres (Neon/Supabase free tier) "
            "or unset it to use the local SQLite default."
        ) from exc


def get_session():
    return SessionLocal()
