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
import os

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
    # sandbox | live - the app mode the run was created under (settings).
    # Stamped at creation; sandbox runs never count as production findings.
    env_mode = Column(String, default="sandbox")
    source_type = Column(String, default="website")  # website | bank | atm
    status = Column(String, default="running")  # running | done | error
    # Owning customer (users.id) for GitHub-signed-in runs; NULL for the
    # owner's access-code runs. Plan gating + reveal caps key off this.
    user_id = Column(Integer, nullable=True, index=True)
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


class AppSetting(Base):
    """Key/value app settings (scan mode, owned-assets allowlist, ...)."""
    __tablename__ = "app_settings"
    key = Column(String, primary_key=True)
    value = Column(JSON, default=dict)
    updated_at = Column(DateTime(timezone=True), default=_utcnow)


class AuditLog(Base):
    """Append-only audit trail for settings-level actions (mode switches)."""
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime(timezone=True), default=_utcnow, index=True)
    action = Column(String)
    actor = Column(String, default="ui")
    detail = Column(JSON, default=dict)


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


class KnownAsset(Base):
    # The hunters' KNOWN SET: every confirmed asset for a target, persisted
    # across runs and namespaced by agent system so other agent systems
    # (Error Inbox swarm, bro-agent) can keep their own sets in the same
    # store. Hunters expand FROM this set: each asset type has pivot rules
    # that generate candidates, the detection plugins verify them, and
    # confirmed candidates join the set and expand again.
    __tablename__ = "known_assets"
    id = Column(Integer, primary_key=True, autoincrement=True)
    system = Column(String, default="recon", index=True)
    target_key = Column(String, index=True)  # root target, e.g. example.com
    asset_type = Column(String, index=True)  # domain|subdomain|ip|url|email|wallet|repo|js_file|endpoint|cert|org
    value = Column(Text, index=True)
    found_by = Column(String, default="")  # hunter or plugin that confirmed it
    first_run_id = Column(String, index=True)
    last_run_id = Column(String, index=True)
    depth = Column(Integer, default=0)  # pivot depth at which it was found
    meta = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    updated_at = Column(DateTime(timezone=True), default=_utcnow)


class HuntAction(Base):
    # Full audit trail for the hunter layer: every asset found, job
    # enqueued, dead end recorded, and expansion pass, per hunter.
    __tablename__ = "hunt_actions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String, index=True)
    system = Column(String, default="recon", index=True)
    target_key = Column(String, index=True)
    hunter = Column(String, index=True)
    action = Column(String, index=True)  # asset_found|job_enqueued|dead_end|expand_pass|note
    asset_type = Column(String, default="")
    asset_value = Column(Text, default="")
    detail = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class HuntMemory(Base):
    # Per-target hunt memory, one row per (system, target_key). Hunters
    # read this before expanding a repeat target: what is already known,
    # which branches were dead ends, and how the known set grew per run.
    __tablename__ = "hunt_memory"
    id = Column(Integer, primary_key=True, autoincrement=True)
    system = Column(String, default="recon", index=True)
    target_key = Column(String, index=True)
    assets_by_type = Column(JSON, default=dict)  # {asset_type: count}
    finding_counts = Column(JSON, default=dict)  # {category: count} cumulative
    dead_ends = Column(JSON, default=list)  # [{type, value, run_id, reason}]
    runs = Column(JSON, default=list)  # [{run_id, at, known_before, known_after, findings}]
    notes = Column(JSON, default=list)  # free-form memory notes from hunters
    updated_at = Column(DateTime(timezone=True), default=_utcnow)


class ResourceCache(Base):
    # Fetched library resources (wordlists, pattern packs, references)
    # cached by the agent data service with source URL + attribution, so
    # hunters consult the real public material at hunt time.
    __tablename__ = "resource_cache"
    id = Column(String, primary_key=True)  # resource id from the registry
    source_url = Column(Text)
    attribution = Column(Text, default="")
    content = Column(Text)  # cached body (truncated at fetch time)
    fetched_at = Column(DateTime(timezone=True), default=_utcnow)
    size_bytes = Column(Integer, default=0)


class User(Base):
    """A GitHub-signed-in customer (app/billing.py). The owner account
    (OWNER_GITHUB_LOGIN, default jaykk99) also lands here on sign-in;
    billing.effective_plan gives it full access with no payment UI."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    github_id = Column(Integer, unique=True, index=True)
    github_login = Column(String, index=True)
    plan = Column(String, default="free")  # free | starter | pro | agency
    plan_expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class Order(Base):
    """A BTC checkout order. amount_btc is pinned at creation from the
    live rate and stored as an exact decimal string. Status flow:
    pending -> paid (owner-approved from /admin/orders after the
    payment confirms) | cancelled."""
    __tablename__ = "orders"
    id = Column(String, primary_key=True)  # uuid hex
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    plan = Column(String)  # starter | pro | agency
    amount_usd = Column(Integer)
    amount_btc = Column(String)  # exact decimal string, 8dp
    btc_address = Column(String)
    status = Column(String, default="pending", index=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    paid_at = Column(DateTime(timezone=True), nullable=True)


class AuthAcceptance(Base):
    """LEGACY (Authenticated Mode removed 2026-10-23): table left in
    place harmlessly; no code reads or writes it anymore.

    One-time Authenticated Mode attestation, per account identity.

    The user accepts the warning text ONCE ("I own my targets or have
    written permission to test them; my attestations are logged"); the
    acceptance row is the server-side proof. Authenticated runs are
    rejected for identities with no acceptance of the current text
    version. identity_key is "owner" for the access-code/owner-login
    caller, "user:<id>" for signed-in customers.
    """
    __tablename__ = "auth_acceptances"
    id = Column(Integer, primary_key=True, autoincrement=True)
    identity_key = Column(String, unique=True, index=True)
    identity_label = Column(String)  # github login or "owner"
    text_version = Column(String)  # version of the accepted text
    accepted_at = Column(DateTime(timezone=True), default=_utcnow)
    client_ip = Column(String, nullable=True)


class RunAuth(Base):
    """LEGACY (Authenticated Mode removed 2026-10-23): table left in
    place harmlessly; no code reads or writes it anymore.

    Per-run authenticated-scan stamp + encrypted credentials.

    secret_enc holds the run's credential config, Fernet-encrypted
    (app/authscan.py). It is decrypted only inside the worker while
    the run executes and is WIPED (set NULL, wiped_at stamped) when
    the run finishes. The attestation columns (acceptance reference,
    creator, hosts, timestamp) are the permanent audit stamp and
    contain no secret material.
    """
    __tablename__ = "run_auth"
    run_id = Column(String, ForeignKey("runs.id"), primary_key=True)
    auth_type = Column(String)  # cookie | bearer | basic | headers
    secret_enc = Column(Text, nullable=True)
    acceptance_id = Column(Integer, nullable=True)
    attested_by = Column(String)  # identity label of the run's creator
    target_hosts = Column(JSON, default=list)  # seed hosts auth may touch
    client_ip = Column(String, nullable=True)
    attested_at = Column(DateTime(timezone=True), default=_utcnow)
    wiped_at = Column(DateTime(timezone=True), nullable=True)


class FindingReveal(Base):
    """Free-tier reveal ledger: one row per (user, UTC day) - the single
    finding that user got fully revealed that day, across all runs."""
    __tablename__ = "finding_reveals"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    run_id = Column(String, index=True)
    finding_id = Column(Integer, index=True)
    day = Column(String, index=True)  # YYYY-MM-DD (UTC)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


class PaymentWatch(Base):
    """One row per BTC checkout order: the DIY payment watcher state.

    A NEW table (create_all builds it on fresh DBs and on the live
    Postgres at boot); the orders table is never altered. The payer
    address is public on-chain data the buyer voluntarily provides.
    No private key, seed, or wallet-connection data ever lands here:
    only public addresses, public txids, and amounts.
    Status flow: pending -> underpaid | confirmed | expired.
    A txid is claimed by at most one watch (unique constraint) so one
    payment can never unlock two purchases.
    """
    __tablename__ = "payment_watches"
    id = Column(Integer, primary_key=True, autoincrement=True)
    order_id = Column(String, ForeignKey("orders.id"), unique=True,
                      index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    payer_address = Column(String, nullable=True)
    expected_sats = Column(Integer)
    threshold_sats = Column(Integer)
    status = Column(String, default="pending", index=True)
    txid = Column(String, unique=True, nullable=True, index=True)
    tx_received_sats = Column(Integer, default=0)
    confirmations = Column(Integer, default=0)
    seen_sats = Column(Integer, default=0)
    seen_txid = Column(String, nullable=True)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    late_payment_note = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)


connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
if DATABASE_URL.startswith("sqlite"):
    # SQLite concurrency recipe (2026-10-23 speed pass): the worker now
    # runs job load/persist/claim DB work on executor threads (on
    # Postgres that is the designed mode - see the pool sizing note
    # below), which means several threads write this file at once.
    # Stock SQLite settings turned that into a lock convoy: writers
    # errored with "database is locked" after the driver's 5s default
    # wait, SQLAlchemy invalidated the connections, and the pool
    # churned (measured locally: 294s of cursor time for the same
    # statements that took 13s serialized). WAL lets readers and the
    # single writer proceed concurrently, and a 30s busy timeout makes
    # writers queue inside SQLite instead of erroring. The driver's
    # own `timeout` connect arg is the same busy handler; both are set
    # because the PRAGMA is per-connection and the pool recycles them.
    connect_args = {"check_same_thread": False, "timeout": 30}
    engine = create_engine(DATABASE_URL, connect_args=connect_args,
                           pool_pre_ping=True)

    from sqlalchemy import event as _sa_event

    @_sa_event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _rec):
        try:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=30000")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()
        except Exception:
            pass
else:
    # Postgres: the default pool (5 + 10 overflow, 30s wait) starved under
    # the queue worker's concurrency and every API request 500'd after a
    # 30s pool wait. Size the pool for the worker + API + SSE load and
    # fail faster when it is genuinely exhausted. 30 + 30 since
    # 2026-10-21 to match the worker's 32 scan slots; 40 + 40 since
    # 2026-10-23 for the 64-slot worker (jobs check connections out
    # briefly at load/persist - now from executor threads - and never
    # hold one across plugin execution). Env-tunable per service if a
    # database plan's connection cap ever requires smaller pools.
    engine = create_engine(
        DATABASE_URL, connect_args=connect_args,
        pool_pre_ping=True,
        pool_size=int(os.environ.get("RECON_DB_POOL_SIZE", "40")),
        max_overflow=int(os.environ.get("RECON_DB_MAX_OVERFLOW", "40")),
        pool_timeout=10, pool_recycle=1800)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    # Self-healing column/index backfill for pre-existing databases.
    # create_all only creates MISSING tables - it never adds columns to
    # tables that already exist. A direct push to master (e.g. the daily
    # code-quota workers) that adds a model column would otherwise break
    # every INSERT on the live Postgres DB (2026-10-20: plugin_jobs
    # .estimate_s was added by a quota push and the live DB predated it).
    # ADD COLUMN IF NOT EXISTS works on both Postgres and SQLite, so this
    # runs everywhere, on every boot, and is a no-op when current.
    is_sqlite = IS_SQLITE
    for table, column, ddl in (
        ("runs", "source_type", "VARCHAR DEFAULT 'website'"),
        ("runs", "env_mode", "VARCHAR DEFAULT 'sandbox'"),
        ("runs", "user_id", "INTEGER"),
        ("plugin_jobs", "estimate_s", "INTEGER DEFAULT 12"),
    ):
        try:
            with engine.connect() as conn:
                if is_sqlite:
                    # SQLite has no ADD COLUMN IF NOT EXISTS - inspect
                    # the table first like the old code did.
                    cols = [r[1] for r in
                            conn.exec_driver_sql(
                                f"PRAGMA table_info({table})")]
                    if column not in cols:
                        conn.exec_driver_sql(
                            f"ALTER TABLE {table} ADD COLUMN "
                            f"{column} {ddl}")
                        conn.commit()
                else:
                    conn.exec_driver_sql(
                        f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS "
                        f"{column} {ddl}")
                    conn.commit()
        except Exception as exc:  # keep booting on any schema oddity
            log.warning("schema backfill skipped for %s.%s: %s",
                        table, column, exc)
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_runs_created_at "
                "ON runs (created_at)")
            conn.commit()
    except Exception as exc:
        log.warning("schema backfill skipped for ix_runs_created_at: %s",
                    exc)


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
