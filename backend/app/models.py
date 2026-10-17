"""SQLAlchemy data model.

Tables: runs, targets, plugins, findings, nodes, edges, evidence,
api_keys, snapshots, schedules. Every finding stores run_id + plugin_id +
timestamp so any result is reproducible and diffable.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import (Boolean, Column, DateTime, Float, ForeignKey, Integer,
                        JSON, String, Text, UniqueConstraint, create_engine)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from .config import DATABASE_URL

Base = declarative_base()


def _utcnow():
    return dt.datetime.now(dt.timezone.utc)


class Run(Base):
    __tablename__ = "runs"
    id = Column(String, primary_key=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow)
    finished_at = Column(DateTime(timezone=True), nullable=True)
    mode = Column(String, default="passive")  # passive | active
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


connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def get_session():
    return SessionLocal()
