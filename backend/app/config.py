"""Configuration from environment."""
from __future__ import annotations

import os


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


DATABASE_URL = env("DATABASE_URL", "sqlite:///./recon.db")
DATABASE_URL_BACKUP = env("DATABASE_URL_BACKUP", "")  # second Postgres (Railway); failover only
REDIS_URL = env("REDIS_URL", "")  # Upstash Redis: shared cache layer
MONGO_URL = env("MONGO_URL", "")  # MongoDB Atlas: findings archive
NEO4J_URL = env("NEO4J_URL", "")  # Neo4j Aura: asset graph sink
NEO4J_USER = env("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = env("NEO4J_PASSWORD", "")
ACCESS_CODE = env("RECON_ACCESS_CODE", "")  # single-user gate; empty = no gate
MASTER_KEY = env("RECON_MASTER_KEY", "")  # Fernet key for API key encryption
USER_AGENT = "ReconAnything/1.0 (+https://github.com/jaykk99/recon-anything)"
DEFAULT_TIMEOUT = float(env("RECON_TIMEOUT", "20"))
# 32 parallel plugins: plugins are I/O-bound (waiting on DNS/HTTP), so
# more slots keep the pipe full without hammering the target - the
# per-host rate limiter (DEFAULT_RPS) still paces actual requests, and
# WAF/challenge detection already throttles hostile targets. Was 16,
# then 24 (2026-10-20); raised to 32 on 2026-10-21 with the
# anti-starvation dispatch order, because even at 24 slots the scan
# budget ceiling - not plugin slowness alone - was cutting 34 of 170
# plugins. The worker's DB pool is sized to match (models.py:
# RECON_DB_POOL_SIZE/OVERFLOW, default 30+30); plugin jobs never hold a
# pooled connection across execution (the 2026-10-20 outage rule), so
# slot count does not translate into held connections. Env-overridable.
MAX_CONCURRENCY = int(env("RECON_CONCURRENCY", "32"))
# Per-host request pacing. Raised 50 -> 100 on 2026-10-23 (speed pass):
# profiling a full 552-plugin fixture run showed ~4,800 requests to the
# target host, so at 50 RPS the limiter alone imposed a ~96s floor on
# wall time - the single largest pacing constraint in the run. 100 RPS
# is still modest for authorized testing (a browser tab bursts more),
# and the protections are unchanged: WAF/challenge detection drops a
# hostile host to the 1 RPS graceful floor, 429/Retry-After is honored,
# and the per-host circuit breaker (ratelimit.py) fast-fails dead hosts.
# Lower it via RECON_RPS if a target rate-limits.
DEFAULT_RPS = float(env("RECON_RPS", "100"))
EVIDENCE_DIR = env("RECON_EVIDENCE_DIR", "./evidence")
