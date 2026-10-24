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
# Parallel plugins: plugins are I/O-bound (waiting on DNS/HTTP), so
# more slots keep the pipe full without hammering the target - the
# per-host rate limiter (DEFAULT_RPS) still paces actual requests, and
# WAF/challenge detection already throttles hostile targets. Was 16,
# then 24 (2026-10-20); raised to 32 on 2026-10-21 with the
# anti-starvation dispatch order. Raised to 64 on 2026-10-23 (speed
# pass round 2): on the 587-plugin fixture benchmark, 32 slots sat
# half idle (mean 14.7 concurrent of 32) because hunter targets arrive
# over time and long plugins strand the tail; 64 slots cut wall time
# ~22% at the same RPS (158.7s -> 124.6s at 100 RPS) with no change in
# findings. The worker's DB pool is sized to match (models.py:
# RECON_DB_POOL_SIZE/OVERFLOW, default 40+40); plugin jobs never hold a
# pooled connection across execution (the 2026-10-20 outage rule), so
# slot count does not translate into held connections. Env-overridable.
MAX_CONCURRENCY = int(env("RECON_CONCURRENCY", "64"))
# Per-host request pacing. 50 -> 100 -> 200 on 2026-10-23 (speed pass):
# profiling a full fixture run showed ~5,000-5,700 requests to the
# target host, so at 50 RPS the limiter alone imposed a ~96s floor on
# wall time, and at 100 RPS it was still the binding constraint for the
# bulk sweepers (their plugin durations were mostly limiter queue).
# At 200 the pacing axis saturates (300 measured no faster), so 200 is
# where the honest knee is. The protections are unchanged: WAF /
# challenge detection drops a hostile host to the 1 RPS graceful floor,
# 429/Retry-After is honored, and the per-host circuit breaker
# (ratelimit.py) fast-fails dead hosts. This is an authorized-testing
# scanner; lower it via RECON_RPS if a target rate-limits.
DEFAULT_RPS = float(env("RECON_RPS", "200"))
EVIDENCE_DIR = env("RECON_EVIDENCE_DIR", "./evidence")
