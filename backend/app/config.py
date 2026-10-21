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
# 24 parallel plugins: plugins are I/O-bound (waiting on DNS/HTTP), so
# more slots keep the pipe full without hammering the target - the
# per-host rate limiter (DEFAULT_RPS) still paces actual requests, and
# WAF/challenge detection already throttles hostile targets. Was 16;
# raised 2026-10-20 because live scans showed throughput (~90 plugins
# per 600s at 16 slots on the free-tier instance) was the binding
# constraint cutting plugins on the scan budget. Env-overridable.
MAX_CONCURRENCY = int(env("RECON_CONCURRENCY", "24"))
# Per-host request pacing. 50 RPS is still polite for authorized testing
# (a single browser tab bursts more than this) and keeps the bulk-sweep
# plugins (artifacts, backup, cloud_buckets: hundreds of probe requests
# each) from serializing behind one shared 25 RPS budget - at 25 RPS the
# sweeps alone needed 40s+ of limiter queuing. Lower it if a target
# rate-limits.
DEFAULT_RPS = float(env("RECON_RPS", "50"))
EVIDENCE_DIR = env("RECON_EVIDENCE_DIR", "./evidence")
