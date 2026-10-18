"""Configuration from environment."""
from __future__ import annotations

import os


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


DATABASE_URL = env("DATABASE_URL", "sqlite:///./recon.db")
REDIS_URL = env("REDIS_URL", "")
ACCESS_CODE = env("RECON_ACCESS_CODE", "")  # single-user gate; empty = no gate
MASTER_KEY = env("RECON_MASTER_KEY", "")  # Fernet key for API key encryption
USER_AGENT = "ReconAnything/1.0 (+https://github.com/jaykk99/recon-anything)"
DEFAULT_TIMEOUT = float(env("RECON_TIMEOUT", "20"))
# 5 parallel plugins: steady streaming batches Jay can check as they land,
# fast enough without hammering the target or tripping its WAF.
MAX_CONCURRENCY = int(env("RECON_CONCURRENCY", "5"))
# Per-host request pacing. 25 RPS is still polite for authorized testing
# (a single browser tab does more) and keeps bulk sweeps from serializing
# behind one shared 10 RPS budget. Lower it if a target rate-limits.
DEFAULT_RPS = float(env("RECON_RPS", "25"))
EVIDENCE_DIR = env("RECON_EVIDENCE_DIR", "./evidence")
