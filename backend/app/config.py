"""Configuration from environment."""
from __future__ import annotations

import os


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


DATABASE_URL = env("DATABASE_URL", "sqlite:///./recon.db")
REDIS_URL = env("REDIS_URL", "")
ACCESS_CODE = env("RECON_ACCESS_CODE", "")  # single-user gate; empty = no gate
PIN = env("RECON_PIN", "")  # numeric screen-lock PIN; empty = no PIN gate
MASTER_KEY = env("RECON_MASTER_KEY", "")  # Fernet key for API key encryption
USER_AGENT = "ReconAnything/1.0 (+https://github.com/jaykk99/recon-anything)"
DEFAULT_TIMEOUT = float(env("RECON_TIMEOUT", "20"))
MAX_CONCURRENCY = int(env("RECON_CONCURRENCY", "8"))
EVIDENCE_DIR = env("RECON_EVIDENCE_DIR", "./evidence")
