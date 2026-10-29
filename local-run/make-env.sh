#!/usr/bin/env bash
# Generate .local-env and .local-access-code at the repo root if missing.
# Local-only owner mode: a random access code plus a Fernet master key.
# These files are never committed (see .gitignore).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
umask 077

PY="${1:-$ROOT/.venv/bin/python}"
if [ ! -x "$PY" ]; then
  PY="$(command -v python3 || command -v python)"
fi

if [ ! -f .local-access-code ]; then
  "$PY" -c "import secrets; print(secrets.token_urlsafe(18))" > .local-access-code
  chmod 600 .local-access-code
  echo "Generated a local access code (.local-access-code)."
fi

if [ ! -f .local-env ]; then
  KEY="$("$PY" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || echo "")"
  {
    printf 'RECON_ACCESS_CODE=%s\n' "$(cat .local-access-code)"
    printf 'RECON_MASTER_KEY=%s\n' "$KEY"
    printf 'RECON_API_URL=%s\n' "http://127.0.0.1:8000"
  } > .local-env
  chmod 600 .local-env
  echo "Wrote .local-env."
fi
