#!/usr/bin/env bash
# ReconAnything local run, one command (Linux). Safe to re-run.
# Pulls latest, sets up on first run (or when pieces are missing),
# then starts the worker + API + web UI.
#
# From inside the repo clone:
#   bash local-run/run.sh
# From anywhere (fresh machine):
#   curl -fsSL https://raw.githubusercontent.com/jaykk99/recon-anything/master/local-run/bootstrap.sh | bash
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -d .git ]; then
  git pull --ff-only || echo "WARNING: git pull failed (local changes or offline); continuing with this checkout." >&2
fi

NEED_SETUP=0
[ -x .venv/bin/python ] || NEED_SETUP=1
[ -f .local-env ] || NEED_SETUP=1
[ -f frontend/.next/standalone/server.js ] || NEED_SETUP=1
if [ "$NEED_SETUP" = 1 ]; then
  echo "First run (or missing pieces): running setup..."
  bash local-run/linux-setup.sh
else
  echo "Setup already done; starting."
fi

bash local-run/linux-start.sh
