#!/usr/bin/env bash
# Shared launcher for ReconAnything local runs (Linux + Termux).
# Starts the three processes the production container runs:
#   1. scan worker   (python -m app.worker_main, health on its own port 10000)
#   2. API backend   (uvicorn on 127.0.0.1:8000)
#   3. web frontend  (Next.js standalone on $PORT, default 3000, serves the UI
#                     and proxies /api/* to the backend)
# Run linux-setup.sh or termux-setup.sh first.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -f .local-env ]; then
  echo "Missing .local-env. Run the setup script for your platform first." >&2
  exit 1
fi
set -a
. ./.local-env
set +a
export RECON_API_URL="${RECON_API_URL:-http://127.0.0.1:8000}"
export PORT="${PORT:-3000}"

PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "Missing .venv. Run the setup script for your platform first." >&2
  exit 1
fi
if [ ! -f frontend/.next/standalone/server.js ]; then
  echo "Frontend is not built. Run the setup script for your platform first." >&2
  exit 1
fi

PIDS=""
cleanup() {
  echo
  echo "Stopping ReconAnything..."
  # shellcheck disable=SC2086
  kill $PIDS 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "Starting scan worker..."
(cd backend && while true; do
   PORT=10000 "$PY" -m app.worker_main || true
   echo "[worker] exited, restarting in 5s"
   sleep 5
 done) &
PIDS="$PIDS $!"

echo "Starting API backend on 127.0.0.1:8000..."
(cd backend && "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8000) &
PIDS="$PIDS $!"

# Give the backend a moment so the first page load can reach it.
sleep 3

echo "Starting web UI on port $PORT..."
(cd frontend/.next/standalone && HOSTNAME=0.0.0.0 node server.js) &
PIDS="$PIDS $!"

echo
echo "ReconAnything is running:"
echo "  Open http://localhost:$PORT on this device."
echo "  Sign in with the access code saved in .local-access-code"
echo "  (in the repo folder). Press Ctrl+C to stop everything."
wait
