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

# Node may live in ~/.local from the linux-setup.sh user-local install
# (no sudo): pick it up here too so start works after a fresh setup.
if ! command -v node >/dev/null 2>&1; then
  for d in "$HOME"/.local/node-v*/bin; do
    [ -x "$d/node" ] && export PATH="$d:$PATH" && break
  done
fi

# Phone pair code: one 6-digit code per boot, printed at the end with
# the phone command. The backend reads it from RECON_PAIR_CODE and
# lets a phone exchange it once for the access code (GET /api/pair).
PAIR_CODE="$(shuf -i 100000-999999 -n 1 2>/dev/null || echo $((RANDOM % 900000 + 100000)))"
export RECON_PAIR_CODE="$PAIR_CODE"
# Termux is the phone itself: no phone block to print there.
IS_TERMUX=0
[ -d /data/data/com.termux ] && IS_TERMUX=1

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
if [ "$IS_TERMUX" = 0 ]; then
  LAN="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [ -n "$LAN" ]; then
    echo
    echo "On your phone (Termux), paste this one command to scan from the phone:"
    echo "  curl -s http://$LAN:8000/recon-client.py | python3 - $PAIR_CODE scan <target>"
    echo "The code lasts 10 minutes and works once. Then save the client on the phone:"
    echo "  curl -s http://$LAN:8000/recon-client.py -o recon.py"
    echo "  python3 recon.py scan <target>   (needs python3 in Termux: pkg install python)"
  fi
fi
wait
