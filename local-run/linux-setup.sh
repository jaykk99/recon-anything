#!/usr/bin/env bash
# ReconAnything local setup for Linux (Debian/Ubuntu-like; adapt the
# apt line to your distro). Safe to re-run: it updates the checkout,
# refreshes dependencies, and rebuilds the frontend.
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# 1. Code: update if this is already a clone, otherwise say how to clone.
if [ -d .git ]; then
  git pull --ff-only || echo "git pull skipped (local changes or offline)."
else
  echo "Run this script from inside the repo clone:" >&2
  echo "  git clone https://github.com/jaykk99/recon-anything.git" >&2
  exit 1
fi

# 2. System tools the command detectors use when present (all optional;
#    missing tools are skipped gracefully by the app). Node 20+ required.
for tool in python3 node npm; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing $tool. Install it first (python3 >= 3.11, node >= 20)." >&2; exit 1; }
done
if command -v apt-get >/dev/null 2>&1; then
  echo "Optional detector tools (skip with Ctrl+C if you lack sudo):"
  sudo apt-get install -y dnsutils curl openssl netcat-openbsd 2>/dev/null || \
    echo "Skipped optional tools; scans still run, cmd_* detectors will skip."
fi

# 3. Backend: venv + requirements.
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r backend/requirements.txt

# 4. Local owner-mode env (.local-env + .local-access-code).
bash local-run/make-env.sh

# 5. Frontend: install + production build + standalone static assets,
#    exactly like snapdeploy/Dockerfile does.
cd frontend
npm install --no-audit --no-fund
npm run build
rm -rf .next/standalone/.next/static
cp -r .next/static .next/standalone/.next/static
cd "$ROOT"

echo
echo "Setup done. Start it with:"
echo "  bash local-run/linux-start.sh"
echo "Then open http://localhost:3000 and sign in with the code in .local-access-code"
