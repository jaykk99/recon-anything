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
#    missing tools are skipped gracefully by the app). Python 3.11+ and
#    Node 20+ required; both are installed user-local below when missing.
command -v python3 >/dev/null 2>&1 || { echo "Missing python3 (>= 3.11). Install it first." >&2; exit 1; }
if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "python3-venv is missing; trying to install it..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y python3-venv python3-full 2>/dev/null || true
  fi
  python3 -m venv --help >/dev/null 2>&1 || {
    echo "ERROR: python3 -m venv still fails. On Debian/Ubuntu run: sudo apt-get install -y python3-venv python3-full" >&2
    exit 1
  }
fi
NODE_VERSION="$(node --version 2>/dev/null | sed 's/^v//; s/\..*//')"
if [ -z "$NODE_VERSION" ] || [ "$NODE_VERSION" -lt 20 ] 2>/dev/null; then
  echo "Node 20+ is missing; installing Node 20 user-local (no sudo)..."
  NODE_VER="20.18.1"
  NODE_DIR="$HOME/.local/node-v$NODE_VER-linux-x64"
  if [ ! -x "$NODE_DIR/bin/node" ]; then
    TMPD="$(mktemp -d)"
    curl -fsSL "https://nodejs.org/dist/v$NODE_VER/node-v$NODE_VER-linux-x64.tar.xz" -o "$TMPD/node.tar.xz" || {
      echo "ERROR: could not download Node $NODE_VER. Install Node 20+ first (https://nodejs.org)." >&2
      rm -rf "$TMPD"
      exit 1
    }
    mkdir -p "$HOME/.local"
    tar -xf "$TMPD/node.tar.xz" -C "$HOME/.local"
    rm -rf "$TMPD"
  fi
  export PATH="$NODE_DIR/bin:$PATH"
  echo "Node $(node --version) installed to $NODE_DIR"
fi
for tool in node npm; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing $tool. Install Node 20+ first (https://nodejs.org)." >&2; exit 1; }
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
