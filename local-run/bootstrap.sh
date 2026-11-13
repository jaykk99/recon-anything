#!/usr/bin/env bash
# One-command Linux install + run for ReconAnything. Paste this:
#   curl -fsSL https://raw.githubusercontent.com/jaykk99/recon-anything/master/local-run/bootstrap.sh | bash
# Clones to ~/recon-anything (or pulls if already there), then runs
# local-run/run.sh: setup on first run, then worker + API + web UI.
# Loud failures: any failed step stops here with the error visible.
set -euo pipefail
DIR="${RECON_DIR:-$HOME/recon-anything}"
if [ -d "$DIR/.git" ]; then
  echo "Updating $DIR ..."
  git -C "$DIR" pull --ff-only || {
    echo "ERROR: git pull failed in $DIR (local changes?). Fix it or move the folder." >&2
    exit 1
  }
elif [ -e "$DIR" ]; then
  echo "ERROR: $DIR exists but is not a git clone. Move it and re-run." >&2
  exit 1
else
  echo "Cloning into $DIR ..."
  git clone https://github.com/jaykk99/recon-anything.git "$DIR" || {
    echo "ERROR: git clone failed. Check internet and git." >&2
    exit 1
  }
fi
bash "$DIR/local-run/run.sh"
