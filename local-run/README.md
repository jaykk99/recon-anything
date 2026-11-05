# Run ReconAnything locally (Linux + Termux)

ReconAnything does not need a hosted server. The same three processes the
production container runs (scan worker, API backend, web frontend) run fine
on a Linux box or on an Android phone inside Termux. Scans are stored in a
local SQLite database (`backend/recon.db`), and the UI is served on port
3000.

## Linux

One-time setup (clone, Python venv, backend dependencies, frontend build,
local access code):

```bash
git clone https://github.com/jaykk99/recon-anything.git
cd recon-anything
bash local-run/linux-setup.sh
```

Start it:

```bash
bash local-run/linux-start.sh
```

Then open http://localhost:3000 in your browser. Sign in with the access
code printed in the `.local-access-code` file in the repo folder (it is
generated during setup, stored with owner-only permissions, and never
committed). Press Ctrl+C in the terminal to stop everything.

Requirements: Python 3.11+, Node 20+, git. The setup script also tries to
install the optional command-line tools some detectors shell out to
(`dig`, `curl`, `openssl`, `nc`); if they are missing, those detectors
skip themselves and the rest of the scan still runs.

## Termux (Android phone)

Install Termux from F-Droid or GitHub releases (the Play Store build is
outdated), open it, then:

```bash
pkg install -y git
git clone https://github.com/jaykk99/recon-anything.git
cd recon-anything
bash local-run/termux-setup.sh
```

Start it:

```bash
bash local-run/termux-start.sh
```

On the phone itself, open http://localhost:3000 in the phone browser.
That is the full app: sign in with the code in `.local-access-code`, start
scans, watch them live. To reach the phone UI from another device on the
same Wi-Fi, use the phone's local IP address instead of localhost, same
port 3000.

Practical phone notes:

- Setup takes a while on a phone: the frontend build is the slow step
  (several minutes). It only runs during setup, not on each start.
- Run `termux-wake-lock` in a second Termux session and keep Termux out
  of battery optimization, or Android may freeze the app mid-scan.
- A full default scan runs 600+ detection plugins and can take many
  minutes on a phone CPU. It works, it is just slower than a server.

### What is reduced on Termux

The core app (API, worker, UI, scanning engine) runs the same as on
Linux. Differences are only in optional extras:

- Screenshot findings need Playwright + Chromium, which are not practical
  in Termux. The screenshots plugin skips itself with a "not installed"
  note; every other plugin still runs.
- Command detectors that call `dig`, `curl`, `openssl`, or `nc` use the
  Termux packages installed by the setup script; any tool that is still
  missing is skipped gracefully, never a crash.
- Optional Python integrations (Redis cache, Postgres, MongoDB archive,
  Neo4j graph, bcrypt hash checks) are installed best-effort only. The app
  imports them lazily, so if a wheel cannot build on Android that feature
  simply stays off and the app still runs. Local runs use SQLite, so none
  of them are needed.
- Two core dependencies (`pydantic`, `cryptography`) ship as compiled
  wheels on desktop Linux. In Termux, pip may need to build them from
  source, which is why the setup script installs `clang` and `rust`
  first. If a source build still fails on your device, the setup stops
  with that error visible rather than pretending to succeed.

Status: the Linux path is verified end to end (setup, start, sign-in,
and a full real scan). The Termux scripts are syntax-checked and mirror
the verified Linux steps, but have not yet been run on a physical phone;
treat the first phone run as the device test and keep the setup output.
