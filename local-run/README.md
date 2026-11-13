# Run ReconAnything locally (Linux + Termux)

ReconAnything does not need a hosted server. The same three processes the
production container runs (scan worker, API backend, web frontend) run on
a Linux box, and a phone drives that box over the LAN with a thin client.
Scans are stored in a local SQLite database (`backend/recon.db`), and the
UI is served on port 3000.

## Linux: one command

Paste this on any Linux box (Debian/Ubuntu-like, or anything with git,
curl, and python3):

```bash
curl -fsSL https://raw.githubusercontent.com/jaykk99/recon-anything/master/local-run/bootstrap.sh | bash
```

That clones to `~/recon-anything` (or pulls if it is already there),
sets up on first run (Python venv + backend dependencies, frontend
build), and starts everything. Already have a clone? Just run this
inside it instead:

```bash
bash local-run/run.sh
```

Then open http://localhost:3000 in your browser. Sign in with the access
code printed in the `.local-access-code` file in the repo folder (it is
generated during setup, stored with owner-only permissions, and never
committed). Press Ctrl+C in the terminal to stop everything.

Setup needs Python 3.11+ and Node 20+. If Node is missing, the setup
installs Node 20 user-local (no sudo) by itself; if `python3-venv` is
missing it tries `sudo apt-get install -y python3-venv python3-full`
and otherwise stops with the exact command to run. The setup script
also tries to install the optional command-line tools some detectors
shell out to (`dig`, `curl`, `openssl`, `nc`); if they are missing,
those detectors skip themselves and the rest of the scan still runs.
Any failed step stops loudly with the error visible, never a silent
half-installed state. Safe to re-run: `run.sh` pulls latest and only
re-does the setup steps whose pieces are missing.

## Termux (Android phone): thin client, recommended

The phone does not run the stack. It drives the Linux box over the same
WiFi (no internet on the phone needed) with one small script that needs
only Python 3. When the Linux box starts, it prints the exact command:

```bash
curl -s http://<linux-ip>:8000/recon-client.py | python3 - <6-digit-code> scan <target>
```

The code is exchanged once for the access code and saved on the phone
(`~/.recon-client.json`, 0600); it lasts 10 minutes and works once.
After that, save the client once and use it directly:

```bash
curl -s http://<linux-ip>:8000/recon-client.py -o recon.py
python3 recon.py scan <target>              # quick preset, waits, prints findings
python3 recon.py scan <target> --preset standard
python3 recon.py status <run_id>
python3 recon.py runs
python3 recon.py findings <run_id>
python3 recon.py plugins
```

The phone needs `python3` in Termux (`pkg install python` once, if it
is not already there). On the phone itself, the full web UI is also
one tap away: open `http://<linux-ip>:3000` in the phone browser and
sign in with the code in the Linux box's `.local-access-code`.

### Full install on the phone (heavy option, not recommended)

The whole stack can run on the phone itself (see `termux-setup.sh` +
`termux-start.sh`), but it is heavy: a 10,000-file clone, a Python
venv, compiled wheels, and a several-minute Node frontend build, and it
needs internet in Termux for `pkg`/`pip`/`npm`. The thin client above
is the way to scan from the phone; use the full install only if you
want the phone to be its own server with no Linux box around.

Practical phone notes for the full install:

- Setup takes a while on a phone: the frontend build is the slow step
  (several minutes). It only runs during setup, not on each start.
- Run `termux-wake-lock` in a second Termux session and keep Termux out
  of battery optimization, or Android may freeze the app mid-scan.
- A full default scan runs 600+ detection plugins and can take many
  minutes on a phone CPU. It works, it is just slower than a server.

### What is reduced on Termux (full install)

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
and a full real scan). The thin Termux client is verified end to end
against a live Linux backend (pair exchange, scan, findings) in a
sandbox; the client logic is pure Python stdlib, so the only unproven
step on a real phone is running it under Termux's python. The full
Termux install is syntax-checked and mirrors the verified Linux steps,
but has not yet been run on a physical phone.

## MCP server (use ReconAnything from Claude)

`mcp_server.py` is a stdio [MCP](https://modelcontextprotocol.io) server that
wraps a running backend, exposing `list_plugins`, `start_scan`,
`get_scan_status`, `get_findings` and `list_scans`.

```bash
pip install mcp                      # v1 or v2 both work
claude mcp add recon-anything -- python /path/to/recon-anything/mcp_server.py
```

It talks to `RECON_API_URL` (default `http://127.0.0.1:8000`) and
authenticates with `RECON_ACCESS_CODE`, falling back to the
`.local-access-code` file in the repo folder. Start the backend first
(`bash local-run/run.sh`). Only scan targets you are authorized to test.
