# ReconAnything: off SnapDeploy, to Railway (prepared, NOT deployed)

Status: preparation only. Nothing in this document deploys anything.
The live host is still SnapDeploy until the steps in "What Jay must
tap" are done, and the SnapDeploy container is left running as the
fallback until the new host is verified live. Do NOT delete it yet.

## Why move at all (before-state, observed 2026-10-27)

SnapDeploy free sleeps after 15 minutes idle and serves a JS wake
page (header `X-Wake-Page: true`) instead of the app. On 2026-10-27
around 15:20-15:21 EST the live SnapDeploy host showed, in the same
few minutes:

- `/` and `/api/health` 200 (health is frontend-native, so it does
  NOT prove the backend is up)
- `/api/me` and `/api/runs?limit=1` 500 Internal Server Error
- `/live/runs/test/stream` 503 with the SnapDeploy wake page

That flap is exactly what the run page's loop feeds on: the stream
dies, the poll fails, both retry, and the page says "live" while
nothing is live. The loop fix in this branch (session-cookie stream,
managed reconnect with backoff, stop on 401) makes the page stop
lying about it, but it cannot make a sleeping container stay awake.
Only a host that does not sleep can.

## Host evaluation (no-card rule applied throughout)

| Host | Can it run this app? | Sleep / always-on | Verdict |
| --- | --- | --- | --- |
| Cloudflare Pages | No. Static hosting only. It cannot run the Next.js standalone server, the FastAPI backend, the scan worker subprocesses (dig, curl, openssl, plugin jobs), or the Postgres/SQLite run queue. | Never sleeps, but there is no backend to keep awake. | Rejected. A Pages frontend would still need a backend host elsewhere, which is two hosts, not a move. |
| Cloudflare Workers | No. Workers are V8 isolates (JavaScript/TypeScript), with per-request CPU limits. They cannot run Python FastAPI, long-running plugin subprocesses, or a persistent scan worker, and SSE/long-lived streams do not fit the model. | No sleep, wrong runtime. | Rejected. |
| Cloudflare Containers | Yes, technically (real containers), but it requires the Workers Paid plan ($5/month minimum, plus usage). That is a paid, card-gated route. | Always-on only on a paid plan. | Blocked by the no-card rule. Do not use. |
| SnapDeploy Always-On | Yes (it already runs there). | $12/month per container, paid. Free tier sleeps after 15 min idle, 100 awake-hours/month shared. | Blocked by the no-card rule for the paid tier; free tier is the problem being escaped. |
| Render free | Yes, it ran there before. | Sleeps after 15 min idle anyway, AND the workspace's free hours are exhausted: services suspended since 2026-10-25. | Not a fix. Same sleep, plus a suspension. |
| Fly.io | Yes, technically. | Trial is 2 hours of runtime or 7 days, then a credit card is required. | Card-gated. Blocked. |
| Koyeb | Yes, technically. | Free tier requires a card ($29 hold on record). | Card-gated. Blocked. |
| Railway (chosen) | Yes. Dockerfile-based, same all-in-one container as SnapDeploy (Next.js + FastAPI + worker in one image). No sleep: Railway services run until they are stopped or their credit is spent; there is no idle sleep timer. | See the honest caveat below. | Chosen route, with the caveat stated, not hidden. |

### Railway caveat, stated plainly

Railway does not sleep, but it is not unlimited free. Public terms
and the account's own record disagree on the exact free allowance,
so check the dashboard at deploy time:

- Public pricing (Oct 2026 sources): Free plan $0/month with $1 of
  monthly usage credit, 1 vCPU, 0.5 GB RAM per service, 1 replica.
  A 0.5 GB always-on service at published rates ($10/GB-month RAM
  plus CPU) can cost more than $1/month, so the credit alone may
  not cover a full month of always-on running. When credit is
  spent, Railway pauses the service instead of waking it on demand.
- On record for this account: the uncensored-harness service is
  already live on Railway, sleep OFF, and answered 200 on
  2026-10-27. That proves the account and the Railway route work
  for a service of this shape today; it does not prove ReconAnything
  will fit inside $1/month forever.

Consequence: Railway fixes the sleep/wake loop (no wake page, no
15-minute death), but it does NOT promise free forever. If the
credit runs out, the fallback is still SnapDeploy (left running),
and the next decision is a paid tier, not another free host.
Budget for that possibility instead of discovering it mid-month.

The Oct 21/22 Railway incident (API tokens invalidated, Free/Trial
builds paused) is over in the sense that matters here: the existing
Railway service answers 200 today. A brand-new Railway service
still needs Jay's dashboard tap to confirm, because no agent
session can prove a new deploy without his sign-in.

## What to deploy (config, ready)

- Repo: jaykk99/recon-anything, branch: this PR's branch until it
  is merged, then master. Do NOT deploy this PR branch as
  production without merging it first; the loop fix must land on
  master first (parent re-runs the full suite before merging).
- Builder: Dockerfile, path `snapdeploy/Dockerfile` (the all-in-one
  image: frontend on `$PORT`, backend on 127.0.0.1:8000, worker
  alongside). See `railway.json` in the repo root.
- Port: Railway sets `$PORT`; the image already listens on it.
- Health check: `/api/health` proves the frontend process is up
  only. Backend proof is `/api/me` returning 200 JSON (not 500)
  plus a signed-in run page that stays connected.
- Restart policy: on failure, with a 10-second max retry window in
  `railway.json`. A crash loop must not look like a sleep loop.

## Environment variables (names only, no values in this repo)

Copy these from the SnapDeploy container's settings into the
Railway service. Never paste values into git, chat, or this file.

Required for sign-in + checkout + persistence:

- `DATABASE_URL` — the persistent Postgres already used by
  SnapDeploy, NOT the default SQLite. SQLite inside a Railway
  container is ephemeral and wipes runs on redeploy, exactly the
  "run not found" failure the loop fix documents.
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` — see the OAuth
  callback note below; a second OAuth app is the safe route.
- `RECON_BTC_ADDRESS` — BTC checkout receive address.
- `RECON_MASTER_KEY` — Fernet key for the API-key vault.
- `RECON_SESSION_SECRET` — session cookie signing secret.
- `RECON_CONCURRENCY`, `RECON_TIMEOUT` — scan tuning, as on
  SnapDeploy.

Hunter keys already on SnapDeploy (copy names, same values):

- `CENSYS_API_ID`, `CENSYS_API_SECRET`, `SECURITYTRAILS_API_KEY`,
  `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `HIBP_API_KEY`,
  `GITHUB_TOKEN`.

Optional / already defaulted in the image:

- `PORT` (set by Railway), `RECON_API_URL`
  (already `http://127.0.0.1:8000` in the image),
  `PYTHONUNBUFFERED=1`.

## GitHub OAuth callback (do this in the right order)

Current state: GitHub OAuth app 3959006 has its callback set to
the SnapDeploy URL (`.../api/auth/github/callback`). A GitHub
OAuth app has a single callback URL, so overwriting it for
Railway would break SnapDeploy sign-in while SnapDeploy is still
the fallback.

Safe order:

1. Create a SECOND GitHub OAuth app for the Railway URL, with
   callback `https://<railway-domain>/api/auth/github/callback`.
2. Put that app's client id/secret on the Railway service only.
3. Leave app 3959006 and the SnapDeploy container untouched.
4. Only after Railway is verified live (below) should anyone
   consider retiring the SnapDeploy callback, and only on Jay's tap.

The sign-in link on the new host must point at its own callback;
verify that by opening the new host's home page signed out and
following the "Sign in with GitHub" link to github.com with the
new client id in the URL, before any scan is run.

## What Jay must tap (in order, nothing here is done yet)

1. Merge this PR on GitHub, after the parent's full-suite re-run.
   (Agent PRs get individual review; this one is not merged by
   this branch's author.)
2. In the Railway dashboard, create a new service from GitHub:
   repo jaykk99/recon-anything, master branch, Dockerfile
   `snapdeploy/Dockerfile` (or let Railway pick up `railway.json`
   from the repo root).
3. In the Railway service settings, paste the environment
   variables listed above (names only here; values come from the
   SnapDeploy dashboard, copied by Jay).
4. Create the second GitHub OAuth app for the Railway domain and
   paste its id/secret into the Railway service.
5. Deploy, then tell the agent the Railway URL. The agent then
   verifies: root 200, `/api/health` 200, `/api/me` 200 JSON,
   sign-in link points to the new callback, and a signed-in run
   page stays connected without the 4s loop.

## Verification checklist (new host, after Jay's taps)

- [ ] Root loads and stays up for 20+ minutes with no wake page.
- [ ] `/api/health` 200.
- [ ] `/api/me` 200 JSON (not 500, not the wake page).
- [ ] Signed-out home page shows only "Sign in with GitHub".
- [ ] Signed-in run page: stream connects, progress moves, no
      "Connection lost" banner, no 4s reconnect loop.
- [ ] SnapDeploy container still running as fallback until every
      box above is checked; only then discuss deleting it.
