Live: https://recon-anything-9b68f.containers.snapdeploy.app

# ReconAnything

Universal OSINT and attack-surface recon. Give it almost any identifier
(domain, URL, IP, email, username, phone, hash, wallet, JWT, GitHub repo,
npm package, Play Store app...) and it discovers everything publicly
knowable about it: DNS, subdomains, WHOIS, web tech, JS-buried endpoints,
API maps, TLS posture, mobile app internals, leaks. No ownership of the
target needed, no source code needed.

Passive by default. Active mode does polite, rate-limited direct probing.

## Quick start

### Docker Compose (full stack: Postgres + Redis + API + UI)

```bash
cp .env.example .env
docker compose up --build
# UI: http://localhost:3000   API: http://localhost:8000
```

### Local dev (no Docker)

```bash
# backend
cd backend
python -m venv .venv && .venv/bin/pip install -r requirements.txt
RECON_ACCESS_CODE=letmein .venv/bin/uvicorn app.main:app --port 8000

# frontend (another terminal)
cd frontend
npm install && npm run dev
# UI: http://localhost:3000 (proxies /api to :8000)
```

Set `RECON_ACCESS_CODE` to gate the UI/API with a single access code.
Leave it empty for local dev only.

## How it works

```
                    +------------------+
                    |  Next.js UI      |  input bar, live SSE run view,
                    |  (App Router)    |  findings, graph, API map, diff
                    +--------+---------+
                             |  /api  (rewritten to backend)
                    +--------v---------+
                    |  FastAPI        |  classify, plugin registry,
                    |  runner         |  SSE event bus, graph, reports
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
        +-----v-----+               +-------v------+
        | Postgres  |               | Redis (opt)  |
        | (SQLite   |               | cache        |
        |  fallback)|               +--------------+
        +-----------+
```

### Attack-path correlation (cross-finding synthesis)

Individual plugins each see one slice of a target. The correlation
engine (`backend/app/correlate.py`) runs once at finalize — after every
plugin and hunter pass has settled — over the *whole* finding set, and
synthesizes **attack paths**: exploitable sequences that no single
plugin could see. A forgeable JWT is one finding; an admin endpoint is
another; together they are an *authentication bypass path*, and that is
what gets reported.

What it chains (detection/analysis only — never sends a payload):

- exposed cloud credential + reachable bucket/cloud host → live
  infrastructure access
- forgeable JWT + privileged/auth endpoint → auth-bypass path
- exposed source/.git/.env + a recovered secret → source leaks creds
- SSRF on a cloud-hosted target → instance-metadata credential theft
- dangling CNAME → subdomain takeover
- permissive CORS + authenticated API → cross-origin data theft
- internet-exposed management port (+ default creds) → direct access
- breached email + live login → credential-stuffing path
- IDOR/BOLA candidate + mapped API surface → object-level authz gap
- 3+ distinct secret classes → "secret sprawl"
- public OpenAPI/GraphQL introspection → self-documenting attack surface

Each path carries a plain-language narrative, the chained component
findings (credential values redacted), an attacker-impact line, the fix,
a severity and an exploitability rating. The engine also computes a
single **exposure score** (0–100, banded clean→critical) for the run.

Paths are persisted as ordinary findings (`plugin_id="correlation"`,
`key="attack_path"`), so they flow through the API, the JSON/CSV/MD/HTML
exports, and the UI's new **Attack Paths** tab + exposure banner. The
engine is pure-stdlib, deterministic, idempotent across hunter reopens,
and never raises on bad input. Add a rule by appending a pure function
to `RULES` in `correlate.py`; unit gate is `tests/test_correlate.py`.

### Plugin architecture

Every capability is an isolated plugin in `backend/app/plugins/`.
Drop in a new file implementing the `Plugin` interface and it is
hot-loaded on next start. No central list to edit.

```python
from .base import Plugin, Ctx, Target, PluginResult, Cost

class MyPlugin(Plugin):
    id = "myplugin"          # unique
    label = "My Plugin"
    accepts = ["domain"]     # target types, [] = all
    requires_keys = []       # e.g. ["shodan"]
    passive = True
    cost = Cost.FREE
    group = "network"        # network | web | api | mobile | identity
    description = "What it does."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        # ctx.http: shared httpx client (trust_env=False, UA set)
        # ctx.cache.cached("source", key, fn) for cached external calls
        # ctx.limiter via ratelimit.fetch() for rate-limited HTTP
        # self.module_mode(ctx) -> "passive" | "active" (per-module override)
        findings = [self._f("dns", "a", "1.2.3.4", source="example")]
        return self._ok(findings, "done")
```

Rules:
- Never throw fatally. Return `_ok`, `_skipped`, `_rate_limited`, or `_error`.
- One failing plugin must never kill a run (the runner also wraps each call).
- Every external call goes through `ctx.cache` (per-source TTLs) and
  `ratelimit.fetch` (global + per-host limits, 429 Retry-After, backoff).
- Tag each finding with the mode that produced it (`passive=True/False`).

### Shipped plugins (197 and counting)

The registry auto-discovers every `Plugin` subclass in
`backend/app/plugins/` - drop in a file, no central list to edit.
Below are the core ones; the health gate (`backend/tests/test_plugin_health.py`)
enforces unique ids, valid groups, and metadata on all 197.

| id | label | what it does |
|----|-------|--------------|
| dns | DNS Records | A/AAAA/CNAME/MX/TXT/NS/SOA/CAA/SRV/PTR, DNSSEC posture |
| subdomains | Subdomain Enum | crt.sh certificate transparency; active DNS brute force |
| rdap | WHOIS / RDAP | registrar, creation/expiry, registrant org |
| wayback | Wayback History | snapshots, first/last seen, interesting old URLs |
| tls | TLS + Email Security | cert chain/SAN/issuer/expiry, SPF/DMARC/BIMI/MTA-STS |
| webtech | Web Tech Fingerprint | framework/CMS/CDN/analytics signatures, robots/sitemap/security.txt, favicon hash |
| jsminer | JS Bundle Miner | endpoint/API-host/key mining in JS, source-map recovery |
| artifacts | Exposed Artifacts | sensitive-file check (Wayback in passive, direct probe in active) |
| apidiscover | API Discovery | backend inference, OpenAPI/Swagger, GraphQL introspection, endpoint probes, CORS check, JWT audit |
| mobile | Mobile App Analysis | Play Store metadata + APK strings/secret scan; App Store lookup |
| leaks | Leaks + Identity | HIBP breach check, GitHub code search, dork generator, username enum |
| pivots | Pivot Finder | favicon/Shodan pivot, tracking-ID pivots, sibling-site queries |

With zero API keys the app still works using only free sources
(crt.sh, RDAP, DNS, Wayback, direct HTTP, JS analysis). Paid sources
(Shodan, HIBP, GitHub code search) degrade to clear "skipped" notes.

### New plugins (2026-10-20 batch)

25 passive audit plugins, each with canned-response tests in
`backend/tests/test_new_plugins.py` and a dead-network resilience gate
(`test_plugin_resilience.py`) covering all 197 plugins:

| id | label | what it does |
|----|-------|--------------|
| cookie_security | Cookie Security Flags | Secure/HttpOnly/SameSite audit, __Host-/__Secure- prefix rules |
| csp_audit | CSP Policy Audit | grades an existing CSP: unsafe-inline/eval, wildcards, data:, missing object-src/base-uri |
| hsts | HSTS Analysis | max-age, includeSubDomains, preload readiness, bare-domain downgrade probe |
| http_methods | HTTP Methods Audit | OPTIONS-advertised verbs: TRACE/XST, PUT/DELETE, WebDAV, DEBUG (never exercised) |
| error_pages | Error Page Disclosure | stack traces, debug mode, SQL errors, path disclosure on 404/500 pages |
| exposed_debug | Exposed Debug Toolbars | Django/Symfony/Laravel/Rails toolbar markers in prod HTML |
| phpinfo | phpinfo() Exposure | conventional phpinfo paths, marker-confirmed |
| mixed_content | Mixed Content | http:// subresources on https pages (active vs passive) |
| http2_check | HTTP/2 / HTTP/3 Support | ALPN-negotiated protocol detection |
| graphql_probe | GraphQL Exposure | endpoint detection + introspection availability (read-only queries) |
| rate_limit_audit | Rate-Limit Headers | documents advertised limits vs undocumented throttling |
| web_manifest | PWA Manifest / SW Audit | scope, icons, start_url, service-worker scope header |
| sri_audit | Subresource Integrity | cross-origin scripts/styles missing integrity attributes |
| html_comments | HTML Comment Intel | TODOs, credential patterns, internal hosts, commented endpoints |
| trackers | Third-Party Trackers | inventory of adtech/analytics with script access |
| well_known_audit | Well-Known URIs | security.txt, change-password, assetlinks, app-site-association, gpc.json |
| redirect_chain | Redirect Chain | downgrades, off-domain hops, loops, long chains |
| dns_infra | DNS Infra Health | lame delegation, missing glue, SOA health, single-NS risk |
| ipv6_check | IPv6 Support | AAAA records + real IPv6 connectivity (broken dual-stack detection) |
| ip_reputation | IP Reputation (DNSBL) | Spamhaus/Barracuda/SpamCop/SORBS listings |
| smtp_tls | Mail Server TLS | STARTTLS advertisement vs working handshake, cleartext AUTH |
| cdn_detect | CDN Detection | edge provider from headers/CNAMEs (no origin hunting) |
| typosquat | Typosquat Domains | generated lookalikes that actually resolve |
| tls_config | TLS Config Audit | deprecated versions, weak ciphers, CRIME, forward secrecy |
| caa_audit | CAA Policy Audit | missing policy, issuewild gaps, issuance forbids |

Fast mode (`fastmode` plugin) now also runs inline cookie-flag, CSP,
HSTS and GraphQL triage checks reusing these plugins' graders.

### API notes

- `GET /api/runs` no longer embeds each run's full summary JSON (it made
  the list ~6s idle). Light columns only, plus `findings_count` from one
  indexed `GROUP BY`; pass `?summary=1` for the full blobs. `runs.created_at`
  is indexed.
- Job dispatch order is `(priority, phase, estimate_s)`: Jay's priority
  tiers are unchanged, but fast plugins stream first *within* each tier.
- Vuln advisor candidates carry `confidence_basis` ("direct evidence: ..."
  vs "heuristic: ...") and `needs_manual_verification` so the UI can
  label heuristic findings honestly.

### API keys

Manage at `/keys` in the UI or `POST /api/keys`. Secrets are
Fernet-encrypted at rest when `RECON_MASTER_KEY` is set. Keys are never
shipped to the browser; plugins get decrypted values server-side.

### Pricing, sign-in and BTC checkout

ReconAnything is a paid product with a free tier (`/pricing`):

| Plan | Price | Scans/day | Findings | Crypto Pack | Extras |
| --- | --- | --- | --- | --- | --- |
| Free | $0 | 3 | 1 revealed per day (UTC) | no | locked findings shown as counts |
| Starter | $19/mo | 10 | full | no | exports |
| Pro | $49/mo | unlimited | full | yes | API access |
| Agency | $149/mo | unlimited | full | yes | bulk targets, white-label export |

- Customers sign in with GitHub (OAuth; callback
  `https://recon-anything-9b68f.containers.snapdeploy.app/api/auth/github/callback`,
  also served at `/auth/github/callback` on the API service). Sessions
  are HMAC-signed cookies; users/orders/reveals live in `users`,
  `orders`, `finding_reveals` tables.
- The owner account (`OWNER_GITHUB_LOGIN`, default `jaykk99`) has full
  access and is never shown payment UI, upgrade prompts or checkout:
  `/api/me` reports `show_payment_ui: false` for the owner.
- Free tier: scans run in full (detection only, same scope rules), but
  exactly 1 finding per UTC day is revealed per account; the rest are
  masked server-side in run detail and export responses.
- Paid plans are BTC only. Creating an order pins the BTC amount at
  the live CoinGecko rate and shows the address from `RECON_BTC_ADDRESS`.
  The DIY payment watcher (`backend/app/paywatch.py`) watches that
  address on mempool.space (public, no key) and unlocks the picked tier
  automatically once a payment from the buyer's declared address reaches
  2 confirmations, within a 60-minute invoice window and a 1%
  tolerance. Owner approval at `/admin/orders` stays as the manual
  fallback for payments the watcher cannot match. With
  `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET` unset the
  sign-in button shows "opens soon"; with `RECON_BTC_ADDRESS` unset
  checkout shows "checkout opens soon". No address is ever invented.

### Authenticated Mode (Pro / Agency)

Authenticated scans run the same detection plugins behind a target's
login, using credentials the user supplies for a target they own or
have written permission to test. Authenticated: scans behind the
login of your own systems. For authorized testing only.

- **One-time attestation.** The warning is accepted once per account
  (`POST /api/auth/attestation`); the acceptance (identity, timestamp,
  text version) is stored in `auth_acceptances`. Authenticated runs
  are rejected server-side for accounts with no stored acceptance -
  the owner account accepts once too. After that, runs need no
  repeated warning: each one is stamped with its acceptance reference
  and carries an "Authenticated" badge (run detail, run list,
  findings, exports).
- **Credentials** (session cookie, bearer token, basic auth, or up to
  5 custom headers) are supplied per run, Fernet-encrypted into the
  run's `run_auth` row (`RECON_AUTH_SECRET`; set the same value on the
  API and worker services), decrypted only in the worker's memory,
  attached ONLY to requests to the run's seed target hosts, and wiped
  when the run finishes. They never appear in logs, findings, events,
  exports or API responses - the API shows only a presence label like
  "auth: cookie (set)". There is no login-form submission, credential
  testing or bypass: the user replays a session they already hold.
- **Plans.** Pro and Agency only (plus the owner). Free and Starter
  run creation with credentials is rejected server-side.

## Deploy

### SnapDeploy (single container, free tier)

The repo ships an all-in-one image at `snapdeploy/Dockerfile`:
Next.js frontend + FastAPI backend in one container, one public port.

1. In SnapDeploy, create a container from the GitHub repo,
   Dockerfile path `snapdeploy/Dockerfile`, port `3000`.
2. Set env vars: `RECON_ACCESS_CODE` (pick a strong one),
   `RECON_MASTER_KEY` (generate with
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
3. Deploy. SQLite is used by default (data resets on redeploy);
   point `DATABASE_URL` at a Postgres for persistence (see
   "Persistent storage on Render" below).

### Persistent storage on Render (free tier)

Render's free tier has no persistent disks (disks need a paid plan) and the
default SQLite file is wiped on every redeploy, which makes finished scans
vanish with "run not found". The fix is a free external Postgres; Neon is
recommended (free tier, no expiry). The backend already supports Postgres via
SQLAlchemy; only the env var is needed.

1. Create a free project at https://neon.tech and copy the connection string
   (it looks like `postgresql://user:pass@ep-xyz.us-east-2.aws.neon.tech/dbname?sslmode=require`).
2. In the Render dashboard: service -> Environment -> add env var
   `DATABASE_URL` = that connection string. Redeploy.
3. Check the service logs on boot: you should NOT see the
   "using ephemeral SQLite" warning anymore.

On boot the app now fails fast with a clear error if `DATABASE_URL` is set
but unreachable, instead of silently losing runs. If a run ID is requested
that no longer exists, the API returns 404 with an explanation pointing at
this fix instead of a bare "run not found".

### Railway (two services)

1. New project from the repo. Add the `backend` service
   (Dockerfile `backend/Dockerfile`, port 8000) and the `frontend`
   service (Dockerfile `frontend/Dockerfile`, port 3000).
2. On the frontend service set `RECON_API_URL` to the backend's
   internal URL (e.g. `http://backend:8000`).
3. Set `RECON_ACCESS_CODE` on both. Add a Postgres plugin and set
   `DATABASE_URL` on the backend for persistence.

### Environment variables

| Var | Default | What it does |
|-----|---------|--------------|
| `DATABASE_URL` | `sqlite:///./recon.db` | Database. Set to a Postgres URL (e.g. Neon free tier) for persistence; see above. `postgres://` URLs are auto-rewritten and the `psycopg2` driver is pinned (plain `postgresql://` would otherwise make SQLAlchemy 2.x look for the uninstalled `psycopg` v3 driver). |
| `RECON_ACCESS_CODE` | (empty = no gate) | Single access code gating the UI/API. |
| `RECON_MASTER_KEY` | (empty = plaintext) | Fernet key for encrypting stored API keys. |
| `RECON_AUTH_SECRET` | (empty = fallbacks) | Encrypts Authenticated Mode run credentials. Set the SAME value on the API and worker services. Falls back to `RECON_MASTER_KEY`, then to a key derived from `RECON_ACCESS_CODE`. |
| `REDIS_URL` | (empty = in-memory) | Optional Redis for the cache backend. |
| `RECON_TIMEOUT` | `20` | Default HTTP timeout (seconds) for plugins. |
| `RECON_CONCURRENCY` | `5` | Parallel plugins per run. |
| `RECON_RPS` | `25` | Per-host request pacing (requests/sec). |
| `RECON_EVIDENCE_DIR` | `./evidence` | On-disk evidence files (ephemeral on Render free tier). |

## Demo

```bash
cd backend
.venv/bin/python ../demo.py   # runs the mocked pipeline end-to-end
```

`demo.py` runs the full pipeline (classify, 9 plugins, findings, graph,
exports) against canned responses and prints a summary. For a live demo,
start the stack and scan `example.com` in passive mode from the UI.

## Legal and ethics

- Passive recon uses only third-party APIs and public datasets and sends
  no packets to the target. It generally needs no permission.
- Active mode sends direct DNS queries, HTTP requests, and probes.
  Be polite: it is rate-limited, respects robots.txt, identifies itself
  as `ReconAnything/1.0`, and never authenticates or mutates state.
- Terms of service, robots.txt, and local law still apply. Only scan
  targets you are authorized to assess: your own assets, CTFs, and bug
  bounty programs in scope.
- Findings can include leaked secrets. They are masked in exports by
  default; handle them responsibly.

## Conventions

TypeScript strict. Python typed. Prefer free data sources; mark paid
ones optional. Every external call goes through the cache layer.
No em dashes in user-facing text.

## Live URL

https://recon-anything-9b68f.containers.snapdeploy.app
