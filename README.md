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

### Shipped plugins (12)

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

### API keys

Manage at `/keys` in the UI or `POST /api/keys`. Secrets are
Fernet-encrypted at rest when `RECON_MASTER_KEY` is set. Keys are never
shipped to the browser; plugins get decrypted values server-side.

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
   point `DATABASE_URL` at a Postgres for persistence.

### Railway (two services)

1. New project from the repo. Add the `backend` service
   (Dockerfile `backend/Dockerfile`, port 8000) and the `frontend`
   service (Dockerfile `frontend/Dockerfile`, port 3000).
2. On the frontend service set `RECON_API_URL` to the backend's
   internal URL (e.g. `http://backend:8000`).
3. Set `RECON_ACCESS_CODE` on both. Add a Postgres plugin and set
   `DATABASE_URL` on the backend for persistence.

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

https://recon-anything.onrender.com
