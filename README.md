Live: https://recon-anything.onrender.com

# ReconAnything

A reconnaissance platform for web targets and smart contracts.
Detection only: it finds and reports weaknesses, it never exploits
them, never authenticates against a target it was not given credentials
for, and never signs or sends a transaction.

Give it almost any identifier (domain, URL, IP, email, username, phone,
hash, wallet, contract address, JWT, GitHub repo, npm package, Play
Store app...) and it discovers what is publicly knowable about it: DNS,
subdomains, WHOIS, web tech, JS-buried endpoints, API maps, TLS
posture, mobile app internals, leaks. For a smart contract it pulls the
verified source (or bytecode when source is unverified) from public
chain data and runs the contract-analysis stack described below:
static analysis, auditor tooling, read-only simulation, and a local
fuzz lane that can confirm whether a flagged weakness is actually
reachable by an unauthenticated stranger.

Passive by default. Active mode does polite, rate-limited direct
probing.

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
                             |  /api + /mcp  (rewritten to backend)
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

## Smart contract analysis

Contract targets are first-class, not an afterthought. Coverage:

- **EVM, 6 chains:** Ethereum (1), BNB Chain (56), Polygon (137),
  Arbitrum One (42161), Base (8453), Optimism (10). Chains are config
  in `backend/app/plugins/contract_chain.py`; adding one is one entry.
  Verified source comes from Blockscout / Sourcify, keyless.
- **Proxies are followed one level:** EIP-1967 implementation and
  beacon slots and the EIP-1167 minimal-proxy bytecode pattern are
  resolved read-only, and findings are tagged `proxy_shell` vs
  implementation so a shell is never confused with the code behind it.
- **Solana:** the `solana_contract` plugin analyzes programs and token
  mints (authorities, supply, pool state), keyless via public RPC and
  RugCheck.
- **Stacks / Clarity:** `stacks_contract` reads contracts from the
  keyless Hiro API: mint authority (hardcoded principal vs data-var
  owner vs unguarded), whether the mint cap is enforced in the mint
  path or merely decorative, burn / pause / freeze / blacklist
  powers, owner rotation, `tx-sender` auth patterns, and live SIP-010
  supply against the cap.

The analysis plugins (all under `backend/app/plugins/`):

| id | what it does |
|----|--------------|
| contract_recon | Pulls a contract's code from public chain data on the 6 EVM chains and reports privileged functions, proxy pattern, dangerous code and secrets, with bytecode analysis when source is unverified. Read-only. |
| crypto_drain_scanner | Static repo/source analysis for unprotected drain functions: public functions with no access gate that can move the contract's own ETH or tokens to the caller or a caller-supplied address. Gated, internal, view/pure, own-balance and `msg.value` pass-through cases are not flagged. |
| contract_logic | Logic flaws rather than surface patterns: reentrancy, integer overflow/underflow, access-control flaws (ungated sensitive functions, `tx.origin` auth, unprotected `initialize()`, arbitrary delegatecall). Falls back to a clearly labeled low-confidence bytecode opcode heuristic when no verified source exists. |
| audit_toolbox | Runs the standard external auditor tools over the verified source and bytecode and normalizes their output: Slither, Aderyn, Semgrep (Solidity rules), solc SMTChecker, Heimdall, Echidna and Medusa (prepared harnesses), plus the GoPlus and Honeypot.is token-risk APIs. Heavy lane only; tools are optional external installs and absent binaries skip silently. |
| contract_simulation | Read-only on-chain simulation of one flagged contract: boundary-input `eth_call` probes of its public state-changing functions from an unfunded caller, cross-checked against the gate its source implies, plus optional Mythril symbolic execution behind `RECON_SIM_SYMBOLIC=1`. Heavy lane only, refuses bulk sweeps. Its flags are candidates, never verdicts. |
| contract_fuzz | Local exploit-confirmation fuzzing. The flagged contract is compiled with a local solc and deployed inside an Echidna harness where a house actor seeds it with mock ETH and an unauthenticated stranger fuzz-calls every public state-changing function under per-call balance accounting. A finding is reported as `fuzz_confirmed` only when the stranger actually ends up with profit beyond what it put in. Everything else is a low-severity inconclusive note with a machine-readable reason. Heavy lane only. |
| zeroday_differential / zeroday_error_miner / zeroday_contract_guards | Zero-day candidate hunters: type/shape mutation of a target's parameters, mining error responses for internal disclosures, and flagging the one public state-changing function that breaks a contract's own access-control convention. Every output is labeled `candidate_zero_day`, severity is capped at high, and all of it is pending human review. Passive mode sends zero mutations. |
| aml_* (8 plugins) | AML typology checks over discovered addresses: mixer/tumbler exposure, XMR conversion services, chain-hopping, non-KYC exchanges, P2P cash trades and related patterns. |

### How findings are judged

- **A finding is a candidate until verified.** Static detectors flag
  shapes; shapes are not proof. Confidence and, where a check is
  heuristic, `needs_manual_verification` say so on the finding itself.
- **Recipient analysis is mandatory.** An ungated function is not a
  stranger drain just because anyone can call it. Who receives the
  value decides: the caller, a caller-supplied address, a fixed
  hardcoded address, or the holder's own position. Only the first two
  are reported as stranger-reachable; fixed-recipient and holder-self
  cases are recorded as trigger-only, not as drains.
- **`fuzz_confirmed` is the strongest class.** It means a local fuzz
  run produced an actual call sequence in which an unauthenticated
  stranger profited at the contract's expense, and it ships with that
  shrunk counterexample as evidence.
- **Detection only.** No exploit confirmation against live contracts,
  no brute-forcing, no auth bypass, no transactions. Probes are
  read-only `eth_call` simulations; fuzzing happens on local deploys
  against mock balances.

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

Each path also carries a **complexity** rating and, when enough stages
line up, a compound **kill chain** (recon → foothold → access →
escalation) that orders isolated weak spots into the sequence an
attacker would actually walk.

### Verification commands on every finding

Every actionable finding (and every attack path) carries the exact
**read-only command(s) to reproduce/confirm it** — `curl` the exposed
`.git/config`, `dig` the dangling CNAME, `openssl s_client` the TLS,
base64-decode the JWT, `aws sts get-caller-identity` to see whose key it
is. Generated in `backend/app/commands.py` (pure stdlib, read-time so old
runs get them too) and shown with copy buttons in the UI and the exports.
These are *verification* commands — they confirm a finding exists or
identify its scope; they never exfiltrate data, modify the target, or
weaponize the finding. Gate: `tests/test_commands.py`.

### Full secret / credential reveal

An exposed secret **is** the finding, so the Secrets and Credentials
tabs show full values (with copy / copy-all and a per-value hide) rather
than masking them — you can't rotate a leaked key you can't see. The UI
requests `?show_secrets=true` and a **🔓 secrets revealed / 🔒 masked**
toggle flips it live; the server still enforces its own per-plan reveal
limits, so full values appear wherever the account is entitled to them.

### Vulnerability hunting: version → weaponized CVE

The CVE matcher fingerprints software versions from Server / X-Powered-By
headers, HTML, meta generators and JS filenames and matches them against
a curated database of **real, public, version-bounded CVEs** (142
entries, ~93 with public exploits). Coverage spans web servers,
languages and CMS/plugins plus the high-value, exploited-in-the-wild edge
and enterprise targets bug-bounty hunters prize: F5 BIG-IP, Exchange
(ProxyLogon/ProxyShell), vCenter, MOVEit, Zimbra, PaperCut, ColdFusion,
WebLogic, ActiveMQ, OFBiz, GeoServer, Ivanti, Citrix Bleed, Cisco ASA,
SonicWall, Webmin, Roundcube, Kibana/Elasticsearch and more. Each match
carries a severity and an **exploitability** rating (weaponized /
public_poc / theoretical) so a working RCE sorts above theoretical noise.
Detection only — it reads the version and references the CVE; it never
runs an exploit. Add an entry to `VERSION_CVES` in
`plugins/cves.py`; gate is `tests/test_cves_db.py`.

A **weaponized CVE is now also an attack path.** The correlation engine
raises any finding rated `weaponized` into a critical attack path on its
own ("Weaponized exploit available: …"), and when the same run shows a
reachable privileged/management endpoint the narrative links them. That
pushes the single most valuable thing a scan can find — a public exploit
against a live service — to the top of the Attack Paths tab and the
exposure score.

### Multi-chain crypto OSINT

The checksum-verified address detectors find wallets across ~15 chains,
and every detection now feeds the enrichment bus with a chain tag — so a
discovered address gets looked up, not just listed. `chain_osint` keeps
the deep Ethereum view (balance, tx history, counterparties, verified
source); `chain_enrich` adds keyless balance/activity for **Bitcoin,
Litecoin, Dogecoin, Bitcoin Cash, Dash, Zcash, Tron, XRP and Solana**
(Blockchair / TronScan / XRPScan / Solana RPC, no keys). `cryptolabels`
tags **every** address against a public label set — burn/null, known
mixers, bridges, major-exchange hot wallets, and OFAC-sanctioned
addresses — so "an address" becomes "an address linked to X". All
read-only public-explorer data; it never signs or sends. Pure parsers
live in `app/chaindata.py` / `app/cryptolabels.py`; gate is
`tests/test_chain_enrich.py`.

### Deeper bank / ATM surface

The financial packs recognize far more platforms now. `bank_surface`
fingerprints 27 ATM-fleet and payment-switch platforms (NCR APTRA/Vision,
Diebold Vynamic/Agilis, Nautilus Hyosung MoniView, Auriga WWS, ACI
Postilion/BASE24, Compass Plus TranzWare, OpenWay WAY4, BPC SmartVista,
FIS, Fiserv, Euronet…) across an expanded set of locator and console
paths, and the `atm` plugin covers more vendors (Nautilus Hyosung,
Fujitsu, OKI, Genmega, Hantle, Euronet, Cardtronics, Auriga, KAL) and
more subdomains / portal / management paths. Detection-only: it
fingerprints what a public page runs and references public CVEs — it
never logs in or interacts with a console.

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

### Shipped plugins (655)

The registry auto-discovers every `Plugin` subclass in
`backend/app/plugins/` - drop in a file, no central list to edit.
The count is the live registry size, measured by loading the registry
(`discover()` in `backend/app/plugins/registry.py`): **655 plugins**
across 259 plugin modules on current master. The health gate
(`backend/tests/test_plugin_health.py`) enforces unique ids, valid
groups, and metadata on all of them. Below are the core web plugins;
the contract-analysis plugins are listed in the Smart contract
analysis section above.

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
(`test_plugin_resilience.py`) covering the full plugin registry:

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
  `https://recon-anything.onrender.com/api/auth/github/callback`,
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

### Render (the live deployment)

The live instance at https://recon-anything.onrender.com runs on
Render as three services from this repo: the Next.js frontend (which
rewrites `/api/*` and `/mcp` to the backend), the FastAPI backend, and
a standalone scan worker (`backend/app/worker_main.py`). Set
`RECON_ACCESS_CODE` (pick a strong one) and `RECON_MASTER_KEY`
(generate with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`)
on the backend and worker. SQLite is used by default (data resets on
redeploy); point `DATABASE_URL` at a Postgres for persistence (see
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
| `RECON_SERVICE_KEY` | (generated) | Auth key for the MCP server (`/mcp`). When unset, a key is generated once and saved 0600 to the key file below; set the same value on the API and any standalone MCP service. |
| `RECON_SERVICE_KEY_FILE` | `~/workspace/recon-mcp-service-key.txt` | Where the generated MCP service key is stored when `RECON_SERVICE_KEY` is unset. |
| `MCP_PORT` | `8765` | Port for the standalone MCP server (`python -m app.mcp_server`); `$PORT` is honored when `MCP_PORT` is unset. |

## MCP server

ReconAnything is also an MCP server (Model Context Protocol, streamable
HTTP transport), so MCP clients (Claude, Error Inbox's black team, any
MCP host) can start scans and read results directly. It is mounted on
the API at `/mcp`, and the moment the backend is deployed the MCP
endpoint is live at `<backend-url>/mcp`. It can also run as its own
service:

```bash
cd backend
python -m app.mcp_server   # standalone MCP-only service
```

Tools (they wrap the same engine as the REST API; detection-only,
exactly like the web app):

| Tool | What it does |
|------|--------------|
| `recon_health` | Service + database health, plugin count |
| `recon_start_scan` | Start a scan (`targets`, `preset` quick/standard/deep, optional `mode`/`plugins`/`source_type`/`bounty`); honors the SANDBOX/LIVE gate |
| `recon_list_runs` | Recent runs with status + findings counts |
| `recon_run_status` | One run's status, live progress, targets, summary |
| `recon_get_findings` | A run's findings (secrets masked) with confidences; optional `min_confidence` filter |
| `recon_get_graph` | A run's attack-surface correlation graph (nodes/edges) |
| `recon_list_plugins` | The full plugin registry |

Auth: every MCP request needs the service key, as the
`X-Recon-Service-Key` header (or `Authorization: Bearer <key>`). No key
or a wrong key gets HTTP 401. See the `RECON_SERVICE_KEY` env vars
above.

Client config (Claude / any MCP host):

```json
{
  "mcpServers": {
    "recon-anything": {
      "url": "<backend-url>/mcp",
      "headers": {
        "X-Recon-Service-Key": "<RECON_SERVICE_KEY>"
      }
    }
  }
}
```

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
