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

## MCP (use ReconAnything from any AI)

The full backend is an MCP server: 32 tools covering scans, run
detail and findings, the vuln advisor and safe tester, settings and
schedules, breach watch, and the agent/hunter data layer. No API key,
no account, no setup file to hunt down. It runs locally over stdio,
keyless, like every other local MCP server.

Claude Code, one line:

```bash
claude mcp add recon-anything -- uvx --from git+https://github.com/jaykk99/recon-anything#subdirectory=backend recon-mcp --stdio
```

Claude Desktop (`claude_desktop_config.json`), Cursor
(`.cursor/mcp.json`), and VS Code (`.vscode/mcp.json`) all take the
same server entry; VS Code wraps it in a top-level `"servers"` object
instead of `"mcpServers"`:

```json
{
  "mcpServers": {
    "recon-anything": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/jaykk99/recon-anything#subdirectory=backend", "recon-mcp", "--stdio"]
    }
  }
}
```

No `uvx`? `pip install ./backend` (from a clone) gives the same
`recon-mcp` command, and `python -m app.mcp_server --stdio` works
from the `backend/` directory with no install at all.

Remote/hosted use: the hosted app serves the same tools over
streamable HTTP at `https://recon-anything.onrender.com/mcp`. Hosted
is the one place a key applies: send the service key as the
`X-Recon-Service-Key` header (the key is the `RECON_SERVICE_KEY`
env var on the server). A standalone HTTP server
(`recon-mcp --http --port 8765`) binds localhost and stays keyless
unless `RECON_SERVICE_KEY` is set; binding a non-localhost host
requires the key, or `RECON_MCP_NO_AUTH=1` to opt out explicitly.

Two deliberate limits: authenticated-mode scans (stored credentials)
are not offered over MCP, and the `/api/keys` credential vault has
no MCP tools. The SANDBOX/LIVE mode gate still applies to scan
starts, and `recon_test_vulns` defaults to `dry_run=true` (zero
requests sent).

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

## Batch scanning (high-throughput corpus mode)

The per-target runner is async and network-bound: it fetches each
contract's verified source from a public explorer, politely rate-limited,
one target at a time. That is right for scanning an address someone hands
you, but it cannot sweep a large corpus at speed.

`app/batch_scan.py` is the other lane - it runs the detection stack over
sources that are **already on disk** (a directory of `.sol` files, or a
JSONL corpus of `{address, chain, source}`), with **no network**, across
a multiprocessing pool, every regex compiled once per worker:

```bash
# fast lane: compiled RULES + the structured analyzer
python -m app.batch_scan --input ./corpus --workers 16 --out findings.jsonl

# faithful lane: the real contract plugins, run fully offline
python -m app.batch_scan --input corpus.jsonl --engine plugins --workers 32

# tiered: fast rules sweep across all, full plugins only on what flags
python -m app.batch_scan --input corpus.jsonl --engine tiered \
    --escalate-severity high,critical --workers 48
```

The `tiered` engine is the affordable path to full depth on a huge corpus.
It runs the fast `rules` engine across every contract, then escalates only
the ones whose findings reach the **confirmed confidence tier** (the
selective signal - reserved for unambiguous drains: ungated selfdestruct,
tx.origin auth, ungated full-balance withdraw) to the heavy full-plugin
engine. The heavy source text crosses to tier 2 only for that flagged
subset, not all 1M.

Measured on a real 1k Tier-1 sample: the rules sweep runs at ~18
contracts/sec/core and the confirmed-tier flag rate is **~1.7%**. So full
depth on 1M = ~48 cores for the 20-minute sweep, plus a deep pass on only
~17k contracts instead of ~580k (escalating on raw `high` severity flagged
~58% - most of it gated-owner noise). `--escalate-tier` picks the tier
(default `confirmed`); set it empty to fall back to `--escalate-severity`
with `--escalate-min-count`. The summary reports each tier's throughput and
the flag rate.

A JSONL corpus record may carry pre-fetched chain data, not just source:

```json
{"address": "0x...", "chain": "ethereum", "source": "contract ...",
 "bytecode": "0x6080...", "storage": {"0x0": "0x...", "0x1": "0x..."}}
```

When `bytecode`/`storage` are present, the `plugins` engine seeds them into
the same caches the deep plugins read (`_code_cache`/`_storage_cache`), so
`rpc_get_code` / `rpc_get_storage_at` serve from the corpus and **nothing
touches the network**. This is what lets the deep analysis run at corpus
speed (scales with cores) instead of live-RPC speed - feed it the bytecode
and source your fast Tier-1 fetch already pulled, and the deep pass scales
the same way Tier-1 does. The live per-target runner stays the on-demand
path; it is fast but network-bound and not the million-contract lane.

It prints the achieved `contracts_per_sec` and the projected minutes for
1,000,000 contracts, so you can size the box. Measured single-core cost
on ~9 KB of Solidity: the structured analyzer ~2.4 ms (~410/sec/core);
the `rules` engine ~357/sec/core end-to-end. So **1M in 20 minutes**
(833/sec) is reached by the `rules` engine on ~3 cores, and a 16-core box
clears it in about 3 minutes. The `plugins` engine runs the full plugin
detection logic and is correspondingly heavier - benchmark it on your
hardware with `--limit` to read the per-core rate, then scale cores to
hit your target.

Two honest constraints: **the network wall is upstream** - no public
explorer API will serve 833 sources/second, so fetching 1M contracts is a
separate, slower step (a Sourcify repo export, a BigQuery dump of verified
sources, or your own crawl); this lane assumes the source is already
fetched. And the `plugins` engine scans source with the network killed, so
checks that need a live chain read (storage state, simulation) degrade to
skipped - exactly the resilience contract the plugins already guarantee.
Both lanes are detection only: pure functions of the source text, nothing
touches a chain.

## Smart contract analysis

Contract targets are first-class, not an afterthought. Coverage:

- **EVM, 6 chains:** Ethereum (1), BNB Chain (56), Polygon (137),
  Arbitrum One (42161), Base (8453), Optimism (10). Chains are config
  in `backend/app/plugins/contract_chain.py`; adding one is one entry.
  Verified source comes keyless from Blockscout, then the Sourcify v2
  API, then the legacy Sourcify repository route (Etherscan only when
  a key is already configured, never a requirement). Public RPC access
  fails over per chain: BNB Chain alone carries 8 endpoints, so one
  dead RPC never silently degrades a scan.
- **Proxies are followed one level:** EIP-1967 implementation and
  beacon slots and the EIP-1167 minimal-proxy bytecode pattern are
  resolved read-only, and findings are tagged `proxy_shell` vs
  implementation so a shell is never confused with the code behind it.
- **EIP-7702 delegations are resolved live:** when an account's code
  is a 7702 delegation designator (`0xef0100` + delegate address), the
  delegate is read from live chain state before findings are judged,
  so a delegated account is never scored as if the designator were
  its real code (`eip7702_unverified_delegate`).
- **One fetch per contract:** every contract plugin reads through a
  shared chain-data layer (`chain_data`), so code, verified source,
  balances and proxy resolution are fetched once per contract per run
  and shared, instead of each plugin re-paying the same RPC and
  source routes.
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
| deep_layers (4 plugins) | The depth pass that runs after surface detection: `cross_contract_call_graph` traces calls across contract boundaries, `storage_state_analysis` reads the live storage state (initialized flags, counters, balances) that decides whether a flagged pattern is actually open, `bytecode_deep_analysis` works unverified bytecode at opcode depth, and `candidate_confirmation_queue` ranks the surviving candidates for confirmation. |
| recipient_first (6 plugins) + auto_validator | Recipient-first detectors establish who would receive the value (caller, caller-supplied address, fixed address, holder's own position) before severity is assigned. The `auto_validator` lane then adjudicates every candidate to exactly one verdict (see "How findings are judged"), replacing hand re-reads of source one contract at a time. |
| deep_audit / deep_audit2 / deep_audit3 (16 plugins) | Deep-audit detector batches for narrow, high-value shapes: vault share inflation, unguarded AA validation and diamond cuts, `ecrecover` zero-signer, read-only reentrancy, bridge replay on unbound digests, CREATE2 metamorphic redeploys, EIP-7702 delegates, fee-on-transfer over-credit, hook CEI reentrancy, missing L2 sequencer checks, Uniswap v4 hook delta accounting, transient-storage latches, inverted-division collapse, share/transfer desync, and EIP-712 digests not bound to their payload. New batches are added as the hunting research lands them. |
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
- **Every candidate gets a machine verdict.** The auto-validator
  adjudicates each candidate to exactly one of `VERIFIED_REAL`,
  `TRIGGER_ONLY`, `FALSE_POSITIVE` or `UNVERIFIED`, naming the
  evidence that decided it (a gate found on the deep source read, a
  live probe that reverted, a zero contract balance) and, for
  `UNVERIFIED`, exactly which piece of evidence is missing. Candidates
  from degraded evidence are never silently cleared.
- **Live verdicts need live proof.** On a live target, `VERIFIED_REAL`
  requires a read-only `eth_call` probe from an unfunded stranger
  address against the contract in its current on-chain state, with
  the recipient checked as caller or caller-supplied and the
  contract's live balance read as evidence. The probes are built by
  an encoder that handles complex argument types and canonicalizes
  function signatures, so a probe fires on the function the source
  actually declares. Local simulation and fuzz
  results can show a weakness is reachable in the lab; they never
  promote a live verdict on their own.
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

### Neural scoring engine (`backend/app/nn_engine.py`)

Every finding is scored once, at finalize, by a small neural network: a
2-layer MLP (80 features -> 16 tanh -> actionability) that gives findings
from across the whole registry one comparable 0-100 scale, and gives the
run a single number the network produced. Inference is pure stdlib - the
weights are a JSON file next to the module, no numpy/torch/sklearn at
runtime, ~1.3k multiply-adds per finding, deterministic in any process
(key tokens are sha1-bucketed, never Python's salted `hash()`).

Features are the evidence every plugin already emits: severity,
exploitability tier, confidence, bounty tier, the 27 semantic signals
`correlate` derives (credential / ssrf / takeover / weaponized_cve ...),
category, verification-command and manual-verification flags, and 24
hashed key-token buckets - so a plugin added tomorrow is scored on its own
vocabulary with no model change and no retraining.

Each finding carries the score in `evidence.nn`:

```json
{"score": 78, "p": 0.78, "band": "high", "version": "2026-11-14",
 "drivers": [{"feature": "sev_critical", "contribution": 4.21},
              {"feature": "expl_weaponized", "contribution": 2.05}]}
```

`drivers` names the inputs that moved the score, so a number is always
traceable to evidence instead of trusted as a black box - the same
"candidate, not verdict" contract the detectors follow.

The run exposure block is now network-driven: `exposure.score`,
`.band` and `.headline` come from the model (the strongest finding sets
most of it; summed probability mass adds the rest with diminishing
returns, so a noisy run of low-confidence notes cannot peg at 100), with
the previous heuristic kept under `exposure.heuristic` and the full model
block - top findings, actionable count, mean probability - under
`exposure.nn`. Missing or corrupt weights disable the engine cleanly and
finalize falls back to the heuristic score.

Training (`backend/app/nn_train.py`, numpy, dev-only) ships weights that
distill the project's own adjudication policy - `prioritizer.impact_of` x
exploitability x confidence, plus semantic-signal breadth and available
verification commands - over the real registry vocabulary parsed textually
from `app/plugins/` (881 declared plugin ids, 1,802 records, split by
plugin so the holdout never saw the id). Measured on that held-out split:
**Spearman 0.9145, MAE 0.0281, AUC 0.9948**. That is the honest claim: one
network reproduces the hand-tuned ranking it was distilled from across all
plugins; it does not yet outperform that policy, and it inherits its blind
spots. When adjudicated finding-level labels accumulate, retrain against
them instead:

```bash
python -m app.nn_train --corpus labels.jsonl   # {"finding": {...}, "label": 0..1}
python -m app.nn_train                          # policy distillation (shipped weights)
python -m app.nn_train --self-report            # model + measured metrics
python -m app.nn_engine findings.jsonl          # score any JSONL, ranked
```


The score is what orders every surface: `findings_dump` backfills it
for older runs and sorts by it, so the run-detail API, the JSON/CSV/MD/HTML
exports, the MCP tools and the UI list (its default sort) all serve the
same ranking - KEV and crypto-key findings still lead, and unscored
legacy rows fall back to the old heuristic order behind them.

Gate: `tests/test_nn_engine.py`.

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

### Engine infrastructure

- **Shared chain-data layer** (`backend/app/plugins/chain_data.py`):
  one fetch sequence per contract per run serves every plugin (code,
  verified source, balances, proxy implementation), with batched RPC
  reads (`eth_getCode` + `eth_getBalance` in a single POST) and
  memoized proxy resolution.
- **Knowledge store** (`backend/app/knowledge_store.py`): assets from
  every finalized run accumulate in a cross-run store, so later runs
  and queries build on what earlier runs already found. Exposed to
  MCP clients as `recon_query_knowledge`.
- **Checkpoints and resume** (`backend/app/checkpoints.py`): long
  runs checkpoint their progress by content hash, so an interrupted
  run resumes from the last checkpoint instead of starting over.
- **Delta engine** (`backend/app/delta.py`): a per-target diff
  between the previous and latest completed runs, with each asset
  labeled `+ NEW_*`, `- REMOVED_*` or `~ CHANGED_*` by kind. Exposed
  to MCP clients as `recon_get_delta`.
- **Adaptive rate limiting and event bus** (`backend/app/ratelimit.py`,
  `backend/app/eventbus.py`): per-host pacing with backoff protects
  targets and upstream APIs; run events stream over the bus to the
  live SSE view and the store/delta writers.

**Measured effect (benchmark, 2026-11-04):** with the same 20-plugin
harness on the same fixed set of 32 BSC contracts (30 market contracts
plus the WBNB and BlackMambaCoin controls), the shared chain-data
layer cut wall time from 1,786.5s to 148.5s (64.5 to 775.9
contracts/hour, about 12x) and per-contract HTTP calls from ~210 to
~24, with findings identical on every contract (625 of 625, same
per-plugin verdicts). Benchmark numbers are from the change's own
before/after runs; the merged code and its test suites were
re-verified on master.

### Shipped plugins (1226)

The registry auto-discovers every `Plugin` subclass in
`backend/app/plugins/` - drop in a file, no central list to edit.
The count is the live registry size, measured by loading the registry
(`discover()` in `backend/app/plugins/registry.py`): **1226 plugins**
on current master. Roughly 900 are statically defined (one class per
capability) and the rest are generated at import by detector batches
that expand a spec list into one plugin each (e.g. `deep_audit*`,
`privfind`, `recipient_first`) - so a file or class count understates
the real total; only loading the registry sees it.

The live count is authoritative and exposed at `GET /api/plugins`
(and summarised on `GET /api/health`). CI guards it: the health gate
(`backend/tests/test_plugin_health.py`) enforces unique ids, valid
groups, metadata, and a **count floor of 1200** (`MIN_PLUGINS` in
`registry.py`), so a silently deleted category or a broken import
fails the build instead of shipping with less. `python -m
app.plugins.registry` prints the same self-report locally.

Below are the core web plugins; the contract-analysis plugins are
listed in the Smart contract analysis section above. The enumerated
[All plugins](#all-plugins) table lists the statically-defined set;
the dynamically-generated detectors are described in their batch rows
(`deep_audit*`, `recipient_first`, `aml_*`) above.

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

## All plugins

Every plugin registered in the live registry, generated from
`discover()` in `backend/app/plugins/registry.py` on current
master. Grouped by the plugin's `group` value (the same grouping
the UI uses), alphabetical by plugin id within each group.
No sampling: if it is registered, it is listed here.

Group counts (live registry): Network 65 · Web 262 · API 28 · Mobile 34 · Identity 29 · Infra 138 · Web3 607 · Financial 43 · Graph 20 · **Total 1226**.

### Network (33)

| id | label | module | description |
|----|-------|--------|-------------|
| asn_scan | ASN + Infra Map | asn_scan | ASN/prefix lookup and web-port check on the target's own IPs. |
| banners | Banner Grabber | banners | Grab service banners, flag outdated software. |
| bitcoin | Bitcoin Node Exposure | bitcoin | Bitcoin service exposure: P2P (8333), RPC (8332), Electrum (50001/50002), and unauthenticated block explorer APIs. Connect-only, never authenticates. |
| caa_audit | CAA Policy Audit | caa_audit | Grade the CAA issuance policy: missing policy, issuewild gaps, issuance forbids. |
| censys_enum | Censys Exposure Search | censys_enum | Exposed hosts, services, and certificate anomalies: keyless crt.sh cert search always runs; Censys API keys (optional) add host exposure data. |
| cmd_dns | Command DNS (dig/host) | cmdtools | dig/host/nslookup record enumeration: A, AAAA, MX, NS, TXT, SOA, CAA + PTR. |
| cmd_dns_nscheck | Command DNS Nameserver Health (dig) | cmdtools | dig @NS SOA per nameserver: lame delegation (NS answers nothing authoritative) + SOA serial disagreement. |
| cmd_dns_recurse | Command DNS Open Resolver (dig) | cmdtools | dig @NS test: does the domain's own nameserver answer recursive queries for unrelated names (open resolver)? |
| cmd_ocsp | Command OCSP Stapling (openssl) | cmdtools | openssl s_client -status: stapled OCSP response present or missing (revocation checking). |
| cmd_ports | Command Service Ports | cmdtools | TCP connect to common service ports + banner grabs (nc, socket fallback). Detection only. |
| cmd_smtp | Command SMTP Check | cmdtools | MX-driven SMTP banner + STARTTLS capability. QUIT immediately, never sends mail. |
| cmd_tls | Command TLS (openssl) | cmdtools | openssl s_client cert inspection: subject, issuer, SANs, protocol, cipher, expiry. |
| db | Exposed Databases | db | Check if database ports are internet-reachable (no auth attempted). |
| dns | DNS Records | dns | A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, SRV, PTR + DNSSEC posture. |
| dns_infra | DNS Infra Health | dns_infra | Delegation quality: lame NS, missing glue, SOA health, single-point-of-failure nameservers. |
| fastmode | Fast Mode Triage | fastmode | Rapid triage: top 20 highest-value checks in under 30 seconds. |
| ip_reputation | IP Reputation (DNSBL) | ip_reputation | Check the target's IPs against Spamhaus, Barracuda, SpamCop and SORBS blocklists. |
| ipv6_check | IPv6 Support | ipv6_check | AAAA records + real IPv6 connectivity: ready, broken dual-stack, or IPv4-only. |
| passive_dns | Passive DNS History | passive_dns | Historical DNS from AlienVault OTX + ThreatCrowd: past IPs, vanished hostnames, CNAME chains. Keyless, passive. |
| passive_subdomains | Passive Subdomain Sources | passive_subdomains | Extra passive subdomain sources: CertSpotter CT, Wayback CDX and Bufferover passive DNS. Deduped, same-target only, no brute force. |
| port_audit | Port Auditor | port_audit | ~1000-port sweep with banner/version grabs, OS hints, TLS-on-any-port detection, and dangerous-exposure flags (databases, RDP/VNC/Telnet/ADB, Docker, K8s, ICS, crypto). |
| port_scan | Web Port Scan | port_scan | Deep scan of 50 web/dev ports with banner grab and TLS cert inspection. Read-only. |
| ports | Port Scanner | ports | Common port suggestions (passive) or real scan (active). |
| rapiddns | RapidDNS Subdomains | rapiddns | Subdomain enumeration from the RapidDNS index (multi-feed DNS data). Keyless, passive. |
| rdap | WHOIS / RDAP | rdap | Registrar, creation/expiry dates, registrant org via RDAP. |
| reverse_ip | Reverse IP (Co-hosted Domains) | reverse_ip | Co-hosted domains for an IP from hackertarget, AlienVault OTX passive DNS and RapidDNS same-IP listings. Keyless, passive. |
| smtp_tls | Mail Server TLS | smtp_tls | Audit MX hosts: STARTTLS advertisement, handshake success, cleartext auth exposure. |
| subdomain_brute | Subdomain Brute Force | subdomain_brute | DNS brute-force over a large wordlist with wildcard detection. Complements CT-log enumeration. |
| subdomain_compiler | Passive Subdomain Compiler | subdomain_compiler | Fast keyless subdomain compilation from crt.sh, hackertarget, threatcrowd, AlienVault OTX, certspotter, urlscan.io, subdomain.center. |
| subdomains | Subdomain Enum | subdomains | Certificate-transparency subdomains via crt.sh, plus active DNS brute force. |
| takeover | Takeover Checker | takeover | Detect dangling DNS / subdomain takeover potential. Fingerprint CNAME targets, verify the target is unclaimed (NXDOMAIN or provider error page). Detection only - never claims anything. |
| tls | TLS + Email Security | tls | Certificate details, SAN hostnames, SPF/DMARC/BIMI/MTA-STS posture. |
| wayback | Wayback History | wayback | Historical snapshots and old URLs via the Wayback CDX API. |

### Web (197)

| id | label | module | description |
|----|-------|--------|-------------|
| ai_llms_conflict | llms.txt vs robots.txt Conflicts | aipack | Flag llms.txt links to paths robots.txt tells crawlers to stay out of. |
| ai_llms_index | llms.txt Index & Link Map | aipack | Read /llms.txt and /llms-full.txt, feed their same-origin links to the hunters, and flag links to sensitive-looking paths. |
| ai_llms_secrets | llms.txt & Linked Docs Secret Miner | aipack | Mine llms.txt, llms-full.txt and the same-origin .md docs they link for credentials and secrets, masked + fingerprinted. |
| ai_robots_ai | AI Crawler robots.txt Inventory | aipack | Inventory which AI crawlers robots.txt allows, blocks, or partially restricts. |
| ai_tdm | TDM Reservation Protocol Audit | aipack | Audit the W3C TDM reservation: robots.txt tdm-reservation / tdm-policy lines and /.well-known/tdmrep.json. |
| allsources | All Sources | allsources | Extract every public source: JS, CSS, images, docs, inline code, comments, meta, JSON-LD. |
| altsvc_audit | Alt-Svc Header Audit | altsvc_audit | Parse the Alt-Svc response header (RFC 7838): HTTP/3 advertisements, draft versions, cross-origin alternative services, cleartext entries, and malformed headers. |
| appintel | App Intelligence | appintel | Build the AI app-analysis brief: frameworks, API patterns, auth flows, file inventory, hot files. |
| artifacts | Exposed Artifacts | artifacts | Sensitive-file exposure check (Wayback in passive, direct probe in active). |
| assetmap | Asset Map | assetmap | Full asset inventory: every file the site loads, sizes, first vs third party, heaviest assets, orphans. |
| auth | Auth Weakness Check | auth | JWT alg issues, cookie flags, default login hints. |
| auth_surface | Auth Surface Map | auth_surface | Find signup flows and exposed Jira/Confluence/GitLab/Jenkins. |
| autotriage | Auto Triage Router | autotriage | Route discovered tech to the right scanners; build manual test plan. |
| backup | Backup File Sweeper | backup | Sweep backup extensions on common files; sniff for secrets. |
| blogic | Business Logic Scout | blogic | Flag price params, coupons, paywalls for logic testing. |
| bounty | Bug Bounty Checklist | bounty | Automated bug bounty checks: open redirects, debug pages, sensitive endpoints. |
| cache_poisoning | Cache Poisoning Check | cache_poisoning | Detect web cache poisoning potential: unkeyed inputs reflected into cached responses. GET/HEAD only. |
| cards | Exposed Card Numbers | cards | Find Luhn-valid credit/debit card numbers exposed in pages and JS. |
| clickjack | Clickjack Tester | clickjack | Deep clickjacking analysis with PoC generation. |
| cmd_http | Command HTTP (curl) | cmdtools | curl redirect chain, raw banner headers, HTTP version and timing. |
| cmdi | Command Injection | cmdi | Command injection: time-based + error-based probes. |
| cms_probes | CMS Probes | cms_probes | WordPress/Drupal/Joomla + Shopify/Squarespace/Wix version detection + known-vuln checks. GET only, no login attempts. |
| cookie_security | Cookie Security Flags | cookie_security | Audit Set-Cookie flags: Secure, HttpOnly, SameSite, and __Host-/__Secure- prefix rules. |
| cors | CORS Tester | cors | Deep CORS misconfiguration testing. |
| crawler | Site Crawler | crawler | 5-level crawl: links, forms, comments, sitemap, CSS, externals. |
| creds | Hardcoded Credentials | creds | Find hardcoded logins, DB URLs, basic-auth and framework secrets. |
| crypto | Crypto Address Finder | crypto | Find published crypto addresses for fund-flow pivoting. |
| cryptoconfig | Crypto RPC Checker | cryptoconfig | Check for open blockchain RPC endpoints. |
| csp_audit | CSP Policy Audit | csp_audit | Parse and grade the Content-Security-Policy: unsafe-inline, wildcards, data: sources, missing fallbacks. |
| cves | CVE Matcher | cves | Detect software versions, match against known CVEs with exploitability. |
| da_archive_configs | App Archive Config Exposure (da) | artifacts_deep | JAR/WAR archives: embedded config filenames via ZIP central directory, keystore names, and masked secrets from one bounded config entry. |
| da_build_listing | Build Artifact Listing (da) | artifacts_deep | Open listings of build folders exposing compiled artifacts by filename: .pyc/.class/.pdb/.hprof/.jar/.wasm and source files. |
| da_crash_dump | Crash/Core Dump Exposure (da) | artifacts_deep | Windows minidump (.dmp) and ELF core dump files verified by file signature from a capped ranged read. |
| da_debug_symbols | Debug Symbols Exposure (da) | artifacts_deep | PDB debug symbol files verified by the MSF signature and dSYM bundles exposed via their Info.plist. |
| da_heap_dump | Heap Dump Exposure (da) | artifacts_deep | Java heap dumps (.hprof), Node/V8 heap snapshots and JVM thread dumps verified by format signature from a capped ranged read. |
| da_wasm_surface | WASM Module Surface (da) | artifacts_deep | WebAssembly modules verified by the \0asm magic; import/export names and embedded URLs parsed from a capped head window. |
| dedup | Finding Deduplicator | dedup | Remove duplicate findings across plugins and repeat scans; merge cross-plugin evidence; boost corroborated findings; flag contradictions. |
| deepcrawl | Deep Source Analyzer | deepcrawl | Deep crawl: every link, JS file, API call. Complete surface map. |
| dependency_conf | Dependency Confusion Detector | dependency_conf | Finds exposed dependency manifests and flags internal-looking packages against public registries. |
| devtools | DevTools Analyzer | devtools | DevTools equivalent: page structure, network surface, error hints, performance. |
| dir_brute | Directory Brute Force | dir_brute | Brute-force hidden paths (admin, backups, configs) with 404-baseline filtering. GET only, no login attempts. |
| dorks | Google Dorks | dorks | Targeted Google dork queries for the domain. |
| enterprise | Enterprise Software Scout | enterprise | Detect SAP, Oracle, Salesforce, SharePoint, Exchange, ServiceNow, Atlassian, Tableau, Splunk, Kibana and admin panels. Read-only. |
| error_pages | Error Page Disclosure | error_pages | Probe nonexistent paths for stack traces, debug mode, SQL errors and path disclosure in error pages. |
| exif | Image EXIF Extractor | exif | Extract EXIF GPS/device metadata from site images. |
| exposed_debug | Exposed Debug Toolbars | exposed_debug | Detect dev debug toolbars/profilers (Django, Symfony, Laravel, Rails) left enabled in production. |
| favicon_hash | Favicon Hasher | favicon_hash | MurmurHash3 favicon hash (Shodan-compatible) for asset pivoting. |
| feroxbuster | Feroxbuster | feroxbuster | Recursive content discovery: auto-recurses into found dirs. GET only. |
| filehunter | File Hunter | filehunter | Hunt exposed backups, configs, VCS, logs, DB dumps, archives. Notes 403s, never bypasses. |
| financial | Financial Footprint | financial | Find payment processors, bank refs, crypto wallets, billing. |
| fingerprint | Deep Tech Fingerprinter | fingerprint | Identify every framework, version, plugin, server, CDN. |
| firecrawl | Firecrawl Mapper | firecrawl | Sitemap + robots + crawl path index. Keyless, no external API. |
| forms | Form Catalog | forms | Crawl same-site pages and catalog every HTML form (method, action, inputs). Detection only, never submitted. |
| fx_deserialization_surface | Deserialization Surface (passive) | fmtpack | Native serialized objects (Java, PHP, Python pickle, .NET) observed in the target's own cookies and responses - the classic untrusted-deserialization attack surface. |
| fx_dtd_schema | DTD Exposed | fmtpack | A .dtd document type definition served publicly: element and entity declarations disclose the document grammar; external DTDs are also the classic XXE delivery file. |
| fx_xsd_schema | XML Schema (XSD) Exposed | fmtpack | An .xsd XML Schema served publicly: element and type names disclose the exact document grammar the application accepts - the map for XXE and schema-complexity attacks. |
| gau | Get All URLs | gau | Known URLs from OTX + Wayback + Common Crawl. Keyless archives only. |
| giftcards | Exposed Gift Card Codes | giftcards | Find exposed gift card codes (Amazon, Steam, Visa gift) in pages and JS. |
| giftinfra | Gift Card Infrastructure Map | giftinfra | Map gift card systems: providers, API endpoints, purchase/redeem/balance flows. |
| git | Exposed .git Check | git | Deep .git exposure check: HEAD, config, logs, index. |
| git_exposed | Exposed .git Detector | git_exposed | GitTools-style: probe for publicly readable VCS metadata (.git, .svn, .hg, .bzr). |
| gitleaks_scan | GitLeaks Secret Scan | gitleaks_scan | GitLeaks-style rule pack: 40+ secret patterns across pages, JS, comments, and meta tags. |
| gobuster | Gobuster | gobuster | Fast directory/file brute force: 350+ entries x extensions, 404-baseline filtered. GET only. |
| graphql | GraphQL Analyzer | graphql | Finds GraphQL endpoints, runs one safe introspection query, and flags schema exposure and deep-query risk. |
| gx_confluence_public_page | Public Confluence Page | gappack | Confluence pages linked from the target's pages and reachable without a login. |
| gx_git_history_secrets | Git History Secret Scan | gappack | When /.git is exposed, walks the loose-object history (reflog -> commits -> trees -> blobs) and scans blobs - including secrets deleted at HEAD that still live in history. |
| gx_google_share_link | Public Google Drive/Docs Link | gappack | Google Drive folders/files and Docs/Sheets/Slides share links in the target's pages; verified when they resolve without a Google sign-in wall. |
| gx_jira_public_link | Public Jira Surface | gappack | Jira boards/dashboards/filters/projects linked from the target's pages and reachable without a login. |
| gx_pinecone_key | Pinecone API Key Exposed | gappack | Pinecone vector DB API keys (pcsk_ format) in pages/JS - a leaked key hands over the account's indexes. hf_ tokens are covered elsewhere and are not repeated here. |
| gx_training_data_refs | Training Data References | gappack | Training-data exposure leads in the target's pages/JS: public Hugging Face dataset links, load_dataset() calls, and direct dataset file URLs (jsonl/parquet/arrow) - the raw material AI features are trained on, left public. |
| gx_trello_board | Public Trello Board | gappack | Public Trello boards linked from the target's pages; verified via the board's own public .json view. |
| hakrawler | HaKrawler | hakrawler | Fast lightweight crawl: URLs, subdomains, JS files. GET only. |
| hashid | Hash Identifier | hashid | Identify hash algorithms in page text and JS (CTF helper). |
| headers | Security Headers | headers | Missing security headers and information-disclosure headers. |
| hiddenpaths | Hidden Endpoint Finder | hiddenpaths | Brute-force unlinked paths. Find hidden endpoints. |
| hsts | HSTS Analysis | hsts | Grade the HSTS policy: max-age, includeSubDomains, preload readiness, bare-domain downgrade. |
| html_comments | HTML Comment Intel | html_comments | Mine HTML comments for TODOs, commented-out endpoints, internal hosts and credential patterns. |
| htmli | HTML Injection | htmli | HTML injection: inert markup canary reflection check. |
| http2_check | HTTP/2 / HTTP/3 Support | http2_check | Detect negotiated HTTP version via ALPN: HTTP/1.1-only, HTTP/2, or HTTP/3 (QUIC). |
| http_methods | HTTP Methods Audit | http_methods | OPTIONS-based audit: TRACE/XST, PUT/DELETE, WebDAV verbs, DEBUG. Advertised methods only, never exercised. |
| httrack | HTTrack Mapper | httrack | Full site structure map: directory tree, section sizes, orphan dirs. GET only. |
| idor | IDOR Pattern Finder | idor | Flag predictable IDs; sequential=high risk, UUID=low. |
| infodisclosure | Info Disclosure Probe | infodisclosure | Probe debug/info endpoints: phpinfo, server-status, actuator, pprof. |
| js_retire | Vulnerable JS Libraries | js_retire | Retire.js-style: detect outdated/vulnerable JS libraries with CVE mapping. |
| js_secrets | JS Secret Miner | js_secrets | Deep JS/HTML secret mining: 60+ patterns over every JS bundle, inline scripts, HTML comments, and source maps. |
| jsdeep | Deep JS Analysis | jsdeep | Download all JS bundles: endpoints, URLs, secrets, TODOs, source maps + original-source reconstruction. |
| jsminer | JS Bundle Miner | jsminer | Mine JS bundles for endpoints, hosts, keys; recover source maps. |
| katana | Katana Crawler | katana | Next-gen crawl: isolate page URLs, API endpoints, and JS files. GET only. |
| ldapi | LDAP Injection | ldapi | LDAP injection detection via safe error-based probes. |
| misconfig | Framework Misconfig Detector | misconfig | Detects framework dev-mode exposures: Django debug, Laravel .env, Rails keys, Spring Boot actuator, phpinfo, Apache server-status. |
| misconfig_sweep | Misconfig Sweep | misconfig_sweep | 50+ misconfiguration checks: headers, cookies, CORS, methods. |
| mixed_content | Mixed Content | mixed_content | Find http:// subresources on https pages (active vs passive mixed content). |
| nosqli | NoSQL Injection | nosqli | NoSQL injection: operator, error and timing probes. |
| notifications | Scan Notifications | notifications | Sends scan-complete alerts to Discord / Slack / Telegram webhooks when configured. |
| oob_callback | Out-of-Band Callback Trigger | oob_callback | Inject unique OOB callback canaries; documents payloads for Jay to check. |
| opendir | Open Directories | opendir | Find open directory listings on common paths. |
| openid_discovery | OIDC Discovery | openid_discovery | Parse /.well-known/openid-configuration: issuer, endpoints, and weak OIDC configuration. |
| param_discovery | Parameter Discovery | param_discovery | Discover hidden GET params with canary probes; flag unencoded reflection (XSS candidates). GET only. |
| param_fuzzer | Response-Diff Parameter Fuzzer | param_fuzzer | GET-only param fuzzer; flags behavior-changing params via response diff. |
| pf_ably_api_key | Ably API key | privfind | Private findings: detects Ably API key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_age_secret_key | age encryption secret key | privfind | Private findings: detects age encryption secret key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_airtable_pat | Airtable personal access token | privfind | Private findings: detects Airtable personal access token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_alibaba_access_key | Alibaba Cloud AccessKey ID | privfind | Private findings: detects Alibaba Cloud AccessKey ID publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_appsettings_json | ASP.NET appsettings with connection strings | privfind | Private findings: detects ASP.NET appsettings with connection strings publicly served at a well-known path. Marker-gated; detection only. |
| pf_auth_json_file | Registry auth.json with credentials | privfind | Private findings: detects Registry auth.json with credentials publicly served at a well-known path. Marker-gated; detection only. |
| pf_auth_secret_env | Framework auth secret (env-style) | privfind | Private findings: detects Framework auth secret (env-style) publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_aws_session_token | AWS session token | privfind | Private findings: detects AWS session token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_buildkite_token | Buildkite API token | privfind | Private findings: detects Buildkite API token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_contentful_token | Contentful management token | privfind | Private findings: detects Contentful management token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_cookies_txt | cookies.txt session file | privfind | Private findings: detects cookies.txt session file publicly served at a well-known path. Marker-gated; detection only. |
| pf_docker_config_file | Docker client config with registry credentials | privfind | Private findings: detects Docker client config with registry credentials publicly served at a well-known path. Marker-gated; detection only. |
| pf_doppler_token | Doppler service token | privfind | Private findings: detects Doppler service token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_edgerc_file | Akamai .edgerc API credentials | privfind | Private findings: detects Akamai .edgerc API credentials publicly served at a well-known path. Marker-gated; detection only. |
| pf_facebook_token | Facebook access token | privfind | Private findings: detects Facebook access token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_figma_token | Figma personal access token | privfind | Private findings: detects Figma personal access token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_flutterwave_secret | Flutterwave secret key | privfind | Private findings: detects Flutterwave secret key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_gcp_sa_token | Google Cloud service-agent token | privfind | Private findings: detects Google Cloud service-agent token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_gitlab_runner_token | GitLab runner authentication token | privfind | Private findings: detects GitLab runner authentication token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_google_oauth_access | Google OAuth access token | privfind | Private findings: detects Google OAuth access token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_google_refresh_token | Google OAuth refresh token | privfind | Private findings: detects Google OAuth refresh token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_groq_api_key | Groq API key | privfind | Private findings: detects Groq API key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_idea_workspace | JetBrains workspace.xml with credentials | privfind | Private findings: detects JetBrains workspace.xml with credentials publicly served at a well-known path. Marker-gated; detection only. |
| pf_jwk_private_key | JWK private key material | privfind | Private findings: detects JWK private key material publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_kubeconfig_file | Kubernetes kubeconfig with client keys | privfind | Private findings: detects Kubernetes kubeconfig with client keys publicly served at a well-known path. Marker-gated; detection only. |
| pf_laravel_log | Laravel log file with secrets | privfind | Private findings: detects Laravel log file with secrets publicly served at a well-known path. Marker-gated; detection only. |
| pf_linear_api_key | Linear API key | privfind | Private findings: detects Linear API key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_newrelic_api_key | New Relic user API key | privfind | Private findings: detects New Relic user API key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_notebook_creds | Jupyter notebook with embedded credentials | privfind | Private findings: detects Jupyter notebook with embedded credentials publicly served at a well-known path. Marker-gated; detection only. |
| pf_notion_secret | Notion integration secret | privfind | Private findings: detects Notion integration secret publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_otpauth_seed | TOTP/HOTP shared secret (otpauth URL) | privfind | Private findings: detects TOTP/HOTP shared secret (otpauth URL) publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_perplexity_key | Perplexity API key | privfind | Private findings: detects Perplexity API key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_posthog_personal_key | PostHog personal API key | privfind | Private findings: detects PostHog personal API key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_postman_collection | Postman collection with embedded auth | privfind | Private findings: detects Postman collection with embedded auth publicly served at a well-known path. Marker-gated; detection only. |
| pf_pypirc_file | PyPI .pypirc with repository password | privfind | Private findings: detects PyPI .pypirc with repository password publicly served at a well-known path. Marker-gated; detection only. |
| pf_rails_master_key | Rails master key file | privfind | Private findings: detects Rails master key file publicly served at a well-known path. Marker-gated; detection only. |
| pf_replicate_token | Replicate API token | privfind | Private findings: detects Replicate API token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_reset_link_leak | Password-reset / magic-login link | privfind | Private findings: detects Password-reset / magic-login link publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_sentry_org_token | Sentry organization auth token | privfind | Private findings: detects Sentry organization auth token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_serverless_yml | Serverless Framework config with secrets | privfind | Private findings: detects Serverless Framework config with secrets publicly served at a well-known path. Marker-gated; detection only. |
| pf_session_cookie_leak | Session cookie value in served text | privfind | Private findings: detects Session cookie value in served text publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_square_oauth_secret | Square OAuth application secret | privfind | Private findings: detects Square OAuth application secret publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_ssh_ed25519_file | SSH ed25519 private key file | privfind | Private findings: detects SSH ed25519 private key file publicly served at a well-known path. Marker-gated; detection only. |
| pf_stripe_webhook_secret | Stripe webhook signing secret | privfind | Private findings: detects Stripe webhook signing secret publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_supabase_service_key | Supabase service-role secret key | privfind | Private findings: detects Supabase service-role secret key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_tencent_secret_id | Tencent Cloud SecretId | privfind | Private findings: detects Tencent Cloud SecretId publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_terraform_cloud_token | Terraform Cloud API token | privfind | Private findings: detects Terraform Cloud API token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_terraformrc_file | Terraform CLI config with registry token | privfind | Private findings: detects Terraform CLI config with registry token publicly served at a well-known path. Marker-gated; detection only. |
| pf_tfstate_file | Terraform state file (contains secrets) | privfind | Private findings: detects Terraform state file (contains secrets) publicly served at a well-known path. Marker-gated; detection only. |
| pf_tfvars_file | Terraform variables file with secrets | privfind | Private findings: detects Terraform variables file with secrets publicly served at a well-known path. Marker-gated; detection only. |
| pf_token_in_url | Access token embedded in a public URL | privfind | Private findings: detects Access token embedded in a public URL publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_vault_token | HashiCorp Vault token | privfind | Private findings: detects HashiCorp Vault token publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_webhook_secret_env | Webhook signing secret (env-style) | privfind | Private findings: detects Webhook signing secret (env-style) publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_xai_api_key | xAI API key | privfind | Private findings: detects xAI API key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| photon | Photon OSINT | photon | Fast OSINT scrape: background files, hidden endpoints, params, emails. |
| phpinfo | phpinfo() Exposure | phpinfo | Detect exposed phpinfo() pages disclosing PHP config, paths and environment. |
| proto_pollution | Prototype Pollution Detector | proto_pollution | Checks JS library versions for known prototype-pollution CVEs and tests for safe pollution-marker reflection. |
| rate_limit_audit | Rate-Limit Headers | rate_limit_audit | Audit rate-limit signals (X-RateLimit-*, Retry-After): documented limits vs no abuse signals at all. |
| rce | RCE Time Probe | rce | RCE check: time-delay canary + error-based detection. |
| redirect_chain | Redirect Chain | redirect_chain | Analyze the homepage redirect chain: downgrades, off-domain hops, loops, long chains. |
| robots | Robots / Sitemap | robots | Parse robots.txt and sitemap.xml for hidden paths. |
| s3 | Cloud Bucket Finder | s3 | Find S3/GCS/Azure buckets and test public access. |
| screenshots | Screenshot Capture | screenshots | Headless-browser screenshots of the target and discovered subdomains for fast visual vetting. |
| secrets | Exposed API Keys | secrets | Mine pages and JS bundles for 90+ API key and token patterns. |
| smartcontract | Smart Contract Scout | smartcontract | Find contract addresses and flag risky patterns. |
| smb_tech | SMB Tech Stack | smb_tech | Detect small-business website platforms (Shopify, Squarespace, Wix, Weebly, GoDaddy, Webflow, Duda) and flag quick misconfigs. GET only. |
| smuggling | Request Smuggling Detector | smuggling | Timing-based HTTP request-smuggling/desync detection with harmless conflicting-header probes. |
| sourcemap | Source Map Reconstructor | sourcemap | Reconstruct source maps; extract secrets, internal URLs, debug flags. |
| sqli | SQLi Probe | sqli | SQLi check: error-based + UNION + time-blind + boolean-blind. |
| sri_audit | Subresource Integrity | sri_audit | Audit cross-origin scripts/stylesheets for missing SRI integrity attributes. |
| ssrf | SSRF Sink Finder | ssrf | Find SSRF-prone params and metadata references (verify manually). |
| ssti | SSTI Probe | ssti | SSTI check: math-canary probes across template engines. |
| stealth_crawler | Stealth Crawler | stealth_crawler | Human-like crawler (jittered delays, rotating UAs, respects robots.txt) that finds hidden API endpoints, WebSocket URLs and dynamic routes in JS. |
| supplychain | Supply Chain Scout | supplychain | Flag vulnerable third-party JS libraries. |
| tech_fingerprint | Tech Fingerprint+ | tech_fingerprint | Exact version detection for 100+ technologies, CVE matching via OSV, and EOL flagging. |
| tls_config | TLS Config Audit | tls_config | Audit TLS versions, weak ciphers, compression (CRIME) and forward secrecy. |
| trackers | Third-Party Trackers | trackers | Inventory third-party trackers/adtech with script access on the page. |
| traversal | Path Traversal Check | traversal | Probe file params for directory traversal (read-only passwd check). |
| truffle_scan | TruffleHog Entropy Scan | truffle_scan | High-entropy string detection (TruffleHog-style) across pages, JS, and exposed .git metadata. |
| urlscan | URL Analyzer | urlscan | Full HTTP transaction record: redirect chain, background resources, third-party domains. Keyless. |
| waf | WAF Detector | waf | Detect Web Application Firewalls via shared vendor signatures. |
| walletcheck | Wallet Security Check | walletcheck | Find exposed wallets, mnemonics, keystores. |
| wallets | Wallet Key Exposure | wallets | Hunt exposed crypto private keys, seed phrases and wallet files. |
| waybackurls | Wayback URLs | waybackurls | Every URL Wayback cached for the site. Keyless CDX API. |
| web_manifest | PWA Manifest / SW Audit | web_manifest | Audit PWA manifest (scope, icons, start_url) and service worker exposure. |
| webtech | Web Tech Fingerprint | webtech | Framework/CMS/CDN/analytics fingerprint + robots/sitemap/security.txt + favicon hash. |
| well_known_audit | Well-Known URIs | well_known_audit | Audit /.well-known/ files: security.txt, change-password, assetlinks, apple-app-site-association, gpc.json. |
| wget | Wget Mirror | wget | Recursive asset inventory (wget -r -np style). Reports URLs/types/sizes, stores nothing. |
| xml_policy | XML Cross-Domain Policy Reader | xmlpack | Parse crossdomain.xml / clientaccesspolicy.xml contents: wildcard cross-domain grants let any site read this origin's data with a victim's session (existence probes existed; the policy itself was never read). |
| xml_secrets | XML Secrets & Config Miner | xmlpack | Read the target's XML files (config XML, feeds, WSDLs, discovered .xml) for credentials, connection strings, secrets and PII. |
| xml_sitemap_paths | XML Sitemap Path Miner | xmlpack | Parse sitemap contents from every source (probes, robots.txt declarations, index children): sensitive-path URLs become findings and all URLs feed the hunter bus. |
| xml_wsdl | XML WSDL Service Reader | xmlpack | Read WSDL documents: published service addresses (internal ones flagged), operation names and imported schemas map the SOAP attack surface. |
| xml_xxe_surface | XML External Entity Surface | xmlpack | Detect external entity, external DTD, parameter entity and XInclude declarations in the target's served XML (XXE surface). The declared URIs are reported, never fetched. |
| xpathi | XPath Injection | xpathi | XPath injection detection via safe error-based probes. |
| xs_leak | Cross-Site Leak Detector | xs_leak | Checks COOP/COEP/CORP isolation headers, framing protections, and status-code oracle candidates. |
| xss | XSS Canary | xss | XSS check: reflected canary + DOM sink analysis. |
| zeroday_differential | Zero-Day Candidate Hunter (Differential) | zeroday_differential | Mutates the types/shapes of parameters a target actually uses (arrays, duplicates, nulls, huge numbers, malformed bodies) and flags crash, debug disclosure, data-shaped or timing anomalies as candidate zero-days for human review. |
| zeroday_error_miner | Zero-Day Candidate Hunter (Error-Path Miner) | zeroday_error_miner | Sends deliberately malformed requests (bad IDs, broken encodings, truncated bodies) to discovered endpoints and mines the error responses for internal paths, SQL detail, hostnames, env names and versions nobody enumerated. |

### API (18)

| id | label | module | description |
|----|-------|--------|-------------|
| apidiscover | API Discovery | apidiscover | Backend inference, docs discovery, GraphQL introspection, API map. |
| authscan | Authenticated Scanner | authscan | Test endpoints with your credentials (env-provided). Finds auth-gated vs unexpectedly open endpoints. |
| bola | BOLA API Tester | bola | Detect BOLA candidates on API endpoints. |
| endpointauth | Endpoint Auth Probe | endpointauth | Probe API-looking endpoints with one clean GET to classify auth requirements. Detection only: no parameters, no credentials, no auth attempts. |
| fx_avro_schema | Avro Schema Exposed | fmtpack | An .avsc Avro schema served publicly: record and field names disclose the exact shape of the data pipeline's payloads. |
| fx_capnp_schema | Cap'n Proto Schema Exposed | fmtpack | A .capnp Cap'n Proto schema served publicly: struct and interface definitions disclose the binary protocol contract. |
| fx_flatbuffers_schema | FlatBuffers Schema Exposed | fmtpack | A .fbs FlatBuffers schema served publicly: table/struct definitions disclose the binary message layout exactly. |
| fx_proto_schema | Protobuf Schema Exposed | fmtpack | A .proto file served publicly: the service, RPC method and message definitions are the API's complete blueprint. |
| fx_thrift_schema | Thrift IDL Exposed | fmtpack | A .thrift interface definition served publicly: service and struct definitions disclose the RPC surface in full. |
| graphql_deep | GraphQL Deep Analysis | graphql_deep | Deep read-only GraphQL analysis: schema field enumeration, batching and GET-query probes. No mutations executed. |
| graphql_probe | GraphQL Exposure | graphql_probe | Detect GraphQL endpoints and whether introspection / GraphiQL consoles are exposed. |
| gx_graphql_schema_exposure | GraphQL Schema Exposure (Discovered Endpoints) | gappack | Discovers GraphQL endpoints from the target's pages/JS (custom paths, Hasura, cross-host API hosts the fixed-path probes never see) and runs the standard introspection query: a returned schema is reported with total type/field counts. |
| idor_comparator | Multi-Account IDOR Comparator | idor_comparator | Two-account IDOR/BOLA differential test (env tokens, never stored). |
| js_endpoints | JS Endpoint Extractor | js_endpoints | LinkFinder-style: aggressive endpoint extraction from JS bundles (fetch/axios/XHR, GraphQL, WebSockets). |
| jwt | JWT Analyzer | jwt | Finds JWTs in responses and JS, checks alg=none, weak secrets (offline), missing exp, and payload data. |
| logici | API Logic Injection | logici | Logic injection: boolean/type-juggle differential probes. |
| race_detect | Race Condition Detector | race_detect | Detects payment-style endpoints without idempotency-key support. Detection only - never sends concurrent or duplicate requests. |
| websocket_tester | WebSocket Tester | websocket_tester | Finds ws/wss endpoints in JS and page source, tests the upgrade handshake connect-only. |

### Mobile (5)

| id | label | module | description |
|----|-------|--------|-------------|
| binex | Deep Binary Analysis | binex | Deep APK static analysis: permissions, exported components, secrets, native libs, signer. |
| da_mobile_package | Hosted Mobile Package (da) | artifacts_deep | APK/IPA/AAB hosted on the target: presence plus config entry names from the ZIP central directory (google-services.json and friends). |
| mobile | Mobile App Analysis | mobile | APK/IPA metadata, static strings, secret scan, deep links. |
| pf_apple_service_plist | Firebase GoogleService-Info.plist (mobile backend config) | privfind | Private findings: detects Firebase GoogleService-Info.plist (mobile backend config) publicly served at a well-known path. Marker-gated; detection only. |
| pf_google_services_json | Firebase google-services.json (mobile backend config) | privfind | Private findings: detects Firebase google-services.json (mobile backend config) publicly served at a well-known path. Marker-gated; detection only. |

### Identity (26)

| id | label | module | description |
|----|-------|--------|-------------|
| breachwatch | Breach Watch | breachwatch | Defensive breach check for your own addresses: XposedOrNot keyless lookup, per-breach severity from leaked data classes. Never attempts logins. |
| credential_strength | Credential Strength | credential_strength | Assess hashes/passwords found in public sources: hash type, public cracked-DB lookup, crackability verdict. No cracking performed. Works with no API keys. |
| email_breach | Email Breach Exposure | email_breach | Check emails against public breach data (HaveIBeenPwned): which breaches, what data was exposed, when. |
| email_exposure | Exposed Credentials | email_exposure | Hunt publicly exposed credentials for the target: GitHub code search, paste compilations, exposed .env/config files. |
| email_infra | Email Security Posture | email_infra | Audit email spoofing defenses: SPF, DKIM, DMARC, MX provider. Scores spoofing risk. |
| emails | Email Harvester | emails | Find email addresses on the target site. |
| github | GitHub Dorker | github | Search GitHub code for target mentions and leaks. |
| github_dorking | GitHub Secret Dorks | github_dorking | Secret dorking for committed secrets: keyless Sourcegraph code search + clickable dork links. GITHUB_TOKEN (optional) adds GitHub API results. |
| hashcracker | Hash Cracker (Defensive) | hashcracker | Identify hash types and check public breach/rainbow databases (HIBP k-anonymity, keyless). Direct mode (submit a hash as the target): also cracks it with the bundled dictionary+rules engine, time-boxed 60s. Scan mode is analysis-only: verdicts, never plaintexts. |
| jwt_audit | JWT Security Auditor | jwt_audit | Audits JWTs found during the scan for weak config (alg none, missing/long exp, sensitive claims, weak HMAC secrets checked offline). Detection only - never forges tokens. |
| keyleak | Key Leak Checker | keyleak | Defensive: check if identifiers appear in public leaks (fast parallel). |
| leaks | Leaks + Identity | leaks | Breach check, GitHub code search, dork generator, username enum. |
| pastes | Paste Search | pastes | Search paste sites for leaked data. |
| pf_pii_aadhaar_in | India Aadhaar number | privfind | Private findings: detects India Aadhaar number publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_pii_iban | IBAN (validated) | privfind | Private findings: detects IBAN (validated) publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_pii_nhs_uk | UK NHS number | privfind | Private findings: detects UK NHS number publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_pii_nino_uk | UK National Insurance number | privfind | Private findings: detects UK National Insurance number publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_pii_pan_in | India PAN | privfind | Private findings: detects India PAN publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_pii_sin_ca | Canadian Social Insurance Number | privfind | Private findings: detects Canadian Social Insurance Number publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_pii_ssn_us | US Social Security number | privfind | Private findings: detects US Social Security number publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_pii_tfn_au | Australian Tax File Number | privfind | Private findings: detects Australian Tax File Number publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| phones | Phone Lookup | phones | Carrier, line type, region, and validity for phone numbers (offline, no keys). Extracts phone numbers from pages. |
| pivots | Pivot Finder | pivots | Favicon/Shodan pivot, tracking-ID pivot, tech-stack pivot queries. |
| secret_identity | Exposed Secret Identification | secret_identity | Identify exactly which secret is exposed from masked metadata only: source, line, type, length, masked value, and fingerprint. Full values are never shown. |
| social | Social Footprint | social | Find associated social media accounts. |
| usernames | Username Checker | usernames | Sherlock-style username check; harvests candidates from sites. |

### Infra (53)

| id | label | module | description |
|----|-------|--------|-------------|
| asm | Attack Surface Manager | asm | Track attack surface over time; detect new/removed/changed assets. |
| atm | ATM Infrastructure Detection | atm | ATM footprint: subdomains, portals, mgmt interfaces, locations, vendor CVEs. Detection only. |
| cdn_detect | CDN Detection | cdn_detect | Identify the CDN/edge provider from headers and DNS CNAMEs (edge naming only, no origin hunting). |
| cloud | Cloud Misconfig Scout | cloud | Detect Azure/GCP/AWS cloud misconfigurations. |
| cloud_buckets | Cloud Bucket Probe | cloud_buckets | Probe common bucket names on S3, GCS, Azure (list-only). |
| cloud_enum | Multi-Cloud Enumerator | cloud_enum | CloudBrute-style: bucket/infra discovery across AWS, GCP, Azure, and DigitalOcean. |
| da_device_config_export | Device Config Export (da) | artifacts_deep | Device/router configuration exports at conventional paths; first-bytes classification and credential field names as evidence. |
| da_firmware_image | Firmware Image Exposure (da) | artifacts_deep | Firmware images (.bin/.img/.fw/.trx) verified by format signature - uImage, TRX, SquashFS, UBI, device-tree. |
| da_ota_manifest | OTA/Update Manifest (da) | artifacts_deep | Firmware/OTA update manifests leaking version info and download URLs (internal URLs flagged). |
| docker | Docker Exposure | docker | Detect open Docker registries and daemon sockets. |
| edge_appliances | Edge Appliance Fingerprinter | edge_appliances | Detect VPN gateways, load balancers and mail servers from banners/headers/portal pages/certs, extract versions, and match known CVEs. Passive + port probes; no auth attempts. |
| gx_azure_container_public | Azure Container Public Listing | gappack | Azure Blob CONTAINERS referenced by the target (account + container from real URLs - the level bucket-root probes miss), tested for anonymous listing. |
| gx_chroma_open | Chroma Vector DB Open | gappack | Chroma vector database answering its API with no authentication - collections listable by anyone. |
| gx_consul_catalog | Consul Service Catalog Open | gappack | Consul SERVICE CATALOG (/v1/catalog/services) readable with no token - the full internal service inventory. (The pf pack reads agent info; the catalog is the map of everything.) |
| gx_eureka_registry | Eureka Service Registry Open | gappack | Netflix Eureka registry (/eureka/apps) readable with no auth - every registered service instance, host and port. |
| gx_firebase_storage_public | Firebase Storage Public Listing | gappack | Firebase Storage buckets referenced by the target, tested for anonymous listing via the storage JSON API (s3.py mines these refs but never tests them). |
| gx_istio_debug | Istio Pilot Debug Exposed | gappack | Istio Pilot debug endpoints (/debug/configz) reachable - they dump the full Envoy config: every internal cluster, listener and route. |
| gx_milvus_open | Milvus Vector DB Open | gappack | Milvus vector database: health endpoint and the REST collection list answering with no auth. |
| gx_mlflow_open | MLflow Tracking Server Open | gappack | MLflow tracking server listing experiments (and their artifact locations - where training data and models live) with no authentication. |
| gx_nacos_registry | Nacos Service Registry Open | gappack | Nacos discovery catalog listing services with no auth - the internal service map of Spring Cloud / Alibaba stacks. |
| gx_ollama_open | Ollama LLM Server Open | gappack | Ollama LLM server answering /api/tags with no auth - anyone can run inference on (and pull models to) the host. |
| gx_public_object_read | Public Object Read | gappack | Object-level public access: the exact storage object URLs (and sensitive-file links) the target references, HEAD-probed anonymously. A bucket can be non-listable while its objects are world-readable. Proof is headers only - bodies are never downloaded. |
| gx_qdrant_open | Qdrant Vector DB Open | gappack | Qdrant vector database answering /collections with no API key - anyone can enumerate (and query) the stored embeddings. |
| gx_torchserve_open | TorchServe Management API Open | gappack | TorchServe management API listing registered models and their config - the management port also allows registering/unregistering models. |
| gx_triton_open | Triton Inference Server Open | gappack | NVIDIA Triton inference server listing its models (/v2/models) with no authentication. |
| gx_weaviate_open | Weaviate Vector DB Open | gappack | Weaviate vector database exposing its full schema (/v1/schema) with no authentication. |
| hypervisor | Hypervisor Scout | hypervisor | Detect exposed hypervisor management interfaces. |
| iot | IoT Device Scout | iot | Detect IoT devices, default creds, firmware disclosure. |
| k8s | Kubernetes Misconfig | k8s | Detect exposed Kubernetes API and dashboard. |
| pf_amqps_url | AMQP-over-TLS URL with credentials | privfind | Private findings: detects AMQP-over-TLS URL with credentials publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_azure_sas_url | Leaked Azure Storage SAS URL | privfind | Private findings: detects Leaked Azure Storage SAS URL publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_cassandra_url | Cassandra URL with credentials | privfind | Private findings: detects Cassandra URL with credentials publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_clickhouse_url | ClickHouse URL with credentials | privfind | Private findings: detects ClickHouse URL with credentials publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_consul_agent_info | Consul agent info (unauthenticated) | privfind | Private findings: detects Consul agent info (unauthenticated) publicly served at a well-known path. Marker-gated; detection only. |
| pf_elasticsearch_info | Elasticsearch cluster info (unauthenticated) | privfind | Private findings: detects Elasticsearch cluster info (unauthenticated) publicly served at a well-known path. Marker-gated; detection only. |
| pf_etcd_version | etcd version endpoint (unauthenticated) | privfind | Private findings: detects etcd version endpoint (unauthenticated) publicly served at a well-known path. Marker-gated; detection only. |
| pf_gcs_signed_url | Leaked Google Cloud Storage signed URL | privfind | Private findings: detects Leaked Google Cloud Storage signed URL publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_ldap_url | LDAP bind URL with credentials | privfind | Private findings: detects LDAP bind URL with credentials publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_mongo_express_console | Mongo Express console (DB contents browsable) | privfind | Private findings: detects Mongo Express console (DB contents browsable) publicly served at a well-known path. Marker-gated; detection only. |
| pf_mqtt_url | MQTT URL with credentials | privfind | Private findings: detects MQTT URL with credentials publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_nats_url | NATS URL with credentials | privfind | Private findings: detects NATS URL with credentials publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_oracle_url | Oracle DB URL with credentials | privfind | Private findings: detects Oracle DB URL with credentials publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_portainer_console | Portainer container console | privfind | Private findings: detects Portainer container console publicly served at a well-known path. Marker-gated; detection only. |
| pf_presigned_s3_url | Leaked presigned S3 URL | privfind | Private findings: detects Leaked presigned S3 URL publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_redis_commander_console | Redis Commander console | privfind | Private findings: detects Redis Commander console publicly served at a well-known path. Marker-gated; detection only. |
| pf_s3_cred_url | S3 URL with embedded credentials | privfind | Private findings: detects S3 URL with embedded credentials publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_smtp_url | SMTP URL with credentials | privfind | Private findings: detects SMTP URL with credentials publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_solr_admin | Apache Solr admin info | privfind | Private findings: detects Apache Solr admin info publicly served at a well-known path. Marker-gated; detection only. |
| pf_sqlserver_url | SQL Server URL with credentials | privfind | Private findings: detects SQL Server URL with credentials publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| shadowit | Shadow IT Detector | shadowit | Find unauthorized internal tools exposed to the internet. |
| threat_monitor | Threat Intel Monitor | threat_monitor | Watches public CVE feeds (NVD) for new vulnerabilities affecting the target's detected tech stack. |
| typosquat | Typosquat Domains | typosquat | Generate typosquat variants and report which ones actually resolve (phishing risk / defensive holds). |
| watchdog | Change Watchdog | watchdog | Continuous monitoring: new subdomains, new CVEs, surface drift. |

### Web3 (459)

| id | label | module | description |
|----|-------|--------|-------------|
| aa_validation_ungated | Aa Validation Ungated | deep_audit | Deep-audit detector for aa validation ungated: ERC-4337 validation without gates: a validateUserOp / validatePaymasterUserOp that the EntryPoint does not exclusively own and/or that performs no signature validation accepts every operation it is shown. An account validator like this lets anyone execute as the account through the real EntryPoint (full wallet drain); a paymaster validator like this lets anyone spend the paymaster's deposit on their own operations. Static verified-source analysis, fast lane, detection only. |
| access_control_arbitrary_call_injection | Access Control Arbitrary Call Injection (BSC) | bsc_common | BSC/BNB detector for access control arbitrary call injection: Arbitrary call injection: an ungated function makes an external call to a CALLER-SUPPLIED target (receiver expression is a function parameter), so anyone can make this contract call anything - including token contracts, where the call arrives with this contract's identity and balances behind it. Static verified-source analysis, fast lane, detection only. |
| access_control_hierarchical_privilege_leak | Access Control Hierarchical Privilege Leak (BSC) | bsc_common | BSC/BNB detector for access control hierarchical privilege leak: Hierarchical privilege leak: grantRole is authorized by membership in the VERY role being granted (hasRole(role, msg.sender)) instead of that role's admin role, so any holder of a role can mint unlimited new holders of it - the role hierarchy leaks sideways and revocation can never keep up. Static verified-source analysis, fast lane, detection only. |
| access_control_multi_sig_threshold_bypass | Access Control Multi Sig Threshold Bypass (BSC) | bsc_common | BSC/BNB detector for access control multi sig threshold bypass: Multisig threshold bypass: the multisig's execute path performs the call without ever comparing the approval count against the threshold, so a transaction confirmed by a single owner (or none) executes as if the full quorum had approved. Static verified-source analysis, fast lane, detection only. |
| access_control_ownership_renunciation_trap | Access Control Ownership Renunciation Trap (BSC) | bsc_common | BSC/BNB detector for access control ownership renunciation trap: Ownership renunciation trap: renounceOwnership sets the owner to the zero address while OTHER onlyOwner functions (withdraw / rescue / config) remain live. After renunciation those functions are unreachable forever - any funds or config they guard are permanently locked, a trap for buyers who read 'renounced' as 'safe'. Static verified-source analysis, fast lane, detection only. |
| access_control_role_revocation_hole | Access Control Role Revocation Hole (BSC) | bsc_common | BSC/BNB detector for access control role revocation hole: Role revocation hole: the contract can GRANT roles (grantRole / addMinter / addOperator surface exists) but has NO revocation path anywhere, so a compromised or rogue role holder can never be removed - incident response is impossible without redeploying. Static verified-source analysis, fast lane, detection only. |
| access_control_tx_origin_reliance | Access Control Tx Origin Reliance (BSC) | bsc_common | BSC/BNB detector for access control tx origin reliance: tx.origin authorization: the function authorizes on tx.origin, so any contract the privileged account is tricked into calling inherits its identity - the classic phishing primitive. Authorization must compare msg.sender (the immediate caller), never tx.origin. Static verified-source analysis, fast lane, detection only. |
| access_control_unprotected_initializer | Access Control Unprotected Initializer (BSC) | bsc_common | BSC/BNB detector for access control unprotected initializer: Unprotected initializer: a public initialize() sets owner/state with no initializer modifier and no gate, so the first stranger to call it (or anyone, if it can be re-called) owns the contract. This is the non-proxy form; proxy implementations are covered by the proxy module's detector. Static verified-source analysis, fast lane, detection only. |
| aml_chain_hop | AML: Chain-Hopping Indicators | aml_typologies | Flags rapid cross-chain movement setups: one document embedding two or more verified bridge router addresses inside a deposit/withdrawal flow (multi-bridge routing is the chain-hopping pattern), and content advertising instant cross-chain swaps with no account. |
| aml_giftcard_swap | AML: Gift Card Swap Indicators | aml_typologies | Flags the prepaid gift card typology: content offering to swap gift cards for crypto (the classic route for turning stolen or fraud-bought gift cards into clean funds) and references to gift-card-for-crypto services such as Bitrefill. |
| aml_mixer | AML: Mixer / Tumbler Exposure | aml_typologies | Flags exposure to known crypto mixers: the scan target IS a Tornado Cash mixer contract, its verified source hardcodes a mixer pool/router address, or its pages reference the mixer service. Detection only - the mixer is never contacted. |
| aml_mule_network | AML: Money Mule Recruitment Indicators | aml_typologies | Candidate-style detector for money-mule recruitment: a page only flags when THREE signal families co-occur - money movement (receive and forward funds), a commission for the middleman, and recruitment framing (work from home, payment processing agent, no experience needed). Ordinary job postings, which never combine all three, stay silent. Human review required. |
| aml_non_kyc_exchange | AML: No-Account Instant Exchange Exposure | aml_typologies | Flags integrations with known no-account / conditional-KYC instant swap exchanges (SideShift, Godex, StealthEX, FixedFloat, SimpleSwap, Exolix, ChangeNOW): referral links, API endpoints or widgets in served content (MEDIUM), or the service baked into contract source (HIGH). |
| aml_p2p_cash | AML: P2P Cash Trade Indicators | aml_typologies | Flags peer-to-peer cash-for-crypto routes: references to P2P platforms built around no-identification cash trades (Bisq, HodlHodl, Paxful) and cash-meetup language ('cash in person', 'cash by mail') alongside crypto context. |
| aml_shell_account | AML: Shell / Verified Account Resale Indicators | aml_typologies | Flags the shell-company exchange-account typology: offers to sell verified or aged corporate exchange accounts (HIGH - a KYC identity for hire), and company-formation packages bundled with nominee directors and exchange/crypto accounts (MEDIUM). |
| aml_xmr_conversion | AML: Monero Conversion Points | aml_typologies | Flags Monero conversion points on the target: checksum-valid XMR addresses in code or content, and instant-swap integrations advertising Monero. This flags the conversion POINT only - Monero transfers themselves are opaque by design, so nothing past the point can be scored from public data. |
| assembly_fmp_literal_corruption | Assembly Fmp Literal Corruption | deep_audit9 | Deep-audit detector (batch 9) for assembly fmp literal corruption: Free-memory-pointer corruption in inline assembly: mstore(0x40, <literal>) stores the literal 0 or a value below 0x80 to the free-memory pointer (0x40). That overwrites the allocator's next-free address with a pointer into reserved / scratch space, corrupting every subsequent allocation. This is the precision subset of system_assembly_memory_overwrite: a computed expression stored to 0x40 (the legitimate allocation update) does not fire. Static verified-source analysis, fast lane, detection only. |
| assembly_returndatacopy_unbounded | Assembly Returndatacopy Unbounded | deep_audit9 | Deep-audit detector (batch 9) for assembly returndatacopy unbounded: Unbounded returndatacopy in inline assembly: a function copies returndata with returndatacopy() without ever consulting returndatasize() in the same function, so the copy length is not derived from - or checked against - the actual returned size. A callee returning oversized data turns this into memory corruption or a gas grief (return bomb) against the caller. Static verified-source analysis, fast lane, detection only. |
| ast_visual_audit | AST Visual Audit (structure map + highlights) | ast_visual_audit | Headless rebuild of the Solidity Visual Auditor's analysis function (the extension itself runs only inside the VS Code editor): compiles the target's verified source with solc and emits the structural map an auditor reads first - inheritance tree, contract dependencies, per-function visibility/mutability/modifiers, state reads/writes, the external-interaction map, and per-contract metrics (functions, state vars, nSLOC, complexity; the Solidity Metrics function) - plus low-severity structural highlights (non-constant delegatecall targets, tx.origin, unchecked low-level calls, selfdestruct, inline assembly). Confirmed instances of those classes are reported at higher severity by contract_logic and the audit toolbox; this plugin is the map, not a second verdict. Keyless, read-only. |
| audit_toolbox | Audit Toolbox (Slither/Slitherin/Aderyn/Mythril/Wake/Securify/Semgrep/Solhint/SMT/Fuzz/APIs) | toolbox | Runs the standard auditor toolbox over a contract's verified source and bytecode: Slither (with Slitherin's extra detectors when installed) and Aderyn static analysis, Mythril symbolic execution, Wake detectors, Securify 2.0 pattern analysis, Semgrep Solidity rules, Solhint's security ruleset, solc SMTChecker, Heimdall bytecode disassembly, a Surya call graph, 4byte.directory selector identification for unverified bytecode, Echidna/Medusa property fuzzing (prepared harnesses only), plus GoPlus and Honeypot.is token-risk APIs. Heavy tools run only in the heavy lane (RECON_HEAVY_LANE / worker context); absent binaries skip silently - tools live outside the app image under ~/workspace/tools/audit. |
| auto_validator | Auto Validator | auto_validator | Machine validation of candidate findings: deep gate read, recipient classification, read-only stranger probes, balance reads and simulation results folded into VERIFIED_REAL / TRIGGER_ONLY / FALSE_POSITIVE / UNVERIFIED verdicts with evidence. |
| beacon_implementation_zero_accepted | Beacon Implementation Zero Accepted | deep_audit7 | Deep-audit detector (batch 7) for beacon implementation zero accepted: Beacon implementation setter accepts address(0): a beacon-context function assigns an address parameter to beacon / implementation storage with NO condition in the function requiring the parameter != address(0), so a zero implementation bricks every proxy reading the beacon. Static verified-source analysis, fast lane, detection only. |
| bep1155_batch_transfer_balance_mismatch | BEP-1155 Batch Transfer Balance Mismatch (BSC) | bsc_common | BSC/BNB detector for bep-1155 batch transfer balance mismatch: BEP-1155 batch balance mismatch: the batch transfer processes ids[] and amounts[] without ever checking the arrays have equal length. Mismatched arrays desync the per-id balance accounting (later ids silently skipped or read out of bounds) instead of reverting. Static verified-source analysis, fast lane, detection only. |
| bep20_allowance_double_spend | BEP-20 Allowance Double Spend (BSC) | bsc_common | BSC/BNB detector for bep-20 allowance double spend: Allowance double-spend (approve race): approve() overwrites a non-zero allowance directly, so a spender watching the mempool can spend the OLD allowance and then the NEW one. The safe BEP-20 shapes (require zero-first, or increase/decrease allowance) do not flag. Static verified-source analysis, fast lane, detection only. |
| bep20_arbitrary_minting_endpoints | BEP-20 Arbitrary Minting Endpoints (BSC) | bsc_common | BSC/BNB detector for bep-20 arbitrary minting endpoints: Arbitrary minting endpoint: a function whose name does NOT say mint (issue / airdrop / distribute / release shapes) increases the supply with NO access gate. These side-door mint endpoints are routinely missed by reviewers who only audit the function literally named mint(). Gated endpoints and the mint() function itself (covered by the generic ungated-mint lane) do not flag here. Static verified-source analysis, fast lane, detection only. |
| bep20_balance_of_side_effects | BEP-20 Balance Of Side Effects (BSC) | bsc_common | BSC/BNB detector for bep-20 balance of side effects: balanceOf side effects: balanceOf() is specified as a pure read, but this implementation WRITES state (or calls out) inside it. Wallets, DEXes and lending markets on BNB Chain read balanceOf inside larger operations; a mutating balanceOf desyncs their accounting and breaks the read-only assumption (it is also unusable from other contracts' view paths). Static verified-source analysis, fast lane, detection only. |
| bep20_blacklist_authority_check | BEP-20 Blacklist Authority Check (BSC) | bsc_common | BSC/BNB detector for bep-20 blacklist authority check: Blacklist authority: a blacklist/blocklist administration function performs the state write with NO access gate, so any stranger can blacklist arbitrary addresses (freezing their transfers on BNB Chain tokens that enforce the list in the transfer path). Properly owner/role-gated blacklist administration does not flag. Static verified-source analysis, fast lane, detection only. |
| bep20_burn_from_overflow | BEP-20 Burn From Overflow (BSC) | bsc_common | BSC/BNB detector for bep-20 burn from overflow: Burn-path underflow: a burn/burnFrom function subtracts from a balance (or the supply) with raw pre-0.8 / unchecked arithmetic and no balance bound checked first, so burning more than the balance wraps it to a huge number instead of reverting. Checked 0.8 math and SafeMath .sub do not flag. Static verified-source analysis, fast lane, detection only. |
| bep20_decimal_mismatch | BEP-20 Decimal Mismatch (BSC) | bsc_common | BSC/BNB detector for bep-20 decimal mismatch: Decimal mismatch: the token's decimals() disagrees with the scaling constants its own math uses, so amounts are off by orders of magnitude somewhere in the contract (a classic BNB Chain fork bug: the token is forked from an 18-decimal reference but issued with different decimals). Static verified-source analysis, fast lane, detection only. |
| bep20_fake_transfer_events | BEP-20 Fake Transfer Events (BSC) | bsc_common | BSC/BNB detector for bep-20 fake transfer events: Fake transfer events: transfer/transferFrom moves balances and returns true but never emits the Transfer event (and does not route through an internal _transfer that does). Indexers, exchanges and tax/accounting tooling on BNB Chain track tokens by Transfer logs; silent transfers make real movements invisible to them. Static verified-source analysis, fast lane, detection only. |
| bep20_mint_cap_bypass | BEP-20 Mint Cap Bypass (BSC) | bsc_common | BSC/BNB detector for bep-20 mint cap bypass: Mint cap bypass: the token declares a supply cap but NO code path ever compares the supply against it, so the cap is decorative - minting can blow straight past the advertised maximum on BNB Chain. (A cap variable alone is not a gate; enforcement has to compare, per the PR #78 adjudication.) Static verified-source analysis, fast lane, detection only. |
| bep20_owner_privilege_abuse | BEP-20 Owner Privilege Abuse (BSC) | bsc_common | BSC/BNB detector for bep-20 owner privilege abuse: Owner privilege abuse (seizure shape): an external entry point debits a balance that is NOT the caller's, with no allowance check anywhere in the function. Whoever can call it (an onlyOwner gate does NOT excuse this - it is the caller who receives) can move other holders' tokens at will: the canonical BNB Chain honeypot / rug shape. Legitimate transferFrom debits check the allowance and do not flag. Static verified-source analysis, fast lane, detection only. |
| bep20_transfer_fee_miscalculation | BEP-20 Transfer Fee Miscalculation (BSC) | bsc_common | BSC/BNB detector for bep-20 transfer fee miscalculation: Transfer-fee miscalculation: the transfer path computes a fee, credits the recipient the FULL amount, and ALSO credits the fee to a fee address. The fee is created out of nothing, so the sum of balances grows past totalSupply on every taxed transfer (BNB Chain fee tokens are the classic carrier of this bug). Static verified-source analysis, fast lane, detection only. |
| bep721_mint_index_overflow | BEP-721 Mint Index Overflow (BSC) | bsc_common | BSC/BNB detector for bep-721 mint index overflow: Mint index overflow: the token-id counter is incremented with raw pre-0.8 / unchecked arithmetic, so at the counter's ceiling the id wraps and the mint overwrites/collides with an existing token id instead of reverting. Static verified-source analysis, fast lane, detection only. |
| bep721_reentrancy_on_safe_mint | BEP-721 Reentrancy On Safe Mint (BSC) | bsc_common | BSC/BNB detector for bep-721 reentrancy on safe mint: Safe-mint reentrancy: _safeMint (which calls back into the receiver) executes BEFORE the mint's own state (id counter / supply / per-wallet count) is updated and there is no reentrancy guard, so a receiver contract can re-enter the mint during the callback and mint past per-wallet or supply limits. Static verified-source analysis, fast lane, detection only. |
| block_number_as_time | Block Number As Time | deep_audit9 | Deep-audit detector (batch 9) for block number as time: block.number used as a time proxy: block.number is combined with time semantics (multiplied or divided by a seconds-magnitude constant, stored into a time/deadline/expiry-named variable, or compared against a timestamp-magnitude literal). Block production is not a clock - block times vary by chain and by era, so durations, deadlines and expiries derived from block height drift or break outright. Static verified-source analysis, fast lane, detection only. |
| bridge | Bridge Security Scout | bridge | Detect bridge integrations and trust assumptions. |
| bridge_bytes_proof_length_unvalidated | Bridge Bytes Proof Length Unvalidated | deep_audit7 | Deep-audit detector (batch 7) for bridge bytes proof length unvalidated: Bridge proof blob length never validated: a caller-supplied bytes / bytes[] proof is passed to a verifier by a verify / claim / receive path and NO require, assert or if condition anywhere in the contract inspects that proof's .length. Batch 4 owns the bytes32[] Merkle shape; this is the opaque proof-blob shape (IAVL / ICS23 / relayed proofs) it never matches. Static verified-source analysis, fast lane, detection only. |
| bridge_deposit_event_spoofing | Bridge Deposit Event Spoofing (BSC) | bsc_common | BSC/BNB detector for bridge deposit event spoofing: Deposit event spoofing: this bridge-side credit function mints or releases assets on a deposit CLAIM with no validator signature, no merkle proof and no on-chain proof check of any kind in the function - anyone can assert a deposit that never happened on the other chain and be credited for it. Static verified-source analysis, fast lane, detection only. |
| bridge_digest_no_destination_chain | Bridge Digest No Destination Chain | deep_audit7 | Deep-audit detector (batch 7) for bridge digest no destination chain: Bridge digest omits the destination chain: the keccak256 digest construction binds source chain / origin sender / nonce but contains NO destination-chain term and no generic chain-id term at all, so a message valid for one destination chain can be replayed on any other chain running the same verifier. Static verified-source analysis, fast lane, detection only. |
| bridge_emergency_pause_lockup | Bridge Emergency Pause Lockup (BSC) | bsc_common | BSC/BNB detector for bridge emergency pause lockup: Emergency pause lockup: pause() flips the paused state with NO access gate while user funds exit through whenNotPaused paths - any stranger can freeze every withdrawal on the contract at any time, for as long as they keep re-pausing after an unpause. Static verified-source analysis, fast lane, detection only. |
| bridge_message_payload_injection | Bridge Message Payload Injection (BSC) | bsc_common | BSC/BNB detector for bridge message payload injection: Bridge message payload injection: the message executor calls a target taken from the message / call parameters with no validator verification in the path, so a forged 'message' makes the bridge execute arbitrary calls with the bridge's own identity and balances. Static verified-source analysis, fast lane, detection only. |
| bridge_mint_burn_gate_asymmetry | Bridge Mint Burn Gate Asymmetry | deep_audit7 | Deep-audit detector (batch 7) for bridge mint burn gate asymmetry: Bridge mint / burn gate asymmetry: the contract has both a mint-side (mint / bridgeMint / release / unlock) and a burn-side (burn / lock) function and their caller gates differ - one side is caller-gated and the other is not. The ungated side is the weak link: anyone can drive it while its counterpart was considered sensitive enough to gate. Static verified-source analysis, fast lane, detection only. |
| bridge_native_gas_drain | Bridge Native Gas Drain (BSC) | bsc_common | BSC/BNB detector for bridge native gas drain: Native gas drain: the relayer 'gas refund' / fee is paid to msg.sender in an amount taken from the call/message parameters, with no gas-price derivation and no cap - anyone can name the refund and drain the bridge's native balance fee by fee. Static verified-source analysis, fast lane, detection only. |
| bridge_nonce_order_unenforced | Bridge Nonce Order Unenforced | deep_audit7 | Deep-audit detector (batch 7) for bridge nonce order unenforced: Bridge nonce ordering never enforced: the receive path stores an incoming nonce and the contract keeps a sequential counter (next / expected / last / inbound nonce), but NO condition anywhere compares the incoming nonce against that counter, so cross-chain messages can execute out of sequence - breaking protocols whose messages are order-dependent. Static verified-source analysis, fast lane, detection only. |
| bridge_payload_slice_unbounded | Bridge Payload Slice Unbounded | deep_audit7 | Deep-audit detector (batch 7) for bridge payload slice unbounded: Cross-chain payload sliced without a length check: a message-execution function directly indexes, slices or assembly-reads a bytes payload parameter and NO condition in the function inspects payload.length, so a short / malformed payload reverts unpredictably or is misparsed into attacker-chosen fields. Static verified-source analysis, fast lane, detection only. |
| bridge_proof_length_unvalidated | Bridge Proof Length Unvalidated | deep_audit4 | Deep-audit detector (batch 4) for bridge proof length unvalidated: Bridge Merkle proof length never validated: a caller-supplied bytes32[] proof is consumed by the verify / claim path and NO require, assert or if condition anywhere in the contract compares the proof's length against an expected depth or any bound. Proof length is part of the statement being proven (leaf position and tree shape derive from it); accepting arbitrary-length proofs lets a caller replay proofs across trees of different depths and probe the verifier with shapes the bridge never committed to. Static verified-source analysis, fast lane, detection only. |
| bridge_proof_nullifier_missing | Bridge Proof Nullifier Missing | deep_audit7 | Deep-audit detector (batch 7) for bridge proof nullifier missing: Proof accepted with no nullifier recording: a proof verifier's success gates a mint / release / transfer, and the function records NOTHING keyed by the proof or its public inputs - no nullifier, spent, used-proof or processed marker - so the same valid proof can be submitted again and again for repeated payouts. Static verified-source analysis, fast lane, detection only. |
| bridge_receiver_sender_unchecked | Bridge Receiver Sender Unchecked | deep_audit7 | Deep-audit detector (batch 7) for bridge receiver sender unchecked: Cross-chain receiver never checks msg.sender: the receive / execute handler performs proof or signature verification or state execution but contains NO msg.sender comparison anywhere, so any account can invoke the handler directly instead of only the authorized endpoint / relayer / messenger being able to deliver. Static verified-source analysis, fast lane, detection only. |
| bridge_replay_unbound_digest | Bridge Replay Unbound Digest | deep_audit2 | Deep-audit detector (batch 2) for bridge replay unbound digest: Bridge message replay (unbound digest): the executor verifies a signature / proof over a message digest that does not bind the full message identity - the source chain id, the origin sender and/or a nonce is missing from the hashed inputs - so the same proven message can be replayed on another chain, attributed to another sender, or executed again wherever the executed marker is keyed on the same under-bound digest. Verification being present is exactly what keeps generic payload-injection detectors silent here. Static verified-source analysis, fast lane, detection only. |
| bridge_root_zero_assertion | Bridge Root Zero Assertion | deep_audit4 | Deep-audit detector (batch 4) for bridge root zero assertion: Mute root assertion: a validation condition asserts the Merkle/root variable EQUALS the zero hash. As a gate in a verify / claim path that check passes exactly when NO root is committed, so it validates nothing - a proof checked under it is checked against an unset root. (The one-shot setter guard, require(root == 0) in the function that first assigns that root, is the legitimate shape and does not fire.) Static verified-source analysis, fast lane, detection only. |
| bridge_static_gas_limit | Bridge Static Gas Limit | deep_audit7 | Deep-audit detector (batch 7) for bridge static gas limit: Static gas limit on a cross-chain dispatch: the gas forwarded to the destination is a numeric literal, a constant, or a state variable with a literal initializer, carried via a gasLimit: / gas: field. Destination execution costs change with payload and chain conditions, so a frozen limit strands messages (out-of-gas on delivery) or overpays permanently. Static verified-source analysis, fast lane, detection only. |
| bridge_validator_quorum_manipulation | Bridge Validator Quorum Manipulation (BSC) | bsc_common | BSC/BNB detector for bridge validator quorum manipulation: Validator quorum manipulation: validator signatures are COUNTED (ecrecover in a loop) but signers are never deduplicated and the count is never compared against a real quorum - the same validator signing repeatedly (or a threshold of one signature) satisfies the 'quorum', so one compromised or rogue validator is the whole bridge. Static verified-source analysis, fast lane, detection only. |
| bridge_withdrawer_identity_spoof | Bridge Withdrawer Identity Spoof (BSC) | bsc_common | BSC/BNB detector for bridge withdrawer identity spoof: Withdrawer identity spoof: the bridge release pays a recipient taken straight from the call parameters, and the recipient is not bound to any deposit record or signed message hash in the function - whoever submits the withdrawal names the payee, so a watcher can redirect other users' releases to themselves. Static verified-source analysis, fast lane, detection only. |
| bridge_wrapped_token_mint_unbacked | Bridge Wrapped Token Mint Unbacked (BSC) | bsc_common | BSC/BNB detector for bridge wrapped token mint unbacked: Unbacked wrapped-token mint: this wrapped / bridge token's mint has NO bridge-role gate, so anyone can mint the wrapped asset without any corresponding lock or burn on the origin chain - instant unbacked supply. Static verified-source analysis, fast lane, detection only. |
| bytecode_deep_analysis | Bytecode Deep Analysis (Deep) | deep_layers | Deep bytecode lane for contracts with NO verified source: pure-Python disassembly (PUSH4 selectors + DELEGATECALL/SELFDESTRUCT/CALL opcode scan), dangerous-selector findings at labeled lower confidence with recipient classification or UNRESOLVED + the missing piece named. Heimdall availability is reported, never faked. |
| candidate_confirmation_queue | Candidate Confirmation Queue (Deep, Heavy Lane) | deep_layers | HEAVY lane only. Consumes candidates published on the run bus (deep_candidates / candidates / sim_candidates / fuzz_candidates dicts with source) and reclassifies each with Slither via the audit-toolbox lane: tool-confirmed pattern / trigger-only / false-positive / unconfirmed (tool unavailable - reason named, never silently confirmed). Storage synergy and step paths are attached; tool output never becomes a live VERIFIED verdict (no-simulation rule). |
| chain_enrich | Multi-chain OSINT | chain_enrich | Keyless balance/activity enrichment for discovered Bitcoin, Litecoin, Dogecoin, BCH, Dash, Zcash, Tron, XRP and Solana addresses, plus public address labels (exchange/mixer/bridge/sanctioned/burn) on every address. Read-only public-explorer data. |
| chain_osint | Blockchain OSINT | chain_osint | Chain enrichment for discovered addresses: keyless Blockchair balances/activity + Sourcify verified-source checks always run; ETHERSCAN_API_KEY (optional) adds full tx history and counterparties. Read-only. |
| chainlink_price_unbounded | Chainlink Price Unbounded | deep_audit6 | Deep-audit detector (batch 6) for chainlink price unbounded: Oracle price consumed with no sanity bounds: a function takes the price from latestRoundData() into arithmetic / a transfer decision / a return, and no condition anywhere in the contract compares that price against a literal bound or a MIN / MAX bound variable - there is no de-peg / circuit-breaker check. A malfunctioning, stale-but-fresh-looking or manipulated feed can print any value and every consumer downstream takes it at face value. Static verified-source analysis, fast lane, detection only. |
| coinbase_decision_input | Coinbase Decision Input | deep_audit9 | Deep-audit detector (batch 9) for coinbase decision input: block.coinbase used as a decision input: the block proposer's address feeds a condition, a hash, a payee/winner selection, or a non-payee state variable. Post-merge, coinbase is the proposer / fee recipient chosen by the block builder, so logic keyed on it is miner/builder-influenceable and semantically unstable. Paying coinbase directly (the tip shape) does not fire. Static verified-source analysis, fast lane, detection only. |
| contract_audit | Contract Static Auditor | contract_audit | Static analysis of verified contract source: reentrancy, access control, tx.origin, unchecked calls, overflow. Keyless Sourcify source always tried; ETHERSCAN_API_KEY (optional) adds Etherscan coverage. Never interacts with contracts. |
| contract_fuzz | Contract Fuzz Lane (Local Exploit Confirmation) | contract_fuzz | HEAVY LANE ONLY. Local exploit-confirmation fuzzing of ONE flagged contract: the verified source is scoped (bundle split, test/mock units dropped), compiled with a local solc, and deployed inside an Echidna harness where a HOUSE actor deploys it (holding every constructor deployer role) and seeds it with mock ETH, while an unauthenticated STRANGER (the harness) fuzz-calls every public state-changing function under per-call balance accounting. Only a falsified no-stranger-profit property (ETH or self-token) is reported, as fuzz_confirmed with Echidna's shrunk counterexample and recipient CALLER; everything else is a low-severity fuzz_inconclusive note with a machine reason (compile fail, constructor args, timeout, engine absent). Runs only in an explicitly marked heavy context under the RECON_HEAVY_TIMEOUT ceiling; refuses bulk sweeps. Local VM only - no transactions, no live chain calls beyond keyless source fetch. |
| contract_logic | Smart Contract Logic Analyzer | contract_logic | Analyzes a contract's LOGIC, not just its surface: reentrancy (external call before the state update, plus cross-function hints), integer overflow/underflow (pre-0.8 unchecked arithmetic without SafeMath, >=0.8 unchecked{} blocks and assembly arithmetic on balances), and access-control flaws (ungated sensitive functions that perform the action, tx.origin authorization, unprotected initialize(), arbitrary delegatecall). Same false-positive discipline as the drain analyzer; guarded, gated, CEI-ordered, internal and view/pure code stays silent. With no verified source, falls back to a low-confidence bytecode opcode heuristic, clearly labeled as such. When the target is a proxy, the implementation behind it is analyzed too. Read-only, never interacts with contracts. |
| contract_recon | Smart Contract Recon | contract_recon | Pulls a contract's code from public chain data (Ethereum, BNB Chain, Polygon, Arbitrum, Base, Optimism) and shows it as findings: privileged functions, proxy pattern, dangerous code, secrets - plus bytecode analysis when source is unverified. When the target is a proxy, the implementation behind it is resolved and analyzed too, with findings tagged by which contract they came from. Read-only, never interacts with contracts. |
| contract_simulation | Contract Simulation (Fuzz + Symbolic) | contract_sim | HEAVY LANE ONLY. Read-only on-chain SIMULATION of one explicitly targeted or static-lane-flagged contract: boundary-input eth_call fuzzing of its public state-changing functions, cross-checked against the access gate its verified source implies, plus optional external Mythril symbolic execution behind RECON_SIM_SYMBOLIC=1. Runs only in an explicitly marked heavy-lane context under the RECON_HEAVY_TIMEOUT budget (default 120s, cap 300s); from the default/fast request path it returns an info note immediately. Flags are candidates for human review, never verdicts. Refuses bulk sweeps outright. Keyless: Blockscout/Sourcify source, eth_call only - no transactions, no funded key, no local node, no state changes. |
| cp_ada_addr | Cardano Address (Bech32-verified) | cryptopack_addr | Shelley-era Cardano addr1/stake1 Bech32 addresses. |
| cp_akash_addr | Akash (AKT) Address (Bech32-verified) | cryptopack_addr2 | akash1 Bech32 addresses with verified checksum. |
| cp_algo_addr | Algorand Address (checksum-verified) | cryptopack_addr | Algorand addresses with verified SHA-512/256 checksum. |
| cp_apikey_alchemy | Leaked Alchemy API key | cryptopack_secrets | Alchemy API keys embedded in RPC URLs or assignments. |
| cp_apikey_ankr | Leaked Ankr endpoint token | cryptopack_secrets2 | Ankr infrastructure credentials/endpoints in served content. |
| cp_apikey_binance | Leaked Binance API key | cryptopack_secrets | Binance API credentials in served content. |
| cp_apikey_bingx | Leaked BingX API key | cryptopack_secrets2 | BingX API credentials in served content. |
| cp_apikey_bitfinex | Leaked Bitfinex API key | cryptopack_secrets2 | Bitfinex API credentials in served content. |
| cp_apikey_bitstamp | Leaked Bitstamp API key | cryptopack_secrets2 | Bitstamp API credentials in served content. |
| cp_apikey_blockdaemon | Leaked Blockdaemon API key | cryptopack_secrets2 | Blockdaemon infrastructure credentials/endpoints in served content. |
| cp_apikey_bybit | Leaked Bybit API key | cryptopack_secrets | Bybit API credentials in served content. |
| cp_apikey_chainstack | Leaked Chainstack endpoint/key | cryptopack_secrets2 | Chainstack infrastructure credentials/endpoints in served content. |
| cp_apikey_coinbase | Leaked Coinbase API key | cryptopack_secrets | Coinbase API credentials in served content. |
| cp_apikey_deribit | Leaked Deribit API credentials | cryptopack_secrets2 | Deribit API credentials in served content. |
| cp_apikey_etherscan | Leaked explorer API key (Etherscan family) | cryptopack_secrets | Etherscan/BscScan/PolygonScan/Snowtrace API keys in URLs or assignments in served content. |
| cp_apikey_gateio | Leaked Gate.io API key | cryptopack_secrets2 | Gate.io API credentials in served content. |
| cp_apikey_gemini | Leaked Gemini API key | cryptopack_secrets2 | Gemini API credentials in served content. |
| cp_apikey_htx | Leaked HTX (Huobi) API key | cryptopack_secrets2 | HTX API credentials in served content. |
| cp_apikey_infstones | Leaked InfStones API key | cryptopack_secrets2 | InfStones infrastructure credentials/endpoints in served content. |
| cp_apikey_infura | Leaked Infura project key | cryptopack_secrets | Infura RPC project IDs/secrets embedded in served content. |
| cp_apikey_kraken | Leaked Kraken API key | cryptopack_secrets | Kraken API credentials in served content. |
| cp_apikey_kucoin | Leaked KuCoin API key | cryptopack_secrets | KuCoin API credentials in served content. |
| cp_apikey_mexc | Leaked MEXC API key | cryptopack_secrets2 | MEXC API credentials in served content. |
| cp_apikey_moralis | Leaked Moralis API key | cryptopack_secrets | Moralis API credentials in served content. |
| cp_apikey_okx | Leaked OKX API key | cryptopack_secrets | OKX API credentials in served content. |
| cp_apikey_quicknode | Leaked QuickNode endpoint token | cryptopack_secrets | QuickNode RPC endpoints with embedded auth tokens. |
| cp_apikey_tenderly | Leaked Tenderly access token | cryptopack_secrets2 | Tenderly infrastructure credentials/endpoints in served content. |
| cp_aptos_addr | Aptos Address (context-anchored) | cryptopack_addr | 0x 64-hex Aptos addresses anchored to Aptos context. |
| cp_atom_addr | Cosmos Hub Address (Bech32-verified) | cryptopack_addr | cosmos1 Bech32 addresses with verified checksum. |
| cp_avax_addr | Avalanche X-Chain Address (Bech32-verified) | cryptopack_addr2 | avax1 Bech32 addresses with verified checksum. |
| cp_bch_addr | Bitcoin Cash Address (cashaddr-verified) | cryptopack_addr | Cashaddr-format BCH addresses with verified polymod checksum. |
| cp_bnb_addr | BNB Beacon Chain Address (Bech32-verified) | cryptopack_addr | bnb1 Bech32 addresses with verified checksum. |
| cp_brc20_refs | BRC-20 Token References | cryptopack_addr2 | BRC-20 deploy/mint/transfer JSON blobs and ticker references in the target's content. |
| cp_btc_bech32 | Bitcoin SegWit Address (BIP-173 verified) | cryptopack_addr | Bech32 checksum-verified native SegWit (bc1q) addresses. |
| cp_btc_legacy | Bitcoin Legacy Address (checksum-verified) | cryptopack_addr | Base58Check-verified Bitcoin P2PKH/P2SH addresses (1.../3...) published by the target. |
| cp_btc_taproot | Bitcoin Taproot Address (BIP-350 verified) | cryptopack_addr | Bech32m checksum-verified Taproot (bc1p) addresses. |
| cp_btc_testnet | Bitcoin Testnet Address | cryptopack_addr | Testnet addresses (tb1/m/n/2) on a production site: a test/prod mixup signal worth flagging. |
| cp_celo_addr | Celo (CELO) Address (context-anchored) | cryptopack_addr2 | 0x addresses anchored to Celo (CELO) context - the EVM address shape is shared across chains, so attribution comes from the surrounding text. |
| cp_clipboard_copy_swap | Clipboard hijacker: copy-event address swap | cryptopack_phish | JS listening for copy events and rewriting clipboard text with address-shaped replacements - the classic address-swapper trojan pattern. |
| cp_clipboard_paste_swap | Clipboard hijacker: paste/input address rewrite | cryptopack_phish | JS intercepting paste/input on address fields and substituting a different address-shaped value. |
| cp_cro_addr | Crypto.org Chain (CRO) Address (Bech32-verified) | cryptopack_addr2 | cro1 Bech32 addresses with verified checksum. |
| cp_dash_addr | Dash Address (checksum-verified) | cryptopack_addr | Base58Check-verified Dash addresses (X.../7...). |
| cp_dgb_addr | DigiByte SegWit Address (BIP-173 verified) | cryptopack_addr2 | dgb1 native SegWit addresses. (DigiByte legacy Base58Check shares Dogecoin's 0x1E version byte, so legacy forms are not attributed.) |
| cp_dns_bip353 | DNS: BIP-353 payment instructions | cryptopack_dns | BIP-353 ₿ DNS payment instructions under _bitcoin-payment: BOLT12 offers / Lightning addresses bound to the domain. |
| cp_dns_crypto_cnames | DNS: CNAMEs to hosted crypto services | cryptopack_dns | CNAME records delegating the domain (or www/pay/checkout subdomains) to hosted crypto payment services - the target's payment surface lives on someone else's infrastructure. |
| cp_dns_openalias | DNS: OpenAlias payment records | cryptopack_dns | OpenAlias (oa1:) TXT records: human-readable crypto payment addresses bound to the domain, per chain (xmr/btc/eth/...). |
| cp_doge_validated | Dogecoin Address (checksum-verified) | cryptopack_addr | Base58Check-verified Dogecoin addresses (D.../9.../A...). |
| cp_dot_addr | Polkadot/Kusama Address (SS58-verified) | cryptopack_addr | SS58 addresses with verified Blake2 checksum (formats 0/2). |
| cp_drainer_angel | Drainer kit: Angel Drainer | cryptopack_phish2 | Angel Drainer drainer-as-a-service kit signatures (loader strings, config names, brand marks) in the target's served content. |
| cp_drainer_claim_kit | Phishing: fake airdrop / claim kit | cryptopack_phish | 'Claim your airdrop/reward' lures wired to a wallet connect + approval flow - the dominant drainer funnel. |
| cp_drainer_ethsign | Drainer pattern: eth_sign bait | cryptopack_phish | JS requesting eth_sign / blind personal_sign with 'verify your wallet' framing - signs arbitrary payloads the user cannot read. |
| cp_drainer_inferno | Drainer kit: Inferno Drainer | cryptopack_phish2 | Inferno Drainer drainer-as-a-service kit signatures (loader strings, config names, brand marks) in the target's served content. |
| cp_drainer_ms | Drainer kit: MS / Monkey Drainer | cryptopack_phish2 | MS / Monkey Drainer drainer-as-a-service kit signatures (loader strings, config names, brand marks) in the target's served content. |
| cp_drainer_permit | Drainer pattern: permit signature bait | cryptopack_phish | EIP-2612/Permit2 signature flows in JS (permit, PermitSingle, signTypedData with Permit types) - gasless approval theft's building blocks. |
| cp_drainer_permit2 | Drainer pattern: Permit2 approval bait | cryptopack_phish2 | Permit2-specific signature bait: the canonical Permit2 contract, SignatureTransfer and witness permit flows - one signature can authorize unlimited token movement, which is why drainers standardized on it. |
| cp_drainer_pink | Drainer kit: Pink Drainer | cryptopack_phish2 | Pink Drainer drainer-as-a-service kit signatures (loader strings, config names, brand marks) in the target's served content. |
| cp_drainer_seedform | Phishing: seed phrase harvest form | cryptopack_phish | Forms asking for a seed/recovery phrase or mnemonic - no legitimate service ever does this in a browser. |
| cp_drainer_setapproval | Drainer pattern: setApprovalForAll bait | cryptopack_phish | JS invoking setApprovalForAll - the one-call NFT drain primitive. Legit marketplaces use it too, so this inventories rather than accuses. |
| cp_drainer_walletconnect_kit | Phishing: fake WalletConnect / wallet modal kit | cryptopack_phish | Wallet-connect modal clones that fall back to asking for a seed phrase or private key - the standard drainer-kit tell. |
| cp_ens_name | ENS Name | cryptopack_names | Ethereum Name Service names (*.eth) published by the target. |
| cp_eos_key | EOSIO Public Key (RIPEMD-160 verified) | cryptopack_addr2 | EOSIO account public keys (legacy EOS... and PUB_K1_/PUB_R1_ forms) with verified RIPEMD-160 checksum - the keys controlling EOSIO accounts the target publishes. |
| cp_erc1155_contracts | ERC-1155 Contract Inventory | cryptopack_addr2 | Contract addresses anchored specifically to ERC-1155 context. |
| cp_erc721_contracts | ERC-721 Contract Inventory | cryptopack_addr2 | Contract addresses anchored specifically to ERC-721 context (wave 1 lumped 721/1155 together). |
| cp_ergo_addr | Ergo Address (Blake2b checksum-verified) | cryptopack_addr2 | Ergo P2PK addresses verified against their Blake2b-256 checksum (type byte + compressed key). |
| cp_eth_eip55 | Ethereum Address (EIP-55 checksum state) | cryptopack_addr | 0x addresses with EIP-55 checksum classification: checksummed addresses are reported at high confidence; a mixed-case address with a BROKEN checksum is likely a typo that burns funds. |
| cp_evmos_addr | Evmos (EVMOS) Address (Bech32-verified) | cryptopack_addr2 | evmos1 Bech32 addresses with verified checksum. |
| cp_fetch_addr | Fetch.ai (FET) Address (Bech32-verified) | cryptopack_addr2 | fetch1 Bech32 addresses with verified checksum. |
| cp_ftm_addr | Fantom (FTM) Address (context-anchored) | cryptopack_addr2 | 0x addresses anchored to Fantom (FTM) context - the EVM address shape is shared across chains, so attribution comes from the surrounding text. |
| cp_hbar_addr | Hedera Account ID (context-anchored) | cryptopack_addr2 | Hedera account IDs (0.0.NNNN) - the dotted form is only reported with Hedera/HBAR context nearby. |
| cp_hns_addr | Handshake Address (Bech32-verified) | cryptopack_addr2 | Handshake (hs1) SegWit-style Bech32 addresses. |
| cp_inj_addr | Injective Address (Bech32-verified) | cryptopack_addr | inj1 Bech32 addresses with verified checksum. |
| cp_ipfs_cid | IPFS Content ID (crypto context) | cryptopack_names | IPFS CIDs referenced with NFT/token context - the actual asset storage behind the target's Web3 claims. |
| cp_juno_addr | Juno (JUNO) Address (Bech32-verified) | cryptopack_addr2 | juno1 Bech32 addresses with verified checksum. |
| cp_kas_addr | Kaspa Address (checksum-verified) | cryptopack_addr | kaspa: addresses with verified cashaddr-family checksum. |
| cp_kas_testnet_addr | Kaspa Testnet Address (checksum-verified) | cryptopack_addr2 | kaspatest: addresses on a production site - a test/prod mixup signal, like BTC testnet in wave 1. |
| cp_kava_addr | Kava (KAVA) Address (Bech32-verified) | cryptopack_addr2 | kava1 Bech32 addresses with verified checksum. |
| cp_kuji_addr | Kujira (KUJI) Address (Bech32-verified) | cryptopack_addr2 | kuji1 Bech32 addresses with verified checksum. |
| cp_lightning_address | Lightning Address | cryptopack_names | Lightning Addresses (user@domain) - email-shaped, so they are only reported in Lightning context. |
| cp_lightning_invoice | Lightning Invoice (BOLT11 verified) | cryptopack_names | BOLT11 Lightning invoices with verified Bech32 checksum - live payment requests the target publishes. |
| cp_lnurl | LNURL (Bech32-verified) | cryptopack_names | LNURL bech32 strings (Lightning payment/withdraw links). |
| cp_ltc_validated | Litecoin Address (checksum-verified) | cryptopack_addr | Base58Check (L/M/ltc1) and Bech32-verified Litecoin addresses. |
| cp_miner_authedmine | Cryptojacking: AuthedMine | cryptopack_miners | AuthedMine opt-in CoinHive variant (authedmine.com loader/API). |
| cp_miner_binary_links | Miner binary / release links | cryptopack_pay | Download links for miner software releases (xmrig, gminer, lolMiner, T-Rex, NBMiner, SRBMiner, TeamRedMiner) hosted or referenced by the target. |
| cp_miner_coinhive | Cryptojacking: CoinHive | cryptopack_miners | CoinHive in-browser Monero miner (coinhive.com loader, CoinHive.Anonymous API, site-key start call). |
| cp_miner_coinimp | Cryptojacking: CoinImp | cryptopack_miners | CoinImp miner (coinimp.com loader, Client.Anonymous API). |
| cp_miner_coinnebula | Cryptojacking: CoinNebula | cryptopack_miners | CoinNebula miner (coinnebula.com loader, CoinNebula API). |
| cp_miner_config_exposure | Exposed miner configuration (xmrig-style) | cryptopack_pay | xmrig-format miner config in served content: algorithm + pool URL + wallet user together are a working mining operation, whoever planted it. |
| cp_miner_config_wallet | Exposed miner config with payout wallet | cryptopack_miners2 | xmrig-style config bodies whose pools array carries a stratum URL and a wallet 'user' - a complete mining operation, payout address included. The wallet is checksum-verified where the chain has one. |
| cp_miner_cryptoloot | Cryptojacking: CryptoLoot | cryptopack_miners | CryptoLoot miner (crypto-loot.org loader, CryptoLoot.Anonymous). |
| cp_miner_dashboard_refs | Miner dashboard / fleet management references | cryptopack_miners2 | Mining fleet dashboards (Hive OS, minerstat) and XMRig HTTP API references in the target's content - signs of an operated mining setup, legit or otherwise. |
| cp_miner_deepminer | Cryptojacking: DeepMiner | cryptopack_miners2 | DeepMiner web miner (deepminer / deepminer.net loader). |
| cp_miner_jsecoin | Cryptojacking: JSEcoin | cryptopack_miners | JSEcoin platform miner (jsecoin.com loader / JSEmining API). |
| cp_miner_mineralt | Cryptojacking: Mineralt | cryptopack_miners | Mineralt miner network (mineralt.io loader, Minero API). |
| cp_miner_minero | Cryptojacking: Minero | cryptopack_miners2 | Minero web miner network (minero.cc loader, Minero.User API). |
| cp_miner_moneroocean | Cryptojacking: MoneroOcean web miner | cryptopack_miners | MoneroOcean pool web miner (moneroocean.stream miner script). |
| cp_miner_stratum_endpoints | Mining Pool Stratum Endpoints | cryptopack_miners | Stratum mining endpoints referenced by the target (stratum+tcp/ssl/ws URLs): pool infrastructure the target's mining - or its compromises - talk to. |
| cp_miner_wasm_cryptonight | Cryptojacking: CryptoNight WASM miner (generic) | cryptopack_miners | Generic WASM CryptoNight miner artifacts: cryptonight wasm modules plus worker bootstrap strings no legitimate library ships. |
| cp_miner_webminepool | Cryptojacking: WebMinePool | cryptopack_miners | WebMinePool miner (webminepool.com loader, WMP.Anonymous API). |
| cp_miner_webminerpool | Cryptojacking: WebMinerPool | cryptopack_miners2 | WebMinerPool open-source web miner (webminerpool.com loader / WMP-style globals distinct from WebMinePool). |
| cp_miner_xmrig_proxy | Mining: XMRig proxy | cryptopack_miners2 | XMRig stratum proxy signatures - the aggregation layer mining botnets put between compromised miners and the pool. |
| cp_miner_xmrig_web | Cryptojacking: XMRig web port | cryptopack_miners | XMRig compiled/ported for the browser (xmrig wasm workers, startXmrig-style bootstraps in JS). |
| cp_near_addr | NEAR Account ID | cryptopack_addr | Named NEAR accounts (*.near / *.testnet) published by the target. |
| cp_near_implicit_addr | NEAR Implicit Account (64-hex) | cryptopack_addr2 | NEAR implicit accounts are a bare 64-char lowercase hex string (the public key itself) - only reported with NEAR context nearby. |
| cp_node_bitcoind_rpc | Bitcoin Core RPC exposure references | cryptopack_nodes | Credentialed bitcoind RPC URLs and bitcoin-cli references in served content - the keys to the node kingdom if the port is reachable. |
| cp_node_btcpay_config | BTCPay Server config/backup artifacts | cryptopack_nodes | BTCPay Server database and config artifacts (BTCPayServer.db, NBXplorer settings, backup filenames) referenced in served content - the store's payment configuration, and often its xpubs, in one file. |
| cp_node_devnode_refs | Dev node endpoints in production (Ganache/Hardhat) | cryptopack_nodes | Local dev-node endpoints (localhost:8545/7545) and Ganache/Hardhat node references shipped to production - environment bleed that maps the target's dev setup and breaks or exposes flows. |
| cp_node_electrum_server | Electrum server references | cryptopack_nodes | Electrum server endpoints (electrum://, :50002 SSL stratum, ElectrumX) the target's wallet infrastructure depends on - a malicious or compromised server lies to every wallet using it. |
| cp_node_hardhat_accounts | Known Hardhat test accounts in production | cryptopack_nodes | The deterministic Hardhat/Anvil test accounts (publicly known private keys) appearing in production content - test wallets treated as real ones; anything sent to them is gone. |
| cp_node_near_rpc | NEAR / Avalanche RPC endpoint references | cryptopack_nodes | NEAR RPC endpoints and Avalanche C-Chain custom RPC paths - chain infrastructure wave 1's host inventory did not carry. |
| cp_node_rpc_creds | RPC URLs with embedded credentials | cryptopack_nodes | Web3 RPC URLs carrying userinfo credentials (https://user:pass@node...) in served content - authenticated node access, leaked. |
| cp_nostr_pubkey | Nostr Public Key (npub) | cryptopack_names | Nostr npub identifiers (Bech32-verified) published by the target. |
| cp_onion_service | Tor Onion Service (crypto context) | cryptopack_names | v3 onion services referenced near crypto/payment keywords - the target's darknet payment/support door. |
| cp_ordinals_inscriptions | Ordinals Inscription References | cryptopack_addr2 | Bitcoin Ordinals inscription IDs (<txid>i<n>) and explorer links the target publishes. |
| cp_osmo_addr | Osmosis Address (Bech32-verified) | cryptopack_addr | osmo1 Bech32 addresses with verified checksum. |
| cp_pay_bitpay | Payment rail: BitPay | cryptopack_pay | BitPay invoice/checkout links. |
| cp_pay_blockonomics | Payment rail: Blockonomics | cryptopack_pay | Blockonomics payment links/widgets. |
| cp_pay_btcpay | Payment rail: BTCPay Server | cryptopack_pay | BTCPay Server checkout/invoice endpoints the target uses. |
| cp_pay_coinbase_commerce | Payment rail: Coinbase Commerce | cryptopack_pay | Coinbase Commerce hosted charge links. |
| cp_pay_coingate | Payment rail: CoinGate | cryptopack_pay | CoinGate payment buttons/order endpoints. |
| cp_pay_coinpayments | Payment rail: CoinPayments | cryptopack_pay | CoinPayments checkout buttons/links. |
| cp_pay_cryptocom_pay | Payment rail: Crypto.com Pay | cryptopack_pay | Crypto.com Pay checkout references. |
| cp_pay_nowpayments | Payment rail: NOWPayments | cryptopack_pay | NOWPayments payment links/widgets. |
| cp_pay_opennode | Payment rail: OpenNode | cryptopack_pay | OpenNode Lightning/BTC checkout links. |
| cp_payment_uri | Crypto Payment URI (BIP-21 style) | cryptopack_names | bitcoin:/litecoin:/ethereum: payment URIs - the click-to-pay form of a wallet address, often with amount and label parameters worth inventorying. |
| cp_persistence_addr | Persistence (XPRT) Address (Bech32-verified) | cryptopack_addr2 | persistence1 Bech32 addresses with verified checksum. |
| cp_phish_eligibility_scam | Phishing: fake airdrop eligibility checker | cryptopack_phish2 | 'Check your eligibility' funnels wired to a wallet connect - the current dominant airdrop scam shape (the check is fake; the approval is real). |
| cp_phish_fake_exchange | Phishing: fake exchange login | cryptopack_phish | Exchange-brand login/verification pages (Binance, Coinbase, Kraken, KuCoin) served off-brand - credential + 2FA harvest kits. |
| cp_phish_fake_metamask | Phishing: fake MetaMask UI | cryptopack_phish | MetaMask-branded unlock/import UI served by the target (not metamask.io): password or seed fields under the fox brand. |
| cp_phish_presale_scam | Phishing: fake token presale | cryptopack_phish2 | Presale pages that take payment by direct transfer to a wallet address instead of a contract - the standard rug funnel. |
| cp_phish_qr_swap | Phishing: payment QR / displayed address mismatch | cryptopack_phish | Cross-checks addresses embedded in QR-code image URLs against the addresses shown as page text. A mismatch is the signature of a QR-swap overlay: the victim reads one address and pays another. |
| cp_phish_typosquat_links | Phishing: typosquat/homoglyph brand links | cryptopack_phish2 | Outbound links on the target that impersonate wallet/exchange brands: brand names embedded in lookalike domains, homoglyph swaps, punycode, or 1-2 edit distance from the real domain. |
| cp_pool_2miners | Mining pool endpoints: 2Miners | cryptopack_miners2 | 2Miners stratum pool hostnames referenced by the target - its mining (or its compromise's mining) phones home here. |
| cp_pool_domain_refs | Mining pool references | cryptopack_pay | Known mining pool domains referenced by the target (F2Pool, ViaBTC, AntPool, Hiveon, 2Miners, Nanopool, WoolyPooly, HeroMiners, SupportXMR, MoneroOcean) - its mining footprint, legitimate or planted. |
| cp_pool_hiveon | Mining pool endpoints: Hiveon | cryptopack_miners2 | Hiveon stratum pool hostnames referenced by the target - its mining (or its compromise's mining) phones home here. |
| cp_pool_luxor | Mining pool endpoints: Luxor | cryptopack_miners2 | Luxor stratum pool hostnames referenced by the target - its mining (or its compromise's mining) phones home here. |
| cp_pool_nanopool | Mining pool endpoints: Nanopool | cryptopack_miners2 | Nanopool stratum pool hostnames referenced by the target - its mining (or its compromise's mining) phones home here. |
| cp_pool_viabtc | Mining pool endpoints: ViaBTC | cryptopack_miners2 | ViaBTC stratum pool hostnames referenced by the target - its mining (or its compromise's mining) phones home here. |
| cp_proto_centralized_mint_fee | Protocol: Centralized Mint / Fee | cryptopack_protocol | Owner mint with no supply cap, or fee setter with no bound. Detection only: static analysis of code already served by the target. No RPC, no transaction, no exploit attempt. |
| cp_proto_permit_signature_replay | Protocol: Permit Signature Replay | cryptopack_protocol | permit() / ecrecover() auth with no nonce and no deadline. Detection only: static analysis of code already served by the target. No RPC, no transaction, no exploit attempt. |
| cp_proto_rounding_order | Protocol: Rounding Order | cryptopack_protocol | Division before multiplication in share / price / reward math. Detection only: static analysis of code already served by the target. No RPC, no transaction, no exploit attempt. |
| cp_proto_single_source_oracle | Protocol: Single-Source Oracle | cryptopack_protocol | Spot price from a single DEX pair with no TWAP safeguard. Detection only: static analysis of code already served by the target. No RPC, no transaction, no exploit attempt. |
| cp_proto_timestamp_randomness | Protocol: Timestamp Randomness | cryptopack_protocol | block.timestamp / prevrandao used to pick a random outcome. Detection only: static analysis of code already served by the target. No RPC, no transaction, no exploit attempt. |
| cp_proto_unbounded_slippage | Protocol: Unbounded Slippage | cryptopack_protocol | Swap with zero minimum-out or a maximum deadline. Detection only: static analysis of code already served by the target. No RPC, no transaction, no exploit attempt. |
| cp_proto_unchecked_erc20_return | Protocol: Unchecked ERC20 Return | cryptopack_protocol | token.transfer / transferFrom return value not checked. Detection only: static analysis of code already served by the target. No RPC, no transaction, no exploit attempt. |
| cp_proto_unlimited_approval | Protocol: Unlimited Approval | cryptopack_protocol | Contract-side approve() to uint max or setApprovalForAll(true). Detection only: static analysis of code already served by the target. No RPC, no transaction, no exploit attempt. |
| cp_secret_addr | Secret Network (SCRT) Address (Bech32-verified) | cryptopack_addr2 | secret1 Bech32 addresses with verified checksum. |
| cp_secret_bip38 | Leaked BIP-38 encrypted private key | cryptopack_secrets2 | BIP-38 passphrase-encrypted private keys (6P...) - checksum-verified; brute-forceable offline against weak passphrases. |
| cp_secret_bip39_sequence | Exposed BIP-39 seed phrase (checksum-verified) | cryptopack_secrets | Word sequences in served text that are valid BIP-39 mnemonics - every word on the official list AND a valid SHA-256 checksum. A verified seed phrase is a full wallet compromise. |
| cp_secret_discord_webhook | Discord webhook in crypto context | cryptopack_secrets2 | Discord webhook URLs near crypto/trading keywords - the exfil/alert channel of trading bots and drainer kits alike. |
| cp_secret_env_mnemonic | Leaked mnemonic in config assignment | cryptopack_secrets | MNEMONIC=/SEED_PHRASE= assignments in served JS or config text, word-validated against the BIP-39 list. |
| cp_secret_env_privkey | Leaked private key in config assignment | cryptopack_secrets | PRIVATE_KEY-style assignments with 64-hex values in served JS/config text. |
| cp_secret_env_privkey2 | Leaked private key in config assignment (wave-2 names) | cryptopack_secrets2 | More assignment names wave 1 missed: deployer/hot-wallet/treasury/faucet/relayer keys, plus Solana base58 keypairs in env-style assignments. |
| cp_secret_ethers_wallet | Hardcoded signer in shipped JS | cryptopack_secrets | Live signer construction in production JS: new ethers.Wallet('<key>'), privateKeyToAccount, Wallet.fromMnemonic - keys baked into the bundle. |
| cp_secret_hardhat_key | Hardcoded key in Hardhat/Truffle config | cryptopack_secrets | Deployer keys hardcoded in smart-contract tooling config (accounts arrays, privateKey fields) that ended up in served JS/source. |
| cp_secret_js_comment_keys | Private keys inside JS comments | cryptopack_secrets2 | Keys developers left in // and /* */ comments of shipped JS ('temp', 'test only', 'remove before launch') - the bundle ships them anyway. |
| cp_secret_keystore_file | Served Ethereum keystore file body | cryptopack_secrets | A full Web3 keystore (version 3 + KDF + cipher structure) in served content - brute-forceable offline if the password is weak. |
| cp_secret_keystore_path_refs | Keystore file paths/names in served content | cryptopack_secrets2 | References to actual keystore files (the UTC-- filename format is unique to Ethereum keystores) and keystore paths in configs the target serves. |
| cp_secret_nsec | Leaked Nostr private key (nsec) | cryptopack_secrets | Bech32-verified nsec private keys in served content - a full account compromise if real. |
| cp_secret_signer_hex_ctx | Private key (64-hex) with signer context | cryptopack_secrets2 | Bare 64-hex keys sitting near signer/deployer/private-key words outside the named assignments wave 1 covers - JSON dumps, config objects, frontend bundle constants. |
| cp_secret_solana_keypair | Leaked Solana keypair bytes | cryptopack_secrets | Solana secret keys as 64-byte arrays (id.json format) assigned to secretKey in served content. |
| cp_secret_telegram_bot | Telegram bot token in crypto context | cryptopack_secrets2 | Telegram bot API tokens in served JS/config near crypto keywords - these bots typically control trading alerts, sniper bots or wallet trackers with users' funds in the loop. |
| cp_secret_wallet_dat_ref | Wallet file references in served content | cryptopack_secrets | References to wallet.dat / Electrum wallet files / MetaMask vault blobs in pages, listings or storage dumps the target serves. |
| cp_secret_wif_compressed | Leaked WIF private key (compressed) | cryptopack_secrets2 | Wallet Import Format private keys for compressed public keys (K/L...) - checksum-verified; anyone holding this string owns the wallet. |
| cp_secret_wif_testnet | Leaked testnet WIF private key | cryptopack_secrets2 | Testnet WIF keys (0xEF) in production content - no direct funds, but a loud test/prod hygiene failure that often travels with real keys. |
| cp_secret_wif_uncompressed | Leaked WIF private key (uncompressed) | cryptopack_secrets2 | Wallet Import Format private keys for uncompressed public keys (5...) - checksum-verified full wallet compromise. |
| cp_secret_xprv | Leaked BIP-32 extended private key (xprv family) | cryptopack_secrets2 | Extended private keys (xprv/yprv/zprv) - one string derives every address in the wallet. |
| cp_sei_addr | Sei (SEI) Address (Bech32-verified) | cryptopack_addr2 | sei1 Bech32 addresses with verified checksum. |
| cp_solana_addr | Solana Address (32-byte verified) | cryptopack_addr | Base58 strings that decode to exactly 32 bytes (a real Ed25519 public key), not just look Solana-ish. |
| cp_spl_mint | SPL Token Mint (context-anchored, 32-byte verified) | cryptopack_addr2 | Solana addresses anchored to mint/SPL-token context - the token mints the target works with, as opposed to arbitrary wallets. |
| cp_stars_addr | Stargaze (STARS) Address (Bech32-verified) | cryptopack_addr2 | stars1 Bech32 addresses with verified checksum. |
| cp_stride_addr | Stride (STRD) Address (Bech32-verified) | cryptopack_addr2 | stride1 Bech32 addresses with verified checksum. |
| cp_sui_addr | Sui Address (context-anchored) | cryptopack_addr | 0x 64-hex Sui addresses anchored to Sui context (generic 0x64 strings alone are just hashes). |
| cp_terra_addr | Terra (LUNA) Address (Bech32-verified) | cryptopack_addr2 | terra1 Bech32 addresses with verified checksum. |
| cp_ton_addr | TON Address (CRC16-verified) | cryptopack_addr | TON user-friendly addresses with verified CRC16 checksum. |
| cp_ton_raw_addr | TON Raw Address (workchain:hash form) | cryptopack_addr2 | TON raw-form addresses (0:<64 hex> / -1:<64 hex>) - the form contracts and explorers use; wave 1 only covered the user-friendly base64url form. |
| cp_trx_validated | Tron Address (checksum-verified) | cryptopack_addr | Base58Check-verified Tron addresses (0x41 prefix). |
| cp_unstoppable_domain | Unstoppable Domains Name | cryptopack_names | Web3 naming domains (.crypto/.nft/.x/.wallet/.bitcoin/.dao/.888/.zil) published by the target. |
| cp_vet_addr | VeChain (VET) Address (context-anchored) | cryptopack_addr2 | 0x addresses anchored to VeChain (VET) context - the EVM address shape is shared across chains, so attribution comes from the surrounding text. |
| cp_via_addr | Viacoin SegWit Address (BIP-173 verified) | cryptopack_addr2 | via1 native SegWit addresses. (Viacoin legacy shares Vertcoin's 0x47 version byte, so legacy forms are not attributed.) |
| cp_vtc_addr | Vertcoin SegWit Address (BIP-173 verified) | cryptopack_addr2 | vtc1 native SegWit addresses, checksum-verified. |
| cp_wallet_archive_file | Exposed wallet backup archive | cryptopack_wallet_files | Zip/tar archives named like wallet backups served publicly - the classic 'backed up my whole wallet folder to the web root' leak. |
| cp_wallet_backup_text | Exposed wallet/seed backup text file | cryptopack_wallet_files | Seed/wallet backup text files at well-known paths, validated by content: a served file only counts when it actually contains a verified seed phrase, a labeled key, or validated addresses. |
| cp_wallet_btc_conf | Exposed node config with RPC credentials (bitcoin.conf family) | cryptopack_wallet_files | bitcoin.conf / litecoin.conf / dogecoin.conf / elements.conf served publicly AND containing RPC credential lines - full node control if the RPC port is reachable. |
| cp_wallet_config_creds | Wallet/node credentials in served config text | cryptopack_wallet_files | RPC usernames/passwords and wallet passphrases inside config text the target serves (conf dumps, env samples, JS config) - as opposed to wave 1's key-shaped assignments. |
| cp_wallet_dat_file | Exposed wallet.dat file | cryptopack_wallet_files | A Bitcoin Core / fork wallet.dat database served over HTTP - the wallet itself, keys included, protected only by its passphrase (if any). |
| cp_wallet_dir_listing | Directory listing naming wallet files | cryptopack_wallet_files | Open directory listings (backup/upload/wallet folders) whose index pages name wallet, seed or keystore files - the files are one click away. |
| cp_wallet_electrum_file | Exposed Electrum wallet file | cryptopack_wallet_files | An Electrum wallet file (JSON with wallet_type / keystore structure) served publicly. |
| cp_wallet_git_served | Wallet files in served .git history | cryptopack_wallet_files | When a target serves its own .git, the reflog commit messages reveal wallet/seed/key files that were committed - even if later deleted from the working tree. |
| cp_wallet_keystore_file | Exposed Ethereum keystore file | cryptopack_wallet_files | A Web3 keystore JSON (version 3, KDF + cipher) served at a well-known path - brute-forceable offline against weak passphrases. |
| cp_wallet_metamask_vault | MetaMask vault data in served content | cryptopack_wallet_files | MetaMask encrypted vault blobs (KeyringController state) inside pages, JS bundles or storage dumps the target serves - the vault plus a weak password is the whole wallet. |
| cp_wallet_phantom_vault | Phantom/Solana wallet vault data in served content | cryptopack_wallet_files | Phantom wallet vault/seed structures inside served storage dumps or JS - Solana wallet compromise material if the password is weak. |
| cp_wallet_qr_payload | QR-code payment payloads | cryptopack_wallet_files | QR generator URLs (qrserver / Google Charts / tec-it) whose payload parameter carries a crypto payment URI or validated address - the target's live payment destinations, decodable by anyone. |
| cp_wallet_seed_file_refs | Links to wallet/seed backup files | cryptopack_wallet_files | Pages and JS that link or point at seed, mnemonic, keystore or wallet-backup files hosted on the target - the exposure path to the file itself. |
| cp_wallet_served_docs | Wallet addresses in served docs (README/DONATE/FUNDING) | cryptopack_wallet_files | Donation and payment addresses published in documents the target serves at its web root - only checksum-validated addresses are reported. |
| cp_wallet_sourcemap | Secrets & addresses in JS source maps | cryptopack_wallet_files | Source maps ship the target's original sources to every visitor; this checks sourcesContent for seed phrases, context-labeled private keys and checksum-validated wallet addresses. |
| cp_web3_bridge_refs | Bridge references | cryptopack_web3 | Cross-chain bridge services/contracts the target points users at (Across, Hop, Stargate, Synapse, Connext, Orbiter) - high-value phishing clones cluster around these names. |
| cp_web3_canonical_contracts | Canonical Contract References (WETH, stablecoins, Permit2) | cryptopack_addr2 | The canonical mainnet contracts every Web3 security review checks for: WETH, the big stablecoins, the Beacon deposit contract, Permit2, Seaport, the ENS registry. |
| cp_web3_chainid_refs | Chain ID references | cryptopack_web3 | Chain IDs hardcoded in JS (hex or decimal) - the networks the target's Web3 code actually targets, including testnets that should not ship to prod. |
| cp_web3_dex_routers | DEX router references (known addresses) | cryptopack_web3 | Canonical DEX router/factory addresses appearing in the target's content - which venues its swaps route through. |
| cp_web3_hardhat_artifacts | Served contract artifacts / ABIs | cryptopack_web3 | Contract artifacts shipped to the browser: ABI arrays, deployed bytecode, contractName fields - a full map of the target's contract internals. |
| cp_web3_multisig | Multisig (Safe) references | cryptopack_web3 | Safe/Gnosis multisig references: app links, contract names, owner/threshold config in JS. |
| cp_web3_nft_contracts | NFT contract inventory (in context) | cryptopack_web3 | Contract addresses anchored to ERC-721/1155, minting, or marketplace (OpenSea/Blur) context. |
| cp_web3_oracle_refs | Price oracle references (Chainlink) | cryptopack_web3 | Chainlink aggregator/feed references in code - the price sources the target's contracts trust. |
| cp_web3_proxy_slots | EIP-1967 proxy slots | cryptopack_web3_gaps | EIP-1967 implementation/admin/beacon slot constants and proxy admin contract names in browser-served artifacts. Slot values are keccak(label)-1, computed, not recalled. Detection only. |
| cp_web3_rpc_endpoints | Web3 RPC endpoint inventory | cryptopack_web3 | Public/third-party RPC endpoint URLs wired into the target's pages and JS, per provider. |
| cp_web3_rpc_method_refs | Dangerous RPC method references | cryptopack_web3_gaps | JSON-RPC method names referenced in the target's public JS that must never be exposed to a browser (eth_sendTransaction, personal_unlockAccount, eth_sign). A reference only: no RPC call is made. |
| cp_web3_rpc_misconfig | RPC endpoint misconfiguration | cryptopack_web3_gaps | Non-TLS http RPC URLs, RPC URLs on known RPC ports, and localhost/loopback RPC endpoints shipped in client code. Detected from text only; the endpoint is never contacted. URLs with credentials are deliberately not matched (see module docstring). |
| cp_web3_siwe | Sign-In With Ethereum (SIWE) surface | cryptopack_web3 | SIWE message templates / sign-in domains in JS - the auth surface an attacker must clone to phish this target's users. |
| cp_web3_solana_programs | Solana program references (known IDs) | cryptopack_web3 | Canonical Solana program IDs in content - which on-chain programs the target's frontend invokes. |
| cp_web3_testnet_faucets | Testnet/faucet references in production | cryptopack_web3 | Testnet RPCs and faucet URLs referenced by the production site - environment bleed that maps the target's dev infrastructure. |
| cp_web3_token_abi | Token ABI metadata | cryptopack_web3_gaps | Token symbol/decimals pairs and privileged ABI function names (mint, burn, pause, blacklist) served in the target's pages/JS. Detection only; no chain calls. |
| cp_web3_token_contracts | Token contract inventory (in context) | cryptopack_web3 | 0x contract addresses anchored to ERC-20/token context (symbol, decimals, transfer ABI) - the tokens the target integrates, not random hashes. |
| cp_web3_wallet_roles | Wallet role addresses | cryptopack_web3_gaps | Role-attributed wallet addresses in the target's pages/JS: owner, treasury, fee recipient, dev wallet, vault, admin. Public identifiers only, never secrets. |
| cp_web3_walletconnect_project | WalletConnect project ID exposure | cryptopack_web3 | WalletConnect/Reown project IDs in JS - they map the dapp's wallet traffic to a cloud account and are a favorite clone target. |
| cp_web3_xpub | BIP-32 extended public key (xpub family) | cryptopack_secrets2 | Extended public keys (xpub/ypub/zpub) - not spendable, but they expose the wallet's entire address history and balances to anyone. |
| cp_xdc_addr | XDC Network Address (EIP-55 verified) | cryptopack_addr2 | xdc-prefixed addresses; the hex part carries an EIP-55 checksum exactly as if 0x-prefixed. |
| cp_xlm_addr | Stellar Address (CRC16-verified) | cryptopack_addr | Stellar G... account IDs with verified CRC16-XMODEM checksum. |
| cp_xmr_integrated | Monero Integrated Address (payment ID embedded) | cryptopack_addr | 106-char Monero integrated addresses: they embed a payment ID, which usually means exchange/service deposit infrastructure. |
| cp_xmr_standard | Monero Standard Address (Keccak-verified) | cryptopack_addr | Monero standard addresses with verified Keccak checksum. |
| cp_xmr_subaddress | Monero Subaddress (Keccak-verified) | cryptopack_addr | Monero subaddresses (per-customer/per-purpose wallets). |
| cp_xrp_addr | XRP Address (checksum-verified) | cryptopack_addr | XRP addresses verified with the XRP Base58 alphabet and double-SHA256 checksum. |
| cp_xtz_addr | Tezos Address (checksum-verified) | cryptopack_addr | tz1/tz2/tz3/KT1 addresses with verified Base58Check checksum. |
| cp_zec_addr | Zcash Transparent Address (checksum-verified) | cryptopack_addr | t1/t3 Zcash addresses with verified Base58Check checksum. |
| cp_zen_addr | Horizen Address (checksum-verified) | cryptopack_addr2 | Horizen transparent addresses (zn...) with verified two-byte-version Base58Check checksum. |
| create2_metamorphic_redeploy | Create2 Metamorphic Redeploy | deep_audit2 | Deep-audit detector (batch 2) for create2 metamorphic redeploy: CREATE2 metamorphic redeploy: the compilation both deploys with CREATE2 and contains a selfdestruct path, so the code at a fixed, pre-computed address can be destroyed and replaced by different code at the same address. Approvals, allowlist entries and integrations that trust the address keep trusting it after a total code swap. This is not salt squatting (the deterministic-collision class needs no selfdestruct); the destroy leg is what makes the address's code mutable. Static verified-source analysis, fast lane, detection only. |
| cross_contract_call_graph | Cross-Contract Call Graph (Deep) | deep_layers | Follows the target's external calls ONE level deep: extracts call targets from verified source, fetches each callee's verified source, and flags gate bypass through an ungated callee function and caller-supplied value routes. Edges and callees are recorded in the shared per-target record for the confirmation lane and step-path builder. Read-only. |
| cross_function_guard_sibling | Cross Function Guard Sibling | deep_audit8 | Deep-audit detector (batch 8) for cross function guard sibling: Cross-function reentrancy via an unguarded sibling: the contract DOES carry a reentrancy guard (nonReentrant / own lock) on some functions, but this sibling function is UNGUARDED, makes an external call and only writes state AFTER the call, while moving value or sharing state with a guarded function. A callee re-entering through this sibling during the guarded function's call (or vice versa) observes / mutates the shared state mid-flight - the guard gives a false sense of coverage. Static verified-source analysis, fast lane, detection only. |
| crypto_drain_scanner | Crypto Contract Drain Analyzer | crypto_drain | Analyzes a contract's verified source for unprotected drain functions: public/external functions with NO access gate that can move the contract's own ETH or tokens to the caller or a caller-supplied address (full-balance sweeps, withdraw/rescue functions, token rescue, selfdestruct). Gated, internal, view/pure and interface functions, own-balance withdrawals and msg.value pass-throughs are not flagged. When the target is a proxy, the implementation behind it is analyzed too. Read-only, never interacts with contracts. |
| crypto_infra_ports | Crypto node port surface | crypto_infra | Bounded connect checks on the six crypto node ports (8545/8546/8899/8900/26657/1317) with one read-only version/health probe per open port. |
| crypto_infra_rpc | Crypto RPC endpoint grading | crypto_infra | Harvests the RPC endpoints a crypto target's own pages/JS reference, flags keys embedded in them, and grades each endpoint read-only: client version, chain, rpc_modules namespaces, CORS. |
| default_admin_grant_exposed | Default Admin Grant Exposed | deep_audit5 | Deep-audit detector (batch 5) for default admin grant exposed: DEFAULT_ADMIN_ROLE granted unsafely: the all-powerful default admin role is granted to a hardcoded literal address, or granted inside an initialize-style function where the grant rides on initialization ordering / re-initialization risk, instead of being granted only to msg.sender in the constructor. Whoever controls that literal address - or reaches the initializer first - holds every role-admin power in the system. Static verified-source analysis, fast lane, detection only. |
| defi | DeFi Protocol Scout | defi | Detect DeFi patterns: flash loans, oracles, approvals. |
| defi_risk | DeFi Risk Scanner | defi_risk | DeFi risk factors on discovered pool/vault contracts: proxy/upgrades, owner functions, pause switches, fee-on-transfer. Keyless Sourcify source always tried; ETHERSCAN_API_KEY (optional) adds Etherscan coverage. Public data only. |
| diamond_cut_ungated | Diamond Cut Ungated | deep_audit | Deep-audit detector for diamond cut ungated: Unprotected diamondCut (EIP-2535): the facet replacement entry point performs the cut with no owner gate - no gate modifier, no gated helper, and no LibDiamond.enforceIsContractOwner call in the facet or the library path. Any stranger can point any function selector at any facet, including replacing diamondCut itself: full, permanent takeover of the diamond. Static verified-source analysis, fast lane, detection only. |
| diamond_selector_collision | Diamond Selector Collision | deep_audit7 | Deep-audit detector (batch 7) for diamond selector collision: Diamond facet selector collision: the bundle carries diamond markers and two DISTINCT non-diamond contracts declare functions with identical normalized signatures (name + parameter types), i.e. the same 4-byte selector, so one facet's route shadows the other's when installed via diamondCut. Static verified-source analysis, fast lane, detection only. |
| ecdsa_nonce_reuse_vulnerability | ECDSA Nonce Reuse Vulnerability (BSC) | bsc_common | BSC/BNB detector for ecdsa nonce reuse vulnerability: Signature nonce reuse: the signed payload carries no nonce and no used-signature registry exists, so one valid signature authorizes its action unlimited times - the signer signs once, the bearer replays forever. Static verified-source analysis, fast lane, detection only. |
| ecdsa_recover_zero_unchecked | ECDSA Recover Zero Unchecked | deep_audit8 | Deep-audit detector (batch 8) for ecdsa recover zero unchecked: ECDSA library recovery result not zero-checked: ECDSA.recover / ECDSA.tryRecover output feeds an authorization comparison with NO zero-address check on the recovered address (or a tryRecover error return is silently ignored). Where the library variant in use returns address(0) / an error instead of reverting, an invalid signature recovers to the zero address and authenticates whenever the expected signer slot is unset or zero - and an ignored tryRecover error accepts malformed signatures on the same path. Static verified-source analysis, fast lane, detection only. |
| ecdsa_signature_malleability | ECDSA Signature Malleability (BSC) | bsc_common | BSC/BNB detector for ecdsa signature malleability: ECDSA malleability: the signature is recovered with raw ecrecover and the s value is never range-checked, so for every valid signature (v, r, s) a second valid signature (v^1, r, -s) exists. Any logic keyed on the signature bytes (rather than the signer) can be replayed with the twin signature. OpenZeppelin ECDSA (which rejects high-s) does not flag. Static verified-source analysis, fast lane, detection only. |
| ecdsa_signature_replay_cross_chain | ECDSA Signature Replay Cross Chain (BSC) | bsc_common | BSC/BNB detector for ecdsa signature replay cross chain: Cross-chain signature replay: the signed payload is not bound to this chain (no chain id, no EIP-712 domain separator), so a signature gathered on one chain replays verbatim on every other chain where the contract is deployed - BNB Chain and its forks/testnets included. Static verified-source analysis, fast lane, detection only. |
| ecrecover_zero_signer | Ecrecover Zero Signer | deep_audit | Deep-audit detector for ecrecover zero signer: ecrecover zero-address signer bypass: the recovered address is compared against a signer stored in state (or supplied by the caller) with no address(0) check on the recovery. ecrecover returns address(0) for ANY malformed signature, so whenever the signer slot is unset, zeroed by rotation, or attacker-supplied as zero, a garbage signature authenticates as the signer. Static verified-source analysis, fast lane, detection only. |
| eip1271_magic_value_unchecked | Eip1271 Magic Value Unchecked | deep_audit5 | Deep-audit detector (batch 5) for eip1271 magic value unchecked: EIP-1271 result used without the magic-value check: a function calls isValidSignature(...) on an external contract and uses the result without comparing it to the magic value 0x1626ba7e (or an IERC1271 magic constant) in the same function. A contract signer returning any other bytes4 - including a truthy-looking or partially-matching value - is treated as a valid signature. Static verified-source analysis, fast lane, detection only. |
| eip712_digest_unbound_to_payload | Eip712 Digest Unbound To Payload | deep_audit3 | Deep-audit detector (batch 3) for eip712 digest unbound to payload: EIP-712 digest unbound to payload: the signed struct omits the payload it authorizes - no payload hash, batch index, amount, or recipient - and a single verification is then applied in a loop/batch over N distinct payloads or to a caller-chosen payload. One approval authorizes an arbitrary batch - the Lombard Finance shape. A struct carrying a payload hash (plus batch nonce) is the protected shape. Static verified-source analysis, fast lane, detection only. |
| eip712_separator_unbound | Eip712 Separator Unbound | deep_audit5 | Deep-audit detector (batch 5) for eip712 separator unbound: EIP-712 domain separator not bound to the live chain: the separator used by a signature / permit path is cached once (constructor, immutable or state variable) and never recomputed from block.chainid at verify time, or it is constructed with no chainId term at all. After a chain fork - or on any chain where the contract is redeployed at the same address - signatures replay across chains because the separator no longer distinguishes them. Static verified-source analysis, fast lane, detection only. |
| eip7702_unverified_delegate | Eip7702 Unverified Delegate | deep_audit2 | Deep-audit detector (batch 2) for eip7702 unverified delegate: EIP-7702 unverified delegation: an account's delegation designator (0xef0100 \|\| delegate) is set to a delegate with no verification at all - no allowlist, no code check on the delegate, no signed authorization binding the choice. Whoever controls the delegate contract controls the account's execution, so an unverified delegate is an account-takeover surface; where the delegate is caller-supplied anyone who can call the setter owns the account. Static verified-source analysis, fast lane, detection only. |
| empty_signature_accepted | Empty Signature Accepted | deep_audit8 | Deep-audit detector (batch 8) for empty signature accepted: Empty / unlength-checked signature accepted: either (a) a condition on the signature's length == 0 leads to acceptance (return true / pass) in a verification function, so an EMPTY signature authenticates; or (b) a verification function splits a bytes signature for raw ecrecover with NO length require (== 65 / >= 64) anywhere in the function, so truncated / empty signatures flow into recovery (recovering to address(0) or garbage) instead of being rejected up front. Static verified-source analysis, fast lane, detection only. |
| erc1155_batch_receiver_missing | Erc1155 Batch Receiver Missing | deep_audit5 | Deep-audit detector (batch 5) for erc1155 batch receiver missing: Incomplete ERC-1155 receiver: the contract defines onERC1155Received, so senders treat it as a 1155 receiver, but it does NOT define onERC1155BatchReceived. Batch transfers to this contract revert or strand the tokens - the acceptance surface is half implemented. Static verified-source analysis, fast lane, detection only. |
| erc20_missing_return_guard | Erc20 Missing Return Guard | deep_audit5 | Deep-audit detector (batch 5) for erc20 missing return guard: ERC20 return value handled unsafely for no-return tokens: either a standard-interface transfer / transferFrom / approve call is wrapped directly in a require / assert / if on a contract that never uses SafeERC20 (that shape reverts on tokens such as USDT whose transfer returns nothing at all), or this token-shaped contract's own transfer / transferFrom signature declares no return value, so every bool-expecting caller breaks against it. Static verified-source analysis, fast lane, detection only. |
| erc2771_msg_sender_unbound | Erc2771 Msg Sender Unbound | deep_audit5 | Deep-audit detector (batch 5) for erc2771 msg sender unbound: ERC-2771 trusted forwarder without a bound sender: the contract references a trusted forwarder but has no _msgSender() override extracting the calldata-suffix sender (or the override ignores the forwarder). Meta-transactions therefore authorize on the forwarder's own raw msg.sender - either every relayed call is treated as the forwarder, or the relayed identity is never recovered at all. Static verified-source analysis, fast lane, detection only. |
| erc721_mint_without_receiver_check | Erc721 Mint Without Receiver Check | deep_audit5 | Deep-audit detector (batch 5) for erc721 mint without receiver check: ERC721 mint without a receiver check: a public / external mint function calls plain _mint with a caller-supplied recipient and the mint path never calls _safeMint nor checks onERC721Received. _mint performs no receiver callback, so tokens minted to a contract that cannot handle ERC721 are locked in it forever. Static verified-source analysis, fast lane, detection only. |
| eth_send_stipend_brick | Eth Send Stipend Brick | deep_audit8 | Deep-audit detector (batch 8) for eth send stipend brick: .send() payout inside an accounting function: .send() forwards only a 2300-gas stipend, so a recipient that is a smart wallet / multisig / contract with any receive logic makes the send fail, while the function has already written its accounting state - the payout bricks (funds accounted as paid, never delivered, or the whole withdraw path reverts for contract recipients). Static verified-source analysis, fast lane, detection only. |
| fallback_state_write_extended | Fallback State Write Extended | deep_audit8 | Deep-audit detector (batch 8) for fallback state write extended: Fallback / receive state mutation beyond the plain payable assignment shape: the fallback or receive body performs ++ / -- / delete / array-push state writes, or a NON-payable fallback() writes state at all. Fallbacks run on every stray / malformed call and on plain ETH sends from other contracts mid-execution; mutating counters / storage there desyncs accounting that assumes the fallback is inert and can be triggered by anyone at any time. Static verified-source analysis, fast lane, detection only. |
| fee_on_transfer_overcredit | Fee On Transfer Overcredit | deep_audit2 | Deep-audit detector (batch 2) for fee on transfer overcredit: Fee-on-transfer deposit overcredit: the deposit path pulls tokens with transferFrom and credits the NOMINAL amount parameter as shares / balance, without measuring how much actually arrived (balanceOf before vs after). A fee-on-transfer, rebasing-down or otherwise short-delivering token is credited at face value, and the credited position redeems against the full pool - the shortfall is taken from the other depositors. Static verified-source analysis, fast lane, detection only. |
| flash_loan_callback_auth_bypass | Flash Loan Callback Auth Bypass (BSC) | bsc_common | BSC/BNB detector for flash loan callback auth bypass: Flash-loan callback auth bypass: the receiver callback (onFlashLoan / executeOperation shape) acts on the funds without verifying the caller is the lender or that the initiator is this contract, so anyone can call the callback directly and make the contract move or approve its own assets as if a flash loan were in flight. Static verified-source analysis, fast lane, detection only. |
| flash_loan_governance_takeover | Flash Loan Governance Takeover (BSC) | bsc_common | BSC/BNB detector for flash loan governance takeover: Flash-loan governance takeover: voting weight is read from the CURRENT token balance (balanceOf / current getVotes) at vote time, with no past-block snapshot. An attacker can flash-borrow the governance token, vote with borrowed weight, and return it in the same transaction - voting power that costs nothing to hold. Static verified-source analysis, fast lane, detection only. |
| flash_loan_repayment_underflow | Flash Loan Repayment Underflow (BSC) | bsc_common | BSC/BNB detector for flash loan repayment underflow: Flash-loan repayment underflow: repayment/fee math subtracts balance snapshots (after minus before) in pre-0.8 or unchecked arithmetic, so a callback that leaves the balance LOWER than the snapshot wraps the 'fee' to a huge number instead of reverting, corrupting the repayment accounting. Static verified-source analysis, fast lane, detection only. |
| flash_loan_reward_dilution | Flash Loan Reward Dilution (BSC) | bsc_common | BSC/BNB detector for flash loan reward dilution: Flash-loan reward dilution: the reward claim is computed from the caller's CURRENT balance / share position with no deposit-time or lock weighting, so a flash-borrowed position can be held for exactly the claim transaction and dilute every honest staker's rewards. Static verified-source analysis, fast lane, detection only. |
| flash_loan_spot_balance_check | Flash Loan Spot Balance Check (BSC) | bsc_common | BSC/BNB detector for flash loan spot balance check: Flash-loan spot balance check: the lender verifies repayment only by comparing its own spot token balance before/after the callback. A balance can be inflated without repaying (direct donation, a second loanee's funds, fee-on-transfer games), so the check does not prove THIS borrower repaid. Lenders that pull repayment via transferFrom or track an initiator-bound debt record do not flag. Static verified-source analysis, fast lane, detection only. |
| gamefi_asset_duplication_on_burn | Gamefi Asset Duplication On Burn (BSC) | bsc_common | BSC/BNB detector for gamefi asset duplication on burn: Asset duplication on burn: the burn path pays out (mints or transfers a reward/refund asset) but never actually burns anything - no _burn, no supply reduction - so the same asset can be 'burned' repeatedly, duplicating the payout asset every time. Static verified-source analysis, fast lane, detection only. |
| gamefi_randomness_blockhash_reliance | Gamefi Randomness Blockhash Reliance (BSC) | bsc_common | BSC/BNB detector for gamefi randomness blockhash reliance: Predictable randomness: a game/NFT outcome (mint rarity, draw, loot, reward) is derived from block variables (blockhash / timestamp / block number). Miners and any caller who can choose WHEN to transact can predict or grind the outcome before committing - the house edge runs the wrong way. Static verified-source analysis, fast lane, detection only. |
| gamefi_state_desync_reward_claim | Gamefi State Desync Reward Claim (BSC) | bsc_common | BSC/BNB detector for gamefi state desync reward claim: Reward-claim state desync: the claim path pays the reward but never zeroes the pending balance and never marks the claim (no claimed / lastClaim write in the function), so the stored claim state still shows the full amount - the same reward can be claimed again immediately. Static verified-source analysis, fast lane, detection only. |
| gas_denial_of_service_loop | Gas Denial Of Service Loop (BSC) | bsc_common | BSC/BNB detector for gas denial of service loop: Gas denial of service: the function loops over an ever-growing array (users / holders / stakes) performing calls or payouts per element, with no pagination or bound. Once the array is large enough the function can never complete inside a block's gas limit and the operation is bricked for everyone. Static verified-source analysis, fast lane, detection only. |
| governance_cancel_privilege_abuse | Governance Cancel Privilege Abuse (BSC) | bsc_common | BSC/BNB detector for governance cancel privilege abuse: Cancel privilege abuse: cancel() marks a proposal canceled with NO check that the caller is the proposer, a guardian, or anyone privileged - any stranger can cancel any live proposal at any time, a permanent governance DoS. Static verified-source analysis, fast lane, detection only. |
| governance_early_execution_race | Governance Early Execution Race (BSC) | bsc_common | BSC/BNB detector for governance early execution race: Early execution race: execute() performs the proposal's call without checking the proposal state (Succeeded/Queued) or its eta, so a proposal can be executed while voting is still open - or before it has passed at all. Static verified-source analysis, fast lane, detection only. |
| governance_proposal_threshold_gaming | Governance Proposal Threshold Gaming (BSC) | bsc_common | BSC/BNB detector for governance proposal threshold gaming: Proposal threshold gaming: propose() checks the proposer's CURRENT token balance against the proposal threshold, so the threshold can be met with tokens held for a single transaction (borrowed or flash-borrowed) instead of a real stake at a past block. Static verified-source analysis, fast lane, detection only. |
| governance_quorum_calculation_flaw | Governance Quorum Calculation Flaw (BSC) | bsc_common | BSC/BNB detector for governance quorum calculation flaw: Quorum calculation flaw: quorum is computed from the CURRENT totalSupply at decision/execution time rather than the supply at the proposal's snapshot block, so minting or burning between voting and execution moves the goalposts - proposals can be made to pass (or fail) after the vote is over. Static verified-source analysis, fast lane, detection only. |
| governance_signature_replay | Governance Signature Replay (BSC) | bsc_common | BSC/BNB detector for governance signature replay: Governance signature replay: vote-by-signature recovers the signer with ecrecover but the signed payload carries no nonce, no deadline and no chain/domain binding, so one signed vote can be replayed - on other proposals, other chains, or in later rounds - as often as the relayer likes. Static verified-source analysis, fast lane, detection only. |
| governance_state_staleness | Governance State Staleness (BSC) | bsc_common | BSC/BNB detector for governance state staleness: Governance state staleness (retroactive rule change): a setter rewrites the voting delay / period / quorum parameters that LIVE proposals are being judged against, so proposals created under one ruleset are decided under another - the parameters are treated as immutable by voters but are silently mutable mid-flight. Static verified-source analysis, fast lane, detection only. |
| governance_vote_double_delegation | Governance Vote Double Delegation (BSC) | bsc_common | BSC/BNB detector for governance vote double delegation: Double delegation: delegate() overwrites the caller's delegatee and credits the new delegatee WITHOUT removing the voting power from the previous one (no move-delegates step), so the same tokens vote twice - once through each delegatee. Static verified-source analysis, fast lane, detection only. |
| growable_array_loop_no_pagination | Growable Array Loop No Pagination | deep_audit9 | Deep-audit detector (batch 9) for growable array loop no pagination: Unbounded loop over a growable state array with no pagination: a non-view function loops bounded only by a state array's .length, that array is grown by push() from a public/external function of the same contract, the looping function takes no start/end/limit pagination parameters, and the loop body writes state. Anyone who can grow the array can push the loop past the block gas limit and permanently deny the function - no external call inside the loop is needed for the denial. Static verified-source analysis, fast lane, detection only. |
| hardcoded_decimals_scaling | Hardcoded Decimals Scaling | deep_audit6 | Deep-audit detector (batch 6) for hardcoded decimals scaling: Hardcoded 18-decimal scaling of external token amounts: amounts are scaled by a literal 1e18 / 10**18 in a contract that moves external tokens (transfer / transferFrom / approve) yet never calls decimals() on any token. Token decimals are per-token metadata (USDC / USDT use 6, others 8 or 24); assuming 18 misprices or misaccounts every non-18-decimal token by orders of magnitude. Static verified-source analysis, fast lane, detection only. |
| hardcoded_hash_constant_mismatch | Hardcoded Hash Constant Mismatch | deep_audit8 | Deep-audit detector (batch 8) for hardcoded hash constant mismatch: Hardcoded hash constant does not match its claimed preimage: a bytes32 constant named for a canonical hash (PERMIT_TYPEHASH, an EIP-712 domain typehash, or a *_ROLE identifier) carries a literal that differs from keccak256 of the canonical string, recomputed by this analyzer. Every signature / role check keyed on the constant verifies against the WRONG digest: permits fail or validate a different struct than signers signed, and role gates key on a hash no administrator can reproduce from the role name. Static verified-source analysis, fast lane, detection only. |
| hardcoded_zero_role_address | Hardcoded Zero Role Address | deep_audit9 | Deep-audit detector (batch 9) for hardcoded zero role address: Config-role address assigned the zero address: an address state variable with a config-role name (router / factory / oracle / token / pair / treasury / owner / admin) is assigned address(0) or the all-zero literal in a constructor or setter. The role is left unbound - every call routed through it reverts, is silently dropped, or falls into a zero-address edge case - while mere == address(0) existence checks (the clean shape) do not fire. Static verified-source analysis, fast lane, detection only. |
| hook_cei_reentrancy | Hook Cei Reentrancy | deep_audit2 | Deep-audit detector (batch 2) for hook cei reentrancy: Callback-hook CEI violation (ERC-777 / ERC-1363): the transfer path invokes the token callback hook on the counterparty BEFORE updating the accounting state, and carries no reentrancy guard. During the hook the balances still show the pre-transfer state, so a malicious receiver (or sender, via tokensToSend) reenters and spends the same balance again - the ERC-777 / imBTC / Lendf.me shape. Generic CEI detectors flag any call-before-write; this one fires only on the hook call site with an accounting variable first written after the hook. Static verified-source analysis, fast lane, detection only. |
| initializer_flag_after_call | Initializer Flag After Call | deep_audit7 | Deep-audit detector (batch 7) for initializer flag after call: Initialization flag set only after an external call: an init-named function without an initializer modifier makes an external call and assigns its hand-rolled initialized flag AFTER that call, so during the call the contract is still uninitialized and a re-entrant initialize can run a second time. Static verified-source analysis, fast lane, detection only. |
| inverted_division_zero_collapse | Inverted Division Zero Collapse | deep_audit3 | Deep-audit detector (batch 3) for inverted division zero collapse: Inverted-division zero collapse: a borrow function computes a rate/price as CONSTANT / oraclePrice with integer division and no require(result > 0) / sanity bound, and the result feeds a solvency/LTV/borrow-limit check that PASSES when the value is 0 (a require of the form amount * rate <= limit is trivially true at rate 0). Once the oracle price exceeds the constant, the rate collapses to 0 and the borrow limit stops binding - the ResupplyFi shape. Static verified-source analysis, fast lane, detection only. |
| keyharvest | Key Harvester | keyharvest | Expanded secret harvesting: private keys, seeds, API keys, DB strings. |
| l2_sequencer_uptime_missing | L2 Sequencer Uptime Missing | deep_audit2 | Deep-audit detector (batch 2) for l2 sequencer uptime missing: L2 sequencer-uptime staleness: a Chainlink price feed is consumed on an L2 with no sequencer uptime feed check anywhere in the compilation. When the sequencer is down (or has just come back), transactions queue and the price feed settles on pre-outage data; checking the price feed's own updatedAt cannot detect this, because the feed could not update either. The Chainlink L2 pattern requires reading the sequencer uptime feed, requiring answer == 0, and waiting out a grace period after the sequencer restarts before trusting prices. Static verified-source analysis, fast lane, detection only. |
| lending_pool_collateral_seizure_gap | Lending Pool Collateral Seizure Gap (BSC) | bsc_common | BSC/BNB detector for lending pool collateral seizure gap: Collateral seizure gap: the liquidation path seizes a borrower's collateral without ever checking the account is actually underwater (no liquidity / shortfall / health-factor check in the function). If reachable on healthy accounts, anyone can force-seize collateral at the liquidation discount. Static verified-source analysis, fast lane, detection only. |
| lending_pool_liquidation_incentive_overflow | Lending Pool Liquidation Incentive Overflow (BSC) | bsc_common | BSC/BNB detector for lending pool liquidation incentive overflow: Liquidation incentive overflow: the collateral-seizure amount is computed with raw multiplication (debt x incentive) in pre-0.8 or unchecked arithmetic, so a large liquidation wraps the seizure amount - either stealing far more collateral than the incentive allows or zeroing it and breaking liquidation entirely. Static verified-source analysis, fast lane, detection only. |
| marketplace_atomic_match_frontrun | Marketplace Atomic Match Frontrun (BSC) | bsc_common | BSC/BNB detector for marketplace atomic match frontrun: Atomic match frontrunning: the settlement function transfers the NFT at a price taken from the CALLER's parameters with no order signature or order-state validation, so anyone can settle any listed (or unlisted) asset at a price they choose - the 'order' is whatever the frontrunner says it is. Static verified-source analysis, fast lane, detection only. |
| marketplace_expired_order_execution | Marketplace Expired Order Execution (BSC) | bsc_common | BSC/BNB detector for marketplace expired order execution: Expired order execution: orders carry an expiry field, but the execution path never reads it, so stale orders settle long after the maker intended them dead - at prices the market has moved far away from. Static verified-source analysis, fast lane, detection only. |
| marketplace_fee_deduction_underflow | Marketplace Fee Deduction Underflow (BSC) | bsc_common | BSC/BNB detector for marketplace fee deduction underflow: Marketplace fee underflow: the seller proceeds are computed as price minus fee in pre-0.8 / unchecked arithmetic with no fee <= price bound, so a listing whose fee exceeds its price wraps the seller amount to a huge number instead of reverting. Static verified-source analysis, fast lane, detection only. |
| marketplace_royalties_recipient_spoofing | Marketplace Royalties Recipient Spoofing (BSC) | bsc_common | BSC/BNB detector for marketplace royalties recipient spoofing: Royalty recipient spoofing: the settlement pays the royalty to a recipient taken from the caller's parameters instead of the token's royaltyInfo (EIP-2981), so the buyer/settler can name themselves as the 'creator' and pocket the royalty on every sale. Static verified-source analysis, fast lane, detection only. |
| masterchef_deposit_fee_skimming | Masterchef Deposit Fee Skimming (BSC) | bsc_common | BSC/BNB detector for masterchef deposit fee skimming: MasterChef deposit-fee skimming mismatch: the chef takes a deposit fee OUT of the transfer but credits the user's amount with the FULL pre-fee figure. The credited position exceeds the LP actually held for the user, so withdrawals and reward shares are computed on phantom balance. Static verified-source analysis, fast lane, detection only. |
| masterchef_duplicate_pool_registration | Masterchef Duplicate Pool Registration (BSC) | bsc_common | BSC/BNB detector for masterchef duplicate pool registration: Duplicate pool registration: MasterChef add() registers a pool without scanning existing pools for the same lpToken. The same LP ends up in two pools, its balanceOf(this) backs BOTH pools' accounting, and rewards are allocated (and claimable) twice against one deposit base - the canonical BSC chef misconfiguration. Static verified-source analysis, fast lane, detection only. |
| masterchef_emergency_withdraw_lock | Masterchef Emergency Withdraw Lock (BSC) | bsc_common | BSC/BNB detector for masterchef emergency withdraw lock: Emergency-withdraw lock: emergencyWithdraw pays the LP out but does not zero BOTH the user's amount and rewardDebt. The surviving accounting lets the user deposit the same LP again and claim the pending rewards a second time (or leaves rewardDebt pointing at a position that no longer exists). Zeroing both before the transfer is the canonical MasterChef shape and does not flag. Static verified-source analysis, fast lane, detection only. |
| masterchef_pending_reward_overflow | Masterchef Pending Reward Overflow (BSC) | bsc_common | BSC/BNB detector for masterchef pending reward overflow: MasterChef pending-reward overflow: the pending reward is computed as amount x accRewardPerShare with raw pre-0.8 / unchecked multiplication. accRewardPerShare is a large scaled accumulator, so big positions wrap the product and the pending figure (and every payout based on it) is wrong. Static verified-source analysis, fast lane, detection only. |
| masterchef_pool_length_oob | Masterchef Pool Length Oob (BSC) | bsc_common | BSC/BNB detector for masterchef pool length oob: MasterChef pool index out of bounds: the function indexes poolInfo[pid] with a caller-supplied pool id and never bounds it against poolInfo.length. Out-of-range pids revert every call (a permanent DoS for that path in integrations that pass user pids through) and, in variants that catch the revert, fall through with a zeroed pool struct. Static verified-source analysis, fast lane, detection only. |
| masterchef_reward_token_depletion | Masterchef Reward Token Depletion (BSC) | bsc_common | BSC/BNB detector for masterchef reward token depletion: Reward depletion by stale accrual: this payout path transfers pending rewards WITHOUT calling updatePool() first, so rewards are settled against a stale accRewardPerShare while the pool keeps accruing off-book. Early claimers are paid from the shared reward balance at the wrong rate and the chef's reward token drains ahead of schedule. Static verified-source analysis, fast lane, detection only. |
| math_division_before_multiplication | Math Division Before Multiplication (BSC) | bsc_common | BSC/BNB detector for math division before multiplication: Division before multiplication: value math divides first and multiplies second, so integer truncation eats the remainder BEFORE it is scaled - fees, shares and rewards come out systematically short (and zero for small amounts). Multiply-first ordering does not flag. Static verified-source analysis, fast lane, detection only. |
| math_signed_unsigned_comparison | Math Signed Unsigned Comparison (BSC) | bsc_common | BSC/BNB detector for math signed unsigned comparison: Signed/unsigned comparison: a signed (int) state variable is cast to an unsigned type before use, so negative values become enormous positive ones in any comparison or accounting that consumes the cast - sign logic inverts exactly where the value goes negative. Static verified-source analysis, fast lane, detection only. |
| math_unchecked_downcasting | Math Unchecked Downcasting (BSC) | bsc_common | BSC/BNB detector for math unchecked downcasting: Unchecked downcasting: a value is explicitly cast to a narrower uint type with no range check. Narrowing casts truncate SILENTLY in every Solidity version (0.8's checked arithmetic does not cover casts), so any value above the target type's max wraps - balances, ids and timestamps all corrupt the same way. SafeCast usage does not flag. Static verified-source analysis, fast lane, detection only. |
| meme_coin | Meme Coin Risk Scanner | meme_coin | Meme-coin / token risk scan on verified source: honeypot shapes, rug-pull levers (mint, blacklist, taxes, trading toggles), tax asymmetry, ownership. Keyless Sourcify source always tried; ETHERSCAN_API_KEY (optional) adds Etherscan coverage. Static only, never touches the chain. |
| merkle_leaf_single_hash | Merkle Leaf Single Hash | deep_audit8 | Deep-audit detector (batch 8) for merkle leaf single hash: Merkle leaf hashed only once with packed encoding: the leaf is computed as keccak256(abi.encodePacked(x)) over a single variable-length argument (bytes / string) and checked against a Merkle root, with NO second hashing of the leaf. A single packed hash gives no leaf / internal-node domain separation: a 64-byte leaf can be reinterpreted as the concatenation of two child hashes, letting an attacker prove an internal node as a leaf (second-preimage / leaf-confusion attack). Static verified-source analysis, fast lane, detection only. |
| mev_arbitrary_liquidation_frontrun | MEV Arbitrary Liquidation Frontrun (BSC) | bsc_common | BSC/BNB detector for mev arbitrary liquidation frontrun: Caller-priced liquidation: the liquidation computes the seized collateral from a price / rate / discount supplied BY THE CALLER instead of an oracle or the account's health, so a frontrunner names their own price and liquidates any position - healthy or not - at terms they dictate. Static verified-source analysis, fast lane, detection only. |
| mev_block_number_lock_bypass | MEV Block Number Lock Bypass (BSC) | bsc_common | BSC/BNB detector for mev block number lock bypass: Block-lock bypass: the contract's trade lock / cooldown (keyed on a block-number or timestamp state variable) is enforced on one value-moving path but a sibling path moves the same value without ever reading the lock, so the lock (anti-bot / anti-dump windows on BNB Chain launches) is bypassed by simply choosing the other path. Static verified-source analysis, fast lane, detection only. |
| mev_sandwich_attack_vulnerability | MEV Sandwich Attack Vulnerability (BSC) | bsc_common | BSC/BNB detector for mev sandwich attack vulnerability: Sandwich-attack surface: this contract swaps user or treasury funds through a DEX and its swap function accepts NO slippage parameter at all - users cannot bound their execution price even if they want to, so every swap is fair game for a sandwich (frontrun + backrun) on BNB Chain's public mempool. Static verified-source analysis, fast lane, detection only. |
| multicall_value_reuse | Multicall Value Reuse | deep_audit8 | Deep-audit detector (batch 8) for multicall value reuse: Multicall msg.value reuse: a payable multicall / batch function loops delegatecalls / calls while msg.value is read inside the loop and there is NO per-iteration value accounting (no per-item value field, no running sum checked against msg.value). Each sub-call is credited with the SAME msg.value, so one payment funds every iteration - the canonical multicall value double-spend. Static verified-source analysis, fast lane, detection only. |
| multisig_threshold_setter_unsafe | Multisig Threshold Setter Unsafe | deep_audit5 | Deep-audit detector (batch 5) for multisig threshold setter unsafe: Multisig threshold setter ungated or unbounded: a function assigns the threshold / required / numConfirmations variable on a multisig-shaped contract without a caller gate, or without any require bounding the new value to 0 < v <= owners count. A threshold of 0 turns execution into a no-signature operation; a threshold above the owner count permanently bricks the wallet. Static verified-source analysis, fast lane, detection only. |
| nft | NFT Contract Scout | nft | Check NFT mint functions and metadata exposure. |
| packed_encoding_collision | Packed Encoding Collision | deep_audit8 | Deep-audit detector (batch 8) for packed encoding collision: Packed-encoding hash collision: keccak256(abi.encodePacked(...)) is computed over >= 2 variable-length arguments (string / bytes / arrays) and used as an id / digest / signature input. abi.encodePacked concatenates variable-length values with no length prefixes, so distinct tuples (("ab", "c") vs ("a", "bc")) hash identically - ids collide, digests can be forged across field boundaries, and signatures validate for data the signer never saw. Static verified-source analysis, fast lane, detection only. |
| pancake_add_liquidity_dust_leak | Pancake Add Liquidity Dust Leak (BSC) | bsc_common | BSC/BNB detector for pancake add liquidity dust leak: Add-liquidity dust leak: addLiquidity is called with BOTH minimum amounts set to 0, so the pool can take the full desired amounts at any ratio the market dictates at execution time and the unpaired remainder ('dust') is stranded in the pool for skimmers instead of being bounded by the caller's intent. Static verified-source analysis, fast lane, detection only. |
| pancake_flash_swap_reentrancy | Pancake Flash Swap Reentrancy (BSC) | bsc_common | BSC/BNB detector for pancake flash swap reentrancy: Flash-swap callback without caller validation: the pancakeCall/uniswapV2Call callback moves value or writes state without first verifying that msg.sender is the genuine pair (and that the call was initiated by this contract). Anyone can invoke the callback directly, impersonating a flash swap, and drive the contract's logic with attacker inputs. Static verified-source analysis, fast lane, detection only. |
| pancake_insufficient_slippage_protection | Pancake Insufficient Slippage Protection (BSC) | bsc_common | BSC/BNB detector for pancake insufficient slippage protection: Insufficient slippage protection: a PancakeSwap swapExact* call passes amountOutMin = 0 (directly or via a variable assigned 0), accepting ANY output amount - the textbook sandwich-attack surface on BNB Chain. Static verified-source analysis, fast lane, detection only. |
| pancake_k_value_invariant_violation | Pancake K Value Invariant Violation (BSC) | bsc_common | BSC/BNB detector for pancake k value invariant violation: K invariant violation: this pair-shaped contract rewrites its reserves in a swap/mint/burn path but nowhere checks the constant-product invariant (reserve0 * reserve1 >= K), so trades can settle at ratios that drain one side of the pool - the check PancakeSwap pairs exist to enforce. Static verified-source analysis, fast lane, detection only. |
| pancake_lp_token_burn_logic | Pancake LP Token Burn Logic (BSC) | bsc_common | BSC/BNB detector for pancake lp token burn logic: LP burn logic: a PancakeSwap pair's burn() (which redeems the underlying tokens to the chosen recipient) is exposed through an ungated function with a caller-chosen recipient, so LP tokens held by this contract can be redeemed by anyone, to themselves. Static verified-source analysis, fast lane, detection only. |
| pancake_pool_skimming_vulnerability | Pancake Pool Skimming Vulnerability (BSC) | bsc_common | BSC/BNB detector for pancake pool skimming vulnerability: Pool skimming: a PancakeSwap pair's skim() is invoked from an ungated function, so anyone can sweep the pair's excess tokens (the amount above the reserves) out of the pool instead of the protocol recovering them. Static verified-source analysis, fast lane, detection only. |
| pancake_price_oracle_manipulation | Pancake Price Oracle Manipulation (BSC) | bsc_common | BSC/BNB detector for pancake price oracle manipulation: Spot-price oracle manipulation: a PancakeSwap pair's getReserves() spot price is consumed directly to price a mint / borrow / swap / valuation, with no TWAP (no cumulative-price consult) anywhere. Spot reserves are movable inside one transaction (flash swaps), so every decision priced off them is manipulable at near-zero cost. Static verified-source analysis, fast lane, detection only. |
| pancake_remove_liquidity_frontrun | Pancake Remove Liquidity Frontrun (BSC) | bsc_common | BSC/BNB detector for pancake remove liquidity frontrun: Remove-liquidity frontrunning: removeLiquidity is called with BOTH minimum amounts set to 0, so a frontrunner who moves the pool price first makes the victim's withdrawal settle at the manipulated ratio - the withdrawal has no floor. Static verified-source analysis, fast lane, detection only. |
| pancake_swap_exact_tokens_underflow | Pancake Swap Exact Tokens Underflow (BSC) | bsc_common | BSC/BNB detector for pancake swap exact tokens underflow: Swap amount underflow: the amount fed into a PancakeSwap swap is derived by raw subtraction (balance minus a reserve/fee term) in pre-0.8 or unchecked arithmetic with no bound checked first, so a state where the subtrahend exceeds the balance wraps the swap amount to a huge number instead of reverting. Static verified-source analysis, fast lane, detection only. |
| pancake_v2_v3_router_misdirection | Pancake V2 V3 Router Misdirection (BSC) | bsc_common | BSC/BNB detector for pancake v2 v3 router misdirection: Router misdirection: swap calls are routed through a router address that is not a known PancakeSwap router (or the router address can be rewritten by an ungated setter), so swaps can be silently redirected to an attacker-controlled contract that keeps the input tokens. Static verified-source analysis, fast lane, detection only. |
| pause_coverage_missing | Pause Coverage Missing | deep_audit5 | Deep-audit detector (batch 5) for pause coverage missing: Pause machinery does not cover a value-moving function: the contract has pause / Pausable machinery, but this public / external function moves value (transfer / withdraw / mint / burn / redeem / claim shape) with no whenNotPaused, _requireNotPaused or paused-condition guard. During an incident the emergency pause will not stop this operation. Static verified-source analysis, fast lane, detection only. |
| pf_aptos_private_key | Aptos private key | privfind | Private findings: detects Aptos private key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_cardano_signing_key | Cardano payment signing key (CBOR) | privfind | Private findings: detects Cardano payment signing key (CBOR) publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_deposit_data_file | Eth2 validator deposit data file | privfind | Private findings: detects Eth2 validator deposit data file publicly served at a well-known path. Marker-gated; detection only. |
| pf_electrum_wallet_file | Electrum wallet file | privfind | Private findings: detects Electrum wallet file publicly served at a well-known path. Marker-gated; detection only. |
| pf_filecoin_key_export | Filecoin wallet key export | privfind | Private findings: detects Filecoin wallet key export publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_hedera_private_key | Hedera private key (DER ed25519) | privfind | Private findings: detects Hedera private key (DER ed25519) publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_lnd_macaroon | LND macaroon (hex) | privfind | Private findings: detects LND macaroon (hex) publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_monero_spend_key | Monero secret spend key | privfind | Private findings: detects Monero secret spend key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_near_secret_key | NEAR account secret key | privfind | Private findings: detects NEAR account secret key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_priv_validator_key_file | Cosmos validator private key file | privfind | Private findings: detects Cosmos validator private key file publicly served at a well-known path. Marker-gated; detection only. |
| pf_stellar_secret_key | Stellar secret key | privfind | Private findings: detects Stellar secret key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_sui_private_key | Sui private key | privfind | Private findings: detects Sui private key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_tendermint_privkey | Tendermint/Cosmos validator private key | privfind | Private findings: detects Tendermint/Cosmos validator private key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_xrp_family_seed | XRP family seed | privfind | Private findings: detects XRP family seed publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_zcash_spending_key | Zcash unified spending key | privfind | Private findings: detects Zcash unified spending key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| pf_zcash_viewing_key | Zcash Sapling viewing key | privfind | Private findings: detects Zcash Sapling viewing key publicly exposed in page/JS text. Masked + fingerprinted; detection only. |
| private_sensitive_state_var | Private Sensitive State Var | deep_audit9 | Deep-audit detector (batch 9) for private sensitive state var: Sensitive data in a 'private' state variable: a state variable declared private has a sensitive name (secret / password / api key / private key / seed / mnemonic / credential). Solidity's private visibility only restricts other contracts' code - the value sits in public storage and is readable by anyone from the chain, so the privacy is false and any real secret stored here is exposed. Static verified-source analysis, fast lane, detection only. |
| proxy_beacon_address_manipulation | Proxy Beacon Address Manipulation (BSC) | bsc_common | BSC/BNB detector for proxy beacon address manipulation: Beacon address manipulation: the function that sets the beacon (or the beacon's implementation) has NO access gate, so a stranger can repoint every beacon proxy at an attacker implementation in one call - a fleet-wide takeover, not a single-proxy one. Static verified-source analysis, fast lane, detection only. |
| proxy_cloning_initial_state_leak | Proxy Cloning Initial State Leak (BSC) | bsc_common | BSC/BNB detector for proxy cloning initial state leak: Clone initial-state leak: the factory deploys EIP-1167 minimal-proxy clones WITHOUT calling initialize in the same transaction, so every clone sits uninitialized - with its initial state (owner, config) up for grabs - until someone initializes it, and a watcher can front-run the legitimate initialization. Static verified-source analysis, fast lane, detection only. |
| proxy_delegatecall_selfdestruct | Proxy Delegatecall Selfdestruct (BSC) | bsc_common | BSC/BNB detector for proxy delegatecall selfdestruct: Delegatecall selfdestruct: this compilation both delegatecalls (proxy surface) and contains a selfdestruct. If the selfdestruct sits in code executed in the implementation's context, calling it destroys the implementation and permanently bricks every proxy delegating to it; in the proxy's context it destroys the proxy and traps its assets. Static verified-source analysis, fast lane, detection only. |
| proxy_deterministic_deployment_collision | Proxy Deterministic Deployment Collision (BSC) | bsc_common | BSC/BNB detector for proxy deterministic deployment collision: Deterministic deployment collision: CREATE2 is used with a fully caller-supplied salt that is not bound to msg.sender (or any deployer-specific value), so anyone can pre-compute the deployment address, squat the deployment, or collide with a planned deployment of different code at the same address. Static verified-source analysis, fast lane, detection only. |
| proxy_function_clashing | Proxy Function Clashing (BSC) | bsc_common | BSC/BNB detector for proxy function clashing: Function selector clashing: a function name is defined on BOTH the proxy and the implementation. Calls hit the proxy's own version (or fall through) depending on routing the user cannot see, so the implementation's function of the same name is shadowed - the transparent-proxy clash class that admin/function separation exists to prevent. Static verified-source analysis, fast lane, detection only. |
| proxy_implementation_uninitialized | Proxy Implementation Uninitialized (BSC) | bsc_common | BSC/BNB detector for proxy implementation uninitialized: Implementation uninitialized: this proxy implementation's initialize() sets state with no initializer modifier and the implementation never locks itself with _disableInitializers, so anyone can initialize the IMPLEMENTATION directly and seize its owner/admin role (the Parity-class bug); from there any implementation-side privileged path is the attacker's. Static verified-source analysis, fast lane, detection only. |
| proxy_shadow_variable_override | Proxy Shadow Variable Override (BSC) | bsc_common | BSC/BNB detector for proxy shadow variable override: Shadow variable override: the proxy and the implementation declare the same watched state variable (owner/admin/implementation/...), so both write the same storage slot through delegatecall - each side silently overwrites the other's value. Static verified-source analysis, fast lane, detection only. |
| proxy_storage_collision_detector | Proxy Storage Collision Detector (BSC) | bsc_common | BSC/BNB detector for proxy storage collision detector: Proxy storage collision: the proxy stores its implementation/admin pointer in an ordinary state variable instead of an EIP-1967 namespaced slot, so the implementation's own slot-0 variables overwrite the pointer (or the pointer overwrites implementation state) - the layout collision EIP-1967 exists to prevent. Static verified-source analysis, fast lane, detection only. |
| proxy_transparent_admin_misdirection | Proxy Transparent Admin Misdirection (BSC) | bsc_common | BSC/BNB detector for proxy transparent admin misdirection: Transparent admin misdirection: the proxy's fallback delegatecalls EVERYTHING with no admin routing (no ifAdmin / admin-caller branch anywhere in the contract), so admin-function calls from ordinary users fall through to the implementation and calls from the admin can never reach the implementation's own functions predictably - the proxy is neither transparent nor admin-separated. Static verified-source analysis, fast lane, detection only. |
| proxy_upgrade_authorization_gap | Proxy Upgrade Authorization Gap (BSC) | bsc_common | BSC/BNB detector for proxy upgrade authorization gap: Upgrade authorization gap: the upgrade function rewrites the implementation pointer with NO access gate, so any stranger can point the proxy at their own implementation and take over every function and asset behind it. Static verified-source analysis, fast lane, detection only. |
| push_payment_revert_dos | Push Payment Revert Dos | deep_audit8 | Deep-audit detector (batch 8) for push payment revert dos: Push-payment revert DoS: a loop over the payees / recipients state array pays each entry with .transfer(), which propagates any recipient revert to the whole loop. ONE bad recipient (a reverting fallback, a blacklisted or contract payee) bricks payouts for EVERY payee, forever, while the payee list keeps the poisoned entry. (Overlap: the size-based gas_denial_of_service_loop native also flags large push loops; this detector is the revert-propagation slice and requires .transfer( specifically.) Static verified-source analysis, fast lane, detection only. |
| raw_ecrecover_s_unbounded | Raw Ecrecover S Unbounded | deep_audit8 | Deep-audit detector (batch 8) for raw ecrecover s unbounded: Raw ecrecover with no s upper bound: a raw ecrecover(hash, v, r, s) call (in any function, helpers included) and NO s bound anywhere in the contract (no secp256k1n/2 constant, no s <= comparison). ECDSA signatures are malleable in s: for every valid (v, r, s) the twin (v ^ 1, r, n - s) also recovers to the same signer, so any digest / signature keyed accounting can be replayed with the twin signature unless s is bounded to the lower half. Static verified-source analysis, fast lane, detection only. |
| readonly_reentrancy_gap | Readonly Reentrancy Gap | deep_audit | Deep-audit detector for readonly reentrancy gap: Read-only reentrancy guard gap: state-changing functions carry a reentrancy lock and the contract makes external calls, but a view / pricing function reads the same pool state WITHOUT the lock. During a callback (token hook, ETH receive, flash-loan callback) the pool is mid-update, and any protocol pricing off this view reads the stale, manipulated state - the dForce / Curve read-only reentrancy shape. The view itself cannot be reentered for writes; the victim is whoever trusts its answer mid-transaction. Static verified-source analysis, fast lane, detection only. |
| recipient_bridge_release_unproven | Recipient Bridge Release Unproven | recipient_first | Bridge/escrow release without proof: an unlock / release / finalize function pays a caller-supplied recipient, and nothing in the call path verifies a bridge message, deposit proof, Merkle proof, validator signature, or consumes a message nonce. The release is authorized by the call itself, so any stranger can release escrowed value to themselves. |
| recipient_mint_to_caller | Recipient Mint To Caller | recipient_first | Ungated mint to caller: a public mint entry point with no gate mints tokens straight to msg.sender or a caller-supplied address. The recipient IS the caller, and nothing requires the caller to own or pay for the amount. On any token with a live pool the minted supply is sellable, so this is a direct value print. (Pool liveness is confirmed by the validator lane; the static finding stands on the mint path itself.) |
| recipient_overdraw_withdraw | Recipient Overdraw Withdraw | recipient_first | Withdraw exceeds the caller's own balance: a withdraw / release / redeem function pays msg.sender an amount that is not bounded by the caller's own deposited or credited balance - no require checks the amount against the caller's recorded balance and the payout is not debited from it either. A stranger with a zero deposit can name an amount up to the whole contract balance. This is NOT a holder-self unwrap: an unwrap debits the caller's own balance by exactly the amount paid, and that shape stays silent here. |
| recipient_rescue_to_param | Recipient Rescue To Param | recipient_first | Rescue pays a caller-supplied destination: a rescue / sweep / emergency-withdraw function with no gate moves the contract's tokens or native balance to an address the CALLER passes in. Anyone can point the contract's whole stuck balance at their own wallet. (The hardcoded-destination variant of this shape is trigger-only - the money can only ever land at the project wallet - and stays out of this finding.) |
| recipient_sig_value_to_self | Recipient Sig Value To Self | recipient_first | Signature path moves value to the caller without a valid owner signature: a permit / claim / signed-withdraw function moves value to msg.sender (or a caller address) while the recovered signer is never compared to a stored owner/authority, or the expected signer is itself a caller-supplied parameter (pass address(0) as the signer and any garbage signature recovers to it). No valid owner signature is needed to take the value. |
| recipient_unbacked_claim | Recipient Unbacked Claim | recipient_first | Claim pays the caller with no backing entitlement: a claim / reward / faucet function transfers value to msg.sender (or a caller-supplied address) where the payout is not bounded by the caller's own recorded entitlement, or the entitlement is read but never decremented or marked consumed - so the claim is repeatable (double claim) by any stranger, forever, until the contract is empty. |
| reentrancy_guard_uninitialized | Reentrancy Guard Uninitialized | deep_audit8 | Deep-audit detector (batch 8) for reentrancy guard uninitialized: Hand-rolled reentrancy guard never initialized: the guard status variable is declared in this source with NO initializer and is never assigned in any constructor / initializer. Guard logic ported from OpenZeppelin assumes NOT_ENTERED = 1 semantics; at the default 0 the state machine is shifted (the first entry check compares against the wrong sentinel), so the lock can admit a re-entrant call or lock the contract outright. Static verified-source analysis, fast lane, detection only. |
| renounce_role_last_admin | Renounce Role Last Admin | deep_audit5 | Deep-audit detector (batch 5) for renounce role last admin: renounceRole with no last-holder guard: the renounceRole definition / override performs no remaining-holder check (no getRoleMemberCount, no hasRole guard on another holder), so the sole holder of a critical role - including DEFAULT_ADMIN_ROLE - can renounce it and leave the contract with no backup authority able to administer roles. Static verified-source analysis, fast lane, detection only. |
| rugpull | Rug Pull Indicators | rugpull | Flag honeypot and rug pull contract patterns. |
| shadowed_state_variable_legacy | Shadowed State Variable Legacy | deep_audit6 | Deep-audit detector (batch 6) for shadowed state variable legacy: Shadowed state variable (legacy compiler): under a pragma that allows solc < 0.6.0, a derived contract redeclares a state variable with the same name as a base contract's state variable. Pre-0.6 the compiler accepts this and the two names are separate storage slots: code reading the base variable and code reading the derived variable silently disagree about the value (the classic pre-0.6 shadowing bug class the 0.6 compiler change made an error). Static verified-source analysis, fast lane, detection only. |
| share_transfer_cancel_desync | Share Transfer Cancel Desync | deep_audit3 | Deep-audit detector (batch 3) for share transfer cancel desync: Share-transfer cancel desync: the contract stores a per-user entitlement in a mapping at join/deposit, issues freely transferable shares, but cancel()/withdraw() refunds from the STORED mapping while burning balanceOf(msg.sender) - which may be 0 after the user transferred their shares away - without reconciling stored vs live balance. A user can transfer shares and then still cancel on the stored entitlement (double exit), or be shorted when the ledgers diverge - the BriVault shape. Non-transferable shares, or a cancel that burns from the stored mapping, is the protected shape. Static verified-source analysis, fast lane, detection only. |
| shodan_enum | Shodan Crypto Enumerator | shodan_enum | Exposed crypto infra: keyless urlscan.io host intel always runs; SHODAN_API_KEY (optional) adds Shodan ETH RPC 8545, WS 8546, node ports, open DBs. Detection only. |
| signature_nonce_unconsumed | Signature Nonce Unconsumed | deep_audit5 | Deep-audit detector (batch 5) for signature nonce unconsumed: Signature nonce read but never consumed: a nonce state variable / mapping is read inside a signed-digest / verify path (ecrecover or ECDSA.recover present), yet the nonce is never written, incremented or assigned anywhere in the contract. The digest therefore stays valid forever and the same signature can be replayed unboundedly - the nonce is decoration, not a replay guard. Static verified-source analysis, fast lane, detection only. |
| solana_contract | Solana Contract Recon | solana_contract | Reads Solana contracts from public chain data: SPL token mints (mint/freeze authority still set, REAL holder distribution by owner wallet, full Token-2022 dangerous-extension audit, creator deep-dive, authority map), pump.fun coins (bonding curve, mutable metadata, creator holdings), DexScreener sell-side checks (no-sells, pair age, dumps), and programs (BPF upgrade authority). Read-only, never sends a transaction. |
| spot_price_own_balance | Spot Price Own Balance | deep_audit4 | Deep-audit detector (batch 4) for spot price own balance: Spot price derived from the contract's own token balance: a price / rate / valuation is computed from balanceOf(address(this)) with arithmetic on the balance. The contract's own spot balance is movable by anyone in a single transaction (direct donation, flash-minted deposit, skim), so every mint / borrow / settlement priced off it can be manipulated at near-zero cost. No TWAP, oracle feed or multi-source safeguard is visible. Static verified-source analysis, fast lane, detection only. |
| stacks_contract | Stacks Contract Recon | stacks_contract | Reads Stacks (Clarity) contracts from the keyless Hiro API: mint authority (hardcoded principal vs data-var owner vs unguarded), mint cap enforced or decorative, burn / pause / freeze / blacklist powers, owner rotation, tx-sender auth patterns, and live SIP-010 supply state vs the cap. Read-only, never submits a transaction. |
| staking_lockup_duration_bypass | Staking Lockup Duration Bypass (BSC) | bsc_common | BSC/BNB detector for staking lockup duration bypass: Lockup bypass: the staking contract declares a lock (lockPeriod / unlockTime state) but the withdraw path never reads any lock or timestamp state - the advertised lockup is unenforced and stakers can exit at any time, defeating the lock's purpose (and any reward priced for it). Static verified-source analysis, fast lane, detection only. |
| staking_reward_compounding_reentrancy | Staking Reward Compounding Reentrancy (BSC) | bsc_common | BSC/BNB detector for staking reward compounding reentrancy: Compounding reentrancy: the compound/claim path makes its external call BEFORE updating the user's reward state (checks-effects-interactions violated, no reentrancy guard), so a caller contract can re-enter during the payout and compound/claim against the stale position repeatedly. Static verified-source analysis, fast lane, detection only. |
| staking_total_shares_mismatch | Staking Total Shares Mismatch (BSC) | bsc_common | BSC/BNB detector for staking total shares mismatch: Total-shares mismatch: shares are credited from the REQUESTED deposit amount, never from the balance delta actually received. With a fee-on-transfer staking token (the BNB Chain norm), every deposit over-credits shares, so totalShares permanently exceeds the assets backing them and late withdrawers are shorted. Static verified-source analysis, fast lane, detection only. |
| staking_zero_deposit_harvest | Staking Zero Deposit Harvest (BSC) | bsc_common | BSC/BNB detector for staking zero deposit harvest: Zero-deposit harvest loop: this deposit/claim path pays out pending rewards but never writes rewardDebt, so the same pending amount stays claimable - calling deposit(0) (or the claim path) repeatedly harvests the same rewards until the reward balance is empty. Static verified-source analysis, fast lane, detection only. |
| state_change_without_event | State Change Without Event | deep_audit9 | Deep-audit detector (batch 9) for state change without event: State-changing setter emits no event: the contract defines at least one event, yet a public/external setter-shaped function writes state with no emit in its body, so indexers, wallets and monitoring cannot observe the change off-chain. (Event payload completeness - events that are emitted but lack old/new values - is out of scope for this detector.) Static verified-source analysis, fast lane, detection only. |
| storage_state_analysis | Storage State Analysis (Deep) | deep_layers | Reads LIVE storage (EIP-1967 slots + the source-derived layout) for gate-deciding values - owner, implementation, paused, fee/recipient - and combines them with source analysis: findings fire when live state changes the source-shape verdict. Also extracts token parameters (decimals/totalSupply/cap/totalAssets via eth_call, fee params from source) into the shared per-target record for the math layer. Read-only eth_getStorageAt / eth_call. |
| strict_balance_equality | Strict Balance Equality | deep_audit6 | Deep-audit detector (batch 6) for strict balance equality: Strict equality on the contract balance: a validation condition compares address(this).balance with == (directly or through a local assigned from it) gating a value / state path. ETH can be forced into any contract (selfdestruct, coinbase payment, pre-funded address), so an exact-balance equality can be broken - or satisfied - by a stranger at will: the gated path can be bricked permanently or opened off-schedule. Static verified-source analysis, fast lane, detection only. |
| swap_deadline_unbound | Swap Deadline Unbound | deep_audit6 | Deep-audit detector (batch 6) for swap deadline unbound: Unbound swap deadline: the deadline-position argument of a V2-router swap call is a numeric literal or type(uint256).max rather than a block.timestamp-derived expiry. A fixed or effectively-infinite deadline leaves a signed / queued swap executable at any future block, so whoever relays or mines it can hold it until the market moves against the signer. Static verified-source analysis, fast lane, detection only. |
| swap_fixed_min_amount_out | Swap Fixed Min Amount Out | deep_audit6 | Deep-audit detector (batch 6) for swap fixed min amount out: Hardcoded non-zero minimum-out on a swap: the amountOutMin-position argument of a V2-router swap call is a fixed numeric literal rather than a value derived from a quote / expected output for THIS trade size. A constant floor protects nothing proportionally: on a large swap it is dust (sandwichable down to the literal), on a small swap it can exceed the honest output and brick the path. (A literal 0 is the unbounded case owned by the slippage detectors; this lane is the non-zero constant.) Static verified-source analysis, fast lane, detection only. |
| system_assembly_memory_overwrite | System Assembly Memory Overwrite (BSC) | bsc_common | BSC/BNB detector for system assembly memory overwrite: Assembly memory overwrite: inline assembly writes directly to memory slot 0x40 (the free memory pointer) or the 0x00 scratch slot with a value that is not a computed allocation, corrupting the allocator for every subsequent memory operation in the call. Static verified-source analysis, fast lane, detection only. |
| system_ether_transfer_fallback_brick | System Ether Transfer Fallback Brick (BSC) | bsc_common | BSC/BNB detector for system ether transfer fallback brick: Ether transfer brick: native payouts use .transfer()/.send()-style 2300-gas semantics (.transfer with a single value argument), which permanently fails for recipients whose fallback does real work (smart wallets, multisigs, contracts) - their withdrawals brick while plain accounts succeed. Call-based payouts in the same function suppress this. Static verified-source analysis, fast lane, detection only. |
| system_hardcoded_gas_limits | System Hardcoded Gas Limits (BSC) | bsc_common | BSC/BNB detector for system hardcoded gas limits: Hardcoded gas limit: a low-level call carries a literal gas stipend baked into the code. Stipends chosen for today's opcode prices break silently when gas repricing lands (the 2300 transfer stipend class of bug), and a stipend too small for the callee's fallback bricks the call path. Static verified-source analysis, fast lane, detection only. |
| system_selfdestruct_funds_trap | System Selfdestruct Funds Trap (BSC) | bsc_common | BSC/BNB detector for system selfdestruct funds trap: Selfdestruct funds trap: the contract contains a selfdestruct. Beyond the destruction itself, any native funds sent to the contract's address AFTER destruction are trapped forever (the address can still receive, nothing can ever move them), and pre-destruction the opcode is a one-call kill switch for every integration pointing at the address. (Proxy compilations are covered by the proxy module's detector.) Static verified-source analysis, fast lane, detection only. |
| system_stale_oracle_data | System Stale Oracle Data (BSC) | bsc_common | BSC/BNB detector for system stale oracle data: Stale oracle data: the Chainlink latestRoundData() result is consumed reading ONLY the price - updatedAt / answeredInRound are never touched anywhere in the function - so a stalled or stale feed is indistinguishable from a live one and every price decision settles on dead data. Static verified-source analysis, fast lane, detection only. |
| system_unbounded_fee_parameter | System Unbounded Fee Parameter (BSC) | bsc_common | BSC/BNB detector for system unbounded fee parameter: Unbounded fee parameter: the fee/tax setter stores the new fee with NO upper-bound check, so the fee can be set to 100% (or more) - every subsequent transfer is confiscated by the fee. An owner gate does not excuse this: owner-set 100% fees are the standard BNB Chain honeypot shape. A bounded setter (require fee <= cap) does not flag. Static verified-source analysis, fast lane, detection only. |
| timelock_delay_bypass | Timelock Delay Bypass (BSC) | bsc_common | BSC/BNB detector for timelock delay bypass: Timelock delay bypass: queue/execute handles the eta without enforcing a minimum delay between queueing and execution (no minDelay comparison anywhere in the path), so a queued transaction can execute immediately - the timelock's whole purpose (a public waiting period) is void. Static verified-source analysis, fast lane, detection only. |
| timelock_execution_gas_exhaustion | Timelock Execution Gas Exhaustion (BSC) | bsc_common | BSC/BNB detector for timelock execution gas exhaustion: Timelock execution gas exhaustion: batch execution loops over an unbounded array of queued transactions making an external call per item, with no length cap or gas accounting - past a certain batch size the execution can never fit in a block and the queued transactions are bricked. Static verified-source analysis, fast lane, detection only. |
| timelock_queue_transaction_collision | Timelock Queue Transaction Collision (BSC) | bsc_common | BSC/BNB detector for timelock queue transaction collision: Timelock queue collision: the queued-transaction hash is computed WITHOUT the eta, the call data, or the signature, so two genuinely different transactions (same target/value, different data or timing) hash to the same queue entry - one can be queued innocuously and executed as the other. Static verified-source analysis, fast lane, detection only. |
| token_callback_caller_unverified | Token Callback Caller Unverified | deep_audit8 | Deep-audit detector (batch 8) for token callback caller unverified: Token receipt callback does not verify the caller: onERC721Received / onERC1155Received / onERC1155BatchReceived / tokensReceived / onTransferReceived writes state or credits value with NO msg.sender comparison anywhere in the function, so ANY caller can invoke the handler directly and claim the credit / state change the callback grants for a genuine token transfer that never happened. Static verified-source analysis, fast lane, detection only. |
| token_rugcheck | Token Rug-Check | token_rugcheck | Scam-token safety check for a token contract (EVM) or Solana mint: holder concentration, unlocked liquidity, live mint/freeze authority, honeypot and tax signals, unverified source, owner control. Read-only via keyless GoPlus + DexScreener + public RPC. Detection only - never trades or touches funds. |
| tokenapproval | Token Approval Risk | tokenapproval | Find unlimited token approvals (drain vector). |
| transient_latch_unconsumed | Transient Latch Unconsumed | deep_audit3 | Deep-audit detector (batch 3) for transient latch unconsumed: Transient-storage auth latch never consumed: the function checks a tload latch as one-time proof that a privileged delivery/callback happened, then performs a privileged external call or state write without ever clearing the slot back to zero. The latch stays set, so the same proof authorizes the privileged effect again - the zkLink Nova shape. A tstore(slot, 0) reset after the check, or a latch slot hashed over target+payload, is the protected shape. Static verified-source analysis, fast lane, detection only. |
| twap_observe_window_short | Twap Observe Window Short | deep_audit6 | Deep-audit detector (batch 6) for twap observe window short: TWAP observation window too short: a Uniswap V3 observe() secondsAgo window (or the PERIOD / WINDOW constant feeding an observe / consult consumer) maxes below 1800 seconds. A sub-30-minute TWAP can be moved within a handful of blocks by a funded attacker and held long enough for the victim to read it, so the 'manipulation-resistant' price is manipulable at feasible capital. Static verified-source analysis, fast lane, detection only. |
| two_step_ownership_missing | Two Step Ownership Missing | deep_audit5 | Deep-audit detector (batch 5) for two step ownership missing: Single-step ownership transfer: transferOwnership assigns the owner state variable directly in its body, and the contract has no pendingOwner-style record and no acceptOwnership function. One typo'd or uncontrolled address in a single call irreversibly hands over - or bricks - control of the contract. Static verified-source analysis, fast lane, detection only. |
| unchecked_math_user_input | Unchecked Math User Input | deep_audit6 | Deep-audit detector (batch 6) for unchecked math user input: Unchecked arithmetic on caller-supplied input: an unchecked{} block performs arithmetic on an operand that is a parameter of the enclosing function and the result is assigned onward (a state variable, or a local that is stored, returned or passed on). Since Solidity 0.8 the compiler's overflow checks are the only thing standing between a crafted input and a wrapped balance / fee / share figure; inside unchecked{} that protection is explicitly switched off, and a caller-identity gate on the function does not bound the arithmetic for the callers who ARE allowed through (or for a compromised / relayer path). Static verified-source analysis, fast lane, detection only. |
| unified_keyword_search | Unified Keyword Search | unified_keyword_search | One search, multiple keywords, all three ReconAnything lanes at once: the verified-source code index (FTS5), the continuous scanner's batches and queues, and the transition watcher's watchlist, snapshots and events. AND across keywords by default (OR mode and exact phrases supported), chain and minimum-value filters, one deduped result set tagged by lane with matched code lines. A match is a lead for the live-probe validator, never a verdict. Solana is not in the source index (no keyless verified-source corpus); it can still surface from the scanner and watch lanes. |
| uups_authorize_upgrade_missing | Uups Authorize Upgrade Missing | deep_audit7 | Deep-audit detector (batch 7) for uups authorize upgrade missing: UUPS upgrade authorization missing or empty: in a UUPSUpgradeable context the _authorizeUpgrade override is defined with an EMPTY body (anyone who can reach upgradeTo upgrades the implementation), or no _authorizeUpgrade definition appears anywhere in the source at all. Static verified-source analysis, fast lane, detection only. |
| v4_hook_shared_delta_take_pair | V4 Hook Shared Delta Take Pair | deep_audit3 | Deep-audit detector (batch 3) for v4 hook shared delta take pair: Uniswap v4 hook shared-delta take: the hook takes pool credit via PositionManager modifyLiquiditiesWithoutUnlock / take (TAKE_PAIR) without opening its own unlock and without asserting currencyDelta == 0 / delta isolation. The hook spends from the PoolManager's shared ledger without proving the delta it takes is its own - the GoldPesa GPXHooks shape. Opening the hook's own unlock, or asserting delta isolation before taking, is the protected shape. Static verified-source analysis, fast lane, detection only. |
| vault_share_inflation | Vault Share Inflation | deep_audit | Deep-audit detector for vault share inflation: ERC-4626 share inflation (first-depositor / donation attack): totalAssets() is the vault's raw asset balance, so anyone can move it with a direct transfer, and the share conversion divides by that balance with no virtual-share offset, no dead-share bootstrap mint and no minimum-shares guard. The first depositor mints 1 share, donates a large sum directly to the vault, and later depositors are minted 0 (or dust) shares for real money, which the attacker then redeems against their deposits. Static verified-source analysis, fast lane, detection only. |
| venus_accrue_interest_omission | Venus Accrue Interest Omission (BSC) | bsc_common | BSC/BNB detector for venus accrue interest omission: Venus accrue-interest omission: the function reads stored (stale) exchange-rate / borrow-balance values without calling accrueInterest() first, so it acts on rates that lag real time - redemptions and liquidations settle at yesterday's price while the market's true state has moved. Static verified-source analysis, fast lane, detection only. |
| venus_comptroller_state_sync | Venus Comptroller State Sync (BSC) | bsc_common | BSC/BNB detector for venus comptroller state sync: Venus comptroller desync: this Venus/Compound-style market mints or lends WITHOUT consulting the comptroller (no mintAllowed/borrowAllowed, no membership/liquidity check), so the comptroller's account-liquidity state never learns about the position - collateral factors, listing status and shortfall checks are all bypassed on BNB Chain's main lending design. Static verified-source analysis, fast lane, detection only. |
| venus_mint_rate_assumption | Venus Mint Rate Assumption (BSC) | bsc_common | BSC/BNB detector for venus mint rate assumption: Venus mint-rate assumption: the market credits vTokens 1:1 with the underlying amount deposited, never dividing by the exchange rate. As the rate drifts from 1.0 (it only grows in Venus markets), new minters are over-credited and existing holders are diluted. Static verified-source analysis, fast lane, detection only. |
| view_price_no_reentrancy_protection | View Price No Reentrancy Protection | deep_audit6 | Deep-audit detector (batch 6) for view price no reentrancy protection: Read-only reentrancy exposure with NO lock anywhere: a view / pure function computes a price / ratio from live pool state (getReserves(), a pair balanceOf, get_virtual_price, reserve reads) while the contract carries no reentrancy protection at all (no nonReentrant / ReentrancyGuard / _status-style lock) and its non-view functions make external calls. During any callback out of this contract (or a sibling integration), the pool state behind the price is mid-flight, and an external consumer reading the view price settles against a state that does not exist outside the callback. Static verified-source analysis, fast lane, detection only. |
| weak_randomness_value_outcome | Weak Randomness Value Outcome | deep_audit8 | Deep-audit detector (batch 8) for weak randomness value outcome: Weak randomness decides a value outcome: the function derives a result from block.timestamp / block.prevrandao / blockhash / block.difficulty (including inside a keccak256 packed hash) AND moves value (transfer / call{value} / mint) or selects a winner / index by modulo over a participants array. Block values are observable and influenceable by validators and by anyone who can time a call, so the 'random' outcome can be predicted or ground until it favors the caller. Static verified-source analysis, fast lane, detection only. |
| zeroday_contract_guards | Zero-Day Candidate Hunter (Contract Guard Consistency) | zeroday_contract_guards | Learns a contract's own access-control convention from its verified source and flags public state-changing functions that break it (no guard where every sibling has one, allowance checks a sibling enforces but a spender skips) as candidate zero-days for human review. |

### Financial (43)

| id | label | module | description |
|----|-------|--------|-------------|
| bank | Bank Infrastructure Detection | bank | Banking portals, admin panels, API surface, header audit, platform fingerprints. Detection only. |
| bank_surface | Bank Surface Leaks & Fleet Panels | bank_surface | Internal IPs / hostnames leaked on branch & ATM locator pages, ATM fleet-management panel fingerprints. Detection only, read-only GETs. |
| card_validator | Card Validator | card_validator | Report ONLY complete card records: 16-digit Luhn-valid PAN + MM/YY expiry + CVV found together. Partial numbers are never reported. |
| fin_ach_config | ACH Transfer Config Exposure | bankpack_pay | ACH/Nacha processing configs disclosing the file-transfer (SFTP) hosts used to move payment files - internal hostnames or IPs included. |
| fin_alerts_mail_posture | Alert Subdomain Spoofable (No SPF) | bankpack_infra | Banking alert/notification subdomains (alerts., notify., securemail., estatements.) that resolve but publish no SPF record - anyone can spoof the bank's alert sender. |
| fin_api_docs_secrets | API Docs Credential Leak | bankpack_portals | Banking API documentation (Swagger/OpenAPI/developer docs) whose examples embed live-looking client secrets, API keys or tokens. Values are masked. |
| fin_atm_journal | ATM Journal Data Exposure | bankpack_atm | Electronic-journal / receipt data served on the web surface: transaction records with masked PAN fragments, amounts and response codes. Fragments are reported as found (already masked at source). |
| fin_atm_locator_feed | ATM Locator Feed Hardware Data | bankpack_atm | ATM locator feeds that go beyond location: terminal hardware models, firmware versions, internal asset tags and service vendors. |
| fin_atm_monitor | ATM Monitoring Dashboard Exposure | bankpack_atm | ATM monitoring dashboards (MoniView, NCR Vision, K-Monitor, ProView...) reachable on public paths. Fingerprint only; no interaction with the console. |
| fin_atm_network_status | ATM Network Status Internals | bankpack_atm | Bank-published ATM network status pages that name internal switch/core systems or internal incident ticket IDs. |
| fin_atm_remote_access | ATM Remote-Access Gateway Exposure | bankpack_atm | Browser remote-access gateways (Guacamole, Thinfinity, Ericom...) reachable on the bank/ATM web surface. Fingerprint only; no session is started and no credential is tried. |
| fin_atm_status_api | ATM Status API Sensitive Fields | bankpack_atm | Public APIs returning per-terminal ATM status with internal IPs, firmware versions, cassette/cash levels or technician data. |
| fin_atm_switch_config | ATM Switch Config Exposure | bankpack_atm | Terminal/switch configuration files served publicly, disclosing transaction-switch hosts, ports and internal addresses. |
| fin_atm_updates | ATM Software Update Exposure | bankpack_atm | ATM software-update / distribution endpoints listing terminal packages and versions - a map of exactly what unpatched software the fleet runs. |
| fin_bin_config | BIN Lookup Config Exposure | bankpack_pay | BIN/IIN lookup endpoints or configs exposing the service API key or a downloadable full BIN database. |
| fin_card_form_action | Card Form Posts Off-Site / Over HTTP | bankpack_pay | Payment forms collecting card numbers whose form action posts over plain HTTP or to a foreign host instead of the bank/processor - a skimming red flag. Forms are read, never submitted. |
| fin_cert_expired | Banking Certificate Expired | bankpack_infra | TLS certificate on the banking host is expired or not yet valid, read from the certificate the server presents during a normal handshake. |
| fin_cert_mismatch | Banking Certificate Name Mismatch | bankpack_infra | TLS certificate presented for the banking host does not cover that hostname (CN/SAN mismatch). |
| fin_cert_weak | Banking Certificate Weak | bankpack_infra | Weak TLS material on the banking host: short keys, MD5/SHA1 signatures, or a legacy protocol version negotiated. |
| fin_core_backup | Core Banking Backup Exposure | bankpack_docs | Core-banking database backups (SQL dumps with accounts/loans/transactions tables) on public paths. Content is sampled, never downloaded in full. |
| fin_ct_internal_names | CT Log Internal Hostname Leak | bankpack_infra | Certificates logged in public CT logs whose names betray internal banking systems (internal, core, switch, uat, vpn hostnames). |
| fin_doc_metadata | Document Metadata Internal Leak | bankpack_docs | PDFs published on the bank domain whose metadata (Author/Title/Creator) names internal users, domain accounts or file-server paths. |
| fin_docstore_listing | Document Store Listing Exposure | bankpack_docs | Directory listings enabled on document stores (documents/files/uploads) of a bank domain, naming statements, wires, loans or backups. |
| fin_form_hidden_fields | Application Form Internal Fields | bankpack_docs | Banking application forms whose hidden fields leak internal URLs, officer/employee IDs, workflow or branch routing codes to every visitor. |
| fin_js_config | Banking JS Config Leak | bankpack_portals | Front-end banking config objects (window.__CONFIG__, apiBase, env blocks) that publish internal API hosts, IdP hosts or RFC1918 addresses to every visitor. |
| fin_locator_api | Locator API Internal Fields | bankpack_portals | Branch/ATM locator APIs that return more than public data: internal IPs/hostnames, staff emails, vault or cash-handling fields. |
| fin_login_thirdparty_scripts | Third-Party Scripts on Login/Payment Pages | bankpack_infra | Login and payment pages loading JavaScript from unexpected third-party hosts - the Magecart skimming pattern. Scripts are inventoried, never executed. |
| fin_merchant_portal | Merchant Portal Exposure | bankpack_pay | Merchant acquiring portals (Moneris, Elavon, Worldpay, Global Payments...) reachable on the public domain. Existence + fingerprint only. |
| fin_mobile_config | Mobile Banking Config Exposure | bankpack_portals | JSON config files served for the mobile-banking app that disclose internal backend hosts or embed API keys/secrets. Values are masked. |
| fin_oidc_config | Banking OIDC Config Leak | bankpack_portals | OpenID Connect discovery documents on the bank domain that point at internal issuers/token hosts or advertise legacy password grants. |
| fin_partner_portal | Partner / Agent Portal Exposure | bankpack_portals | Partner, agent, broker and advisor portals reachable on the public bank domain. Existence + fingerprint only; no login is attempted. |
| fin_payment_secrets | Payment Secret Key Exposure | bankpack_pay | Payment-processor SECRET keys (Stripe sk_live, Adyen, Square, Braintree, Checkout.com) sitting in public pages, scripts or configs. Masked + fingerprinted; never used. |
| fin_pos_config | POS Terminal Config Exposure | bankpack_pay | Point-of-sale configuration files served publicly with merchant IDs, terminal IDs, processor hosts or key IDs. |
| fin_report_exports | Financial Report Export Exposure | bankpack_docs | Financial report exports (general-ledger / daily reports) served from public paths with real money rows. |
| fin_saml_metadata | SAML Metadata Leak | bankpack_portals | SAML federation metadata served on the bank domain that exposes internal IdP/SSO hostnames or non-production entity IDs. |
| fin_sandbox_live_mismatch | Sandbox Credentials in Production Config | bankpack_pay | Production-marked payment configs that still carry sandbox/test credentials or test endpoints - the classic sign the live site never got its real (or its test) configuration separated. |
| fin_staff_directory | Staff Directory Internal Fields | bankpack_docs | Public staff directories / employee APIs exposing internal fields: extensions, employee IDs, department codes, reporting lines. |
| fin_staging_env | Staging Banking Environment Exposed | bankpack_infra | Non-production online-banking environments (uat/dev/test/staging subdomains) that resolve and serve a banking login surface to the internet. |
| fin_statement_sample | Statement Sample Internal Data | bankpack_docs | Publicly served account-statement samples/templates that still carry internal data: officer IDs, GL codes, core-banking system names, internal-use markers. |
| fin_status_internals | Status Page Internal Systems | bankpack_infra | Public status/incident pages that name internal core-banking or payment systems and internal incident ticket IDs. |
| fin_tax_sample_data | Tax Form Sample TIN Exposure | bankpack_docs | Public 'sample' 1099/tax forms carrying TIN-shaped values. Values are masked in the finding; samples must be synthetic, and real ones are reportable PII exposure. |
| fin_treasury_portal | Treasury Portal Exposure | bankpack_portals | Treasury / cash-management / corporate banking portals reachable on the public domain. Existence + fingerprint only; no login is attempted. |
| fin_webhook_secrets | Webhook Signing Secret Exposure | bankpack_pay | Webhook signing secrets (Stripe whsec_, Square signature keys, generic webhook_secret assignments) in public scripts/configs of a payment surface. Masked + fingerprinted; never used. |

### Graph (8)

| id | label | module | description |
|----|-------|--------|-------------|
| assetgraph | Asset Graph Builder | assetgraph | Build interactive attack-surface map: domains, IPs, tech, ports. |
| chain_followups | Finding Chaining | chain_followups | Phase-2 chaining: every phase-1 finding feeds a real follow-up probe or a named follow-up plugin, same target only, depth 2, capped, fully audit-logged. Links in probed pages are followed one level deeper; secrets are never used. |
| connections | Connection Mapper | connections | Map every relationship: devices, accounts, services, financial. |
| fx_arangodb_open | ArangoDB Open (no auth) | fmtpack | ArangoDB's /_api/version answering without authentication - auth is disabled or the instance is otherwise wide open. |
| fx_gremlin_open | Gremlin Server Open | fmtpack | A Gremlin Server (JanusGraph / TinkerPop) HTTP endpoint answering without authentication - its traversal endpoint executes submitted scripts by design. |
| fx_neo4j_open | Neo4j Discovery Open | fmtpack | Neo4j's HTTP discovery endpoint answering without authentication and advertising its Bolt address - the graph database's front door. |
| fx_sparql_endpoint | Open SPARQL Endpoint | fmtpack | A SPARQL endpoint answering an unauthenticated service-description request: the dataset/graph summary itself is disclosed, and a query endpoint that describes itself usually also answers queries. |
| harvester | OSINT Harvester | harvester | TheHarvester-style: emails, subdomains, hostnames from keyless public sources. |

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

**Continuous crypto scanning.** Since 2026-11-04 the contract stack
also runs as a standing operator-side schedule, separate from the
hosted services: every 30 minutes a local runner works a bounded
batch from rotating queues (roughly 5,000 contracts: the BNB Chain
long tail, a deep-layer re-scan of the known market set, fresh
contracts, and the zero-day candidate tail), checkpointing after
every contract so an interrupted batch resumes where it stopped. It
uses the same local plugin stack and the same verdict rules as
above, and it reports only when a candidate verifies live as
stranger-reachable; everything else stays in its working files.

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
| `RECON_CRAWL_MAX_PAGES` | `200` | Max pages the site crawlers enumerate per target (bounded by each crawler's time budget). Raise to go deeper. |
| `RECON_CRAWL_MAX_DEPTH` | `8` | Max link depth the crawlers follow from the seed. |
| `RECON_CRAWL_CONCURRENCY` | `16` | Parallel page fetches within a single crawl. |
| `RECON_JS_MAX_BUNDLES` | `24` | JS bundles pulled and mined for endpoints/secrets per site. |
| `RECON_JS_MAX_ENDPOINTS` | `60` | Max JS-discovered endpoints reported per sweep. |
| `RECON_CHAIN_MAX_ITEMS` | `40` | Follow-up items a single finding may chain (same-target). |
| `RECON_CHAIN_MAX_PROBES` | `60` | Confirmation probes per run in the finding-chain layer. |
| `RECON_CHAIN_MAX_SUBLINKS` | `8` | Sublinks followed off one probed page (depth stays 2). |
| `RECON_RPC_COOLDOWN_S` | `120` | Seconds a failing RPC endpoint is skipped before retry (dead-host fast-skip). |
| `RECON_CHECKPOINT_MAX_RESULT` | `65536` | Max bytes of result stored per checkpoint unit; larger results are truncated so the DB survives tight quotas. |
| `RECON_CHECKPOINT_LEASE_S` | `600` | A unit marked running this recently is skipped by a second batch (no double-scan). |
| `RECON_CHECKPOINT_WAL_EVERY` | `500` | Truncate the checkpoint WAL every N writes to bound disk use. |
| `RECON_BATCH_LOCK` | `/tmp/recon_batch.lock` | Path of the single-batch lock; only one batch runs at a time. |
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
| `recon_query_knowledge` | Query the cross-run knowledge store (assets accumulated across every finalized run) |
| `recon_get_delta` | Asset-level delta for a target between its previous and latest completed runs (`+ NEW` / `- REMOVED` / `~ CHANGED`) |

Auth: every MCP request needs the service key, as the
`X-Recon-Service-Key` header (or `Authorization: Bearer <key>`). No key
or a wrong key gets HTTP 401. See the `RECON_SERVICE_KEY` env vars
above. Setup note for the live deployment: the `RECON_SERVICE_KEY`
set on the Render backend must match the key the client presents;
a mismatch fails the handshake with 401 before any tool call, so set
the backend value first, then configure clients with the same key.

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
