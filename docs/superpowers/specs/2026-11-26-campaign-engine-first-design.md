# Campaign engine-first: design

**Status:** approved and implemented (2026-11-26)
**Date:** 2026-11-26
**Chosen slice:** Engine-first (A)

## Why

The campaign lane already matches ARTEX's loop shape (goals -> intents ->
workers -> dual graph -> write-back -> replan, with scope, approvals,
budgets and receipts). What it does not match is the machinery around the
loop: ARTEX plans with an LLM, runs three workers in parallel, records
every exchange through a MITM proxy, and retests findings. This build
closes those four gaps **without** adopting ARTEX's dependencies or
loosening the project's read-only boundary.

Success means: an operator can point a campaign at an authorized target,
get a plan that may come from a model but is re-validated deterministically,
watch intents run concurrently, hand over a complete redacted evidence
archive (JSONL + HAR), and retest any finding to reproducible/fixed.

## Goals

1. Optional LLM planner behind the existing `next_intents()` contract.
   Model output is a proposal; scope, action catalog and worker kinds
   validate every intent before it can run. No model configured -> the
   deterministic planner, unchanged.
2. Parallel intent execution with configurable concurrency (`max_parallel`,
   default 3, matching ARTEX's worker count) while write-back stays
   single-threaded and deterministic.
3. Full exchange evidence: every request/response captured to a sidecar
   JSONL archive with auth/cookie headers redacted, plus a HAR 1.2 export
   endpoint. In-process recording, no proxy, no CA install.
4. Retest: re-run the check behind a stored finding and record
   `reproducible` / `fixed` / `unconfirmed`, with the new receipt.
5. REST + MCP surfaces for retest, and `max_parallel` on start.
6. Tests for all of it; no new runtime dependencies.

## Non-goals

- The campaigns console (option B) and the database/shared-graph migration
  (option C). They follow separately.
- Shell, nmap, Playwright, arbitrary command execution, exploit payloads,
  credential replay, writes to targets, or post-exploitation.
- A persistent distributed queue. Concurrency is per-process waves.
- Token accounting (there is no required model), multi-tenancy, retest
  scheduling, alerts.

## Anti-goals

- An LLM that can widen scope, invent an action, or bypass approval.
- Evidence that hides what decided a finding, or that stores credentials
  in clear.
- Non-deterministic graph writes or tests that flap.
- Unbounded disk use from captured bodies.

## Constraints

- Python stdlib only; HTTP for the model uses `urllib.request`.
- Injectables stay injectable: `fetch`, `sleep`, `clock`, and now `llm`.
- Existing tests run directly (`python tests/test_campaign.py`) and under
  pytest; MCP tool-set assertions are exact.
- Campaign state stays under `data/campaigns/` (gitignored).
- No model key is available in this environment: the LLM path is tested
  with an injected fake, never a live call.

## Approaches considered

| Area | Options | Pick | Why |
|---|---|---|---|
| Evidence | (a) enrich existing receipts only; (b) sidecar JSONL + HAR export; (c) MITM recording proxy | **b** | (a) loses bodies; (c) needs a CA and a listener, which is the invasive part of ARTEX. (b) is complete, portable and testable. |
| Concurrency | (a) persistent queue + worker threads + leases; (b) per-round wave with `ThreadPoolExecutor`; (c) multiprocessing | **b** | The loop is round-based; a wave keeps budget and graph writes deterministic. (a) adds claim/lease states the engine does not need yet. (c) cannot share the injectable fetch. |
| Planner | (a) LLM replaces the planner; (b) LLM augments it, validated, with fallback; (c) no LLM | **b** | (a) makes an external service a hard dependency and lets a bad completion stall a run. (b) keeps ARTEX's capability and this project's guarantee. |
| Retest | (a) manual re-scan; (b) re-execute the originating action; (c) re-run the whole campaign | **b** | Scoped, cheap, and gives a verdict tied to the same finding id. |

## How it works

### 1. Evidence archive (`campaign/evidence.py`)

- `EvidenceRecorder` wraps a fetch callable; it records method, URL,
  status, response headers (redacted), body (cap 64 KiB, sha256 always,
  `truncated` flag) and a timestamp. Appends are lock-protected and
  thread-safe because workers run in parallel.
- Redaction: `authorization`, `proxy-authorization`, `cookie`,
  `set-cookie`, `x-api-key` become `[redacted]`; everything else kept.
  Bodies are kept (they are the proof) but capped.
- `save(path)` writes JSONL; `to_har()` renders HAR 1.2 with one entry per
  exchange. Archive path is `<campaign id>.evidence.jsonl` beside the
  campaign JSON.
- `run_campaign(..., evidence=recorder)` installs the wrapper once, so
  probes, workers and verify steps all record without knowing.
- REST: `GET /api/campaigns/{id}/evidence.har` returns the HAR (404 when
  absent). The campaign result carries an `evidence` summary (count,
  bytes, archive name) so the report can cite it.

### 2. Parallel waves (`campaign/engine.py`, `campaign/scope.py`)

- `Scope.max_parallel` (default 3, clamped 1..8), serialized with the rest
  of the scope.
- Per round: gate and budget-check intents in the main thread, submit up
  to `max_parallel` at a time, then record results in submission order.
  Budget is spent before submission, so concurrency cannot outspend it.
- Per-host pacing is applied at submission, not completion, so parallel
  work still respects `per_host_rps`.
- A worker failure still becomes a failed attempt; one failure never
  aborts the wave.
- Determinism: the plan, the budget and the graph writes are decided in
  the main thread; only the I/O inside a worker overlaps.

### 3. LLM planner (`campaign/llm_planner.py`)

- `propose_intents(llm, graph, scope, goals, limit)` sends a compact
  situation report (goals, scope roots, asset/finding titles, attempted
  keys, available actions) and asks for JSON:
  `{"intents":[{"kind","action","target","goal","why","priority"}]}`.
- Validation, in order: JSON shape -> known kind -> known action
  (`surface`, a probe id, `enumerate:<known console>`, `bucket-list`,
  `jwt-forge`) -> target in scope -> not attempted/pending -> approval flag
  forced for `impact`. Anything else is dropped and counted in
  `meta.llm_dropped`. Output is data, never instructions.
- Merge: chained deterministic impact intents first, then validated model
  intents, then deterministic probes; dedupe by `Intent.key`; cap at
  `limit`.
- Transport: `default_llm()` reads `RECON_CAMPAIGN_LLM_URL`,
  `RECON_CAMPAIGN_LLM_MODEL`, `RECON_CAMPAIGN_LLM_API_KEY` and posts an
  OpenAI-compatible chat completion with a 20 s timeout. Unset -> `None`.
  Any error (transport, JSON, validation) falls back to the deterministic
  plan for that round and is noted, never raised.
- The engine still re-checks `scope.allows_intent` before execution, so
  even a validated intent cannot escape scope.

### 4. Retest (`campaign/retest.py`)

- `retest_finding(result, finding_id, fetch=...)` loads the stored graph,
  finds the finding, infers the originating worker action, and re-runs it
  once with a fresh 6-request budget against the same target.
- Verdict: `reproducible` when the same finding id is produced again;
  `fixed` when the action ran cleanly and did not; `unconfirmed` when the
  action could not run (no worker, target error, missing approval scope).
- Appends `{finding_id, verdict, at, receipt}` to `result["retests"]`,
  rerenders nothing; the report gains a "Retests" section.
- REST: `POST /api/campaigns/{id}/retest` with `{finding_id}`; scope and
  approval flags are re-checked from the stored campaign, so an `impact`
  retest requires `allow_exploit_confirm`.
- MCP: `recon_campaign_retest` (tool count 65 -> 66), and `max_parallel`
  on `recon_campaign_start`.

### 5. Docs and report

- README campaign section: the four additions, env vars, evidence/HAR and
  retest endpoints, and the unchanged read-only boundary.
- Report: evidence summary line, retest verdicts, and a note when the plan
  came from a model.

## Tests

- Evidence: redaction of Authorization/Cookie, body cap + sha256, HAR
  structure, archive written by a campaign run.
- Parallel: two intents against a fake target that blocks on a barrier
  must both succeed (sequential execution would time out); default
  `max_parallel=1` still runs in order.
- LLM: valid proposal accepted, out-of-scope / unknown-action / unapproved
  impact proposals dropped, transport error falls back, deterministic
  output unchanged with `llm=None`.
- Retest: docker finding against still-open fake -> `reproducible`;
  against a 401 fake -> `fixed`; unknown finding -> error.
- Existing 14 campaign + 14 probe tests and 47 MCP tests stay green.

## Risks and mitigations

- **Prompt injection through target content**: the prompt carries only
  graph titles/targets, never raw bodies, and all output is validated.
- **Evidence growth**: 64 KiB per body, per-campaign file, gitignored.
- **Concurrency races**: single-threaded planning/write-back; recorder
  locked; budget spent before dispatch.
- **LLM stalls**: 20 s timeout, per-round fallback, budget unaffected.
- **Retest false "fixed"**: a transport failure is `unconfirmed`, not
  `fixed`; only a clean negative is `fixed`.

## Rollout

One commit on `master` after approval: new modules, engine/routes/MCP
wiring, tests, README. No push unless asked.
