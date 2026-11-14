# Synthesized tools — review gate

This directory is the staging area for tools produced by the Sandboxed
Synthesizer (`backend/app/nn/synthesis.py`). It is **not** a plugin
package: the registry only scans `backend/app/plugins/`, so nothing
here ever runs in the live scanner.

## How a file gets here

1. An existing module fails on an unknown format.
2. The synthesizer infers a schema from observed examples.
3. It generates decoder source (template-based, deterministic).
4. The AST verifier checks it against a strict allowlist.
5. The sandbox runs it in an isolated subprocess (no network, temp
   working dir, hard timeout, memory cap) against held-out fixtures.
6. Only if every fixture passes is the tool staged here.

## How a file leaves here (human only)

1. Read the decoder and the synthesis report (schema, fixtures, timings).
2. Confirm it is detection-only: parsing only, no transactions, no
   drains, no exploits, no auth bypass, no private-data access.
3. Move the file into `backend/app/plugins/`.
4. Flip `HUMAN_REVIEWED` to `True` in the moved file. Until then its
   `run()` refuses to run.
5. Run the plugin health gate (`backend/tests/test_plugin_health.py`)
   before any merge. Synthesized tools are never auto-merged and never
   auto-deployed.

## What never happens

- No staged tool runs outside the sandbox before review.
- No staged tool is auto-merged, auto-deployed, or wired into the live
  scanner by any automation.
- No synthesized tool predicts `VERIFIED_REAL`. Triage only.
