# Sheaf Theory & Hypergraph Signal Processing for ReconAnything

Branch `feat/nn-sheaf`. Pure Python stdlib, zero new dependencies.
Triage only. Never predicts `VERIFIED_REAL`. Detection only,
read-only live probes only, no transactions, no drains, no exploit
execution, no auth bypass, no private-data access. crypto.com is
never a target.

## The idea in one paragraph

A pairwise graph can only say "A relates to B". The cover story of
a target lives one level up: a multi-sig transaction, a shared
deployer plus shared commit history plus a DNS change, an owner
transition (contract + old owner + new owner + block + time), all
the findings on one contract. Those are **hyperedges**: one event
over N entities, not N flattened rows and not N(N-1)/2 pair edges.
A **sheaf** attaches a local data space (a **stalk**) to every
entity in a hyperedge: each entity carries its own local facts
(owner, code hash, findings, timestamps) plus the source each fact
came from. A **restriction map** projects one entity's local data
onto the overlap the hyperedge claims ("the owner of this contract
at this block", "the token identity this symbol names"). Local
sections **glue** into a global section when every restriction
agrees on every overlap. When they do not agree, the disagreement
is a **hole** in the target's cover story.

## What a "hole" means, operationally

Two or more local facts that cannot all be true at once, with the
exact facts named (entity, field, value, source row). Examples:

- **Owner null-flip oscillation.** The owner timeline for a
  contract reads A -> null -> A. A renounced owner cannot return,
  so the same address coming back after a null read is a read
  glitch, not a transfer. On the real data this fires on 7
  contracts (13 obstruction instances); see Evaluation.
- **Validator does not bind the function.** A finding names
  `withdraw`; the validator's function field is empty, so the
  validation never engaged with the function the finding is about.
  10 real rows, 6 contracts.
- **VERIFIED_REAL on a failed probe.** A verified-real verdict is
  a claim about the live chain; a failed live probe leaves no live
  evidence behind it. Fires 0 times on real data (the 2 real
  `VERIFIED_REAL` rows both have successful probes), fires on
  injection.
- **One symbol, two owners.** Two contracts name the same symbol
  but restrict to different owners: the "same token" story does
  not glue. Fires 0 times on real data (no non-null symbol is
  shared by two contracts); exercised on toy input.
- **Paused hop on a candidate-grade path.** PR #178: a paused
  middle hop downgrades a call path to trigger-only. A path graded
  candidate while a hop is paused contradicts its own grading.
  Toy only; no real call paths exist on disk.

A hole is **never** proof of a vulnerability and never a
`VERIFIED_REAL` verdict. It is a triage signal: this target's story
does not add up, so a human (or the investigator loop) should look
here before trusting any single finding on it.

## Cohomology, honestly

This module does Cech-style consistency checking (local sections,
restriction maps, gluing obstructions), not a computation of sheaf
cohomology groups. The obstructions it returns play the role of a
first cohomology class: they are the precise residue that stops
local data from gluing. Nothing here pretends to be H^1 computed
over a simplicial complex. If a later module wants real cohomology
it can build it on the restriction maps defined in
`backend/app/nn/sheaf.py` (`restrict`, `OVERLAPS`).

## Modules

- `backend/app/nn/sheaf.py` -- core. `Fact`, `Stalk`,
  `Hyperedge`, `CheckResult`, restriction maps (`restrict`,
  `restrict_all`), the check registry (`CHECKS`, one list per
  hyperedge kind), `consistency(edge, pairwise=False)`,
  `check_cover` / `cover_obstructions` (sequence-level gluing
  across hyperedges), `rank_inconsistencies`, `to_hypergraph_nn`
  (interchange adapter), `copy_hyperedge`.
- `backend/app/nn/hyperedges.py` -- builders from real data:
  `build_owner_transition_hyperedges`,
  `build_finding_cluster_hyperedges`, `build_symbol_cluster_hyperedges`,
  `build_owner_cluster_hyperedges`, `build_call_path_hyperedges`,
  `build_all`, `latest_owner_map`, `load_jsonl`.
- `backend/app/nn/eval_sheaf.py` -- the evaluation runner. Prints
  a JSON report to stdout; the recorded run is
  `backend/docs/nn-sheaf-eval.json`.
- `backend/tests/test_nn_sheaf.py` -- 9 tests, pytest, stdlib only.

## Hyperedge kinds

| kind | entities | overlap | what breaks it |
| --- | --- | --- | --- |
| `owner_transition` | contract + before-owner + after-owner | `owner@after` | no-op transition (before == after) |
| `finding_cluster` | contract + its findings | `target` | validator binds a different target / function, VERIFIED_REAL on failed probe |
| `symbol_cluster` | symbol + its contracts | `token-identity` | two known owners for one symbol |
| `owner_cluster` | owner + its contracts | `control` | independent owner feed disagrees |
| `call_path` | contracts on a multi-hop path | `hop-gate` | bypass unnamed, paused hop graded candidate, unsourced hop presented firm |

Checks with weight 0 are **observations**, reported but never
scored: a null owner read, a missing block, high severity with
empty evidence and no verified source. A single null flip proves
nothing on its own; the contradiction only appears at sequence
level, which is exactly why the cover check exists.

## Scores

`consistency` returns the weighted fraction of passing scored
checks. 1.0 means every scored check passed. A hyperedge is
flagged when score < 1.0. `pairwise=True` runs the pairwise-graph
baseline: multi-entity checks are skipped, so only facts visible
from one hyperedge at a time can fail. The gap between pairwise
and full mode is exactly what hyperedges add.

## Evaluation (real numbers, 2026-11-14)

Full report: `backend/docs/nn-sheaf-eval.json`.
Re-run: `cd backend && python -m app.nn.eval_sheaf`.

Data: 727 candidates, 52 transitions, 610 distinct contracts,
0 torn rows. Hyperedges built: 52 `owner_transition`, 610
`finding_cluster`, 0 `symbol_cluster`, 8 `owner_cluster`,
0 `call_path` (670 total).

**Real flags.** 6 finding clusters flagged, all on one check
(`validation_binds_function`, 10 rows): the validator leaves the
function blank while the finding names it, e.g.
`arbitrum:0x2cab...` names `claimTokens`,
`arbitrum:0x13a7...` names `withdraw`. 0 owner-transition
hyperedges flagged on their own: a single transition is always
self-consistent.

**Real cover obstructions: 13 across 7 contracts**, all
`owner_null_flip_oscillation`. Every one of the 7 known oscillating
contracts is found (7/7): `0x2260...` (wbtc), `0x4c9e...`,
`0x501e...` (evausdt), `0x73e0...`, `0x741b...`, `0xc96d...`
(fbtc), `0xe343...` (usdg). The pairwise baseline finds 0 of 7:
no single edge holds the sequence, so a pairwise graph cannot see
an oscillation at all. That is the headline hyperedge-vs-pairwise
result, and it is real data, not a toy.

**Observations (not contradictions).** 27/52 transitions read a
null owner after; 4/52 lack a block number; 475 finding entities
claim high severity with empty evidence, a failed probe and no
verified source (the Token Hub row, `bsc:0x0e59...` / HUBBX /
`_transferShares`, is the exemplar: high severity, "no verified
source available", probe `transport_error`). 727 rows collapse to
668 finding entities: 59 duplicate (plugin, key) rows on the same
contract share one finding entity; the row count is preserved in
the contract stalk's `n_findings`.

**Labelled injected set (seed 42, synthetic fixtures).** 30
positives (5 injections x 6 types: no-op transition, validator
target mismatch, function unbind, VERIFIED_REAL on failed probe,
symbol-owner disagreement, paused hop on candidate path) + 30
untouched controls. Sheaf: precision 1.0, recall 1.0, F1 1.0
(30/30, 0 false positives). Pairwise baseline: precision 1.0,
recall 0.6667, F1 0.8 (20/30: it catches the four single-entity
injection types and misses all 10 multi-entity ones). The perfect
sheaf score here measures check coverage against deliberately
planted contradictions, not real-world precision: the injections
target the checks directly, so a high score is expected. Real-data
precision is unknown beyond the 7/7 oscillations; do not quote
1.0 as a field result.

**Toy call path.** Clean trigger-only path scores 1.0; the same
path with a paused hop graded candidate scores 0.6. Toy inputs
only; a perfect toy score is a toy result, not a win.

## Integration point with the hypergraph-NN branch

The hypergraph-NN agent (`feat/nn-hypergraph`,
`~/workspace/wt/nn-hypergraph`) had **no module written** when this
was built (checked 2026-11-14: no `backend/app/nn/` in that
worktree, no file mentioning hyperedge/hypergraph). So this branch
defines its own hyperedge primitives rather than building on its
code, and does not block on it.

The interchange shape is `to_hypergraph_nn(edge)`:

```json
{"id": "...", "kind": "finding_cluster",
 "nodes": ["contract:bsc:0x...", "finding:bsc:0x...:plugin:key"],
 "features": {"n_entities": 3, "consistency": 1.0,
              "n_failed_checks": 0, "failed_checks": [],
              "observations": []},
 "score": 1.0}
```

When the hypergraph-NN module lands, the merge point is:
import its `Hyperedge` type in `hyperedges.py` and replace the
local construction, keeping the check registry and restriction maps
here. The hypergraph network consumes one dict per hyperedge and
can use `features.consistency` as a hyperedge-level feature (or
`score` directly). The call-path hyperedge input shape is the
PR #178 `analyze_call_graph_multihop` output: ordered hop lists
with `caller`, `callee`, `function`, `gated`, `paused`,
`source_available`, plus `finding_kinds` and `grade`.

Related branches (same program, separate worktrees, do not touch):
`feat/nn-scorer` (v1 81-32-16-1, acc 0.8897, AUC 0.9781; v2
255-64-32-1, acc 0.9103, AUC 0.9697), `feat/gnn-neurosymbolic`,
`feat/nn-hypergraph`, `feat/nn-swarm`, `feat/nn-multimodal`,
`feat/nn-tda`, `feat/nn-snn`, `feat/nn-bayesian`,
`feat/nn-federated`.

## Assumptions and limits

- A null owner is treated as "unreadable", not "renounced". If
  the watcher ever records a genuine renounce as null, the
  oscillation check still holds (a renounced owner cannot return),
  but a single null flip would need a second source to adjudicate.
- `symbol_cluster` is empty on real data: no non-null symbol is
  shared by two contracts. The check is exercised on toy input
  only until a real shared symbol appears.
- `call_path` is empty on real data: no real PR #178 paths exist
  on disk for these contracts. Toy only.
- `owner_cluster` is built only from transition rows; candidates
  carry no owner field, so it covers ~10 contracts. Its
  independent-feed check is vacuous on one source and says so in
  the code; it bites only when a second owner feed is supplied.
- Injected-set precision is measured against untouched controls
  from the same pool, not against live traffic. Real-data precision
  beyond the 7 oscillations is unmeasured.
- The eval reads the two jsonl files from
  `~/workspace/recon-continuous/` by default; pass
  `--candidates` / `--transitions` to point elsewhere.
- Injected contradictions are labelled test fixtures for
  evaluating the checker (the same role as toy examples in the
  tests). They are never presented as scan results, and no
  simulated data enters the scanning pipeline. Real-data numbers
  in the eval come only from the two real jsonl files.
