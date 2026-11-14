# GNN + neuro-symbolic triage scorer

Graph neural network over contract call graphs, combined with a
symbolic rule layer, on top of the flat NN triage scorer
(`nn.md`). Pure Python stdlib, no new dependencies. Triage only:
it ranks findings worth-validating vs likely-false-positive. It
never predicts `VERIFIED_REAL`.

## Architecture

```
finding row
  -> contract graph (graph.py): nodes = target contract,
     implementation contract (proxy link), functions named on the
     contract, findings produced on the contract; edges =
     contract-implementation, contract-function, contract-finding,
     function-finding (real function-name match only)
  -> GNN (gnn.py): 2 message-passing layers, hidden 16
       h' = tanh(W_self . h + W_neigh . mean(neighbours) + b)
     mean readout (16-dim)
  -> concat with the flat 255-dim v2 finding vector
  -> MLP head [271, 32, 1] (sigmoid) -> neural score
  -> symbolic layer (symbolic.py): veto wins, boosts/dampens shift
  -> combined score + fired rules (every decision cites its rules)
```

Node features are 32-dim and reuse the v2 vocabulary (severity /
bounty ordinals, chains, sources, roles) so the graph and the flat
scorer speak the same language. Graphs are small (mean 3.68 nodes,
3.51 edges on the training set) and train on CPU.

## Real data only, no invented edges

Every node and edge traces to a real field: the row's own evidence
(`implementation_address`, `proxy_address`, `function`,
`gate_analysis`, `source_origin`, `contract_role`) or
`batches.jsonl` findings on the same `(chain, address)`. A contract
with no implementation address gets no implementation node; a
finding with no function gets no function-finding edge. No
synthetic or random edges, no simulated data anywhere in the
pipeline (Jay's Nov 14 restatement of the no-simulation rule).

Labels never leak into features or graphs: verdicts and live-probe
outcomes are label-side only. Graph context for a test row comes
from batch findings (scan output, no labels), never from other
rows' labels.

## Symbolic rules

Facts are extracted from the same real fields the features use
(`symbolic.extract_facts`). Rules are validated on the OWN-TRAIN
split only (580 rows, the real triage distribution), before
evaluation:

- boost: coverage >= 20 and precision above the training base rate
- dampen: coverage >= 20 and precision below the base rate
- veto: coverage >= 20 and precision >= 0.90 on label 0

Rules that fail validation are dropped and listed as dropped with
the reason. The veto is a boundary guard: the neural net never
overrides it, and a veto forces the combined score to 0.0.

### Validation outcome (own-train, 580 rows, base rate 0.855)

Kept: `BOOST_NO_GATE_HIGH_SEV` (+0.15), `BOOST_PROXY_IMPL` (+0.08),
`BOOST_CALLER_HIGH_CONF` (+0.10), `BOOST_HIGH_BOUNTY` (+0.05),
`BOOST_MULTI_FINDING` (+0.05). Full coverage/precision table is in
`viewer-data-gnn.json` (`rules_kept` / `rules_dropped`).

Dropped, and why (honest, not hidden):

- `VETO_FIXED_RECIPIENT`: coverage 11 in own-train (< 20),
  precision 0.909 (10/11 label 0). The finding-level
  `recipient_class` never says FIXED/HOLDER-SELF in this data; the
  signal lives in `evidence.recipient` (16/725 own rows). Two of
  those 16 are UNVERIFIED (worth-validating), so a hard veto would
  also be wrong on 2 real candidates. The veto mechanism is
  implemented and unit-tested; the data does not support firing it.
- `DAMPEN_BYTECODE_ONLY`: zero coverage — every one of the 725 own
  rows carries a `source_origin` (Sourcify v2 685, Blockscout 40).
  There is no bytecode-only candidate in this dataset to dampen.
- `DAMPEN_LOW_RISK_LOW_SEV`: coverage 15 < 20 (risk is high on 705
  of 725 rows).

## Training and evaluation protocol

Same fixed holdout as the v2 retrain, so the numbers compare
honestly:

- own rows: `candidates.jsonl` joined to `batches.jsonl` (725 rows:
  620 worth-validating / 105 likely-FP). Stratified split, seed 42:
  test = 145 (124 / 21), train = 580.
- train rows = own-train 580 + external 1,922 (public audit
  findings from ScaBench / xanoutas / defihack / Sherlock-invalid /
  audit-findings; 1,629 pos / 293 neg). Test rows are own-only.
- 30 epochs, batch 32, lr 0.05, L2 1e-4, seed 42.

### Results (fixed own-test holdout, 145 rows)

30 epochs, 2,502 train rows (own-train 580 + external 1,922), seed
42. Dataset snapshot: own 725 rows as of 2026-11-14 ~07:59 UTC;
`candidates.jsonl` was rewritten at 08:53 UTC (723 rows) by other
work, so re-running `train_gnn.py` now trains on a slightly
different split — the numbers below are the snapshot's, and
`--eval-only` now refuses to evaluate when the holdout has drifted.

| model | test acc | ROC AUC | confusion (tn/fp/fn/tp) | FP recall | WV recall |
|---|---|---|---|---|---|
| v1 MLP 81-32-16-1 | 0.8897 | 0.9781 | tn 21 fp 0 fn 16 tp 108 | 1.000 | 0.871 |
| v2 MLP 255-64-32-1 | 0.9103 | 0.9697 | tn 18 fp 3 fn 10 tp 114 | 0.857 | 0.919 |
| GNN neural-only | 0.9103 | 0.9693 | tn 19 fp 2 fn 11 tp 113 | 0.905 | 0.911 |
| symbolic-only | 0.8552 | 0.9372 | tn 0 fp 21 fn 0 tp 124 | 0.000 | 1.000 |
| GNN + symbolic (combined) | 0.9103 | 0.9666 | tn 18 fp 3 fn 10 tp 114 | 0.857 | 0.919 |

Read it straight: the GNN ties v2 on accuracy (0.9103) with
essentially the same AUC (0.9693 vs 0.9697) and a near-identical
confusion matrix — the 16-dim graph readout adds almost nothing on
these shallow graphs (mean 3.68 nodes), because the head already
sees the full 255-dim finding vector. The combined model lands on
exactly v2's confusion (18/3/10/114): the symbolic boosts flip one
neural false negative the right way and one neural true negative
the wrong way, net zero. No 100% anywhere.

### What each layer caught

The disagreement ledger (`evaluation.caught_by_symbolic` /
`caught_by_neural` in `viewer-data-gnn.json`) needs its qualifier
stated, not hidden: symbolic-only predicts everything positive on
this data (no dampen or veto rule survived validation, so nothing
ever scores below 0.5), which is why its WV recall is 1.000 and its
FP recall is 0.000. Its 11 "catches" are exactly the neural
model's 11 false negatives — the symbolic boosts lift their scores
(e.g. 0.074 → 0.224) but only 1 of the 11 actually crosses 0.5 in
the combined model. Conversely the neural net correctly rejects 19
of the 21 negatives that symbolic-only would have passed. So the
honest summary is: the symbolic layer is a blunt yes-machine here,
not a second opinion — it nudges scores up on caller-receivable,
ungated, proxy findings, and on this holdout that nudge is worth
+1 TP / −1 TN. A veto or a dampen that survived validation would
have given it a real "no" voice; none did (see above).

## Files

- `backend/app/nn/graph.py` — graph construction, node features,
  contract index from `batches.jsonl`
- `backend/app/nn/gnn.py` — message-passing layers, `CombinedNet`
  (GNN + head, joint SGD)
- `backend/app/nn/symbolic.py` — facts, rule table, validation,
  combine
- `backend/app/nn/combined.py` — `CombinedModel` (predict, score,
  evaluate, save/load), `score_finding_dicts_combined`
- `backend/app/nn/train_gnn.py` — training CLI
- `backend/app/nn/gnn-weights.json` — trained weights
  (`recon-nn-gnn-weights/1`)
- `backend/app/nn/viewer-data-gnn.json` — metrics, rules, demo
- `backend/tests/test_nn_gnn.py`, `backend/tests/test_nn_symbolic.py`
- `backend/app/nn/external_findings.jsonl` — external training rows
  (copied from the v2 retrain worktree, 2026-11-14)
- `backend/app/nn/build_external_dataset.py` — rebuilds the
  external rows from public sources

## Use

```bash
# Train (writes gnn-weights.json + viewer-data-gnn.json)
python -m app.nn.train_gnn [--epochs 30]

# Score a findings file with the combined model
python -m app.nn.score --gnn --findings findings.jsonl

# Score a live target with the combined model
python -m app.nn.score --gnn --target bsc:0x...

# Pipeline hook (default off; enable with RECON_NN_GNN=1)
from app.nn.pipeline import maybe_score_gnn
findings = maybe_score_gnn(findings)
```

## Honest limits

- Graphs are shallow stars (mean 3.68 nodes): most contracts in
  this data have one function and one or two findings, so the GNN
  sees little multi-hop structure. The call-graph depth the
  multi-hop plugin (`call_graph_multihop`, PR #178) produces is not
  in these rows — the graph cannot use edges the data does not
  carry. A deeper graph needs per-target call-graph output wired
  into the row builder.
- The test set has 21 negatives: FP recall moves in steps of ~0.05
  per row. Small differences vs v1/v2 are noise until the negative
  set grows.
- External rows are audit findings, a different distribution from
  scanner candidates; they lift the positive class but teach
  nothing about scanner false positives (the likely-FP class is
  Jay's own rows only).
- The veto does not fire on this data (see above). If Jay wants the
  boundary veto live regardless of coverage, that is a policy call,
  not a modeling one.
- Training is slow in pure Python under a loaded VM (~10 CPU-min
  for 30 epochs); the smoke run (`--smoke`: 200 rows, 2 epochs)
  exists for timing checks.
