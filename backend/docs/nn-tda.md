# TDA features for ReconAnything triage (`feat/nn-tda`)

Persistent-homology-style features over the contract call graph, fed
to the triage scorer as 16 extra inputs alongside the 255-feature v2
vector (271 inputs total, layers 271-64-32-1). Pure Python stdlib, no
new dependencies. Triage only: the features describe the SHAPE of a
target's call graph. They never verify anything and never predict
`VERIFIED_REAL`.

## What is computed (`backend/app/nn/tda.py`)

For one finding, `build_graph` assembles the call graph, then:

- **Betti-0 style** — connected components and their size
  distribution, via union-find.
- **Betti-1 style** — cycle count and cycle-length distribution, via
  a spanning forest: every non-tree edge closes exactly one cycle,
  whose length is the tree distance between its endpoints plus one.
  A self-loop is a cycle of length 1.
- **Filtration** — edges are swept in ascending weight order (call
  depth: 1 = direct callee, 2 = second hop, ...). Each component is
  born at weight 0 and dies when an edge merges it (persistence =
  merge weight); each cycle is born at the weight of the edge that
  closes it and lives forever. The summary is merge persistences,
  cycle births, and the (weight, beta0, beta1) curve.

Homology is over the UNDERLYING UNDIRECTED graph: call graphs are
directed (caller -> callee), but Betti numbers are a property of the
undirected shape. Direction survives only in the edge weight (call
depth), which the filtration reads.

The 16 features (`tda:*`, each scaled to [0, 1]):

| feature | meaning |
|---|---|
| `graph_present` | 1 when a graph record, depth evidence, or proxy edge was present |
| `n_nodes`, `n_edges` | graph size (/16 capped) |
| `betti0`, `betti1` | components, cycles (/8 capped) |
| `largest_component_frac` | largest component / nodes |
| `mean_component_size` | (/8 capped) |
| `components_gt1` | components with >1 node (/4 capped) |
| `max_cycle_len`, `mean_cycle_len` | (/16 capped) |
| `triangles` | cycles of length 3 (/4 capped) |
| `has_cycle` | 0/1 |
| `n_merges` | filtration merges (/8 capped) |
| `total_persistence_h0`, `max_persistence_h0` | merge persistence sums (/8, /4) |
| `earliest_cycle_birth` | smallest cycle-birth weight (/4; 0 when no cycle) |

## Where the graph comes from

In priority order, per finding:

1. `finding["call_graph"]` — a dict stamped by the caller:
   - `{"edges": [[u, v], [u, v, w], {"from": u, "to": v, ...}]}`
   - `{"call_edges": [{"from_fn": fn, "to_addr": addr, ...}]}` — the
     multihop call-graph plugin's `extract_call_edges` shape (PR #178,
     `deep_layers.py`: edges run from the target's function to the
     callee address, weight 1 unless the record carries a hop/depth).
   - `{"callees": N, "callee_layers": [...]}` — the deep-layer
     coverage record: a star, target -> N callee nodes, weight 1.
   - `{"nodes": [...], "edges": [...]}`.
2. `finding["evidence"]["depth"]` — the same deep-layer record as a
   JSON string (how batch rows store it) or a dict. This is how the
   finding of the `cross_contract_call_graph` plugin itself is read.
3. Proxy / implementation — `evidence.proxy_address` ->
   `evidence.implementation_address` is one edge (weight 1), merged
   into whatever graph the above produced.
4. Nothing — the empty graph. All 16 features read 0 and
   `graph_present` reads 0, so "no graph measured" stays distinct
   from "a graph was measured and it is trivial". A depth record with
   `callees == 0` is NOT empty: it is one node (the target) with no
   edges, `graph_present = 1`.

Train path: `data.py` indexes the target's `cross_contract_call_graph`
finding in the same batch run and stamps its record on every row for
that target. When a target was scanned several times, the record with
the most callees wins (the most complete measurement); a record whose
depth field carries no usable callee count is skipped so a later
parseable one can win. The record carries no verdict, so nothing
label-side leaks. Live path: `score.py` stamps the record from the
run's own call-graph finding on every finding (same shape).

## What the training data actually contains (measured 2026-11-14)

- Own rows: 725 (727 candidates minus 2 excluded `VERIFIED_REAL`).
  610 distinct targets; every target has >=1 call-graph finding.
- Call-graph findings in batches: 3,888. Callees distribution:
  0 in 2,437 findings, 1 in 110, 2 in 3, unusable (no callee count
  in the depth record) in 1,338.
- **1,337 targets have ONLY unusable depth records** — their graphs
  are unknown, and no record is stamped for them.
- Rows with a call-graph record: **269 of 725**. Rows with a
  non-empty graph (>0 callees or multihop edges): **7 of 725**
  (max 1 callee each).
- The other rows get TDA features from proxy/implementation edges:
  534 of 725 own rows have a 2-node proxy graph; the rest read
  all-zero (no graph evidence at all).
- **Cycles: zero.** No training row has `betti1 > 0` or `has_cycle`.
  Every training graph is empty, a single node, or a single edge.
  The cycle and filtration features are constant (all zero) on this
  data, so the network cannot learn anything from them here.
- External rows (1,922) carry no graph evidence at all: their TDA
  block is all zeros.

Consequence: on this data the TDA block can at most re-learn
proxy presence (already a v2 feature, `proxy_present`). Any delta
vs the v2 control is expected to be noise. The features are correct
and live for targets whose call-graph plugin actually returns edges
(multihop BFS 3 deep); the training data just has almost no such
targets yet. When the scanner starts returning real call graphs,
retrain: the same code will pick them up with no changes.

## Evaluation protocol

Fixed own-test holdout, the same protocol the v1/v2 numbers were
reported on: Jay's own 725 rows are split first (stratified, seed
42, test_frac 0.2 -> **145 test rows: 124 worth-validating, 21
likely-false-positive**, majority baseline 0.8552). Training uses
own-train (580) + all 1,922 external rows (2,502 total). The test
set is Jay's own data only, so the easier external rows cannot
inflate the score. Both arms below use identical settings:
60 epochs, hidden 64,32, lr 0.05, seed 42.

`python -m app.nn.train --own-holdout --external <path>` trains the
TDA model; `--no-tda` trains the v2 control on the same split.

## Results (fixed 145-row own holdout, seed 42)

| model | features | test acc | ROC AUC | WV recall | FP recall | confusion (tp/fp/fn/tn) |
|---|---|---|---|---|---|---|
| v1 (published) | 81-32-16-1 | 0.8897 | 0.9781 | — | — | — |
| v2 (published) | 255-64-32-1 | 0.9103 | 0.9697 | — | — | — |
| v2 control (this branch, reproduced) | 255-64-32-1 | _TBD_ | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| TDA (this branch) | 271-64-32-1 | _TBD_ | _TBD_ | _TBD_ | _TBD_ | _TBD_ |

Published v1/v2 numbers are quoted from the NN scorer work (own
holdout); the v2 control row is the apples-to-apples reproduction
run on this branch with the same split and seed. The shipped v2
weights on `feat/nn-scorer` report higher numbers (acc 0.9811, AUC
0.9978) because they were evaluated on the 530-row COMBINED split,
which mixes in the easier external rows — do not compare those with
the holdout numbers above.

Verdict: _TBD once both arms finish._ (Expected: no meaningful
delta — see "What the training data actually contains".)

## Wiring

- `features.py` — spec version 3; the 16 `tda:*` features are
  appended after `evidence_count`. `FeatureSpec(use_tda=False)` is
  the v2 control layout (255 inputs). `from_dict` on a v2 weights
  file (no `use_tda` key) loads TDA-off, so old weights keep working.
- `pipeline.py` — `load_model` fails closed on a feature-layout
  mismatch (`spec.dim != net.layers[0]` returns None): the forward
  pass would otherwise silently ignore extra inputs.
- `data.py` — stamps `finding["call_graph"]` per target (see above).
- `score.py` — stamps the run's call-graph record per target.
- `train.py` — `--own-holdout`, `--no-tda`; writes retry on
  transient write failures; prints a `TRAIN-RESULT-JSON` line with
  the metrics so the numbers survive even if the weights files are
  still retrying.
- `api.py`, `mlp.py` — unchanged from v2 (copied verbatim).

## Tests

`backend/tests/test_nn_tda.py` (21 tests): hand-computed toy graphs
— triangle must give 1 cycle of length 3, a 5-node tree must give 0,
two triangles sharing a vertex must give 2, a square 1 cycle of
length 4, a self-loop 1 cycle of length 1; filtration merges at
weights 1, 2 with the cycle born at 3; star/proxy/multihop/depth
construction; feature scaling and `extract()` integration; v2
weights still loading TDA-off. Run:

```
cd backend && python -m pytest tests/test_nn_tda.py tests/test_nn_features.py \
    tests/test_nn_mlp.py tests/test_nn_pipeline.py -q
```

## Limits

- Triage only. Zero verified-real positives in the data; the model
  never predicts `VERIFIED_REAL`.
- TDA signal on the current data is ~nil by construction (see
  coverage above): no cycles, 7 non-empty graphs in 725 rows.
- The filtration is H0/H1 only (no H2: call graphs have no filled
  triangles by construction — a 3-clique is a cycle, not a 2-simplex,
  in this implementation).
- Edge weights are call depth only; the implementation does not
  distinguish call types (delegatecall vs call) or value flow.
- Detection only, read-only live probes, no transactions, no drains.
  crypto.com is never a target.
