# Federated learning for the triage scorer

Status: implemented on branch `feat/nn-federated`, demo run on this VM
only (3 local partitions). No second live device took part in the
numbers below. See "Honest limits".

## What it is

The same 255-64-32-1 triage MLP as the centrally trained v2 model
(`backend/app/nn/train.py`), trained with FedAvg across Jay's own
machines **without moving raw findings off any device**. Each client
trains locally on its own partition and sends only weight updates;
the server aggregates them with a sample-weighted average and sends
back the global model.

- Client: `FederatedClient` in `backend/app/nn/federated.py` —
  local training + update packaging.
- Server / aggregator: `FederatedServer` (in-process) and
  `FederatedHTTPServer` (stdlib HTTP, so a real device can join).
- Transport: in-process calls for the demo; real HTTP
  (`GET /model`, `POST /update`, `POST /aggregate`, `GET /status`)
  for remote clients. Pure Python stdlib, no new dependencies.

## What moves, what never moves

Per client per round, the update payload contains ONLY:

| field | content |
|---|---|
| `protocol` | `recon-nn-fedavg/1` |
| `client_id`, `round` | who, which round |
| `n` | how many rows the client trained on |
| `layers`, `weights`, `biases` | the model update (floats) |
| `vocab_sketch` | plugin/key frequency COUNTS (bare names + counts) |

It never contains finding dicts, labels, verdicts, addresses,
contract code, values, or evidence. The packaging function
(`package_update`) has no code path that could put a row in, the
server (`validate_update_payload`) rejects any payload with extra
keys, wrong layer sizes, non-finite weights, or `n < 1`, and
`tests/test_nn_federated.py::TestUpdatePayload` scans a serialised
payload for address/value material and asserts it is absent.

The feature vocabulary is agreed the same way: clients send count
sketches, the server merges them (`merge_sketches`) into the shared
top-24 plugin/key vocab. Counts, not rows.

## Rules (non-negotiable)

- Triage / prediction only. The model ranks findings by how much
  they look like past candidates that survived triage. It never
  predicts `VERIFIED_REAL`: there are zero verified-real positives
  in the data.
- Detection only, read-only live probes, no transactions, no
  drains. `crypto.com` is never a target.
- Raw findings never leave a device; only weight updates move.

## The demo (what the numbers are)

```
python -m app.nn.federated demo [--rounds 4] [--local-epochs 2]
    [--central-epochs 8] [--jobs 3] [--out backend/app/nn]
```

- Fixed holdout: 145 of Jay's own rows (stratified split of the 725
  own rows, 20%, seed 42): 124 worth-validating / 21
  likely-false-positive. Never trained on by any client, the
  server, or the central baseline. Every model below is scored on
  this same holdout.
- Training pool: the other 580 own rows + all 1,922 external rows
  = 2,502 rows, split into 3 non-IID partitions (deterministic,
  every row used exactly once — proven by
  `test_partitions_real_data`):

| client (stands in for) | rows | make-up |
|---|---|---|
| `vm` (this VM) | 1,315 | own bsc rows + external scabench + xanoutas |
| `linux-box` (Linux box) | 894 | own non-bsc rows + external defihack + audit-findings |
| `phone` (phone) | 293 | external sherlock-invalid ONLY — all likely-false-positive |

  The phone partition is label-skewed on purpose: it is the honest
  stress case. Its local-only model is expected to be degenerate
  (it has never seen a positive row), and FedAvg has to survive it.
- FedAvg: 4 rounds x 2 local epochs per client (8 local epochs
  per client total), lr 0.05, batch 32, seed 42. Client training
  within a round runs in parallel (one fork worker per client,
  `--jobs 3`); the math is identical to sequential training.
- Local-only: each client trains 8 epochs on its own partition.
- Central baseline: one model, whole 2,502-row pool, 8 epochs —
  the same number of passes over each row as the federated
  clients did, so the gap between federated and central is the
  privacy cost at equal work, not an epoch-budget artifact. The
  quoted 60-epoch v2 numbers are in the table for reference.

### Results (fixed 145-row holdout, seed 42)

<!-- METRICS-START: filled by the demo run 2026-11-14 (4 rounds x 2 local epochs, central 8 epochs equal work) -->
| model | test acc | ROC AUC | confusion (tn/fp/fn/tp) | likely-FP recall | worth-validating recall |
|---|---|---|---|---|---|
| v1 baseline, quoted (81-32-16-1, own rows only) | 0.8897 | 0.9781 | 21 / 0 / 16 / 108 | 1.000 | 0.871 |
| v2 central, quoted (255-64-32-1) | 0.9103 | 0.9697 | — | — | — |
| federated (this run, 4 rounds x 2 ep) | 0.9172 | 0.9731 | 19 / 2 / 10 / 114 | 0.905 | 0.919 |
| central v2, reproduced here (8 ep, same holdout+spec, equal work) | 0.9241 | 0.9670 | 13 / 8 / 3 / 121 | 0.619 | 0.976 |
| local-only vm (8 ep) | 0.9172 | 0.9689 | 15 / 6 / 6 / 118 | 0.714 | 0.952 |
| local-only linux-box (8 ep) | 0.8759 | 0.7746 | 8 / 13 / 5 / 119 | 0.381 | 0.960 |
| local-only phone (8 ep) | 0.1448 | 0.4528 | 21 / 0 / 124 / 0 | 1.000 | 0.000 |

Honest read: federated accuracy (0.9172) sits 0.007 below the
equal-work central baseline (0.9241) — that is the privacy cost on
accuracy — but federated AUC (0.9731) beats central (0.9670), and
federated likely-FP recall (0.905) is far above central (0.619):
the phone client's all-negative partition teaches the global
model the minority class the central run mostly misses at this
epoch budget, at the cost of worth-validating recall (0.919 vs
0.976). No single winner; it is a trade-off, not a pure loss.
Federated also beats local-only vm on AUC (0.9731 vs 0.9689) and
likely-FP recall (0.905 vs 0.714) at the same accuracy — the
federation helped the biggest client on the minority class.
Local-only phone is degenerate by construction (it has never seen
a positive row: it predicts everything likely-FP, acc 0.1448).
Federated beats the quoted v2 numbers on both accuracy and AUC,
but the quoted v2 run used a different setup (60 epochs, its own
spec build), so the controlled comparison is federated vs the
reproduced central baseline above, not vs the quote.
<!-- METRICS-END -->

Reading the table: the majority baseline on this holdout is
124/145 = 0.8552 (predict "worth-validating" for everything), so
accuracy near 0.855 means nothing was learned; judge by
likely-false-positive recall and ROC AUC. If federated scores below
central, that gap is the expected privacy cost — federated training
never sees centralised data — not a bug to hide. Any 100% would be
flagged as overfit, not a win. Per-round federated metrics are in
`federated-viewer-data.json` (`history`).

The federated model ships as `backend/app/nn/federated-weights.json`
(+ `federated-viewer-data.json`), in the same `recon-nn-weights/1`
format as the central weights, so the normal pipeline loads it
unchanged:

```python
from app.nn.federated import load_federated_model
model = load_federated_model()  # or load_model(path) from app.nn.pipeline
```

## Pointing it at a real second device (via the bridge)

Checked 2026-11-14: the linuxtomux bridge server on this VM is NOT
running (nothing on port 8765, no `monico-server` process, last
bridge activity Nov 5), and no Linux box or phone is reachable.
That is why the demo above is local partitions only. When a device
is online, the real run is:

1. **Start the bridge.** On the Linux box (or this VM):
   `monico-server start` — it prints a 4-digit code. On the phone:
   `monico-connect`, enter the code. Confirm the device shows up
   (`/api/devices` on port 8765, `X-Pair-Key` auth).
   Both sides must be on the same bridge version (the 4-digit flow
   needs the Nov 12 build or later on both ends).
2. **Start the aggregator on this VM** (the machine that holds the
   holdout for scoring — the holdout never leaves it):
   ```
   cd <repo>/backend
   FEDERATED_TOKEN=<a long random token> python -m app.nn.federated serve \
       --host 0.0.0.0 --port 8766 --clients vm,linux-box,phone
   ```
   Bind `127.0.0.1` (default) for local-only. `0.0.0.0` only on a
   trusted LAN, and always set `FEDERATED_TOKEN` when the port is
   reachable beyond localhost — without a token the server accepts
   updates from anyone who can reach it.
3. **Run the client on the remote device.** From this VM, via the
   bridge (the remote device needs the repo checked out and its own
   scanner results at its own `candidates.jsonl` / `batches.jsonl`):
   ```
   # via /api/exec (pairing-key auth), or directly on the device:
   cd <repo>/backend
   FEDERATED_TOKEN=<same token> python -m app.nn.federated client \
       --server http://<vm-lan-ip>:8766 --client-id linux-box \
       --data-mode own-only --rounds 4 --local-epochs 2
   ```
   `--data-mode own-only` trains on that device's OWN rows only —
   that is the real deployment. `--data-mode partition` (default)
   takes the named slice of the local pool and exists only for the
   local demo. The client fetches the global model (`GET /model`),
   trains locally, and `POST`s only the weight update.
4. **Aggregate.** After every expected client has posted its
   update for the round (`GET /status` shows who is in), trigger:
   `curl -X POST http://<vm-lan-ip>:8766/aggregate` (with
   `Authorization: Bearer <token>` when a token is set). Repeat
   for each round, or script steps 3–4 in a loop. Score the global
   model on the holdout from this VM afterwards.
5. **The phone over the bridge proxy.** The phone reaches the LAN
   aggregator the same way it reaches anything on the Linux box's
   LAN; if the phone is remote (not on the same WiFi), run the
   bridge with `--public` and point the client at an aggregator
   URL the phone can reach — that path is documented, not yet
   tested end to end. Do not claim a remote phone round happened
   until `GET /status` shows its client id and its update was
   aggregated.

## Tests

```
cd backend
python -m pytest tests/test_nn_federated.py -v
```

- `test_average_states_*`: the aggregator averages known weight
  updates exactly (weighted by client row count).
- `test_no_raw_finding_rows_in_payload`: a serialised update
  contains no address or finding-value material; keys are the
  weights-only set.
- `test_validate_rejects_*`: smuggled keys, wrong layers, `n < 1`,
  non-finite weights are all rejected.
- `test_partitions_*`: partitions cover the real 2,502-row pool
  exactly once; the 145-row holdout is in none of them; the
  sketch-merged vocab matches `build_vocab`.
- `test_fedavg_end_to_end_tiny_problem`: 2 FedAvg rounds on a
  synthetic problem, end to end.
- `test_http_round_trip_localhost`: a real HTTP round trip
  (client `POST /update`, server `/aggregate`) on localhost.

## Honest limits

- Demo ran on this VM only. `linux-box` and `phone` are local
  partitions, not live devices. Nothing here proves a remote
  device can or did train.
- The phone partition (all likely-FP) is an extreme skew; a real
  phone's data would look different, and the numbers would move.
- FedAvg with 4 rounds x 2 local epochs is a small budget; more
  rounds usually close some of the gap to central, at the cost of
  more update traffic.
- Weight updates can in principle leak information about training
  data (membership inference); this protocol does not add noise
  (no differential privacy) or secure aggregation. The guarantee
  is "no raw rows move", not "no information moves".
- The bridge was down at check time; the remote-join steps above
  are written from the bridge's own docs and server code, not from
  a live remote run.
