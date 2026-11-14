"""Tests for the federated (FedAvg) triage scorer.

Run from backend/:  python -m pytest tests/test_nn_federated.py -v
(or python -m unittest tests.test_nn_federated -v)

Fast unit tests use synthetic rows. One test (test_partitions_real_data)
loads the real training pool to prove the partitions cover it exactly
once; it takes ~40s because batches.jsonl is 431M. No test moves raw
rows anywhere: the payload tests assert exactly that.
"""
from __future__ import annotations

import json
import math
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn import federated as F
from app.nn.features import FeatureSpec, build_vocab
from app.nn.mlp import MLP


def _row(plugin, key, label, chain="bsc", address="0x0000000000000000000000000000000000000001",
         value="SECRET_VALUE_123", source=""):
    finding = {"plugin": plugin, "key": key, "severity": "high",
               "bounty_value": "high", "confidence": 80,
               "value": value, "recipient_class": "CALLER",
               "chain": chain, "function": "withdraw",
               "evidence": {"risk": "high", "gate_analysis": "no caller gate",
                            "source_origin": "Sourcify v2"}}
    row = {"finding": finding, "label": label, "verdict": "UNVERIFIED",
           "chain": chain, "address": address, "plugin": plugin,
           "key": key, "function": "withdraw"}
    if source:
        row["source"] = {"dataset": source}
    return row


def _tiny_spec():
    # plugins=[] keys=[] -> dim 39 (see features.FeatureSpec.dim).
    spec = FeatureSpec([], [])
    assert spec.dim == 39, spec.dim
    return spec


def _tiny_xy(n=40, seed=7):
    import random
    rng = random.Random(seed)
    X, y = [], []
    for _ in range(n):
        x = [rng.uniform(-1, 1) for _ in range(39)]
        label = 1 if x[0] + x[1] > 0 else 0
        X.append(x)
        y.append(label)
    return X, y


class TestAverageStates(unittest.TestCase):
    def test_weighted_average_known_values(self):
        s1 = {"weights": [[[1.0, 2.0]], [[3.0]]],
              "biases": [[0.5], [1.5]]}
        s2 = {"weights": [[[3.0, 4.0]], [[5.0]]],
              "biases": [[1.5], [2.5]]}
        avg = F.average_states([s1, s2], [1, 3])
        self.assertEqual(avg["weights"][0][0], [2.5, 3.5])
        self.assertEqual(avg["weights"][1][0], [4.5])
        self.assertEqual(avg["biases"], [[1.25], [2.25]])

    def test_equal_weights_when_counts_equal(self):
        s1 = {"weights": [[[0.0]]], "biases": [[0.0]]}
        s2 = {"weights": [[[2.0]]], "biases": [[4.0]]}
        avg = F.average_states([s1, s2], [5, 5])
        self.assertEqual(avg["weights"][0][0], [1.0])
        self.assertEqual(avg["biases"], [[2.0]])

    def test_rejects_empty_and_mismatched(self):
        with self.assertRaises(ValueError):
            F.average_states([], [])
        with self.assertRaises(ValueError):
            F.average_states([{"weights": [[[1.0]]], "biases": [[1.0]]}], [1, 2])
        with self.assertRaises(ValueError):
            F.average_states([{"weights": [[[1.0]]], "biases": [[1.0]]}], [0])


class TestUpdatePayload(unittest.TestCase):
    def _client_and_update(self):
        spec = _tiny_spec()
        rows = [_row("plugin_a", "check_a", 1,
                     address="0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                     value="FINDING_VALUE_ALPHA"),
                _row("plugin_b", "check_b", 0,
                     address="0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                     value="FINDING_VALUE_BETA")]
        client = F.FederatedClient("vm", rows, spec, layers=[39, 4, 1])
        net = MLP([39, 4, 1], seed=42)
        return client.local_train(F.state_dict(net), epochs=1, round_no=1), rows

    def test_payload_keys_are_weights_only(self):
        update, _rows = self._client_and_update()
        self.assertEqual(set(update), set(F.UPDATE_KEYS))
        for bad in ("rows", "findings", "finding", "labels", "label",
                    "addresses", "address", "evidence", "value"):
            self.assertNotIn(bad, update)

    def test_no_raw_finding_rows_in_payload(self):
        update, rows = self._client_and_update()
        # Addresses and finding VALUES must never appear. Plugin ids
        # and finding keys appear ONLY as bare vocabulary names in
        # the count sketch (counts, no rows) - that is by design, so
        # they are not forbidden here.
        forbidden = []
        for r in rows:
            forbidden.append(r["address"])
            forbidden.append(r["finding"]["value"])
        leaks = F.payload_contains_row_material(update, forbidden)
        self.assertEqual(leaks, [], f"payload leaked row material: {leaks}")
        blob = json.dumps(update)
        self.assertNotIn("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", blob)
        self.assertNotIn("FINDING_VALUE_ALPHA", blob)
        # The sketch carries counts only: no finding dict, no label.
        sketch = update["vocab_sketch"]
        self.assertEqual(sketch["plugins"], {"plugin_a": 1, "plugin_b": 1})
        self.assertEqual(sketch["keys"], {"check_a": 1, "check_b": 1})

    def test_validate_rejects_smuggled_keys(self):
        update, _ = self._client_and_update()
        bad = dict(update)
        bad["findings"] = [{"plugin": "x"}]
        with self.assertRaises(ValueError):
            F.validate_update_payload(bad, [39, 4, 1])
        bad = dict(update)
        bad["rows"] = []
        with self.assertRaises(ValueError):
            F.validate_update_payload(bad, [39, 4, 1])

    def test_validate_rejects_bad_shapes_and_values(self):
        update, _ = self._client_and_update()
        bad = dict(update)
        bad["layers"] = [39, 8, 1]
        with self.assertRaises(ValueError):
            F.validate_update_payload(bad, [39, 4, 1])
        bad = dict(update)
        bad["n"] = 0
        with self.assertRaises(ValueError):
            F.validate_update_payload(bad, [39, 4, 1])
        bad = dict(update)
        bad["weights"] = [[[float("nan")]]]
        with self.assertRaises(ValueError):
            F.validate_update_payload(bad, [39, 4, 1])
        # A good payload validates.
        F.validate_update_payload(update, [39, 4, 1])


class TestPartitions(unittest.TestCase):
    def test_synthetic_partitions_cover_pool_once(self):
        own = ([_row("p1", "k1", 1, chain="bsc") for _ in range(5)]
               + [_row("p2", "k2", 0, chain="ethereum") for _ in range(3)]
               + [_row("p3", "k3", 1, chain="base") for _ in range(2)])
        ext = ([_row("p4", "k4", 1, source="scabench") for _ in range(4)]
               + [_row("p5", "k5", 1, source="defihack") for _ in range(4)]
               + [_row("p6", "k6", 0, source="sherlock-invalid")
                  for _ in range(3)]
               + [_row("p7", "k7", 1, source="audit-findings")
                  for _ in range(2)]
               + [_row("p8", "k8", 1, source="xanoutas") for _ in range(2)])
        parts = F.partition_training_pool(own, ext)
        total = sum(len(v) for v in parts.values())
        self.assertEqual(total, len(own) + len(ext))
        seen = set()
        for rows in parts.values():
            for r in rows:
                self.assertNotIn(id(r), seen)
                seen.add(id(r))
        self.assertEqual(len(parts["vm"]), 5 + 4 + 2)
        self.assertEqual(len(parts["linux-box"]), 3 + 2 + 4 + 2)
        self.assertEqual(len(parts["phone"]), 3)
        # Phone client is all likely-FP by construction.
        self.assertTrue(all(r["label"] == 0 for r in parts["phone"]))

    def test_sketch_merge_matches_build_vocab(self):
        rows = ([_row("pa", "ka", 1) for _ in range(6)]
                + [_row("pb", "kb", 0) for _ in range(4)]
                + [_row("pc", "kc", 1) for _ in range(2)])
        spec_vocab = build_vocab([r["finding"] for r in rows])
        spec_sketch = F.merge_sketches(
            [F.client_vocab_sketch(rows[:6]),
             F.client_vocab_sketch(rows[6:])])
        self.assertEqual(spec_sketch.plugins, spec_vocab.plugins)
        self.assertEqual(spec_sketch.keys, spec_vocab.keys)

    def test_partitions_real_data(self):
        """Real pool: 580 own-train + 1,922 external = 2,502 rows,
        covered exactly once; holdout (145) in none of them."""
        data = F.load_federated_data()
        self.assertEqual(len(data["own_train"]), 580)
        self.assertEqual(len(data["holdout"]), 145)
        self.assertEqual(len(data["external"]), 1922)
        parts = F.partition_training_pool(data["own_train"],
                                          data["external"])
        total = sum(len(v) for v in parts.values())
        self.assertEqual(total, 2502)
        holdout_ids = {id(r) for r in data["holdout"]}
        seen = set()
        for rows in parts.values():
            for r in rows:
                self.assertNotIn(id(r), seen)
                seen.add(id(r))
                self.assertNotIn(id(r), holdout_ids)


class TestFedAvgEndToEnd(unittest.TestCase):
    def test_parallel_matches_sequential(self):
        """Parallel client training must be bit-identical to
        sequential: same clients, same global state, same seeds."""
        spec = _tiny_spec()
        X, y = _tiny_xy(60)
        layers = [39, 4, 1]
        server = F.FederatedServer(spec, layers=layers)
        state = server.global_state

        def mk(cid, Xs, ys):
            rows = [{"finding": {"plugin": "p", "key": "k"},
                     "label": v} for v in ys]
            c = F.FederatedClient(cid, rows, spec, layers=layers)
            c.X, c.y = Xs, ys
            return c

        clients = {"vm": mk("vm", X[:30], y[:30]),
                   "linux-box": mk("linux-box", X[30:], y[30:]),
                   "phone": mk("phone", X[:10], y[:10])}
        seq = F._train_clients(clients, state, 1, 1, jobs=1)
        par = F._train_clients(clients, state, 1, 1, jobs=3)
        self.assertEqual(seq, par)

    def test_two_rounds_tiny_problem(self):
        spec = _tiny_spec()
        X, y = _tiny_xy(60)
        rows_a = [{"finding": {"plugin": "pa", "key": "ka"},
                   "label": yy} for yy in y[:30]]
        rows_b = [{"finding": {"plugin": "pb", "key": "kb"},
                   "label": yy} for yy in y[30:]]
        # Features for the synthetic rows are degenerate (same
        # finding dict per client), so drive the clients with the
        # synthetic X directly: this tests the FedAvg machinery,
        # not the feature extractor.
        layers = [39, 4, 1]
        server = F.FederatedServer(spec, layers=layers)
        ca = F.FederatedClient("a", rows_a, spec, layers=layers)
        cb = F.FederatedClient("b", rows_b, spec, layers=layers)
        ca.X, ca.y = X[:30], y[:30]
        cb.X, cb.y = X[30:], y[30:]
        for rnd in (1, 2):
            updates = [ca.local_train(server.global_state, 2, rnd),
                       cb.local_train(server.global_state, 2, rnd)]
            server.aggregate(updates)
        m = server.evaluate(X, y)
        self.assertIn("accuracy", m)
        self.assertIn("roc_auc", m)
        self.assertTrue(0.0 <= m["accuracy"] <= 1.0)
        self.assertTrue(math.isfinite(m["roc_auc"]))
        self.assertEqual(server.round, 2)

    def test_http_round_trip_localhost(self):
        spec = _tiny_spec()
        layers = [39, 4, 1]
        srv = F.FederatedHTTPServer(spec, host="127.0.0.1", port=0,
                                    expected_clients=["vm"],
                                    layers=layers)
        srv.start()
        try:
            port = srv.httpd.server_address[1]
            rows = [_row("pa", "ka", 1), _row("pb", "kb", 0)]
            remote = F.RemoteClient("vm", rows,
                                    f"http://127.0.0.1:{port}")
            res = remote.train_round(epochs=1, round_no=1)
            self.assertTrue(res.get("ok"))
            status = remote._req("GET", "/status")
            self.assertEqual(status["updates_received"], ["vm"])
            done = remote._req("POST", "/aggregate")
            self.assertTrue(done.get("ok"))
            self.assertEqual(done["round"], 1)
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
