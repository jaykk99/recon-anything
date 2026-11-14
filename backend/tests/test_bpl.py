"""Tests for the BPL engine. Stdlib only, no network, no writes.

Run from the worktree root:
    PYTHONDONTWRITEBYTECODE=1 python3 -m pytest backend/tests/test_bpl.py -q
or without pytest:
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest backend.tests.test_bpl -v
"""

import math
import random
import unittest

from backend.app.bpl import (
    DigitalTwin,
    Program,
    execute_program,
    verify_source,
)
from backend.app.bpl import baselines, data
from backend.app.bpl.likelihood import log_likelihood, posterior
from backend.app.bpl.search import fit_program
from backend.app.bpl.synthesizer import mutate_program, random_program


def _synthetic_events(seed=1, n=60):
    rng = random.Random(seed)
    truth = Program(
        interval_mu=3.0, interval_sigma=0.5, burst_p=0.2, burst_hours=0.5,
        group_probs={"scroll": 0.8, "optimism": 0.2},
        kind_probs={"GnosisSafeProxy": 0.7, "BeaconProxy": 0.3},
        group_sticky=0.3, kind_sticky=0.4,
    )
    events = []
    t = 0.0
    state = {"group": "scroll", "kind": "GnosisSafeProxy"}
    src = truth.to_source()
    for i in range(n):
        step = execute_program(src, state, seed * 1000 + i)
        t += step["dt_hours"] * 3600.0
        state = {"group": step["group"], "kind": step["kind"]}
        events.append(data.Event(t=t, group=step["group"], kind=step["kind"]))
    return events, truth


class TestVerifier(unittest.TestCase):
    def test_generated_source_verifies(self):
        prog = Program(group_probs={"a": 1.0}, kind_probs={"x": 1.0})
        ok, reason = verify_source(prog.to_source())
        self.assertTrue(ok, reason)

    def test_rejects_import(self):
        self.assertFalse(verify_source("import os\ndef step(s, r):\n    return {}")[0])

    def test_rejects_eval_open(self):
        self.assertFalse(verify_source("def step(s, r):\n    return eval('1')")[0])
        self.assertFalse(verify_source("def step(s, r):\n    return open('/etc/passwd')")[0])

    def test_rejects_loops_and_dunders(self):
        self.assertFalse(verify_source("def step(s, r):\n    while True:\n        pass")[0])
        self.assertFalse(verify_source("def step(s, r):\n    return s.__class__")[0])

    def test_execute_is_deterministic_given_seed(self):
        prog = Program(group_probs={"a": 0.5, "b": 0.5},
                       kind_probs={"x": 0.5, "y": 0.5})
        src = prog.to_source()
        a = execute_program(src, {"group": "a", "kind": "x"}, seed=7)
        b = execute_program(src, {"group": "a", "kind": "x"}, seed=7)
        self.assertEqual(a, b)

    def test_execute_rejects_bad_source(self):
        with self.assertRaises(ValueError):
            execute_program("import os", {}, seed=1)


class TestPrior(unittest.TestCase):
    def test_shorter_program_higher_prior(self):
        short = Program(group_probs={"a": 1.0}, kind_probs={"x": 1.0})
        long = Program(
            group_probs={"a": 0.5, "b": 0.3, "c": 0.2},
            kind_probs={"x": 0.4, "y": 0.3, "z": 0.3},
            burst_p=0.3, group_sticky=0.5, kind_sticky=0.5,
        )
        self.assertGreater(short.description_length_bits(),
                           0)
        self.assertLess(long.log_prior(), short.log_prior())

    def test_likelihood_prefers_fitting_program(self):
        events, truth = _synthetic_events()
        uniform = Program(
            interval_mu=5.0, interval_sigma=1.5,
            group_probs={"scroll": 0.5, "optimism": 0.5},
            kind_probs={"GnosisSafeProxy": 0.5, "BeaconProxy": 0.5},
        )
        self.assertGreater(log_likelihood(truth, events),
                           log_likelihood(uniform, events))


class TestSearch(unittest.TestCase):
    def test_fit_beats_periodic_on_synthetic(self):
        events, _ = _synthetic_events()
        train, hold = events[:42], events[42:]
        groups = ["scroll", "optimism"]
        kinds = ["GnosisSafeProxy", "BeaconProxy"]
        best, _, _ = fit_program(train, groups, kinds, seed=42,
                                 mcmc_iters=800, generations=10)
        base = baselines.fit_periodic(train)
        self.assertGreater(log_likelihood(best, hold),
                           log_likelihood(base, hold))
        self.assertGreater(posterior(best, train),
                           posterior(base, train))

    def test_mutation_keeps_program_valid(self):
        prog = random_program(random.Random(3), ["a"], ["x"])
        for _ in range(50):
            prog = mutate_program(prog, random.Random(4), ["a"], ["x"])
            self.assertTrue(verify_source(prog.to_source())[0])
            self.assertGreaterEqual(prog.description_length_bits(), 0)


class TestTwin(unittest.TestCase):
    def test_counterfactual_removes_group(self):
        events, _ = _synthetic_events()
        prog = Program(
            interval_mu=3.0, interval_sigma=0.5,
            group_probs={"scroll": 0.8, "optimism": 0.2},
            kind_probs={"GnosisSafeProxy": 1.0},
        )
        twin = DigitalTwin(prog, last_event=events[-1])
        cf = twin.counterfactual({"remove_group": "scroll"},
                                 n_events=50, seed=1, reps=10)
        self.assertTrue(cf["hypothetical"])
        self.assertNotIn("scroll", cf["group_share"])
        self.assertAlmostEqual(cf["group_share"].get("optimism", 0), 1.0)

    def test_counterfactual_only_group_falls_back(self):
        events, _ = _synthetic_events()
        prog = Program(
            interval_mu=3.0, interval_sigma=0.5,
            group_probs={"optimism": 1.0},
            kind_probs={"GnosisSafeProxy": 1.0},
        )
        twin = DigitalTwin(prog, last_event=events[-1])
        cf = twin.counterfactual({"remove_group": "optimism"},
                                 n_events=50, seed=1, reps=5,
                                 all_groups=["optimism", "scroll"])
        self.assertTrue(cf["hypothetical"])
        self.assertNotIn("optimism", cf["group_share"])
        self.assertAlmostEqual(cf["group_share"].get("scroll", 0), 1.0)
        cf2 = twin.counterfactual({"remove_group": "optimism"},
                                  n_events=50, seed=1, reps=5)
        self.assertEqual(cf2["group_share"], {})


class TestRealData(unittest.TestCase):
    def test_loaders_see_real_rows(self):
        tls, stats = data.load_deploy_timelines()
        self.assertEqual(stats["rows"], 370)
        self.assertGreater(stats["with_ge_5"], 0)
        tls2, stats2 = data.load_transition_timelines()
        self.assertGreaterEqual(stats2["rows"], 52)  # grows as watcher runs
        self.assertGreater(stats2["events"], 0)

    def test_split_is_time_ordered(self):
        tls, _ = data.load_deploy_timelines()
        tl = next(t for t in tls if len(t) >= 5)
        train, hold = data.train_holdout_split(tl)
        self.assertLessEqual(train[-1].t, hold[0].t)


if __name__ == "__main__":
    unittest.main()
