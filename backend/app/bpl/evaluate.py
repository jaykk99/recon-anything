"""Evaluation runner: fit BPL programs on real deployer + transition
timelines, score on held-out events, compare against baselines.

Usage (from the worktree root):
    PYTHONDONTWRITEBYTECODE=1 python3 -m backend.app.bpl.evaluate

Prints a JSON report to stdout. No files are written by this script; the
caller captures stdout. All numbers come from real held-out events.
"""

from __future__ import annotations

import json
import sys

from . import baselines, data
from .likelihood import log_likelihood, per_event_ll, posterior
from .search import fit_program
from .twin import DigitalTwin

SEED = 42


def _evaluate_domain(name, timelines, min_events=5):
    fitted = []
    skipped = 0
    for tl in timelines:
        train, hold = data.train_holdout_split(tl)
        if train is None:
            skipped += 1
            continue
        # Per-entity support: only groups/kinds this entity actually used
        # in training. Global support would spread the categoricals over
        # ~100 kinds and drown the signal (and the description length).
        groups = sorted({e.group for e in train})
        kinds = sorted({e.kind for e in train})
        best, _, _ = fit_program(train, groups, kinds, seed=SEED,
                                 mcmc_iters=1500, generations=25)
        per = {
            "periodic": baselines.fit_periodic(train),
            "markov": baselines.fit_markov(train),
        }
        row = {
            "entity": tl.entity,
            "n_train": len(train),
            "n_holdout": len(hold),
            "bpl_holdout_ll": log_likelihood(best, hold),
            "bpl_holdout_per_event": per_event_ll(best, hold),
            "bpl_train_posterior": posterior(best, train),
            "bpl_description_bits": round(best.description_length_bits(), 1),
            "bpl_program": best.describe(),
            "bpl_source": best.to_source(),
        }
        for label, prog in per.items():
            row["%s_holdout_ll" % label] = log_likelihood(prog, hold)
            row["%s_holdout_per_event" % label] = per_event_ll(prog, hold)
        row["bpl_beats_periodic"] = row["bpl_holdout_ll"] > row["periodic_holdout_ll"]
        row["bpl_beats_markov"] = row["bpl_holdout_ll"] > row["markov_holdout_ll"]
        fitted.append(row)
    return {
        "domain": name,
        "entities_fitted": len(fitted),
        "entities_skipped_too_short": skipped,
        "total_holdout_events": sum(r["n_holdout"] for r in fitted),
        "bpl_beats_periodic": sum(1 for r in fitted if r["bpl_beats_periodic"]),
        "bpl_beats_markov": sum(1 for r in fitted if r["bpl_beats_markov"]),
        "mean_bpl_per_event": (
            sum(r["bpl_holdout_per_event"] for r in fitted) / len(fitted)
            if fitted else None
        ),
        "mean_periodic_per_event": (
            sum(r["periodic_holdout_per_event"] for r in fitted) / len(fitted)
            if fitted else None
        ),
        "mean_markov_per_event": (
            sum(r["markov_holdout_per_event"] for r in fitted) / len(fitted)
            if fitted else None
        ),
        "rows": fitted,
    }


def main():
    deploy_tls, deploy_stats = data.load_deploy_timelines()
    trans_tls, trans_stats = data.load_transition_timelines()
    deploy = _evaluate_domain("deployer", deploy_tls)
    trans = _evaluate_domain("owner_transition", trans_tls)

    # Worked example: the busiest deployer, and its digital twin.
    worked = None
    if deploy["rows"]:
        top = max(deploy["rows"], key=lambda r: r["n_train"] + r["n_holdout"])
        tl = next(t for t in deploy_tls if t.entity == top["entity"])
        train, _ = data.train_holdout_split(tl)
        groups = sorted({e.group for e in train})
        kinds = sorted({e.kind for e in train})
        best, _, _ = fit_program(train, groups, kinds,
                                 seed=SEED, mcmc_iters=1500, generations=25)
        twin = DigitalTwin(best, last_event=train[-1])
        worked = {
            "entity": top["entity"],
            "n_events": len(tl),
            "program": top["bpl_program"],
            "description_bits": top["bpl_description_bits"],
            "source": top["bpl_source"],
            "holdout_ll": top["bpl_holdout_ll"],
            "markov_holdout_ll": top["markov_holdout_ll"],
            "periodic_holdout_ll": top["periodic_holdout_ll"],
            "twin_next_5": twin.simulate(5, seed=7),
            "twin_counterfactual_remove_top_group": twin.counterfactual(
                {"remove_group": max(best.group_probs, key=best.group_probs.get)}
                if best.group_probs else {}, n_events=50, seed=7, reps=20,
                all_groups=data.all_groups(deploy_tls)[0]),
        }

    report = {
        "engine": "bpl-solomonoff",
        "seed": SEED,
        "note": "All scores are log-likelihood on real held-out events. "
                "Higher (less negative) is better. Twin outputs are "
                "labelled hypothetical counterfactuals, never findings.",
        "deploy_data": deploy_stats,
        "transition_data": trans_stats,
        "deployer": deploy,
        "owner_transition": trans,
        "worked_example": worked,
    }
    if "--compact" in sys.argv:
        for domain in (deploy, trans):
            for row in domain["rows"]:
                row.pop("bpl_source", None)
    print(json.dumps(report, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
