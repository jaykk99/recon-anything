"""Digital twin: run a fitted program forward as a runnable model of an
entity's operational logic, for counterfactual simulation.

Everything here is HYPOTHETICAL. A twin run predicts what the program
says would happen, not what will happen. Twin output is labelled as a
counterfactual and must never be presented as a finding, a candidate, or
evidence about a live target. No actions are taken on live targets.
"""

from __future__ import annotations

import copy
import math
import random

from .program import execute_program


class DigitalTwin:
    def __init__(self, program, last_event=None):
        self.program = program
        self.source = program.to_source()
        self.state = {
            "group": last_event.group if last_event else None,
            "kind": last_event.kind if last_event else None,
        }
        self.t0 = last_event.t if last_event else 0.0

    def simulate(self, n_events, seed=0):
        """Forward Monte Carlo: n simulated future events. Returns a list
        of dicts {t, group, kind, dt_hours}. Deterministic given the seed."""
        rng_state = dict(self.state)
        t = self.t0
        out = []
        for i in range(n_events):
            step = execute_program(self.source, rng_state, seed + i * 7919)
            t += step["dt_hours"] * 3600.0
            rng_state = {"group": step["group"], "kind": step["kind"]}
            out.append({"t": t, "group": step["group"], "kind": step["kind"],
                        "dt_hours": step["dt_hours"]})
        return out

    def counterfactual(self, intervention, n_events=50, seed=0, reps=20,
                       all_groups=None):
        """Run the twin under an intervention and summarise. Interventions:
          {"remove_group": <group>} - the entity never uses that group again
            (categorical renormalised; if that empties the program's own
            support, fall back to a uniform over all_groups minus the
            removed one, or report no valid group when none is known);
          {"scale_interval": <factor>} - all gaps multiplied by factor;
          {"force_kind": <kind>} - every event is that kind.
        Returns a dict labelled hypothetical with aggregate stats over reps.
        """
        prog = copy.deepcopy(self.program)
        no_group = False
        if "remove_group" in intervention:
            g = intervention["remove_group"]
            prog.group_probs.pop(g, None)
            total = sum(prog.group_probs.values())
            if total > 0:
                for k in prog.group_probs:
                    prog.group_probs[k] /= total
            elif all_groups:
                rest = [x for x in all_groups if x != g]
                if rest:
                    prog.group_probs = {x: 1.0 / len(rest) for x in rest}
                else:
                    no_group = True
            else:
                no_group = True
            prog.group_sticky = 0.0
        if no_group:
            return {
                "hypothetical": True,
                "intervention": intervention,
                "reps": reps,
                "events_per_rep": n_events,
                "note": "intervention removes the entity's only group and "
                        "no alternative group is known; the twin has "
                        "nothing to simulate",
                "median_dt_hours": None,
                "group_share": {},
                "kind_share": {},
            }
        if "scale_interval" in intervention:
            f = float(intervention["scale_interval"])
            prog.interval_mu += math.log(f)
            prog.burst_hours *= f
        if "force_kind" in intervention:
            k = intervention["force_kind"]
            prog.kind_probs = {k: 1.0}
            prog.kind_sticky = 0.0
        twin = DigitalTwin(prog)
        twin.state = dict(self.state)
        twin.t0 = self.t0
        all_runs = [twin.simulate(n_events, seed=seed + r) for r in range(reps)]
        from collections import Counter
        groups = Counter()
        kinds = Counter()
        dts = []
        for run in all_runs:
            for ev in run:
                groups[ev["group"]] += 1
                kinds[ev["kind"]] += 1
                dts.append(ev["dt_hours"])
        dts.sort()
        n = len(dts)
        return {
            "hypothetical": True,
            "intervention": intervention,
            "reps": reps,
            "events_per_rep": n_events,
            "median_dt_hours": dts[n // 2] if n else None,
            "group_share": {k: round(v / max(1, sum(groups.values())), 3)
                            for k, v in groups.most_common(5)},
            "kind_share": {k: round(v / max(1, sum(kinds.values())), 3)
                           for k, v in kinds.most_common(5)},
        }
