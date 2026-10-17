"""Run diff for continuous monitoring (Milestone 7).

diff(runA, runB) -> new/removed/changed findings: new subdomains,
new endpoints, changed headers, new certs, etc.
"""
from __future__ import annotations

from typing import Dict, List

from .models import Finding


def _sig(f: Finding) -> str:
    return f"{f.plugin_id}|{f.category}|{f.key}|{f.value}"


def diff_runs(session, run_a: str, run_b: str) -> Dict:
    fa: List[Finding] = session.query(Finding).filter_by(run_id=run_a).all()
    fb: List[Finding] = session.query(Finding).filter_by(run_id=run_b).all()
    sa = {_sig(f): f for f in fa}
    sb = {_sig(f): f for f in fb}

    def dump(f: Finding) -> Dict:
        return {"plugin": f.plugin_id, "category": f.category, "key": f.key,
                "value": f.value, "confidence": f.confidence,
                "passive": f.passive, "source": f.source}

    new = [dump(sb[s]) for s in sb if s not in sa]
    removed = [dump(sa[s]) for s in sa if s not in sb]

    # changed: same plugin+category+key but different value
    def k3(f: Finding) -> str:
        return f"{f.plugin_id}|{f.category}|{f.key}"

    ma = {}
    for f in fa:
        ma.setdefault(k3(f), set()).add(f.value)
    changed = []
    for f in fb:
        old_vals = ma.get(k3(f), set())
        if old_vals and f.value not in old_vals:
            changed.append({"plugin": f.plugin_id, "category": f.category,
                            "key": f.key, "old": sorted(old_vals)[:3],
                            "new": f.value, "source": f.source})
    # de-dupe changed
    seen = set()
    uniq_changed = []
    for c in changed:
        s = (c["plugin"], c["category"], c["key"], c["new"])
        if s not in seen:
            seen.add(s)
            uniq_changed.append(c)

    return {
        "run_a": run_a, "run_b": run_b,
        "counts": {"a": len(fa), "b": len(fb)},
        "new": new[:200], "removed": removed[:200], "changed": uniq_changed[:200],
        "new_count": len(new), "removed_count": len(removed),
        "changed_count": len(uniq_changed),
    }
