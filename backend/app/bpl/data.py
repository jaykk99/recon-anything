"""Real event streams for the BPL engine. Read-only; no network, no writes.

Two domains, both from real staged/working data on this box:
  1. Deployer timelines: fresh contract deploys grouped by creator address
     (~/workspace/recon-continuous/targets-2026-11-12/fresh-deploys-more-chains.jsonl).
     Each event: time, chain, contract type (name).
  2. Owner-transition timelines: owner-change events grouped by token symbol
     (~/workspace/recon-continuous/state/transition_events.jsonl).
     Each event: time, symbol, flip direction (to-null / from-null).

Only creators/symbols with enough events are modelled; the rest are
reported as insufficient data, never invented.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

DEPLOY_PATH = os.path.expanduser(
    "~/workspace/recon-continuous/targets-2026-11-12/fresh-deploys-more-chains.jsonl"
)
TRANSITION_PATH = os.path.expanduser(
    "~/workspace/recon-continuous/state/transition_events.jsonl"
)


@dataclass
class Event:
    """One observed event. `kind` is the categorical label (contract type
    for deploys, flip direction for transitions); `group` is the categorical
    axis (chain for deploys, symbol for transitions)."""

    t: float  # unix seconds
    kind: str
    group: str


@dataclass
class Timeline:
    """One entity's ordered event stream."""

    entity: str
    events: list = field(default_factory=list)

    def __len__(self):
        return len(self.events)


def _parse_time(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def load_deploy_timelines(path=DEPLOY_PATH):
    """Group deploys by creator. Returns (timelines, stats)."""
    by_creator = defaultdict(list)
    rows = 0
    skipped = 0
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows += 1
            rec = json.loads(line)
            creator = rec.get("creator")
            t = _parse_time(rec.get("first_seen_utc"))
            if not creator or t is None:
                skipped += 1
                continue
            by_creator[creator].append(
                Event(t=t, kind=str(rec.get("name") or "unknown"),
                      group=str(rec.get("chain") or "unknown"))
            )
    timelines = []
    for creator, events in by_creator.items():
        events.sort(key=lambda e: e.t)
        timelines.append(Timeline(entity=creator, events=events))
    timelines.sort(key=lambda tl: -len(tl))
    stats = {
        "rows": rows,
        "skipped": skipped,
        "entities": len(timelines),
        "events": sum(len(tl) for tl in timelines),
        "with_ge_2": sum(1 for tl in timelines if len(tl) >= 2),
        "with_ge_3": sum(1 for tl in timelines if len(tl) >= 3),
        "with_ge_5": sum(1 for tl in timelines if len(tl) >= 5),
    }
    return timelines, stats


def load_transition_timelines(path=TRANSITION_PATH):
    """Group owner-change events by token symbol. Returns (timelines, stats)."""
    by_symbol = defaultdict(list)
    rows = 0
    skipped = 0
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows += 1
            rec = json.loads(line)
            symbol = rec.get("symbol")
            t = _parse_time(rec.get("detected_at"))
            if not symbol or t is None:
                skipped += 1
                continue
            before = (rec.get("before") or {}).get("owner")
            after = (rec.get("after") or {}).get("owner")
            if before is None and after is not None:
                direction = "from-null"
            elif before is not None and after is None:
                direction = "to-null"
            else:
                direction = "other"
            by_symbol[symbol].append(
                Event(t=t, kind=direction, group=str(rec.get("chain") or "unknown"))
            )
    timelines = []
    for symbol, events in by_symbol.items():
        events.sort(key=lambda e: e.t)
        timelines.append(Timeline(entity=symbol, events=events))
    timelines.sort(key=lambda tl: -len(tl))
    stats = {
        "rows": rows,
        "skipped": skipped,
        "entities": len(timelines),
        "events": sum(len(tl) for tl in timelines),
        "with_ge_2": sum(1 for tl in timelines if len(tl) >= 2),
        "with_ge_3": sum(1 for tl in timelines if len(tl) >= 3),
        "with_ge_5": sum(1 for tl in timelines if len(tl) >= 5),
    }
    return timelines, stats


def train_holdout_split(timeline, holdout_frac=0.30):
    """Split one timeline in time order. Returns (train, holdout) or
    (None, None) when too short to split honestly (needs >= 5 events)."""
    if len(timeline) < 5:
        return None, None
    n_hold = max(1, int(round(len(timeline) * holdout_frac)))
    n_train = len(timeline) - n_hold
    if n_train < 3:
        return None, None
    return timeline.events[:n_train], timeline.events[n_train:]


def all_groups(timelines):
    groups = set()
    kinds = set()
    for tl in timelines:
        for ev in tl.events:
            groups.add(ev.group)
            kinds.add(ev.kind)
    return sorted(groups), sorted(kinds)
