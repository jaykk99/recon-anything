"""The swarm blackboard: the one shared surface the agents use.

Five role agents (Scout, Hypothesizer, ForkTester, LiveProber,
Reporter) never talk to each other directly. Each reads the
blackboard, does its job, and posts its output back as an event.
The Coordinator reads the same board to decide what runs next.

Append-only, JSON-serializable, thread-safe. Every event carries the
agent that wrote it, the target it concerns, and a wall-clock
timestamp, so a run can be replayed from its log alone.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, List, Optional


class Blackboard:
    """Shared state for one swarm run."""

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.started_at = time.time()
        self._lock = threading.Lock()
        self.events: List[Dict[str, Any]] = []
        self.targets: Dict[str, Dict[str, Any]] = {}
        # Blobs hold large payloads (verified source, ABI) in memory
        # only: they are never written to the event log, so the run
        # log stays small while the ForkTester can still read them.
        self.blobs: Dict[str, Dict[str, Any]] = {}

    def post(self, agent: str, target_key: str, kind: str,
             payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Append one event. Returns the event dict."""
        event = {
            "run_id": self.run_id,
            "ts": time.time(),
            "agent": agent,
            "target": target_key,
            "kind": kind,
            "payload": payload or {},
        }
        with self._lock:
            self.events.append(event)
            state = self.targets.setdefault(target_key, {})
            state[kind] = payload or {}
            state.setdefault("events", []).append(kind)
        return event

    def get(self, target_key: str, kind: str) -> Optional[Dict[str, Any]]:
        """Latest payload of `kind` for `target_key`, or None."""
        with self._lock:
            state = self.targets.get(target_key) or {}
            value = state.get(kind)
            return dict(value) if isinstance(value, dict) else value

    def put_blob(self, target_key: str, kind: str, value: Any) -> None:
        """Store a large payload in memory only (never in the log)."""
        with self._lock:
            self.blobs.setdefault(target_key, {})[kind] = value

    def get_blob(self, target_key: str, kind: str) -> Any:
        with self._lock:
            return (self.blobs.get(target_key) or {}).get(kind)

    def events_for(self, target_key: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [e for e in self.events if e["target"] == target_key]

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "run_id": self.run_id,
                "started_at": self.started_at,
                "events": list(self.events),
                "targets": {k: v for k, v in self.targets.items()},
            }

    def to_jsonl(self) -> str:
        """One JSON object per line, for the run log."""
        with self._lock:
            return "\n".join(json.dumps(e) for e in self.events)
