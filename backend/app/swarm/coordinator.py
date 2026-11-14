"""Coordinator: assign targets, cap concurrency, dedupe, enforce rules.

The Coordinator is the only agent that talks to the queue. It:

1. filters intake through the hard rules (crypto.com rejection,
   malformed addresses, non-EVM chains, duplicates by chain:address);
2. orders what is left with triage (value first, NN score when the
   scorer is wired in, heuristic otherwise);
3. runs the five-role pipeline per target (Scout -> Hypothesizer ->
   ForkTester -> LiveProber -> Reporter), capped at
   ``max_concurrent_targets`` parallel targets;
4. chains to related addresses the Scout found (depth 1, deduped,
   only when the hypothesis is a story or a lead, never more);
5. collects honest run metrics: targets attempted/completed,
   findings, candidates, verified-real passthroughs (expect 0),
   time per target. A target that errors is recorded as ERROR and
   never kills the run.

The Coordinator never investigates, never probes, never scores a
verdict. It schedules.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

from .bus import Blackboard
from .fork import ForkTesterAgent
from .hypothesis import HypothesizerAgent
from .probe import LiveProberAgent
from .reporter import ReporterAgent
from .rpc import RpcClient
from .rules import BOUNTY_FLOOR_USD, is_forbidden_target
from .scout import ScoutAgent
from .triage import rank_targets, target_key

SUPPORTED_CHAINS = {
    "ethereum", "optimism", "bsc", "polygon", "arbitrum", "base",
    "scroll", "linea", "avalanche",
}


class Coordinator:
    """Assigns targets to the five-role pipeline, under the rules."""

    def __init__(self, max_concurrent_targets: int = 2,
                 chain_depth: int = 1,
                 out_dir: Optional[str] = None,
                 rpc_factory: Optional[Callable[[str], RpcClient]] = None,
                 nn_score_fn: Optional[Callable] = None) -> None:
        self.max_concurrent_targets = max(1, int(max_concurrent_targets))
        self.chain_depth = max(0, int(chain_depth))
        self.out_dir = out_dir
        self.rpc_factory = rpc_factory or (lambda chain: RpcClient(chain))
        self.nn_score_fn = nn_score_fn
        self.scout = ScoutAgent()
        self.hypothesizer = HypothesizerAgent()
        self.forktester = ForkTesterAgent()
        self.liveprober = LiveProberAgent()
        self.reporter = ReporterAgent()

    # -- intake ----------------------------------------------------------

    def filter_intake(self, targets: List[Dict[str, Any]]):
        """Apply the hard rules. Returns (accepted, rejected) where
        rejected is a list of {target, reason}."""
        accepted: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []
        seen = set()
        for target in targets:
            key = target_key(target)
            reason: Optional[str] = None
            if not str(target.get("address") or "").lower().startswith("0x"):
                reason = "malformed address"
            elif key in seen:
                reason = "duplicate target (chain:address already queued)"
            elif str(target.get("chain") or "").lower() not in SUPPORTED_CHAINS:
                reason = f"unsupported chain: {target.get('chain')!r}"
            else:
                reason = is_forbidden_target(target)
            if reason:
                rejected.append({"target": target, "reason": reason})
            else:
                seen.add(key)
                accepted.append(target)
        return accepted, rejected

    # -- one target ------------------------------------------------------

    def run_target(self, target: Dict[str, Any], board: Blackboard,
                   depth: int = 0) -> Dict[str, Any]:
        """Run the five-role pipeline over one target. Returns the
        per-target outcome, including chained targets when depth
        allows."""
        key = target_key(target)
        started = time.time()
        outcome: Dict[str, Any] = {
            "key": key, "chain": target.get("chain"),
            "address": target.get("address"), "status": "ok",
            "verdict": None, "findings": 0, "candidates": 0,
            "chained": [],
        }
        try:
            rpc = self.rpc_factory(str(target.get("chain") or ""))
            scout = self.scout.run(target, rpc, board)
            outcome["findings"] = scout.get("findings_count", 0)
            hypothesis = self.hypothesizer.run(scout, board)
            # Source/ABI for the fork step come from the Scout's blob
            # store: no second fetch, no log bloat.
            source = board.get_blob(key, "source") or ""
            abi = board.get_blob(key, "abi")
            fork = self.forktester.run(target, hypothesis, scout, rpc,
                                       board, source=source, abi=abi)
            probe = self.liveprober.run(target, hypothesis, scout, rpc, board)
            outcome["verdict"] = probe.get("verdict")
            outcome["candidates"] = len(probe.get("candidates") or [])
            metrics = {"target_elapsed_s": round(time.time() - started, 3)}
            self.reporter.run(target, board, out_dir=self.out_dir,
                              metrics=metrics)
            # Chain to related addresses (depth 1, deduped by caller).
            if (depth < self.chain_depth
                    and hypothesis.get("kind") in ("story", "lead")):
                for related in scout.get("related_addresses") or []:
                    outcome["chained"].append({
                        "chain": target.get("chain"),
                        "address": related,
                        "from": key,
                    })
        except Exception as e:  # noqa: BLE001 - one target never kills run
            outcome["status"] = "error"
            outcome["error"] = f"{type(e).__name__}: {e}"
            board.post("coordinator", key, "target_error", outcome)
        outcome["elapsed_s"] = round(time.time() - started, 3)
        board.post("coordinator", key, "target_done", outcome)
        return outcome

    # -- whole queue -----------------------------------------------------

    def run_queue(self, targets: List[Dict[str, Any]],
                  run_id: Optional[str] = None) -> Dict[str, Any]:
        """Run the queue. Returns the run record with honest metrics."""
        run_id = run_id or f"swarm-{int(time.time())}"
        board = Blackboard(run_id)
        started = time.time()
        accepted, rejected = self.filter_intake(targets)
        for item in rejected:
            board.post("coordinator", target_key(item["target"]),
                       "rejected", {"reason": item["reason"]})
        ordered = rank_targets(accepted, nn_score_fn=self.nn_score_fn)
        outcomes: List[Dict[str, Any]] = []
        # Depth-1 chaining: chained targets run after the first pass,
        # through the same intake filter (dedupe + rules apply again).
        pending = list(ordered)
        seen_keys = {target_key(t) for t in ordered}
        depth = 0
        while pending and depth <= self.chain_depth:
            batch = pending
            pending = []
            with ThreadPoolExecutor(
                    max_workers=self.max_concurrent_targets) as pool:
                futures = {pool.submit(self.run_target, t, board, depth): t
                           for t in batch}
                for fut in as_completed(futures):
                    outcomes.append(fut.result())
            if depth < self.chain_depth:
                chained: List[Dict[str, Any]] = []
                for outcome in outcomes:
                    for nxt in outcome.get("chained") or []:
                        k = target_key(nxt)
                        if k not in seen_keys:
                            seen_keys.add(k)
                            chained.append(nxt)
                if chained:
                    acc, rej = self.filter_intake(chained)
                    for item in rej:
                        board.post("coordinator",
                                   target_key(item["target"]), "rejected",
                                   {"reason": item["reason"]})
                    pending = rank_targets(acc, nn_score_fn=self.nn_score_fn)
            depth += 1

        elapsed = time.time() - started
        metrics = {
            "run_id": run_id,
            "targets_queued": len(targets),
            "targets_rejected": len(rejected),
            "targets_attempted": len(outcomes),
            "targets_completed": sum(1 for o in outcomes
                                     if o["status"] == "ok"),
            "targets_errored": sum(1 for o in outcomes
                                   if o["status"] == "error"),
            "findings_total": sum(o.get("findings", 0) for o in outcomes),
            "candidates_total": sum(o.get("candidates", 0) for o in outcomes),
            "verified_real": sum(
                1 for o in outcomes if o.get("verdict") == "VERIFIED_REAL"),
            "trigger_only": sum(
                1 for o in outcomes if o.get("verdict") == "TRIGGER_ONLY"),
            "elapsed_s": round(elapsed, 3),
            "seconds_per_target": round(
                elapsed / max(len(outcomes), 1), 3),
            "bounty_floor_usd": BOUNTY_FLOOR_USD,
            "max_concurrent_targets": self.max_concurrent_targets,
        }
        record = {"metrics": metrics, "outcomes": outcomes,
                  "rejected": rejected, "board": board.to_dict()}
        board.post("coordinator", "run", "run_done", metrics)
        return record
