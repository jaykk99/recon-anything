"""Turning a caller's target list into an authorized campaign Scope.

Two things happen here, in this order:

1. the app's SANDBOX/LIVE mode is applied, so a sandbox install cannot
   point a campaign at a third-party host even if it names it, and
2. the resulting hosts become the campaign's declared roots - which is
   the only thing that authorizes network work (see scope.py).

If the mode cannot be resolved, nothing is authorized: a campaign fails
closed rather than guessing that it is allowed.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple

from .scope import NEVER_TARGETS, Scope, host_of


def _sandbox_refusals(targets: Sequence[str]) -> Tuple[List[str], List[Dict[str, str]]]:
    try:
        from ..models import get_session
        from ..modes import (SANDBOX, get_mode, get_owned_assets,
                             sandbox_host_allowed)
    except Exception as exc:  # pragma: no cover - import guard
        return [], [{"target": "*",
                     "reason": f"scope policy unavailable: {exc}"}]
    try:
        session = get_session()
        try:
            mode = get_mode(session)
            owned = get_owned_assets(session)
        finally:
            session.close()
    except Exception as exc:  # DB unavailable -> fail closed
        return [], [{"target": "*",
                     "reason": f"scan mode could not be resolved: {exc}"}]
    if mode != SANDBOX:
        return list(targets), []
    allowed: List[str] = []
    refused: List[Dict[str, str]] = []
    for t in targets:
        ok, reason = sandbox_host_allowed(host_of(t), owned)
        if ok:
            allowed.append(t)
        else:
            refused.append({"target": t, "reason": f"sandbox mode: {reason}"})
    return allowed, refused


def build_scope(targets: Iterable[str], *,
                allow_active: bool = False,
                allow_exploit_confirm: bool = False,
                allow_auth_replay: bool = False,
                exclude: Iterable[str] = (),
                max_requests: int = 60,
                max_intents: int = 24,
                max_rounds: int = 3,
                max_parallel: int = 3,
                max_seconds: float = 120.0,
                per_host_rps: float = 2.0,
                check_mode: bool = True) -> Tuple[Scope, List[Dict[str, str]]]:
    """Build the campaign scope, returning (scope, refusals)."""
    clean: List[str] = []
    refusals: List[Dict[str, str]] = []
    for raw in targets or ():
        target = (raw or "").strip()
        if not target:
            continue
        host = host_of(target)
        if not host:
            refusals.append({"target": target, "reason": "target has no host"})
            continue
        if host in NEVER_TARGETS or host.endswith(".crypto.com"):
            refusals.append({"target": target,
                             "reason": "crypto.com is never a campaign target"})
            continue
        if target not in clean:
            clean.append(target)
    if check_mode and clean:
        clean, mode_refusals = _sandbox_refusals(clean)
        refusals.extend(mode_refusals)
    roots = tuple(dict.fromkeys(host_of(t) or t for t in clean))
    scope = Scope(
        roots=roots, exclude=tuple(exclude),
        allow_active=allow_active,
        allow_exploit_confirm=allow_exploit_confirm,
        allow_auth_replay=allow_auth_replay,
        max_requests=max(1, int(max_requests)),
        max_intents=max(1, int(max_intents)),
        max_rounds=max(1, int(max_rounds)),
        max_parallel=max(1, min(8, int(max_parallel))),
        max_seconds=max(5.0, float(max_seconds)),
        per_host_rps=max(0.0, float(per_host_rps)),
    )
    return scope, refusals
