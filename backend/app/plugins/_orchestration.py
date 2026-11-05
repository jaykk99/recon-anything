"""Shared execution engine for the Tier-5 orchestration plugins.

The orchestration tier is meta: its plugins compose, dispatch and
track OTHER plugins instead of probing a target themselves. This
module is the one place that knows how to run a downstream plugin
safely from inside another plugin:

  * resolution order: a caller-registered override in
    ``ctx.shared["orchestration_plugins"]`` (plugin id -> Plugin
    subclass, instance, or async callable(target, ctx)) wins over the
    global registry. Tests use the override seam to substitute
    deterministic fake downstream plugins; production runs fall back
    to ``registry.discover()``.
  * orchestration plugins never run each other (no recursion): every
    id in ORCHESTRATION_IDS is refused as a downstream target.
  * a downstream plugin can never kill the orchestrator: accepts /
    missing-key gating is honoured when the object supports it, every
    run is timeout-capped, and exceptions degrade to a per-plugin
    status entry instead of propagating.
  * composed findings are deduped on (plugin_id, key, value).

No network or filesystem access of its own. Pure glue.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Sequence, Tuple

ORCHESTRATION_IDS = frozenset({
    "reconftw_pipeline",
    "rengine_scan_engine",
    "osmedeus_workflow",
    "axiom_fleet_dispatch",
    "purpleteam_test_plan",
    "spiderfoot_osint_graph",
    "amass_asset_tracker",
    "trickest_workflow_templates",
    "bbrf_recon_store",
    "flyover_surface_summary",
    # PR #118's meta-plugin (not on master at time of writing): an
    # orchestrator must never dispatch another orchestrator.
    "lifecycle_orchestrator",
})

DOWNSTREAM_TIMEOUT_S = 25.0
MAX_DOWNSTREAM_FINDINGS = 200


def shared_get(ctx: Any, key: str, default: Any = None) -> Any:
    """Duck-typed ctx.shared read (works for real Ctx and test stubs)."""
    shared = getattr(ctx, "shared", None)
    if isinstance(shared, dict):
        value = shared.get(key, default)
        return default if value is None else value
    return default


def consume(ctx: Any, kind: str) -> List[Any]:
    """Duck-typed discovery-bus read."""
    fn = getattr(ctx, "consume", None)
    if callable(fn):
        try:
            return list(fn(kind) or [])
        except Exception:
            return []
    shared = getattr(ctx, "shared", None)
    if isinstance(shared, dict):
        return list(shared.get(kind, []) or [])
    return []


def override_for(ctx: Any, key: str) -> Any:
    """Per-plugin config override: module_overrides first, then shared."""
    overrides = getattr(ctx, "module_overrides", None)
    if isinstance(overrides, dict) and overrides.get(key):
        return overrides[key]
    return shared_get(ctx, key)


def _resolve_class(ctx: Any, plugin_id: str):
    overrides = shared_get(ctx, "orchestration_plugins")
    if isinstance(overrides, dict) and plugin_id in overrides:
        return overrides[plugin_id]
    try:
        from .registry import discover
        return discover().get(plugin_id)
    except Exception:
        return None


def is_runnable(ctx: Any, plugin_id: str) -> bool:
    if not plugin_id or plugin_id in ORCHESTRATION_IDS:
        return False
    return _resolve_class(ctx, plugin_id) is not None


def classify_ids(ctx: Any, ids: Sequence[str]) -> Dict[str, List[str]]:
    """Split requested ids into runnable / unknown / excluded."""
    out: Dict[str, List[str]] = {"runnable": [], "unknown": [],
                                 "excluded": []}
    seen = set()
    for raw in ids or []:
        pid = str(raw or "").strip()
        if not pid or pid in seen:
            continue
        seen.add(pid)
        if pid in ORCHESTRATION_IDS:
            out["excluded"].append(pid)
        elif _resolve_class(ctx, pid) is not None:
            out["runnable"].append(pid)
        else:
            out["unknown"].append(pid)
    return out


async def _run_one(ctx: Any, target: Any, plugin_id: str,
                   entry: Any) -> Dict[str, Any]:
    """Run one downstream entry; never raises."""
    record: Dict[str, Any] = {"id": plugin_id, "status": "error",
                              "reason": "", "findings": []}
    try:
        if callable(entry) and not isinstance(entry, type):
            # Instance or async callable override.
            run = getattr(entry, "run", entry)
            result = run(target, ctx)
            if asyncio.iscoroutine(result):
                result = await asyncio.wait_for(
                    result, timeout=DOWNSTREAM_TIMEOUT_S)
        else:
            plugin = entry()
            accepts = getattr(plugin, "accepts", None)
            if accepts and getattr(target, "type", None) not in accepts:
                record.update(status="skipped",
                              reason="target type not accepted")
                return record
            missing = None
            fn = getattr(plugin, "missing_keys", None)
            if callable(fn):
                try:
                    missing = fn(ctx)
                except Exception:
                    missing = None
            if missing:
                record.update(status="skipped",
                              reason=f"needs key: {', '.join(missing)}")
                return record
            result = await asyncio.wait_for(
                plugin.run(target, ctx), timeout=DOWNSTREAM_TIMEOUT_S)
        findings = list(getattr(result, "findings", None) or [])
        status = getattr(result, "status", "ok")
        record.update(
            status=str(getattr(status, "value", status)),
            reason=str(getattr(result, "reason", "") or ""),
            findings=findings[:MAX_DOWNSTREAM_FINDINGS])
    except asyncio.TimeoutError:
        record.update(status="timeout",
                      reason=f"exceeded {DOWNSTREAM_TIMEOUT_S:.0f}s cap")
    except Exception as exc:  # noqa: BLE001 - downstream must not kill us
        record.update(status="error",
                      reason=f"{type(exc).__name__}: {exc}"[:200])
    return record


async def run_downstream(ctx: Any, target: Any, ids: Sequence[str],
                         cap: int = 12) -> List[Dict[str, Any]]:
    """Execute the requested downstream plugins in order.

    Returns one record per requested id (runnable or not) so callers
    can report exactly what ran, what was skipped and why.
    """
    records: List[Dict[str, Any]] = []
    classified = classify_ids(ctx, ids)
    runnable = set(classified["runnable"])
    seen = set()
    for raw in ids or []:
        pid = str(raw or "").strip()
        if not pid or pid in seen:
            continue
        seen.add(pid)
        if pid in ORCHESTRATION_IDS:
            records.append({"id": pid, "status": "excluded",
                            "reason": "orchestration plugins never "
                                      "dispatch each other",
                            "findings": []})
        elif pid not in runnable:
            records.append({"id": pid, "status": "unknown",
                            "reason": "no such plugin in registry",
                            "findings": []})
        elif len([r for r in records if r["status"] not in
                  ("unknown", "excluded")]) >= cap:
            records.append({"id": pid, "status": "skipped",
                            "reason": f"downstream cap {cap} reached",
                            "findings": []})
        else:
            records.append(await _run_one(
                ctx, target, pid, _resolve_class(ctx, pid)))
    return records


def dedupe_findings(findings: Sequence[Any]) -> List[Any]:
    """Dedupe composed findings on (plugin_id, key, value)."""
    seen = set()
    out: List[Any] = []
    for f in findings or []:
        key = (getattr(f, "plugin_id", ""), getattr(f, "key", ""),
               getattr(f, "value", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def collect_findings(records: Sequence[Dict[str, Any]]) -> List[Any]:
    out: List[Any] = []
    for rec in records or []:
        out.extend(rec.get("findings") or [])
    return dedupe_findings(out)


def severity_of(finding: Any) -> str:
    ev = getattr(finding, "evidence", None) or {}
    if isinstance(ev, dict):
        sev = str(ev.get("severity") or ev.get("risk") or "low").lower()
        if sev in ("critical", "high"):
            return "high"
        if sev in ("medium", "med"):
            return "medium"
    return "low"


def parse_engine_config(raw: Any) -> Tuple[Dict[str, Any], str]:
    """Parse a reNgine-style scan-engine config.

    Accepts a dict, a JSON string, or the small YAML subset reNgine
    engine files actually use in practice:

        name: light-web
        intensity: light
        checks:
          - headers
          - cors
        stages:
          discovery:
            - passive_subdomains

    Returns (config_dict, error). On any malformed input the config
    is {} and error names the problem; callers degrade, never crash.
    """
    if raw is None:
        return {}, ""
    if isinstance(raw, dict):
        return dict(raw), ""
    if not isinstance(raw, str):
        return {}, f"config must be a mapping or string, got {type(raw).__name__}"
    text = raw.strip()
    if not text:
        return {}, ""
    try:
        import json
        data = json.loads(text)
        if isinstance(data, dict):
            return data, ""
    except Exception:
        pass
    # Minimal YAML subset: top-level scalars, top-level lists, and one
    # level of nested mappings whose values are lists.
    config: Dict[str, Any] = {}
    current_key: Optional[str] = None
    current_sub: Optional[str] = None
    try:
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            if stripped.startswith("- "):
                item = stripped[2:].strip().strip("'\"")
                if current_sub is not None and current_key:
                    bucket = config.setdefault(current_key, {})
                    if isinstance(bucket, dict):
                        bucket.setdefault(current_sub, []).append(item)
                elif current_key:
                    bucket = config.setdefault(current_key, [])
                    if isinstance(bucket, list):
                        bucket.append(item)
                continue
            if ":" not in stripped:
                return {}, f"unparseable config line: {stripped[:60]!r}"
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip().strip("'\"")
            if indent == 0:
                current_key, current_sub = key, None
                if value:
                    config[key] = value
                else:
                    config.setdefault(key, [])
            else:
                # Nested mapping key (e.g. a stage name under stages:).
                if current_key is None:
                    return {}, "nested key without a parent"
                parent = config.get(current_key)
                if not isinstance(parent, dict):
                    parent = {}
                    config[current_key] = parent
                current_sub = key
                if value:
                    parent[key] = value
                else:
                    parent.setdefault(key, [])
    except Exception as exc:  # noqa: BLE001
        return {}, f"config parse failed: {exc}"[:120]
    return config, ""


def engine_check_ids(config: Dict[str, Any]) -> List[str]:
    """Flatten an engine config into an ordered downstream id list."""
    ids: List[str] = []
    for key in ("checks", "plugins", "modules"):
        val = (config or {}).get(key)
        if isinstance(val, list):
            ids.extend(str(v) for v in val)
        elif isinstance(val, str) and val:
            ids.append(val)
    stages = (config or {}).get("stages")
    if isinstance(stages, dict):
        for stage in stages.values():
            if isinstance(stage, list):
                ids.extend(str(v) for v in stage)
            elif isinstance(stage, dict):
                for sub in stage.values():
                    if isinstance(sub, list):
                        ids.extend(str(v) for v in sub)
    elif isinstance(stages, list):
        ids.extend(str(v) for v in stages)
    seen, out = set(), []
    for pid in ids:
        if pid and pid not in seen:
            seen.add(pid)
            out.append(pid)
    return out
