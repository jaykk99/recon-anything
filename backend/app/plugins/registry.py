"""Hot-loadable plugin registry.

Plugins are discovered by importing every module in this package and
collecting Plugin subclasses. Adding a new capability = drop a new file
in this directory implementing Plugin. No central list to edit.
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, List, Type

from .base import Plugin


_registry: Dict[str, Type[Plugin]] = {}

# Modules that raised during import, as (module_name, "ExcType: message").
# A broken plugin file vanishes from the registry silently; recording the
# failure here lets health checks and the API surface it instead of losing
# capability without a trace. Populated by discover().
IMPORT_FAILURES: List[tuple] = []


def discover() -> Dict[str, Type[Plugin]]:
    """Import all plugin modules and register Plugin subclasses."""
    global _registry
    if _registry:
        return _registry
    # __package__ is "app.plugins" both on normal import and under
    # `python -m app.plugins.registry`. __name__ is NOT reliable here: under
    # -m it is "__main__", so __name__.rsplit(".", 1)[0] yields "__main__"
    # and import_module("__main__") has no __path__ -> AttributeError.
    # (That exact crash red-lit CI from 0114f87 until this fix.)
    package = __package__ or __name__.rsplit(".", 1)[0]
    pkg = importlib.import_module(package)
    for mod in pkgutil.iter_modules(pkg.__path__):
        name = mod.name
        if name in ("base", "registry"):
            continue
        try:
            module = importlib.import_module(f"{package}.{name}")
        except Exception as e:
            # One broken plugin module must never kill the whole registry.
            # Record it (so health checks can see it) and keep going.
            import logging
            IMPORT_FAILURES.append((name, f"{type(e).__name__}: {e}"))
            logging.getLogger(__name__).warning(
                "plugin module %s failed to import: %s", name, e)
            continue
        for attr in dir(module):
            obj = getattr(module, attr)
            if (isinstance(obj, type) and issubclass(obj, Plugin)
                    and obj is not Plugin and getattr(obj, "id", None)):
                _registry[obj.id] = obj
    return _registry


def all_plugins() -> List[Plugin]:
    return [cls() for cls in discover().values()]


def for_target(target_type: str) -> List[Plugin]:
    return [p for p in all_plugins()
            if not p.accepts or target_type in p.accepts]


def describe() -> List[Dict]:
    out = []
    for p in all_plugins():
        out.append({
            "id": p.id,
            "label": p.label,
            "accepts": p.accepts,
            "requires_keys": p.requires_keys,
            "passive": p.passive,
            "cost": p.cost.value,
            "group": p.group,
            "description": p.description,
        })
    return sorted(out, key=lambda d: (d["group"], d["label"]))


# Floor for the registered-plugin count. The registry self-checks against
# this: a drop below it means capability was silently lost (a category of
# files deleted, a generator's spec list truncated, a shared base broken so
# a whole tier fails to import) and should fail CI, not ship quietly. Raise
# it when the real count grows well past it; lower it only on a deliberate,
# reviewed removal.
MIN_PLUGINS = 1200


def health() -> Dict:
    """Self-report the registry's state: how many plugins loaded, how many
    modules failed to import, whether the count cleared the floor, and a
    per-group breakdown. Cheap (import-only, no network), so it is safe to
    call from an API handler or a CI gate."""
    reg = discover()
    groups: Dict[str, int] = {}
    for cls in reg.values():
        g = getattr(cls, "group", "network")
        groups[g] = groups.get(g, 0) + 1
    count = len(reg)
    return {
        "registered": count,
        "floor": MIN_PLUGINS,
        "healthy": count >= MIN_PLUGINS and not IMPORT_FAILURES,
        "import_failures": list(IMPORT_FAILURES),
        "by_group": dict(sorted(groups.items())),
    }


def _main() -> int:
    """`python -m app.plugins.registry` — print the registry health report
    and exit non-zero if unhealthy. Intended for CI and quick local checks."""
    import json as _json
    rep = health()
    print(_json.dumps(rep, indent=2))
    if not rep["healthy"]:
        if rep["registered"] < rep["floor"]:
            print(
                f"UNHEALTHY: {rep['registered']} plugins registered, "
                f"below floor {rep['floor']}.")
        if rep["import_failures"]:
            print(f"UNHEALTHY: {len(rep['import_failures'])} import "
                  f"failure(s): {rep['import_failures']}")
        return 1
    print(f"OK: {rep['registered']} plugins registered "
          f"(floor {rep['floor']}), no import failures.")
    return 0


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(_main())
