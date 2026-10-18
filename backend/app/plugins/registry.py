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


def discover() -> Dict[str, Type[Plugin]]:
    """Import all plugin modules and register Plugin subclasses."""
    global _registry
    if _registry:
        return _registry
    package = __name__.rsplit(".", 1)[0]
    pkg = importlib.import_module(package)
    for mod in pkgutil.iter_modules(pkg.__path__):
        name = mod.name
        if name in ("base", "registry"):
            continue
        try:
            module = importlib.import_module(f"{package}.{name}")
        except Exception as e:
            # One broken plugin module must never kill the whole registry.
            # Log it and keep going with the rest.
            import logging
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
