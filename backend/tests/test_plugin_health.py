"""Plugin health gate for ReconAnything.

Fast, network-free: every plugin module must import, every plugin must
instantiate with sane metadata, and plugin ids must be unique. The full
live health check (run every plugin against a target) is
backend/scripts/plugin_health.py:

    python scripts/plugin_health.py --target example.com
"""
import importlib
import inspect
import os
import pkgutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import base  # noqa: E402


def _iter_plugin_modules():
    pkg = importlib.import_module("app.plugins")
    for mod in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda m: m.name):
        if mod.name in ("base", "registry", "__init__"):
            continue
        yield mod.name


def _load_classes():
    classes = {}
    for name in _iter_plugin_modules():
        module = importlib.import_module(f"app.plugins.{name}")
        for attr in dir(module):
            obj = getattr(module, attr)
            if (isinstance(obj, type) and issubclass(obj, base.Plugin)
                    and obj is not base.Plugin and getattr(obj, "id", None)):
                classes.setdefault(obj.id, (name, obj))
    return classes


@pytest.fixture(scope="module")
def plugin_classes():
    return _load_classes()


def test_all_plugin_modules_import():
    failures = {}
    for name in _iter_plugin_modules():
        try:
            importlib.import_module(f"app.plugins.{name}")
        except Exception as e:  # noqa: BLE001
            failures[name] = f"{type(e).__name__}: {e}"
    assert not failures, f"plugin modules failed to import: {failures}"


def test_plugin_ids_unique():
    seen = {}
    dupes = set()
    for name in _iter_plugin_modules():
        module = importlib.import_module(f"app.plugins.{name}")
        for attr in dir(module):
            obj = getattr(module, attr)
            if (isinstance(obj, type) and issubclass(obj, base.Plugin)
                    and obj is not base.Plugin and getattr(obj, "id", None)):
                if obj.id in seen:
                    dupes.add(obj.id)
                seen[obj.id] = name
    assert not dupes, f"duplicate plugin ids: {sorted(dupes)}"


def test_every_plugin_has_metadata(plugin_classes):
    assert plugin_classes, "no plugins discovered"
    problems = []
    for pid, (name, cls) in sorted(plugin_classes.items()):
        if not cls.label:
            problems.append(f"{pid}: missing label")
        if not cls.description:
            problems.append(f"{pid}: missing description")
        if cls.group not in base.PLUGIN_GROUPS:
            problems.append(f"{pid}: bad group {cls.group!r}")
        try:
            cost = cls.cost.value
        except Exception:  # noqa: BLE001
            problems.append(f"{pid}: invalid cost")
        else:
            if cost not in ("free", "freemium", "paid"):
                problems.append(f"{pid}: unknown cost {cost!r}")
        if not inspect.iscoroutinefunction(cls.run):
            problems.append(f"{pid}: run() is not async")
        if not (cls.timeout_s or 0) > 0:
            problems.append(f"{pid}: bad timeout_s {cls.timeout_s!r}")
    assert not problems, "plugin metadata problems:\n" + "\n".join(problems)


def test_every_plugin_instantiates(plugin_classes):
    failures = {}
    for pid, (name, cls) in sorted(plugin_classes.items()):
        try:
            cls()
        except Exception as e:  # noqa: BLE001
            failures[pid] = f"{type(e).__name__}: {e}"
    assert not failures, f"plugins failed to instantiate: {failures}"
