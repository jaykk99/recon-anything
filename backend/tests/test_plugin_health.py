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


def test_registered_plugin_count_floor():
    """Regression guard for silent capability loss.

    The registry is the runtime source of truth (it includes plugins
    generated dynamically at import, which a file/class count misses).
    If the registered count ever drops below the floor with no import
    error, a whole category was deleted or a generator's spec list was
    truncated - a bug that no other test here would catch.
    """
    from app.plugins.registry import discover, MIN_PLUGINS, IMPORT_FAILURES
    count = len(discover())
    assert not IMPORT_FAILURES, (
        f"{len(IMPORT_FAILURES)} plugin module(s) failed to import, so "
        f"capability was silently lost: {IMPORT_FAILURES}")
    assert count >= MIN_PLUGINS, (
        f"only {count} plugins registered, below floor {MIN_PLUGINS}; "
        f"a category of plugins was likely removed or broken. If this "
        f"removal was deliberate, lower MIN_PLUGINS in registry.py.")


def test_registry_health_reports_healthy():
    """The health() self-report must agree the registry is healthy."""
    from app.plugins.registry import health
    rep = health()
    assert rep["healthy"], f"registry reports unhealthy: {rep}"
