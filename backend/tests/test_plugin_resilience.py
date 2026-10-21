"""Plugin resilience gate: no plugin ever throws fatally.

Runs every registered plugin against a stubbed context with all network
paths dead (fetch/fetch_many raise, DNS raises, TCP raises). Each plugin
must return a PluginResult (ok / degraded / skipped / error) - never
raise. This is the contract in plugins/base.py: partial findings plus a
per-plugin status, never a fatal throw.

Network-free by construction: socket, DNS and HTTP are all stubbed.
"""
import asyncio
import importlib
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.asyncresolver  # noqa: E402
import dns.resolver  # noqa: E402
import pytest  # noqa: E402

from app.plugins import base  # noqa: E402
from app.plugins.registry import discover  # noqa: E402


# ---------------------------------------------------------------------------
# Stub context
# ---------------------------------------------------------------------------

class _FakeCache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        return None

    async def cached(self, source, target, fn, ttl=None):
        return await fn(), False


class DeadCtx:
    """Every network path raises; plugins must degrade, not throw."""

    def __init__(self):
        self.run_id = "resilience-test"
        self.mode = "passive"
        self.http = None
        self.cache = _FakeCache()
        self.keys = {}
        self.limiter = None
        self.emit = None
        self.module_overrides = {}
        self.evidence_dir = "/tmp"
        self.source_type = "website"
        self.shared = {}

    def publish(self, kind, item):
        b = self.shared.setdefault(kind, [])
        if isinstance(item, str):
            if item not in b:
                b.append(item)
        else:
            b.append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    async def fetch_page(self, url, timeout=10):
        return None

    async def probe(self, url, timeout=8):
        # Mirrors Ctx.probe's contract: failures are status 0, never raise.
        return {"status": 0, "headers": {}, "text": "", "url": url}


async def _boom(*a, **k):
    raise ConnectionError("network dead (resilience test)")


class _DeadResolver:
    def __init__(self, *a, **k):
        pass

    async def resolve(self, *a, **k):
        raise dns.resolver.NXDOMAIN()


def _dead_socket(*a, **k):
    raise ConnectionError("network dead (resilience test)")


def _dead_connect(self, *a, **k):
    raise ConnectionError("network dead (resilience test)")


@pytest.fixture()
def dead_network(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", _dead_socket)
    # NOTE: do not patch socket.socket itself - asyncio needs socketpair()
    # to build an event loop. Patching connect kills all TCP without
    # breaking the loop.
    monkeypatch.setattr(socket.socket, "connect", _dead_connect)
    monkeypatch.setattr(dns.asyncresolver, "Resolver", _DeadResolver)
    # per-module fetch/fetch_many stubs (plugins import the names directly)
    for _pid, cls in discover().items():
        mod = sys.modules.get(cls.__module__)
        if mod is None:
            continue
        if hasattr(mod, "fetch"):
            monkeypatch.setattr(mod, "fetch", _boom, raising=False)
        if hasattr(mod, "fetch_many"):
            async def _boom_many(*a, **k):
                reqs = a[2] if len(a) > 2 else k.get("requests", [])
                return [None] * len(reqs)
            monkeypatch.setattr(mod, "fetch_many", _boom_many, raising=False)


def _plugins():
    return sorted(discover().items())


def test_every_plugin_survives_dead_network(dead_network):
    failures = {}
    for pid, cls in _plugins():
        ctx = DeadCtx()
        target = base.Target(raw="https://example.com/", type="url",
                             normalized="https://example.com/")
        try:
            res = asyncio.run(asyncio.wait_for(
                cls().run(target, ctx), timeout=25))
        except Exception as e:  # noqa: BLE001
            failures[pid] = f"{type(e).__name__}: {e}"
            continue
        if not isinstance(res, base.PluginResult):
            failures[pid] = f"bad return type {type(res).__name__}"
        elif res.status not in base.PluginStatus:
            failures[pid] = f"bad status {res.status!r}"
    assert not failures, "plugins threw on dead network:\n" + "\n".join(
        f"  {pid}: {err}" for pid, err in sorted(failures.items()))


def test_every_plugin_survives_dead_network_domain_target(dead_network):
    # domain targets exercise the DNS/socket paths, not just HTTP.
    failures = {}
    for pid, cls in _plugins():
        if "domain" not in cls.accepts:
            continue
        ctx = DeadCtx()
        target = base.Target(raw="example.com", type="domain",
                             normalized="example.com")
        try:
            res = asyncio.run(asyncio.wait_for(
                cls().run(target, ctx), timeout=25))
        except Exception as e:  # noqa: BLE001
            failures[pid] = f"{type(e).__name__}: {e}"
            continue
        if not isinstance(res, base.PluginResult):
            failures[pid] = f"bad return type {type(res).__name__}"
    assert not failures, "plugins threw on dead network (domain target):\n" + \
        "\n".join(f"  {pid}: {err}" for pid, err in sorted(failures.items()))


def test_findings_have_actionable_shape(dead_network):
    # Whatever findings survive dead network must carry the quality-gate
    # fields: severity normalized to low|medium|high and a remediation.
    problems = []
    for pid, cls in _plugins():
        ctx = DeadCtx()
        target = base.Target(raw="https://example.com/", type="url",
                             normalized="https://example.com/")
        try:
            res = asyncio.run(asyncio.wait_for(
                cls().run(target, ctx), timeout=25))
        except Exception:  # noqa: BLE001
            continue  # covered by the throw-tests above
        for f in res.findings:
            sev = (f.evidence or {}).get("severity")
            if sev not in ("low", "medium", "high"):
                problems.append(f"{pid}: finding {f.key} severity={sev!r}")
            if not (f.evidence or {}).get("remediation"):
                problems.append(f"{pid}: finding {f.key} has no remediation")
            if not (0 <= f.confidence <= 100):
                problems.append(
                    f"{pid}: finding {f.key} confidence={f.confidence}")
    assert not problems, "finding shape problems:\n" + "\n".join(problems)
