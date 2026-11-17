"""Reverse-IP shared-infra guard: don't balloon a scan with co-tenants.

A scan of one site produced 600+ findings because reverse-IP fired on a
shared Render/Cloudflare address and promoted every stranger's domain
into a scan target. These lock in the guard: CDN/PaaS addresses are
recognised and skipped, and an unlisted shared host (too many owners on
one address) is summarised instead of expanded.

Network-free: the shared-IP path returns before any fetch.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.cdn_ranges import classify_ip, is_shared_edge_ip  # noqa: E402


def _get_plugin():
    from app.plugins.registry import discover
    cls = discover().get("reverse_ip")
    assert cls is not None
    return cls()


class _Cache:
    def get(self, ns, k):
        return None

    def set(self, ns, k, v, ttl=None):
        pass

    async def cached(self, ns, k, fn):
        return await fn(), False


class _Ctx:
    def __init__(self):
        self.run_id = "t"
        self.mode = "passive"
        self.cache = _Cache()
        self.shared = {}
        self.module_overrides = {}

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


class _T:
    def __init__(self, ip):
        self.normalized = ip
        self.raw = ip
        self.type = "ip"
        self.id = "t1"


# -- classifier ------------------------------------------------------------

def test_known_shared_ranges_classified():
    assert classify_ip("216.24.57.16") == "Render"
    assert classify_ip("104.20.23.154") == "Cloudflare"
    assert classify_ip("172.66.147.243") == "Cloudflare"
    assert classify_ip("151.101.1.1") == "Fastly"
    assert classify_ip("13.32.5.5") == "Amazon CloudFront"
    assert classify_ip("185.199.108.153") == "GitHub Pages"
    assert classify_ip("2606:4700::1111") == "Cloudflare"


def test_non_shared_ips_not_classified():
    for ip in ("93.184.216.34", "1.2.3.4", "198.51.100.7"):
        assert classify_ip(ip) is None
        assert not is_shared_edge_ip(ip)


def test_bad_input_never_raises():
    assert classify_ip("") is None
    assert classify_ip("not-an-ip") is None
    assert classify_ip(None) is None


# -- plugin guard ----------------------------------------------------------

def test_reverse_ip_skips_shared_edge_without_network():
    p = _get_plugin()
    res = asyncio.run(p.run(_T("216.24.57.16"), _Ctx()))
    keys = [f.key for f in res.findings]
    # exactly one informational note, and crucially NO cohosted_domain
    # (nothing for the hunter to promote into a scan target)
    assert "reverse_ip_skipped" in keys
    assert "cohosted_domain" not in keys
    assert len(res.findings) == 1
    assert res.findings[0].evidence.get("provider") == "Render"


def test_reverse_ip_runs_on_dedicated_ip_shape():
    # A non-shared IP must NOT be short-circuited by the guard (it will
    # then go on to the real passive lookups).
    assert classify_ip("93.184.216.34") is None


def test_registrable_root_counts_owners():
    from app.plugins.reverse_ip import _registrable_root
    assert _registrable_root("a.example.com") == "example.com"
    assert _registrable_root("x.y.example.co.uk") == "example.co.uk"
    assert _registrable_root("example.com") == "example.com"


# -- port_scan shared-edge guard ------------------------------------------

def _port_scan_plugin():
    from app.plugins.registry import discover
    cls = discover().get("port_scan")
    assert cls is not None
    return cls()


def test_port_scan_skips_active_scan_on_shared_edge_ip():
    # An IP target resolves to itself (no network), so this exercises the
    # guard offline: active scan of a Render edge IP must be skipped.
    p = _port_scan_plugin()
    ctx = _Ctx()
    ctx.mode = "active"
    res = asyncio.run(p.run(_T("216.24.57.16"), ctx))
    keys = [f.key for f in res.findings]
    assert "port_scan_skipped_shared_edge" in keys
    # it must NOT have emitted real open-port findings for the provider
    assert not any(k.startswith("open_port") or k == "port" for k in keys)


def test_port_scan_runs_on_ordinary_ip():
    # A non-shared IP is not short-circuited by the guard (classifier None).
    assert classify_ip("93.184.216.34") is None
