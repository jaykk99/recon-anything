"""Beyond-recon plugin batch (2026-11-05): fixture tests.

Every plugin must fire on its VULN fixture and stay silent on its
CLEAN fixture, through the real Plugin.run path with a stubbed Ctx
(probe/fetch_page backed by fixture maps - no network).

Plugins: nuclei_template_verify, content_discovery_ffuf,
param_discovery_arjun, js_endpoint_mining_linkfinder,
wayback_surface_waymore, lifecycle_orchestrator.
"""
import asyncio
import os
import sys
from urllib.parse import parse_qsl, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.plugins import wayback_surface as ws_mod  # noqa: E402
from app.plugins.base import PageData, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

BASE = "https://example.com/"
NEW_IDS = ["nuclei_template_verify", "lifecycle_orchestrator",
           "content_discovery_ffuf", "param_discovery_arjun",
           "js_endpoint_mining_linkfinder", "wayback_surface_waymore"]


class _FakeCache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        return None


def _resp(status, text="", headers=None, url=""):
    hdrs = {str(k).lower(): v for k, v in (headers or {}).items()}
    return {"status": status, "headers": hdrs, "text": text,
            "url": url, "length": len(text)}


class FakeCtx:
    """Ctx stub: probe/fetch_page served from fixture callables."""

    def __init__(self, pages=None, probe_fn=None, mode="active"):
        self.run_id = "test"
        self.mode = mode
        self.http = None
        self.cache = _FakeCache()
        self.keys = {}
        self.limiter = None
        self.emit = None
        self.event_bus = None
        self.module_overrides = {}
        self.evidence_dir = "/tmp"
        self.source_type = "website"
        self.shared = {}
        self._pages = pages or {}
        self._probe_fn = probe_fn or (lambda url: _resp(404, "nope"))

    def publish(self, kind, item):
        bucket = self.shared.setdefault(kind, [])
        if isinstance(item, str):
            if item not in bucket:
                bucket.append(item)
        else:
            bucket.append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    async def fetch_page(self, url, timeout=10):
        data = self._pages.get(url)
        if data is None:
            return None
        return PageData(data)

    async def probe(self, url, timeout=8):
        return self._probe_fn(url)


def _target():
    return Target(raw=BASE, type="url", normalized=BASE)


def _run(pid, ctx):
    plugin = discover()[pid]()
    return asyncio.run(plugin.run(_target(), ctx))


def _keys(res):
    return [f.key for f in res.findings]


# ----------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------

def test_new_plugins_registered():
    reg = discover()
    for pid in NEW_IDS:
        assert pid in reg, pid
    assert len(reg) == 1438  # 927 master + 10 Tier-4 Vuln/CVE plugins (PR #125) + 10 Tier-5 Orchestration plugins (PR #123) + 8 Tier-6 Detection plugins (PR #126) + 10 Tier-7 Blockchain Ingestion plugins (PR #127) + 5 Tier-8 Static Analysis plugins (PR #129) + 8 Tier-9 plugins (PR #128) + 10 Tier-10 Mempool/MEV plugins (PR #130) + 1 cache_control_audit plugin


# ----------------------------------------------------------------------
# nuclei_template_verify
# ----------------------------------------------------------------------

def _nuclei_probe(vuln):
    def fn(url):
        path = urlparse(url).path
        if path == "/":
            srv = "Apache/2.4.49 (Unix)" if vuln else "Apache/2.4.62"
            return _resp(200, "home page", {"Server": srv}, url)
        if not vuln:
            return _resp(404, "not found", {}, url)
        table = {
            "/.git/HEAD": _resp(200, "ref: refs/heads/main\n", {}, url),
            "/.env": _resp(200, "APP_KEY=supersecretvalue\n"
                                "DB_HOST=db.internal\n", {}, url),
        }
        return table.get(path, _resp(404, "not found", {}, url))
    return fn


def test_nuclei_fires_on_vuln_fixture():
    res = _run("nuclei_template_verify",
               FakeCtx(probe_fn=_nuclei_probe(True)))
    keys = _keys(res)
    assert "git_exposed" in keys
    assert "exposed_env" in keys
    assert "cve_version_match" in keys
    env_hit = [f for f in res.findings if f.key == "exposed_env"][0]
    assert "APP_KEY" in env_hit.evidence["exposed_key_names"]
    # Flag, don't exfiltrate: the secret VALUE appears nowhere.
    blob = str(res.findings)
    assert "supersecretvalue" not in blob
    assert "db.internal" not in blob
    cve_hit = [f for f in res.findings
               if f.key == "cve_version_match"][0]
    assert cve_hit.evidence["cve"] == "CVE-2021-41773"


def test_nuclei_silent_on_clean_fixture():
    res = _run("nuclei_template_verify",
               FakeCtx(probe_fn=_nuclei_probe(False)))
    assert res.findings == []


def test_nuclei_passive_mode_is_silent():
    res = _run("nuclei_template_verify",
               FakeCtx(probe_fn=_nuclei_probe(True), mode="passive"))
    assert res.findings == []


# ----------------------------------------------------------------------
# content_discovery_ffuf
# ----------------------------------------------------------------------

_BASELINE = "spa shell page not found error"  # catch-all body


def _ffuf_probe(vuln):
    def fn(url):
        path = urlparse(url).path.lstrip("/")
        if not vuln:
            return _resp(200, _BASELINE, {}, url)
        special = {
            "admin": _resp(200, "Admin console login dashboard with "
                                "lots of unique content here", {}, url),
            "backup.zip": _resp(200, "PK\x03\x04binary", {}, url),
            "api": _resp(301, "", {"Location": "/api/"}, url),
            "api/users": _resp(200, '[{"id": 1, "name": "ada lovelace", '
                                    '"role": "admin"}, {"id": 2, '
                                    '"name": "grace hopper", '
                                    '"role": "operator"}, {"id": 3, '
                                    '"name": "alan turing", '
                                    '"role": "analyst"}]',
                               {}, url),
        }
        return special.get(path, _resp(200, _BASELINE, {}, url))
    return fn


def test_ffuf_fires_on_vuln_fixture():
    res = _run("content_discovery_ffuf",
               FakeCtx(probe_fn=_ffuf_probe(True)))
    values = " ".join(f.value for f in res.findings)
    assert "/admin" in values
    assert "backup.zip" in values
    assert "/api/users" in values  # depth-1 recursion into /api
    for f in res.findings:
        assert f.key == "discovered_path"
        assert f.evidence["contents_stored"] is False


def test_ffuf_silent_on_clean_fixture():
    res = _run("content_discovery_ffuf",
               FakeCtx(probe_fn=_ffuf_probe(False)))
    assert res.findings == []


# ----------------------------------------------------------------------
# param_discovery_arjun
# ----------------------------------------------------------------------

_ARJUN_BASELINE = ("Item catalogue page with many descriptive words "
                   "padding the body length out quite a long way")


def _arjun_probe(url):
    q = dict(parse_qsl(urlparse(url).query))
    if q.get("q", "").endswith("'"):
        return _resp(200, "Error: You have an error in your SQL "
                          "syntax near the supplied value", {}, url)
    if "id" in q:
        return _resp(200, "Item detail for one specific product: "
                          "completely different body with far more "
                          "descriptive content than the catalogue "
                          "listing page ever shows anyone", {}, url)
    return _resp(200, _ARJUN_BASELINE, {}, url)


def _arjun_probe_clean(url):
    return _resp(200, _ARJUN_BASELINE, {}, url)


def test_arjun_fires_on_vuln_fixture():
    res = _run("param_discovery_arjun",
               FakeCtx(probe_fn=_arjun_probe))
    by_key = {}
    for f in res.findings:
        by_key.setdefault(f.key, []).append(f.evidence.get("parameter"))
    assert by_key.get("idor_suspect_param") == ["id"]
    assert by_key.get("sqli_suspect_param") == ["q"]
    for f in res.findings:
        assert f.evidence["confirmed"] is False  # suspects, not proof


def test_arjun_silent_on_clean_fixture():
    res = _run("param_discovery_arjun",
               FakeCtx(probe_fn=_arjun_probe_clean))
    assert res.findings == []


# ----------------------------------------------------------------------
# js_endpoint_mining_linkfinder
# ----------------------------------------------------------------------

_VULN_JS = """
const apiBase = "/api/v2";
fetch("/api/v2/users?id=42").then(r => r.json());
axios.get('/internal/metrics');
const cfg = { awsKey: "AKIAIOSFODNN7EXAMPLE", region: "us-east-1" };
"""
_CLEAN_JS = """
function add(a, b) { return a + b; }
console.log("hello world");
document.title = "Welcome";
"""


def _js_ctx(js_text):
    pages = {
        BASE: {"status_code": 200, "headers": {},
               "text": '<html><head><script src="/static/app.js">'
                       "</script></head><body>hi</body></html>",
               "url": BASE},
        BASE + "static/app.js": {"status_code": 200, "headers": {},
                                 "text": js_text,
                                 "url": BASE + "static/app.js"},
    }
    return FakeCtx(pages=pages)


def test_linkfinder_fires_on_vuln_fixture():
    ctx = _js_ctx(_VULN_JS)
    res = _run("js_endpoint_mining_linkfinder", ctx)
    keys = _keys(res)
    assert "js_secret_shape" in keys
    assert "mined_endpoint" in keys
    secret = [f for f in res.findings if f.key == "js_secret_shape"][0]
    assert secret.evidence["secret_type"] == "aws_access_key"
    assert secret.evidence["value_stored"] is False
    assert len(secret.evidence["sha256_fingerprint"]) == 12
    # The full secret value appears NOWHERE in the findings.
    assert "AKIAIOSFODNN7EXAMPLE" not in str(res.findings)
    # Endpoints were published to the discovery bus for chain plugins.
    bus = ctx.consume("endpoints")
    assert any("/api/v2/users" in e for e in bus)


def test_linkfinder_silent_on_clean_fixture():
    res = _run("js_endpoint_mining_linkfinder", _js_ctx(_CLEAN_JS))
    assert res.findings == []


# ----------------------------------------------------------------------
# wayback_surface_waymore
# ----------------------------------------------------------------------

_CDX_ROWS = [
    ["original", "timestamp"],
    ["https://example.com/old-admin/", "20150301000000"],
    ["https://example.com/admin-legacy", "20160202000000"],
    ["https://example.com/old-backup/", "20160303000000"],
    ["https://example.com/about", "20190404000000"],
    ["https://evil.com/admin", "20170505000000"],
    ["http://example.com/%22%20+%20payload", "20180606000000"],
]


class _FakeResp:
    status_code = 200

    def json(self):
        return _CDX_ROWS


def _wayback_ctx(live):
    def probe_fn(url):
        if not live:
            return _resp(404, "gone", {}, url)
        table = {
            "/old-admin/": _resp(200, "old admin panel", {}, url),
            "/admin-legacy": _resp(403, "forbidden", {}, url),
        }
        path = urlparse(url).path
        return table.get(path, _resp(404, "gone", {}, url))
    return FakeCtx(probe_fn=probe_fn)


def _run_wayback(monkeypatch, live):
    async def fake_fetch(client, limiter, method, url, **kw):
        return _FakeResp()
    monkeypatch.setattr(ws_mod, "fetch", fake_fetch)
    return _run("wayback_surface_waymore", _wayback_ctx(live))


def test_wayback_fires_on_vuln_fixture(monkeypatch):
    res = _run_wayback(monkeypatch, live=True)
    keys = _keys(res)
    assert keys.count("forgotten_live_endpoint") == 1
    assert keys.count("forgotten_protected_endpoint") == 1
    live_hit = [f for f in res.findings
                if f.key == "forgotten_live_endpoint"][0]
    assert "old-admin" in live_hit.value
    assert live_hit.evidence["first_archived"] == "20150301000000"
    # Off-domain and junk-payload rows never became findings.
    assert "evil.com" not in str(res.findings)
    assert "payload" not in str(res.findings)


def test_wayback_silent_on_clean_fixture(monkeypatch):
    res = _run_wayback(monkeypatch, live=False)
    assert res.findings == []


# ----------------------------------------------------------------------
# lifecycle_orchestrator
# ----------------------------------------------------------------------

def _lifecycle_ctx(vuln):
    links = ('<a href="/admin">Admin</a><a href="/api/users">API</a>'
             '<script src="/app.js"></script>') if vuln else \
            '<a href="/about">About</a>'
    pages = {BASE: {"status_code": 200, "headers": {}, "text": links,
                    "url": BASE}}

    def probe_fn(url):
        path = urlparse(url).path
        if vuln and path in ("/admin", "/api/users"):
            return _resp(200, "ok", {}, url)
        return _resp(404, "nope", {}, url)
    return FakeCtx(pages=pages, probe_fn=probe_fn)


def test_lifecycle_fires_on_vuln_fixture():
    res = _run("lifecycle_orchestrator", _lifecycle_ctx(True))
    keys = _keys(res)
    assert "lifecycle_risk_report" in keys
    assert keys.count("lifecycle_priority_target") == 2
    report = [f for f in res.findings
              if f.key == "lifecycle_risk_report"][0]
    stages = report.evidence["stages"]
    assert stages["assets"]["js_files"] == 1
    assert stages["verified_live"] == 2
    top = [f for f in res.findings
           if f.key == "lifecycle_priority_target"][0]
    assert "/admin" in top.value
    assert top.evidence["remediation"]  # every priority has its fix


def test_lifecycle_silent_on_clean_fixture():
    res = _run("lifecycle_orchestrator", _lifecycle_ctx(False))
    assert res.findings == []
