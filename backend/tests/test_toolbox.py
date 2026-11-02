"""Audit Toolbox (audit_toolbox) tests.

Layers:
1. Parsers against SAVED fixture outputs captured from real runs of
   each tool against tests/fixtures/toolbox/Vulnerable.sol (canary:
   Ethernaut Fallback pattern + reentrancy-after-call + tx.origin +
   selfdestruct) and Clean.sol (guarded control):
   slither / aderyn / smtchecker / heimdall / echidna / medusa /
   goplus / honeypot.
2. Normalization: severity mapping, key shape, SWC ids, evidence.
3. Availability / absence: a missing binary yields no adapter output
   and never raises; availability() reports it honestly.
4. Lane gating: heavy adapters do not execute without the heavy
   opt-in (one info finding instead); light adapters are unaffected.
5. Plugin run with the chain layer stubbed (no network): light lane
   end-to-end (heimdall bytecode + API parsers stubbed at the fetch
   layer), no-source path, registry discovery.
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import toolbox  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "fixtures", "toolbox")
ADDR = "0x" + "ab" * 20
REQ = "0x8f8221afbb33998d8584a2b05749ba73c37a938a"


def _load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


def _load_json(name):
    return json.loads(_load(name))


def _src(name):
    return _load(name)


# ---------------------------------------------------------------------------
# 1. Parser fixtures (real tool outputs)
# ---------------------------------------------------------------------------

def test_slither_parser_flags_canary():
    hits = toolbox.parse_slither(_load_json("slither-vulnerable.json"),
                                  _src("Vulnerable.sol"))
    by_detector = {h["detector"]: h for h in hits}
    assert "reentrancy-eth" in by_detector
    assert by_detector["reentrancy-eth"]["severity"] == "high"
    assert by_detector["reentrancy-eth"]["swc_id"] == "SWC-107"
    assert "suicidal" in by_detector
    assert by_detector["suicidal"]["swc_id"] == "SWC-106"
    assert "tx-origin" in by_detector
    assert by_detector["tx-origin"]["swc_id"] == "SWC-115"
    # evidence carries the actual code the tool pointed at
    assert "call{value" in by_detector["reentrancy-eth"]["code"]


def test_slither_parser_clean_control_has_no_high():
    hits = toolbox.parse_slither(_load_json("slither-clean.json"),
                                  _src("Clean.sol"))
    assert all(h["severity"] != "high" for h in hits)


def test_aderyn_parser_flags_canary():
    hits = toolbox.parse_aderyn(_load_json("aderyn-vulnerable.json"),
                                 _src("Vulnerable.sol"))
    detectors = {h["detector"] for h in hits}
    assert "reentrancy-state-change" in detectors
    reent = next(h for h in hits
                 if h["detector"] == "reentrancy-state-change")
    assert reent["severity"] == "high"
    assert reent["swc_id"] == "SWC-107"
    assert "tx-origin-used-for-auth" in detectors


def test_aderyn_parser_clean_control_no_reentrancy():
    hits = toolbox.parse_aderyn(_load_json("aderyn-clean.json"),
                                 _src("Clean.sol"))
    assert not any("reentrancy" in h["detector"] for h in hits)


def test_smtchecker_parser():
    hits = toolbox.parse_smtchecker(_load("smt-vulnerable.txt"))
    assert hits, "CHC overflow warnings must parse"
    assert all(h["tool"] == "smtchecker" for h in hits)
    assert any("verflow" in h["message"] for h in hits)
    # solver-absent output is absence, not findings
    absent = ("Warning: Solver z3 was selected for SMTChecker but "
              "it is not available.\nWarning: CHC analysis was not "
              "possible since no Horn solver was found")
    assert toolbox.parse_smtchecker(absent) == []


def test_heimdall_parser():
    hits = toolbox.parse_heimdall_asm(_load("heimdall-vulnerable.asm"))
    ops = {h["detector"] for h in hits}
    assert "opcode_selfdestruct" in ops
    sd = next(h for h in hits if h["detector"] == "opcode_selfdestruct")
    assert sd["severity"] == "high"
    assert sd["bytecode_only"] is True


def test_echidna_parser():
    hits = toolbox.parse_echidna(_load("echidna-vulnerable.txt"))
    assert len(hits) == 1
    assert hits[0]["tool"] == "echidna"
    assert hits[0]["severity"] == "high"
    assert hits[0]["simulation_candidate"] is True
    # a passing run produces nothing
    assert toolbox.parse_echidna("attack(): passing\n") == []


def test_medusa_parser():
    hits = toolbox.parse_medusa(_load("medusa-vulnerable.txt"))
    assert len(hits) == 1
    assert hits[0]["tool"] == "medusa"
    assert "attack" in hits[0]["detector"]
    assert toolbox.parse_medusa("Test summary: 5 test(s) passed") == []


def test_semgrep_parser_real_fixture():
    # Real output of semgrep + the cached solidity pack on the
    # canary (the pack's generic rules are mostly protocol-specific;
    # the one hit is a performance INFO, parsed and normalized).
    hits = toolbox.parse_semgrep(_load_json("semgrep-vulnerable.json"),
                                  _src("Vulnerable.sol"))
    assert len(hits) == 1
    assert hits[0]["tool"] == "semgrep"
    assert hits[0]["detector"] == "non-payable-constructor"
    assert hits[0]["severity"] == "low"
    # 'requires login' redaction must not leak into evidence code
    assert "requires login" not in hits[0]["code"]
    assert "constructor" in hits[0]["code"]


def test_semgrep_parser_shape():
    data = {"results": [{
        "check_id": "solidity.security.delegatecall-to-arbitrary-address",
        "path": "Contract.sol", "start": {"line": 12},
        "extra": {"severity": "ERROR",
                  "message": "Delegatecall to arbitrary address",
                  "lines": "target.delegatecall(data);"}}],
        "errors": []}
    hits = toolbox.parse_semgrep(data, "")
    assert len(hits) == 1
    assert hits[0]["severity"] == "high"      # ERROR -> high
    assert hits[0]["swc_id"] == "SWC-112"
    assert hits[0]["code"] == "target.delegatecall(data);"


def test_goplus_parser_clean_req():
    hits = toolbox.parse_goplus(_load_json("goplus-req.json"), REQ)
    assert len(hits) == 1
    assert hits[0]["detector"] == "token_security_profile"
    assert hits[0]["severity"] == "low"


def test_goplus_parser_honeypot_flags():
    data = {"result": {ADDR: {"is_honeypot": "1", "is_mintable": "1",
                              "sell_tax": "0.25",
                              "can_take_back_ownership": "0"}}}
    hits = toolbox.parse_goplus(data, ADDR)
    detectors = {h["detector"] for h in hits}
    assert "is_honeypot" in detectors
    assert "is_mintable" in detectors
    assert "sell_tax" in detectors
    assert next(h for h in hits
                if h["detector"] == "is_honeypot")["severity"] == "high"


def test_honeypot_parser():
    hits = toolbox.parse_honeypot(_load_json("honeypot-req.json"))
    assert len(hits) == 1 and hits[0]["severity"] == "low"
    bad = toolbox.parse_honeypot(
        {"honeypotResult": {"isHoneypot": True}})
    assert bad and bad[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# 2. Normalization + SWC
# ---------------------------------------------------------------------------

def test_severity_mapping():
    assert toolbox.map_severity("High") == "high"
    assert toolbox.map_severity("ERROR") == "high"
    assert toolbox.map_severity("WARNING") == "medium"
    assert toolbox.map_severity("Informational") == "low"
    assert toolbox.map_severity("whatever") == "low"


def test_swc_table():
    assert toolbox.swc_for("reentrancy-eth") == "SWC-107"
    assert toolbox.swc_for("unknown-detector") == ""
    assert toolbox.swc_for("custom", "uses tx.origin for auth") \
        == "SWC-115"


def test_normalized_key_shape():
    hit = toolbox._norm("slither", "reentrancy-eth", "High", "msg")
    assert hit["key"] == "slither_reentrancy_eth"
    assert hit["severity"] == "high"


# ---------------------------------------------------------------------------
# 3. Availability / absence behavior
# ---------------------------------------------------------------------------

def test_availability_shape():
    avail = toolbox.availability()
    for name in ("slither", "aderyn", "semgrep", "smtchecker",
                 "heimdall", "echidna", "medusa", "goplus", "honeypot"):
        assert name in avail
    assert avail["goplus"]["available"] is True   # keyless API
    assert avail["slither"]["lane"] == "static"
    assert avail["echidna"]["lane"] == "fuzz"


def test_missing_binary_adapters_are_silent(tmp_path, monkeypatch):
    monkeypatch.setattr(toolbox, "AUDIT_BIN", str(tmp_path / "nope"))
    monkeypatch.setattr(toolbox, "SLITHER_VENV", str(tmp_path / "nope"))
    monkeypatch.setattr(toolbox, "SEMGREP_VENV", str(tmp_path / "nope"))
    monkeypatch.setenv("PATH", str(tmp_path))
    assert toolbox.tool_binary("slither") is None
    src = _src("Vulnerable.sol")
    assert asyncio.run(toolbox._adapt_slither(
        str(tmp_path), src, 10)) == []
    assert asyncio.run(toolbox._adapt_semgrep(
        str(tmp_path), src, 10)) == []
    assert asyncio.run(toolbox._adapt_heimdall(
        str(tmp_path), "0x6001ff", 10)) == []
    monkeypatch.setattr(toolbox, "_solc_for", lambda source: None)
    assert asyncio.run(toolbox._adapt_smtchecker(
        str(tmp_path), src, 10)) == []


# ---------------------------------------------------------------------------
# 4. Lane gating + registry
# ---------------------------------------------------------------------------

def test_plugin_metadata():
    plugin = discover()["audit_toolbox"]()
    assert plugin.lane == "heavy"
    assert plugin.group == "web3"
    assert plugin.accepts == ["crypto_wallet", "domain", "url"]
    assert plugin.requires_keys == []


def test_heavy_gate():
    plugin = discover()["audit_toolbox"]()
    ctx = Ctx(run_id="t", mode="active", http=None, cache=None,
              keys={})
    assert plugin._heavy_enabled(ctx) is False
    ctx.shared["allow_heavy"] = True
    assert plugin._heavy_enabled(ctx) is True


def test_registry_count_includes_toolbox():
    reg = discover()
    assert "audit_toolbox" in reg
    # Canonical count is 640 in the full-suite context (639 + this
    # plugin; the seven pack suites assert it exactly). A bare
    # standalone run can discover MORE: a dozen plugin modules
    # import fine standalone in this venv but are skipped in the
    # full-suite import order on unmodified master too (651 vs 639
    # there), so this test asserts the floor, not the exact count.
    assert len(reg) >= 640


# ---------------------------------------------------------------------------
# 5. Plugin run, chain layer + heavy adapters stubbed (no network)
# ---------------------------------------------------------------------------

class _FakeCache:
    def get(self, ns, key):
        return None

    def set(self, ns, key, val, ttl=None):
        pass


def test_plugin_run_light_lane(monkeypatch):
    from app.plugins import contract_chain as cc

    async def fake_get_code(ctx, chain, address):
        return "0x60006000fd" if chain.id == "ethereum" else "0x"

    async def fake_source(ctx, chain, address, key=None):
        return {"source": _src("Vulnerable.sol"),
                "contract_name": "VulnerableVault",
                "compiler": "v0.8.20", "proxy": False,
                "implementation": "", "origin": "Blockscout"}

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)

    async def fake_heimdall(workdir, code_hex, budget):
        return [toolbox._norm("heimdall", "opcode_selfdestruct",
                               "high", "SELFDESTRUCT present",
                               code="0002ac SELFDESTRUCT",
                               extra={"opcode": "SELFDESTRUCT",
                                      "bytecode_only": True})]

    async def fake_semgrep(workdir, source, budget):
        return []

    async def fake_api(self, ctx, chain, addr):
        return toolbox.parse_goplus(_load_json("goplus-req.json"),
                                    addr)

    monkeypatch.setattr(toolbox, "_adapt_heimdall", fake_heimdall)
    monkeypatch.setattr(toolbox, "_adapt_semgrep", fake_semgrep)
    monkeypatch.setattr(toolbox.AuditToolboxPlugin, "_api_hits",
                        fake_api)

    plugin = toolbox.AuditToolboxPlugin()
    ctx = Ctx(run_id="t", mode="active", http=None,
              cache=_FakeCache(), keys={})
    target = Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                    normalized=f"ethereum:{ADDR}")
    res = asyncio.run(plugin.run(target, ctx))
    keys = {f.key for f in res.findings}
    assert "heimdall_opcode_selfdestruct" in keys
    assert "goplus_token_security_profile" in keys
    # heavy lane is OFF here: no slither/aderyn findings may appear,
    # and when heavy tools exist in this env, exactly one info
    # finding explains they were not run in the fast lane.
    assert not any(k.startswith("slither_") for k in keys)
    avail = toolbox.availability()
    if any(avail[n]["available"] for n in toolbox.HEAVY_TOOLS):
        assert "heavy_lane_not_run" in keys


def test_plugin_no_address_skips():
    plugin = toolbox.AuditToolboxPlugin()
    ctx = Ctx(run_id="t", mode="passive", http=None,
              cache=_FakeCache(), keys={})
    target = Target(raw="example.com", type="domain",
                    normalized="example.com")
    res = asyncio.run(plugin.run(target, ctx))
    assert res.findings == []
