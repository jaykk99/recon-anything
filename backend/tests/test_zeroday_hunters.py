"""Tests for the zero-day candidate hunters.

Includes the CANARY PROOF: local fixtures the hunters have never
been told about -

(a) a tiny web app (httpx MockTransport) with a planted
    non-checklist bug: an array-typed parameter makes /api/item
    return a list it never returns for normal input, a null value
    crashes it, and a bad ID makes its error path leak an internal
    source path + SQL fragment. A clean control app with the same
    routes but correct validation must produce ZERO candidates.

(b) a fixture Solidity vault where one public state-changing
    function (emergencyWithdraw) is missing the onlyOwner guard all
    its siblings carry. The guard-consistency hunter must flag
    exactly that function, and stay silent on the fixed control.

No live network anywhere.
"""

import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.cache import Cache  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import zeroday_contract_guards as zg  # noqa: E402
from app.plugins import zeroday_differential as zd  # noqa: E402
from app.plugins import zeroday_error_miner as ze  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.zeroday_differential import (  # noqa: E402
    ZerodayDifferentialPlugin, body_mutations, evaluate_anomaly,
    mutations_for)
from app.plugins.zeroday_error_miner import (  # noqa: E402
    ZerodayErrorMinerPlugin, malformed_variants)
from app.plugins.zeroday_contract_guards import (  # noqa: E402
    ZerodayContractGuardsPlugin, analyze_guard_consistency, guards_of)
from app.plugins.zeroday_util import mine_disclosures  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) \
        if False else asyncio.run(coro)


# =====================================================================
# Canary web app (a): buggy + clean control, served via MockTransport
# =====================================================================

LEAK_BODY = (
    'Traceback (most recent call last):\n'
    '  File "/srv/app/handlers/item.py", line 42, in get_item\n'
    '    row = db.query("SELECT * FROM items WHERE id = " + raw)\n'
    'psycopg2.errors.UndefinedTable: relation "secret_items" '
    'does not exist')

_requests_seen: list = []


def _item_ok(single=True):
    if single:
        return httpx.Response(200, json={"id": 1, "name": "widget",
                                         "price": 10})
    return httpx.Response(200, json=[
        {"id": 1, "name": "widget", "price": 10},
        {"id": 2, "name": "gadget", "price": 25}])


def _buggy_handler(request: httpx.Request) -> httpx.Response:
    _requests_seen.append(str(request.url))
    url = request.url
    if url.path != "/api/item":
        return httpx.Response(404, json={"error": "not found"})
    if request.method == "POST":
        return httpx.Response(400, json={"error": "bad body"})
    params = url.params
    if "id[]" in params:
        # PLANTED BUG: array-typed id returns the whole table.
        return _item_ok(single=False)
    raw = params.get("id", "")
    if raw == "null":
        # PLANTED BUG: null crashes the handler.
        return httpx.Response(500, text="Internal Server Error")
    if raw and not raw.lstrip("-").isdigit():
        # PLANTED BUG: bad ID reaches an error path that leaks
        # internals (source path + SQL fragment + traceback).
        return httpx.Response(500, text=LEAK_BODY)
    if raw in ("", "0", "-1") or (raw.isdigit() and int(raw) > 10 ** 6):
        return httpx.Response(404, json={"error": "not found"})
    return _item_ok(single=True)


def _clean_handler(request: httpx.Request) -> httpx.Response:
    _requests_seen.append(str(request.url))
    url = request.url
    if url.path != "/api/item":
        return httpx.Response(404, json={"error": "not found"})
    if request.method == "POST":
        return httpx.Response(400, json={"error": "bad body"})
    params = url.params
    raw = params.get("id", "")
    if "id[]" in params or not raw.isdigit() or int(raw) <= 0:
        return httpx.Response(400, json={"error": "invalid id"})
    if int(raw) > 10 ** 6:
        return httpx.Response(404, json={"error": "not found"})
    return _item_ok(single=True)


def _web_ctx(handler, mode="active"):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ctx = Ctx(run_id="canary", mode=mode, http=client, cache=Cache(),
              keys={}, limiter=RateLimiter(), evidence_dir="/tmp")
    ctx.publish("endpoints", "https://canary.test/api/item?id=1")
    return ctx


def _web_target():
    return Target(raw="https://canary.test/", type="url",
                  normalized="https://canary.test/")


def _candidates(result):
    return [f for f in result.findings
            if (f.evidence or {}).get("candidate_zero_day")]


def test_canary_differential_flags_planted_bugs():
    _requests_seen.clear()
    res = _run(ZerodayDifferentialPlugin().run(
        _web_target(), _web_ctx(_buggy_handler)))
    cands = _candidates(res)
    anomalies = {(c.evidence or {}).get("anomaly") for c in cands}
    assert "data_shaped_response_to_invalid_input" in anomalies
    assert "crash_on_mutation" in anomalies
    for c in cands:
        assert (c.evidence or {}).get("review_status", "") \
            .startswith("pending human review")
        assert (c.evidence or {}).get("severity") in \
            ("low", "medium", "high")


def test_canary_differential_clean_control_is_silent():
    res = _run(ZerodayDifferentialPlugin().run(
        _web_target(), _web_ctx(_clean_handler)))
    assert _candidates(res) == []


def test_canary_error_miner_finds_leak():
    res = _run(ZerodayErrorMinerPlugin().run(
        _web_target(), _web_ctx(_buggy_handler)))
    kinds = {(f.evidence or {}).get("disclosure_kind")
             for f in res.findings}
    assert "internal_file_path" in kinds
    assert "sql_fragment" in kinds
    cands = _candidates(res)
    assert cands and all(
        (c.evidence or {}).get("disclosure_kind")
        == "internal_file_path" for c in cands)


def test_canary_error_miner_clean_control_is_silent():
    res = _run(ZerodayErrorMinerPlugin().run(
        _web_target(), _web_ctx(_clean_handler)))
    assert res.findings == []


def test_passive_mode_never_sends_mutations():
    _requests_seen.clear()
    ctx = _web_ctx(_buggy_handler, mode="passive")
    res = _run(ZerodayDifferentialPlugin().run(_web_target(), ctx))
    assert res.findings == []
    assert _requests_seen == []
    res2 = _run(ZerodayErrorMinerPlugin().run(_web_target(), ctx))
    assert res2.findings == []
    assert _requests_seen == []


# =====================================================================
# Pure differential helpers
# =====================================================================

def test_mutations_cover_the_shape_set():
    muts = mutations_for("https://x.test/api/item?id=7&fmt=json", "id")
    names = {m["name"] for m in muts}
    assert {"array_type", "duplicate_param", "null_value", "empty_value",
            "negative_number", "zero_value", "huge_number",
            "object_value", "missing_param",
            "malformed_encoding"} <= names
    for m in muts:
        assert "fmt=json" in m["url"]  # other params preserved


def test_body_mutations_shapes():
    muts = body_mutations([("id", "7")])
    names = {m["name"] for m in muts}
    assert {"json_array_value", "json_object_value", "json_null_value",
            "json_truncated", "json_wrong_content_type"} == names


def test_evaluate_anomaly_data_shaped():
    base = {"status": 200, "text": '{"id": 1, "name": "w"}',
            "elapsed": 0.1}
    mut = {"status": 200, "text": '[{"id": 1}, {"id": 2}]',
           "elapsed": 0.1}
    sigs = evaluate_anomaly(base, mut)
    assert any(s["anomaly"] == "data_shaped_response_to_invalid_input"
               for s in sigs)


def test_evaluate_anomaly_crash_and_clean():
    base = {"status": 200, "text": '{"ok": true}', "elapsed": 0.1}
    crash = {"status": 500, "text": "Internal Server Error",
             "elapsed": 0.1}
    assert any(s["anomaly"] == "crash_on_mutation"
               for s in evaluate_anomaly(base, crash))
    same = {"status": 200, "text": '{"ok": true}', "elapsed": 0.1}
    assert evaluate_anomaly(base, same) == []


# =====================================================================
# Error miner helpers
# =====================================================================

def test_malformed_variants_bad_ids():
    vs = malformed_variants("https://x.test/api/item?id=7")
    names = {v["name"] for v in vs}
    assert {"bad_id_param", "huge_id_param", "negative_id_param",
            "bad_utf8"} <= names
    vs2 = malformed_variants("https://x.test/users/123")
    assert any(v["name"] == "bad_id_path" for v in vs2)


def test_mine_disclosures_kinds_and_dedup():
    text = (LEAK_BODY + "\n" + LEAK_BODY +
            "\nhost db01.internal:5432 down, 10.0.3.7 unreachable\n"
            "Django/4.2.7 error page")
    kinds = {d["kind"] for d in mine_disclosures(text)}
    assert {"internal_file_path", "sql_fragment", "debug_output",
            "internal_hostname", "internal_ip",
            "framework_version"} <= kinds
    paths = [d for d in mine_disclosures(text)
             if d["kind"] == "internal_file_path"]
    assert len(paths) == 1  # deduped despite appearing twice


# =====================================================================
# Canary contract (b): one unguarded sibling among guarded ones
# =====================================================================

VAULT_BUGGY = """
contract Vault {
    address public owner;
    uint256 public fee;
    bool public paused;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function setFee(uint256 f) public onlyOwner {
        fee = f;
    }

    function setPaused(bool p) public onlyOwner {
        paused = p;
    }

    function withdrawAll(address to) public onlyOwner {
        to.transfer(address(this).balance);
    }

    function emergencyWithdraw(address to) public {
        to.transfer(address(this).balance);
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
"""

VAULT_FIXED = VAULT_BUGGY.replace(
    "function emergencyWithdraw(address to) public {",
    "function emergencyWithdraw(address to) public onlyOwner {")


def test_canary_contract_flags_unguarded_sibling():
    cands = analyze_guard_consistency(VAULT_BUGGY)
    flagged = {c["function"] for c in cands
               if c["kind"] == "guard_convention_break"}
    assert flagged == {"emergencyWithdraw"}
    cand = cands[0]
    assert "onlyOwner" in cand["sibling_pattern"]
    assert "emergencyWithdraw" in cand["code"]


def test_canary_contract_fixed_control_is_silent():
    assert analyze_guard_consistency(VAULT_FIXED) == []


def test_standard_functions_not_flagged():
    src = """
    contract Token {
        address public owner;
        mapping(address => uint256) public balances;
        mapping(address => mapping(address => uint256)) public allowanceMap;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function setTax(uint256 t) public onlyOwner { tax = t; }
        function pause() public onlyOwner { paused = true; }
        uint256 public tax;
        bool public paused;
        function transfer(address to, uint256 amt) public {
            balances[msg.sender] -= amt;
            balances[to] += amt;
        }
    }
    """
    cands = analyze_guard_consistency(src)
    assert all(c["function"] != "transfer" for c in cands)


def test_missing_allowance_check_pair():
    src = """
    contract PairToken {
        mapping(address => uint256) public balances;
        mapping(address => mapping(address => uint256)) public allowances;
        function transferFrom(address from, address to, uint256 amt) public {
            require(allowances[from][msg.sender] >= amt);
            balances[from] -= amt;
            balances[to] += amt;
        }
        function moveFrom(address from, address to, uint256 amt) public {
            balances[from] -= amt;
            balances[to] += amt;
        }
    }
    """
    cands = analyze_guard_consistency(src)
    kinds = {(c["function"], c["kind"]) for c in cands}
    assert ("moveFrom", "missing_allowance_check") in kinds


def test_guards_of_detects_patterns():
    funcs = {f["name"]: f for f in cc.extract_functions(VAULT_BUGGY)}
    assert guards_of(funcs["setFee"]) == {"modifier:onlyOwner"}
    assert guards_of(funcs["emergencyWithdraw"]) == set()
    src = ("contract C { function f() public { "
           "require(msg.sender == owner); x = 1; } uint256 x; "
           "address owner; }")
    fn = cc.extract_functions(src)[0]
    assert any(g.startswith("sender_check:") for g in guards_of(fn))


# =====================================================================
# Contract plugin end-to-end (chain access monkeypatched)
# =====================================================================

ADDR = "0x1111111111111111111111111111111111111111"


def _contract_ctx():
    return Ctx(run_id="test", mode="active", http=None, cache=Cache(),
               keys={}, limiter=None, evidence_dir="/tmp")


def test_contract_plugin_emits_candidate(monkeypatch):
    async def fake_code(ctx, chain, addr):
        return "0x60806040"

    async def fake_source(ctx, chain, addr, key):
        return {"source": VAULT_BUGGY, "contract_name": "Vault",
                "implementation": ""}

    async def fake_resolve(ctx, chain, addr, code, src):
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)

    target = Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                    normalized=f"ethereum:{ADDR}")
    res = _run(ZerodayContractGuardsPlugin().run(
        target, _contract_ctx()))
    cands = [f for f in res.findings if f.key == "candidate_zero_day"]
    assert len(cands) == 1
    ev = cands[0].evidence or {}
    assert ev.get("candidate_zero_day") is True
    assert ev.get("function") == "emergencyWithdraw"
    assert ev.get("severity") == "high"
    assert "not yet verified" in cands[0].value


def test_contract_plugin_no_source_no_candidates(monkeypatch):
    async def fake_code(ctx, chain, addr):
        return "0x60806040"

    async def fake_source(ctx, chain, addr, key):
        return None

    async def fake_resolve(ctx, chain, addr, code, src):
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)

    target = Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                    normalized=f"ethereum:{ADDR}")
    res = _run(ZerodayContractGuardsPlugin().run(
        target, _contract_ctx()))
    assert res.findings == []


# =====================================================================
# Registry
# =====================================================================

def test_registry_discovers_hunters():
    from app.plugins.registry import discover
    reg = discover()
    assert "zeroday_differential" in reg
    assert "zeroday_error_miner" in reg
    assert "zeroday_contract_guards" in reg
    for pid in ("param_fuzzer", "error_pages", "contract_recon"):
        assert pid in reg  # pre-existing coverage untouched


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
