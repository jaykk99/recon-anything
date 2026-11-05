"""Sourcify v2 verified-source route in contract_chain.

Covers, with the network layer (contract_chain.fetch) stubbed the
same way tests/test_fetch_page_contract.py stubs app.ratelimit.fetch
(a fake async fetch returning objects with status_code / json() /
text):

- _parse_sourcify_v2_payload on a REAL v2 response shape (WBNB on
  BSC, chain 56, fetched live from
  https://sourcify.dev/server/v2/contract/56/0xbb4...095c on
  2026-11-04 and trimmed to a fixture below);
- fallback order: Blockscout -> Sourcify v2 -> legacy Sourcify repo
  route -> Etherscan (key only);
- fetch_verified_source_with_status honest "degraded" reporting;
- per-run memoization on ctx.shared["_source_cache"] (successes
  only).
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import contract_chain as cc  # noqa: E402

WBNB = "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c"
BSC = cc.CHAINS["bsc"]

# Trimmed from the live Sourcify v2 response for WBNB (chain 56):
# compilation block verbatim (minus compilerSettings), and the head
# of the single WBNB.sol source file verbatim.
WBNB_SOURCE = """/**
 *Submitted for verification at Bscscan.com on 2020-09-03
*/

pragma solidity ^0.4.18;

contract WBNB {
    string public name     = "Wrapped BNB";
    string public symbol   = "WBNB";
    uint8  public decimals = 18;

    event  Approval(address indexed src, address indexed guy, uint wad);
    event  Transfer(address indexed src, address indexed dst, uint wad);
    event  Deposit(address indexed dst, uint wad);
    event  Withdrawal(address indexed src, uint wad);

    mapping (address => uint)                       public  balanceOf;
    mapping (address => mapping (address => uint))  public  allowance;

    function() public payable {
        deposit();
    }
    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        Deposit(msg.sender, msg.value);
    }
    function withdraw(uint wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        msg.sender.transfer(wad);
        Withdrawal(msg.sender, wad);
    }
}
"""

WBNB_V2_PAYLOAD = {
    "sources": {"WBNB.sol": {"content": WBNB_SOURCE}},
    "compilation": {
        "language": "Solidity",
        "compiler": "solc",
        "compilerVersion": "0.4.18+commit.9cf6e910",
        "name": "WBNB",
        "fullyQualifiedName": "WBNB.sol:WBNB",
    },
    "chainId": "56",
    "address": WBNB,
}

BLOCKSCOUT_SOURCE = (
    "pragma solidity ^0.8.20;\n\n"
    "contract Blocky {\n"
    "    uint256 public value;\n"
    "    function set(uint256 v) public { value = v; }\n"
    "}\n")


class FakeCtx:
    def __init__(self, shared=None):
        self.keys = {}
        self.mode = "passive"
        self.http = None
        self.limiter = None
        self.cache = None
        self.run_id = "test"
        self.module_overrides = {}
        self.shared = shared if shared is not None else {}


class FakeResp:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        return self._payload


def _install_fetch(monkeypatch, handler):
    """Patch contract_chain.fetch (its own imported binding).

    handler(url) -> FakeResp. Returns the list of requested URLs.
    """
    calls = []

    async def fake_fetch(client, limiter, method, url, **kw):
        calls.append(url)
        return handler(url)

    monkeypatch.setattr(cc, "fetch", fake_fetch)
    return calls


def _is_blockscout(url):
    return "blockscout.com" in url


def _is_sourcify_v2(url):
    return "sourcify.dev/server/v2/contract/" in url


def _is_sourcify_legacy(url):
    return "repo.sourcify.dev" in url


def _is_etherscan(url):
    return "api.etherscan.io" in url


# ---------------------------------------------------------------------------
# Parser: real v2 response shape
# ---------------------------------------------------------------------------

def test_parse_real_wbnb_payload():
    got = cc._parse_sourcify_v2_payload(WBNB_V2_PAYLOAD, WBNB)
    assert got is not None
    assert got["contract_name"] == "WBNB"
    assert got["compiler"] == "0.4.18+commit.9cf6e910"
    assert got["origin"] == "Sourcify v2"
    assert got["proxy"] is False
    assert got["implementation"] == ""
    assert "// ==== WBNB.sol ====" in got["source"]
    assert "contract WBNB {" in got["source"]
    assert '"Wrapped BNB"' in got["source"]
    assert "function deposit() public payable" in got["source"]


def test_parse_rejects_empty_and_nonsol():
    assert cc._parse_sourcify_v2_payload({}, WBNB) is None
    assert cc._parse_sourcify_v2_payload(None, WBNB) is None
    assert cc._parse_sourcify_v2_payload(
        {"sources": {"notes.txt": {"content": "hello"}}}, WBNB) is None
    assert cc._parse_sourcify_v2_payload(
        {"sources": {"A.sol": {"content": ""}}}, WBNB) is None


def test_parse_sorted_sol_only_and_capped():
    payload = {"sources": {}, "compilation": {"name": "Many",
                                               "compilerVersion": "1"}}
    for i in reversed(range(50)):
        payload["sources"][f"c{i:02d}.sol"] = {"content": f"// file {i}"}
    payload["sources"]["zzz.json"] = {"content": "// not sol"}
    got = cc._parse_sourcify_v2_payload(payload, WBNB)
    assert got is not None
    assert got["source"].count("// ====") == 40  # capped at 40 parts
    assert "// ==== c00.sol ====" in got["source"]
    assert "// ==== c39.sol ====" in got["source"]
    assert "c40.sol" not in got["source"]  # sorted order, cap wins
    assert "zzz.json" not in got["source"]


# ---------------------------------------------------------------------------
# Fallback order (stubbed contract_chain.fetch)
# ---------------------------------------------------------------------------

def test_blockscout_404_falls_back_to_sourcify_v2(monkeypatch):
    def handler(url):
        if _is_blockscout(url):
            return FakeResp(404, text="default backend - 404")
        if _is_sourcify_v2(url):
            return FakeResp(200, payload=WBNB_V2_PAYLOAD)
        return FakeResp(404)

    calls = _install_fetch(monkeypatch, handler)
    ctx = FakeCtx()
    got = asyncio.run(cc.fetch_verified_source(ctx, BSC, WBNB))
    assert got is not None
    assert got["origin"] == "Sourcify v2"
    assert got["contract_name"] == "WBNB"
    assert any(_is_sourcify_v2(u) for u in calls)
    assert not any(_is_sourcify_legacy(u) for u in calls)

    ctx2 = FakeCtx()
    res = asyncio.run(cc.fetch_verified_source_with_status(ctx2, BSC, WBNB))
    assert res["status"] == "ok"
    assert res["source"]["origin"] == "Sourcify v2"
    assert res["routes_tried"] == ["Blockscout", "Sourcify v2"]


def test_blockscout_success_skips_sourcify_v2(monkeypatch):
    def handler(url):
        if _is_blockscout(url):
            return FakeResp(200, payload={"result": [{
                "SourceCode": BLOCKSCOUT_SOURCE,
                "ContractName": "Blocky",
                "CompilerVersion": "v0.8.20+commit.a1b2c3d4",
                "Proxy": "0",
                "Implementation": "",
            }]})
        return FakeResp(404)

    calls = _install_fetch(monkeypatch, handler)
    got = asyncio.run(cc.fetch_verified_source(FakeCtx(), BSC, WBNB))
    assert got is not None
    assert got["origin"] == "Blockscout"
    assert got["contract_name"] == "Blocky"
    assert not any(_is_sourcify_v2(u) for u in calls)
    assert not any(_is_sourcify_legacy(u) for u in calls)


def test_all_routes_fail_reports_degraded(monkeypatch):
    def handler(url):
        return FakeResp(404, payload={"result": []}, text="not found")

    _install_fetch(monkeypatch, handler)
    got = asyncio.run(cc.fetch_verified_source(
        FakeCtx(), BSC, WBNB, etherscan_key="test-key"))
    assert got is None

    ctx = FakeCtx()
    res = asyncio.run(cc.fetch_verified_source_with_status(
        ctx, BSC, WBNB, etherscan_key="test-key"))
    assert res["source"] is None
    assert res["status"] == "degraded"
    assert res["routes_tried"] == ["Blockscout", "Sourcify v2",
                                    "Sourcify", "Etherscan"]
    # Failures are never cached.
    assert not ctx.shared.get("_source_cache")


def test_no_etherscan_route_without_key(monkeypatch):
    def handler(url):
        return FakeResp(404, payload={"result": []}, text="not found")

    calls = _install_fetch(monkeypatch, handler)
    res = asyncio.run(cc.fetch_verified_source_with_status(
        FakeCtx(), BSC, WBNB))
    assert res["status"] == "degraded"
    assert res["routes_tried"] == ["Blockscout", "Sourcify v2", "Sourcify"]
    assert not any(_is_etherscan(u) for u in calls)


# ---------------------------------------------------------------------------
# Per-run memoization
# ---------------------------------------------------------------------------

def test_success_is_memoized_per_run(monkeypatch):
    def handler(url):
        if _is_blockscout(url):
            return FakeResp(404, text="default backend - 404")
        if _is_sourcify_v2(url):
            return FakeResp(200, payload=WBNB_V2_PAYLOAD)
        return FakeResp(404)

    calls = _install_fetch(monkeypatch, handler)
    ctx = FakeCtx()
    first = asyncio.run(cc.fetch_verified_source(ctx, BSC, WBNB))
    assert first is not None and first["origin"] == "Sourcify v2"
    n_after_first = len(calls)
    assert n_after_first == 2  # Blockscout miss + Sourcify v2 hit

    second = asyncio.run(cc.fetch_verified_source(ctx, BSC, WBNB))
    assert second == first
    assert len(calls) == n_after_first  # no second round of HTTP fetches

    # A different run (fresh shared) pays the fetches again.
    third = asyncio.run(cc.fetch_verified_source(FakeCtx(), BSC, WBNB))
    assert third == first
    assert len(calls) == 2 * n_after_first
