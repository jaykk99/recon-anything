"""Tests for r100 wave 1 (Track A): 5 new crypto detectors, CISA KEV
enrichment, CWE taxonomy map. No network: detector tests call the pure
analyze() functions on source fixtures; KEV tests use a fixture feed
plus the real shipped snapshot; the cves wiring test stubs the HTTP
transport. Run: PYTHONPATH=. <venv>/bin/python test_r100_wave1.py
"""
import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, "backend")

from app.cwe_map import cwe_for, label_for  # noqa: E402
from app import kev  # noqa: E402
from app.plugins import div_before_mul as d1  # noqa: E402
from app.plugins import unbounded_loop_dos as d2  # noqa: E402
from app.plugins import erc721_unsafe_transfer as d3  # noqa: E402
from app.plugins import payable_ignores_value as d4  # noqa: E402
from app.plugins import state_var_shadowing as d5  # noqa: E402
from app.plugins.base import Target  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name} {detail}")


def keys(hits):
    return [h["key"] for h in hits]


# ---------------------------------------------------------------- detectors
def test_div_before_mul():
    print("div_before_mul:")
    vuln = """
    pragma solidity ^0.8.20;
    contract Fee {
        function pay(uint amount, uint fee) public returns (uint) {
            uint out = amount / 100 * fee;
            return out;
        }
    }"""
    safe = """
    pragma solidity ^0.8.20;
    contract Fee {
        function pay(uint amount, uint fee) public returns (uint) {
            uint out = amount * fee / 100;
            return out;
        }
        function ratio(uint a, uint b) public returns (uint) {
            return a / b;
        }
    }"""
    paren = """
    pragma solidity ^0.8.20;
    contract Fee {
        function pay(uint a, uint b, uint c) public returns (uint) {
            return (a / b) * c;
        }
    }"""
    h = d1.analyze({"source": vuln})
    check("vuln flagged", keys(h) == ["div_before_mul_precision_loss"], keys(h))
    check("safe clean", d1.analyze({"source": safe}) == [])
    check("paren form flagged", len(d1.analyze({"source": paren})) == 1)
    check("empty source clean", d1.analyze({"source": ""}) == [])
    check("cwe in evidence", h and h[0]["evidence"].get("cwe") == "CWE-682")


def test_unbounded_loop():
    print("unbounded_loop_dos:")
    vuln = """
    pragma solidity ^0.8.20;
    contract Dist {
        address[] public users;
        mapping(address => uint) public balances;
        function payout(uint amt) public {
            for (uint i = 0; i < users.length; i++) {
                balances[users[i]] += amt;
            }
        }
    }"""
    vuln_calldata = """
    pragma solidity ^0.8.20;
    contract Batch {
        function batch(address[] calldata tos) public {
            for (uint i = 0; i < tos.length; i++) {
                (bool ok, ) = tos[i].call{value: 1}("");
                require(ok);
            }
        }
    }"""
    safe = """
    pragma solidity ^0.8.20;
    contract Dist {
        address[] public users;
        uint public total;
        function count() public view returns (uint s) {
            for (uint i = 0; i < users.length; i++) {
                s += 1;
            }
        }
        function fixed() public {
            for (uint i = 0; i < 10; i++) {
                total += i;
            }
        }
    }"""
    h = d2.analyze({"source": vuln})
    check("state-array loop flagged",
          keys(h) == ["unbounded_loop_gas_dos"], keys(h))
    check("calldata-array loop flagged",
          len(d2.analyze({"source": vuln_calldata})) == 1)
    check("pure-read / fixed loops clean",
          d2.analyze({"source": safe}) == [])
    check("cwe in evidence", h and h[0]["evidence"].get("cwe") == "CWE-400")


def test_erc721():
    print("erc721_unsafe_transfer:")
    vuln = """
    pragma solidity ^0.8.20;
    import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
    contract Market {
        IERC721 public nft;
        function buy(address seller, uint tokenId) public {
            nft.transferFrom(seller, msg.sender, tokenId);
        }
    }"""
    safe = """
    pragma solidity ^0.8.20;
    import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
    contract Market {
        IERC721 public nft;
        function buy(address seller, uint tokenId) public {
            nft.safeTransferFrom(seller, msg.sender, tokenId);
        }
    }"""
    erc20_only = """
    pragma solidity ^0.8.20;
    contract Pay {
        function move(address t, address a, address b, uint v) public {
            IERC20(t).transferFrom(a, b, v);
        }
    }
    interface IERC20 { function transferFrom(address,address,uint) external returns (bool); }"""
    h = d3.analyze({"source": vuln})
    check("unsafe transferFrom flagged",
          keys(h) == ["erc721_transferfrom_no_receiver_check"], keys(h))
    check("safeTransferFrom clean", d3.analyze({"source": safe}) == [])
    check("ERC20-only clean", d3.analyze({"source": erc20_only}) == [])
    check("cwe in evidence", h and h[0]["evidence"].get("cwe") == "CWE-703")


def test_payable():
    print("payable_ignores_msg_value:")
    vuln = """
    pragma solidity ^0.8.20;
    contract Mint {
        function mint() public payable {
            _mint(msg.sender, 1);
        }
        function _mint(address to, uint id) internal {}
    }"""
    safe = """
    pragma solidity ^0.8.20;
    contract Vault {
        mapping(address => uint) public balances;
        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }
    }"""
    locked = """
    pragma solidity ^0.8.20;
    contract Sink {
        receive() external payable {}
    }"""
    withdrawable = """
    pragma solidity ^0.8.20;
    contract Sink {
        address public owner;
        receive() external payable {}
        function withdraw() public {
            payable(owner).transfer(address(this).balance);
        }
    }"""
    h = d4.analyze({"source": vuln})
    check("payable ignoring value flagged",
          keys(h) == ["payable_ignores_msg_value"], keys(h))
    check("payable using value clean", d4.analyze({"source": safe}) == [])
    h2 = d4.analyze({"source": locked})
    check("no-withdrawal path flagged",
          "eth_no_withdrawal_path" in keys(h2), keys(h2))
    check("withdrawal path clean",
          d4.analyze({"source": withdrawable}) == [])
    check("cwe in evidence", h and h[0]["evidence"].get("cwe") == "CWE-404")


def test_shadowing():
    print("state_var_shadowing:")
    vuln = """
    pragma solidity ^0.8.20;
    contract Base {
        uint public total;
        address public owner;
    }
    contract Child is Base {
        uint public total;
        function bump() public { total += 1; }
    }"""
    safe = """
    pragma solidity ^0.8.20;
    contract Base {
        uint public total;
    }
    contract Child is Base {
        uint public childTotal;
    }"""
    override_ok = """
    pragma solidity ^0.8.20;
    contract Base {
        uint public virtual total;
    }
    contract Child is Base {
        uint public override total;
    }"""
    h = d5.analyze({"source": vuln})
    check("shadowed var flagged", keys(h) == ["state_var_shadowed"], keys(h))
    check("distinct names clean", d5.analyze({"source": safe}) == [])
    check("explicit override clean",
          d5.analyze({"source": override_ok}) == [])
    check("cwe in evidence", h and h[0]["evidence"].get("cwe") == "CWE-710")


# --------------------------------------------------------------------- KEV
KEV_FIXTURE = {
    "title": "CISA KEV fixture",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2021-41773", "vendorProject": "Apache",
         "product": "HTTP Server", "vulnerabilityName": "Path Traversal",
         "dateAdded": "2021-10-06", "dueDate": "2021-10-20",
         "shortDescription": "Apache HTTP Server path traversal.",
         "requiredAction": "Apply updates."},
        {"cveID": "CVE-2023-44487", "vendorProject": "Multiple",
         "product": "HTTP/2", "vulnerabilityName": "Rapid Reset",
         "dateAdded": "2023-10-10", "dueDate": "2023-10-31",
         "shortDescription": "HTTP/2 rapid reset attack.",
         "requiredAction": "Apply updates."},
    ],
}


def test_kev():
    print("kev:")
    with tempfile.NamedTemporaryFile("w", suffix=".json",
                                     delete=False) as fh:
        json.dump(KEV_FIXTURE, fh)
        path = fh.name
    try:
        check("fixture CVE listed",
              kev.is_exploited("CVE-2021-41773", path))
        check("lookup case-insensitive",
              kev.is_exploited("cve-2023-44487", path))
        check("unlisted CVE clean",
              not kev.is_exploited("CVE-2024-99999", path))
        e = kev.kev_entry("CVE-2021-41773", path)
        check("entry fields",
              e and e["vendor"] == "Apache" and e["due_date"] == "2021-10-20")
        check("missing file fails open",
              not kev.is_exploited("CVE-2021-41773", "/nonexistent/kev.json"))
    finally:
        os.unlink(path)
    # malformed feed fails open
    with tempfile.NamedTemporaryFile("w", suffix=".json",
                                     delete=False) as fh:
        fh.write("{not json")
        bad = fh.name
    try:
        check("malformed feed fails open",
              kev.load_index(bad) == {})
    finally:
        os.unlink(bad)
    # real shipped snapshot (fetched from CISA 2026-11-15)
    idx = kev.load_index()
    check("real snapshot loads (>=1000 entries)", len(idx) >= 1000,
          f"got {len(idx)}")
    check("real snapshot has Apache CVE-2021-41773",
          kev.is_exploited("CVE-2021-41773"))


class FakeResp:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


class FakeCtx:
    def __init__(self):
        self.keys = {}
        self.mode = "passive"
        self.http = object()
        self.limiter = None
        self.cache = None
        self.run_id = "test-r100"
        self.module_overrides = {}
        self.shared = {}


def test_cves_kev_wiring():
    print("cves KEV wiring (stubbed transport):")
    from app.plugins import cves
    real_fetch = cves.fetch

    async def fake_fetch(http, limiter, method, url, **kw):
        if "wp-json" in url:
            return FakeResp(text="[]", status_code=404, headers={})
        return FakeResp(text="<html></html>", status_code=200,
                        headers={"server": "Apache/2.4.49"})

    cves.fetch = fake_fetch
    try:
        plugin = cves.CvesPlugin()
        target = Target(raw="http://example.com/", type="url",
                        normalized="http://example.com/")
        res = asyncio.run(plugin.run(target, FakeCtx()))
    finally:
        cves.fetch = real_fetch
    cve_hits = [f for f in res.findings
                if f.evidence.get("cve") == "CVE-2021-41773"]
    check("Apache 2.4.49 CVE matched", len(cve_hits) == 1,
          f"findings={len(res.findings)}")
    if cve_hits:
        f = cve_hits[0]
        check("KEV flag set", f.evidence.get("kev_exploited") is True)
        check("KEV due date present",
              bool(f.evidence.get("kev_due_date")))
        check("exploitability weaponized",
              f.evidence.get("exploitability") == "weaponized")
        check("value prefixed KEV",
              f.value.startswith("KEV ACTIVELY EXPLOITED:"))


# ----------------------------------------------------------------- CWE map
def test_cwe_map():
    print("cwe_map:")
    for key, want in [
            ("div_before_mul_precision_loss", "CWE-682"),
            ("unbounded_loop_gas_dos", "CWE-400"),
            ("erc721_transferfrom_no_receiver_check", "CWE-703"),
            ("payable_ignores_msg_value", "CWE-404"),
            ("state_var_shadowed", "CWE-710"),
            ("reentrancy_path", "CWE-841"),
            ("unchecked_erc20_return", "CWE-252"),
            ("sqli_error_based", "CWE-89"),
            ("ssrf_cloud_metadata", "CWE-918")]:
        e = cwe_for(key)
        check(f"{key} -> {want}", e and e["cwe"] == want,
              f"got {e}")
    check("unknown key -> None", cwe_for("no_such_key_xyz") is None)
    check("label format",
          label_for("div_before_mul_precision_loss")
          == "CWE-682: Incorrect Calculation")


# ---------------------------------------------------------------- registry
def test_registry():
    print("registry:")
    from app.plugins.registry import discover
    d = discover()
    for pid in ["div_before_mul_precision", "unbounded_loop_dos",
                "erc721_unsafe_transfer", "payable_ignores_msg_value",
                "state_var_shadowing"]:
        check(f"registered: {pid}", pid in d)
    check("registry grew by 5 over 1431 baseline", len(d) >= 1436,
          f"got {len(d)}")


def main():
    test_div_before_mul()
    test_unbounded_loop()
    test_erc721()
    test_payable()
    test_shadowing()
    test_kev()
    test_cves_kev_wiring()
    test_cwe_map()
    test_registry()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
