"""Smart Contract Logic Analyzer (contract_logic) tests.

Layers:
1. Pure analyzer against fixture sources. Canaries that MUST
   flag: classic EtherStore-style reentrancy (external call
   before the balance update), a cross-function reentrancy pair,
   pre-0.8 unchecked add on a balance, a >=0.8 unchecked{} block
   on totalSupply, assembly arithmetic on a stored balance, an
   unguarded setOwner, an unguarded mint, an unprotected
   initialize(), an arbitrary delegatecall to a caller-supplied
   target, and tx.origin authorization.
2. Clean controls that MUST NOT flag: ReentrancyGuard +
   CEI-ordered withdraw, CEI order without a guard, Solidity 0.8
   checked math, pre-0.8 SafeMath method-call math, onlyOwner
   setters, onlyMinter mint, initialize() with the initializer
   modifier, a gated upgrade delegatecall.
3. Bytecode lane: risky opcodes flag LOW + labeled heuristic;
   clean bytecode stays silent.
4. Plugin runs with the chain layer stubbed (no network): canary
   source path with full evidence shape, clean source path, and
   the no-verified-source path (bytecode lane only, flags no
   logic flaw).
5. Registry discovery picks the plugin up.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import contract_logic  # noqa: E402
from app.plugins.base import Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402

ADDR = "0x" + "cd" * 20

# ---------------------------------------------------------------------------
# Canary fixtures
# ---------------------------------------------------------------------------

# The classic EtherStore shape (Solidity <0.8): the balance is
# decremented only AFTER the external call pays out.
REENTRANCY_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.4.18;

contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) public {
        if (balances[msg.sender] >= _amount) {
            msg.sender.call.value(_amount)();
            balances[msg.sender] -= _amount;
        }
    }
}
"""

CROSS_FUNCTION_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CrossVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }

    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"""

OVERFLOW_PRE080_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;

contract OldToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function transfer(address _to, uint256 _value) public {
        balances[msg.sender] = balances[msg.sender] - _value;
        balances[_to] += _value;
    }

    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        balances[to] += amount;
    }
}
"""

UNCHECKED_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UncheckedVault {
    uint256 public totalSupply;

    function addUnchecked(uint256 amount) external {
        unchecked {
            totalSupply += amount;
        }
    }
}
"""

ASSEMBLY_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AssemblyVault {
    uint256 public storedBalance;

    function addAssembly(uint256 amount) external {
        assembly {
            let b := sload(0)
            let c := add(b, amount)
            sstore(0, c)
        }
    }
}
"""

ACCESS_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LooseVault {
    address public owner;
    uint256 public fee;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function setFee(uint256 newFee) external {
        fee = newFee;
    }

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balances[to] += amount;
    }

    function initialize() external {
        owner = msg.sender;
    }

    function emergencyWithdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }

    function exec(address target, bytes calldata data)
        external returns (bytes memory)
    {
        (bool ok, bytes memory result) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return result;
    }

    function ownerOnlyAction() external {
        require(tx.origin == owner, "not the owner");
        fee = 1;
    }
}
"""

# Live-smoke FP regressions (2026-11-02, USDT + REQ):
# - USDT issue()/redeem() are onlyOwner: pre-0.8 arithmetic only the
#   privileged account can trigger is operator self-harm, not a
#   flaw. Gated functions stay silent in the overflow lane.
# - REQ's RequestToken() is an old-style (pre-0.5) constructor:
#   deploy-time code, not live logic.
SMOKE_FP_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.4.17;

contract Tetherish {
    address public owner;
    uint256 public _totalSupply;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function Tetherish() public {
        owner = msg.sender;
        _totalSupply = 1000000 * 10 ** 6;
        balances[owner] = _totalSupply;
    }

    function issue(uint amount) public onlyOwner {
        balances[owner] += amount;
        _totalSupply += amount;
    }

    function redeem(uint amount) public onlyOwner {
        balances[owner] -= amount;
        _totalSupply -= amount;
    }
}
"""

OLD_CTOR_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.4.15;

contract Requestish {
    uint256 public totalSupply;

    function Requestish(uint tokenTotalAmount) public {
        totalSupply = tokenTotalAmount * 10 ** 18;
    }
}
"""

# ---------------------------------------------------------------------------
# Clean controls
# ---------------------------------------------------------------------------

CLEAN_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CleanVault {
    address public owner;
    uint256 public fee;
    uint256 public totalSupply;
    uint256 private _status;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyMinter() {
        require(msg.sender == owner, "not minter");
        _;
    }

    modifier nonReentrant() {
        require(_status == 0, "reentrant");
        _status = 1;
        _;
        _status = 0;
    }

    function initialize() external initializer {
        owner = msg.sender;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function setFee(uint256 newFee) external onlyOwner {
        fee = newFee;
    }

    function mint(address to, uint256 amount) external onlyMinter {
        totalSupply += amount;
        balances[to] += amount;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function withdrawCei(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function upgrade(address target, bytes calldata data)
        external onlyOwner returns (bytes memory)
    {
        (bool ok, bytes memory result) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return result;
    }
}
"""

SAFEMATH_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "overflow");
        return c;
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "underflow");
        return a - b;
    }
}

contract SafeToken {
    using SafeMath for uint256;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function transfer(address _to, uint256 _value) public {
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
    }
}
"""


def _hits(src, compiler=""):
    return contract_logic.analyze_logic_source(src, compiler)


def _by_kind(src, kind, compiler=""):
    return [h for h in _hits(src, compiler) if h["kind"] == kind]


# ---------------------------------------------------------------------------
# 1. Canaries
# ---------------------------------------------------------------------------

def test_reentrancy_canary_flags():
    hits = _by_kind(REENTRANCY_SOURCE, "reentrancy")
    assert len(hits) == 1
    assert hits[0]["function"] == "withdraw"
    assert hits[0]["logic_kind"] == "cei_violation"
    assert hits[0]["severity"] == "high"
    assert "balances[msg.sender] -= _amount" in hits[0]["code"]


def test_cross_function_reentrancy_hint():
    hits = _by_kind(CROSS_FUNCTION_SOURCE, "reentrancy")
    kinds = {(h["function"], h["logic_kind"]) for h in hits}
    assert ("withdraw", "cei_violation") in kinds
    assert ("withdrawAll", "cross_function_reentrancy") in kinds


def test_pre080_overflow_flags():
    hits = _by_kind(OVERFLOW_PRE080_SOURCE, "integer_overflow")
    fns = {h["function"] for h in hits}
    assert fns == {"transfer", "mint"}
    assert all(h["logic_kind"] == "pre080_unchecked_arithmetic"
               for h in hits)
    assert all(h["severity"] == "high" for h in hits)


def test_unchecked_block_flags():
    hits = _by_kind(UNCHECKED_SOURCE, "integer_overflow")
    assert len(hits) == 1
    assert hits[0]["logic_kind"] == "unchecked_block_arithmetic"
    assert hits[0]["function"] == "addUnchecked"


def test_assembly_arithmetic_flags():
    hits = _by_kind(ASSEMBLY_SOURCE, "integer_overflow")
    assert len(hits) == 1
    assert hits[0]["logic_kind"] == "assembly_arithmetic"


def test_access_control_canaries_flag():
    hits = _by_kind(ACCESS_SOURCE, "access_control_flaw")
    kinds = {(h["function"], h["logic_kind"]) for h in hits}
    assert ("setOwner", "ungated_sensitive_function") in kinds
    assert ("setFee", "ungated_sensitive_function") in kinds
    assert ("mint", "ungated_sensitive_function") in kinds
    assert ("emergencyWithdraw", "ungated_sensitive_function") in kinds
    assert ("initialize", "unprotected_initializer") in kinds
    assert ("exec", "arbitrary_delegatecall") in kinds
    assert ("ownerOnlyAction", "tx_origin_auth") in kinds
    for h in hits:
        assert h["severity"] == "high"
        assert h["code"]  # the finding SHOWS the code


# ---------------------------------------------------------------------------
# 2. Clean controls
# ---------------------------------------------------------------------------

def test_clean_controls_never_flag():
    assert _hits(CLEAN_SOURCE) == []


def test_safemath_pre080_never_flags():
    assert _by_kind(SAFEMATH_SOURCE, "integer_overflow") == []


def test_smoke_fp_gated_overflow_and_old_ctor_silent():
    assert _by_kind(SMOKE_FP_SOURCE, "integer_overflow") == []
    assert _hits(OLD_CTOR_SOURCE) == []


def test_version_detection():
    assert contract_logic.solc_version(REENTRANCY_SOURCE) == (0, 4, 18)
    assert contract_logic.solc_version(CLEAN_SOURCE) == (0, 8, 20)
    assert contract_logic.solc_version(
        "", "v0.7.6+commit.7338295f") == (0, 7, 6)
    assert contract_logic.solc_version("contract X {}") is None


# ---------------------------------------------------------------------------
# 3. Bytecode lane
# ---------------------------------------------------------------------------

def test_bytecode_lane_flags_risky_opcodes_low():
    # PUSH1 0, PUSH1 0, SELFDESTRUCT, PUSH1 0, PUSH1 0, DELEGATECALL
    hits = contract_logic.analyze_logic_bytecode(
        "0x60006000ff60006000f4")
    assert len(hits) == 1
    assert hits[0]["kind"] == "bytecode_opcode_risk"
    assert hits[0]["severity"] == "low"
    assert "heuristic" in hits[0]["detail"]


def test_bytecode_lane_clean_stays_silent():
    assert contract_logic.analyze_logic_bytecode("0x600060006000") == []
    assert contract_logic.analyze_logic_bytecode("0x") == []


# ---------------------------------------------------------------------------
# 4. Plugin runs (chain layer stubbed, no network)
# ---------------------------------------------------------------------------

class FakeCtx:
    def __init__(self, shared=None):
        self.keys = {}
        self.mode = "passive"
        self.http = None
        self.limiter = None
        self.cache = None
        self.run_id = "test"
        self.module_overrides = {}
        self.shared = shared or {}

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    def publish(self, kind, item):
        self.shared.setdefault(kind, []).append(item)


def _patch(monkeypatch, code_by_chain, source):
    async def fake_get_code(ctx, chain, address):
        return code_by_chain.get(chain.id)

    async def fake_source(ctx, chain, address, key=None):
        return source

    async def fake_resolve(ctx, chain, address, code_hex, meta):
        return {"implementation": "", "via": "", "beacon": ""}

    monkeypatch.setattr(cc, "rpc_get_code", fake_get_code)
    monkeypatch.setattr(cc, "fetch_verified_source", fake_source)
    monkeypatch.setattr(cc, "resolve_implementation", fake_resolve)


def _meta(source):
    if source is None:
        return None
    return {"source": source, "contract_name": "Fixture",
            "compiler": "v0.8.20+commit", "proxy": False,
            "implementation": "", "origin": "Blockscout"}


def _target():
    return Target(raw=f"ethereum:{ADDR}", type="crypto_wallet",
                  normalized=f"ethereum:{ADDR}")


def test_plugin_flags_canary_with_evidence(monkeypatch):
    _patch(monkeypatch, {"ethereum": "0x60006000"},
           _meta(REENTRANCY_SOURCE))
    p = contract_logic.ContractLogicPlugin()
    res = asyncio.run(p.run(_target(), FakeCtx()))
    re_hits = [f for f in res.findings if f.key == "reentrancy"]
    assert len(re_hits) == 1
    ev = re_hits[0].evidence
    assert ev["severity"] == "high"
    assert ev["function"] == "withdraw"
    assert ev["chain"] == "ethereum"
    assert ev["address"] == ADDR
    assert ev["contract_role"] == "standalone"
    assert ev["bytecode_only"] is False
    assert ev["code"]


def test_plugin_clean_source_no_flaws(monkeypatch):
    _patch(monkeypatch, {"ethereum": "0x60006000"}, _meta(CLEAN_SOURCE))
    p = contract_logic.ContractLogicPlugin()
    res = asyncio.run(p.run(_target(), FakeCtx()))
    flaws = [f for f in res.findings if f.key in (
        "reentrancy", "integer_overflow", "access_control_flaw")]
    assert flaws == []


def test_plugin_bytecode_only_path(monkeypatch):
    _patch(monkeypatch, {"ethereum": "0x60006000ff60006000f4"}, None)
    p = contract_logic.ContractLogicPlugin()
    res = asyncio.run(p.run(_target(), FakeCtx()))
    flaws = [f for f in res.findings if f.key in (
        "reentrancy", "integer_overflow", "access_control_flaw")]
    assert flaws == []  # heuristic lane never claims a logic flaw
    bc = [f for f in res.findings if f.key == "bytecode_opcode_risk"]
    assert len(bc) == 1
    assert bc[0].evidence["bytecode_only"] is True
    assert bc[0].evidence["severity"] == "low"
    assert "bytecode-only" in res.reason


# ---------------------------------------------------------------------------
# 5. Registry
# ---------------------------------------------------------------------------

def test_registry_discovers_plugin():
    reg = discover()
    assert "contract_logic" in reg
    assert reg["contract_logic"] is contract_logic.ContractLogicPlugin
