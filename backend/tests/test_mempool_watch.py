"""Tests for the mempool fresh-deploy interceptor.

Covers: CREATE address prediction against the canonical Hardhat
vector, creation-tx extraction from a pending-block fixture,
runtime-code extraction from solc-style init code, queue dedupe,
the inline-gate integration (a burn-funded fixture gates, a
clean payout fixture passes), and a full poll cycle against a
fake RPC pool (no network).
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.mempool_watch import (  # noqa: E402
    MempoolWatcher, QueueStore, RpcPool, Tier1Screener,
    extract_creations, extract_runtime_code, gate_flags,
    gate_summary, predict_create_address,
)

HARDHAT_DEPLOYER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
HARDHAT_FIRST = "0x5FbDB2315678afecb367f032d93F642f64180aa3"


def test_predict_create_address_hardhat_vector():
    assert predict_create_address(HARDHAT_DEPLOYER, 0) == \
        HARDHAT_FIRST.lower()
    # nonce changes the address
    assert predict_create_address(HARDHAT_DEPLOYER, 1) != \
        HARDHAT_FIRST.lower()


def _solc_init(runtime: bytes) -> bytes:
    """Minimal solc-style init stub: CODECOPY then RETURN runtime."""
    def push(v: int) -> bytes:
        if v == 0:
            return b"\x60\x00"
        b = v.to_bytes((v.bit_length() + 7) // 8, "big")
        return bytes([0x5F + len(b)]) + b
    stub_head = b"\x60\x80\x60\x40\x52"  # MSTORE boilerplate-ish
    codecopy = push(len(runtime)) + push(len(stub_head) + 11) + \
        b"\x60\x00\x39"
    ret = push(len(runtime)) + b"\x60\x00\xf3"
    init = stub_head + codecopy + ret
    # fix the offset now that the header length is known
    offset = len(init)
    codecopy = push(len(runtime)) + push(offset) + b"\x60\x00\x39"
    return stub_head + codecopy + ret + runtime


def test_extract_runtime_code_roundtrip():
    runtime = bytes.fromhex("6080604052348015600e57600080fd5b50")
    init = _solc_init(runtime)
    assert extract_runtime_code(init) == runtime
    assert extract_runtime_code(b"") is None
    assert extract_runtime_code(b"\x00" * 32) is None


def _pending_block():
    runtime = bytes.fromhex("6080604052348015600e57600080fd5b50")
    init = "0x" + _solc_init(runtime).hex()
    return {
        "number": "0x100",
        "timestamp": "0x6553f100",
        "transactions": [
            {"hash": "0xaaa1", "from": HARDHAT_DEPLOYER, "to": None,
             "nonce": "0x0", "input": init, "value": "0x0"},
            {"hash": "0xaaa2", "from": HARDHAT_DEPLOYER,
             "to": "0x0000000000000000000000000000000000000000",
             "nonce": "0x1", "input": init, "value": "0x1"},
            {"hash": "0xaaa3", "from": HARDHAT_DEPLOYER,
             "to": "0x1111111111111111111111111111111111111111",
             "nonce": "0x2", "input": "0xa9059cbb", "value": "0x0"},
        ],
    }


def test_extract_creations_from_pending_block():
    creations = extract_creations(_pending_block())
    assert len(creations) == 2
    assert creations[0]["address"] == HARDHAT_FIRST.lower()
    assert creations[0]["tx_hash"] == "0xaaa1"
    assert creations[1]["nonce"] == 1
    assert creations[1]["value_wei"] == 1
    assert extract_creations(None) == []
    assert extract_creations({}) == []


def test_queue_dedupe(tmp_path):
    store = QueueStore(str(tmp_path))
    row = {"chain": "ethereum", "tx_hash": "0xaaa1",
           "address": HARDHAT_FIRST.lower()}
    assert store.add(row) is True
    assert store.add(dict(row)) is False  # same tx
    assert store.add({**row, "tx_hash": "0xbbb2"}) is False  # same addr
    assert store.add({**row, "tx_hash": "0xbbb2",
                      "address": "0x22222222222222222222222222222222"
                                   "22222222"}) is True
    # persisted: a fresh store sees the same rows
    store2 = QueueStore(str(tmp_path))
    assert len(store2.rows) == 2
    lines = open(os.path.join(str(tmp_path), "queue.jsonl")).readlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["tx_hash"] == "0xaaa1"


AEWETH_LIKE_SRC = """
contract L2Eth {
    mapping(address => uint256) private _balances;
    function _burn(address account, uint256 amount) internal {
        _balances[account] -= amount;
    }
    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }
    function withdrawTo(address account, uint256 amount) public {
        _burn(msg.sender, amount);
        (bool success, ) = account.call{ value: amount }("");
        require(success, "FAIL_TRANSFER");
    }
}
"""

CLEAN_PAYOUT_SRC = """
contract VulnVault {
    function withdraw(uint256 amount) public {
        require(address(this).balance >= amount, "insolvent");
        payable(msg.sender).transfer(amount);
    }
}
"""


def test_gate_flags_burn_funded_gates():
    flags = [{"plugin": "x", "key": "k", "function": "withdrawTo",
              "recipient_class": "", "severity": "high"}]
    gated = gate_flags("arbitrum", "0xabc", flags,
                       source=AEWETH_LIKE_SRC, contract_name="L2Eth")
    assert gated[0]["gate"] == "GATED_SELF_FUNDED"
    assert gate_summary(gated) == "gated_out"


def test_gate_flags_clean_payout_passes():
    flags = [{"plugin": "x", "key": "k", "function": "withdraw",
              "recipient_class": "", "severity": "high"}]
    gated = gate_flags("ethereum", "0xabc", flags,
                       source=CLEAN_PAYOUT_SRC,
                       contract_name="VulnVault")
    assert gated[0]["gate"] == "PASS"
    assert gate_summary(gated) == "pass"


def test_gate_flags_bytecode_only_passes_with_reason():
    flags = [{"plugin": "x", "key": "k", "function": "withdraw",
              "recipient_class": "", "severity": ""}]
    gated = gate_flags("ethereum", "0xabc", flags)  # no source
    assert gated[0]["gate"] == "PASS"
    assert "no verified source" in gated[0]["gate_reason"]


class _FakeRpc(RpcPool):
    def __init__(self, block):
        super().__init__(pools={"ethereum": ["http://fake"]})
        self._block = block

    def pending_block(self, chain):
        return self._block

    def get_code(self, chain, address):
        return "0x6080604052"

    def get_balance(self, chain, address):
        return 60 * 10**18


class _FakeScreener(Tier1Screener):
    def __init__(self):
        super().__init__()
        self.calls = []

    async def screen(self, chain, address, code_hex):
        self.calls.append((chain, address))
        if address == HARDHAT_FIRST.lower():
            return [{"plugin": "constant_inliner_check", "key": "k1",
                     "function": "", "recipient_class": "",
                     "severity": "low"}]
        return []


def test_poll_cycle_queues_flagged_creation(tmp_path):
    watcher = MempoolWatcher(str(tmp_path), chains=["ethereum"],
                             rpc=_FakeRpc(_pending_block()),
                             screener=_FakeScreener())
    stats = asyncio.run(watcher.poll_chain("ethereum"))
    assert stats["blocks"] == 1
    assert stats["creations"] == 2
    assert stats["flagged"] == 1
    assert stats["queued"] == 1
    row = watcher.store.rows[0]
    assert row["address"] == HARDHAT_FIRST.lower()
    assert row["status"] == "UNVERIFIED"
    assert row["screened"] == "runtime_extracted"
    assert row["gate_summary"] == "pass"
    # second poll of the same pending block queues nothing new
    stats2 = asyncio.run(watcher.poll_chain("ethereum"))
    assert stats2["queued"] == 0
    # confirmation pass stamps mined + high priority (60 ETH >= 50)
    conf = watcher.confirm_mined()
    assert conf["mined"] == 1
    assert watcher.store.rows[0]["priority"] == "high"
    assert watcher.store.rows[0]["initial_balance_wei"] == 60 * 10**18
    assert watcher.store.rows[0]["initial_balance_usd"] is None
