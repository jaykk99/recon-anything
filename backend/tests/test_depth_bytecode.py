"""Depth-3 bytecode lane: per-selector attribution, EIP-1167
surfacing, probe sketches, benign silence, legacy fallback.

Fixtures are assembled with a tiny self-contained EVM assembler
(the benchmark corpus approach) so the dispatcher / selector
layout is exact. Detection only: sketches are inert data and
nothing here executes a call.
"""
from app.plugins import bytecode_paths as bp
from app.plugins import contract_chain as cc
from app.plugins import contract_logic
from app.plugins.cryptopack_util import keccak256

STRANGER = "0x00000000000000000000000000000000deaDBeef"
IMPL = "0x1111111111111111111111111111111111111111"

# ---------------------------------------------------------------------------
# Tiny EVM assembler (runtime code only)
# ---------------------------------------------------------------------------

_OPS = {"STOP": 0x00, "BALANCE": 0x31, "ADDRESS": 0x30,
        "CALLER": 0x33, "CALLVALUE": 0x34, "CALLDATALOAD": 0x35,
        "CALLDATASIZE": 0x36, "POP": 0x50, "SLOAD": 0x54,
        "SSTORE": 0x55, "JUMP": 0x56, "JUMPI": 0x57,
        "JUMPDEST": 0x5B, "SHR": 0x1C, "EQ": 0x14, "DUP1": 0x80,
        "SWAP1": 0x90, "RETURN": 0xF3, "CALL": 0xF1,
        "DELEGATECALL": 0xF4, "REVERT": 0xFD,
        "SELFDESTRUCT": 0xFF}


def _push(value):
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    else:
        n = max(1, (int(value).bit_length() + 7) // 8)
        data = int(value).to_bytes(n, "big")
    return bytes([0x5F + len(data)]) + data


def assemble(items):
    sizes = []
    for kind, val in items:
        if kind in ("label", "op"):
            sizes.append(1)
        elif kind == "push":
            sizes.append(len(_push(val)))
        elif kind == "pushlabel":
            sizes.append(3)
    labels, off = {}, 0
    for (kind, val), size in zip(items, sizes):
        if kind == "label":
            labels[val] = off
        off += size
    out = bytearray()
    for (kind, val), size in zip(items, sizes):
        if kind == "label":
            out.append(_OPS["JUMPDEST"])
        elif kind == "op":
            out.append(_OPS[val])
        elif kind == "push":
            out += _push(val)
        elif kind == "pushlabel":
            out += bytes([0x61]) + labels[val].to_bytes(2, "big")
    return "0x" + bytes(out).hex()


def _dispatcher(routes):
    items = [("push", 0), ("op", "CALLDATALOAD"),
             ("push", 0xE0), ("op", "SHR")]
    for sel, label in routes:
        items += [("op", "DUP1"), ("push", sel), ("op", "EQ"),
                  ("pushlabel", label), ("op", "JUMPI")]
    items += [("push", 0), ("push", 0), ("op", "REVERT")]
    return items


def _sel(sig: bytes) -> str:
    return "0x" + keccak256(sig)[:4].hex()


KILL_SEL = _sel(b"kill()")
STORE_SEL = _sel(b"store()")
EXEC_SEL = _sel(b"execute(address,bytes)")
WITHDRAW_SEL = _sel(b"withdraw(uint256)")


def _selfdestruct_hex():
    items = _dispatcher([(keccak256(b"kill()")[:4], "kill"),
                         (keccak256(b"store()")[:4], "store")])
    items += [("label", "kill"), ("op", "CALLER"),
              ("op", "SELFDESTRUCT")]
    items += [("label", "store"), ("push", 0x2A), ("push", 0),
              ("op", "SSTORE"), ("op", "STOP")]
    return assemble(items)


def _delegatecall_hex():
    items = _dispatcher(
        [(keccak256(b"execute(address,bytes)")[:4], "exec"),
         (keccak256(b"withdraw(uint256)")[:4], "wd")])
    items += [("label", "exec"),
              ("push", 0), ("push", 0), ("push", 0x40),
              ("push", 0x24), ("push", 4), ("op", "CALLDATALOAD"),
              ("push", 0xFFFF), ("op", "DELEGATECALL"),
              ("op", "POP"), ("op", "STOP")]
    items += [("label", "wd"),
              ("push", 0), ("push", 0), ("push", 0), ("push", 0),
              ("op", "ADDRESS"), ("op", "BALANCE"),
              ("op", "CALLER"), ("push", 0xFFFF), ("op", "CALL"),
              ("op", "POP"), ("op", "STOP")]
    return assemble(items)


def _benign_hex():
    items = _dispatcher([(keccak256(b"get()")[:4], "get"),
                         (keccak256(b"set(uint256)")[:4], "set")])
    items += [("label", "get"), ("push", 0), ("op", "SLOAD"),
              ("push", 0), ("push", 0), ("op", "RETURN")]
    items += [("label", "set"), ("push", 4),
              ("op", "CALLDATALOAD"), ("push", 0), ("op", "SSTORE"),
              ("op", "STOP")]
    return assemble(items)


MINIMAL_PROXY_HEX = (
    "0x363d3d373d3d3d363d73" + IMPL[2:] +
    "5af43d82803e903d91602b57fd5bf3")


# ---------------------------------------------------------------------------
# bytecode_paths.analyze
# ---------------------------------------------------------------------------

def test_paths_selfdestruct_attribution():
    res = bp.analyze(_selfdestruct_hex())
    assert res["dispatcher_found"] is True
    assert res["minimal_proxy_impl"] is None
    by_sel = {e["selector"]: e for e in res["selectors"]}
    assert set(by_sel) == {KILL_SEL, STORE_SEL}
    kill = by_sel[KILL_SEL]
    assert kill["sensitive_opcodes"] == ["SELFDESTRUCT"]
    assert "SELFDESTRUCT" in kill["opcodes"]
    assert kill["offset"] > 0
    store = by_sel[STORE_SEL]
    assert store["sensitive_opcodes"] == []
    assert store["storage_writes"] == [0]


def test_paths_delegatecall_and_call_attribution():
    res = bp.analyze(_delegatecall_hex())
    assert res["dispatcher_found"] is True
    by_sel = {e["selector"]: e for e in res["selectors"]}
    assert by_sel[EXEC_SEL]["sensitive_opcodes"] == ["DELEGATECALL"]
    wd = by_sel[WITHDRAW_SEL]
    assert wd["sensitive_opcodes"] == ["CALL"]
    assert wd["signature"] == "withdraw(uint256)"


def test_paths_benign_storage_slots():
    res = bp.analyze(_benign_hex())
    assert res["dispatcher_found"] is True
    by_sel = {e["selector"]: e for e in res["selectors"]}
    assert by_sel[_sel(b"get()")]["storage_reads"] == [0]
    assert by_sel[_sel(b"set(uint256)")]["storage_writes"] == [0]
    assert all(e["sensitive_opcodes"] == []
               for e in res["selectors"])


def test_paths_non_dispatcher_blob():
    res = bp.analyze("0x60006000ff60006000f4")
    assert res["dispatcher_found"] is False
    assert res["selectors"] == []
    assert bp.analyze("0x")["dispatcher_found"] is False
    assert bp.analyze("not hex")["dispatcher_found"] is False


def test_paths_minimal_proxy():
    res = bp.analyze(MINIMAL_PROXY_HEX)
    assert res["minimal_proxy_impl"] == IMPL
    assert res["dispatcher_found"] is False


# ---------------------------------------------------------------------------
# analyze_logic_bytecode v2
# ---------------------------------------------------------------------------

def test_logic_kill_finding_only_for_sensitive_selector():
    hits = contract_logic.analyze_logic_bytecode(
        _selfdestruct_hex())
    assert len(hits) == 1  # store() stays silent
    f = hits[0]
    assert f["kind"] == "bytecode_opcode_risk"
    assert f["logic_kind"] == "bytecode_selector_capability"
    assert f["selector"] == KILL_SEL
    assert f["function"] == KILL_SEL  # no known signature
    assert f["severity"] == "medium"
    assert "SELFDESTRUCT" in f["opcodes"]
    assert "heuristic" in f["detail"]
    assert "NOT a confirmed flaw" in f["detail"]


def test_logic_execute_and_withdraw_findings():
    hits = contract_logic.analyze_logic_bytecode(
        _delegatecall_hex())
    assert len(hits) == 2
    by_sel = {f["selector"]: f for f in hits}
    ex = by_sel[EXEC_SEL]
    assert ex["severity"] == "medium"
    assert "DELEGATECALL" in ex["opcodes"]
    wd = by_sel[WITHDRAW_SEL]
    assert wd["severity"] == "low"  # CALL-only path
    assert wd["function"] == "withdraw(uint256)"
    assert wd["signature"] == "withdraw(uint256)"
    assert "CALL" in wd["opcodes"]


def test_logic_minimal_proxy_surfaces_impl():
    hits = contract_logic.analyze_logic_bytecode(MINIMAL_PROXY_HEX)
    assert len(hits) == 1
    f = hits[0]
    assert f["minimal_proxy_impl"] == IMPL
    assert f["logic_kind"] == "bytecode_minimal_proxy"
    assert IMPL in f["detail"]
    assert "IMPLEMENTATION" in f["detail"]
    sketch = f["probe_sketches"][0]
    assert sketch["target"] == IMPL
    assert sketch["from_address"] == STRANGER


def test_logic_benign_stays_silent():
    assert contract_logic.analyze_logic_bytecode(
        _benign_hex()) == []


def test_logic_legacy_fallback_non_dispatcher():
    hits = contract_logic.analyze_logic_bytecode(
        "0x60006000ff60006000f4")
    assert len(hits) == 1
    f = hits[0]
    assert f["kind"] == "bytecode_opcode_risk"
    assert f["logic_kind"] == "bytecode_opcode_presence"
    assert f["severity"] == "low"
    assert "heuristic" in f["detail"]
    assert not f.get("probe_sketches")
    assert not f.get("selector")


# ---------------------------------------------------------------------------
# Probe sketches (inert data)
# ---------------------------------------------------------------------------

def test_sketch_contents_stranger_and_selector_data():
    hits = contract_logic.analyze_logic_bytecode(
        _delegatecall_hex())
    by_sel = {f["selector"]: f for f in hits}
    sketch = by_sel[WITHDRAW_SEL]["probe_sketches"][0]
    assert sketch["from_address"] == STRANGER
    assert sketch["selector"] == WITHDRAW_SEL
    # withdraw(uint256): selector + exactly one zero word
    assert sketch["data"] == "0x" + WITHDRAW_SEL[2:] + "00" * 32
    assert "eth_call" in sketch["purpose"]
    assert "never executed" in sketch["purpose"]
    # Unknown signature: selector only, no invented arguments.
    ex_sketch = by_sel[EXEC_SEL]["probe_sketches"][0]
    assert ex_sketch["data"] == "0x" + EXEC_SEL[2:]
    assert ex_sketch["from_address"] == STRANGER


# ---------------------------------------------------------------------------
# Plugin wiring: new fields land in finding evidence
# ---------------------------------------------------------------------------

def test_plugin_evidence_carries_attribution():
    plugin = contract_logic.ContractLogicPlugin()
    findings = []
    got = plugin._analyze_contract(
        cc.CHAINS["ethereum"],
        "0x00000000000000000000000000000000000000aa",
        None, _selfdestruct_hex(), findings, role="standalone")
    assert got is False
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["bytecode_only"] is True
    assert ev["selector"] == KILL_SEL
    assert "SELFDESTRUCT" in ev["opcodes"]
    assert ev["probe_sketches"][0]["from_address"] == STRANGER
    assert ev["severity"] == "medium"


def test_plugin_evidence_carries_proxy_impl():
    plugin = contract_logic.ContractLogicPlugin()
    findings = []
    plugin._analyze_contract(
        cc.CHAINS["ethereum"],
        "0x00000000000000000000000000000000000000aa",
        None, MINIMAL_PROXY_HEX, findings, role="standalone")
    assert len(findings) == 1
    ev = findings[0].evidence
    assert ev["minimal_proxy_impl"] == IMPL
    assert ev["probe_sketches"]
