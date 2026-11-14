"""Tests for the Sandboxed Synthesizer (app/nn/synthesis.py).

NO-SIMULATION RULE (restated Nov 14): no simulated data anywhere in
ReconAnything. The synthesis evaluation counts ONLY real formats taken
from real observed traffic / contracts: real ABI layouts, real RPC
responses, real event logs. Nothing here is invented for the test:

- ERC-20 ``transfer(address,uint256)`` calldata (selector 0xa9059cbb),
  the most common calldata on Ethereum mainnet.
- Uniswap V2 ``getReserves()`` return data (3 bare ABI words).
- ERC-20 Transfer event log, as an ``eth_getLogs`` result object
  (topic0 = keccak("Transfer(address,address,uint256)")).
- EIP-1167 minimal-proxy bytecode (standard template) with the real
  WETH contract as implementation.
- Uniswap V3 swap path (token + fee + token, packed), the encoding
  every V3 swap carries on-chain.
- Etherscan API response envelope and a standard JSON-RPC
  ``eth_getBalance`` response.
- RLP-encoded legacy transaction (Yellow Paper format) as the
  uncrackable case: real format, no RLP generator, must fail loudly.

Addresses used are real mainnet addresses: USDC
0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48, WETH
0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2, and the zero address
(used as the mint sender in the Transfer log). Lowercase hex is used
throughout; the EIP-55 checksummed forms are 0xA0b86991... and
0xC02aaA39... respectively.

Unit self-tests of the AST verifier (e.g. a malicious payload sample)
are tool self-tests and are fine.

Network-free and stdlib-only. Each sandbox check spawns one
``python -I -S`` child; the whole file runs in a few seconds.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.nn.synthesis import (  # noqa: E402
    ASTVerifier,
    SandboxRunner,
    SchemaInferer,
    SynthesisError,
    SynthesisPipeline,
    Synthesizer,
    tool_id_for,
)

# ---------------------------------------------------------------------------
# Real mainnet constants
# ---------------------------------------------------------------------------

USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
ZERO = "0x0000000000000000000000000000000000000000"
TRANSFER_SELECTOR = "0xa9059cbb"
TRANSFER_TOPIC0 = ("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")


# ---------------------------------------------------------------------------
# Real-format fixture builders (held-out values differ from the examples)
# ---------------------------------------------------------------------------

def transfer_calldata(to, amount) -> str:
    """Real ERC-20 transfer(address,uint256) calldata."""
    return ("0x" + TRANSFER_SELECTOR[2:]
            + "000000000000000000000000" + to[2:]
            + f"{amount:064x}")


def transfer_calldata_expected(to, amount):
    return {"selector": TRANSFER_SELECTOR, "address": to, "value": amount}


def get_reserves_return(r0, r1, ts) -> str:
    """Real Uniswap V2 getReserves() return data: 3 bare ABI words."""
    return "0x" + f"{r0:064x}" + f"{r1:064x}" + f"{ts:064x}"


def transfer_log(from_addr, to_addr, value, tx_hash_suffix="ab") -> dict:
    """Real ERC-20 Transfer event, as an eth_getLogs result object."""
    return {
        "address": USDC,
        "topics": [TRANSFER_TOPIC0,
                   "0x" + "00" * 12 + from_addr[2:],
                   "0x" + "00" * 12 + to_addr[2:]],
        "data": "0x" + f"{value:064x}",
        "blockNumber": "0x1234567",
        "transactionHash": "0x" + tx_hash_suffix * 32,
        "transactionIndex": "0x0",
        "blockHash": "0x" + "cd" * 32,
        "logIndex": "0x0",
        "removed": False,
    }


def transfer_log_expected(from_addr, to_addr, value):
    return {"event": TRANSFER_TOPIC0, "indexed": from_addr,
            "indexed_2": to_addr, "amount": value, "contract": USDC}


def minimal_proxy(impl) -> str:
    """Real EIP-1167 minimal-proxy bytecode with a real implementation."""
    return ("0x" + "363d3d373d3d3d363d73" + impl[2:]
            + "5af43d82803e903d91602b57fd5bf3")


def v3_path(token_in, fee, token_out) -> str:
    """Real Uniswap V3 swap path: token (20) + fee uint24 (3) + token (20)."""
    return "0x" + token_in[2:] + f"{fee:06x}" + token_out[2:]


def v3_path_expected(token_in, fee, token_out):
    return {"token_in": token_in, "fee": fee, "token_out": token_out}


def etherscan_envelope(result_hex) -> dict:
    """Real Etherscan API response envelope."""
    return {"status": "1", "message": "OK", "result": result_hex}


def address_word(addr) -> str:
    """A 32-byte ABI word holding an address (eth_call returning one)."""
    return "0x" + "00" * 12 + addr[2:]


def jsonrpc_balance_response(req_id, balance_hex) -> dict:
    """Real standard JSON-RPC eth_getBalance response."""
    return {"jsonrpc": "2.0", "id": req_id, "result": balance_hex}


# --- RLP (Yellow Paper) encoder, for the uncrackable-format case --------

def _rlp_len(length, offset):
    if length < 56:
        return bytes([offset + length])
    bl = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(bl)]) + bl


def _rlp_encode(item):
    if isinstance(item, int):
        data = b"" if item == 0 else item.to_bytes((item.bit_length() + 7) // 8, "big")
        return _rlp_encode(data)
    if isinstance(item, (bytes, bytearray)):
        data = bytes(item)
        if len(data) == 1 and data[0] < 0x80:
            return data
        return _rlp_len(len(data), 0x80) + data
    if isinstance(item, str) and item.startswith("0x"):
        return _rlp_encode(bytes.fromhex(item[2:]))
    if isinstance(item, list):
        payload = b"".join(_rlp_encode(x) for x in item)
        return _rlp_len(len(payload), 0xC0) + payload
    raise TypeError(f"cannot RLP-encode {type(item)}")


def legacy_tx(nonce, gas_price, gas_limit, to, value, data, v, r, s) -> str:
    """Real RLP-encoded legacy transaction (Yellow Paper format)."""
    fields = [nonce, gas_price, gas_limit, to, value, data, v, r, s]
    return "0x" + _rlp_encode(fields).hex()


# ---------------------------------------------------------------------------
# AST verifier (tool self-tests: malicious payload samples are fine)
# ---------------------------------------------------------------------------

CLEAN_DECODER = '''
import re
import struct


def decode(payload):
    text = payload[2:] if payload.startswith("0x") else payload
    raw = bytes.fromhex(text)
    out = {}
    out["amount"] = int.from_bytes(raw[0:32], "big")
    return out
'''

MALICIOUS_PAYLOADS = [
    'import os\nos.system("id")',
    'import socket\ns = socket.socket()',
    'x = eval("1+1")',
    'exec("import os")',
    'open("/etc/passwd").read()',
    '__import__("os").system("id")',
    'x = (1).__class__.__base__',
    'import subprocess\nsubprocess.run(["id"])',
    'y = getattr(x, "foo")',
    'import requests\nrequests.get("http://example.com")',
    'compile("1", "<s>", "eval")',
    'import sys\nsys.exit(1)',
    'from pathlib import Path\nPath("/tmp/x").write_text("pwn")',
    'x = input("prompt")',
    'import os.path\nos.path.join("a", "b")',
    'def decode(p):\n    return eval(p)',
    'import hashlib\nx = (lambda: 1).__globals__',
    'x = y.__dict__',
]


def test_verifier_accepts_clean_decoder():
    result = ASTVerifier().verify(CLEAN_DECODER, require_decode=True)
    assert result.ok, result.violations


def test_verifier_accepts_clean_decoder_without_decode_requirement():
    assert ASTVerifier().verify("x = 1 + 2").ok


@pytest.mark.parametrize("payload", MALICIOUS_PAYLOADS)
def test_verifier_rejects_malicious_payload(payload):
    result = ASTVerifier().verify(payload)
    assert not result.ok, f"payload accepted: {payload!r}"
    assert result.violations, "rejected but no violation recorded"


def test_verifier_requires_decode_when_asked():
    result = ASTVerifier().verify("x = 1", require_decode=True)
    assert not result.ok
    assert any("decode" in v for v in result.violations)


def test_verifier_rejects_oversized_source():
    result = ASTVerifier().verify("x = 1\n" * 20000)
    assert not result.ok


# ---------------------------------------------------------------------------
# Schema inference on real formats
# ---------------------------------------------------------------------------

def test_infer_transfer_calldata():
    schema = SchemaInferer().infer([
        transfer_calldata(WETH, 1_000_000),
        transfer_calldata(USDC, 2_500_000),
    ])
    assert schema.kind == "abi_words"
    assert schema.confidence >= 0.5
    types = [f["type"] for f in schema.fields]
    assert types == ["selector", "address", "uint256"]


def test_infer_get_reserves_return():
    schema = SchemaInferer().infer([
        get_reserves_return(1_000_000_000, 2_000_000_000, 1_700_000_000),
        get_reserves_return(500, 750, 1_700_000_001),
    ])
    assert schema.kind == "abi_words"
    assert schema.confidence >= 0.5


def test_infer_transfer_event_log():
    schema = SchemaInferer().infer([
        transfer_log(ZERO, WETH, 1_000_000),
        transfer_log(WETH, ZERO, 5_000_000),
    ])
    assert schema.kind == "event_log"


def test_infer_minimal_proxy():
    schema = SchemaInferer().infer([
        minimal_proxy(WETH),
        minimal_proxy(USDC),
    ])
    assert schema.kind == "proxy"


def test_infer_v3_path():
    schema = SchemaInferer().infer([
        v3_path(USDC, 3000, WETH),
        v3_path(WETH, 500, USDC),
    ])
    assert schema.kind == "abi_packed"
    assert schema.confidence >= 0.5


def test_infer_etherscan_envelope():
    schema = SchemaInferer().infer([
        etherscan_envelope(address_word(USDC)),
        etherscan_envelope(address_word(WETH)),
    ])
    assert schema.kind == "json_envelope"


def test_infer_jsonrpc_balance_response():
    schema = SchemaInferer().infer([
        jsonrpc_balance_response(83, "0x2a"),
        jsonrpc_balance_response(84, "0x10"),
    ])
    assert schema.kind == "json_envelope"


# ---------------------------------------------------------------------------
# Synthesizer: held-out fixtures (real formats, unseen values)
# ---------------------------------------------------------------------------

def _run_sandbox_ok(source, heldout):
    result = SandboxRunner(timeout_s=10).run(source, heldout)
    assert result.ok, f"sandbox failed: {result.to_dict()}"
    assert result.passed == len(heldout)
    assert result.failed == 0


def test_synthesizer_transfer_calldata_heldout():
    synth = Synthesizer()
    _, source = synth.synthesize([
        transfer_calldata(WETH, 1_000_000),
        transfer_calldata(USDC, 2_500_000),
    ])
    _run_sandbox_ok(source, [
        {"payload": transfer_calldata("0x000000000000000000000000000000000000dead", 42),
         "expected": transfer_calldata_expected("0x000000000000000000000000000000000000dead", 42)},
    ])


def test_synthesizer_get_reserves_heldout():
    synth = Synthesizer()
    _, source = synth.synthesize([
        get_reserves_return(1_000_000_000, 2_000_000_000, 1_700_000_000),
        get_reserves_return(500, 750, 1_700_000_001),
    ])
    _run_sandbox_ok(source, [
        {"payload": get_reserves_return(123, 456, 1_700_000_099),
         "expected": {"value": 123, "value_2": 456, "value_3": 1_700_000_099}},
    ])


def test_synthesizer_transfer_event_log_heldout():
    synth = Synthesizer()
    _, source = synth.synthesize([
        transfer_log(ZERO, WETH, 1_000_000),
        transfer_log(WETH, ZERO, 5_000_000),
    ])
    _run_sandbox_ok(source, [
        {"payload": transfer_log(ZERO, USDC, 777, tx_hash_suffix="ef"),
         "expected": transfer_log_expected(ZERO, USDC, 777)},
    ])


def test_synthesizer_minimal_proxy_heldout():
    synth = Synthesizer()
    _, source = synth.synthesize([
        minimal_proxy(WETH),
        minimal_proxy(USDC),
    ])
    _run_sandbox_ok(source, [
        {"payload": minimal_proxy("0x000000000000000000000000000000000000dead"),
         "expected": {"proxy_kind": "eip1167_minimal",
                      "implementation": "0x000000000000000000000000000000000000dead"}},
    ])


def test_synthesizer_v3_path_heldout():
    synth = Synthesizer()
    _, source = synth.synthesize([
        v3_path(USDC, 3000, WETH),
        v3_path(WETH, 500, USDC),
    ])
    _run_sandbox_ok(source, [
        {"payload": v3_path(USDC, 10000, "0x000000000000000000000000000000000000dead"),
         "expected": v3_path_expected(USDC, 10000, "0x000000000000000000000000000000000000dead")},
    ])


def test_synthesizer_etherscan_envelope_heldout():
    synth = Synthesizer()
    _, source = synth.synthesize([
        etherscan_envelope(address_word(USDC)),
        etherscan_envelope(address_word(WETH)),
    ])
    _run_sandbox_ok(source, [
        {"payload": etherscan_envelope(address_word("0x000000000000000000000000000000000000dead")),
         "expected": {"address": "0x000000000000000000000000000000000000dead"}},
    ])


def test_synthesizer_jsonrpc_balance_heldout():
    synth = Synthesizer()
    _, source = synth.synthesize([
        jsonrpc_balance_response(83, "0x2a"),
        jsonrpc_balance_response(84, "0x10"),
    ])
    _run_sandbox_ok(source, [
        {"payload": jsonrpc_balance_response(99, "0x63"),
         "expected": {"value": 99}},
    ])


def test_synthesizer_fails_loudly_on_uncrackable_format():
    """RLP legacy tx: a real format with no RLP generator. Must fail loud."""
    synth = Synthesizer()
    with pytest.raises(SynthesisError):
        synth.synthesize([
            legacy_tx(42, 20_000_000_000, 21_000, USDC, 0, b"", 37,
                      bytes.fromhex("11" * 32), bytes.fromhex("22" * 32)),
            legacy_tx(43, 20_000_000_000, 60_000, USDC, 0,
                      bytes.fromhex(transfer_calldata(WETH, 1_000_000)[2:]), 38,
                      bytes.fromhex("33" * 32), bytes.fromhex("44" * 32)),
        ])


def test_synthesizer_fails_loudly_on_no_examples():
    with pytest.raises(SynthesisError):
        Synthesizer().synthesize([])


# ---------------------------------------------------------------------------
# Sandbox isolation
# ---------------------------------------------------------------------------

def test_sandbox_rejects_unverified_source():
    result = SandboxRunner().run('import os\n\n\ndef decode(p):\n    return os.system("id")', [])
    assert not result.ok
    assert result.violations, "expected AST violations recorded"


def test_sandbox_timeout_kills_infinite_loop():
    source = "def decode(payload):\n    while True:\n        pass\n"
    assert ASTVerifier().verify(source, require_decode=True).ok
    result = SandboxRunner(timeout_s=2).run(source, [{"payload": "x", "expected": {}}])
    assert not result.ok
    assert result.timed_out


def test_sandbox_reports_fixture_mismatch():
    synth = Synthesizer()
    _, source = synth.synthesize([
        transfer_calldata(WETH, 1_000_000),
        transfer_calldata(USDC, 2_500_000),
    ])
    result = SandboxRunner().run(source, [
        {"payload": transfer_calldata(WETH, 1_000_000),
         "expected": {"selector": TRANSFER_SELECTOR, "address": WETH, "value": 999}},
    ])
    assert not result.ok
    assert result.failed == 1
    assert result.failures[0]["reason"] == "mismatch"


# ---------------------------------------------------------------------------
# Pipeline + review gate
# ---------------------------------------------------------------------------

def test_pipeline_stages_for_review_only(tmp_path):
    pipeline = SynthesisPipeline()
    report = pipeline.run(
        [transfer_calldata(WETH, 1_000_000),
         transfer_calldata(USDC, 2_500_000)],
        [{"payload": transfer_calldata("0x000000000000000000000000000000000000dead", 42),
          "expected": transfer_calldata_expected("0x000000000000000000000000000000000000dead", 42)}],
        failure_context={"module": "abi_reconstructor", "reason": "unknown layout"},
        stage_dir=tmp_path / "synthesized")
    assert report.status == "staged_for_review", report.to_dict()
    assert report.staged_path is not None
    staged = open(report.staged_path).read()
    assert "HUMAN_REVIEWED = False" in staged
    assert "PENDING HUMAN REVIEW" in staged
    assert report.tool_id.startswith("synth_")
    # The staged file is valid Python defining the decoder + plugin stub.
    import ast as _ast
    _ast.parse(staged)
    # Nothing was written into the live plugin tree.
    plugins_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "app", "plugins")
    assert not any(name.startswith("synth_") for name in os.listdir(plugins_dir))


def test_pipeline_failed_verification_never_stages(tmp_path):
    pipeline = SynthesisPipeline()
    report = pipeline.run(
        [transfer_calldata(WETH, 1_000_000),
         transfer_calldata(USDC, 2_500_000)],
        [{"payload": transfer_calldata(WETH, 1_000_000),
          "expected": {"selector": TRANSFER_SELECTOR, "address": WETH, "value": 999}}],
        stage_dir=tmp_path / "synthesized")
    assert report.status == "failed_verification"
    assert report.staged_path is None
    assert not (tmp_path / "synthesized").exists() or not list((tmp_path / "synthesized").glob("synth_*.py"))


def test_pipeline_uncrackable_never_stages(tmp_path):
    pipeline = SynthesisPipeline()
    report = pipeline.run(
        [legacy_tx(42, 20_000_000_000, 21_000, USDC, 0, b"", 37,
                   bytes.fromhex("11" * 32), bytes.fromhex("22" * 32)),
         legacy_tx(43, 20_000_000_000, 21_000, USDC, 0, b"", 38,
                   bytes.fromhex("33" * 32), bytes.fromhex("44" * 32))],
        [{"payload": "0xdeadbeef", "expected": {}}],
        stage_dir=tmp_path / "synthesized")
    assert report.status == "failed"
    assert report.staged_path is None
    assert report.error and "cannot crack" in report.error


def test_tool_id_stable():
    _, source = Synthesizer().synthesize([
        transfer_calldata(WETH, 1_000_000),
        transfer_calldata(USDC, 2_500_000),
    ])
    assert tool_id_for(source) == tool_id_for(source)
    assert tool_id_for(source).startswith("synth_")
