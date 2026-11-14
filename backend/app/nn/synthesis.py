"""Program synthesis & self-modifying tooling (meta-learning) for ReconAnything.

Sandboxed Synthesizer: when an existing module fails on an unknown
protocol / obfuscated API / custom contract format, this module

1. reverse-engineers the schema from observed examples (field types,
   lengths, selectors),
2. synthesizes a new parser / scraper / decoder as Python source,
3. verifies it with STRICT AST checking (allowlist only),
4. executes it ONLY inside an isolated subprocess (no network, temp
   working dir, hard timeout, memory cap) against held-out fixtures,
5. and only on passing all fixtures stages it for HUMAN review.

Safety is the point. Synthesized tools NEVER auto-merge, NEVER
auto-deploy, NEVER touch the live scanner, and NEVER run outside the
sandbox. They are detection-only decoders / parsers: never exploit
code, never transaction builders. They never predict VERIFIED_REAL.
Triage only. crypto.com is never a target.

Pure Python stdlib. Zero new dependencies. Runs on CPU.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import resource
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "ALLOWED_IMPORTS",
    "BANNED_NAMES",
    "ASTVerifier",
    "VerificationResult",
    "Schema",
    "SchemaInferer",
    "SynthesisError",
    "Synthesizer",
    "SandboxResult",
    "SandboxRunner",
    "SynthesisReport",
    "SynthesisPipeline",
    "synthesize",
    "stage_for_review",
    "SYNTHESIZED_DIR",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The ONLY modules generated code may import. Everything else is rejected.
ALLOWED_IMPORTS = frozenset({
    "re", "json", "math", "struct", "binascii", "hashlib", "base64",
    "collections", "itertools", "string",
})

#: Names generated code may never use (as a Name, attribute, or import).
#: Covers execution, file/network access, introspection, and dunder escapes.
BANNED_NAMES = frozenset({
    "eval", "exec", "open", "__import__", "compile", "input", "breakpoint",
    "getattr", "setattr", "delattr", "hasattr", "vars", "dir", "globals",
    "locals", "memoryview", "exit", "quit", "help", "__builtins__",
    "os", "sys", "subprocess", "socket", "pathlib", "shutil", "requests",
    "urllib", "http", "pty", "signal", "threading", "multiprocessing",
    "ctypes", "inspect", "importlib", "pkgutil", "code", "codeop", "runpy",
    "builtins", "socketserver", "ftplib", "smtplib", "webbrowser", "atexit",
})

#: AST node types generated code may never contain. Import / ImportFrom
#: are NOT in this tuple: they are checked separately against the
#: import allowlist below.
BANNED_NODE_TYPES = (
    ast.ClassDef, ast.AsyncFunctionDef, ast.Await, ast.Yield, ast.YieldFrom,
    ast.Global, ast.Nonlocal, ast.Delete,
)

#: Attributes generated code may never touch. Same as BANNED_NAMES
#: except "compile": ``re.compile`` is the one legitimate use, and the
#: bare ``compile()`` builtin stays banned via the Name check.
BANNED_ATTRS = BANNED_NAMES - {"compile"}

MAX_SOURCE_CHARS = 65536
MAX_AST_NODES = 5000
DEFAULT_SANDBOX_TIMEOUT_S = 10.0
DEFAULT_SANDBOX_MEMORY_MB = 256

SYNTHESIZED_DIR = Path(__file__).resolve().parent / "synthesized"

#: Canonical field names the JSON normalizer maps obfuscated keys onto,
#: keyed by the value pattern that identifies them.
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
HEX_INT_RE = re.compile(r"^0x[0-9a-fA-F]{1,64}$")

#: EIP-1167 minimal-proxy bytecode: prefix + 20-byte impl + suffix.
EIP1167_PREFIX = "363d3d373d3d3d363d73"
EIP1167_SUFFIX = "5af43d82803e903d91602b57fd5bf3"
#: EIP-1967 implementation / beacon slots (keccak-256("eip1967.proxy.implementation")-1 etc.)
EIP1967_IMPL_SLOT = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON_SLOT = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d"


class SynthesisError(Exception):
    """Raised when a format cannot be cracked. Fails LOUDLY, never silent."""


# ---------------------------------------------------------------------------
# AST verifier (strict allowlist)
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    ok: bool
    violations: List[str] = field(default_factory=list)
    nodes: int = 0

    def __bool__(self) -> bool:
        return self.ok


class ASTVerifier:
    """Strict allowlist checker for synthesized Python source.

    Rejects anything outside the allowlist: imports outside
    ALLOWED_IMPORTS, execution / file / network primitives, dunder
    attribute access, dynamic attribute access, classes, async, globals,
    decorators, and oversized sources. Accepts only small, pure decoder
    code built from the allowlisted modules and safe builtins.
    """

    def verify(self, source: str, require_decode: bool = False) -> VerificationResult:
        violations: List[str] = []
        if len(source) > MAX_SOURCE_CHARS:
            return VerificationResult(False, [f"source too large: {len(source)} chars > {MAX_SOURCE_CHARS}"])
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return VerificationResult(False, [f"syntax error: {exc}"])
        nodes = list(ast.walk(tree))
        if len(nodes) > MAX_AST_NODES:
            return VerificationResult(False, [f"AST too large: {len(nodes)} nodes > {MAX_AST_NODES}"])

        has_decode = False
        for node in nodes:
            if isinstance(node, ast.FunctionDef) and node.name == "decode":
                has_decode = True
                if len(node.args.args) != 1 or node.args.vararg or node.args.kwarg:
                    violations.append("decode() must take exactly one positional argument")
                if node.decorator_list:
                    violations.append("decode() must not have decorators")
            if isinstance(node, BANNED_NODE_TYPES):
                violations.append(f"banned node type: {type(node).__name__} at line {getattr(node, 'lineno', '?')}")
            if isinstance(node, ast.FunctionDef) and node.decorator_list:
                violations.append(f"decorators banned: function {node.name!r} at line {node.lineno}")
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root not in ALLOWED_IMPORTS:
                        violations.append(f"banned import: {alias.name!r} at line {node.lineno}")
            if isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root not in ALLOWED_IMPORTS:
                    violations.append(f"banned import: from {node.module!r} at line {node.lineno}")
                elif any(a.name == "*" for a in node.names):
                    violations.append(f"star import banned at line {node.lineno}")
            if isinstance(node, ast.Name):
                if node.id in BANNED_NAMES:
                    violations.append(f"banned name: {node.id!r} at line {node.lineno}")
                elif node.id.startswith("__") and node.id.endswith("__"):
                    violations.append(f"dunder name banned: {node.id!r} at line {node.lineno}")
            if isinstance(node, ast.Attribute):
                if node.attr in BANNED_ATTRS:
                    violations.append(f"banned attribute: {node.attr!r} at line {node.lineno}")
                elif node.attr.startswith("_"):
                    violations.append(f"private/dunder attribute banned: {node.attr!r} at line {node.lineno}")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                # A string literal alone is inert, but flag the classic
                # smuggle: a banned call spelled out as data fed to a
                # dynamic construct. The dynamic constructs themselves
                # are already banned above; this is a tripwire only.
                if node.value.strip().startswith(("__import__(", "eval(", "exec(")):
                    violations.append(f"suspicious string literal at line {node.lineno}")

        if require_decode and not has_decode:
            violations.append("missing required top-level function decode(payload)")
        return VerificationResult(ok=not violations, violations=violations, nodes=len(nodes))


# ---------------------------------------------------------------------------
# Schema inference (reverse-engineering from observed examples)
# ---------------------------------------------------------------------------

@dataclass
class Schema:
    kind: str  # abi_words | abi_packed | json_envelope | json_positional | event_log | proxy | unknown
    fields: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    confidence: float = 0.0
    examples_seen: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "fields": self.fields, "notes": self.notes,
                "confidence": round(self.confidence, 3), "examples_seen": self.examples_seen}


def _is_hex_str(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX_RE.match(value.strip()))


def _classify_word(word_hex: str) -> str:
    """Classify one 32-byte word of ABI-style data.

    Order matters: a bool word (0...01) also has 12 leading zero bytes,
    so bool / small-int are checked before address. An address is only
    claimed when the top 12 bytes are zero AND the remaining 20 bytes
    do not fit in a uint64 (real addresses are random 160-bit values;
    small ints almost never are addresses).
    """
    if not word_hex:
        return "empty"
    if set(word_hex) == {"0"}:
        return "zero"
    raw = bytes.fromhex(word_hex)
    value = int(word_hex, 16)
    if value in (0, 1):
        return "bool"
    if raw[:12] == b"\x00" * 12 and value >= 2 ** 64:
        return "address"
    if value < 2 ** 64:
        return "uint_small"
    return "uint256_or_bytes32"


def _infer_hex_schema(examples: List[str]) -> Schema:
    stripped = [e.strip()[2:] if e.strip().lower().startswith("0x") else e.strip() for e in examples]
    if any(len(s) % 2 for s in stripped):
        return Schema(kind="unknown", confidence=0.0,
                      notes=["hex examples have odd length; not decodable as bytes"],
                      examples_seen=len(examples))
    blobs = [bytes.fromhex(s) for s in stripped]
    lengths = {len(b) for b in blobs}
    if len(lengths) != 1:
        return Schema(kind="unknown", confidence=0.15,
                      notes=["hex examples disagree on length; no fixed layout"],
                      examples_seen=len(examples))
    blob = blobs[0]
    n = len(blob)
    # EIP-1167 minimal proxy: fixed prefix + 20-byte address + fixed suffix.
    hexblob = blob.hex()
    if hexblob.startswith(EIP1167_PREFIX) and hexblob.endswith(EIP1167_SUFFIX):
        impl = "0x" + hexblob[len(EIP1167_PREFIX):len(EIP1167_PREFIX) + 40]
        return Schema(kind="proxy", confidence=0.95, examples_seen=len(examples),
                      fields=[{"name": "proxy_kind", "type": "const", "value": "eip1167_minimal"},
                              {"name": "implementation", "type": "address", "offset": len(EIP1167_PREFIX) // 2, "length": 20}],
                      notes=[f"EIP-1167 minimal proxy; implementation at byte {len(EIP1167_PREFIX) // 2}",
                             f"implementation={impl}"])
    # EIP-1967 proxy marker: a 32-byte slot value that looks like an impl slot.
    if n == 32 and hexblob in (EIP1967_IMPL_SLOT, EIP1967_BEACON_SLOT):
        kind = "eip1967_implementation" if hexblob == EIP1967_IMPL_SLOT else "eip1967_beacon"
        return Schema(kind="proxy", confidence=0.9, examples_seen=len(examples),
                      fields=[{"name": "proxy_kind", "type": "const", "value": kind}],
                      notes=[f"EIP-1967 slot {kind}"])
    # Word-aligned ABI layout (multiple of 32 bytes, >= 32), optionally
    # prefixed by a 4-byte function selector (real calldata: selector +
    # ABI-encoded args, e.g. ERC-20 transfer 0xa9059cbb). A blob whose
    # length is 4 mod 32 is read as selector + args; a blob whose length
    # is 0 mod 32 is read as bare words. The two cases never overlap.
    has_selector = n >= 36 and (n - 4) % 32 == 0 and n % 32 != 0
    args = blob[4:] if has_selector else blob
    if len(args) >= 32 and len(args) % 32 == 0:
        words = [args[i:i + 32].hex() for i in range(0, len(args), 32)]
        fields: List[Dict[str, Any]] = []
        notes: List[str] = []
        if has_selector:
            fields.append({"name": "selector", "type": "selector",
                           "offset": 0, "length": 4})
            notes.append(f"4-byte function selector 0x{blob[:4].hex()}; "
                         f"{len(words)} ABI words follow")
        consumed = set()
        i = 0
        while i < len(words):
            if i in consumed:
                i += 1
                continue
            wtype = _classify_word(words[i])
            value = int(words[i], 16)
            if wtype == "address":
                fields.append({"name": f"field_{i}", "type": "address", "word": i})
            elif wtype == "bool":
                fields.append({"name": f"field_{i}", "type": "bool", "word": i})
            elif wtype == "zero":
                fields.append({"name": f"field_{i}", "type": "uint256", "word": i})
            elif wtype == "uint_small":
                # Could be a dynamic offset: points inside the args at a
                # word boundary, followed by a small length word. Offsets
                # are relative to the start of the args (after any
                # selector), per the ABI spec.
                if 0 < value < len(args) and value % 32 == 0 and i + 1 < len(words):
                    target = value // 32
                    if target > i and int(words[target], 16) <= 4096:
                        fields.append({"name": f"field_{i}", "type": "bytes_dynamic",
                                       "word": i, "data_word": target})
                        # The length word and its data words belong to
                        # this dynamic field; do not emit them as fields.
                        length = int(words[target], 16)
                        data_words = (length + 31) // 32
                        consumed.update(range(target, target + 1 + data_words))
                        notes.append(f"word {i} is a dynamic offset -> data at word {target}")
                        i += 1
                        continue
                fields.append({"name": f"field_{i}", "type": "uint256", "word": i})
            else:
                fields.append({"name": f"field_{i}", "type": "bytes32", "word": i})
            i += 1
        return Schema(kind="abi_words", confidence=0.9, fields=fields,
                      notes=notes or [f"{len(words)} 32-byte words; per-word types inferred"],
                      examples_seen=len(examples))
    # Tightly-packed layout: only one real packed width is pinned down —
    # the Uniswap V3 swap path (token 20 bytes + fee uint24 3 bytes +
    # token 20 bytes = 43 bytes), the packed encoding every V3 swap
    # carries on-chain. Any other non-word-aligned length is reported
    # unknown rather than guessed.
    if n == 43:
        return Schema(kind="abi_packed", confidence=0.8, examples_seen=len(examples),
                      fields=[{"name": "token_in", "type": "address", "offset": 0, "length": 20},
                              {"name": "fee", "type": "uint24", "offset": 20, "length": 3},
                              {"name": "token_out", "type": "address", "offset": 23, "length": 20}],
                      notes=["Uniswap V3 swap path: token(20) + fee uint24(3) + token(20)"])
    return Schema(kind="unknown", confidence=0.2,
                  notes=[f"hex blob of {n} bytes matches no known layout (not word-aligned, not a proxy, not a packed width)"],
                  examples_seen=len(examples))


def _canonical_for_value(value: Any) -> Optional[str]:
    """Map an observed value to a canonical field name by its shape."""
    if isinstance(value, str) and ADDRESS_RE.match(value):
        return "address"
    if isinstance(value, str) and HASH_RE.match(value):
        # A 32-byte word whose top 12 bytes are zero is an address
        # sitting in a word (eth_call returning an address, a log topic),
        # not a hash.
        if value[2:26] == "0" * 24:
            return "address"
        return "hash"
    if isinstance(value, str) and HEX_INT_RE.match(value):
        return "value"
    if isinstance(value, bool):
        return "active"
    if isinstance(value, int):
        return "value"
    return None


def _infer_json_schema(examples: List[Dict[str, Any]]) -> Schema:
    # Event logs first: dicts carrying topics + data + address (the
    # eth_getLogs result object: ERC-20 Transfer has topics[0]=event,
    # topics[1]=from, topics[2]=to, data=value, address=token).
    if all(isinstance(e, dict) and "topics" in e and "data" in e for e in examples):
        return Schema(kind="event_log", confidence=0.9, examples_seen=len(examples),
                      fields=[{"name": "event", "type": "topic0"},
                              {"name": "indexed", "type": "address", "topic": 1},
                              {"name": "indexed_2", "type": "address", "topic": 2},
                              {"name": "amount", "type": "uint256", "word": 0},
                              {"name": "contract", "type": "address"}],
                      notes=["topics[0]=event signature, topics[1]=from, topics[2]=to, data=value word"])
    # Collect every (key path, value) pair across examples.
    pairs: Dict[str, List[Any]] = {}

    def walk(obj: Any, path: str) -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                walk(val, f"{path}.{key}" if path else str(key))
        elif isinstance(obj, list):
            for idx, val in enumerate(obj):
                walk(val, f"{path}[{idx}]")
        else:
            pairs.setdefault(path, []).append(obj)

    for example in examples:
        walk(example, "")
    # Positional format: top-level list of lists, or a single key holding
    # a list of lists whose items look like [address, int, bool].
    positional = False
    for example in examples:
        rows = example if isinstance(example, list) else None
        if rows is None and isinstance(example, dict) and len(example) == 1:
            only = next(iter(example.values()))
            rows = only if isinstance(only, list) else None
        if isinstance(rows, list) and rows and all(isinstance(r, list) and len(r) >= 2 for r in rows):
            first = rows[0]
            if (isinstance(first[0], str) and ADDRESS_RE.match(first[0])
                    and isinstance(first[1], int)):
                positional = True
    if positional:
        return Schema(kind="json_positional", confidence=0.85, examples_seen=len(examples),
                      fields=[{"name": "entries", "type": "list",
                               "item": {"address": 0, "value": 1, "active": 2}}],
                      notes=["rows are positional [address, value, active]; no keys to trust"])
    # Envelope format: a standard envelope key (result / data / payload)
    # whose subtree holds at least one recognizable value, or two or
    # more canonical fields anywhere in the object. A single-field
    # response (e.g. eth_getBalance {"result": "0x2a"}) still counts
    # when it sits under a real envelope key.
    mapping: Dict[str, List[str]] = {}
    for path, values in pairs.items():
        canon = None
        for value in values:
            canon = _canonical_for_value(value)
            if canon:
                break
        if canon:
            mapping.setdefault(canon, []).append(path)
    envelope_keys = {"result", "data", "payload", "response", "return"}
    has_envelope_key = any(
        isinstance(e, dict) and envelope_keys & set(e.keys()) for e in examples)
    if (has_envelope_key and mapping) or len(mapping) >= 2:
        return Schema(kind="json_envelope", confidence=0.85,
                      fields=[{"name": canon, "type": "value_pattern", "paths": paths}
                              for canon, paths in sorted(mapping.items())],
                      notes=[f"canonical field {canon!r} seen under key path(s): {paths}"
                             for canon, paths in sorted(mapping.items())],
                      examples_seen=len(examples))
    return Schema(kind="unknown", confidence=0.2,
                  notes=["JSON examples carry no recognizable address/hex/int/bool pattern"],
                  examples_seen=len(examples))


class SchemaInferer:
    """Reverse-engineers a format's schema from observed examples."""

    def infer(self, examples: List[Any]) -> Schema:
        if not examples:
            raise SynthesisError("cannot infer schema: no examples supplied")
        if all(isinstance(e, str) and _is_hex_str(e) for e in examples):
            return _infer_hex_schema(examples)
        if all(isinstance(e, dict) for e in examples):
            return _infer_json_schema(examples)
        if all(isinstance(e, list) for e in examples):
            return _infer_json_schema(examples)  # positional lists
        return Schema(kind="unknown", confidence=0.1,
                      notes=["mixed or unsupported example types; no schema inferred"],
                      examples_seen=len(examples))


# ---------------------------------------------------------------------------
# Synthesizer (template-based code generation; no LLM, deterministic)
# ---------------------------------------------------------------------------

def _schema_literal(schema: Schema) -> str:
    return "SCHEMA = " + json.dumps(schema.to_dict(), sort_keys=True)


def _gen_abi_words(schema: Schema) -> str:
    has_selector = any(f["type"] == "selector" for f in schema.fields)
    lines = [
        "import re",
        "",
        _schema_literal(schema),
        "",
        "",
        "def decode(payload):",
        "    text = payload[2:] if payload.startswith(\"0x\") else payload",
        "    raw = bytes.fromhex(text)",
    ]
    if has_selector:
        lines.append("    out = {\"selector\": \"0x\" + raw[0:4].hex()}")
        lines.append("    words = [raw[i:i + 32].hex() for i in range(4, len(raw), 32)]")
    else:
        lines.append("    out = {}")
        lines.append("    words = [raw[i:i + 32].hex() for i in range(0, len(raw), 32)]")
    seen: Dict[str, int] = {}
    for f in schema.fields:
        if f["type"] == "selector":
            continue
        name = f["name"]
        ftype = f["type"]
        word = f["word"]
        if ftype == "address":
            base = "address"
        elif ftype == "bool":
            base = "active"
        elif ftype == "bytes_dynamic":
            base = "data"
        elif ftype == "bytes32":
            base = "data"
        else:
            base = "value"
        seen[base] = seen.get(base, 0) + 1
        key = base if seen[base] == 1 else f"{base}_{seen[base]}"
        if ftype == "address":
            lines.append(f"    out[{key!r}] = \"0x\" + words[{word}][24:]")
        elif ftype == "bool":
            lines.append(f"    out[{key!r}] = int(words[{word}], 16) != 0")
        elif ftype == "bytes_dynamic":
            target = f["data_word"]
            lines.append(f"    _length = int(words[{target}], 16)")
            lines.append(f"    _blob = b\"\".join(bytes.fromhex(w) for w in words[{target} + 1:])")
            lines.append(f"    out[{key!r}] = \"0x\" + _blob[:_length].hex()")
        elif ftype == "bytes32":
            lines.append(f"    out[{key!r}] = \"0x\" + words[{word}]")
        else:
            lines.append(f"    out[{key!r}] = int(words[{word}], 16)")
    lines.append("    return out")
    lines.append("")
    return "\n".join(lines)


def _gen_abi_packed(schema: Schema) -> str:
    """Field-driven packed decoder: slices raw bytes per schema field.

    No layout is hardcoded here; the field table comes from the
    inferrer (currently only the Uniswap V3 swap path is pinned down).
    """
    lines = [
        "import re",
        "",
        _schema_literal(schema),
        "",
        "",
        "def decode(payload):",
        "    text = payload[2:] if payload.startswith(\"0x\") else payload",
        "    raw = bytes.fromhex(text)",
        "    out = {}",
    ]
    for f in schema.fields:
        name = f["name"]
        ftype = f["type"]
        off = f["offset"]
        length = f["length"]
        if ftype == "address":
            lines.append(f"    out[{name!r}] = \"0x\" + raw[{off}:{off + length}].hex()")
        elif ftype in ("uint24", "uint96", "uint256", "uint"):
            lines.append(f"    out[{name!r}] = int.from_bytes(raw[{off}:{off + length}], \"big\")")
        elif ftype == "bool":
            lines.append(f"    out[{name!r}] = raw[{off}] != 0")
        else:
            lines.append(f"    out[{name!r}] = \"0x\" + raw[{off}:{off + length}].hex()")
    lines.append("    return out")
    lines.append("")
    return "\n".join(lines)


def _gen_json_envelope(schema: Schema) -> str:
    lines = [
        "import re",
        "",
        _schema_literal(schema),
        "",
        "_ADDRESS = re.compile(r\"^0x[0-9a-fA-F]{40}$\")",
        "_HASH = re.compile(r\"^0x[0-9a-fA-F]{64}$\")",
        "_HEXINT = re.compile(r\"^0x[0-9a-fA-F]{1,64}$\")",
        "",
        "",
        "def _walk(obj, out):",
        "    if isinstance(obj, dict):",
        "        for val in obj.values():",
        "            _walk(val, out)",
        "    elif isinstance(obj, list):",
        "        for val in obj:",
        "            _walk(val, out)",
        "    elif isinstance(obj, bool):",
        "        out[\"active\"] = obj",
        "    elif isinstance(obj, str) and _ADDRESS.match(obj):",
        "        out[\"address\"] = obj",
        "    elif isinstance(obj, str) and _HASH.match(obj):",
        "        if obj[2:26] == \"0\" * 24:",
        "            out[\"address\"] = \"0x\" + obj[26:]",
        "        else:",
        "            out[\"hash\"] = obj",
        "    elif isinstance(obj, str) and _HEXINT.match(obj):",
        "        out[\"value\"] = int(obj, 16)",
        "    elif isinstance(obj, int):",
        "        out[\"value\"] = obj",
        "",
        "",
        "def decode(payload):",
        "    out = {}",
        "    _walk(payload, out)",
        "    return out",
        "",
    ]
    return "\n".join(lines)


def _gen_json_positional(schema: Schema) -> str:
    lines = [
        "import re",
        "",
        _schema_literal(schema),
        "",
        "",
        "def decode(payload):",
        "    rows = payload",
        "    if isinstance(payload, dict):",
        "        vals = list(payload.values())",
        "        rows = vals[0] if vals and isinstance(vals[0], list) else []",
        "    entries = []",
        "    for row in rows:",
        "        if not isinstance(row, list) or len(row) < 2:",
        "            continue",
        "        entry = {\"address\": row[0], \"value\": row[1]}",
        "        if len(row) > 2:",
        "            entry[\"active\"] = row[2]",
        "        entries.append(entry)",
        "    return {\"entries\": entries}",
        "",
    ]
    return "\n".join(lines)


def _gen_event_log(schema: Schema) -> str:
    lines = [
        "import re",
        "",
        _schema_literal(schema),
        "",
        "",
        "def decode(payload):",
        "    topics = payload.get(\"topics\", [])",
        "    text = payload.get(\"data\", \"\")",
        "    text = text[2:] if text.startswith(\"0x\") else text",
        "    raw = bytes.fromhex(text) if text else b\"\"",
        "    words = [raw[i:i + 32].hex() for i in range(0, len(raw), 32)]",
        "    out = {}",
        "    if topics:",
        "        out[\"event\"] = topics[0]",
        "    if len(topics) > 1:",
        "        out[\"indexed\"] = \"0x\" + topics[1][-40:]",
        "    if len(topics) > 2:",
        "        out[\"indexed_2\"] = \"0x\" + topics[2][-40:]",
        "    if words:",
        "        out[\"amount\"] = int(words[0], 16)",
        "    if payload.get(\"address\"):",
        "        out[\"contract\"] = payload.get(\"address\")",
        "    return out",
        "",
    ]
    return "\n".join(lines)


def _gen_proxy(schema: Schema) -> str:
    lines = [
        "import re",
        "",
        _schema_literal(schema),
        "",
        "_PREFIX = \"363d3d373d3d3d363d73\"",
        "_SUFFIX = \"5af43d82803e903d91602b57fd5bf3\"",
        "",
        "",
        "def decode(payload):",
        "    text = payload[2:] if payload.startswith(\"0x\") else payload",
        "    text = text.lower()",
        "    if text.startswith(_PREFIX) and text.endswith(_SUFFIX):",
        "        impl = \"0x\" + text[len(_PREFIX):len(_PREFIX) + 40]",
        "        return {\"proxy_kind\": \"eip1167_minimal\", \"implementation\": impl}",
        "    return {\"proxy_kind\": \"unknown\", \"implementation\": None}",
        "",
    ]
    return "\n".join(lines)


_GENERATORS = {
    "abi_words": _gen_abi_words,
    "abi_packed": _gen_abi_packed,
    "json_envelope": _gen_json_envelope,
    "json_positional": _gen_json_positional,
    "event_log": _gen_event_log,
    "proxy": _gen_proxy,
}

#: Minimum inference confidence before synthesis is even attempted.
MIN_SYNTHESIS_CONFIDENCE = 0.5


class Synthesizer:
    """Infers a schema from examples, then generates decoder source.

    Template-based and deterministic: the generator only fills in
    field layouts the inferrer actually observed. Anything it cannot
    pin down raises SynthesisError instead of guessing.
    """

    def __init__(self, verifier: Optional[ASTVerifier] = None) -> None:
        self.verifier = verifier or ASTVerifier()
        self.inferrer = SchemaInferer()

    def synthesize(self, examples: List[Any]) -> Tuple[Schema, str]:
        schema = self.inferrer.infer(examples)
        if schema.kind == "unknown" or schema.confidence < MIN_SYNTHESIS_CONFIDENCE:
            raise SynthesisError(
                f"cannot crack format: inferred kind={schema.kind!r} "
                f"confidence={schema.confidence:.2f}; notes: {'; '.join(schema.notes)}"
            )
        generator = _GENERATORS.get(schema.kind)
        if generator is None:
            raise SynthesisError(f"no generator for kind {schema.kind!r}")
        source = generator(schema)
        result = self.verifier.verify(source, require_decode=True)
        if not result.ok:
            # A template failing its own gate is a bug in the template,
            # never something to paper over: fail loudly.
            raise SynthesisError(
                f"generated source failed AST verification: {result.violations}"
            )
        return schema, source


def tool_id_for(source: str) -> str:
    """Stable id for a synthesized tool: synth_<first 8 of sha256>."""
    return "synth_" + hashlib.sha256(source.encode("utf-8")).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Sandbox runner (isolated subprocess, no network, hard limits)
# ---------------------------------------------------------------------------

#: Modules the sandbox child refuses to import, even if AST verification
#: were ever bypassed. Defense in depth: the AST allowlist is the gate,
#: this blocklist is the second wall.
_SANDBOX_BANNED_IMPORTS = frozenset({
    "os", "sys", "subprocess", "socket", "pathlib", "shutil", "urllib",
    "http", "pty", "signal", "threading", "multiprocessing", "ctypes",
    "inspect", "importlib", "pkgutil", "code", "codeop", "runpy",
    "builtins", "socketserver", "ftplib", "smtplib", "webbrowser",
    "atexit", "io", "posix", "nt", "errno", "fcntl", "select", "ssl",
})

_CHILD_RUNNER = r'''
import sys, json, builtins
_BANNED = {"os", "sys", "subprocess", "socket", "pathlib", "shutil", "urllib", "http", "pty", "signal", "threading", "multiprocessing", "ctypes", "inspect", "importlib", "pkgutil", "code", "codeop", "runpy", "builtins", "socketserver", "ftplib", "smtplib", "webbrowser", "atexit", "io", "posix", "nt", "errno", "fcntl", "select", "ssl"}
class _Blocker:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in _BANNED:
            raise ImportError("blocked import: " + name)
        return None
sys.meta_path.insert(0, _Blocker())
_ALLOWED = {"re", "json", "math", "struct", "binascii", "hashlib", "base64", "collections", "itertools", "string"}
_real_import = builtins.__import__
def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level != 0:
        raise ImportError("relative imports blocked")
    if name.split(".")[0] not in _ALLOWED:
        raise ImportError("import not allowlisted: " + name)
    return _real_import(name, globals, locals, fromlist, level)
_SAFE_NAMES = ["abs", "all", "any", "bool", "bytes", "bytearray", "chr", "dict", "divmod", "enumerate", "filter", "float", "format", "frozenset", "hex", "int", "isinstance", "issubclass", "iter", "len", "list", "map", "max", "min", "next", "oct", "ord", "pow", "range", "repr", "reversed", "round", "set", "slice", "sorted", "str", "sum", "tuple", "zip", "print"]
_safe_builtins = {k: getattr(builtins, k) for k in _SAFE_NAMES}
_safe_builtins["__import__"] = _safe_import
for _exc in ["ValueError", "TypeError", "KeyError", "IndexError", "AttributeError", "Exception", "StopIteration", "ZeroDivisionError", "OverflowError", "RuntimeError", "NotImplementedError"]:
    _safe_builtins[_exc] = getattr(builtins, _exc)
def main():
    req = json.loads(sys.stdin.read())
    out = {"ok": False, "results": [], "error": None}
    try:
        ns = {"__builtins__": _safe_builtins}
        exec(compile(req["source"], "<synthesized>", "exec"), ns)
        decode = ns.get("decode")
        if not callable(decode):
            raise RuntimeError("no decode() defined in synthesized source")
        all_ok = True
        for i, fx in enumerate(req["fixtures"]):
            try:
                got = decode(fx["payload"])
                passed = got == fx["expected"]
                if not passed:
                    all_ok = False
                keep = got if isinstance(got, (dict, list, str, int, float, bool)) or got is None else repr(got)
                out["results"].append({"index": i, "passed": passed, "reason": None if passed else "mismatch", "got": keep})
            except Exception as e:
                all_ok = False
                out["results"].append({"index": i, "passed": False, "reason": type(e).__name__ + ": " + str(e), "got": None})
        out["ok"] = all_ok
    except Exception as e:
        out["error"] = type(e).__name__ + ": " + str(e)
    sys.stdout.write(json.dumps(out))
main()
'''


@dataclass
class SandboxResult:
    ok: bool
    passed: int = 0
    failed: int = 0
    failures: List[Dict[str, Any]] = field(default_factory=list)
    duration_s: float = 0.0
    timed_out: bool = False
    error: Optional[str] = None
    violations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "passed": self.passed, "failed": self.failed,
                "failures": self.failures, "duration_s": round(self.duration_s, 3),
                "timed_out": self.timed_out, "error": self.error,
                "violations": self.violations}


class SandboxRunner:
    """Runs synthesized source in an isolated child process.

    The child runs ``python -I -S`` (isolated, no site-packages) with a
    stripped environment, a temp working directory, a hard wall-clock
    timeout, and an address-space cap. The child re-verifies nothing:
    the PARENT re-checks the AST first, and the child additionally
    blocks dangerous imports and runs the code with restricted
    builtins (no open / eval / exec / __import__ except a safe
    allowlisted wrapper). No network is reachable from generated code:
    socket and friends cannot be imported, and no file access exists.
    """

    def __init__(self, timeout_s: float = DEFAULT_SANDBOX_TIMEOUT_S,
                 memory_mb: int = DEFAULT_SANDBOX_MEMORY_MB,
                 verifier: Optional[ASTVerifier] = None) -> None:
        self.timeout_s = timeout_s
        self.memory_mb = memory_mb
        self.verifier = verifier or ASTVerifier()

    def run(self, source: str, fixtures: List[Dict[str, Any]]) -> SandboxResult:
        started = time.monotonic()
        check = self.verifier.verify(source, require_decode=True)
        if not check.ok:
            return SandboxResult(ok=False, failed=len(fixtures),
                                 violations=check.violations,
                                 error="AST verification failed in sandbox gate",
                                 duration_s=time.monotonic() - started)
        tmpdir = tempfile.mkdtemp(prefix="nn-synth-")
        try:
            payload = json.dumps({"source": source, "fixtures": fixtures}).encode("utf-8")
            mem_bytes = self.memory_mb * 1024 * 1024

            def _limits() -> None:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                cpu = max(5, int(self.timeout_s) + 5)
                resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))

            try:
                proc = subprocess.run(
                    [sys.executable, "-I", "-S", "-c", _CHILD_RUNNER],
                    input=payload, capture_output=True, timeout=self.timeout_s,
                    cwd=tmpdir, env={"PATH": "/usr/bin:/bin"},
                    preexec_fn=_limits)
            except subprocess.TimeoutExpired:
                return SandboxResult(ok=False, failed=len(fixtures), timed_out=True,
                                     error=f"sandbox timeout after {self.timeout_s}s",
                                     duration_s=time.monotonic() - started)
            duration = time.monotonic() - started
            try:
                data = json.loads(proc.stdout.decode("utf-8"))
            except Exception as exc:
                return SandboxResult(ok=False, failed=len(fixtures),
                                     error=f"child output not JSON: {exc}; stderr={proc.stderr.decode('utf-8', 'replace')[:500]}",
                                     duration_s=duration)
            if data.get("error"):
                return SandboxResult(ok=False, failed=len(fixtures),
                                     error=data["error"], duration_s=duration)
            results = data.get("results", [])
            failures = [r for r in results if not r.get("passed")]
            return SandboxResult(ok=bool(data.get("ok")) and not failures,
                                 passed=len(results) - len(failures),
                                 failed=len(failures), failures=failures,
                                 duration_s=duration)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Pipeline + review gate
# ---------------------------------------------------------------------------

@dataclass
class SynthesisReport:
    status: str  # staged_for_review | failed | failed_verification
    schema: Optional[Dict[str, Any]] = None
    source: Optional[str] = None
    tool_id: Optional[str] = None
    verification: Optional[Dict[str, Any]] = None
    sandbox: Optional[Dict[str, Any]] = None
    staged_path: Optional[str] = None
    error: Optional[str] = None
    timings_s: Dict[str, float] = field(default_factory=dict)
    failure_context: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status, "schema": self.schema,
                "source": self.source, "tool_id": self.tool_id,
                "verification": self.verification, "sandbox": self.sandbox,
                "staged_path": self.staged_path, "error": self.error,
                "timings_s": {k: round(v, 3) for k, v in self.timings_s.items()},
                "failure_context": self.failure_context}


_PLUGIN_WRAPPER = '''"""SYNTHESIZED PLUGIN -- PENDING HUMAN REVIEW -- NOT ACTIVE.

This file was produced by the Sandboxed Synthesizer (app/nn/synthesis.py)
and staged here for human review. It is NOT registered: the plugin
registry only scans app/plugins/, and this file lives in
app/nn/synthesized/, so the live scanner never runs it.

REVIEW GATE (do not skip):
  1. Read the decoder below and the fixture evidence in the synthesis report.
  2. Confirm it is detection-only: it only parses data, never sends
     transactions, never drains, never exploits, never touches auth.
  3. Only then move this file into app/plugins/ AND flip
     HUMAN_REVIEWED to True. Until then run() refuses to run.

Synthesized tool id: {tool_id}
Inferred schema: {schema_json}
"""

from __future__ import annotations

from typing import Any, Dict, List

from ...plugins.base import Cost, Ctx, Plugin, PluginResult, Target

HUMAN_REVIEWED = False
SYNTHESIZED = True
REVIEW_STATUS = "pending_human_review"

{decoder_source}

class {class_name}(Plugin):
    id = "{tool_id}"
    label = "Synthesized {kind} decoder"
    accepts = ["crypto_wallet"]
    requires_keys = []
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Synthesized {kind} decoder, staged for human review. "
                   "Detection-only parsing of an unknown format; never "
                   "sends transactions or predicts VERIFIED_REAL.")
    phase = 2
    synthesized = True
    review_status = "pending_human_review"

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        if not HUMAN_REVIEWED:
            return self._skipped(
                "synthesized tool pending human review; "
                "move to app/plugins/ and set HUMAN_REVIEWED=True first")
        import json as _json
        raw = (target.normalized or "").strip()
        payload: Any = raw
        if raw.startswith("{{"):
            try:
                payload = _json.loads(raw)
            except Exception:
                payload = raw
        try:
            decoded = decode(payload)
        except Exception as exc:  # noqa: BLE001 - decoder must never throw fatally
            return self._skipped(f"synthesized decoder could not parse target: {{exc}}")
        finding = self._f("web3", "synthesized_decode",
                          f"synthesized decoder parsed target: {{decoded}}",
                          source="synthesized", confidence=60,
                          evidence={{"decoded": decoded, "tool_id": self.id}},
                          bounty_value="low")
        return self._ok([finding], reason="synthesized decoder parsed the target")
'''


def stage_for_review(source: str, schema: Schema, stage_dir: Optional[Path] = None) -> Path:
    """Stage a verified synthesized tool for HUMAN review.

    Writes into ``backend/app/nn/synthesized/`` (the branch's staging
    tree), NEVER into ``backend/app/plugins/``. The staged file refuses
    to run until a human moves it and flips HUMAN_REVIEWED. The live
    scanner is untouched: the registry never scans this directory.
    """
    target_dir = Path(stage_dir) if stage_dir else SYNTHESIZED_DIR
    if "plugins" in target_dir.parts:
        raise SynthesisError("refusing to stage into a plugins/ directory")
    target_dir.mkdir(parents=True, exist_ok=True)
    tool_id = tool_id_for(source)
    class_name = "Synth" + "".join(part.capitalize() for part in tool_id.split("_")) + "Plugin"
    content = _PLUGIN_WRAPPER.format(
        tool_id=tool_id,
        schema_json=json.dumps(schema.to_dict(), sort_keys=True),
        decoder_source=source.rstrip("\n"),
        class_name=class_name,
        kind=schema.kind,
    )
    path = target_dir / f"{tool_id}.py"
    path.write_text(content, encoding="utf-8")
    return path


class SynthesisPipeline:
    """End-to-end: infer -> synthesize -> AST-verify -> sandbox -> stage.

    Only a tool that passes every held-out fixture in the sandbox is
    staged, and staging means "for human review", never "live".
    """

    def __init__(self, synthesizer: Optional[Synthesizer] = None,
                 sandbox: Optional[SandboxRunner] = None) -> None:
        self.synthesizer = synthesizer or Synthesizer()
        self.sandbox = sandbox or SandboxRunner()

    def run(self, examples: List[Any], heldout: List[Dict[str, Any]],
            failure_context: Optional[Dict[str, Any]] = None,
            stage_dir: Optional[Path] = None) -> SynthesisReport:
        timings: Dict[str, float] = {}
        started = time.monotonic()
        try:
            schema, source = self.synthesizer.synthesize(examples)
        except SynthesisError as exc:
            return SynthesisReport(status="failed", error=str(exc),
                                   timings_s={"synthesize_s": round(time.monotonic() - started, 3)},
                                   failure_context=failure_context)
        timings["synthesize_s"] = time.monotonic() - started
        verification = self.synthesizer.verifier.verify(source, require_decode=True)
        sandbox_started = time.monotonic()
        sandbox_result = self.sandbox.run(source, heldout)
        timings["sandbox_s"] = time.monotonic() - sandbox_started
        if not sandbox_result.ok:
            return SynthesisReport(
                status="failed_verification", schema=schema.to_dict(), source=source,
                tool_id=tool_id_for(source),
                verification={"ok": verification.ok, "violations": verification.violations},
                sandbox=sandbox_result.to_dict(),
                error=sandbox_result.error or f"sandbox failed: {sandbox_result.failures}",
                timings_s=timings, failure_context=failure_context)
        staged = stage_for_review(source, schema, stage_dir=stage_dir)
        timings["total_s"] = time.monotonic() - started
        return SynthesisReport(
            status="staged_for_review", schema=schema.to_dict(), source=source,
            tool_id=tool_id_for(source),
            verification={"ok": verification.ok, "violations": verification.violations},
            sandbox=sandbox_result.to_dict(), staged_path=str(staged),
            timings_s=timings, failure_context=failure_context)


def synthesize(examples: List[Any], heldout: List[Dict[str, Any]],
               failure_context: Optional[Dict[str, Any]] = None,
               stage_dir: Optional[Path] = None) -> SynthesisReport:
    """One-shot convenience wrapper around SynthesisPipeline."""
    return SynthesisPipeline().run(examples, heldout, failure_context, stage_dir)
