"""Immutable & Constructor-Argument Extractor (Cat-1 #29, SHIP).

No existing plugin extracts deployed immutable values or decodes
constructor arguments. Given runtime bytecode plus, when available,
solc immutableReferences (offset/length per variable) and the
constructor ABI, this decodes:

- each immutable variable's value straight out of the deployed
  runtime code at its reference offsets;
- the constructor arguments appended to the creation bytecode
  (creation code minus the runtime code prefix), decoded against
  the constructor ABI (address / uint / int / bool / bytes32 /
  string).

Keyless: inputs come from the discovery bus / local artifacts, or
eth_getCode + verified source via the shared keyless route.
Extraction output is informational (low) unless an immutable holds
a privileged role address (owner/admin), which is medium.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_PRIV_NAMES = ("owner", "admin", "governor", "operator", "controller")


def _decode_word(raw: bytes, typ: str) -> Any:
    if not raw:
        return None
    if typ == "address":
        return "0x" + raw[-20:].hex()
    if typ.startswith("uint"):
        return int.from_bytes(raw, "big")
    if typ.startswith("int"):
        v = int.from_bytes(raw, "big")
        bits = len(raw) * 8
        return v - (1 << bits) if v >= (1 << (bits - 1)) else v
    if typ == "bool":
        return raw[-1] != 0
    if typ.startswith("bytes"):
        return "0x" + raw.hex()
    return "0x" + raw.hex()


def _decode_args(arg_bytes: bytes, types: List[str]) -> List[Any]:
    out: List[Any] = []
    head = 0
    for typ in types:
        word = arg_bytes[head:head + 32]
        if typ == "string":
            try:
                off = int.from_bytes(word, "big")
                ln = int.from_bytes(arg_bytes[off:off + 32], "big")
                out.append(arg_bytes[off + 32:off + 32 + ln]
                           .decode("utf-8", "replace"))
            except Exception:
                out.append(None)
        elif typ.startswith("bytes") and typ == "bytes":
            try:
                off = int.from_bytes(word, "big")
                ln = int.from_bytes(arg_bytes[off:off + 32], "big")
                out.append("0x" + arg_bytes[off + 32:off + 32 + ln].hex())
            except Exception:
                out.append(None)
        else:
            out.append(_decode_word(word, typ))
        head += 32
    return out


def extract_immutables(runtime_code: str = "",
                       immutable_refs: Optional[List[Dict[str, Any]]] = None,
                       creation_code: str = "",
                       constructor_types: Optional[List[str]] = None,
                       arg_hex: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    code = C.code_bytes(runtime_code)
    for ref in immutable_refs or []:
        try:
            off = int(ref.get("offset", 0))
            ln = int(ref.get("length", 32))
            name = str(ref.get("name") or ref.get("id") or "immutable")
            typ = str(ref.get("type") or "bytes32")
        except Exception:
            continue
        raw = code[off:off + ln]
        if not raw:
            continue
        val = _decode_word(raw.rjust(32, b"\x00")[-32:]
                           if typ != "address" else raw, typ) \
            if typ != "address" else "0x" + raw[-20:].hex()
        sev = "medium" if any(p in name.lower() for p in _PRIV_NAMES) \
            else "low"
        hits.append(C.hit(
            "immutable_value_extracted",
            f"immutable {name} ({typ}) at runtime offset {off} = "
            f"{val}; this value is baked into the deployed code "
            f"and can never be changed.",
            sev,
            "Review baked-in immutables: a privileged or wrong "
            "value here can only be fixed by redeploying.",
            variable=name, var_type=typ, offset=off, decoded_value=str(val),
            check="immutable_extract"))
    args_blob = b""
    if arg_hex:
        args_blob = C.code_bytes(arg_hex)
    elif creation_code and runtime_code:
        creation = C.code_bytes(creation_code)
        if len(creation) > len(code) and creation[:len(code)] != code:
            # appended args follow the init code; the runtime code
            # length marks where they start in the common layout
            args_blob = creation[len(creation) - (len(creation) - len(code)):] \
                if False else b""
        if creation.startswith(code) and len(creation) > len(code):
            args_blob = creation[len(code):]
    if args_blob and constructor_types:
        vals = _decode_args(args_blob, list(constructor_types))
        for i, (typ, val) in enumerate(zip(constructor_types, vals)):
            hits.append(C.hit(
                "constructor_arg_decoded",
                f"constructor argument #{i} ({typ}) = {val} "
                f"(decoded from appended creation-code arguments).",
                "low",
                "Check constructor arguments against the intended "
                "deployment parameters.",
                index=i, var_type=typ, decoded_value=str(val),
                check="constructor_args"))
    return hits


def _first_dicts(data: Dict[str, Any], kind: str) -> List[Dict[str, Any]]:
    return [x for x in data["extras"].get(kind, []) if isinstance(x, dict)]


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    for d in _first_dicts(data, "immutable_refs"):
        if isinstance(d.get("refs"), list):
            refs.extend(d["refs"])
        else:
            refs.append(d)
    types: List[str] = []
    arg_hex = ""
    for d in _first_dicts(data, "constructor_abi"):
        types = [str(t) for t in d.get("types", [])]
    for d in _first_dicts(data, "constructor_args"):
        arg_hex = str(d.get("args_hex") or d.get("hex") or "")
        if d.get("types"):
            types = [str(t) for t in d["types"]]
        if d.get("creation_code"):
            return extract_immutables(
                data.get("bytecode", ""), refs,
                creation_code=str(d["creation_code"]),
                constructor_types=types, arg_hex=arg_hex)
    abi = data.get("abi")
    if isinstance(abi, list) and not types:
        for entry in abi:
            if isinstance(entry, dict) and entry.get("type") == "constructor":
                types = [str(i.get("type", "bytes32"))
                         for i in entry.get("inputs", [])]
    return extract_immutables(data.get("bytecode", ""), refs,
                              constructor_types=types, arg_hex=arg_hex)


class ImmutableArgExtractorPlugin(Plugin):
    id = "immutable_arg_extractor"
    label = "Immutable & Constructor Argument Extractor"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Decodes constructor arguments appended to "
                   "creation bytecode and extracts immutable "
                   "variable values from deployed runtime code "
                   "using solc immutableReferences when supplied.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze,
            extras=("immutable_refs", "constructor_args",
                    "constructor_abi"),
            fetch=True,
            no_input="no bytecode / immutable references / "
                     "constructor data to extract from")
