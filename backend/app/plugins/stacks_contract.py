"""Stacks (Clarity) Contract Recon.

Given a Stacks contract id - ``<principal>.<contract-name>``, e.g.
``SP213KNHB5QD308TEESY1ZMX1BP8EZDPG4JWD0MEA.fari-token-mn``, as the
scan target itself (optionally ``stacks:``-prefixed, or a Hiro
explorer address URL) - this pulls the contract READ-ONLY from the
keyless Hiro API (source code + ABI) and turns the Clarity code into
findings:

- the mint path: every public function that can reach ``ft-mint?``
  and the authorization guarding it - a hardcoded single-principal
  ``tx-sender``/``contract-caller`` check (centralized, baked into
  immutable code), a data-var owner (with or without a public
  rotation setter), or NO guard at all (anyone can mint).
- the mint cap: a MAX-supply constant only counts when the mint
  path actually compares ``ft-get-supply`` against it; a cap that
  is defined but never enforced is called out as such.
- an authority map: who can mint, pause, freeze/blacklist, burn,
  and whether any owner variable can be rotated - present AND
  absent-but-material powers, one summary finding.
- Clarity auth patterns: authorization keyed on ``tx-sender``
  instead of ``contract-caller``, ``as-contract`` authority inside
  public functions, and panic-style unwraps in public entry points.
- live state: when the contract exposes the SIP-010 read-only
  getters, they are called READ-ONLY (Hiro call-read) and decoded -
  current total supply vs the cap (percent minted) and vs any
  deploy-time top-level mint call found in the source.

Detection only. Never submits a transaction, never calls anything
that mutates state; the deepest access is the public Hiro contract
read and read-only function calls. Stacks contract code is
immutable once deployed, so every authority found here is exactly
as permanent as the code itself.

Prefixes: SP = mainnet single-sig, SM = mainnet multi-sig,
ST = testnet (testnet contracts are read from the Hiro testnet
API). Findings show code and values IN FULL, per Jay's order
(2026-10-29) - never masked.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .base import safe_json_dict

HIRO_MAINNET = "https://api.mainnet.hiro.so"
HIRO_TESTNET = "https://api.testnet.hiro.so"
EXPLORER_CONTRACT = "https://explorer.hiro.so/address/{cid}?chain={net}"

MAX_CONTRACTS = 3

# Contract id: principal (SP mainnet single-sig, SM mainnet
# multi-sig, ST testnet) + "." + contract name.
CONTRACT_ID_RE = re.compile(
    r"^(SP|SM|ST)[0-9A-Z]{20,}\.[A-Za-z0-9_-]+$")
_CID_SEARCH_RE = re.compile(
    r"(?<![0-9A-Za-z.])((?:SP|SM|ST)[0-9A-Z]{20,}\.[A-Za-z0-9_-]+)")

_PRINCIPAL_LITERAL_RE = re.compile(r"'(S[PTM][0-9A-Z]{20,})")
_UINT_LITERAL_RE = re.compile(r"^u(\d+)$")
_SECRET_HEX_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

# SIP-010-style read-only getters worth calling live.
_GETTER_MAP = {"get-total-supply": "total_supply",
               "get-decimals": "decimals",
               "get-name": "name",
               "get-symbol": "symbol"}

_REMEDIATION = {
    "stacks_mint_authority": (
        "Mint authority is the token's master key. Prefer no mint "
        "function at all, or authority held by a multisig/governance "
        "contract - a single hardcoded key holder can inflate the "
        "supply at will, and Clarity code cannot be patched after "
        "deploy."),
    "stacks_mint_cap": (
        "Enforce the cap inside the mint path itself (compare "
        "ft-get-supply + amount against the cap before ft-mint?) - "
        "a cap constant that is never checked does not bound "
        "anything."),
    "stacks_burn_authority": (
        "Burn functions must only ever burn the caller's own "
        "balance: require the burned-from principal to equal "
        "contract-caller (or tx-sender) before calling ft-burn?."),
    "stacks_pause_control": (
        "Pause switches stop every transfer while they are on. "
        "Confirm who holds this one and prefer multisig or "
        "governance control over a single key."),
    "stacks_freeze_blacklist_control": (
        "Freeze/blacklist powers let one authority strand user "
        "funds in place. Confirm the holder, and prefer time-locked "
        "or governance control - or no such power at all."),
    "stacks_owner_rotation": (
        "A publicly settable owner variable means whoever holds "
        "the current owner key can hand every power in this "
        "contract to a new principal. Guard the setter and prefer "
        "multisig ownership."),
    "stacks_tx_sender_auth": (
        "Key authorization on contract-caller, not tx-sender: "
        "tx-sender stays the original signer even when the call "
        "arrives through an intermediary contract, so a user "
        "tricked into routing through a malicious contract still "
        "passes tx-sender checks."),
    "stacks_as_contract": (
        "as-contract hands a function the contract's own "
        "principal - any funds or assets the contract holds are "
        "spendable from inside it. Audit every as-contract call "
        "site and what guards it."),
    "stacks_panic_surface": (
        "Panic-style unwraps (unwrap-panic / unwrap-err-panic / "
        "unwrap!) abort the whole transaction when hit. In public "
        "entry points, an attacker who can force the failing "
        "input can grief every call - prefer explicit err returns."),
    "stacks_secret_string": (
        "This secret sits in PUBLIC on-chain source - treat it as "
        "burned. Rotate it now and sweep anything it controls to "
        "fresh credentials generated offline."),
}


def _fd(key: str, severity: str, value: str,
        evidence: Dict[str, Any]) -> Dict[str, Any]:
    ev = dict(evidence)
    ev["severity"] = severity
    return {"key": key, "severity": severity, "value": value,
            "evidence": ev}


# ---------------------------------------------------------------------------
# Target parsing (pure)
# ---------------------------------------------------------------------------

def is_stacks_contract_id(s: str) -> bool:
    return bool(CONTRACT_ID_RE.match((s or "").strip()))


def parse_stacks_target(raw: str) -> Optional[str]:
    """Extract a Stacks contract id from a scan target, or None.

    Accepts a raw contract id, a ``stacks:<id>`` prefix, and Hiro
    explorer address URLs (``/address/<id>``).
    """
    s = (raw or "").strip()
    if not s:
        return None
    low = s.lower()
    if low.startswith("stacks:"):
        rest = s[len("stacks:"):].strip()
        return rest if is_stacks_contract_id(rest) else None
    if is_stacks_contract_id(s):
        return s
    if re.match(r"(?i)^https?://", s):
        try:
            urlparse(s)
        except Exception:
            return None
        m = _CID_SEARCH_RE.search(s)
        if m:
            return m.group(1)
    return None


def split_contract_id(cid: str) -> Tuple[str, str]:
    principal, _, name = cid.partition(".")
    return principal, name


def is_testnet_contract(cid: str) -> bool:
    principal, _ = split_contract_id(cid)
    return principal.startswith("ST")


# ---------------------------------------------------------------------------
# Clarity value decoding (pure)
# ---------------------------------------------------------------------------

def _decode_value(data: bytes, off: int) -> Tuple[Any, int]:
    """Decode one Clarity value at ``off``; returns (value, next).

    Serialization prefixes (Stacks Clarity codec): 0x00 int,
    0x01 uint, 0x02 buffer, 0x03/0x04 bool, 0x05 standard
    principal, 0x06 contract principal, 0x07 response-ok,
    0x08 response-err, 0x09 optional-none, 0x0a optional-some,
    0x0b list, 0x0c tuple, 0x0d string-ascii, 0x0e string-utf8.
    Responses decode to ("ok", v) / ("err", v) tuples.
    """
    if off >= len(data):
        raise ValueError("truncated Clarity value")
    t = data[off]
    off += 1
    if t == 0x00:
        return int.from_bytes(data[off:off + 16], "big",
                              signed=True), off + 16
    if t == 0x01:
        return int.from_bytes(data[off:off + 16], "big"), off + 16
    if t == 0x02:
        ln = int.from_bytes(data[off:off + 4], "big")
        return data[off + 4:off + 4 + ln].hex(), off + 4 + ln
    if t == 0x03:
        return True, off
    if t == 0x04:
        return False, off
    if t == 0x05:
        return ("principal", data[off:off + 21].hex()), off + 21
    if t == 0x06:
        name_len = data[off + 21]
        name = data[off + 22:off + 22 + name_len].decode(
            "ascii", "replace")
        return ("contract_principal", name), off + 22 + name_len
    if t == 0x07:
        v, nxt = _decode_value(data, off)
        return ("ok", v), nxt
    if t == 0x08:
        v, nxt = _decode_value(data, off)
        return ("err", v), nxt
    if t == 0x09:
        return None, off
    if t == 0x0a:
        return _decode_value(data, off)
    if t == 0x0b:
        count = int.from_bytes(data[off:off + 4], "big")
        off += 4
        out = []
        for _ in range(count):
            v, off = _decode_value(data, off)
            out.append(v)
        return out, off
    if t == 0x0c:
        count = int.from_bytes(data[off:off + 4], "big")
        off += 4
        out = {}
        for _ in range(count):
            klen = data[off]
            off += 1
            key = data[off:off + klen].decode("ascii", "replace")
            off += klen
            v, off = _decode_value(data, off)
            out[key] = v
        return out, off
    if t in (0x0d, 0x0e):
        ln = int.from_bytes(data[off:off + 4], "big")
        raw = data[off + 4:off + 4 + ln]
        return raw.decode("utf-8", "replace"), off + 4 + ln
    raise ValueError(f"unknown Clarity type prefix {t:#x}")


def decode_clarity_hex(hexstr: str) -> Any:
    """Decode a Hiro call-read ``result`` hex string, or None."""
    try:
        h = (hexstr or "").strip()
        if h.startswith(("0x", "0X")):
            h = h[2:]
        data = bytes.fromhex(h)
        if not data:
            return None
        value, _ = _decode_value(data, 0)
        return value
    except Exception:
        return None


def _unwrap_ok(value: Any) -> Any:
    """(ok v) -> v; anything else passes through unchanged."""
    if isinstance(value, tuple) and len(value) == 2 \
            and value[0] == "ok":
        return value[1]
    return value


# ---------------------------------------------------------------------------
# Clarity source parsing (pure)
# ---------------------------------------------------------------------------

def blank_comments(source: str) -> str:
    """Replace ``;;`` comment text with spaces (strings respected).

    Same length as the input, so offsets and line numbers computed
    on the blanked copy are valid on the original - detection runs
    on the blanked copy, evidence quotes the original.
    """
    out = list(source)
    i, n = 0, len(source)
    in_str = False
    while i < n:
        ch = source[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            i += 1
            continue
        if ch == ";" and i + 1 < n and source[i + 1] == ";":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
            continue
        i += 1
    return "".join(out)


class _Node:
    __slots__ = ("kind", "text", "children", "start", "end")

    def __init__(self, kind: str, text: str, start: int, end: int,
                 children: Optional[List["_Node"]] = None):
        self.kind = kind          # "atom" | "string" | "list"
        self.text = text          # atom text / raw string literal
        self.children = children or []
        self.start = start
        self.end = end


def _tokenize(blanked: str) -> List[Tuple[str, str, int, int]]:
    toks: List[Tuple[str, str, int, int]] = []
    i, n = 0, len(blanked)
    while i < n:
        ch = blanked[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            toks.append((ch, ch, i, i + 1))
            i += 1
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if blanked[j] == "\\":
                    j += 2
                    continue
                if blanked[j] == '"':
                    j += 1
                    break
                j += 1
            toks.append(("string", blanked[i:j], i, j))
            i = j
            continue
        j = i
        while j < n and not blanked[j].isspace() \
                and blanked[j] not in '()"':
            j += 1
        toks.append(("atom", blanked[i:j], i, j))
        i = j
    return toks


def parse_forms(blanked: str) -> List[_Node]:
    """Parse top-level s-expressions. Never raises: unbalanced
    input degrades to whatever parsed cleanly."""
    toks = _tokenize(blanked)
    root: List[_Node] = []
    stack: List[List[Any]] = [[root, 0]]  # (children, start offset)
    for kind, text, start, end in toks:
        if kind == "(":
            stack.append([[], start])
        elif kind == ")":
            if len(stack) > 1:
                children, st = stack.pop()
                stack[-1][0].append(
                    _Node("list", "", st, end, children))
        else:
            stack[-1][0].append(_Node(
                "string" if kind == "string" else "atom",
                text, start, end))
    while len(stack) > 1:  # unclosed lists: close at EOF
        children, st = stack.pop()
        stack[-1][0].append(
            _Node("list", "", st, len(blanked), children))
    return root


def _head(node: _Node) -> str:
    if node.kind == "list" and node.children \
            and node.children[0].kind == "atom":
        return node.children[0].text
    return node.text if node.kind == "atom" else ""


def _walk(node: _Node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _find_calls(node: _Node, callee: str) -> List[_Node]:
    return [n for n in _walk(node)
            if n.kind == "list" and _head(n) == callee]


_AUTH_EQ_RE = re.compile(
    r"\(\s*is-eq\s+(tx-sender|contract-caller)\s+"
    r"(?:'([SPTM][0-9A-Z]{20,})|\(var-get\s+([A-Za-z0-9_-]+)\s*\))"
    r"|\(\s*is-eq\s+(?:'([SPTM][0-9A-Z]{20,})|\(var-get\s+"
    r"([A-Za-z0-9_-]+)\s*\))\s+(tx-sender|contract-caller)\s*\)")


def find_auth_checks(text: str) -> List[Dict[str, str]]:
    """Authorization checks in a function body: (is-eq tx-sender X)
    or (is-eq contract-caller X) where X is a literal principal or
    a (var-get ...) - either argument order."""
    out: List[Dict[str, str]] = []
    for m in _AUTH_EQ_RE.finditer(text):
        if m.group(1):
            who, lit, var = m.group(1), m.group(2), m.group(3)
        else:
            who, lit, var = m.group(6), m.group(4), m.group(5)
        rec = {"who": who or ""}
        if lit:
            rec.update({"kind": "literal", "principal": lit})
        elif var:
            rec.update({"kind": "var", "var": var})
        else:
            continue
        out.append(rec)
    return out


class ClaritySource:
    """Indexed view of one contract's Clarity source."""

    def __init__(self, source: str):
        self.source = source
        self.blanked = blank_comments(source)
        self.forms = parse_forms(self.blanked)
        self.constants: Dict[str, Dict[str, Any]] = {}
        self.data_vars: Dict[str, Dict[str, Any]] = {}
        self.maps: Dict[str, Dict[str, Any]] = {}
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.ft_names: List[Tuple[str, Optional[int]]] = []
        self.traits: List[str] = []
        self.top_level_calls: List[_Node] = []
        self._index()

    # -- indexing ---------------------------------------------------
    def _index(self) -> None:
        for form in self.forms:
            if form.kind != "list":
                self.top_level_calls.append(form)
                continue
            head = _head(form)
            kids = form.children
            if head == "define-constant" and len(kids) >= 3 \
                    and kids[1].kind == "atom":
                name = kids[1].text
                expr = self.blanked[kids[2].start:kids[2].end]
                m = _UINT_LITERAL_RE.match(expr.strip())
                self.constants[name] = {
                    "expr": expr.strip(),
                    "int_value": int(m.group(1)) if m else None,
                    "node": form}
            elif head == "define-data-var" and len(kids) >= 3 \
                    and kids[1].kind == "atom":
                self.data_vars[kids[1].text] = {"node": form}
            elif head == "define-map" and len(kids) >= 2 \
                    and kids[1].kind == "atom":
                self.maps[kids[1].text] = {"node": form}
            elif head in ("define-fungible-token",
                          "define-non-fungible-token") \
                    and len(kids) >= 2 and kids[1].kind == "atom":
                max_supply = None
                if len(kids) >= 3 and kids[2].kind == "atom":
                    m = _UINT_LITERAL_RE.match(kids[2].text)
                    if m:
                        max_supply = int(m.group(1))
                if head == "define-fungible-token":
                    self.ft_names.append((kids[1].text, max_supply))
            elif head == "impl-trait" and len(kids) >= 2:
                self.traits.append(
                    self.blanked[kids[1].start:kids[1].end])
            elif head in ("define-public", "define-read-only",
                          "define-private") and len(kids) >= 2 \
                    and kids[1].kind == "list" \
                    and kids[1].children \
                    and kids[1].children[0].kind == "atom":
                name = kids[1].children[0].text
                self.functions[name] = {
                    "access": head.replace("define-", ""),
                    "node": form,
                    "text": self.blanked[form.start:form.end]}
            elif head and not head.startswith("define-"):
                self.top_level_calls.append(form)

    # -- helpers ------------------------------------------------------
    def line_of(self, offset: int) -> int:
        return self.source.count("\n", 0, offset) + 1

    def quote(self, node: _Node, max_lines: int = 6) -> str:
        """Original source lines spanned by a node (evidence)."""
        lines = self.source.splitlines()
        a = self.line_of(node.start)
        b = self.line_of(max(node.start, node.end - 1))
        picked = lines[a - 1:b][:max_lines]
        text = "\n".join(picked)
        if b - a + 1 > max_lines:
            text += "\n..."
        return text

    def call_graph(self) -> Dict[str, Set[str]]:
        graph: Dict[str, Set[str]] = {}
        for name, fn in self.functions.items():
            callees: Set[str] = set()
            for other in self.functions:
                if other != name and re.search(
                        r"\(\s*" + re.escape(other) + r"(?=[\s\)])",
                        fn["text"]):
                    callees.add(other)
            graph[name] = callees
        return graph

    def reachable(self, graph: Dict[str, Set[str]],
                  entries: Set[str]) -> Set[str]:
        seen: Set[str] = set()
        stack = list(entries)
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(graph.get(cur, ()))
        return seen

    def public_functions(self) -> Set[str]:
        return {n for n, f in self.functions.items()
                if f["access"] == "public"}

    def public_reachable(self) -> Set[str]:
        return self.reachable(self.call_graph(),
                              self.public_functions())

    def functions_with(self, needle: str,
                       within: Optional[Set[str]] = None) -> List[str]:
        out = []
        for name, fn in self.functions.items():
            if within is not None and name not in within:
                continue
            if needle in fn["text"]:
                out.append(name)
        return out

    def var_setters(self, var: str) -> Dict[str, List[str]]:
        """Functions writing a data-var, split by access."""
        out: Dict[str, List[str]] = {"public": [], "other": []}
        pat = re.compile(r"\(\s*var-set\s+" + re.escape(var) +
                         r"(?=[\s\)])")
        for name, fn in self.functions.items():
            if pat.search(fn["text"]):
                key = "public" if fn["access"] == "public" \
                    else "other"
                out[key].append(name)
        return out


# ---------------------------------------------------------------------------
# Source analysis (pure): detectors
# ---------------------------------------------------------------------------

def _cap_candidates(cs: ClaritySource) -> List[Dict[str, Any]]:
    """Supply-cap candidates: MAX/CAP/SUPPLY-named uint constants
    and an explicit define-fungible-token max supply."""
    out: List[Dict[str, Any]] = []
    for name, c in cs.constants.items():
        if c["int_value"] is not None and re.search(
                r"MAX|CAP|SUPPLY", name, re.I):
            out.append({"kind": "constant", "name": name,
                        "value": c["int_value"], "node": c["node"]})
    for ft_name, max_supply in cs.ft_names:
        if max_supply is not None:
            out.append({"kind": "ft-max", "name": ft_name,
                        "value": max_supply, "node": None})
    return out


def analyze_clarity_source(contract_id: str, source: str,
                           live: Optional[Dict[str, Any]] = None
                           ) -> List[Dict[str, Any]]:
    """All source detectors. ``live`` carries decoded SIP-010
    getter values (total_supply/decimals/name/symbol) when the
    live read worked, else None/{}. Returns finding dicts."""
    cs = ClaritySource(source)
    live = live or {}
    principal, _ = split_contract_id(contract_id)
    out: List[Dict[str, Any]] = []
    base = {"address": contract_id, "chain": "stacks",
            "deployer": principal}
    reach = cs.public_reachable()

    # ---- mint path ------------------------------------------------
    mint_sinks = cs.functions_with("ft-mint?", within=reach)
    mint_entries = sorted(
        n for n in cs.public_functions()
        if n in reach and (n in mint_sinks or cs.reachable(
            cs.call_graph(), {n}) & set(mint_sinks)))
    mint_path: Set[str] = set()
    if mint_entries:
        mint_path = cs.reachable(cs.call_graph(), set(mint_entries))
    caps = _cap_candidates(cs)
    cap = caps[0] if caps else None

    auth_checks: List[Dict[str, str]] = []
    for fn_name in sorted(mint_path):
        for chk in find_auth_checks(cs.functions[fn_name]["text"]):
            chk = dict(chk)
            chk["function"] = fn_name
            auth_checks.append(chk)
    literals = [c for c in auth_checks if c["kind"] == "literal"]
    var_checks = [c for c in auth_checks if c["kind"] == "var"]

    if mint_sinks and mint_entries:
        entry_list = ", ".join(mint_entries)
        if literals:
            holders = sorted({c["principal"] for c in literals})
            quote_fn = literals[0]["function"]
            out.append(_fd(
                "stacks_mint_authority", "high",
                f"HIGH: {contract_id}: minting is controlled by a "
                f"hardcoded principal check - public function(s) "
                f"{entry_list} reach ft-mint? only when the caller "
                f"is {', '.join(holders)}. That is a centralized, "
                f"single-principal mint authority baked into "
                f"immutable code: it cannot be rotated or revoked "
                f"without deploying a new contract, and whoever "
                f"holds that key can mint up to the cap at any "
                f"time.\n\nCode:\n"
                + cs.quote(cs.functions[quote_fn]["node"]),
                {**base, "mint_entries": mint_entries,
                 "mint_authority_principals": holders,
                 "auth_who": literals[0]["who"],
                 "rotatable": False,
                 "remediation":
                     _REMEDIATION["stacks_mint_authority"]}))
        elif var_checks:
            var = var_checks[0]["var"]
            setters = cs.var_setters(var)
            rotatable = bool(setters["public"])
            out.append(_fd(
                "stacks_mint_authority", "high",
                f"HIGH: {contract_id}: minting is gated on the "
                f"data-var '{var}' (public function(s) {entry_list} "
                f"reach ft-mint?). Mint authority sits with "
                f"whatever principal that variable holds. "
                + (f"The variable CAN be rotated: public "
                   f"function(s) {', '.join(setters['public'])} "
                   f"write it with var-set, so the current holder "
                   f"can hand minting to any new principal."
                   if rotatable else
                   "No public function writes that variable with "
                   "var-set, so the mint authority is fixed at its "
                   "deploy-time value.")
                + f"\n\nCode:\n"
                + cs.quote(cs.functions[var_checks[0]['function']]
                           ["node"]),
                {**base, "mint_entries": mint_entries,
                 "mint_authority_var": var, "rotatable": rotatable,
                 "var_public_setters": setters["public"],
                 "remediation":
                     _REMEDIATION["stacks_mint_authority"]}))
        else:
            sink_fn = mint_sinks[0]
            out.append(_fd(
                "stacks_mint_authority", "critical",
                f"CRITICAL: {contract_id}: UNGUARDED MINT - public "
                f"function(s) {entry_list} reach ft-mint? with NO "
                f"authorization check anywhere on the mint path "
                f"(no principal check, no owner variable). Any "
                f"account can mint new tokens to itself until "
                f"the cap (if any) is exhausted.\n\nCode:\n"
                + cs.quote(cs.functions[sink_fn]["node"]),
                {**base, "mint_entries": mint_entries,
                 "mint_authority_principals": [],
                 "rotatable": False,
                 "remediation":
                     _REMEDIATION["stacks_mint_authority"]}))

        # ---- cap --------------------------------------------------
        enforced = False
        enforce_fn = ""
        if cap is not None:
            for fn_name in sorted(mint_path):
                text = cs.functions[fn_name]["text"]
                if "ft-get-supply" in text and (
                        cap["kind"] == "ft-max"
                        or cap["name"] in text
                        or f"u{cap['value']}" in text):
                    enforced = True
                    enforce_fn = fn_name
                    break
        if cap is not None and enforced:
            out.append(_fd(
                "stacks_mint_cap", "medium",
                f"MEDIUM: {contract_id}: mint cap ENFORCED - "
                f"{cap['name']} = u{cap['value']} and the mint "
                f"path (function '{enforce_fn}') compares "
                f"ft-get-supply against it before minting. The "
                f"cap bounds the mint authority's worst case: "
                f"supply can never exceed u{cap['value']}."
                + (f"\n\nCode:\n" + cs.quote(cap["node"])
                   if cap["node"] is not None else ""),
                {**base, "cap": cap["value"], "cap_name": cap["name"],
                 "cap_enforced": True, "cap_function": enforce_fn,
                 "remediation": _REMEDIATION["stacks_mint_cap"]}))
        elif cap is not None:
            out.append(_fd(
                "stacks_mint_cap", "high",
                f"HIGH: {contract_id}: a supply cap is DEFINED "
                f"({cap['name']} = u{cap['value']}) but the mint "
                f"path never compares ft-get-supply against it - "
                f"the cap is decorative and does NOT bound "
                f"minting.\n\nCode:\n"
                + (cs.quote(cap["node"]) if cap["node"] is not None
                   else ""),
                {**base, "cap": cap["value"], "cap_name": cap["name"],
                 "cap_enforced": False,
                 "remediation": _REMEDIATION["stacks_mint_cap"]}))
        else:
            out.append(_fd(
                "stacks_mint_cap", "high",
                f"HIGH: {contract_id}: UNCAPPED MINT - the mint "
                f"path defines no MAX/CAP supply constant and no "
                f"ft-get-supply check, so minting is bounded by "
                f"nothing but the mint authority itself.",
                {**base, "cap": None, "cap_enforced": False,
                 "remediation": _REMEDIATION["stacks_mint_cap"]}))

    # ---- deploy-time mint + live supply state ----------------------
    deploy_mint: Optional[Dict[str, Any]] = None
    for form in cs.top_level_calls:
        head = _head(form)
        if head and (head in mint_entries or head == "mint") \
                and form.kind == "list" and len(form.children) >= 3:
            amount_node = form.children[1]
            m = _UINT_LITERAL_RE.match(amount_node.text) \
                if amount_node.kind == "atom" else None
            if m:
                recip = form.children[2]
                deploy_mint = {
                    "function": head, "amount": int(m.group(1)),
                    "recipient": recip.text.lstrip("'")
                    if recip.kind == "atom" else "",
                    "quote": cs.quote(form, max_lines=2)}
                break
    supply = live.get("total_supply")
    if supply is not None or deploy_mint is not None:
        bits = []
        ev = dict(base)
        if deploy_mint is not None:
            bits.append(
                f"deploy-time mint: {deploy_mint['function']} "
                f"minted u{deploy_mint['amount']} to "
                f"{deploy_mint['recipient']} in a top-level call "
                f"when the contract deployed")
            ev["deploy_mint_amount"] = deploy_mint["amount"]
            ev["deploy_mint_recipient"] = deploy_mint["recipient"]
            if cap is not None and cap["value"]:
                pct = deploy_mint["amount"] * 100.0 / cap["value"]
                bits.append(
                    f"that is {pct:.2f}% of the u{cap['value']} cap")
                ev["deploy_mint_pct_of_cap"] = round(pct, 4)
        if isinstance(supply, int):
            bits.append(f"current total supply (live read): "
                        f"u{supply}")
            ev["total_supply"] = supply
            if cap is not None and cap["value"]:
                pct = supply * 100.0 / cap["value"]
                bits.append(f"{pct:.2f}% of the cap is minted")
                ev["supply_pct_of_cap"] = round(pct, 4)
            if deploy_mint is not None:
                since = supply - deploy_mint["amount"]
                bits.append(
                    f"u{since} minted since deploy"
                    if since >= 0 else
                    f"live supply is u{-since} BELOW the "
                    f"deploy-time mint (burns or a second token "
                    f"definition in play)")
                ev["minted_since_deploy"] = since
        out.append(_fd(
            "stacks_supply_state", "low",
            f"LOW: {contract_id}: supply state - " +
            "; ".join(bits) + "."
            + (f"\n\nCode:\n{deploy_mint['quote']}"
               if deploy_mint is not None else ""),
            {**ev, "remediation": "Supply state is public chain "
                                  "data; compare it against the "
                                  "project's published distribution "
                                  "schedule."}))

    # ---- burn -------------------------------------------------------
    burn_risk: List[Dict[str, Any]] = []
    burn_any = False
    for fn_name in cs.functions_with("ft-burn?", within=reach):
        burn_any = True
        fn = cs.functions[fn_name]
        if fn["access"] != "public":
            continue
        for call in _find_calls(fn["node"], "ft-burn?"):
            if len(call.children) < 4:
                continue
            sender_node = call.children[3]
            sender = sender_node.text \
                if sender_node.kind == "atom" else ""
            if sender in ("tx-sender", "contract-caller"):
                continue
            text = fn["text"]
            tied = re.search(
                r"\(\s*is-eq\s+(tx-sender|contract-caller)\s+" +
                re.escape(sender) + r"(?=[\s\)])", text) or \
                re.search(r"\(\s*is-eq\s+" + re.escape(sender) +
                          r"\s+(tx-sender|contract-caller)(?=[\s\)])",
                          text)
            if not tied:
                burn_risk.append({"function": fn_name,
                                  "sender_arg": sender,
                                  "quote": cs.quote(call)})
    for risk in burn_risk:
        out.append(_fd(
            "stacks_burn_authority", "high",
            f"HIGH: {contract_id}: public function "
            f"'{risk['function']}' calls ft-burn? on an arbitrary "
            f"principal argument ('{risk['sender_arg']}') with no "
            f"check tying it to the caller - anyone can burn "
            f"tokens out of any holder's balance.\n\nCode:\n"
            f"{risk['quote']}",
            {**base, "burn_function": risk["function"],
             "remediation": _REMEDIATION["stacks_burn_authority"]}))

    # ---- pause / freeze / blacklist ---------------------------------
    def _controls(keyword_res: List[str]) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        names = [n for n in list(cs.data_vars) + list(cs.maps)
                 if any(re.search(k, n, re.I) for k in keyword_res)]
        for name in names:
            writers = []
            write_re = re.compile(
                r"\(\s*(?:var-set|map-set|map-insert|map-delete)\s+"
                + re.escape(name) + r"(?=[\s\)])")
            for fn_name in sorted(reach):
                if write_re.search(cs.functions[fn_name]["text"]):
                    writers.append(fn_name)
            public_writers = [w for w in writers
                              if cs.functions[w]["access"]
                              == "public"]
            if public_writers:
                hits.append({"mechanism": name,
                             "writers": public_writers})
        return hits

    pause_hits = _controls([r"paus"])
    freeze_hits = _controls(
        [r"freez", r"frozen", r"blacklist", r"blocklist", r"ban"])
    for hit in pause_hits:
        out.append(_fd(
            "stacks_pause_control", "medium",
            f"MEDIUM: {contract_id}: a pause switch exists - "
            f"'{hit['mechanism']}' is written by public "
            f"function(s) {', '.join(hit['writers'])}. While "
            f"paused, transfers controlled by that flag stop "
            f"moving; whoever can call those functions holds "
            f"an on/off switch over the token.",
            {**base, "mechanism": hit["mechanism"],
             "writer_functions": hit["writers"],
             "remediation": _REMEDIATION["stacks_pause_control"]}))
    for hit in freeze_hits:
        out.append(_fd(
            "stacks_freeze_blacklist_control", "high",
            f"HIGH: {contract_id}: a freeze/blacklist mechanism "
            f"exists - '{hit['mechanism']}' is written by public "
            f"function(s) {', '.join(hit['writers'])}. The "
            f"authority behind those functions can freeze or "
            f"blocklist holder balances in place.",
            {**base, "mechanism": hit["mechanism"],
             "writer_functions": hit["writers"],
             "remediation":
                 _REMEDIATION["stacks_freeze_blacklist_control"]}))

    # ---- owner rotation ----------------------------------------------
    owner_vars = [n for n in cs.data_vars
                  if re.search(r"owner|admin|governor", n, re.I)]
    rotation_notes: List[str] = []
    for var in owner_vars:
        setters = cs.var_setters(var)
        if setters["public"]:
            rotation_notes.append(
                f"'{var}' can be rotated by public function(s) "
                f"{', '.join(setters['public'])}")
            out.append(_fd(
                "stacks_owner_rotation", "medium",
                f"MEDIUM: {contract_id}: owner variable '{var}' "
                f"has a PUBLIC rotation path - function(s) "
                f"{', '.join(setters['public'])} write it with "
                f"var-set. Whoever holds the current authority "
                f"can transfer every power keyed on '{var}' to a "
                f"new principal at any time.",
                {**base, "owner_var": var,
                 "setter_functions": setters["public"],
                 "remediation":
                     _REMEDIATION["stacks_owner_rotation"]}))
        else:
            rotation_notes.append(
                f"'{var}' has no public var-set path (fixed at "
                f"deploy)")

    # ---- tx-sender auth pattern ---------------------------------------
    tx_sender_fns: List[Tuple[str, str]] = []
    for fn_name in sorted(cs.public_functions()):
        fn = cs.functions[fn_name]
        m = re.search(r"\(\s*is-eq\s+tx-sender\s+[^\s\)]+|"
                      r"\(\s*is-eq\s+[^\s\(\)]+\s+tx-sender\s*\)",
                      fn["text"])
        if m:
            line_no = cs.line_of(fn["node"].start +
                                 fn["text"].find("tx-sender"))
            lines = cs.source.splitlines()
            quote_line = lines[line_no - 1].strip() \
                if 0 < line_no <= len(lines) else ""
            tx_sender_fns.append((fn_name, quote_line))
    if tx_sender_fns:
        names = ", ".join(n for n, _ in tx_sender_fns)
        quotes = "\n".join(q for _, q in tx_sender_fns[:4] if q)
        out.append(_fd(
            "stacks_tx_sender_auth", "medium",
            f"MEDIUM: {contract_id}: authorization keyed on "
            f"tx-sender in public function(s) {names} - "
            f"contract-caller is the safer check: tx-sender is "
            f"the original transaction signer, so these checks "
            f"still pass when the call arrives through an "
            f"intermediary contract the signer was tricked into "
            f"using.\n\nCode:\n{quotes}",
            {**base, "functions": [n for n, _ in tx_sender_fns],
             "remediation": _REMEDIATION["stacks_tx_sender_auth"]}))

    # ---- as-contract + panic surface -----------------------------------
    as_contract_fns = [n for n in sorted(cs.public_functions())
                       if "(as-contract" in cs.functions[n]["text"]]
    if as_contract_fns:
        out.append(_fd(
            "stacks_as_contract", "low",
            f"LOW: {contract_id}: as-contract used in public "
            f"function(s) {', '.join(as_contract_fns)} - inside "
            f"those calls the function acts as the contract "
            f"itself, so any assets the contract holds are in "
            f"reach of that code path.",
            {**base, "functions": as_contract_fns,
             "remediation": _REMEDIATION["stacks_as_contract"]}))
    panic_fns = [n for n in sorted(cs.public_functions())
                 if re.search(r"unwrap-panic|unwrap-err-panic|"
                              r"\(\s*unwrap!",
                              cs.functions[n]["text"])]
    if panic_fns:
        out.append(_fd(
            "stacks_panic_surface", "low",
            f"LOW: {contract_id}: panic-style unwraps "
            f"(unwrap!/unwrap-panic/unwrap-err-panic) inside "
            f"public function(s) {', '.join(panic_fns)} - a "
            f"hit aborts the whole transaction, a griefing "
            f"surface if an attacker can force the failing "
            f"input.",
            {**base, "functions": panic_fns,
             "remediation": _REMEDIATION["stacks_panic_surface"]}))

    # ---- embedded secrets ------------------------------------------------
    seen_secrets: Set[str] = set()
    for m in _SECRET_HEX_RE.finditer(cs.blanked):
        value = m.group(0)
        if value in seen_secrets or set(value.lower()) <= {"0"}:
            continue
        seen_secrets.add(value)
        out.append(_fd(
            "stacks_secret_string", "high",
            f"HIGH: {contract_id}: a 64-hex-character string "
            f"that looks like a private key sits in the "
            f"published source, shown IN FULL: {value}",
            {**base, "secret_kind": "hex_64", "secret_value": value,
             "remediation": _REMEDIATION["stacks_secret_string"]}))

    # ---- authority map summary -------------------------------------------
    lines = [f"Authority map for {contract_id}:"]
    if mint_entries and literals:
        lines.append(
            f"- mint: hardcoded principal(s) "
            f"{', '.join(sorted({c['principal'] for c in literals}))} "
            f"via public function(s) {', '.join(mint_entries)}; "
            f"not rotatable (immutable code)")
    elif mint_entries and var_checks:
        lines.append(
            f"- mint: data-var '{var_checks[0]['var']}' holder via "
            f"public function(s) {', '.join(mint_entries)}"
            + ("; rotatable through a public setter"
               if cs.var_setters(var_checks[0]['var'])["public"]
               else "; no public rotation path"))
    elif mint_entries:
        lines.append(
            f"- mint: UNGUARDED, public function(s) "
            f"{', '.join(mint_entries)}")
    elif mint_sinks:
        lines.append(
            "- mint: ft-mint? exists in code but no public "
            "function reaches it (dead at runtime)")
    else:
        lines.append(
            "- mint: NO mint function - supply is fixed at "
            "whatever was minted at deploy")
    if cap is not None:
        lines.append(
            f"- mint cap: u{cap['value']} ({cap['name']})"
            + (" - enforced in the mint path"
               if mint_entries and any(
                   "ft-get-supply" in cs.functions[f]["text"]
                   and (cap["kind"] == "ft-max"
                        or cap["name"] in cs.functions[f]["text"])
                   for f in mint_path)
               else " - NOT enforced in the mint path"))
    else:
        lines.append("- mint cap: none defined")
    lines.append(
        "- burn: public function(s) can burn arbitrary holders' "
        "balances (see HIGH finding)" if burn_risk else
        "- burn: holder-only (ft-burn? tied to the caller)"
        if burn_any else
        "- burn: no burn function - balances can never be "
        "destroyed through this contract")
    lines.append(
        f"- pause: present ({', '.join(h['mechanism'] for h in pause_hits)})"
        if pause_hits else "- pause: none")
    lines.append(
        f"- freeze/blacklist: present "
        f"({', '.join(h['mechanism'] for h in freeze_hits)})"
        if freeze_hits else "- freeze/blacklist: none")
    if owner_vars:
        lines.append("- owner variable(s): " +
                     "; ".join(rotation_notes))
    else:
        lines.append(
            "- owner variable: none - authority is whatever "
            "literal checks the code carries")
    lines.append(
        "- code upgrade: impossible - Stacks contracts are "
        "immutable once deployed; every authority above is "
        "permanent")
    out.append(_fd(
        "stacks_authority_map", "low", "\n".join(lines),
        {**base,
         "mint_entries": mint_entries,
         "has_mint": bool(mint_sinks),
         "has_burn": burn_any,
         "has_pause": bool(pause_hits),
         "has_freeze_blacklist": bool(freeze_hits),
         "owner_vars": owner_vars,
         "remediation": "This map is the contract's trust "
                        "surface. Every power listed here is "
                        "permanent - verify each holder before "
                        "trusting the token."}))
    return out


def source_getter_values(cs: ClaritySource) -> Dict[str, Any]:
    """SIP-010 getter values readable straight from source:
    (ok "Name") / (ok u8) / (ok SOME-CONST) in the read-only
    getter bodies - the fallback when live call-read fails."""
    out: Dict[str, Any] = {}
    for fn_name, key in (("get-name", "name"),
                         ("get-symbol", "symbol")):
        fn = cs.functions.get(fn_name)
        if not fn:
            continue
        m = re.search(r'\(\s*ok\s+"((?:[^"\\]|\\.)*)"\s*\)',
                      fn["text"])
        if m:
            out[key] = m.group(1)
    fn = cs.functions.get("get-decimals")
    if fn:
        m = re.search(r"\(\s*ok\s+u(\d+)\s*\)", fn["text"])
        if m:
            out["decimals"] = int(m.group(1))
        else:
            m = re.search(r"\(\s*ok\s+([A-Za-z0-9_-]+)\s*\)",
                          fn["text"])
            if m and m.group(1) in cs.constants:
                val = cs.constants[m.group(1)]["int_value"]
                if val is not None:
                    out["decimals"] = val
    return out


# ---------------------------------------------------------------------------
# Hiro API access (read-only; 429 -> one backoff retry, then report)
# ---------------------------------------------------------------------------

async def _hiro_request(ctx: Ctx, method: str, url: str,
                        json_body: Optional[Dict[str, Any]] = None
                        ) -> Tuple[str, Optional[Dict[str, Any]]]:
    """One Hiro API read. Returns (status, data) with status in
    ok | rate_limited | not_found | unreachable. On 429 it backs
    off ONCE and retries; a second 429 reports rate_limited -
    never hammers."""
    for attempt in (0, 1):
        try:
            r = await fetch(ctx.http, ctx.limiter, method, url,
                            json=json_body, timeout=20,
                            max_retries=0)
        except Exception:
            return "unreachable", None
        if r.status_code == 429:
            if attempt == 0:
                await asyncio.sleep(2.0)
                continue
            return "rate_limited", None
        if r.status_code == 404:
            return "not_found", None
        if r.status_code != 200:
            return "unreachable", None
        return "ok", safe_json_dict(r)
    return "unreachable", None


async def fetch_contract(ctx: Ctx, base: str, contract_id: str
                         ) -> Tuple[str, Optional[Dict[str, Any]]]:
    """GET /extended/v1/contract/{id}: source_code + abi."""
    return await _hiro_request(
        ctx, "GET", f"{base}/extended/v1/contract/{contract_id}")


async def call_read(ctx: Ctx, base: str, contract_id: str,
                    function: str) -> Any:
    """POST /v2/contracts/call-read for a no-arg read-only
    function; returns the decoded Clarity value or None."""
    principal, name = split_contract_id(contract_id)
    url = (f"{base}/v2/contracts/call-read/{principal}/{name}/"
           f"{function}")
    status, data = await _hiro_request(
        ctx, "POST", url,
        json_body={"sender": principal, "arguments": []})
    if status != "ok" or not data or not data.get("okay"):
        return None
    result = data.get("result")
    if not isinstance(result, str):
        return None
    return decode_clarity_hex(result)


async def fetch_token_state(ctx: Ctx, base: str, contract_id: str,
                            getter_names: Set[str]
                            ) -> Dict[str, Any]:
    """Live SIP-010 state: call-read each getter the contract
    actually defines (subset of get-total-supply / get-decimals /
    get-name / get-symbol) and decode the results."""
    out: Dict[str, Any] = {}
    for fn_name, key in _GETTER_MAP.items():
        if fn_name not in getter_names:
            continue
        value = _unwrap_ok(await call_read(ctx, base, contract_id,
                                           fn_name))
        if value is None:
            continue
        if key in ("total_supply", "decimals") \
                and isinstance(value, int) \
                and not isinstance(value, bool):
            out[key] = value
        elif key in ("name", "symbol") and isinstance(value, str):
            out[key] = value
    return out


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class StacksContractPlugin(Plugin):
    id = "stacks_contract"
    label = "Stacks Contract Recon"
    accepts = ["stacks_contract", "crypto_wallet", "url", "domain"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []  # keyless: public Hiro API
    description = ("Reads Stacks (Clarity) contracts from the "
                   "keyless Hiro API: mint authority (hardcoded "
                   "principal vs data-var owner vs unguarded), "
                   "mint cap enforced or decorative, burn / pause "
                   "/ freeze / blacklist powers, owner rotation, "
                   "tx-sender auth patterns, and live SIP-010 "
                   "supply state vs the cap. Read-only, never "
                   "submits a transaction.")
    phase = 2  # also consumes contract ids discovered by miners
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        work = self._collect(target, ctx)
        if not work:
            res = self._skipped(
                "no Stacks contract id to recon: scan a contract "
                "id like SP...<name> (optionally stacks:-prefixed) "
                "or a Hiro explorer contract URL")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        reconned = 0
        for contract_id in work:
            try:
                done = await self._recon_contract(
                    ctx, contract_id, findings)
            except Exception:
                done = False
                findings.append(self._f(
                    "web3", "stacks_recon_failed",
                    f"MEDIUM: {contract_id}: Stacks recon failed "
                    "- contract data could not be retrieved (Hiro "
                    "API unreachable). No conclusion drawn.",
                    source="Hiro Stacks API",
                    confidence=60, passive=True,
                    evidence={"severity": "medium",
                              "address": contract_id,
                              "chain": "stacks",
                              "remediation": "Retry the scan; if "
                                             "the Hiro API stays "
                                             "down, read the "
                                             "contract on the "
                                             "Hiro explorer "
                                             "manually."}))
            if done:
                reconned += 1

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"reconned {reconned} Stacks "
                                 f"contract(s), {len(findings)} "
                                 f"findings")
        res.duration_ms = dur
        return res

    # -- target collection --------------------------------------------
    def _collect(self, target: Target, ctx: Ctx) -> List[str]:
        out: List[str] = []
        seen: Set[str] = set()

        def add(raw: Any) -> None:
            cid = parse_stacks_target(str(raw or ""))
            if cid and cid not in seen:
                seen.add(cid)
                out.append(cid)

        for raw in (target.normalized, target.raw):
            add(raw)
        for kind in ("stacks_contracts", "contract_addresses",
                     "crypto_addresses"):
            for item in ctx.consume(kind):
                add(item if isinstance(item, str)
                    else str((item or {}).get("address", "")))
        return out[:MAX_CONTRACTS]

    # -- per-contract recon ---------------------------------------------
    async def _recon_contract(self, ctx: Ctx, contract_id: str,
                              findings: List[Finding]) -> bool:
        testnet = is_testnet_contract(contract_id)
        base = HIRO_TESTNET if testnet else HIRO_MAINNET
        net = "testnet" if testnet else "mainnet"
        url = EXPLORER_CONTRACT.format(cid=contract_id, net=net)
        status, data = await fetch_contract(ctx, base, contract_id)
        if status == "rate_limited":
            findings.append(self._f(
                "web3", "stacks_recon_rate_limited",
                f"MEDIUM: {contract_id}: the Hiro API rate-"
                "limited the read (429 twice, after one backoff "
                "retry), so no contract data was retrieved. No "
                "conclusion drawn.",
                source="Hiro Stacks API", source_url=url,
                confidence=70, passive=True,
                evidence={"severity": "medium",
                          "address": contract_id, "chain": "stacks",
                          "remediation": "Retry later; the keyless "
                                         "Hiro API is rate "
                                         "limited per IP."}))
            return False
        if status == "not_found":
            findings.append(self._f(
                "web3", "stacks_contract_not_found",
                f"MEDIUM: {contract_id}: no contract exists on "
                f"Stacks {net} under this id - it was never "
                "deployed there, or the id is misspelled.",
                source="Hiro Stacks API", source_url=url,
                confidence=90, passive=True,
                evidence={"severity": "medium",
                          "address": contract_id, "chain": "stacks",
                          "network": net,
                          "remediation": "Confirm the contract id "
                                         "and network; SP/SM ids "
                                         "are mainnet, ST ids are "
                                         "testnet."}))
            return False
        if status != "ok" or not data:
            findings.append(self._f(
                "web3", "stacks_recon_failed",
                f"MEDIUM: {contract_id}: the Hiro API did not "
                "answer, so no contract data could be retrieved. "
                "No conclusion drawn.",
                source="Hiro Stacks API", source_url=url,
                confidence=60, passive=True,
                evidence={"severity": "medium",
                          "address": contract_id, "chain": "stacks",
                          "remediation": "Retry later; the Hiro "
                                         "API was unreachable."}))
            return False

        ctx.publish("stacks_contracts", contract_id)
        source = data.get("source_code") or ""
        principal, name = split_contract_id(contract_id)
        if not source:
            findings.append(self._f(
                "web3", "stacks_source_unavailable",
                f"MEDIUM: {contract_id}: the Hiro API returned "
                "no Clarity source for this contract, so the code "
                "cannot be audited. Treat it as unauditable until "
                "its source can be read.",
                source="Hiro Stacks API", source_url=url,
                confidence=85, passive=True,
                evidence={"severity": "medium",
                          "address": contract_id, "chain": "stacks",
                          "remediation": "Read the contract on "
                                         "the Hiro explorer; if "
                                         "source stays unavailable, "
                                         "do not trust it."}))
            return True

        cs = ClaritySource(source)
        getter_names = {n for n, f in cs.functions.items()
                        if f["access"] == "read-only"
                        and n in _GETTER_MAP}
        live = await fetch_token_state(ctx, base, contract_id,
                                       getter_names)
        if not live:
            live = source_getter_values(cs)
        else:
            for k, v in source_getter_values(cs).items():
                live.setdefault(k, v)

        findings.append(self._identity_finding(
            contract_id, data, cs, live, url, net))
        for fd in analyze_clarity_source(contract_id, source, live):
            findings.append(self._to_finding(fd, url))
        return True

    def _identity_finding(self, contract_id: str,
                          data: Dict[str, Any], cs: ClaritySource,
                          live: Dict[str, Any], url: str,
                          net: str) -> Finding:
        principal, name = split_contract_id(contract_id)
        bits = [f"contract {name}", f"deployer {principal}",
                f"Stacks {net}"]
        if data.get("clarity_version") is not None:
            bits.append(f"Clarity version {data['clarity_version']}")
        if data.get("block_height") is not None:
            bits.append(f"deployed at block {data['block_height']}")
        sip010 = any("sip-010" in t.lower() for t in cs.traits)
        if live.get("name"):
            bits.append(f"token name \"{live['name']}\"")
        if live.get("symbol"):
            bits.append(f"symbol {live['symbol']}")
        if live.get("decimals") is not None:
            bits.append(f"decimals {live['decimals']}")
        if isinstance(live.get("total_supply"), int):
            bits.append(f"total supply u{live['total_supply']}")
        if cs.ft_names:
            bits.append("fungible token(s): " +
                        ", ".join(n for n, _ in cs.ft_names))
        value = (f"LOW: {contract_id}: " + "; ".join(bits) + "."
                 + (" Implements the SIP-010 fungible-token "
                    "trait." if sip010 else ""))
        ev = {"severity": "low", "address": contract_id,
              "chain": "stacks", "network": net,
              "deployer": principal, "contract_name": name,
              "clarity_version": data.get("clarity_version"),
              "block_height": data.get("block_height"),
              "tx_id": data.get("tx_id"),
              "sip_010": sip010,
              "token_name": live.get("name"),
              "token_symbol": live.get("symbol"),
              "token_decimals": live.get("decimals"),
              "total_supply": live.get("total_supply"),
              "remediation": "Identity is public chain data; the "
                             "authority findings below say who "
                             "can do what with this token."}
        return self._f("web3", "stacks_contract_identity", value,
                       source="Hiro Stacks API (read-only)",
                       source_url=url, confidence=95, passive=True,
                       evidence=ev)

    def _to_finding(self, fd: Dict[str, Any],
                    url: Optional[str]) -> Finding:
        return self._f(
            "web3", fd["key"], fd["value"],
            source="Hiro Stacks API (read-only)",
            source_url=url, confidence=90, passive=True,
            evidence=fd["evidence"])
