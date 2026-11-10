"""Read-only RPC / signer hardblock.

ReconAnything is a detection tool: it reads chain state, it never writes it.
This module makes that an enforced invariant instead of a convention. Every
JSON-RPC call funnels through `assert_read_only(method)`, which refuses any
state-changing or transaction-broadcasting method at the transport layer, so
no plugin - present or future, well-meaning or not - can broadcast to a live
chain even if it tries.

It also refuses to run with real signing material in the environment
(`enforce_read_only_env`): a read-only tool has no business holding a private
key or seed phrase, and their presence is treated as a misconfiguration to
fail on, not to use.

Nothing here changes what any detector finds. It only forecloses the write
path entirely.
"""
from __future__ import annotations

import os
import re
from typing import Any, Iterable, List, Optional


class RpcWriteBlocked(RuntimeError):
    """Raised when a state-changing / broadcasting RPC method is attempted."""


# Explicit broadcast / signing methods across EVM, Solana and common nodes.
# Compared case-insensitively against the method name.
BLOCKED_METHODS = frozenset({
    # EVM broadcast + signing
    "eth_sendrawtransaction",
    "eth_sendtransaction",
    "eth_signtransaction",
    "eth_sign",
    "eth_signtypeddata",
    "eth_signtypeddata_v3",
    "eth_signtypeddata_v4",
    # go-ethereum / parity personal namespace (key custody + broadcast)
    "personal_sign",
    "personal_signtransaction",
    "personal_sendtransaction",
    "personal_unlockaccount",
    "personal_importrawkey",
    "personal_newaccount",
    # Solana / SVM broadcast  (note: simulateTransaction is read-only -> allowed)
    "sendtransaction",
    "requestairdrop",
    # account/key mutation seen on various nodes
    "parity_signtransaction",
    "parity_composetransaction",
})

# Any method whose name matches one of these is also refused, so a renamed or
# namespaced broadcast method (e.g. "xyz_sendRawTransaction") can't slip past
# the explicit set above.
_BLOCKED_PATTERNS = (
    re.compile(r"sendrawtransaction", re.I),
    re.compile(r"sendtransaction", re.I),
    re.compile(r"signtransaction", re.I),
    re.compile(r"importrawkey", re.I),
    re.compile(r"unlockaccount", re.I),
)

# Env var name fragments that indicate real signing material. Presence of any
# of these with a non-empty value makes the environment unsafe for a tool that
# must never sign or broadcast.
_SIGNING_ENV_PATTERNS = (
    re.compile(r"private_?key", re.I),
    re.compile(r"mnemonic", re.I),
    re.compile(r"seed_?phrase", re.I),
    re.compile(r"secret_?key", re.I),
    re.compile(r"signer_?key", re.I),
    re.compile(r"wallet_?key", re.I),
    re.compile(r"keystore_?password", re.I),
)

# Env var names that look like signing material but are public / harmless, so
# they don't trip the environment check.
_SIGNING_ENV_ALLOW = re.compile(
    r"public|pub_?key|address|api|rpc|infura|alchemy|etherscan|explorer",
    re.I,
)


def is_blocked_method(method: Any) -> bool:
    """True if `method` is a state-changing / broadcasting RPC method."""
    if not isinstance(method, str):
        return False
    m = method.strip().lower()
    if m in BLOCKED_METHODS:
        return True
    return any(p.search(m) for p in _BLOCKED_PATTERNS)


def assert_read_only(method: Any) -> None:
    """Raise RpcWriteBlocked if `method` would change state or broadcast.

    Call this at every transport entry point before a request is sent.
    """
    if is_blocked_method(method):
        raise RpcWriteBlocked(
            f"blocked write/broadcast RPC method: {method!r} "
            "(ReconAnything is read-only)")


def assert_payload_read_only(payload: Any) -> None:
    """Guard a JSON-RPC payload (single dict or a batch list) before sending."""
    if isinstance(payload, dict):
        assert_read_only(payload.get("method"))
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            if isinstance(item, dict):
                assert_read_only(item.get("method"))


def signing_material_env(environ: Optional[Iterable] = None) -> List[str]:
    """Return the names of env vars that appear to hold real signing material.

    An all-zero / empty / obviously-placeholder value does not count.
    """
    src = dict(os.environ) if environ is None else dict(environ)
    hits: List[str] = []
    for name, value in src.items():
        if not value or not str(value).strip():
            continue
        if _SIGNING_ENV_ALLOW.search(name):
            continue
        if any(p.search(name) for p in _SIGNING_ENV_PATTERNS):
            v = str(value).strip().lower()
            if v in ("", "0", "0x", "none", "null", "changeme",
                     "your_private_key", "replace_me"):
                continue
            hits.append(name)
    return hits


def enforce_read_only_env(environ: Optional[Iterable] = None) -> None:
    """Raise RpcWriteBlocked if the environment holds real signing material.

    Entry points (batch scan, live probe) call this at startup so the tool
    refuses to run anywhere a key could be used, rather than trusting that no
    code path will reach for one.
    """
    hits = signing_material_env(environ)
    if hits:
        raise RpcWriteBlocked(
            "signing material present in environment "
            f"({', '.join(sorted(hits))}); ReconAnything is read-only and "
            "will not run with a key or seed phrase available")
