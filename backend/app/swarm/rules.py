"""Hard rules for the swarm. Non-negotiable, enforced in code.

Detection only. Read-only live probes from an unfunded stranger.
No transactions, no drains, no exploit execution, no fund-taking.
Only CALLER / CALLER-SUPPLIED recipients count as real; FIXED /
HOLDER-SELF are trigger-only. crypto.com is never a target. The swarm
never predicts VERIFIED_REAL on its own: that verdict may only arrive
as a passthrough from the existing validator path, never constructed
by swarm code.
"""
from __future__ import annotations

# The unfunded stranger: an address with no known private key and no
# funds. Every live probe is an eth_call FROM this address. It can
# never sign or send anything, so a probe can never become a tx.
STRANGER_ADDRESS = "0x000000000000000000000000000000000000dEaD"

# JSON-RPC methods the swarm may ever call. Anything else (send,
# sign, estimate-and-send flows) is refused before it is built.
READONLY_METHODS = frozenset({
    "eth_call",
    "eth_getCode",
    "eth_getBalance",
    "eth_getStorageAt",
    "eth_getTransactionCount",
    "eth_chainId",
    "eth_blockNumber",
    "eth_getBlockByNumber",
})

# Recipient classes that count as stranger-receivable (real). Every
# other class is trigger-only: it can flag a finding, never a payout.
REAL_RECIPIENT_CLASSES = frozenset({"CALLER", "CALLER-SUPPLIED"})
TRIGGER_ONLY_RECIPIENT_CLASSES = frozenset({
    "FIXED", "HOLDER-SELF", "OWNER", "UNKNOWN",
})

# Verdicts swarm code itself may assign. VERIFIED_REAL is deliberately
# absent: only the validator path may produce it, and the swarm passes
# it through unchanged (see probe.py) instead of constructing it.
SWARM_VERDICTS = frozenset({
    "UNVERIFIED", "TRIGGER_ONLY", "FALSE_POSITIVE", "CLEAN", "ERROR",
})

# crypto.com is never a target (its policy bans scanners; repo-wide
# rule, see app/main.py and app/finding_chain.py BLOCKED_DOMAINS).
# A target is rejected when its name, label, or creator metadata
# contains any of these tokens, or its address is on the denylist.
FORBIDDEN_NAME_TOKENS = ("crypto.com", "cryptocom", "crypto_com")
FORBIDDEN_ADDRESSES = frozenset({
    # No hard-coded addresses: the denylist is a hook for Jay to add
    # specific addresses. Name matching is the live gate.
})

# $100k realizable-value floor for the live path (mirrors the
# investigator loop's BOUNTY_FLOOR_USD). Unknown value is never
# filtered as dust; it sorts after known-value targets.
BOUNTY_FLOOR_USD = 100_000.0


def check_readonly(method: str) -> None:
    """Raise unless `method` is a read-only JSON-RPC method."""
    if method not in READONLY_METHODS:
        raise ValueError(
            f"refused non-read-only RPC method: {method!r} "
            "(swarm probes are read-only eth_call only)")


def is_forbidden_target(target: dict) -> str | None:
    """Return a reason when `target` must never be investigated.

    Checks name/label/creator metadata for crypto.com tokens and the
    address denylist. Returns None when the target is allowed.
    """
    address = str(target.get("address") or "").lower()
    if address in FORBIDDEN_ADDRESSES:
        return f"address {address} is on the forbidden-target denylist"
    haystack = " ".join([
        str(target.get("name") or ""),
        str(target.get("label") or ""),
        str(target.get("source") or ""),
        str(target.get("creator") or ""),
    ]).lower()
    for token in FORBIDDEN_NAME_TOKENS:
        if token in haystack:
            return f"target metadata matches forbidden token {token!r}"
    return None


def recipient_counts_as_real(recipient_class: str | None) -> bool:
    """True only for CALLER / CALLER-SUPPLIED recipients."""
    return (recipient_class or "").upper() in REAL_RECIPIENT_CLASSES
