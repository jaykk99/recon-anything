"""Route findings by the evidence they actually need.

A "no source on file" bucket is too coarse: it puts a bytecode-checkable
constant next to a finding that genuinely needs readable Solidity, and
then holds both behind the same acquisition queue. The result is a
critical path where nothing drains, and a batch that looks blocked when
most of it is not.

This module answers one question per finding: *what is the cheapest
evidence that can settle it?*

  * ``bytecode``  - bytecode alone settles it (all-zero / empty checks,
    self-destruct-free shapes, code size, dispatcher presence).
  * ``runtime``   - bytecode plus a few read-only eth_call reads settles it
    (keccak constants against ``name()``/``version()``, selectors,
    EIP-712 domain separators, proxy/admin slots, balances).
  * ``decoded``   - the finding already carries the decoded fact it was
    derived from, so re-acquiring source adds nothing to adjudication
    (unchecked arithmetic already sliced to a function and operand).
  * ``source``    - a human or model must read the source: access control,
    recipient routing, business logic, economic flows.

Only ``source`` blocks on acquisition; everything else can be drained
now. Routing is by key/plugin vocabulary, so a new detector lands in a
sensible bucket without a mapping table, and anything unknown defaults to
``source`` (the conservative direction: never claim a finding is
settleable when it may not be).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Sequence

EVIDENCE_TYPES = ("bytecode", "runtime", "decoded", "source")

# Findings whose verdict is a property of the deployed code, not of a
# human read (constants, selectors, layout, presence).
BYTECODE_KEYS = frozenset({
    "hardcoded_hash_constant_mismatch",
    "zero_address_check_missing",
    "empty_code_address",
    "selfdestruct_present",
    "delegatecall_present",
    "no_source_code",
    "proxy_implementation_slot",
    "storage_layout_collision",
    "selector_collision",
    "function_selector_mismatch",
    "permit_domain_mismatch",
    "permit_typehash_mismatch",
    "eip712_domain_mismatch",
    "decimals_mismatch",
    "name_symbol_mismatch",
})

# Settleable from bytecode plus a handful of eth_call reads.
RUNTIME_PREFIXES = ("owner_", "proxy_admin", "admin_slot", "upgrade_authority",
                    "allowance_", "balance_", "total_supply", "pause_",
                    "paused_", "role_", "minter_", "cap_", "is_verified",
                    "bytecode_")

# Already decoded: the row carries the slice that would be re-read.
DECODED_KEYS = frozenset({
    "unchecked_math_user_input",
    "unchecked_math",
    "unchecked_arithmetic",
    "integer_truncation",
    "unsafe_cast",
})

# Genuinely needs source: authorization and routing decisions.
SOURCE_REQUIRED = frozenset({
    "access_control_flaw",
    "authorization_missing",
    "business_logic",
    "logic_flaw",
    "reentrancy",
    "oracle_manipulation",
    "economic_invariant",
})
SOURCE_PREFIXES = ("recipient_", "auth_", "permission_", "role_check_",
                   "signature_verification_", "withdraw_", "claim_")

_SOURCE_HINTS = re.compile(r"access[_-]?control|authoriz|recipient|"
                           r"business[_-]?logic|reentran|oracle|"
                           r"invariant|permission", re.I)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def evidence_for(finding: Dict[str, Any]) -> str:
    """Cheapest evidence that can settle one finding."""
    if not isinstance(finding, dict):
        return "source"
    key = _norm(finding.get("key") or finding.get("kind"))
    plugin = _norm(finding.get("plugin") or finding.get("plugin_id"))
    if key in DECODED_KEYS:
        return "decoded"
    if key in BYTECODE_KEYS:
        return "bytecode"
    if key.startswith(RUNTIME_PREFIXES):
        return "runtime"
    if key in SOURCE_REQUIRED or key.startswith(SOURCE_PREFIXES):
        return "source"
    blob = f"{key} {plugin}"
    if _SOURCE_HINTS.search(blob):
        return "source"
    return "source"


def needs_acquisition(finding: Dict[str, Any]) -> bool:
    """True only when the finding is blocked on reading the source."""
    return evidence_for(finding) == "source"


def split(findings: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Partition a queue into "drain now" and "blocked on acquisition".

    Returns ``{no_acquisition, needs_acquisition, counts, note}``; the
    counts are per evidence type, so a batch can report exactly how much
    of its backlog is a plumbing problem.
    """
    drain: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    counts = {t: 0 for t in EVIDENCE_TYPES}
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        kind = evidence_for(finding)
        counts[kind] = counts.get(kind, 0) + 1
        row = dict(finding)
        row["evidence_required"] = kind
        (blocked if kind == "source" else drain).append(row)
    total = len(drain) + len(blocked)
    return {
        "no_acquisition": drain,
        "needs_acquisition": blocked,
        "counts": counts,
        "total": total,
        "acquisition_share": round(len(blocked) / total, 3) if total else 0.0,
        "note": ("Only 'source' rows wait on acquisition. bytecode/runtime "
                 "rows are settleable from the deployed code; decoded rows "
                 "already carry the slice they were derived from."),
    }


__all__ = ["BYTECODE_KEYS", "DECODED_KEYS", "EVIDENCE_TYPES",
           "SOURCE_REQUIRED", "evidence_for", "needs_acquisition", "split"]


def _main(argv: Optional[List[str]] = None) -> int:
    """CLI: split a JSONL queue into drain-now and blocked-on-acquisition.

    ``python -m app.evidence_route --input queue.jsonl [--write DIR]``
    prints the counts and, with --write, emits ``drain.jsonl`` and
    ``blocked.jsonl`` so the first queue can be worked now.
    """
    import argparse
    import json as _json
    import os

    ap = argparse.ArgumentParser(prog="app.evidence_route")
    ap.add_argument("--input", required=True, help="JSONL of findings")
    ap.add_argument("--write", default="", help="output directory")
    args = ap.parse_args(argv)
    rows = []
    with open(args.input, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(_json.loads(line))
            except _json.JSONDecodeError:
                continue
    out = split(rows)
    print(f"total: {out['total']}  drain now: {len(out['no_acquisition'])}  "
          f"blocked on acquisition: {len(out['needs_acquisition'])}")
    for kind, count in sorted(out["counts"].items()):
        print(f"  {kind}: {count}")
    if args.write:
        os.makedirs(args.write, exist_ok=True)
        for name, items in (("drain.jsonl", out["no_acquisition"]),
                            ("blocked.jsonl", out["needs_acquisition"])):
            path = os.path.join(args.write, name)
            with open(path, "w", encoding="utf-8") as fh:
                for item in items:
                    fh.write(_json.dumps(item) + "\n")
            print(f"wrote {path} ({len(items)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
