#!/usr/bin/env python3
"""Trace pack: a per-contract audit pack a human can read.

Usage:
  trace_pack.py --address 0x... --chain bsc [--out dir/]
  trace_pack.py --source-file contract.sol [--contract Name] [--out dir/]

Fetches verified source (keyless: Blockscout / Sourcify, via the
repo's own fetch_verified_source) or reads a local source file,
then writes two files:
  trace_pack.json - the structured pack
  trace_pack.md   - the readable pack

The pack has four parts:
- value-flow map: per function, the state variables read and
  written, the external calls made, and where value moves
  (transfers in/out, payable, msg.value).
- external-call ordering: the ordered sequence of state writes
  vs external calls per function, flagging checks-effects-
  interactions (CEI) violations (an external call before a
  state write) and read-only reentrancy shapes (a view function
  reading state that another function writes after an external
  call, so the view can observe inconsistent state mid-call).
- inheritance / interface trace: the contract, its ancestors,
  and the external interfaces it calls.
- trust-assumption list: which external protocols are trusted,
  for what, and what breaks if one misbehaves.

Detection only: static analysis of verified source. No
transaction is sent, nothing is executed, no private data is
accessed. A contract with no verified source is reported as
degraded (no pack is faked from bytecode).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app import net  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import contract_logic as cl  # noqa: E402
from app.plugins.base import Ctx  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

_TRANSFER_RE = re.compile(
    r"\b(transfer|transferFrom|safeTransfer|safeTransferFrom|"
    r"send|call)\s*(\{[^}]*value[^}]*\})?\s*\(")
_PAYABLE_RE = re.compile(r"\bpayable\b")
_MSG_VALUE_RE = re.compile(r"\bmsg\.value\b")
_INHERIT_RE = re.compile(
    r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\s+is\s+([^{]+)\{")
_CONTRACT_RE = re.compile(
    r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b")
_INTERFACE_RE = re.compile(r"\b(I[A-Z][A-Za-z0-9_]*)\b")
_STATE_DECL_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*)\s+(?:public\s+|private\s+|internal\s+)?"
    r"([a-z_][A-Za-z0-9_]*)\s*(?:=|;)")

# What an external protocol is trusted for, by the call made on
# it. The "breaks if" is the audit question the pack asks.
_TRUST_RULES = (
    (re.compile(r"latestRoundData|getPrice|getUnderlyingPrice|"
                r"getLatestPrice|peek"),
     "price feed",
     "trusted to report a current, honest price",
     "if the feed is stale, manipulated, or halted, every "
     "borrow / mint / liquidate / swap priced off it is wrong"),
    (re.compile(r"\btransfer\b|\btransferFrom\b|safeTransfer"),
     "token",
     "trusted to move exactly the requested amount and to "
     "report balances honestly",
     "if it reverts, takes a fee, or is a rebasing / malicious "
     "token, the transfer accounting and balances are wrong"),
    (re.compile(r"\bbalanceOf\b"),
     "token",
     "trusted to report the true balance",
     "if the balance is manipulated (donation, flash loan), any "
     "rate or accumulator computed from it is wrong"),
    (re.compile(r"\bflashLoan\b|onFlashLoan|executeOperation"),
     "flash-loan provider",
     "trusted to call back exactly once with the agreed terms",
     "if the callback is re-entered or the terms change, the "
     "state the callback relies on is wrong"),
)


def _contract_name(src: str, hint: str = "") -> str:
    if hint:
        return hint
    m = _CONTRACT_RE.search(src)
    return m.group(1) if m else "Unknown"


def _ancestors(src: str, name: str):
    for m in _INHERIT_RE.finditer(src):
        if m.group(1) == name:
            return [a.strip() for a in m.group(2).split(",")
                    if a.strip()]
    return []


def _external_types(src: str, scope) -> dict:
    """Interface / external contract types used -> the state
    variables (or locals) of that type. Only types that are
    actually used (a variable, a call, or a cast) are listed -
    an interface merely declared in a shared interface block
    is not a trust assumption."""
    out = {}
    for m in _STATE_DECL_RE.finditer(src):
        t, var = m.group(1), m.group(2)
        if re.match(r"^I[A-Z]", t):
            out.setdefault(t, []).append(var)
    # Types used only in casts / calls (no state variable).
    for t in set(_INTERFACE_RE.findall(src)):
        if t in out:
            continue
        if f"{t}." in src or f"{t}(" in src:
            out.setdefault(t, [])
    return out


def _call_str(call: dict) -> str:
    """An external-call dict from cl._external_calls -> a
    readable 'receiver.kind' string, e.g. 'asset.transferFrom'."""
    recv = (call.get("receiver") or "").strip()
    kind = call.get("kind") or ""
    return f"{recv}.{kind}" if recv else kind


_EXT_CALL_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _ext_var_names(src: str, scope) -> set:
    """Variable names of interface / external-contract type."""
    names = set()
    for vars_ in _external_types(src, scope).values():
        names.update(vars_)
    return names


def _external_call_sites(text: str, ext_vars: set):
    """All external call sites in a function, as sorted
    {pos, call} dicts. cl._external_calls covers the
    value-moving calls (call / transfer / send / ...); a
    price-feed read (feed.latestRoundData()) or a balance
    read (token.balanceOf(x)) is also an external call, so
    calls on interface-typed receivers are added by regex.
    Deduped by position."""
    sites = {}
    for c in cl._external_calls(text):
        sites[c["pos"]] = _call_str(c)
    for m in _EXT_CALL_RE.finditer(text):
        if m.group(1) in ext_vars:
            call_s = f"{m.group(1)}.{m.group(2)}"
            method_pos = m.start(2)
            # Dedupe: a cl call for the same method sits at the
            # dot just before the method name, so it is within
            # a couple of chars of the method position.
            if any(abs(p - method_pos) <= 2 and v == call_s
                   for p, v in sites.items()):
                continue
            sites.setdefault(m.start(), call_s)
    return [{"pos": p, "call": c}
            for p, c in sorted(sites.items())]


def _value_flow(src: str, scope, state):
    """Per function: reads, writes, external calls, value flow."""
    ext_vars = _ext_var_names(src, scope)
    flow = []
    for fn in scope.functions:
        text = fn["text"]
        if "{" not in text:
            continue
        reads = sorted({t for t in re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*", text) if t in state})
        writes = sorted({var for _, var in
                         cl._state_writes(text, state)})
        calls = [s["call"] for s in
                 _external_call_sites(text, ext_vars)]
        transfers = sorted({m.group(1) for m in
                            _TRANSFER_RE.finditer(text)})
        flow.append({
            "function": fn["name"],
            "visibility": (
                "view" if re.search(r"\bview\b", fn["signature"])
                else "pure" if re.search(r"\bpure\b",
                                         fn["signature"])
                else "external" if re.search(
                    r"\bexternal\b", fn["signature"])
                else "public" if re.search(
                    r"\bpublic\b", fn["signature"]) else "internal"),
            "reads": reads,
            "writes": writes,
            "external_calls": calls,
            "transfers": transfers,
            "payable": bool(_PAYABLE_RE.search(fn["signature"])),
            "uses_msg_value": bool(_MSG_VALUE_RE.search(text)),
        })
    return flow


def _call_ordering(src: str, scope, state):
    """Ordered state writes vs external calls per function, with
    CEI violations and read-only reentrancy shapes."""
    ext_vars = _ext_var_names(src, scope)
    ordering = []
    cei = []
    # State written after an external call, per function, for
    # the read-only reentrancy shape.
    written_after_call = {}
    for fn in scope.functions:
        text = fn["text"]
        if "{" not in text:
            continue
        events = []
        for pos, var in cl._state_writes(text, state):
            events.append((pos, "state_write", var))
        for site in _external_call_sites(text, ext_vars):
            events.append((site["pos"], "external_call",
                           site["call"]))
        events.sort(key=lambda e: e[0])
        if not events:
            continue
        ordered = [{"kind": k, "detail": d}
                   for _, k, d in events]
        ordering.append({"function": fn["name"],
                         "events": ordered})
        # CEI: an external call before a later state write.
        seen_call = False
        for _, kind, detail in events:
            if kind == "external_call":
                seen_call = True
            elif kind == "state_write" and seen_call:
                cei.append({
                    "function": fn["name"],
                    "detail": f"state write '{detail}' happens "
                              f"after an external call - "
                              f"checks-effects-interactions "
                              f"violation"})
                break
        # Record vars written after the first external call.
        call_pos = [p for p, k, _ in events
                    if k == "external_call"]
        if call_pos:
            first = min(call_pos)
            written_after_call[fn["name"]] = {
                var for p, k, var in events
                if k == "state_write" and p > first}
    # Read-only reentrancy: a view reads state that another
    # function writes after an external call.
    readonly = []
    for fn in scope.functions:
        text = fn["text"]
        if "{" not in text:
            continue
        if not re.search(r"\b(view|pure)\b", fn["signature"]):
            continue
        reads = {t for t in re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*", text) if t in state}
        for other, written in written_after_call.items():
            shared = reads & written
            if shared:
                readonly.append({
                    "view": fn["name"],
                    "writer": other,
                    "state": sorted(shared),
                    "detail": f"view '{fn['name']}' reads "
                              f"{sorted(shared)} which "
                              f"'{other}' writes after an "
                              f"external call - the view can "
                              f"observe inconsistent state "
                              f"mid-call (read-only reentrancy "
                              f"shape)"})
    return ordering, cei, readonly


def _trust_assumptions(src: str, scope):
    """External protocols trusted, for what, and what breaks."""
    ext_vars = _ext_var_names(src, scope)
    assumptions = []
    seen = set()
    for fn in scope.functions:
        text = fn["text"]
        for site in _external_call_sites(text, ext_vars):
            call_s = site["call"]
            for pat, kind, trusted, breaks in _TRUST_RULES:
                if pat.search(call_s):
                    key = (kind, call_s)
                    if key in seen:
                        continue
                    seen.add(key)
                    assumptions.append({
                        "external": call_s,
                        "kind": kind,
                        "trusted_for": trusted,
                        "breaks_if": breaks,
                        "called_from": fn["name"],
                    })
    # External contract types declared in the contract.
    for t, vars_ in _external_types(src, scope).items():
        if t in ("IERC20Like",):
            continue
        if any(a["external"].startswith(t) for a in assumptions):
            continue
        assumptions.append({
            "external": t,
            "kind": "external contract",
            "trusted_for": "trusted to behave as its interface "
                           "promises",
            "breaks_if": "if it misbehaves, every call that "
                         "depends on it fails or returns a wrong "
                         "value",
            "called_from": "",
        })
    return assumptions


def build_trace_pack(src: str, contract_name: str = "",
                     address: str = "", chain: str = "",
                     compiler: str = "") -> dict:
    """Build the pack from verified source. Pure (no network)."""
    name = _contract_name(src, contract_name)
    scope = cl._Scope(src, name)
    state = cl.state_variables(src)
    flow = _value_flow(src, scope, state)
    ordering, cei, readonly = _call_ordering(src, scope, state)
    assumptions = _trust_assumptions(src, scope)
    return {
        "contract": {
            "name": name, "address": address, "chain": chain,
            "compiler": compiler,
            "source_lines": src.count("\n") + 1,
            "state_variables": sorted(state),
        },
        "inheritance": {
            "contract": name,
            "ancestors": _ancestors(src, name),
            "external_types": _external_types(src, scope),
        },
        "value_flow": flow,
        "call_ordering": ordering,
        "cei_violations": cei,
        "readonly_reentrancy_shapes": readonly,
        "trust_assumptions": assumptions,
    }


def pack_to_markdown(pack: dict) -> str:
    c = pack["contract"]
    lines = [
        f"# Trace pack: {c['name']}",
        "",
        f"- Address: `{c['address'] or 'local source'}`",
        f"- Chain: {c['chain'] or '-'}",
        f"- Compiler: {c['compiler'] or '-'}",
        f"- Source lines: {c['source_lines']}",
        f"- State variables: "
        f"{', '.join(c['state_variables']) or '-'}",
        "",
        "## Inheritance / interface trace",
        "",
        f"- Contract: `{pack['inheritance']['contract']}`",
        f"- Ancestors: "
        f"{', '.join(pack['inheritance']['ancestors']) or '-'}",
    ]
    for t, vars_ in pack["inheritance"]["external_types"].items():
        lines.append(f"- External type `{t}`"
                     + (f" (as {', '.join(vars_)})" if vars_ else ""))
    lines += ["", "## Value-flow map", ""]
    for f in pack["value_flow"]:
        lines.append(f"### {f['function']} ({f['visibility']})")
        lines.append(f"- Reads: {', '.join(f['reads']) or '-'}")
        lines.append(f"- Writes: {', '.join(f['writes']) or '-'}")
        lines.append(f"- External calls: "
                     f"{', '.join(f['external_calls']) or '-'}")
        lines.append(f"- Transfers: "
                     f"{', '.join(f['transfers']) or '-'}")
        if f["payable"]:
            lines.append("- Payable: yes")
        if f["uses_msg_value"]:
            lines.append("- Uses msg.value: yes")
        lines.append("")
    lines += ["## External-call ordering", ""]
    for o in pack["call_ordering"]:
        lines.append(f"### {o['function']}")
        for ev in o["events"]:
            lines.append(f"- {ev['kind']}: {ev['detail']}")
        lines.append("")
    if pack["cei_violations"]:
        lines += ["## CEI violations", ""]
        for v in pack["cei_violations"]:
            lines.append(f"- `{v['function']}`: {v['detail']}")
        lines.append("")
    if pack["readonly_reentrancy_shapes"]:
        lines += ["## Read-only reentrancy shapes", ""]
        for v in pack["readonly_reentrancy_shapes"]:
            lines.append(f"- {v['detail']}")
        lines.append("")
    lines += ["## Trust assumptions", ""]
    if not pack["trust_assumptions"]:
        lines.append("- None detected (no external calls found).")
    for a in pack["trust_assumptions"]:
        lines.append(f"- `{a['external']}` ({a['kind']})"
                     + (f" called from `{a['called_from']}`"
                        if a["called_from"] else "")
                     + f": {a['trusted_for']}. "
                     f"Breaks if: {a['breaks_if']}.")
    lines.append("")
    return "\n".join(lines)


async def _fetch_source(chain_id: str, address: str):
    chain = cc.CHAINS.get(chain_id)
    if chain is None:
        raise ValueError(f"unknown chain: {chain_id}")
    async with net.async_client(timeout=30) as http:
        ctx = Ctx(run_id="trace-pack", mode="passive", http=http,
                  cache=None, keys={},
                  limiter=RateLimiter(default_rps=5.0), shared={})
        src = await cc.fetch_verified_source(ctx, chain, address)
    return chain, src


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Build a per-contract audit trace pack "
                    "(JSON + readable markdown).")
    ap.add_argument("--address",
                    help="contract address")
    ap.add_argument("--chain", default="bsc",
                    help="chain id (default: bsc)")
    ap.add_argument("--source-file",
                    help="local Solidity source file instead of "
                         "fetching verified source")
    ap.add_argument("--contract",
                    help="contract name (default: first contract "
                         "in the source)")
    ap.add_argument("--out",
                    help="output dir (default: ./trace_pack_<name>)")
    args = ap.parse_args(argv)

    src = ""
    compiler = ""
    address = args.address or ""
    chain = args.chain
    if args.source_file:
        with open(args.source_file) as fh:
            src = fh.read()
    elif address:
        if not cc.ADDRESS_RE.match(address):
            print(f"bad address: {address}", file=sys.stderr)
            return 2
        try:
            _chain, got = asyncio.run(
                _fetch_source(chain, address))
        except Exception as exc:
            print(f"verified-source fetch failed: {exc}",
                  file=sys.stderr)
            return 2
        if not got:
            print(f"degraded: no verified source for {address} "
                  f"on {chain} - no pack is faked from bytecode",
                  file=sys.stderr)
            return 3
        src = got["source"]
        compiler = got.get("compiler", "")
    else:
        print("give --address or --source-file", file=sys.stderr)
        return 2

    pack = build_trace_pack(src, args.contract or "",
                            address, chain, compiler)
    name = pack["contract"]["name"]
    outdir = args.out or f"trace_pack_{name}"
    os.makedirs(outdir, exist_ok=True)
    jpath = os.path.join(outdir, "trace_pack.json")
    mpath = os.path.join(outdir, "trace_pack.md")
    with open(jpath, "w") as fh:
        json.dump(pack, fh, indent=2)
    with open(mpath, "w") as fh:
        fh.write(pack_to_markdown(pack))
    print(f"trace pack for {name} ({address or 'local source'}):")
    print(f"  {jpath}")
    print(f"  {mpath}")
    print(f"  functions: {len(pack['value_flow'])}, "
          f"CEI violations: {len(pack['cei_violations'])}, "
          f"read-only reentrancy shapes: "
          f"{len(pack['readonly_reentrancy_shapes'])}, "
          f"trust assumptions: {len(pack['trust_assumptions'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
