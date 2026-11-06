#!/usr/bin/env python3
"""Chain-layer proxy resolution for the continuous-validator path.

Sync, cast-based, read-only companion to scripts/auto_validate.py.

Why this exists: candidates stalled as "function 'X' not found in
the verified source for this contract" when the flagged function
lives in a proxy's IMPLEMENTATION. The validator evidence path
only ever fetched the target address's own verified source, so a
function that the proxy delegatecalls into was invisible to it.

This module closes that gap without touching the app-side async
machinery in app.plugins.contract_chain:

- resolve_implementation_sync(): EIP-1167 bytecode pattern,
  EIP-1967 implementation slot, EIP-1967 beacon slot (beacon's
  implementation() call, falling back to the beacon's storage
  slot 0) - all via `cast code` / `cast storage` / `cast call`,
  reusing auto_validate's _cast helper and contract_chain's pure
  helpers/slot constants (never duplicated here).
- fetch_source_for(): verified source for any address -
  auto_validate.fetch_sourcify (Sourcify files API) with the
  Sourcify v2 fallback the continuous runner uses.
- resolve_candidate_source(): the candidate-level entry point.
  Returns the target's own source unchanged when the function is
  already in the target's deployed scope (fast path: no chain
  reads at all); otherwise walks the proxy chain (depth <= 2:
  implementation of implementation) and returns the first
  implementation source whose deployed scope carries the
  function, with the origin noting the resolution.

Detection only: storage reads, code reads and eth_call - never
a transaction.

Usage (live read-only smoke):
  python3 scripts/proxy_source.py ethereum \
      0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 transfer
"""
import argparse
import json
import pathlib
import re
import sys
import urllib.request

_HERE = pathlib.Path(__file__).resolve().parent
_BACKEND = _HERE.parent
for _p in (str(_HERE), str(_BACKEND)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import auto_validate as av  # noqa: E402  (sibling script)
from app.plugins import contract_chain as cc  # noqa: E402

ZERO_WORD = "0x" + "00" * 32
_WORD_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")


# ---------------------------------------------------------------------------
# Cast primitives (sync versions of contract_chain's rpc_get_*)
# ---------------------------------------------------------------------------

def _cast_first_line(chain, args, timeout=15):
    """Run cast over the chain's RPC list; return the first
    output line of the first route that produced one, else None.
    Transport failures fall through to the next route."""
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return None
    for rpc in cfg.rpc_urls:
        out, _err = av._cast([*args[0:1], "--rpc-url", rpc,
                              *args[1:]], timeout=timeout)
        if out is None:
            continue
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        if lines and "Error" not in lines[0]:
            return lines[0]
    return None


def storage_at(chain, address, slot):
    """One storage word (0x + 64 hex) at `slot`, or None when no
    RPC route answers. Read-only (`cast storage`)."""
    line = _cast_first_line(chain, ["storage", address, slot])
    if line and _WORD_RE.match(line):
        return line.lower()
    return None


def code_at(chain, address):
    """Deployed bytecode hex at `address`, or None. Read-only
    (`cast code`)."""
    line = _cast_first_line(chain, ["code", address])
    if line and line.startswith("0x") and len(line) > 2:
        return line.lower()
    return None


def call_address(chain, address, signature):
    """One read-only `cast call` returning an address, parsed to
    lowercase, or "" on revert / transport failure."""
    line = _cast_first_line(chain, ["call", address, signature])
    if not line:
        return ""
    m = _ADDR_RE.search(line)
    if not m:
        # cast can also return the raw 32-byte word form
        return cc.address_from_storage_word(line)
    addr = m.group(0).lower()
    return "" if addr == "0x" + "00" * 20 else addr


# ---------------------------------------------------------------------------
# Proxy resolution (sync mirror of contract_chain.resolve_implementation,
# with the task's via vocabulary: eip1167 | eip1967 | beacon)
# ---------------------------------------------------------------------------

def resolve_implementation_sync(chain, address):
    """Resolve a proxy's implementation address, read-only.

    Order: EIP-1167 minimal-proxy bytecode pattern, EIP-1967
    implementation slot, EIP-1967 beacon slot -> the beacon's
    implementation() call, falling back to the beacon's storage
    slot 0 (where OpenZeppelin's UpgradeableBeacon stores its
    implementation).

    Returns {"implementation": addr|"", "via":
    "eip1167"|"eip1967"|"beacon"|"", "beacon": addr|""}.
    """
    empty = {"implementation": "", "via": "", "beacon": ""}
    if cc.CHAINS.get(chain) is None:
        return empty
    code = code_at(chain, address)
    impl = cc.implementation_from_bytecode(code)
    if impl and impl.lower() != address.lower():
        return {"implementation": impl.lower(), "via": "eip1167",
                "beacon": ""}
    word = storage_at(chain, address,
                      cc.EIP1967_IMPLEMENTATION_SLOT)
    impl = cc.address_from_storage_word(word)
    if impl and impl.lower() != address.lower():
        return {"implementation": impl, "via": "eip1967",
                "beacon": ""}
    word = storage_at(chain, address, cc.EIP1967_BEACON_SLOT)
    beacon = cc.address_from_storage_word(word)
    if beacon:
        impl = call_address(chain, beacon,
                            "implementation()(address)")
        if not impl:
            bword = storage_at(chain, beacon, "0x0")
            impl = cc.address_from_storage_word(bword)
        if impl and impl.lower() != address.lower():
            return {"implementation": impl, "via": "beacon",
                    "beacon": beacon}
        return {"implementation": "", "via": "", "beacon": beacon}
    return empty


# ---------------------------------------------------------------------------
# Verified source for an arbitrary address
# ---------------------------------------------------------------------------

def fetch_sourcify_v2(chain, address, timeout=25):
    """Sourcify v2 contract API (the continuous runner's fallback
    fetch, copied here so scripts do not import the runner)."""
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return None
    url = (f"https://sourcify.dev/server/v2/contract/{cfg.chain_id}/"
           f"{address}?fields=sources,compilation")
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "recon-continuous-validator"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode())
    except Exception:
        return None
    sources = d.get("sources") or {}
    parts = []
    for path, obj in list(sources.items())[:16]:
        content = (obj or {}).get("content") or ""
        if content:
            parts.append(f"\n// ==== {path} ====\n{content}")
    if not parts:
        return None
    return {"source": "\n".join(parts),
            "contract_name": (d.get("compilation") or {}).get("name", ""),
            "origin": "Sourcify v2"}


def fetch_source_for(chain, address):
    """Verified source for `address`: Sourcify files API first
    (auto_validate.fetch_sourcify), then Sourcify v2. Returns the
    auto_validate source dict shape {source, contract_name,
    origin} or None."""
    return av.fetch_sourcify(chain, address) or \
        fetch_sourcify_v2(chain, address)


# ---------------------------------------------------------------------------
# Candidate-level resolution
# ---------------------------------------------------------------------------

def _in_deployed_scope(src, function):
    """True when `function` is in the deployed scope of the
    contract the source dict names (auto_validate.function_scope
    semantics: present and not compilation_only)."""
    if not src or not src.get("source") or not function:
        return False
    try:
        return av.function_scope(src["source"], function,
                                 src.get("contract_name", "")) \
            == "scoped"
    except Exception:
        return False


def resolve_candidate_source(chain, address, function):
    """Source that actually deploys `function` for `address`.

    Fast path: the target's own verified source already carries
    the function in its deployed scope - returned unchanged and
    NO chain reads happen. Otherwise the proxy chain is walked
    (depth <= 2) and the first implementation source whose
    deployed scope carries the function is returned as
    {source, contract_name, origin, implementation, via}, with
    origin noting the resolution (e.g. "Sourcify v2 via eip1967
    implementation 0x..."). None when nothing resolves - the
    caller falls back to today's behavior.

    Note for callers: the returned SOURCE is the implementation's
    (for building the probe signature); probing still targets the
    PROXY address - delegatecall semantics.
    """
    if not function:
        return None
    target = fetch_source_for(chain, address)
    if _in_deployed_scope(target, function):
        return {"source": target["source"],
                "contract_name": target.get("contract_name", ""),
                "origin": target.get("origin", ""),
                "implementation": "", "via": ""}
    current = address
    for _depth in range(2):
        res = resolve_implementation_sync(chain, current)
        impl = res.get("implementation") or ""
        if not impl:
            break
        impl_src = fetch_source_for(chain, impl)
        if _in_deployed_scope(impl_src, function):
            return {"source": impl_src["source"],
                    "contract_name":
                        impl_src.get("contract_name", ""),
                    "origin": f"{impl_src.get('origin', '')} via "
                              f"{res.get('via', '')} implementation "
                              f"{impl}",
                    "implementation": impl,
                    "via": res.get("via", "")}
        current = impl
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("chain")
    ap.add_argument("address")
    ap.add_argument("function", nargs="?", default="")
    args = ap.parse_args()
    out = {"chain": args.chain, "address": args.address,
           "resolution": resolve_implementation_sync(args.chain,
                                                     args.address)}
    if args.function:
        src = resolve_candidate_source(args.chain, args.address,
                                       args.function)
        if src is None:
            out["candidate_source"] = None
        else:
            out["candidate_source"] = {
                "contract_name": src["contract_name"],
                "origin": src["origin"],
                "implementation": src["implementation"],
                "via": src["via"],
                "source_bytes": len(src["source"])}
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
