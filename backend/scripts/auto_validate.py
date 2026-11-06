#!/usr/bin/env python3
"""Auto-validator runner: machine verdicts for candidate findings.

Reads candidate findings as JSONL (one object per line:
{chain, address, function, kind, ...}), gathers the evidence the
auto-validator needs, and writes verdict JSONL:

- verified source: local source caches first (the recon-verify
  src_cache format: <chain>_<address>.json with {source, name}),
  then the keyless Sourcify repository over HTTP;
- recipient classification + deep gate read: the pure engine in
  app.plugins.auto_validator;
- read-only stranger probe: eth_call via the `cast` binary when
  present (from the unfunded stranger
  0x00000000000000000000000000000000deaDBeef), with default /
  boundary arguments for static parameter types only - functions
  whose arguments cannot be encoded get no probe, and the engine
  says so;
- native balance: `cast balance` over the chain's public RPCs.

Detection only: eth_call is a node-local simulation. No
transaction is ever sent. Rows whose evidence cannot be gathered
come out UNVERIFIED with the missing piece named, never cleared.

Usage:
  python3 scripts/auto_validate.py candidates.jsonl \
      --src-cache ~/workspace/recon-verify/src_cache \
      --out verdicts.jsonl [--limit N] [--no-probe]
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.plugins.auto_validator import STRANGER, \
    validate_candidate  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402
from app.plugins import contract_sim as sim  # noqa: E402

CAST = os.path.expanduser("~/workspace/tools/audit/bin/cast")
SOURCIFY = "https://sourcify.dev/server/files/any/{cid}/{addr}"


def _cast(args, timeout=25):
    if not os.path.exists(CAST):
        return None, "cast binary not present"
    try:
        r = subprocess.run([CAST, *args], capture_output=True,
                           text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or ""), None
    except Exception as e:
        return None, str(e)


def load_cached_source(cache_dirs, chain, address):
    """Local verified-source caches, two on-disk formats:

    - recon-verify format: <chain>_<address>.json with
      {source, name, origin};
    - recon-10k format: <chain_id>_<address>.json with
      {full_source, target_contract, analysis_status}; only
      analysis_status == "source_verified" entries count as
      verified source.
    """
    if isinstance(cache_dirs, str):
        cache_dirs = [c for c in cache_dirs.split(",") if c]
    for cache_dir in cache_dirs or []:
        # recon-verify names files <chain>_<address>.json;
        # recon-10k names them <chain>-<address>.json. Try both.
        p = None
        for sep in ("_", "-"):
            cand = pathlib.Path(os.path.expanduser(cache_dir)) / \
                f"{chain}{sep}{address.lower()}.json"
            if cand.exists():
                p = cand
                break
        if p is None:
            continue
        try:
            d = json.loads(p.read_text())
        except Exception:
            continue
        if d.get("source"):
            return {"source": d["source"],
                    "contract_name": d.get("name")
                    or d.get("contract_name", ""),
                    "origin": f"src_cache ({d.get('origin', '')})"}
        if d.get("full_source") and \
                d.get("analysis_status") == "source_verified":
            return {"source": d["full_source"],
                    "contract_name": d.get("target_contract", ""),
                    "origin": "src_cache (recon-10k, verified)"}
    return None


def fetch_sourcify(chain, address, timeout=20):
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return None
    url = SOURCIFY.format(cid=cfg.chain_id, addr=address)
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "recon-auto-validator"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode())
        files = d.get("files") or []
        parts = [f["content"] for f in files
                 if f.get("name", "").endswith(".sol")
                 and f.get("content")]
        if not parts:
            return None
        name = ""
        for f in files:
            if f.get("name") == "metadata.json":
                try:
                    meta = json.loads(f["content"])
                    targets = ((meta.get("settings") or {})
                               .get("compilationTarget") or {})
                    if targets:
                        name = str(next(iter(targets.values())))
                except Exception:
                    pass
        return {"source": "\n".join(parts), "contract_name": name,
                "origin": "Sourcify"}
    except Exception:
        return None


def probe_function(chain, address, signature, args):
    """One read-only eth_call from the stranger via cast.

    Returns {"status": success|revert|transport_error, ...}."""
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return {"status": "transport_error",
                "detail": f"unknown chain {chain}"}
    last = {"status": "transport_error", "detail": "no route tried"}
    for rpc in cfg.rpc_urls:
        out, err = _cast(["call", "--from", STRANGER,
                          "--rpc-url", rpc, address, signature,
                          *args])
        if out is None:
            last = {"status": "transport_error", "detail": err}
            continue
        if "execution reverted" in out or "revert" in out.lower():
            return {"status": "revert",
                    "detail": out.strip()[-200:], "via": rpc}
        if out.strip() and "Error" not in out:
            return {"status": "success", "detail": out.strip()[:120],
                    "via": rpc}
        last = {"status": "transport_error",
                "detail": out.strip()[-200:]}
    return last


def native_balance(chain, address):
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return {"native_wei": None, "source": "unknown chain"}
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    for rpc in cfg.rpc_urls:
        out, err = _cast(["balance", "--rpc-url", rpc, address],
                         timeout=15)
        if out and out.strip().splitlines():
            try:
                return {"native_wei": int(out.strip().splitlines()[0]),
                        "observed_at": now, "source": rpc}
            except Exception:
                continue
    return {"native_wei": None, "observed_at": now,
            "source": "all RPC routes failed"}


def _call_uint(chain, address, signature, args=()):
    """One read-only cast call returning a uint256, or None.

    A revert is a definitive contract-level answer (the
    function does not exist or rejects the call) - it is NOT
    retried on other RPCs; only transport failures fall
    through to the next route."""
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return None
    for rpc in cfg.rpc_urls:
        out, err = _cast(["call", "--from", STRANGER,
                          "--rpc-url", rpc, address, signature,
                          *args], timeout=15)
        if out is None:
            continue
        s = out.strip()
        if "revert" in s.lower():
            return None
        if s.startswith("0x"):
            try:
                return int(s, 16)
            except Exception:
                return None
    return None


def token_self_balance(chain, address):
    """balanceOf(address) of the contract on itself: the live
    bound for a payout denominated in its own token. None when
    not an ERC20 or unreachable."""
    return _call_uint(chain, address, "balanceOf(address)(uint256)",
                      (address,))


def pair_reserves(chain, address):
    """Live AMM reserves when the contract is a UniswapV2-style
    pair (getReserves). None when it is not a pair."""
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return None
    import datetime as _dt
    for rpc in cfg.rpc_urls:
        out, err = _cast(["call", "--from", STRANGER,
                          "--rpc-url", rpc, address,
                          "getReserves()(uint112,uint112,uint32)"],
                         timeout=15)
        if out is None:
            continue
        s = out.strip()
        if "revert" in s.lower():
            return None  # definitively not a pair; do not
            # retry the remaining RPCs
        if "Error" in s:
            continue
        nums = re.findall(r"\d+", s)
        if len(nums) >= 2:
            try:
                return {"reserve0": int(nums[0]),
                        "reserve1": int(nums[1]),
                        "observed_at": _dt.datetime.now(
                            _dt.timezone.utc).isoformat(),
                        "source": rpc}
            except Exception:
                continue
    return None


# Canonical UniswapV2-style DEX deployments per chain:
# (factory, wrapped native token). The Ethereum WETH address is
# the repo's own constant (app/plugins/_tier10_common.WETH);
# the rest are the DEXes' canonical, publicly documented
# deployment addresses. getPair(tokenA, tokenB) on the factory
# plus getReserves() on the pair is a read-only eth_call.
DEX_PAIRS = {
    "ethereum": [
        ("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
         "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),  # Uniswap V2
        ("0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac",
         "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),  # SushiSwap
    ],
    "bsc": [
        ("0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
         "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"),  # PancakeSwap V2
    ],
    "polygon": [
        ("0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32",
         "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"),  # QuickSwap
        ("0xc35DADB65012eC5796536bD9864eD8773aBc74C4",
         "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270"),  # SushiSwap
    ],
    "arbitrum": [
        ("0xc35DADB65012eC5796536bD9864eD8773aBc74C4",
         "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"),  # SushiSwap
    ],
    "base": [
        ("0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6",
         "0x4200000000000000000000000000000000000006"),  # Uniswap V2
    ],
    "optimism": [
        ("0xc35DADB65012eC5796536bD9864eD8773aBc74C4",
         "0x4200000000000000000000000000000000000006"),  # SushiSwap
    ],
}
_CHAIN_ALIASES = {"bnb": "bsc"}
_ZERO_ADDRESS = "0x" + "0" * 40


def _call_address(chain, address, signature, args=()):
    """One read-only cast call returning an address, or None.

    Mirrors _call_uint's discipline: a revert is a definitive
    contract-level answer (returned as the zero address, NOT
    retried on other RPCs); only transport failures fall
    through to the next route."""
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return None
    for rpc in cfg.rpc_urls:
        out, err = _cast(["call", "--from", STRANGER,
                          "--rpc-url", rpc, address, signature,
                          *args], timeout=15)
        if out is None:
            continue
        s = out.strip()
        if "revert" in s.lower():
            return _ZERO_ADDRESS
        m = re.search(r"0x[0-9a-fA-F]{40,}", s)
        if m:
            return "0x" + m.group(0)[-40:].lower()
    return None


def token_pair_reserves(chain, token_address):
    """Live reserves of the token's pair against the chain's
    wrapped native token, across the chain's known DEX
    factories. Returns {"reserve0", "reserve1", "pair",
    "factory", "observed_at", "source"} or None when no
    factory has a pair for the token (or every route failed).

    This is the evidence validate_candidate consumes as
    balances["token_pair_reserves"] for the mint-value gate:
    pair_reserves() alone only answers when the contract IS a
    pair; a mintable token usually is not - its pair is a
    different contract that the factory registry names."""
    chain = _CHAIN_ALIASES.get(chain, chain)
    dexes = DEX_PAIRS.get(chain)
    if not dexes or not token_address:
        return None
    import datetime as _dt
    for factory, wrapped in dexes:
        if token_address.lower() == wrapped.lower():
            continue
        pair = None
        for a, b in ((token_address, wrapped),
                     (wrapped, token_address)):
            got = _call_address(
                chain, factory, "getPair(address,address)(address)",
                (a, b))
            if got is None:
                break  # transport failure on this factory
            if got != _ZERO_ADDRESS:
                pair = got
                break
        if not pair:
            continue  # not on this factory; try the next
        reserves = pair_reserves(chain, pair)
        if reserves is None:
            continue
        return {"reserve0": reserves["reserve0"],
                "reserve1": reserves["reserve1"],
                "pair": pair,
                "factory": factory,
                "observed_at": reserves.get(
                    "observed_at") or _dt.datetime.now(
                        _dt.timezone.utc).isoformat(),
                "source": reserves.get("source", "")}
    return None


# Default arguments per parameter type, built from the canonical
# types sim._param_types extracts (arrays/tuples included).
# Returns None only when _param_types returns None (a named
# struct parameter, which cast cannot be given blind either).
def _cast_default(typ):
    node = sim._parse_type_str(typ)
    if node is None:
        return None
    kind = node[0]
    if kind == "array":
        elem = _cast_default(sim._node_str(node[1]))
        if elem is None:
            return None
        if node[2] is None:
            return "[]"
        return "[" + ",".join([elem] * node[2]) + "]"
    if kind == "tuple":
        parts = []
        for member in node[1]:
            d = _cast_default(sim._node_str(member))
            if d is None:
                return None
            parts.append(d)
        return "(" + ",".join(parts) + ")"
    name = node[1]
    if name == "address":
        return STRANGER
    if name.startswith("uint") or name.startswith("int"):
        return "0"
    if name == "bool":
        return "false"
    if name == "bytes":
        return "0x"
    if name.startswith("bytes"):
        return "0x" + "00" * int(name[5:])
    if name == "string":
        return ""
    return None


def default_args(signature, address):
    types = sim._param_types(signature)
    if types is None:
        return None
    args = []
    for typ in types:
        d = _cast_default(typ)
        if d is None:
            return None
        args.append(d)
    return args


def _canonical_signature(head, function):
    """Canonical name(types) signature cast can parse, or None.

    sim._param_types canonicalizes ordinary signatures: it reads
    the first parenthesized group, so custom modifiers and
    returns clauses trailing the parameter list do not poison
    it. When it returns None, the usual cause is an
    interface-typed parameter (IERC20-style): at ABI level that
    is an address, so map bare interface identifiers to
    address. Anything else (named structs) stays
    uncanonicalizable -> None, and the caller keeps the raw
    head (default_args then declines and the probe is skipped,
    honestly, instead of failing inside cast).
    """
    types = sim._param_types(head)
    if types is not None:
        return sim.canonical_signature(function, types)
    from app.plugins import crypto_drain as cd
    i = head.find("(")
    if i < 0:
        return None
    inner = head[i + 1:cd._matching(head, i)]
    types = []
    for part in cd._split_top(inner):
        toks = part.strip().split()
        if not toks:
            continue
        t = toks[0]
        if re.fullmatch(r"I?[A-Z][A-Za-z0-9_]*", t):
            types.append("address")
        else:
            return None
    return sim.canonical_signature(function, types)


def function_scope(source, function, contract_name=""):
    """Where the flagged function lives: "scoped" (the deployed
    contract or its ancestors), "compilation_only" (a bundled
    sibling contract in the same verified compilation), or
    "absent" (nowhere in the compilation)."""
    from app.plugins import contract_logic as cl
    scope = cl._Scope(source, contract_name)
    if any(fn["name"] == function and "{" in fn["text"]
           for fn in scope.functions):
        return "scoped"
    all_scope = cl._Scope(source, "")
    if any(fn["name"] == function and "{" in fn["text"]
           for fn in all_scope.functions):
        return "compilation_only"
    return "absent"


def signature_of(source, function, contract_name=""):
    """Canonical signature of a function from verified source."""
    from app.plugins import contract_logic as cl
    scope = cl._Scope(source, contract_name)
    matches = [fn for fn in scope.functions
               if fn["name"] == function and "{" in fn["text"]]
    if not matches:
        # Fall back to the whole compilation so a probe can
        # still be built for a bundled-sibling function; pair
        # with function_scope() to mark it out of scope.
        scope = cl._Scope(source, "")
        matches = [fn for fn in scope.functions
                   if fn["name"] == function
                   and "{" in fn["text"]]
    # Prefer the external entry point over an internal/private
    # same-named definition (same rule as the engine's _find_fn).
    matches.sort(key=lambda fn: bool(
        re.search(r"\b(internal|private)\b", fn["signature"])))
    for fn in matches:
        sig = fn["signature"]
        head = sig[:sig.index("{")] if "{" in sig else sig
        head = head.replace("function ", "").strip()
        for kw in (" public", " external", " internal",
                   " private", " payable", " view", " pure"):
            head = head.replace(kw, "")
        head = " ".join(head.split())
        canon = _canonical_signature(head, function)
        return (canon if canon is not None else head), fn
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("candidates")
    ap.add_argument("--src-cache", default="")
    ap.add_argument("--out", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-probe", action="store_true")
    args = ap.parse_args()

    rows = [json.loads(l) for l in open(args.candidates)
            if l.strip()]
    if args.limit:
        rows = rows[:args.limit]
    out_f = open(args.out, "w") if args.out else sys.stdout
    counts = {}
    for row in rows:
        cand = {
            "address": row.get("address", ""),
            "chain": row.get("chain", ""),
            "function": row.get("function", ""),
            "kind": row.get("kind") or row.get("class", ""),
            "authority_class": bool(row.get("authority_class")),
            "recipient_override": row.get("recipient_override"),
            "entitlement_metered": bool(
                row.get("entitlement_metered")),
        }
        src = load_cached_source(args.src_cache, cand["chain"],
                                 cand["address"]) or \
            fetch_sourcify(cand["chain"], cand["address"])
        if src:
            cand["source"] = src["source"]
            cand["contract_name"] = src.get("contract_name", "")
            cand["source_origin"] = src.get("origin", "")
        if src and cand["function"] and not args.no_probe:
            if function_scope(src["source"], cand["function"],
                              cand["contract_name"]) == \
                    "compilation_only":
                cand["function_out_of_scope"] = True
            sig, _fn = signature_of(src["source"], cand["function"],
                                    cand["contract_name"])
            if sig:
                pargs = default_args(sig, cand["address"])
                if pargs is not None:
                    cand["probe"] = probe_function(
                        cand["chain"], cand["address"], sig, pargs)
                else:
                    cand["probe_note"] = (
                        "probe arguments not encodable by the "
                        "runner (non-static parameter types)")
            cand["balances"] = native_balance(cand["chain"],
                                              cand["address"])
            cand["balances"]["token_self_wei"] = \
                token_self_balance(cand["chain"], cand["address"])
            reserves = pair_reserves(cand["chain"], cand["address"])
            if reserves is not None:
                cand["balances"]["amm_reserves"] = reserves
            else:
                pair_res = token_pair_reserves(cand["chain"],
                                               cand["address"])
                if pair_res is not None:
                    cand["balances"]["token_pair_reserves"] = \
                        pair_res
        verdict = validate_candidate(cand)
        verdict["symbol"] = row.get("symbol", "")
        verdict["source_origin"] = cand.get("source_origin", "")
        if cand.get("probe_note"):
            verdict["probe_note"] = cand["probe_note"]
        counts[verdict["verdict"]] = \
            counts.get(verdict["verdict"], 0) + 1
        out_f.write(json.dumps(verdict) + "\n")
        out_f.flush()
    print(json.dumps({"rows": len(rows), "verdicts": counts}),
          file=sys.stderr)


if __name__ == "__main__":
    main()
