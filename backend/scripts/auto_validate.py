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
import subprocess
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from app.plugins.auto_validator import STRANGER, \
    validate_candidate  # noqa: E402
from app.plugins import contract_chain as cc  # noqa: E402

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


# Default/boundary arguments per static parameter type. Anything
# else (arrays, tuples, strings, bytes) is not encodable here and
# the probe is skipped - the engine reports the missing probe.
def default_args(signature, address):
    try:
        inner = signature[signature.index("(") + 1:
                          signature.rindex(")")]
    except ValueError:
        return None
    if not inner.strip():
        return []
    args = []
    for part in inner.split(","):
        t = part.strip().split()[0] if part.strip() else ""
        if t == "address":
            args.append(STRANGER)
        elif t.startswith("uint") or t.startswith("int"):
            args.append("0")
        elif t == "bool":
            args.append("false")
        elif t == "bytes32":
            args.append("0x" + "00" * 32)
        else:
            return None
    return args


def signature_of(source, function, contract_name=""):
    """Canonical signature of a function from verified source."""
    from app.plugins import contract_logic as cl
    scope = cl._Scope(source, contract_name)
    for fn in scope.functions:
        if fn["name"] == function and "{" in fn["text"]:
            sig = fn["signature"]
            head = sig[:sig.index("{")] if "{" in sig else sig
            head = head.replace("function ", "").strip()
            for kw in (" public", " external", " internal",
                       " private", " payable", " view", " pure"):
                head = head.replace(kw, "")
            head = " ".join(head.split())
            return head, fn
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
