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
transaction is ever sent on a live chain. The fork-delta check
sends one transaction on a local anvil fork only (play money,
gas price 0), as an additional necessary condition for a
VERIFIED_REAL stamp. Rows whose evidence cannot be gathered
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
    _caller_metered, validate_candidate  # noqa: E402
from app.plugins.inline_gates import GATE_CALLER_METERED, \
    GATE_SELF_FUNDED, gate_candidate, gate_verdict  # noqa: E402
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
        # cast prints uints decimal ("0") or 0x-prefixed; the old
        # code only parsed 0x, so every token read silently
        # returned None. Parse either (2026-11-14 fix).
        tok = s.splitlines()[0].split()[0]
        try:
            return int(tok, 0)
        except Exception:
            return None
    return None


def token_self_balance(chain, address):
    """balanceOf(address) of the contract on itself: the live
    bound for a payout denominated in its own token. None when
    not an ERC20 or unreachable."""
    return _call_uint(chain, address, "balanceOf(address)(uint256)",
                      (address,))


def decisive_probe(chain, address, signature, balances):
    """The measured-receipt probe (mirror of the plugin lane):
    one read-only cast call per integer amount slot at a
    NONZERO amount the stranger provably cannot self-fund -
    one more than the largest funding balance measured for
    the stranger (native + the contract's own token), capped
    at the contract's measured bound. A caller-funded path
    cannot complete that call; a contract-funded payout can,
    which proves the payout at that amount is payable to the
    stranger. Returns the decisive record or None when no
    decisive case can be constructed."""
    types = sim._param_types(signature)
    if types is None:
        return None
    slots = [i for i, t in enumerate(types)
             if t.startswith(("uint", "int"))
             and "[" not in t and "(" not in t]
    if not slots:
        return None
    funding = [balances[k] for k in
               ("stranger_native_wei", "stranger_token_self_wei")
               if balances.get(k) is not None]
    if not funding:
        return None
    bounds = [balances[k] for k in
              ("native_wei", "token_self_wei")
              if balances.get(k) is not None]
    bound = max(bounds) if bounds else 0
    if bound <= 0:
        return None
    amount = min(max(funding) + 1, bound)
    base = default_args(signature, address)
    if base is None:
        return None
    result = {"status": "transport_error",
              "detail": "no decisive case ran", "amount": amount}
    for i in slots:
        pargs = list(base)
        pargs[i] = str(amount)
        res = probe_function(chain, address, signature, pargs)
        if res.get("status") == "success":
            return {"status": "success", "amount": amount,
                    "slot": i, "via": res.get("via", ""),
                    "detail": res.get("detail", "")[:120]}
        if res.get("status") == "revert":
            result = {"status": "revert", "amount": amount,
                      "slot": i, "via": res.get("via", ""),
                      "detail": res.get("detail", "")[:120]}
    return result


ANVIL = os.path.expanduser("~/workspace/tools/audit/bin/anvil")

# Fork URLs proven to serve eth_getProof at explicit blocks.
# Anvil's fork execution fetches proofs at the fork block; the
# publicnode free tier rejects those as archive requests, so the
# chain's first-listed public RPCs cannot fork from this VM.
# Overrides are tried first, in order, then the chain's
# configured public RPCs. (Proven 2026-11-14: BSC forks from
# blastapi; publicnode 429s on genesis and 403s proofs.)
FORK_URL_OVERRIDES = {
    "bsc": ["https://bsc-mainnet.public.blastapi.io"],
    # Cronos (2026-11-15 fix-zero-verified): no override proven to
    # serve eth_getProof at explicit blocks yet; evm.cronos.org is
    # the live-verified primary, publicnode is the second RPC.
    # The fork loop tries overrides first, then the chain RPCs.
    "cronos": ["https://evm.cronos.org"],
}


def _free_port():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fork_uint(rpc, address, signature, args=()):
    out, _err = _cast(["call", "--rpc-url", rpc, address, signature,
                       *args], timeout=20)
    if out is None:
        return None
    s = out.strip()
    if "revert" in s.lower() or not s:
        return None
    # cast prints uints decimal ("0") or 0x-prefixed; parse either.
    tok = s.splitlines()[0].split()[0]
    try:
        return int(tok, 0)
    except Exception:
        return None


def _fork_balance(rpc, address):
    out, _err = _cast(["balance", "--rpc-url", rpc, address],
                      timeout=20)
    if out is None:
        return None
    try:
        return int(out.strip().splitlines()[0])
    except Exception:
        return None


def fork_balance_delta(chain, address, signature, args,
                       token_address=None, timeout_s=150):
    """Forked-state balance-delta check (2026-11-14 balance-delta bar).

    Executes the flagged function on a local anvil fork as the
    impersonated unfunded stranger (gas price 0, so the measured
    deltas are exact - no gas correction needed) and asserts
    balanceOf(stranger) increases AND balanceOf(contract)
    decreases by the SAME amount, in the same denomination
    (native, or the target's own token). The call is made FROM
    the stranger, so a proved delta asserts the recipient is the
    probe address by construction.

    A live eth_call succeeding proves the path executes, not that
    value moves (MVK claimReward: eth_call returns 0x, fork
    execution moves 0). This check is an ADDITIONAL necessary
    condition for VERIFIED_REAL, never a substitute for the live
    probe or the source read: sim-only still cannot mint
    VERIFIED_REAL, and a fork failure demotes to UNVERIFIED
    (infra) or FALSE_POSITIVE (measured zero), never to a stamp.

    Returns a dict with status delta_proved | zero_delta |
    revert | unavailable, the measured before/after balances,
    the fork URL + block, and the tx receipt fields. The fork is
    local only: no transaction is ever sent on a live chain.
    """
    import tempfile
    import time as _time
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return {"ran": False, "status": "unavailable",
                "detail": f"unknown chain {chain}"}
    token = token_address or address
    urls = list(FORK_URL_OVERRIDES.get(chain, [])) + \
        list(cfg.rpc_urls)
    last_detail = "no fork URL tried"
    # Pin the fork to the live head (2026-11-15 fix-zero-verified):
    # this Anvil build requires --fork-block-number whenever
    # --fork-chain-id is passed, and a pinned fork is reproducible.
    # One lookup up front; if it fails, fall back to the unpinned
    # invocation below.
    live_block = None
    for _u in urls[:3]:
        _out, _e = _cast(["block-number", "--rpc-url", _u], timeout=10)
        if _out and _out.strip():
            try:
                live_block = int(_out.strip(), 0)
                break
            except Exception:
                pass
    for url in urls[:3]:
        port = _free_port()
        rpc = f"http://127.0.0.1:{port}"
        err_f = tempfile.NamedTemporaryFile(
            mode="w+", suffix=".log", delete=False)
        proc = None
        try:
            anvil_args = [ANVIL, "--fork-url", url, "--port", str(port),
                          "--silent", "--accounts", "1", "--retries", "5",
                          "--gas-price", "0"]
            if live_block is not None:
                anvil_args += ["--fork-chain-id", str(cfg.chain_id),
                               "--fork-block-number", str(live_block)]
            proc = subprocess.Popen(
                anvil_args,
                stdout=subprocess.DEVNULL, stderr=err_f,
                start_new_session=True)
            deadline = _time.monotonic() + 75
            ready = False
            fork_block = None
            while _time.monotonic() < deadline:
                if proc.poll() is not None:
                    break
                out, _e = _cast(["block-number", "--rpc-url", rpc],
                                timeout=10)
                if out and out.strip():
                    # cast prints the block number decimal (or
                    # 0x-prefixed); int(x, 0) parses either.
                    try:
                        fork_block = int(out.strip(), 0)
                        ready = True
                        break
                    except Exception:
                        pass
                _time.sleep(2)
            if not ready:
                err_f.seek(0)
                last_detail = (f"fork from {url} never became "
                               f"ready: {err_f.read()[-300:]}")
                continue
            sb = _fork_balance(rpc, STRANGER)
            cb = _fork_balance(rpc, address)
            stb = _fork_uint(rpc, token,
                             "balanceOf(address)(uint256)",
                             (STRANGER,))
            ctb = _fork_uint(rpc, token,
                             "balanceOf(address)(uint256)",
                             (address,))
            if sb is None or cb is None:
                last_detail = (f"fork from {url}: balance reads "
                               "failed before execution")
                continue
            _cast(["rpc", "anvil_impersonateAccount", STRANGER,
                   "--rpc-url", rpc], timeout=15)
            # 2026-11-15 fix-zero-verified: Cronos (and other
            # EIP-1559 chains) forks with a nonzero base fee, so a
            # gas-price-0 send is rejected ("max fee per gas less
            # than block base fee"). Zero the next block's base fee
            # so gas-price-0 sends land and the measured deltas stay
            # exact (no gas correction needed). Harmless on chains
            # whose base fee is already 0; failures here are ignored
            # and surface as a send failure below.
            _cast(["rpc", "anvil_setNextBlockBaseFeePerGas", "0",
                   "--rpc-url", rpc], timeout=15)
            out, _e = _cast(
                ["send", "--from", STRANGER, "--unlocked",
                 "--gas-limit", "500000", "--gas-price", "0",
                 "--priority-gas-price", "0", "--rpc-url", rpc,
                 address, signature, *args], timeout=60)
            if out is None:
                last_detail = (f"fork from {url}: cast send "
                               "produced no output")
                continue
            low = out.lower()
            tx_hash = None
            m = re.search(r"transactionHash\s+(0x[0-9a-fA-F]+)", out)
            if m:
                tx_hash = m.group(1)
            base = {"ran": True, "recipient": STRANGER,
                    "via": "anvil fork + cast send (impersonated "
                           "stranger, gas price 0)",
                    "fork_url": url, "fork_block": fork_block,
                    "tx_hash": tx_hash,
                    "stranger_before": {"native_wei": sb,
                                        "token_wei": stb},
                    "contract_before": {"native_wei": cb,
                                        "token_wei": ctb}}
            if "revert" in low or "execution reverted" in low:
                sa = _fork_balance(rpc, STRANGER)
                ca = _fork_balance(rpc, address)
                base.update({
                    "status": "revert",
                    "detail": out.strip()[-300:],
                    "stranger_after": {"native_wei": sa,
                                       "token_wei": None},
                    "contract_after": {"native_wei": ca,
                                       "token_wei": None}})
                return base
            if tx_hash:
                # 2026-11-15 fix-zero-verified: a reverted tx still
                # lands with a receipt, and cast send does not print
                # the word "revert" for it - the WCRO withdraw probe
                # landed with receipt status 0 and was misread as
                # zero_delta (FALSE_POSITIVE) instead of revert
                # (UNVERIFIED). Check the receipt status directly.
                _rout, _re = _cast(["receipt", "--rpc-url", rpc,
                                    tx_hash], timeout=20)
                if _rout and re.search(r"status\s+(0|0x0)\b", _rout):
                    sa = _fork_balance(rpc, STRANGER)
                    ca = _fork_balance(rpc, address)
                    base.update({
                        "status": "revert",
                        "detail": f"forked tx {tx_hash} reverted "
                                  f"(receipt status 0)",
                        "stranger_after": {"native_wei": sa,
                                           "token_wei": None},
                        "contract_after": {"native_wei": ca,
                                           "token_wei": None}})
                    return base
            if "blockhash" not in low and "transactionhash" not in low:
                last_detail = (f"fork from {url}: send did not "
                               f"land a tx: {out.strip()[-200:]}")
                continue
            sa = _fork_balance(rpc, STRANGER)
            ca = _fork_balance(rpc, address)
            sta = _fork_uint(rpc, token,
                             "balanceOf(address)(uint256)",
                             (STRANGER,))
            cta = _fork_uint(rpc, token,
                             "balanceOf(address)(uint256)",
                             (address,))
            base.update({
                "stranger_after": {"native_wei": sa,
                                   "token_wei": sta},
                "contract_after": {"native_wei": ca,
                                   "token_wei": cta}})
            if sa is None or ca is None:
                last_detail = (f"fork from {url}: balance reads "
                               "failed after execution")
                continue
            n_stranger = sa - sb
            n_contract = cb - ca
            if n_stranger > 0 and n_stranger == n_contract:
                base.update({"status": "delta_proved",
                             "denomination": "native",
                             "delta_wei": n_stranger})
                return base
            if (sta is not None and ctb is not None
                    and cta is not None):
                t_stranger = sta - (stb or 0)
                t_contract = ctb - cta
                if t_stranger > 0 and t_stranger == t_contract:
                    base.update({"status": "delta_proved",
                                 "denomination": "token",
                                 "delta_wei": t_stranger})
                    return base
                if t_stranger > 0 and t_contract == 0:
                    # 2026-11-15 fix-zero-verified: issuance (mint).
                    # A mint creates new supply for the stranger, so
                    # the contract's own-token balance does NOT fall
                    # - the transfer condition above can never fire
                    # for a mint, and every mint candidate that
                    # reached the fork bar was misread as zero_delta
                    # (FALSE_POSITIVE). A measured increase in the
                    # stranger's token balance with no corresponding
                    # fall in the contract's is a proved receipt of
                    # issuance; the validator's mint branch still
                    # requires live token-value evidence before any
                    # VERIFIED_REAL stamp.
                    base.update({"status": "delta_proved",
                                 "denomination": "token-mint",
                                 "delta_wei": t_stranger,
                                 "kind": "issuance"})
                    return base
            base.update({"status": "zero_delta",
                         "denomination": None, "delta_wei": 0,
                         "detail": "forked-state execution "
                                   "succeeded but moved 0 to the "
                                   "stranger and 0 from the "
                                   "contract"})
            return base
        except Exception as e:  # noqa: BLE001
            last_detail = f"fork from {url} errored: {str(e)[:200]}"
            continue
        finally:
            if proc is not None:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            try:
                err_f.close()
            except Exception:
                pass
    return {"ran": False, "status": "unavailable",
            "detail": last_detail[:400]}


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


def _basis_read(chain, address, signature):
    """One read-only uint256 call for the gate's basis
    confirmation, or None when unreadable / reverting.

    Uses _cast directly with a decimal-or-hex first-token
    parse: this cast build prints annotated uint returns in
    decimal ("0", "12345 [1.2e4]"), which _call_uint's
    hex-only parse cannot read - with _call_uint the stranger
    basis would always come back None and the caller-metered
    fast path could never fire. Kept local to the gate so
    validator v2's own gather semantics are unchanged.
    """
    cfg = cc.CHAINS.get(chain)
    if cfg is None:
        return None
    for rpc in cfg.rpc_urls:
        out, _err = _cast(["call", "--from", STRANGER,
                           "--rpc-url", rpc, address, signature,
                           STRANGER], timeout=15)
        if out is None:
            continue
        s = out.strip()
        if not s or "revert" in s.lower():
            return None
        tok = s.splitlines()[0].split()[0]
        try:
            return int(tok, 16) if tok.startswith("0x") \
                else int(tok)
        except (ValueError, IndexError):
            continue
    return None


def _inline_gate_row(cand, no_probe):
    """Inline static gate fast path (app.plugins.inline_gates).

    Returns a finished verdict row when the static gates settle
    the candidate, else None (fall through to the full evidence
    gather + validator v2, untouched). GATED_SELF_FUNDED needs
    no live read. GATED_CALLER_METERED is confirmed with the
    single basis read of the unfunded stranger (balanceOf or
    the caller-keyed mapping getter) instead of the probe
    suite; a nonzero or unreadable basis falls through.
    """
    gr = gate_candidate(cand)
    if gr["gate"] == GATE_SELF_FUNDED:
        return gate_verdict(cand, gr)
    if gr["gate"] == GATE_CALLER_METERED and not no_probe:
        basis = gr.get("basis") or {}
        if basis.get("basis") == "token_self":
            sig = "balanceOf(address)(uint256)"
        elif basis.get("name"):
            sig = str(basis["name"]) + "(address)(uint256)"
        else:
            return None
        val = _basis_read(cand["chain"], cand["address"], sig)
        if val is not None and int(val) == 0:
            return gate_verdict(cand, gr,
                                basis_measured_zero=True)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("candidates")
    ap.add_argument("--src-cache", default="")
    ap.add_argument("--out", default="")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--inline-gates", action="store_true",
                    help="run the inline static gates before "
                         "the evidence gather; gated shapes "
                         "skip the live probe suite")
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
        verdict = None
        if args.inline_gates and src and cand["function"]:
            verdict = _inline_gate_row(cand, args.no_probe)
        if src and cand["function"] and not args.no_probe \
                and verdict is None:
            if function_scope(src["source"], cand["function"],
                              cand["contract_name"]) == \
                    "compilation_only":
                cand["function_out_of_scope"] = True
            sig, _fn = signature_of(src["source"], cand["function"],
                                    cand["contract_name"])
            cand["balances"] = native_balance(cand["chain"],
                                              cand["address"])
            cand["balances"]["token_self_wei"] = \
                token_self_balance(cand["chain"], cand["address"])
            # The stranger's own measured funding: the funding
            # bound for the decisive probe, and the basis for a
            # caller-metered payout.
            cand["balances"]["stranger_native_wei"] = \
                native_balance(cand["chain"],
                               STRANGER)["native_wei"]
            cand["balances"]["stranger_token_self_wei"] = \
                _call_uint(cand["chain"], cand["address"],
                           "balanceOf(address)(uint256)",
                           (STRANGER,))
            if _fn is not None:
                metered = _caller_metered(_fn)
                if metered and metered["basis"] == "mapping":
                    name = str(metered.get("name"))
                    cand["balances"][
                        "stranger_mapping_" + name + "_wei"] = \
                        _call_uint(
                            cand["chain"], cand["address"],
                            name + "(address)(uint256)",
                            (STRANGER,))
            if sig:
                pargs = default_args(sig, cand["address"])
                if pargs is not None:
                    cand["probe"] = probe_function(
                        cand["chain"], cand["address"], sig, pargs)
                else:
                    cand["probe_note"] = (
                        "probe arguments not encodable by the "
                        "runner (non-static parameter types)")
                if cand.get("probe", {}).get("status") == \
                        "success":
                    decisive = decisive_probe(
                        cand["chain"], cand["address"], sig,
                        cand["balances"])
                    if decisive is not None:
                        cand["decisive_probe"] = decisive
                    # Balance-delta bar (2026-11-14): same call on
                    # a local fork as the stranger; VERIFIED_REAL
                    # requires a proved balance delta.
                    if pargs is not None:
                        try:
                            cand["fork_delta"] = fork_balance_delta(
                                cand["chain"], cand["address"], sig,
                                pargs)
                        except Exception as e:  # noqa: BLE001
                            cand["fork_delta"] = {
                                "ran": False, "status": "unavailable",
                                "detail": f"fork check errored: "
                                          f"{str(e)[:200]}"}
            reserves = pair_reserves(cand["chain"], cand["address"])
            if reserves is not None:
                cand["balances"]["amm_reserves"] = reserves
            else:
                pair_res = token_pair_reserves(cand["chain"],
                                               cand["address"])
                if pair_res is not None:
                    cand["balances"]["token_pair_reserves"] = \
                        pair_res
        if verdict is None:
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
