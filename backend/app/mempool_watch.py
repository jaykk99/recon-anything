"""Mempool fresh-deploy interceptor (2026-11-09, Jay's order).

READ-ONLY detection lane. It polls the pending block of each EVM
chain through the same keyless public RPC pools the sweep uses
(recon-million fetch_api.POOLS patterns, copied below), extracts
contract-creation transactions, predicts the contract address,
screens the deployment bytecode through the Tier-1 plugin pass,
runs flagged functions through the inline static gates, and
appends surviving candidates to a JSONL queue the deep lane can
pick up value-first once the contract is mined and funded.

Hard limits, by construction:

- Nothing is ever broadcast. The only network calls are JSON-RPC
  reads (eth_getBlockByNumber, eth_getCode, eth_getBalance).
  No transaction is built, signed, or submitted, and nothing in
  this module front-runs: it watches, screens, and queues.
- Keyless only. If a chain's public endpoints cannot serve a
  pending block, the watcher records that per chain and moves
  on; it never reaches for a keyed service.
- Screening output is candidates only (UNVERIFIED). This lane
  never stamps VERIFIED_REAL; live-probe verification stays
  with validator v2 exactly as before.
- The Tier-1 screen runs fully offline on pre-seeded bytecode
  (blocked HTTP transport), mirroring bench/tier1_runner.py, so
  plugins cannot turn the screen into network traffic.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .plugins.cryptopack_util import keccak256

# ---------------------------------------------------------------------------
# Keyless public RPC pools (same endpoints/patterns as the sweep's
# fetch_api.POOLS; batch sizes dropped - this lane makes single reads).
# ---------------------------------------------------------------------------
POOLS: Dict[str, List[str]] = {
    "ethereum": [
        "https://ethereum-rpc.publicnode.com",
        "https://rpc.mevblocker.io",
        "https://eth-mainnet.public.blastapi.io",
    ],
    "bsc": [
        "https://bsc-dataseed.binance.org",
        "https://bsc-mainnet.public.blastapi.io",
        "https://bsc-rpc.publicnode.com",
        "https://1rpc.io/bnb",
    ],
    "polygon": [
        "https://polygon-bor-rpc.publicnode.com",
    ],
    "arbitrum": [
        "https://arbitrum-one-rpc.publicnode.com",
        "https://arb1.arbitrum.io/rpc",
    ],
    "base": [
        "https://base-rpc.publicnode.com",
        "https://mainnet.base.org",
        "https://base-mainnet.public.blastapi.io",
    ],
    "optimism": [
        "https://optimism-rpc.publicnode.com",
        "https://mainnet.optimism.io",
    ],
}

CHAINS = tuple(POOLS.keys())

# Rough native-amount priority thresholds (configurable). USD is
# deliberately left unpriced: no price feed is wired into this
# lane, so rows record the native balance and usd=None rather
# than an invented dollar figure.
DEFAULT_PRIORITY_NATIVE_WEI: Dict[str, int] = {
    "ethereum": 50 * 10**18,
    "base": 50 * 10**18,
    "arbitrum": 50 * 10**18,
    "optimism": 50 * 10**18,
    "bsc": 150 * 10**18,
    "polygon": 250_000 * 10**18,
}


class RpcUnavailable(Exception):
    """Every pool endpoint for the chain failed the call."""


class RpcPool:
    """Minimal sync JSON-RPC reader with failover + cooldown.

    Read methods only. Endpoints that error are cooled down and
    skipped until the cooldown expires, mirroring the sweep's
    pool behaviour at single-call scale.
    """

    def __init__(self, pools: Optional[Dict[str, List[str]]] = None,
                 timeout: float = 20.0, cooldown_s: float = 60.0):
        self.pools = pools or POOLS
        self.timeout = timeout
        self.cooldown_s = cooldown_s
        self._down_until: Dict[str, float] = {}
        self._next_id = 0
        self.stats: Dict[str, Dict[str, int]] = {}

    def _stat(self, chain: str, key: str) -> None:
        self.stats.setdefault(chain, {"calls": 0, "errors": 0})
        self.stats[chain][key] += 1

    def call(self, chain: str, method: str, params: Sequence[Any]) -> Any:
        urls = self.pools.get(chain)
        if not urls:
            raise RpcUnavailable(f"no pool for chain {chain!r}")
        last_err: Optional[Exception] = None
        now = time.time()
        for url in urls:
            if self._down_until.get(url, 0.0) > now:
                continue
            self._next_id += 1
            body = json.dumps({
                "jsonrpc": "2.0", "id": self._next_id,
                "method": method, "params": list(params),
            }).encode()
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json",
                         "User-Agent": "recon-mempool-watch/1.0"})
            self._stat(chain, "calls")
            try:
                with urllib.request.urlopen(
                        req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode())
            except Exception as e:  # noqa: BLE001 - failover by design
                last_err = e
                self._stat(chain, "errors")
                self._down_until[url] = time.time() + self.cooldown_s
                continue
            if isinstance(payload, dict) and payload.get("error"):
                last_err = RpcUnavailable(str(payload["error"])[:200])
                self._stat(chain, "errors")
                self._down_until[url] = time.time() + self.cooldown_s
                continue
            return payload.get("result") if isinstance(payload, dict) \
                else None
        raise RpcUnavailable(
            f"{chain} {method}: all endpoints failed ({last_err})")

    def pending_block(self, chain: str) -> Optional[Dict[str, Any]]:
        """Full pending block, or None if the pools cannot serve it."""
        result = self.call(chain, "eth_getBlockByNumber",
                           ["pending", True])
        return result if isinstance(result, dict) else None

    def get_code(self, chain: str, address: str) -> str:
        return self.call(chain, "eth_getCode", [address, "latest"]) or "0x"

    def get_balance(self, chain: str, address: str) -> int:
        raw = self.call(chain, "eth_getBalance", [address, "latest"])
        return int(raw, 16) if isinstance(raw, str) else 0


# ---------------------------------------------------------------------------
# CREATE address prediction: keccak256(rlp([sender, nonce]))[12:]
# ---------------------------------------------------------------------------

def _rlp_encode(item: Any) -> bytes:
    if isinstance(item, int):
        if item == 0:
            return _rlp_encode(b"")
        raw = item.to_bytes((item.bit_length() + 7) // 8, "big")
        return _rlp_encode(raw)
    if isinstance(item, (bytes, bytearray)):
        data = bytes(item)
        if len(data) == 1 and data[0] < 0x80:
            return data
        if len(data) <= 55:
            return bytes([0x80 + len(data)]) + data
        lb = len(data).to_bytes((len(data).bit_length() + 7) // 8, "big")
        return bytes([0xB7 + len(lb)]) + lb + data
    if isinstance(item, (list, tuple)):
        payload = b"".join(_rlp_encode(x) for x in item)
        if len(payload) <= 55:
            return bytes([0xC0 + len(payload)]) + payload
        lb = len(payload).to_bytes(
            (len(payload).bit_length() + 7) // 8, "big")
        return bytes([0xF7 + len(lb)]) + lb + payload
    raise TypeError(f"cannot RLP-encode {type(item)}")


def predict_create_address(sender: str, nonce: int) -> str:
    """The address a CREATE from `sender` at `nonce` will land at."""
    sender_bytes = bytes.fromhex(sender.lower().removeprefix("0x"))
    if len(sender_bytes) != 20:
        raise ValueError("sender must be a 20-byte address")
    digest = keccak256(_rlp_encode([sender_bytes, int(nonce)]))
    return "0x" + digest[12:].hex()


# ---------------------------------------------------------------------------
# Pending-block creation extraction + init-code handling
# ---------------------------------------------------------------------------

def _is_creation(tx: Dict[str, Any]) -> bool:
    to = tx.get("to")
    return to is None or to == "" or \
        to.lower() in ("0x", "0x0", "0x0000000000000000000000000000000000000000")


def extract_creations(block: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Contract-creation txs out of a full pending block."""
    if not block:
        return []
    out: List[Dict[str, Any]] = []
    for tx in block.get("transactions") or []:
        if not isinstance(tx, dict) or not _is_creation(tx):
            continue
        inp = tx.get("input") or "0x"
        sender = (tx.get("from") or "").lower()
        nonce_raw = tx.get("nonce") or "0x0"
        try:
            nonce = int(nonce_raw, 16) if isinstance(nonce_raw, str) \
                else int(nonce_raw)
        except (TypeError, ValueError):
            continue
        if not sender:
            continue
        try:
            address = predict_create_address(sender, nonce)
        except (ValueError, TypeError):
            continue
        out.append({
            "tx_hash": (tx.get("hash") or "").lower(),
            "deployer": sender,
            "nonce": nonce,
            "address": address,
            "input": inp,
            "init_code_bytes": max(0, (len(inp) - 2) // 2),
            "value_wei": int(tx.get("value") or "0x0", 16)
            if isinstance(tx.get("value"), str) else 0,
        })
    return out


def _decode_pushes_before(code: bytes, pos: int, count: int) -> List[int]:
    """Decode the operands of the `count` PUSH instructions that
    immediately precede byte offset `pos` (best effort)."""
    operands: List[int] = []
    i = pos
    while len(operands) < count and i > 0:
        # walk backwards is unreliable; instead scan forward from a
        # window start and keep the last `count` pushes before pos.
        break
    start = max(0, pos - 64)
    j = start
    pushes: List[Tuple[int, int]] = []  # (offset, value)
    while j < pos:
        op = code[j]
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            n = op - 0x5F
            val = int.from_bytes(code[j + 1:j + 1 + n], "big") \
                if j + 1 + n <= len(code) else 0
            pushes.append((j, val))
            j += 1 + n
        else:
            j += 1
    operands = [v for _, v in pushes[-count:]]
    return operands


def extract_runtime_code(init_code: bytes) -> Optional[bytes]:
    """Best-effort runtime-code extraction from solc-style init code.

    The standard init stub CODECOPYs the runtime segment out of
    its own tail and RETURNs it: PUSH len, PUSH off, PUSH 0,
    CODECOPY(0x39) ... PUSH len, PUSH 0, RETURN(0xf3). We locate
    a CODECOPY whose decoded (offset, length) fits inside the
    init code and whose segment is followed by a matching
    RETURN. Returns None when the shape is not recognised; the
    caller then screens the init code as-is.
    """
    if not init_code or len(init_code) < 16:
        return None
    for pos in range(len(init_code)):
        if init_code[pos] != 0x39:  # CODECOPY
            continue
        ops = _decode_pushes_before(init_code, pos, 3)
        if len(ops) < 3:
            continue
        # pushes land in reverse stack order: len, off, dest
        length, offset = ops[0], ops[1]
        if length <= 0 or offset <= 0:
            continue
        if offset + length > len(init_code) or offset >= len(init_code):
            continue
        segment = init_code[offset:offset + length]
        if len(segment) == length and segment:
            return segment
    return None


# ---------------------------------------------------------------------------
# Tier-1 screen (offline, mirrors bench/tier1_runner.py)
# ---------------------------------------------------------------------------

# The production Tier-1 plugin set: registry plugins accepting a
# crypto_wallet target, intersected with the sweep's strict list
# (bench/tier1_strict.json - 57 ids, 54 live on master). Kept as a
# constant so the lane has no dependency on sweep files at runtime.
TIER1_PLUGIN_IDS = (
    "abi_reconstructor", "access_control_scraper", "anvil_fork_probe",
    "bloxroute_stream", "bytecode_diff_viewer", "certora_rules",
    "chisel_repl_eval", "coingecko_price_validator",
    "constant_inliner_check", "contract_creator_osint",
    "contract_state_tracer", "create2_address_predictor",
    "dapp_state_sniffer", "defillama_tvl_verify",
    "dex_liquidity_depth_calc", "ens_reverse_lookup",
    "envis_bytecode", "erc20_compliance_verify",
    "erc721_metadata_guard", "ether_forcing_tester",
    "evm_decompiler_bridge", "evm_tracer",
    "fallback_behavior_analyzer", "flashbots_bundle_builder",
    "flashloan_simulator", "forge_inspect", "foundry_test_generator",
    "frontrunning_guard_eval", "ganache_timewarp_probe",
    "gas_opt_analyzer", "gas_pump_frontrunner",
    "gnosis_safe_multisig_audit", "halmos_symbolic",
    "hardhat_fork_config", "immutable_arg_extractor",
    "ipfs_gateway_resolver", "mev_tx_parser",
    "multicall_aggregator_decode", "oracle_drift_calc",
    "oyente_bytecode", "reentrancy_path_finder",
    "sandwich_attack_profiler", "scribble_annotations",
    "smartcheck_rules", "solana_contract", "solc_version_matcher",
    "solgraph_cfg", "solhint_lint", "stacks_contract",
    "storage_slot_mapper", "tally_proposal_decoder",
    "tenderly_trace_parser", "token_holder_cluster", "token_rugcheck",
    "unified_keyword_search", "vyper_bug_hunter", "yul_optimizer_audit",
)


class _DictCache:
    def __init__(self) -> None:
        self._d: Dict[str, Any] = {}

    def get(self, k: str, default: Any = None) -> Any:
        return self._d.get(k, default)

    def set(self, k: str, v: Any) -> None:
        self._d[k] = v


class Tier1Screener:
    """Runs the Tier-1 plugin pass over one contract's bytecode.

    engine="python" is the working default. engine="rust" tries
    app.engine_switch (the Rust fold-in) when that module exists
    on the branch and falls back to the Python pass when it does
    not - the switch is a drop-in, never a dependency.
    """

    def __init__(self, engine: str = "python"):
        self.engine = engine
        self._plugins: Optional[List[Tuple[str, Any]]] = None
        self._limiter: Any = None
        self._rust: Any = None
        self._rust_tried = False

    def _load_plugins(self) -> List[Tuple[str, Any]]:
        if self._plugins is not None:
            return self._plugins
        import httpx  # noqa: F401  (ensures transport deps import)
        from .plugins.registry import discover
        from .ratelimit import RateLimiter
        reg = discover()
        keep = set(TIER1_PLUGIN_IDS)
        plugins: List[Tuple[str, Any]] = []
        for pid in sorted(keep & set(reg.keys())):
            cls = reg[pid]
            accepts = getattr(cls, "accepts", []) or []
            if "crypto_wallet" not in accepts:
                continue
            try:
                plugins.append((pid, cls()))
            except Exception:  # noqa: BLE001 - a plugin that cannot
                continue          # construct is skipped, like the bench
        self._plugins = plugins
        self._limiter = RateLimiter(default_rps=1000)
        return plugins

    def _try_rust(self) -> Any:
        if self._rust_tried:
            return self._rust
        self._rust_tried = True
        try:
            from . import engine_switch  # type: ignore
            self._rust = engine_switch
        except Exception:  # noqa: BLE001 - switch not landed yet
            self._rust = None
        return self._rust

    async def _screen_python(self, chain: str, address: str,
                             code_hex: str) -> List[Dict[str, Any]]:
        import httpx
        from .plugins.base import Ctx, Target
        from .plugins import chain_data as cdata
        from .ratelimit import RateLimiter  # noqa: F401

        class _BlockedTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):  # noqa: ANN001
                raise httpx.ConnectError(
                    "network blocked in tier1 screen", request=request)

        plugins = self._load_plugins()
        http = httpx.AsyncClient(transport=_BlockedTransport(),
                                 timeout=5.0)
        ctx = Ctx(run_id="mempool-tier1", mode="passive", http=http,
                  cache=_DictCache(), keys={}, limiter=self._limiter,
                  shared={})
        code = code_hex if code_hex and code_hex != "0x" else None
        rec = cdata.ChainData(
            chain_id=chain, address=address.lower(),
            status=cdata.STATUS_NO_SOURCE if code
            else cdata.STATUS_NO_CODE,
            code_hex=code, source=None, balance_wei=None,
            fetched_at=time.time())
        ctx.shared[cdata._CACHE_KEY] = {f"{chain}:{address.lower()}": rec}
        raw = f"{chain}:{address}"
        target = Target(raw=raw, type="crypto_wallet", normalized=raw)
        flags: List[Dict[str, Any]] = []
        for pid, plugin in plugins:
            try:
                res = await plugin.run(target, ctx)
            except Exception:  # noqa: BLE001 - per-plugin isolation
                continue
            for f in (res.findings if res else []):
                flags.append({
                    "plugin": pid,
                    "key": str(getattr(f, "key", None)
                               or getattr(f, "title", "") or ""),
                    "function": str(getattr(f, "function", None) or ""),
                    "recipient_class": str(
                        getattr(f, "recipient_class", None) or ""),
                    "severity": str(getattr(f, "severity", "") or ""),
                })
        await http.aclose()
        return flags

    async def screen(self, chain: str, address: str,
                     code_hex: str) -> List[Dict[str, Any]]:
        if self.engine == "rust":
            rust = self._try_rust()
            if rust is not None and hasattr(rust, "run_tier1"):
                try:
                    return await rust.run_tier1(chain, address, code_hex)
                except Exception:  # noqa: BLE001 - fall back, never fail
                    pass
        return await self._screen_python(chain, address, code_hex)


# ---------------------------------------------------------------------------
# Inline gates over flagged candidates
# ---------------------------------------------------------------------------

def gate_flags(chain: str, address: str, flags: List[Dict[str, Any]],
               source: str = "",
               contract_name: str = "") -> List[Dict[str, Any]]:
    """Run each flagged function through the merged inline gates.

    Fresh deploys have no verified source at pending time, and the
    gates are source-level by construction, so a bytecode-only
    flag PASSes here with that reason recorded - never guessed
    at. When source is supplied (later enrichment), the same call
    can statically gate the self-funded / caller-metered shapes.
    """
    from .plugins.inline_gates import gate_candidate
    out: List[Dict[str, Any]] = []
    for flag in flags:
        candidate = {
            "chain": chain, "address": address,
            "function": flag.get("function") or "",
            "kind": flag.get("key") or "",
            "source": source, "contract_name": contract_name,
        }
        try:
            res = gate_candidate(candidate)
            out.append({**flag, "gate": res.get("gate"),
                        "gate_reason": res.get("reason")})
        except Exception as e:  # noqa: BLE001 - gates never crash the lane
            out.append({**flag, "gate": "PASS",
                        "gate_reason": f"gate error: {e}"[:200]})
    return out


def gate_summary(gated_flags: List[Dict[str, Any]]) -> str:
    gates = {f.get("gate") for f in gated_flags}
    if gates and gates <= {"GATED_SELF_FUNDED", "GATED_CALLER_METERED"}:
        return "gated_out"
    if "GATED_SELF_FUNDED" in gates or "GATED_CALLER_METERED" in gates:
        return "partially_gated"
    return "pass"


# ---------------------------------------------------------------------------
# Queue + checkpoint state
# ---------------------------------------------------------------------------

class QueueStore:
    """JSONL candidate queue with (chain, tx_hash)/(chain, address)
    dedupe and a JSON checkpoint state file in the same directory."""

    def __init__(self, out_dir: str):
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.queue_path = os.path.join(out_dir, "queue.jsonl")
        self.state_path = os.path.join(out_dir, "state.json")
        self.rows: List[Dict[str, Any]] = []
        self._by_tx: set = set()
        self._by_addr: set = set()
        self.state: Dict[str, Any] = {
            "chains": {}, "started_at": None, "polls": 0}
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.queue_path):
            with open(self.queue_path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self.rows.append(row)
                    self._by_tx.add((row["chain"], row["tx_hash"]))
                    self._by_addr.add((row["chain"],
                                       row["address"].lower()))
        if os.path.exists(self.state_path):
            try:
                with open(self.state_path) as fh:
                    self.state = json.load(fh)
            except (json.JSONDecodeError, OSError):
                pass

    def seen(self, chain: str, tx_hash: str, address: str) -> bool:
        return (chain, tx_hash.lower()) in self._by_tx or \
            (chain, address.lower()) in self._by_addr

    def add(self, row: Dict[str, Any]) -> bool:
        if self.seen(row["chain"], row["tx_hash"], row["address"]):
            return False
        self.rows.append(row)
        self._by_tx.add((row["chain"], row["tx_hash"].lower()))
        self._by_addr.add((row["chain"], row["address"].lower()))
        with open(self.queue_path, "a") as fh:
            fh.write(json.dumps(row) + "\n")
        return True

    def rewrite_queue(self) -> None:
        tmp = self.queue_path + ".tmp"
        with open(tmp, "w") as fh:
            for row in self.rows:
                fh.write(json.dumps(row) + "\n")
        os.replace(tmp, self.queue_path)

    def checkpoint(self) -> None:
        self.state["updated_at"] = time.time()
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(self.state, fh, indent=1)
        os.replace(tmp, self.state_path)


# ---------------------------------------------------------------------------
# Watcher
# ---------------------------------------------------------------------------

class MempoolWatcher:
    def __init__(self, out_dir: str, chains: Sequence[str] = CHAINS,
                 rpc: Optional[RpcPool] = None,
                 screener: Optional[Tier1Screener] = None,
                 priority_native_wei: Optional[Dict[str, int]] = None):
        self.store = QueueStore(out_dir)
        self.chains = [c for c in chains if c in POOLS]
        self.rpc = rpc or RpcPool()
        self.screener = screener or Tier1Screener()
        self.priority_native_wei = priority_native_wei or \
            DEFAULT_PRIORITY_NATIVE_WEI
        self.pending_support: Dict[str, Optional[bool]] = {
            c: None for c in self.chains}
        if not self.store.state.get("started_at"):
            self.store.state["started_at"] = time.time()

    async def poll_chain(self, chain: str) -> Dict[str, Any]:
        stats = {"chain": chain, "blocks": 0, "creations": 0,
                 "screened": 0, "flagged": 0, "queued": 0,
                 "pending_supported": self.pending_support[chain],
                 "error": None}
        try:
            block = self.rpc.pending_block(chain)
        except RpcUnavailable as e:
            stats["error"] = str(e)[:200]
            self.pending_support[chain] = False
            stats["pending_supported"] = False
            return stats
        if block is None:
            self.pending_support[chain] = False
            stats["pending_supported"] = False
            stats["error"] = "pending block returned null on all " \
                             "pool endpoints"
            return stats
        self.pending_support[chain] = True
        stats["pending_supported"] = True
        stats["blocks"] = 1
        creations = extract_creations(block)
        stats["creations"] = len(creations)
        seen_unflagged = {
            (c, h) for c, h in
            (self.store.state.get("seen_unflagged") or [])}
        block_number = block.get("number")
        block_ts = int(block.get("timestamp") or "0x0", 16) \
            if isinstance(block.get("timestamp"), str) else None
        for creation in creations:
            if self.store.seen(chain, creation["tx_hash"],
                               creation["address"]):
                continue
            if (chain, creation["tx_hash"]) in seen_unflagged:
                continue
            init_bytes = bytes.fromhex(
                creation["input"].removeprefix("0x")) \
                if creation["input"] != "0x" else b""
            runtime = extract_runtime_code(init_bytes)
            screened_code = runtime if runtime is not None else init_bytes
            screened_kind = "runtime_extracted" if runtime is not None \
                else "init_code"
            code_hex = "0x" + screened_code.hex() if screened_code \
                else "0x"
            stats["screened"] += 1
            flags = await self.screener.screen(
                chain, creation["address"], code_hex)
            if not flags:
                # Unflagged creations are not queued, but the
                # sighting is checkpointed via the seen-set in
                # state so restarts do not rescreen forever.
                self.store.state.setdefault("seen_unflagged", []).append(
                    [chain, creation["tx_hash"]])
                continue
            stats["flagged"] += 1
            gated = gate_flags(chain, creation["address"], flags)
            row = {
                "chain": chain,
                "address": creation["address"],
                "deployer": creation["deployer"],
                "tx_hash": creation["tx_hash"],
                "nonce": creation["nonce"],
                "block_seen": block_number,
                "block_ts": block_ts,
                "seen_at": time.time(),
                "status": "UNVERIFIED",
                "screened": screened_kind,
                "init_code_bytes": creation["init_code_bytes"],
                "deploy_value_wei": creation["value_wei"],
                "flags": gated,
                "gate_summary": gate_summary(gated),
                "mined": False,
                "initial_balance_wei": None,
                "initial_balance_usd": None,
                "runtime_code_bytes": None,
                "priority": "normal",
            }
            if self.store.add(row):
                stats["queued"] += 1
        cstate = self.store.state.setdefault("chains", {}).setdefault(
            chain, {})
        cstate["last_poll_at"] = time.time()
        cstate["last_pending_block"] = block_number
        cstate["pending_supported"] = True
        return stats

    def confirm_mined(self) -> Dict[str, int]:
        """Stamp mined rows with runtime code size + native balance.

        Read-only eth_getCode / eth_getBalance per queued row that
        has not been confirmed yet. Rows at or above the chain's
        native priority threshold are marked priority=high. USD is
        left null on purpose: no price feed is wired in.
        """
        stats = {"checked": 0, "mined": 0, "high_priority": 0,
                 "errors": 0}
        changed = False
        for row in self.rows_iter():
            if row.get("mined"):
                continue
            stats["checked"] += 1
            try:
                code = self.rpc.get_code(row["chain"], row["address"])
                if code in ("0x", "", None):
                    continue
                balance = self.rpc.get_balance(
                    row["chain"], row["address"])
            except RpcUnavailable:
                stats["errors"] += 1
                continue
            row["mined"] = True
            row["runtime_code_bytes"] = (len(code) - 2) // 2
            row["initial_balance_wei"] = balance
            row["confirmed_at"] = time.time()
            threshold = self.priority_native_wei.get(row["chain"])
            if threshold is not None and balance >= threshold:
                row["priority"] = "high"
                stats["high_priority"] += 1
            stats["mined"] += 1
            changed = True
        if changed:
            self.store.rewrite_queue()
        return stats

    def rows_iter(self) -> List[Dict[str, Any]]:
        return self.store.rows

    async def run(self, duration_s: float, interval_s: float = 12.0,
                  confirm_every: int = 5) -> Dict[str, Any]:
        totals: Dict[str, Any] = {"polls": 0, "per_chain": {}}
        deadline = time.time() + duration_s
        cycle = 0
        while True:
            cycle += 1
            for chain in self.chains:
                stats = await self.poll_chain(chain)
                agg = totals["per_chain"].setdefault(chain, {
                    "blocks": 0, "creations": 0, "screened": 0,
                    "flagged": 0, "queued": 0, "errors": 0,
                    "pending_supported":
                        self.pending_support.get(chain)})
                for k in ("blocks", "creations", "screened",
                          "flagged", "queued"):
                    agg[k] += stats[k]
                if stats["error"]:
                    agg["errors"] += 1
                    agg["last_error"] = stats["error"]
                agg["pending_supported"] = stats["pending_supported"]
            totals["polls"] = cycle
            self.store.state["polls"] = \
                self.store.state.get("polls", 0) + 1
            # cap the unflagged seen list so state stays small
            seen = self.store.state.get("seen_unflagged") or []
            if len(seen) > 5000:
                self.store.state["seen_unflagged"] = seen[-5000:]
            self.store.checkpoint()
            if confirm_every and cycle % confirm_every == 0:
                totals["confirm"] = self.confirm_mined()
                self.store.checkpoint()
            if time.time() >= deadline:
                break
            await asyncio.sleep(max(0.0, min(
                interval_s, deadline - time.time())))
        totals["confirm_final"] = self.confirm_mined()
        self.store.checkpoint()
        return totals
