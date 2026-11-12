"""CLI entry point: ``python -m app.fundflow_cli``.

Given chain + address + hops (default 2, max 3) + a bounded block
window, returns a flow graph: nodes (address, EOA vs contract via
eth_getCode, total in, total out, tx count) and edges (from, to,
token/native, amount, tx hash, block), plus a one-page text summary
naming the top counterparties and total in/out.

Read-only, detection only. Never sends a transaction. Keyless only.
Never targets crypto.com or Binance.
"""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from app import fundflow as ff
    from app import fundflow_sources as src
except ImportError:  # pragma: no cover - direct-file invocation
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import fundflow as ff  # type: ignore
    from app import fundflow_sources as src  # type: ignore

MAX_HOPS = 3
MAX_NODES = 200
MAX_EDGES = 5_000
# Pages (50 items each) fetched per address, by hop. Hop 1 is the seed's
# own history (deep); further hops are one step removed, so their fetch
# depth is capped harder to keep the trace bounded. Transactions are
# capped harder than token transfers past hop 1: the transactions
# endpoint pages through an address's full history and dominates runtime.
PAGES_BY_HOP = {1: 10, 2: 3, 3: 2}
TX_PAGES_BY_HOP = {1: 10, 2: 1, 3: 1}
FETCH_WORKERS = 3


def trace(chain: str, address: str, hops: int, from_block: int,
          to_block: int, max_pages: int = src.MAX_PAGES_PER_ADDRESS,
          allow_rpc_fallback: bool = True) -> Dict[str, Any]:
    """Trace fund flows out from ``address`` for ``hops`` hops.

    Breadth-first: hop 1 fetches the seed's own transfers and txs; each
    further hop fetches every new counterparty's flows. Fetches within a
    hop run in parallel (3 workers). A hop-1 failure is fatal (nothing
    to trace); a deeper-hop address failure is recorded in
    provenance.failed_addresses and the rest of the graph is kept.
    """
    if hops < 1 or hops > MAX_HOPS:
        raise ValueError(f"hops must be 1..{MAX_HOPS}")
    if from_block > to_block:
        raise ValueError("from_block must be <= to_block")
    cfg = src.chain_config(chain)
    native = cfg["native"]
    seed = address.lower()
    offenders = src.verify_keyless()
    if offenders:
        raise src.SourceError(
            "refusing to run: credentials present in environment "
            f"({', '.join(sorted(offenders))}); keyless tracing only")

    def fetch_one(addr: str, hop: int) -> Tuple[List[Dict[str, Any]], Set[str], List[str]]:
        """Fetch + parse one address's flows for one hop (thread-safe)."""
        pages = min(PAGES_BY_HOP.get(hop, 2), max_pages)
        tx_pages = min(TX_PAGES_BY_HOP.get(hop, 1), max_pages)
        used: Set[str] = set()
        notes: List[str] = []
        try:
            transfers, s1, trunc1, old1 = src.fetch_token_transfers(
                chain, addr, from_block, to_block, pages)
            txs, s2, trunc2, old2 = src.fetch_transactions(
                chain, addr, from_block, to_block, tx_pages)
            used.update((s1, s2))
            if trunc1:
                notes.append(f"token-transfers for {addr}: page cap hit, "
                             f"oldest block seen {old1}, window floor {from_block}; "
                             "coverage below that block is not established")
            if trunc2:
                notes.append(f"transactions for {addr}: page cap hit, "
                             f"oldest block seen {old2}, window floor {from_block}; "
                             "coverage below that block is not established")
            parsed = [ff.parse_token_transfer(i, hop) for i in transfers]
            parsed += [ff.parse_transaction(i, hop, native) for i in txs]
        except src.SourceError:
            if not allow_rpc_fallback:
                raise
            logs, s3 = src.rpc_transfer_logs(chain, addr, from_block, to_block)
            used.add(s3)
            parsed = [ff.parse_transfer_log(lg, hop) for lg in logs]
        return [e for e in parsed if e is not None], used, notes

    edges: List[Dict[str, Any]] = []
    sources: Set[str] = set()
    coverage_notes: List[str] = []
    failed_addresses: List[Dict[str, str]] = []
    visited: Set[str] = {seed}
    frontier: Set[str] = {seed}
    truncated = False
    for hop in range(1, hops + 1):
        futures = {}
        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
            for addr in sorted(frontier):
                futures[pool.submit(fetch_one, addr, hop)] = addr
            for fut in as_completed(futures):
                addr = futures[fut]
                try:
                    parsed, used, notes = fut.result()
                except src.SourceError as exc:
                    # Hop 1 is the seed: its failure is fatal (nothing to
                    # trace). Deeper hops degrade per address: record it
                    # and keep the rest of the graph.
                    if hop == 1:
                        raise src.SourceError(f"{addr}: {exc}") from exc
                    failed_addresses.append({"address": addr, "hop": hop,
                                           "error": str(exc)})
                    continue
                sources.update(used)
                coverage_notes.extend(notes)
                edges.extend(parsed)
        edges = ff.dedupe_edges(edges)
        if len(edges) >= MAX_EDGES:
            truncated = True
            edges = edges[:MAX_EDGES]
            break
        next_frontier: Set[str] = set()
        for e in edges:
            if e["hop"] == hop:
                for addr in (e["from"], e["to"]):
                    if addr not in visited:
                        next_frontier.add(addr)
        visited.update(next_frontier)
        frontier = next_frontier
        if not frontier:
            break
        if len(visited) >= MAX_NODES:
            truncated = True
            break

    # Classify every node (contract vs EOA). Batched eth_getCode first
    # (one RPC call for all nodes); per-address Blockscout fallback for
    # anything the batch did not answer.
    kinds: Dict[str, str] = {}
    addrs = sorted({seed} | {e["from"] for e in edges} | {e["to"] for e in edges})
    try:
        kinds.update(src.rpc_get_code_kinds(chain, addrs))
        sources.add("rpc:eth_getCode(batch)")
    except src.SourceError:
        pass
    missing = [a for a in addrs if a not in kinds]

    def kind_one(addr: str) -> Tuple[str, str, str]:
        try:
            kind, s = src.fetch_address_kind(chain, addr)
            return addr, kind, s
        except src.SourceError:
            return addr, "unknown", ""

    if missing:
        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
            for addr, kind, s in pool.map(kind_one, missing):
                kinds[addr] = kind
                if s:
                    sources.add(s)

    graph = ff.build_graph(seed, edges, kinds)
    graph["chain"] = chain
    graph["window"] = {"from_block": from_block, "to_block": to_block,
                       "hops": hops}
    graph["provenance"] = {
        "keyless": True,
        "sources": sorted(sources),
        "truncated": truncated,
        "failed_addresses": failed_addresses,
        "coverage_notes": coverage_notes,
        "note": ("No attribution or labels: addresses are not identified. "
                 "No off-chain search was performed."),
    }
    return graph


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Keyless fund-flow trace (Blockscout + public RPC).")
    parser.add_argument("--chain", required=True,
                        choices=sorted(src.CHAINS),
                        help="chain to trace on")
    parser.add_argument("--address", required=True,
                        help="seed address (0x...)")
    parser.add_argument("--hops", type=int, default=2,
                        help="hops out from the seed (1..3, default 2)")
    parser.add_argument("--from-block", type=int, required=True)
    parser.add_argument("--to-block", type=int, required=True)
    parser.add_argument("--max-pages", type=int,
                        default=src.MAX_PAGES_PER_ADDRESS)
    parser.add_argument("--no-rpc-fallback", action="store_true",
                        help="do not fall back to eth_getLogs when "
                             "Blockscout fails")
    parser.add_argument("--out", help="write the graph JSON to this path")
    parser.add_argument("--summary-only", action="store_true",
                        help="print only the one-page summary")
    args = parser.parse_args(argv)

    try:
        graph = trace(args.chain, args.address, args.hops,
                      args.from_block, args.to_block,
                      max_pages=args.max_pages,
                      allow_rpc_fallback=not args.no_rpc_fallback)
    except (src.SourceError, ValueError) as exc:
        print(f"trace failed: {exc}", file=sys.stderr)
        return 1
    text = ff.render_summary(graph, args.chain, args.from_block,
                             args.to_block, args.hops)
    print(text, end="")
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(graph, fh, indent=2, sort_keys=True)
        print(f"Graph JSON written to {args.out}")
    elif not args.summary_only:
        print(json.dumps(graph, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
