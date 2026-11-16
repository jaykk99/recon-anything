"""Fund-flow tracing: pure parsing and graph building (no network).

This module is deliberately network-free: every function here takes
already-fetched JSON (Blockscout v2 responses, or raw eth_getLogs
Transfer events) and returns edges. All HTTP/RPC lives in
``app.fundflow_sources``. That split keeps this module importable and
testable offline, and keeps the tracing code out of the detector-plugin
registry (it operates on address flows, not on single-contract source).

Edge shape (all values are plain JSON):
    {
      "from": <address>, "to": <address>,
      "asset": <token contract address, or "ETH"/"BNB"/... for native>,
      "amount_raw": <int, smallest unit>, "amount": <float, human-scaled>,
      "decimals": <int>, "symbol": <str>,
      "tx_hash": <str>, "block": <int>, "hop": <int>,
      "log_index": <int | None>,
    }

Amounts are raw integers first: human scaling is display-only, because
two contracts can share a symbol (USDG) while having different decimals
and different contracts. Totals must key on the token CONTRACT address,
never on the symbol.
"""

from typing import Any, Dict, List, Optional, Tuple

# keccak256("Transfer(address,address,uint256)") — the only log topic
# this module trusts.
TRANSFER_TOPIC = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)
ADDRESS_ZERO = "0x0000000000000000000000000000000000000000"


def _norm(addr: Any) -> str:
    """Lowercase an address; non-strings become the zero address."""
    if not isinstance(addr, str):
        return ADDRESS_ZERO
    return addr.lower()


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _decimals(value: Any, default: int = 18) -> int:
    return _int(value, default)


def in_window(item: Dict[str, Any], from_block: int, to_block: int) -> bool:
    """True when a Blockscout item's block_number is inside [from, to].

    Items with a missing/null block (pending txs) are OUT: a pending tx
    is not a settled flow.
    """
    block = item.get("block_number")
    return isinstance(block, int) and from_block <= block <= to_block


def parse_token_transfer(item: Dict[str, Any], hop: int) -> Optional[Dict[str, Any]]:
    """Parse one Blockscout ``token-transfers`` item into an edge.

    Returns None for items that carry no value (zero amount) or that
    lack from/to. Token identity is the token CONTRACT address
    (``token.address_hash``); ``token.address`` is not a Blockscout
    field and must never be read.
    """
    if not isinstance(item, dict):
        return None
    frm = _norm(item.get("from", {}).get("hash") if isinstance(item.get("from"), dict) else None)
    to = _norm(item.get("to", {}).get("hash") if isinstance(item.get("to"), dict) else None)
    if frm == ADDRESS_ZERO and to == ADDRESS_ZERO:
        return None
    total = item.get("total") or {}
    amount_raw = _int(total.get("value"))
    if amount_raw <= 0:
        return None
    token = item.get("token") or {}
    decimals = _decimals(total.get("decimals", token.get("decimals")), 18)
    asset = _norm(token.get("address_hash"))
    symbol = token.get("symbol") or ""
    if not isinstance(symbol, str):
        symbol = str(symbol)
    block = item.get("block_number")
    return {
        "from": frm,
        "to": to,
        "asset": asset,
        "amount_raw": amount_raw,
        "amount": amount_raw / (10 ** decimals),
        "decimals": decimals,
        "symbol": symbol,
        "tx_hash": item.get("transaction_hash") or "",
        "block": block if isinstance(block, int) else 0,
        "hop": hop,
        "log_index": _int(item.get("log_index")) if item.get("log_index") is not None else None,
    }


def parse_transaction(item: Dict[str, Any], hop: int, native_symbol: str) -> Optional[Dict[str, Any]]:
    """Parse one Blockscout ``transactions`` item into a native edge.

    Only native-value transfers count (value > 0). Zero-value calls,
    contract creations (no ``to``), and pending txs (null block) return
    None. ``value`` is a raw wei string in the Blockscout response.
    """
    if not isinstance(item, dict):
        return None
    block = item.get("block_number")
    if not isinstance(block, int):
        # Pending tx (null block) is not a settled flow.
        return None
    value_raw = _int(item.get("value"))
    if value_raw <= 0:
        return None
    frm = _norm(item.get("from", {}).get("hash") if isinstance(item.get("from"), dict) else None)
    to_raw = item.get("to")
    to = _norm(to_raw.get("hash") if isinstance(to_raw, dict) else None)
    if to == ADDRESS_ZERO:
        return None
    return {
        "from": frm,
        "to": to,
        "asset": native_symbol,
        "amount_raw": value_raw,
        "amount": value_raw / 10 ** 18,
        "decimals": 18,
        "symbol": native_symbol,
        "tx_hash": item.get("hash") or "",
        "block": block if isinstance(block, int) else 0,
        "hop": hop,
        "log_index": None,
    }


def parse_transfer_log(log: Dict[str, Any], hop: int) -> Optional[Dict[str, Any]]:
    """Parse one raw eth_getLogs Transfer event into an edge.

    Used only by the RPC fallback (no Blockscout). The log's ``address``
    is the token contract; topics[1]/topics[2] are the indexed from/to
    (right-aligned 32-byte words); data is the uint256 amount. Only logs
    whose topics[0] is the Transfer signature are accepted. Amounts here
    are raw only: the fallback has no decimals metadata, so ``amount``
    is the raw value and ``decimals`` is None (callers must not scale).
    """
    if not isinstance(log, dict):
        return None
    topics = log.get("topics") or []
    if len(topics) < 3 or str(topics[0]).lower() != TRANSFER_TOPIC:
        return None

    def _topic_addr(topic: Any) -> str:
        t = str(topic).lower()
        return "0x" + t[-40:] if t.startswith("0x") else ADDRESS_ZERO

    frm = _topic_addr(topics[1])
    to = _topic_addr(topics[2])
    try:
        amount_raw = int(str(log.get("data", "0x0")), 16)
    except (TypeError, ValueError):
        return None
    if amount_raw <= 0:
        return None
    block = _int(log.get("blockNumber"), 0)
    log_index = log.get("logIndex")
    return {
        "from": frm,
        "to": to,
        "asset": _norm(log.get("address")),
        "amount_raw": amount_raw,
        "amount": float(amount_raw),
        "decimals": None,
        "symbol": "",
        "tx_hash": log.get("transactionHash") or "",
        "block": block,
        "hop": hop,
        "log_index": _int(log_index) if log_index is not None else None,
    }


def dedupe_edges(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop exact duplicates, keeping first occurrence.

    Key is (tx_hash, log_index, from, to, asset, amount_raw). The
    log_index matters: one transaction can emit several Transfer events
    for the same pair/asset, and those are distinct flows, not dupes.
    """
    seen = set()
    out = []
    for e in edges:
        key = (e.get("tx_hash"), e.get("log_index"), e.get("from"),
               e.get("to"), e.get("asset"), e.get("amount_raw"))
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def build_graph(seed: str, edges: List[Dict[str, Any]],
                kinds: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Build nodes + seed totals from a deduped edge list.

    Node shape: {kind, total_in_raw, total_out_raw, tx_count} where the
    totals are PER-ASSET dicts keyed by asset (contract address or
    native symbol), because one address routinely moves several assets.
    ``kinds`` maps address -> "contract" | "eoa" | "unknown"; missing
    entries default to "unknown".
    """
    seed = _norm(seed)
    kinds = kinds or {}
    nodes: Dict[str, Dict[str, Any]] = {}
    seed_in: Dict[str, int] = {}
    seed_out: Dict[str, int] = {}

    def _node(addr: str) -> Dict[str, Any]:
        node = nodes.get(addr)
        if node is None:
            node = {"kind": kinds.get(addr, "unknown"),
                    "total_in_raw": {}, "total_out_raw": {}, "tx_count": 0}
            nodes[addr] = node
        return node

    _node(seed)
    for e in edges:
        frm, to = _norm(e["from"]), _norm(e["to"])
        asset = e["asset"]
        amount = _int(e.get("amount_raw"))
        for addr, side in ((frm, "out"), (to, "in")):
            node = _node(addr)
            node["tx_count"] += 1
            totals = node["total_out_raw"] if side == "out" else node["total_in_raw"]
            totals[asset] = totals.get(asset, 0) + amount
        if to == seed:
            seed_in[asset] = seed_in.get(asset, 0) + amount
        if frm == seed:
            seed_out[asset] = seed_out.get(asset, 0) + amount
    return {
        "seed": seed,
        "nodes": nodes,
        "edges": dedupe_edges(edges),
        "summary": {"seed_total_in_raw": seed_in, "seed_total_out_raw": seed_out},
    }


def render_summary(graph: Dict[str, Any], chain: str, from_block: int,
                   to_block: int, hops: int) -> str:
    """One-page text summary: seed totals + top counterparties."""
    seed = graph["seed"]
    summary = graph["summary"]
    nodes = graph["nodes"]
    edges = graph["edges"]
    lines = [
        f"Fund-flow trace: {seed} on {chain}",
        f"Blocks {from_block}..{to_block}, hops {hops}, "
        f"{len(edges)} edges, {len(nodes)} nodes.",
        "",
        "Seed totals in (raw units, per asset):",
    ]
    if summary["seed_total_in_raw"]:
        for asset in sorted(summary["seed_total_in_raw"]):
            lines.append(f"  in  {asset}: {summary['seed_total_in_raw'][asset]}")
    else:
        lines.append("  in  (none)")
    lines.append("Seed totals out (raw units, per asset):")
    if summary["seed_total_out_raw"]:
        for asset in sorted(summary["seed_total_out_raw"]):
            lines.append(f"  out {asset}: {summary['seed_total_out_raw'][asset]}")
    else:
        lines.append("  out (none)")
    lines.append("")
    lines.append("Top counterparties (by edge count):")
    counts: Dict[str, int] = {}
    for e in edges:
        for addr in (e["from"], e["to"]):
            if addr != seed:
                counts[addr] = counts.get(addr, 0) + 1
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
    if top:
        for addr, count in top:
            kind = nodes.get(addr, {}).get("kind", "unknown")
            lines.append(f"  {addr} ({kind}): {count} edges")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Note: amounts are raw smallest-unit values per asset; "
                 "human-scaled amounts are on each edge. No attribution "
                 "or labels are attached: addresses are not identified.")
    prov = graph.get("provenance", {})
    notes = prov.get("coverage_notes") or []
    failed = prov.get("failed_addresses") or []
    if notes or failed:
        lines.append("")
        lines.append("Coverage caveats:")
        for note in notes:
            lines.append(f"  - {note}")
        for item in failed:
            lines.append(f"  - {item.get('address')} (hop {item.get('hop')}): "
                         f"fetch failed, skipped: {item.get('error')}")
    if prov.get("truncated"):
        lines.append("  - Node/edge caps reached: the graph is truncated, "
                     "not complete.")
    return "\n".join(lines) + "\n"
