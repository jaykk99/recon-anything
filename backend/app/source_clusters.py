"""Bytecode-hash clustering: one read per contract family, verdicts propagated.

A corpus sweep produces rows, not contracts: the same deployed bytecode is
copied across hundreds of addresses (bridge clones, factory children, the
same token on several chains), so a per-address read/adjudication pass is
mostly spent re-deriving one verdict over and over. That is also where a
lot of the false positives come from - the same obvious gate is "found"
once per clone.

This module is the dedup lever: group records by runtime bytecode hash
(per chain, because immutables and metadata differ), pick one
representative per cluster, read that once, and propagate the verdict to
every member. 700-odd addresses routinely collapse to a few dozen
families, which turns "verify every contract" into "verify one per
family".

Design rules, matching the rest of the codebase:
  * pure stdlib, deterministic (cluster ids are sha1 of chain + hash),
  * never raises on malformed records,
  * a verdict is a label on evidence, not a proof: ``tp`` still means
    "candidate worth a live look", ``fp`` means "this shape is not a bug",
  * records without a hash are kept as their own singleton cluster and
    flagged ``needs_hash`` rather than silently dropped or merged.

Cluster verdicts: ``unread`` -> ``fp`` | ``tp`` | ``needs_source``.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Sequence

VERDICTS = ("unread", "fp", "tp", "needs_source")
_HASH_KEYS = ("runtime_hash", "bytecode_hash", "code_hash",
              "runtime_bytecode_hash", "runtimeCodeHash")
_ADDR_KEYS = ("address", "contract", "contract_address", "target_id")


def _addr(rec: Dict[str, Any]) -> str:
    for key in _ADDR_KEYS:
        value = rec.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _hash(rec: Dict[str, Any]) -> str:
    for key in _HASH_KEYS:
        value = rec.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return ""


def _chain(rec: Dict[str, Any]) -> str:
    value = rec.get("chain")
    return str(value).strip().lower() if isinstance(value, str) else ""


def _has_source(rec: Dict[str, Any]) -> bool:
    src = rec.get("source")
    return isinstance(src, str) and bool(src.strip())


def _finding_count(rec: Dict[str, Any]) -> int:
    found = rec.get("findings")
    if isinstance(found, list):
        return len(found)
    try:
        return int(rec.get("finding_count") or 0)
    except (TypeError, ValueError):
        return 0


def _cluster_id(chain: str, ident: str) -> str:
    return "bc-" + hashlib.sha1(
        f"{chain}:{ident}".encode("utf-8")).hexdigest()[:10]


def _representative(members: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The member to read: verified first, then has source, then the one
    with the most findings, then the lowest address (deterministic)."""
    return sorted(members, key=lambda r: (
        0 if r.get("verified") else 1,
        0 if _has_source(r) else 1,
        -_finding_count(r),
        _addr(r)))[0]


def cluster(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Group records into bytecode families.

    Returns ``{clusters, cluster_count, address_count, reduction,
    read_plan, note}``; each cluster carries its members, a representative,
    and an ``unread`` verdict ready to be filled in by ``propagate``.
    """
    try:
        return _cluster(records)
    except Exception as exc:  # noqa: BLE001 - never break a batch
        return {"clusters": [], "cluster_count": 0, "address_count": 0,
                "reduction": 0.0, "read_plan": [], "error": str(exc)[:160],
                "note": "clustering unavailable"}


def _cluster(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    unhashed = 0
    seen = set()
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        addr = _addr(rec)
        code_hash = _hash(rec)
        chain = _chain(rec)
        if not addr and not code_hash:
            continue
        ident = addr or code_hash
        if (chain, ident) in seen:
            continue
        seen.add((chain, ident))
        if not code_hash:
            unhashed += 1
            key = f"addr:{ident}"
        else:
            key = f"{chain}:{code_hash}"
        groups.setdefault(key, []).append(rec)

    clusters: List[Dict[str, Any]] = []
    for key, members in groups.items():
        members = sorted(members, key=_addr)
        rep = _representative(members)
        code_hash = _hash(rep)
        chain = _chain(rep)
        clusters.append({
            "id": _cluster_id(chain, code_hash or _addr(rep)),
            "chain": chain or None,
            "hash": code_hash or None,
            "members": [_addr(m) for m in members if _addr(m)],
            "size": len(members),
            "representative": _addr(rep),
            "representative_verified": bool(rep.get("verified")),
            "representative_has_source": _has_source(rep),
            "finding_count": sum(_finding_count(m) for m in members),
            "verdict": "unread",
            "note": "",
            "needs_hash": not code_hash,
        })
    clusters.sort(key=lambda c: (-c["size"], c["chain"] or "", c["id"]))

    addresses = sum(c["size"] for c in clusters)
    read_plan = [{"cluster": c["id"], "address": c["representative"],
                  "chain": c["chain"], "covers": c["size"],
                  "verified": c["representative_verified"]}
                 for c in clusters if c["representative"]]
    return {
        "clusters": clusters,
        "cluster_count": len(clusters),
        "address_count": addresses,
        "hashed_clusters": sum(1 for c in clusters if c["hash"]),
        "unhashed_clusters": unhashed,
        "reduction": (round(1 - (len(clusters) / addresses), 3)
                      if addresses else 0.0),
        "read_plan": read_plan,
        "note": ("One read per bytecode family, verdict propagated to every "
                 "member. Records without a runtime hash stay their own "
                 "cluster and are flagged needs_hash."),
    }


def propagate(report: Dict[str, Any], cluster_id: str, verdict: str,
              note: str = "") -> Dict[str, Any]:
    """Stamp one verdict onto a cluster and every member address.

    Returns a shallow copy of the report so callers can keep the original
    (and so a batch can propagate into a per-address map)."""
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    out = dict(report or {})
    clusters = []
    raw = (report or {}).get("clusters")
    for cl in (raw if isinstance(raw, list) else []):
        if not isinstance(cl, dict):
            continue
        cl = dict(cl)
        if cl.get("id") == cluster_id:
            cl["verdict"] = verdict
            cl["note"] = note
        clusters.append(cl)
    out["clusters"] = clusters
    out["verdicts"] = verdicts_for(out)
    return out


def verdicts_for(report: Dict[str, Any]) -> Dict[str, str]:
    """address -> verdict, for joining back onto the original rows."""
    out: Dict[str, str] = {}
    clusters = (report or {}).get("clusters")
    if not isinstance(clusters, list):
        return out
    for cl in clusters:
        if not isinstance(cl, dict):
            continue
        verdict = cl.get("verdict") or "unread"
        for addr in cl.get("members") or []:
            if isinstance(addr, str) and addr:
                out[addr] = verdict
    return out


def summary(report: Dict[str, Any]) -> Dict[str, Any]:
    """Counts for the report line: families, covered addresses, verdicts."""
    clusters = (report or {}).get("clusters")
    clusters = clusters if isinstance(clusters, list) else []
    counts: Dict[str, int] = {v: 0 for v in VERDICTS}
    unread_members = 0
    for cl in clusters:
        verdict = cl.get("verdict") or "unread"
        counts[verdict] = counts.get(verdict, 0) + 1
        if verdict == "unread":
            unread_members += int(cl.get("size") or 0)
    return {
        "addresses": int((report or {}).get("address_count") or 0),
        "families": int((report or {}).get("cluster_count") or 0),
        "verdicts": counts,
        "unread_addresses": unread_members,
        "reduction": (report or {}).get("reduction", 0.0),
    }


def apply_verdicts(records: Sequence[Dict[str, Any]],
                   report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Attach ``bytecode_verdict`` / ``bytecode_cluster`` to each record."""
    verdicts = verdicts_for(report)
    families: Dict[str, str] = {}
    for cl in (report or {}).get("clusters") or []:
        for addr in cl.get("members") or []:
            if isinstance(addr, str):
                families[addr] = cl.get("id") or ""
    out: List[Dict[str, Any]] = []
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        row = dict(rec)
        addr = _addr(rec)
        row["bytecode_verdict"] = verdicts.get(addr, "unread")
        row["bytecode_cluster"] = families.get(addr, "")
        out.append(row)
    return out


__all__ = ["VERDICTS", "apply_verdicts", "cluster", "propagate", "summary",
           "verdicts_for"]


def _main(argv: Optional[List[str]] = None) -> int:
    """CLI: cluster a JSONL of contract records by runtime bytecode hash.

    ``python -m app.source_clusters --input rows.jsonl [--json]`` prints the
    family count, the reduction, and the read plan (one address per family).
    """
    import argparse
    import json as _json
    import sys

    ap = argparse.ArgumentParser(prog="app.source_clusters")
    ap.add_argument("--input", required=True,
                    help="JSONL, one record per line (address, runtime_hash, "
                         "chain, verified, source, findings)")
    ap.add_argument("--json", action="store_true", help="emit the full report")
    args = ap.parse_args(argv)
    records = []
    with open(args.input, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(_json.loads(line))
            except _json.JSONDecodeError:
                continue
    report = cluster(records)
    if args.json:
        print(_json.dumps(report, indent=2))
        return 0
    counts = summary(report)
    print(f"addresses: {counts['addresses']}  families: {counts['families']}  "
          f"reduction: {counts['reduction']:.1%}")
    print(f"unread addresses: {counts['unread_addresses']}")
    print("read plan (one per family):")
    for item in report["read_plan"]:
        print(f"  {item['address']}  chain={item['chain']}  "
              f"covers={item['covers']}  verified={item['verified']}")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
