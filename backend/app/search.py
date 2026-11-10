"""Live search over everything ReconAnything has collected.

Jay's order (2026-11-06): "make a searcher that you can search any
keyword or filter and list anything — find 100 of anything in
1 second", working on the live service.

How it works: scripts/build_search_index.py merges every collected
corpus (kwindex verified source, continuous scanner results +
candidates, real-hunt verdicts, FP-audit adjudications, transition
watchlist) into ONE compact corpus file shipped inside the image at
app/searchdata/corpus.jsonl.gz. On first use this module gunzips it
and builds an SQLite FTS5 index in a temp file (a few thousand docs —
builds in about a second), then serves AND-of-keywords queries with
structured filters from it. No VM-local state is read at query time,
so the search works identically on Render and locally — this
supersedes the scan-time unified_keyword_search plugin for
interactive use (that plugin still serves scan-time lane searches;
its interface is unchanged).

Ranking: verdict severity first (VERIFIED_REAL > UNVERIFIED >
TRIGGER_ONLY > unadjudicated > FALSE_POSITIVE — confirmed-dead
sinks last), then FTS bm25, then live value. The snippet is built from the structured fields (matched
functions / finding kinds / verdict + reason), not from token soup.
"""
from __future__ import annotations

import gzip
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

DATA_PATH = Path(__file__).resolve().parent / "searchdata" / "corpus.jsonl.gz"

_lock = threading.Lock()
_db: Optional[sqlite3.Connection] = None
_meta: Dict[str, Any] = {}

_VERDICT_ORDER = {"VERIFIED_REAL": 0, "UNVERIFIED": 1,
                  "TRIGGER_ONLY": 2, "FALSE_POSITIVE": 4}  # None -> 3
_ADDR_RE = re.compile(r"^(0x)?[0-9a-fA-F]{40}$")
_SPLIT_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_TERM_RE = re.compile(r"[A-Za-z0-9_]+")


def corpus_path() -> Path:
    env = os.environ.get("RECON_SEARCH_CORPUS")
    return Path(env) if env else DATA_PATH


def _split_parts(identifier: str) -> List[str]:
    parts = []
    for chunk in identifier.split("_"):
        parts += [p.lower() for p in _SPLIT_RE.findall(chunk)]
    return [p for p in parts if len(p) > 1]


def _read_corpus(path: Path) -> List[dict]:
    opener = gzip.open if path.suffix == ".gz" else open
    rows = []
    with opener(path, "rt", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if "_meta" in obj:
                _meta.update(obj["_meta"])
                continue
            if "chain" in obj and "address" in obj:
                rows.append(obj)
    return rows


def _ensure_db() -> sqlite3.Connection:
    global _db
    if _db is not None:
        return _db
    with _lock:
        if _db is not None:
            return _db
        path = corpus_path()
        rows = _read_corpus(path)
        fd, tmp = tempfile.mkstemp(prefix="recon-search-", suffix=".db")
        os.close(fd)
        con = sqlite3.connect(tmp, check_same_thread=False)
        con.execute("PRAGMA journal_mode=OFF")
        con.execute(
            "CREATE TABLE contracts(chain TEXT, address TEXT, "
            "name TEXT, symbol TEXT, value_usd REAL, has_source INTEGER, "
            "functions TEXT, selectors TEXT, plugins TEXT, kinds TEXT, "
            "verdict TEXT, verdicts TEXT, recipients TEXT, reasons TEXT, "
            "sources TEXT, first_seen TEXT, last_seen TEXT)")
        con.execute(
            "CREATE VIRTUAL TABLE docs USING fts5("
            "chain, address, doc, tokenize='unicode61')")
        ins_c = ("INSERT INTO contracts(rowid, chain, address, name, "
                 "symbol, value_usd, has_source, functions, selectors, "
                 "plugins, kinds, verdict, verdicts, recipients, "
                 "reasons, sources, first_seen, last_seen) "
                 "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        ins_d = "INSERT INTO docs(rowid, chain, address, doc) " \
                "VALUES (?,?,?,?)"
        for i, r in enumerate(rows, start=1):
            funcs = r.get("functions") or []
            extra = []
            for fn in funcs:
                extra += _split_parts(fn)
            if r.get("name"):
                extra += _split_parts(str(r["name"]))
            # Also index the finding kinds, plugins and token symbol (with
            # their split parts) so a keyword search can find contracts BY
            # vulnerability class: "selfdestruct", "delegatecall",
            # "withdraw", "reentrancy", a plugin name, or a symbol all hit.
            # Without this you could only search function/name text.
            for kind in (r.get("kinds") or []):
                extra.append(str(kind))
                extra += _split_parts(str(kind))
            for plug in (r.get("plugins") or []):
                extra += _split_parts(str(plug))
            if r.get("symbol"):
                extra.append(str(r["symbol"]).lower())
            doc = (r.get("doc") or "") + " " + " ".join(extra)
            con.execute(ins_c, (
                i, r.get("chain"), r.get("address"), r.get("name"),
                r.get("symbol"), r.get("value_usd"),
                1 if r.get("has_source") else 0,
                json.dumps(funcs), json.dumps(r.get("selectors") or []),
                json.dumps(r.get("plugins") or []),
                json.dumps(r.get("kinds") or []),
                r.get("verdict"), json.dumps(r.get("verdicts") or []),
                json.dumps(r.get("recipients") or []),
                json.dumps(r.get("reasons") or []),
                json.dumps(r.get("sources") or []),
                r.get("first_seen"), r.get("last_seen")))
            con.execute(ins_d, (i, r.get("chain"), r.get("address"),
                                doc))
        con.execute("CREATE INDEX idx_c_chain ON contracts(chain)")
        con.execute("CREATE INDEX idx_c_verdict ON contracts(verdict)")
        con.execute("CREATE INDEX idx_c_addr ON contracts(address)")
        con.commit()
        _meta["contracts_indexed"] = len(rows)
        _db = con
        return _db


def index_status() -> Dict[str, Any]:
    try:
        _ensure_db()
        return {"ok": True, "contracts": _meta.get("contracts_indexed", 0),
                "built_at": _meta.get("built_at"),
                "corpus": str(corpus_path())}
    except Exception as e:  # corpus missing on a fresh deploy etc.
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def _terms(q: str) -> List[str]:
    terms = []
    for t in _TERM_RE.findall(q or ""):
        if len(t) >= 2 and t.lower() not in terms:
            terms.append(t.lower())
    return terms


def _match_expr(terms: Sequence[str]) -> str:
    # AND of prefix terms: "withdr" still finds withdraw functions,
    # and an exact keyword is always a prefix of itself.
    return " AND ".join(f'"{t}"*' for t in terms)


def _snippet(row: dict, terms: Sequence[str]) -> str:
    bits = []
    if terms:
        hit_fns = [f for f in row["functions"]
                   if any(t in f.lower() for t in terms)][:4]
        if hit_fns:
            bits.append("functions: " + ", ".join(hit_fns))
        hit_kinds = [k for k in row["kinds"]
                     if any(t in k.lower() for t in terms)][:3]
        if hit_kinds:
            bits.append("findings: " + ", ".join(hit_kinds))
    if row.get("verdict"):
        v = row["verdict"]
        if row["reasons"]:
            v += " — " + row["reasons"][0]
        bits.append(v)
    if not bits and row["functions"]:
        bits.append("functions: " + ", ".join(row["functions"][:4]))
    return " · ".join(bits)[:400]


def _row_out(r: sqlite3.Row, terms: Sequence[str]) -> dict:
    row = {
        "chain": r["chain"], "address": r["address"],
        "name": r["name"], "symbol": r["symbol"],
        "value_usd": r["value_usd"],
        "has_source": bool(r["has_source"]),
        "functions": json.loads(r["functions"] or "[]")[:50],
        "selectors": json.loads(r["selectors"] or "[]")[:50],
        "plugins": json.loads(r["plugins"] or "[]"),
        "kinds": json.loads(r["kinds"] or "[]"),
        "verdict": r["verdict"],
        "verdicts": json.loads(r["verdicts"] or "[]"),
        "recipients": json.loads(r["recipients"] or "[]"),
        "sources": json.loads(r["sources"] or "[]"),
        "first_seen": r["first_seen"], "last_seen": r["last_seen"],
    }
    row["snippet"] = _snippet(
        {**row, "reasons": json.loads(r["reasons"] or "[]")}, terms)
    return row


_COLS = ("c.rowid AS _rid, c.chain, c.address, c.name, c.symbol, "
         "c.value_usd, c.has_source, c.functions, c.selectors, "
         "c.plugins, c.kinds, c.verdict, c.verdicts, c.recipients, "
         "c.reasons, c.sources, c.first_seen, c.last_seen")


def search(q: str = "", chain: str = "", plugin: str = "",
           verdict: str = "", recipient: str = "",
           min_value_usd: Optional[float] = None,
           has_source: Optional[bool] = None,
           limit: int = 100) -> Dict[str, Any]:
    """One search: keywords (AND) + filters, up to 100 ranked hits."""
    t0 = time.time()
    con = _ensure_db()
    con.row_factory = sqlite3.Row
    limit = max(1, min(int(limit or 100), 100))
    terms = _terms(q)
    where: List[str] = []
    params: List[Any] = []
    if chain:
        chains = [c.strip().lower() for c in chain.split(",") if c.strip()]
        if chains:
            where.append("c.chain IN (%s)" % ",".join("?" * len(chains)))
            params += chains
    if plugin:
        where.append("c.plugins LIKE ?")
        params.append(f"%\"{plugin.strip().lower()}\"%")
    if verdict:
        where.append("c.verdict = ?")
        params.append(verdict.strip().upper())
    if recipient:
        where.append("c.recipients LIKE ?")
        params.append(f"%\"{recipient.strip().upper()}\"%")
    if min_value_usd is not None:
        where.append("c.value_usd >= ?")
        params.append(float(min_value_usd))
    if has_source:
        where.append("c.has_source = 1")

    pinned: List[dict] = []
    if len(terms) == 1 and _ADDR_RE.match(terms[0]):
        addr = terms[0].lower()
        if not addr.startswith("0x"):
            addr = "0x" + addr
        rows = con.execute(
            f"SELECT {_COLS} FROM contracts c WHERE c.address = ?",
            (addr,)).fetchall()
        pinned = [_row_out(r, terms) for r in rows]
        if pinned:
            # an exact-address query means "this contract": the pin
            # is the whole answer, not page 1 of a full browse.
            return {"query": q, "count": len(pinned),
                    "took_ms": round((time.time() - t0) * 1000, 1),
                    "index": {"contracts":
                              _meta.get("contracts_indexed", 0),
                              "built_at": _meta.get("built_at")},
                    "results": pinned[:limit]}

    if terms:
        # Fetch the FTS match set (rowid + bm25) in ONE scan, then do
        # filtering / counting / ranking in SQL+Python over that set.
        # Joining contracts straight into the MATCH lets the planner
        # probe the FTS index per contracts row — measured ~460ms on
        # withdraw+chain vs ~3ms this way.
        pairs = con.execute(
            "SELECT rowid, bm25(docs) FROM docs WHERE docs MATCH ?",
            (_match_expr(terms),)).fetchall()
        scores = {rid: sc for rid, sc in pairs}
        if not pairs:
            total, rows = 0, []
        else:
            ph = ",".join("?" * len(pairs))
            allw = (f"FROM contracts c WHERE c.rowid IN ({ph})"
                    + (" AND " + " AND ".join(where) if where else ""))
            ids = [rid for rid, _ in pairs]
            total = con.execute(f"SELECT COUNT(*) {allw}",
                                ids + params).fetchone()[0]
            rows = con.execute(f"SELECT {_COLS} {allw}",
                               ids + params).fetchall()
            rows.sort(key=lambda r: (
                _VERDICT_ORDER.get(r["verdict"], 3),
                scores.get(r["_rid"], 0.0),
                -(r["value_usd"] or 0)))
            rows = rows[:limit]
    else:
        base = "FROM contracts c"
        allw = base + (" WHERE " + " AND ".join(where) if where else "")
        total = con.execute(f"SELECT COUNT(*) {allw}",
                            params).fetchone()[0]
        rows = con.execute(
            f"SELECT {_COLS} {allw} "
            "ORDER BY CASE c.verdict "
            "WHEN 'VERIFIED_REAL' THEN 0 WHEN 'UNVERIFIED' THEN 1 "
            "WHEN 'TRIGGER_ONLY' THEN 2 WHEN 'FALSE_POSITIVE' THEN 4 "
            "ELSE 3 END, c.value_usd DESC LIMIT ?",
            params + [limit]).fetchall()

    results = pinned + [_row_out(r, _terms(q)) for r in rows]
    return {"query": q, "count": total + len(pinned),
            "took_ms": round((time.time() - t0) * 1000, 1),
            "index": {"contracts": _meta.get("contracts_indexed", 0),
                      "built_at": _meta.get("built_at")},
            "results": results[:limit]}
