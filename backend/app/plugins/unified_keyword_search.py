"""Unified Keyword Search: ONE search, MULTIPLE keywords, all 3 lanes.

Jay's order (2026-11-04): "Search all 3 at once so it only comes with
right results" / "As one search, multiple key words, one search" /
"filter search contracts with those by making a plugin that searches
key words, even multiple at a time."

One call takes a LIST of keywords and queries all three ReconAnything
search lanes together, returning ONE deduped result set (dedupe key:
chain + address). Every hit is tagged with the lane(s) that found it:

  keyword_index    the FTS5 code-search corpus built by kwindex.py
                   (verified contract source; semantics follow
                   kwsearch.py: a multi-token keyword is an AND of
                   quoted tokens, a quoted keyword is an exact phrase)
  scanner          what the continuous scanner already holds:
                   results/batches.jsonl findings and every
                   state/queues/*.jsonl row
  transition_watch the state-transition watcher's top-300 watchlist,
                   its recorded slot/owner/code-hash snapshots and any
                   recorded transition events

Semantics: default AND across keywords (a contract must match every
keyword, in at least one lane each - lanes merge per contract). OR mode
and per-keyword exact phrases are supported. Case-insensitive. Filters:
chain list and minimum USD value (tiers 1000 / 100000), same as
kwsearch. A lane whose data is missing (e.g. the index DB on a fresh
deploy) reports itself unavailable in the result metadata and the
plugin still returns the other lanes' hits - it never crashes on a
missing lane.

A keyword match is a LEAD, never a verdict: it goes to the scanner's
live-probe validator like every other lead. With
RECON_UNIFIED_SEARCH_ENQUEUE=1, hits at/above the min value are handed
to the scanner's keyword_search queue using kwsearch's exact dedupe
(against every existing queue and results/batches.jsonl) and row
format.

Query input (first hit wins):
  - a scan target of type "keyword_search" whose raw text is the
    comma-separated keyword list (a keyword containing spaces is one
    keyword; wrap it in double quotes or prefix phrase: for an exact
    phrase match in the code index)
  - "keyword_query" items on the run's discovery bus (ctx.shared)
  - env RECON_UNIFIED_SEARCH_QUERY (worker / offline runs)

Options (env): RECON_UNIFIED_SEARCH_MODE=and|or,
RECON_UNIFIED_SEARCH_CHAINS=ethereum,bsc,...,
RECON_UNIFIED_SEARCH_MIN_VALUE=1000,
RECON_UNIFIED_SEARCH_LIMIT=50, RECON_UNIFIED_SEARCH_ENQUEUE=1,
RECON_KW_INDEX_DB=<path to index.db>,
RECON_CONTINUOUS_HOME=<path to the recon-continuous checkout>.

Solana is NOT in the source index (no keyless verified-source corpus),
so lane 1 covers the six EVM chains only; Solana contracts can still
surface from the scanner and watch lanes, which hold them. crypto.com
/ Cronos is never a corpus entry or target. Detection only, read-only:
this plugin reads local search state, sends nothing, calls nothing.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

CHAINS = ("ethereum", "bsc", "polygon", "arbitrum", "base", "optimism")

LANE_INDEX = "keyword_index"
LANE_SCANNER = "scanner"
LANE_WATCH = "transition_watch"
LANES = (LANE_INDEX, LANE_SCANNER, LANE_WATCH)

_DEFAULT_INDEX_DB = (Path.home() / "workspace" /
                     "recon-keyword-search-2026-11-04" / "index.db")
_DEFAULT_CONT_HOME = Path.home() / "workspace" / "recon-continuous"

_MAX_FTS_ROWS = 5000        # candidates considered from the code index
_MAX_SNIPPET = 700          # chars of snippet kept per lane


# ---------------------------------------------------------------------
# keyword spec parsing (kwsearch semantics)
# ---------------------------------------------------------------------
class Keyword:
    """One keyword: literal text plus whether it is an exact phrase."""

    __slots__ = ("text", "phrase")

    def __init__(self, text: str, phrase: bool = False) -> None:
        self.text = text
        self.phrase = phrase

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Keyword({self.text!r}, phrase={self.phrase})"


def parse_keywords(spec: str) -> List[Keyword]:
    """Parse a comma/newline separated keyword list.

    A keyword containing spaces is one keyword (multi-token). Wrap a
    keyword in double quotes or prefix it with ``phrase:`` to force an
    exact-phrase match. Duplicates are dropped, order preserved.
    """
    out: List[Keyword] = []
    seen: Set[str] = set()
    for part in re.split(r"[,\n;]", spec or ""):
        p = part.strip()
        if not p:
            continue
        phrase = False
        if p.lower().startswith("phrase:"):
            phrase = True
            p = p[len("phrase:"):].strip()
        if len(p) >= 2 and p.startswith('"') and p.endswith('"'):
            phrase = True
            p = p[1:-1].strip()
        if not p:
            continue
        key = (p.lower(), phrase)
        if key in seen:
            continue
        seen.add(key)
        out.append(Keyword(p, phrase))
    return out


def _tokens_of(s: str) -> List[str]:
    return re.findall(r"[A-Za-z0-9_]+", s or "")


def _fts_expr(kw: Keyword) -> Optional[str]:
    """FTS5 expression for one keyword (kwsearch.fts_query semantics)."""
    toks = _tokens_of(kw.text)
    if not toks:
        return None
    if kw.phrase or len(toks) == 1:
        return '"' + " ".join(toks) + '"'
    return "(" + " AND ".join(f'"{t}"' for t in toks) + ")"


def _keyword_in_text(kw: Keyword, text: str) -> bool:
    """Literal containment check used by the file lanes and snippets.

    Phrase keywords must appear verbatim; other keywords need every
    token present (case-insensitive), mirroring the FTS semantics.
    """
    if not text:
        return False
    low = text.lower()
    if kw.phrase:
        return kw.text.lower() in low
    toks = _tokens_of(kw.text)
    if not toks:
        return False
    return all(t.lower() in low for t in toks)


def _matched_keywords(keywords: Sequence[Keyword],
                      text: str) -> List[Keyword]:
    return [kw for kw in keywords if _keyword_in_text(kw, text)]


def _combine(matched_count: int, total: int, mode: str) -> bool:
    if total == 0:
        return False
    return matched_count >= total if mode == "and" else matched_count > 0


def _snippet(text: str, start: int, ctx_lines: int = 2) -> Tuple[int, str]:
    """kwsearch.snippet: line number + context window around a hit."""
    lines = text.split("\n")
    pos = 0
    line_no = 0
    for i, ln in enumerate(lines):
        if pos + len(ln) + 1 > start:
            line_no = i
            break
        pos += len(ln) + 1
    lo = max(0, line_no - ctx_lines)
    hi = min(len(lines), line_no + ctx_lines + 1)
    snip = "\n".join(
        f"{'>' if j == line_no else ' '} {lines[j]}"
        for j in range(lo, hi))
    return line_no + 1, snip[:_MAX_SNIPPET]


# ---------------------------------------------------------------------
# shared hit accumulator
# ---------------------------------------------------------------------
def _new_hit(chain: str, address: str) -> Dict[str, Any]:
    return {"chain": chain, "address": address.lower(), "name": None,
            "value_usd": None, "lanes": set(), "matched": set(),
            "snippets": {}, "lines": {}, "events": [],
            "scanner_status": None, "finding_keys": set()}


def _merge(hits: Dict[Tuple[str, str], Dict[str, Any]],
           chain: str, address: str, lane: str,
           matched: Sequence[Keyword], name: Optional[str] = None,
           value: Optional[float] = None,
           snippet: Optional[str] = None,
           line: Optional[int] = None) -> Dict[str, Any]:
    k = (chain, (address or "").lower())
    hit = hits.setdefault(k, _new_hit(chain, address or ""))
    hit["lanes"].add(lane)
    for kw in matched:
        hit["matched"].add(kw.text)
    if name and not hit["name"]:
        hit["name"] = name
    if value is not None:
        hit["value_usd"] = (value if hit["value_usd"] is None
                            else max(hit["value_usd"], value))
    if snippet and lane not in hit["snippets"]:
        hit["snippets"][lane] = snippet
    if line is not None and lane == LANE_INDEX:
        hit["lines"] = {"line": line}
    return hit


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        with path.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if isinstance(row, dict):
                    rows.append(row)
    except OSError:
        pass
    return rows


def _passes(chain: str, value: Optional[float],
            chains: Optional[Set[str]],
            min_value: Optional[float]) -> bool:
    if chains and chain not in chains:
        return False
    if min_value is not None:
        if value is None or value < min_value:
            return False
    return True


# ---------------------------------------------------------------------
# lane 1: keyword code-search index (FTS5)
# ---------------------------------------------------------------------
def _search_index(db_path: Path, keywords: Sequence[Keyword], mode: str,
                  hits: Dict[Tuple[str, str], Dict[str, Any]]) -> str:
    """Returns a lane status string; merges hits in place."""
    if not db_path.exists():
        return f"unavailable: index db not found at {db_path}"
    exprs = [e for e in (_fts_expr(kw) for kw in keywords) if e]
    if not exprs:
        return "unavailable: no searchable keyword tokens"
    joiner = " AND " if mode == "and" else " OR "
    expr = joiner.join(exprs)
    try:
        con = sqlite3.connect(str(db_path))
        con.row_factory = sqlite3.Row
        try:
            rows = con.execute(
                "SELECT chain, address, text FROM src_fts "
                "WHERE src_fts MATCH ? LIMIT ?",
                (expr, _MAX_FTS_ROWS)).fetchall()
            metas: Dict[Tuple[str, str], Dict[str, Any]] = {}
            keys = [(r["chain"], r["address"]) for r in rows]
            for i in range(0, len(keys), 400):
                chunk = keys[i:i + 400]
                marks = ",".join("(?,?)" for _ in chunk)
                args = [v for pair in chunk for v in pair]
                for m in con.execute(
                        "SELECT * FROM contracts WHERE (chain, address) "
                        f"IN (VALUES {marks})", args):
                    metas[(m["chain"], m["address"])] = dict(m)
        finally:
            con.close()
    except Exception as e:  # noqa: BLE001 - a lane must never crash us
        return f"unavailable: index query failed ({type(e).__name__}: {e})"
    n = 0
    for r in rows:
        meta = metas.get((r["chain"], r["address"]))
        if not meta:
            continue
        text = r["text"] or ""
        matched = _matched_keywords(keywords, text)
        if mode == "and" and len(matched) < len(keywords):
            # FTS tokenization can split what the literal check wants
            # verbatim (e.g. ".call{value"); FTS already enforced the
            # AND, so trust it for inclusion and label all keywords.
            matched = list(keywords)
        if not _combine(len(matched), len(keywords), mode):
            continue
        first = matched[0]
        m = re.search(re.escape(first.text), text, re.I)
        if m is None and _tokens_of(first.text):
            m = re.search(re.escape(_tokens_of(first.text)[0]), text,
                          re.I)
        pos = m.start() if m else 0
        line, snip = _snippet(text, pos)
        _merge(hits, meta["chain"], meta["address"], LANE_INDEX,
               matched, name=meta.get("name"),
               value=meta.get("value_usd"), snippet=snip, line=line)
        n += 1
    return f"ok: {n} corpus contracts matched"


# ---------------------------------------------------------------------
# lane 2: continuous scanner state (batches + queues)
# ---------------------------------------------------------------------
def _search_scanner(home: Path, keywords: Sequence[Keyword], mode: str,
                    hits: Dict[Tuple[str, str], Dict[str, Any]]) -> str:
    results = home / "results" / "batches.jsonl"
    queues_dir = home / "state" / "queues"
    if not results.exists() and not queues_dir.exists():
        return f"unavailable: no scanner state under {home}"
    n = 0
    for row in _load_jsonl(results):
        chain, addr = row.get("chain"), row.get("address")
        if not chain or not addr:
            continue
        text = json.dumps(row, default=str)
        matched = _matched_keywords(keywords, text)
        if not _combine(len(matched), len(keywords), mode):
            continue
        snippet = None
        fkeys: Set[str] = set()
        for f in row.get("findings") or []:
            if not isinstance(f, dict):
                continue
            if f.get("key"):
                fkeys.add(str(f["key"]))
            if snippet is None and f.get("value") and \
                    _matched_keywords(keywords, str(f["value"])):
                snippet = str(f["value"])[:_MAX_SNIPPET]
        hit = _merge(hits, chain, addr, LANE_SCANNER, matched,
                     name=row.get("symbol"),
                     value=row.get("stake_usd"), snippet=snippet)
        hit["scanner_status"] = row.get("status")
        hit["finding_keys"].update(fkeys)
        n += 1
    qfiles = sorted(queues_dir.glob("*.jsonl")) if queues_dir.exists() \
        else []
    for qf in qfiles:
        for row in _load_jsonl(qf):
            chain, addr = row.get("chain"), row.get("address")
            if not chain or not addr:
                continue
            text = json.dumps(row, default=str)
            matched = _matched_keywords(keywords, text)
            if not _combine(len(matched), len(keywords), mode):
                continue
            _merge(hits, chain, addr, LANE_SCANNER, matched,
                   name=row.get("symbol"), value=row.get("stake_usd"))
            n += 1
    return f"ok: {n} scanner rows matched"


# ---------------------------------------------------------------------
# lane 3: transition watch (watchlist + snapshots + events)
# ---------------------------------------------------------------------
def _search_watch(home: Path, keywords: Sequence[Keyword], mode: str,
                  hits: Dict[Tuple[str, str], Dict[str, Any]]) -> str:
    state = home / "state"
    watchlist = state / "watchlist.jsonl"
    if not watchlist.exists():
        return f"unavailable: no watchlist under {state}"
    seen: Dict[str, Any] = {}
    try:
        seen = json.loads(
            (state / "watch_state.json").read_text()).get("seen", {})
    except Exception:  # noqa: BLE001 - snapshots are best-effort context
        seen = {}
    events: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for ev in _load_jsonl(state / "transition_events.jsonl"):
        if ev.get("chain") and ev.get("address"):
            events.setdefault(
                (ev["chain"], str(ev["address"]).lower()),
                []).append(ev)
    n = 0
    for row in _load_jsonl(watchlist):
        chain, addr = row.get("chain"), row.get("address")
        if not chain or not addr:
            continue
        snap = seen.get(f"{chain}|{str(addr).lower()}") or {}
        text = " ".join(str(x) for x in (
            row.get("symbol") or "", addr,
            json.dumps(snap, default=str)))
        matched = _matched_keywords(keywords, text)
        if not _combine(len(matched), len(keywords), mode):
            continue
        hit = _merge(hits, chain, addr, LANE_WATCH, matched,
                     name=row.get("symbol"),
                     value=row.get("stake_usd"))
        for ev in events.get((chain, str(addr).lower()), []):
            hit["events"].append(ev)
        n += 1
    # Watched contracts with a recorded transition also surface when a
    # keyword matches the event itself (e.g. the new owner address).
    for (chain, addr), evs in events.items():
        if (chain, addr) in hits:
            continue
        for ev in evs:
            matched = _matched_keywords(
                keywords, json.dumps(ev, default=str))
            if _combine(len(matched), len(keywords), mode):
                hit = _merge(hits, chain, addr, LANE_WATCH, matched,
                             name=ev.get("symbol"),
                             value=ev.get("stake_usd"))
                hit["events"].extend(evs)
                n += 1
                break
    return f"ok: {n} watched contracts matched"


# ---------------------------------------------------------------------
# handoff: enqueue combined hits into the scanner keyword_search queue
# (kwsearch.enqueue semantics + row format, deduped vs queues + scanned)
# ---------------------------------------------------------------------
def _enqueue(hits: List[Dict[str, Any]], home: Path,
             label: str) -> int:
    queues_dir = home / "state" / "queues"
    qfile = queues_dir / "keyword_search.jsonl"
    taken: Set[Tuple[str, str]] = set()
    if queues_dir.exists():
        for qf in queues_dir.glob("*.jsonl"):
            for r in _load_jsonl(qf):
                if r.get("chain") and r.get("address"):
                    taken.add((r["chain"],
                               str(r["address"]).lower()))
    for r in _load_jsonl(home / "results" / "batches.jsonl"):
        if r.get("chain") and r.get("address"):
            taken.add((r["chain"], str(r["address"]).lower()))
    added = 0
    queues_dir.mkdir(parents=True, exist_ok=True)
    with qfile.open("a") as fh:
        for h in hits:
            k = (h["chain"], h["address"])
            if k in taken:
                continue
            fh.write(json.dumps({
                "chain": h["chain"], "address": h["address"],
                "symbol": h.get("name"),
                "stake_usd": h.get("value_usd"),
                "queue": "keyword_search", "label": "keyword-search",
                "term": label}) + "\n")
            taken.add(k)
            added += 1
    return added


# ---------------------------------------------------------------------
# the unified search (pure, testable)
# ---------------------------------------------------------------------
def unified_search(keywords: Sequence[Keyword], mode: str = "and",
                   chains: Optional[Set[str]] = None,
                   min_value: Optional[float] = None,
                   limit: int = 50,
                   index_db: Optional[Path] = None,
                   continuous_home: Optional[Path] = None,
                   enqueue: bool = False) -> Dict[str, Any]:
    """Run one multi-keyword search across all three lanes.

    Returns {"hits": [...], "lane_status": {lane: status str},
    "enqueued": int}. Hits are deduped by (chain, address), filtered
    by chain / min value, sorted by value desc then lane count desc.
    """
    home = Path(continuous_home) if continuous_home else \
        _DEFAULT_CONT_HOME
    db = Path(index_db) if index_db else _DEFAULT_INDEX_DB
    hits: Dict[Tuple[str, str], Dict[str, Any]] = {}
    lane_status = {
        LANE_INDEX: _search_index(db, keywords, mode, hits),
        LANE_SCANNER: _search_scanner(home, keywords, mode, hits),
        LANE_WATCH: _search_watch(home, keywords, mode, hits),
    }
    out: List[Dict[str, Any]] = []
    for hit in hits.values():
        if not _passes(hit["chain"], hit["value_usd"], chains,
                       min_value):
            continue
        out.append({
            "chain": hit["chain"], "address": hit["address"],
            "name": hit["name"], "value_usd": hit["value_usd"],
            "lanes": sorted(hit["lanes"]),
            "matched_keywords": sorted(hit["matched"]),
            "snippets": hit["snippets"],
            "line": hit["lines"].get("line"),
            "events": hit["events"],
            "scanner_status": hit["scanner_status"],
            "finding_keys": sorted(hit["finding_keys"]),
        })
    out.sort(key=lambda h: (-(h["value_usd"] or 0.0),
                            -len(h["lanes"]), h["chain"], h["address"]))
    enqueued = 0
    if enqueue and out:
        mv = min_value if min_value is not None else 1000.0
        eligible = [h for h in out
                    if h["value_usd"] is not None
                    and h["value_usd"] >= mv]
        label = "unified:" + ",".join(kw.text for kw in keywords)
        enqueued = _enqueue(eligible, home, label)
    total = len(out)
    return {"hits": out[:limit] if limit else out,
            "total": total, "lane_status": lane_status,
            "enqueued": enqueued}


# ---------------------------------------------------------------------
# plugin
# ---------------------------------------------------------------------
def _env_float(name: str) -> Optional[float]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


class UnifiedKeywordSearchPlugin(Plugin):
    id = "unified_keyword_search"
    label = "Unified Keyword Search"
    accepts = ["keyword_search", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    requires_keys = []
    description = (
        "One search, multiple keywords, all three ReconAnything lanes "
        "at once: the verified-source code index (FTS5), the continuous "
        "scanner's batches and queues, and the transition watcher's "
        "watchlist, snapshots and events. AND across keywords by "
        "default (OR mode and exact phrases supported), chain and "
        "minimum-value filters, one deduped result set tagged by lane "
        "with matched code lines. A match is a lead for the live-probe "
        "validator, never a verdict. Solana is not in the source index "
        "(no keyless verified-source corpus); it can still surface "
        "from the scanner and watch lanes.")
    phase = 2  # consumes keyword_query items published during the run
    timeout_s = 120

    # -- input resolution ----------------------------------------------
    def _query_spec(self, target: Target, ctx: Ctx) -> str:
        for item in ctx.consume("keyword_query"):
            if isinstance(item, str) and item.strip():
                return item
            if isinstance(item, dict):
                spec = item.get("query") or item.get("keywords") or ""
                if isinstance(spec, (list, tuple)):
                    spec = ",".join(str(s) for s in spec)
                if str(spec).strip():
                    return str(spec)
        raw = (target.normalized or target.raw or "").strip()
        if target.type == "keyword_search" and raw:
            return raw
        if raw.lower().startswith(("kw:", "keywords:")):
            return raw.split(":", 1)[1]
        return os.environ.get("RECON_UNIFIED_SEARCH_QUERY", "").strip()

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        spec = self._query_spec(target, ctx)
        keywords = parse_keywords(spec)
        if not keywords:
            res = self._skipped(
                "no keyword query supplied: run with a keyword_search "
                "target (comma-separated keywords), publish "
                "keyword_query items, or set RECON_UNIFIED_SEARCH_QUERY")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        mode = os.environ.get(
            "RECON_UNIFIED_SEARCH_MODE", "and").strip().lower()
        if mode not in ("and", "or"):
            mode = "and"
        chains = {c.strip().lower() for c in os.environ.get(
            "RECON_UNIFIED_SEARCH_CHAINS", "").split(",") if c.strip()} \
            or None
        min_value = _env_float("RECON_UNIFIED_SEARCH_MIN_VALUE")
        try:
            limit = int(os.environ.get(
                "RECON_UNIFIED_SEARCH_LIMIT", "50"))
        except ValueError:
            limit = 50
        enqueue = os.environ.get(
            "RECON_UNIFIED_SEARCH_ENQUEUE", "").strip() in (
                "1", "true", "yes")
        index_db = os.environ.get("RECON_KW_INDEX_DB", "").strip()
        cont_home = os.environ.get("RECON_CONTINUOUS_HOME",
                                   "").strip()

        result = unified_search(
            keywords, mode=mode, chains=chains, min_value=min_value,
            limit=limit,
            index_db=Path(index_db) if index_db else None,
            continuous_home=Path(cont_home) if cont_home else None,
            enqueue=enqueue)

        findings: List[Finding] = []
        for hit in result["hits"]:
            lanes = ", ".join(hit["lanes"])
            matched = ", ".join(hit["matched_keywords"])
            value = (f"${hit['value_usd']:,.0f} value evidence "
                     "(stake/TVL-style, not extractable)"
                     if hit["value_usd"] is not None
                     else "value unknown")
            ev: Dict[str, Any] = {
                "severity": "low",
                "chain": hit["chain"], "address": hit["address"],
                "name": hit["name"], "value_usd": hit["value_usd"],
                "lanes": hit["lanes"],
                "matched_keywords": hit["matched_keywords"],
                "snippets": hit["snippets"], "line": hit["line"],
                "transition_events": hit["events"],
                "scanner_status": hit["scanner_status"],
                "finding_keys": hit["finding_keys"],
                "mode": mode,
                "remediation": (
                    "Treat this as a lead, not a finding: run the "
                    "live-probe validator (recipient analysis + live "
                    "balance evidence) before drawing any conclusion "
                    "about this contract."),
            }
            findings.append(self._f(
                "web3", "unified_keyword_match",
                f"LEAD: {hit['chain']} {hit['address']} "
                f"({hit['name'] or 'unnamed'}): matched keywords "
                f"[{matched}] via lane(s) [{lanes}]; {value}. A "
                f"keyword match is a lead for the validator, never a "
                f"verdict.",
                source="unified keyword search",
                confidence=85 if LANE_INDEX in hit["lanes"] else 70,
                evidence=ev, passive=True))

        status_bits = "; ".join(
            f"{lane}: {result['lane_status'][lane]}" for lane in LANES)
        reason = (f"{len(keywords)} keyword(s), mode={mode}: "
                  f"{result['total']} deduped lead(s) across lanes "
                  f"({status_bits}); shown {len(findings)}")
        if enqueue:
            reason += f"; enqueued {result['enqueued']} new row(s) " \
                      f"to the keyword_search queue"
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
