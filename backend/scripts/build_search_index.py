#!/usr/bin/env python3
"""Build the deployable ReconAnything search corpus.

Jay's order (2026-11-06): one searcher over everything ReconAnything
has collected — any keyword, any filter, 100 results in 1 second,
working on the LIVE service, not just this VM.

This script merges every corpus ReconAnything has already collected
into ONE compact corpus file that ships inside the backend image
(backend/app/searchdata/corpus.jsonl.gz) and is served by
app/search.py via GET /api/search:

  kwindex          ~/workspace/recon-keyword-search-2026-11-04/index.db
                   3,053 contracts with verified source (FTS5 DB, 287MB
                   on disk — the source itself is NOT shipped; see the
                   token note below)
  scanner batches  ~/workspace/recon-continuous/results/batches.jsonl
  scanner cands    ~/workspace/recon-continuous/results/candidates.jsonl
  real-hunt        ~/workspace/recon-real-hunt-2026-11-05/verdicts_*.jsonl
  FP audit         ~/workspace/recon-fp-audit-2026-11-05/audit_w*.jsonl
                   + queue_fp.jsonl
  transition watch ~/workspace/recon-continuous/state/watchlist.jsonl

Dedupe key: (chain, address) — EVM addresses lowercased, Solana
addresses kept case-sensitive (base58).

Search-document design: for source contracts the shipped doc carries
every DISTINCT identifier token from the verified source (function
names, variables, library calls...). Keyword presence in the doc ==
token presence in the source, which preserves kwsearch semantics
(AND of tokens) without shipping 287MB of source. Structured fields
(name, functions, selectors, plugins, kinds, verdict, recipients,
value, sources, seen range) ride alongside for filters and display.

Evidence hygiene: only identifier tokens (regex [A-Za-z_][A-Za-z0-9_]*)
are taken from source — string/hex literals (where key material would
live) never match that pattern, and long hex runs are stripped from
free-text reasons. No raw private keys or seeds enter the corpus.

Verdict precedence (strongest adjudication wins):
  FP audit (live re-probe, Nov 5-6) > real-hunt verdicts (Nov 5) >
  queue_fp (prior FP list) > scanner candidates (validator).
Within one rank: VERIFIED_REAL > UNVERIFIED > TRIGGER_ONLY >
FALSE_POSITIVE.

Update paths:
  full build   python3 scripts/build_search_index.py
               (re-reads every corpus; minutes; do this when the
               kwindex or adjudication files change)
  ingest only  python3 scripts/build_search_index.py \
                 --ingest-batches NEW_ROWS.jsonl
               (starts from the existing corpus file and folds in new
               scanner batch rows only — seconds. Pass a file with the
               new batches.jsonl rows, e.g. a tail slice; re-folding
               old rows is harmless because folding is set-union/max.)
  Then commit corpus.jsonl.gz and push: Render redeploys and the new
  data is live. (Batch pushes: Render auto-deploys on master pushes.)

All corpus locations are overridable: --kwindex-db, --continuous-home,
--hunt-dir, --audit-dir, --out.
"""
from __future__ import annotations

import argparse
import ast
import gzip
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

HOME = Path.home()
DEFAULT_KWINDEX = HOME / "workspace" / "recon-keyword-search-2026-11-04" / "index.db"
DEFAULT_CONT_HOME = HOME / "workspace" / "recon-continuous"
DEFAULT_HUNT_DIR = HOME / "workspace" / "recon-real-hunt-2026-11-05"
DEFAULT_AUDIT_DIR = HOME / "workspace" / "recon-fp-audit-2026-11-05"
REPO_BACKEND = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_BACKEND / "app" / "searchdata" / "corpus.jsonl.gz"

CHAIN_ALIASES = {"bnb": "bsc", "binance": "bsc", "eth": "ethereum",
                 "matic": "polygon"}
VERDICT_RANK = {"FALSE_POSITIVE": 0, "TRIGGER_ONLY": 1,
                "UNVERIFIED": 2, "VERIFIED_REAL": 3}
MAX_TOKENS = 6000          # distinct source tokens kept per contract
MAX_REASONS = 3
REASON_LEN = 240

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")
_FUNC_SIG = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
_FUNC_NAME_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEX_RUN = re.compile(r"\b[0-9a-fA-F]{64,}\b")
_PLUGIN_RE = re.compile(r"'plugin':\s*'([^']+)'")
_KEY_RE = re.compile(r"'key':\s*'([^']+)'")
_FUNC_RE = re.compile(r"'function':\s*'([^']*)'")


def norm_chain(chain: str) -> str:
    c = (chain or "").strip().lower()
    return CHAIN_ALIASES.get(c, c)


def key_of(chain: str, address: str) -> Tuple[str, str]:
    c = norm_chain(chain)
    a = (address or "").strip()
    if c != "solana":
        a = a.lower()
    return (c, a)


def fnum(v: Any) -> Optional[float]:
    try:
        if v is None or v == "" or v == "None":
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def clean_reason(text: Any) -> str:
    t = _HEX_RUN.sub("<hex>", str(text or "")).replace("\n", " ")
    return re.sub(r"\s+", " ", t).strip()[:REASON_LEN]


# ---------------------------------------------------------------------
# pure-python Keccak-256 (Ethereum variant) for function selectors.
# Self-tested against known vectors at build start; on any mismatch
# selectors are skipped rather than shipped wrong.
# ---------------------------------------------------------------------
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
       0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
       0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
       0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_R = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
      [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_MASK = (1 << 64) - 1


def _rot(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK if n else x


def _keccak_f(state: List[int]) -> None:
    for rc in _RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^
             state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rot(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rot(state[x + 5 * y],
                                                       _R[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ (
                    (~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def selector_of(sig: str) -> Optional[str]:
    try:
        return "0x" + keccak256(sig.encode()).hex()[:8]
    except Exception:
        return None


def _sig_params(raw: str) -> str:
    """Reduce a parameter list to canonical types for the selector."""
    parts, depth, cur = [], 0, ""
    for ch in raw:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    types = []
    for p in parts:
        toks = p.strip().split()
        if not toks:
            continue
        t = toks[0]
        if t == "address" and len(toks) > 1 and toks[1] == "payable":
            t = "address payable"
        types.append(t)
    return ",".join(types)


# ---------------------------------------------------------------------
# corpus record assembly
# ---------------------------------------------------------------------
class Rec:
    __slots__ = ("chain", "address", "name", "symbol", "value_usd",
                 "has_source", "functions", "selectors", "plugins",
                 "kinds", "verdict", "verdicts", "_vbest", "recipients",
                 "reasons", "sources", "first_seen", "last_seen",
                 "tokens")

    def __init__(self, chain: str, address: str) -> None:
        self.chain = chain
        self.address = address
        self.name = None
        self.symbol = None
        self.value_usd = None
        self.has_source = False
        self.functions: Set[str] = set()
        self.selectors: Set[str] = set()
        self.plugins: Set[str] = set()
        self.kinds: Set[str] = set()
        self.verdict = None
        self.verdicts: Set[str] = set()
        self._vbest = (-1, -1)   # (source precedence, verdict rank)
        self.recipients: Set[str] = set()
        self.reasons: List[str] = []
        self.sources: Set[str] = set()
        self.first_seen = None
        self.last_seen = None
        self.tokens: Set[str] = set()

    def set_value(self, v: Optional[float]) -> None:
        if v is not None and (self.value_usd is None or v > self.value_usd):
            self.value_usd = v

    def set_verdict(self, verdict: Optional[str], precedence: int,
                    reason: Any = None) -> None:
        if not verdict:
            return
        v = verdict.strip().upper()
        if v not in VERDICT_RANK:
            return
        self.verdicts.add(v)
        cand = (precedence, VERDICT_RANK[v])
        if cand > self._vbest:
            self._vbest = cand
            self.verdict = v
        if reason:
            r = clean_reason(reason)
            if r and r not in self.reasons and len(self.reasons) < MAX_REASONS:
                self.reasons.append(r)

    def seen(self, ts: Optional[str]) -> None:
        if not ts:
            return
        t = str(ts)
        if self.first_seen is None or t < self.first_seen:
            self.first_seen = t
        if self.last_seen is None or t > self.last_seen:
            self.last_seen = t

    def to_json(self) -> dict:
        doc_parts = [self.chain, self.address, self.name or "",
                     self.symbol or ""]
        doc_parts += sorted(self.functions)
        doc_parts += sorted(self.kinds)
        doc_parts += sorted(self.plugins)
        doc_parts += self.reasons
        doc_parts += sorted(self.tokens)
        return {
            "chain": self.chain, "address": self.address,
            "name": self.name, "symbol": self.symbol,
            "value_usd": self.value_usd,
            "has_source": 1 if self.has_source else 0,
            "functions": sorted(self.functions),
            "selectors": sorted(self.selectors),
            "plugins": sorted(self.plugins),
            "kinds": sorted(self.kinds),
            "verdict": self.verdict,
            "verdicts": sorted(self.verdicts),
            "recipients": sorted(self.recipients),
            "reasons": self.reasons,
            "sources": sorted(self.sources),
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "doc": " ".join(p for p in doc_parts if p),
        }


def get_rec(store: Dict[Tuple[str, str], Rec], chain: str,
            address: str) -> Optional[Rec]:
    if not chain or not address:
        return None
    k = key_of(chain, address)
    if k not in store:
        store[k] = Rec(k[0], k[1] if k[0] == "solana" else address.lower())
    return store[k]


def iter_jsonl(path: Path) -> Iterable[dict]:
    if not path.exists():
        return
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                yield obj


# ---------------------------------------------------------------------
# source loaders
# ---------------------------------------------------------------------
def load_kwindex(store: Dict[Tuple[str, str], Rec], db_path: Path,
                 want_selectors: bool) -> int:
    if not db_path.exists():
        print(f"kwindex: missing {db_path}", file=sys.stderr)
        return 0
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    meta = {}
    for chain, address, name, has_source, value in con.execute(
            "SELECT chain, address, name, has_source, value_usd "
            "FROM contracts"):
        rec = get_rec(store, chain, address)
        if rec is None:
            continue
        rec.sources.add("kwindex")
        if name and not rec.name:
            rec.name = str(name)
        if has_source:
            rec.has_source = True
        rec.set_value(fnum(value))
        meta[(rec.chain, rec.address)] = rec
    n = 0
    # one streaming pass over the FTS text: tokens + function signatures
    for chain, address, text in con.execute(
            "SELECT chain, address, text FROM src_fts"):
        rec = meta.get(key_of(chain, address))
        if rec is None or not text:
            continue
        n += 1
        toks = _IDENT.findall(text)
        if len(toks) > MAX_TOKENS:
            freq: Dict[str, int] = {}
            for t in toks:
                freq[t] = freq.get(t, 0) + 1
            toks = [t for t, _ in sorted(
                freq.items(), key=lambda kv: -kv[1])[:MAX_TOKENS]]
        rec.tokens.update(toks)
        for m in _FUNC_SIG.finditer(text):
            fname = m.group(1)
            rec.functions.add(fname)
            if want_selectors:
                sel = selector_of(f"{fname}({_sig_params(m.group(2))})")
                if sel:
                    rec.selectors.add(sel)
    con.close()
    return n


def _parse_pyobj(text: Any) -> Optional[Any]:
    if not isinstance(text, str) or not text or text == "[]":
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return None


def fold_findings(rec: Rec, findings: Any) -> None:
    parsed = _parse_pyobj(findings)
    if isinstance(parsed, list):
        for f in parsed:
            if not isinstance(f, dict):
                continue
            if f.get("plugin"):
                rec.plugins.add(str(f["plugin"]))
            if f.get("key"):
                rec.kinds.add(str(f["key"]))
            ev = f.get("evidence") or {}
            fn = ev.get("function") if isinstance(ev, dict) else None
            if fn and _FUNC_NAME_OK.match(str(fn)):
                rec.functions.add(str(fn))
            rc = f.get("recipient_class")
            if rc and rc != "UNKNOWN":
                rec.recipients.add(str(rc))
        return
    if isinstance(findings, str):  # regex fallback: presence is enough
        rec.plugins.update(_PLUGIN_RE.findall(findings))
        rec.kinds.update(_KEY_RE.findall(findings))
        for fn in _FUNC_RE.findall(findings):
            if fn and _FUNC_NAME_OK.match(fn):
                rec.functions.add(fn)


def fold_batch_row(store: Dict[Tuple[str, str], Rec], row: dict) -> bool:
    rec = get_rec(store, row.get("chain"), row.get("address"))
    if rec is None:
        return False
    rec.sources.add("scanner")
    if row.get("symbol") and not rec.symbol:
        rec.symbol = str(row["symbol"])
    rec.set_value(fnum(row.get("stake_usd")))
    rec.seen(row.get("scanned_at"))
    if row.get("status") == "genuine":
        pass
    fold_findings(rec, row.get("findings"))
    cands = _parse_pyobj(row.get("candidates"))
    if isinstance(cands, list):
        for c in cands:
            if isinstance(c, dict):
                fold_candidate(rec, c)
    return True


def fold_candidate(rec: Rec, c: dict) -> None:
    if c.get("plugin"):
        rec.plugins.add(str(c["plugin"]))
    if c.get("key"):
        rec.kinds.add(str(c["key"]))
    fn = c.get("function")
    if fn and _FUNC_NAME_OK.match(str(fn)):
        rec.functions.add(str(fn))
    rc = c.get("recipient_class")
    if rc and rc != "UNKNOWN":
        rec.recipients.add(str(rc))
    val = c.get("validation") or {}
    if isinstance(val, dict):
        rec.set_verdict(val.get("verdict"), 1, val.get("reason"))
        r = val.get("recipient")
        if r in ("CALLER", "CALLER-SUPPLIED", "FIXED", "HOLDER-SELF"):
            rec.recipients.add(r)
    rec.seen(c.get("found_at"))


def load_batches(store: Dict[Tuple[str, str], Rec], path: Path) -> int:
    n = 0
    for row in iter_jsonl(path):
        if fold_batch_row(store, row):
            n += 1
    return n


def load_candidates(store: Dict[Tuple[str, str], Rec], path: Path) -> int:
    n = 0
    for row in iter_jsonl(path):
        rec = get_rec(store, row.get("chain"), row.get("address"))
        if rec is None:
            continue
        rec.sources.add("scanner")
        fold_candidate(rec, row)
        n += 1
    return n


def load_hunt_verdicts(store: Dict[Tuple[str, str], Rec],
                       hunt_dir: Path) -> int:
    n = 0
    for path in sorted(hunt_dir.glob("verdicts_*.jsonl")):
        for row in iter_jsonl(path):
            rec = get_rec(store, row.get("chain"), row.get("address"))
            if rec is None:
                continue
            rec.sources.add("real_hunt")
            if row.get("name") and not rec.name:
                rec.name = str(row["name"])
            rec.set_value(fnum(row.get("live_value_usd")))
            rec.set_verdict(row.get("verdict"), 3,
                            row.get("kill_or_path"))
            flagged = row.get("flagged")
            if flagged and _FUNC_NAME_OK.match(str(flagged)):
                rec.functions.add(str(flagged))
            n += 1
    for row in iter_jsonl(hunt_dir / "live_value.jsonl"):
        rec = get_rec(store, row.get("chain"), row.get("address"))
        if rec is None:
            continue
        rec.sources.add("real_hunt")
        if row.get("name") and not rec.name:
            rec.name = str(row["name"])
        rec.set_value(fnum(row.get("usd")))
    return n


def load_audit(store: Dict[Tuple[str, str], Rec], audit_dir: Path) -> int:
    n = 0
    amap = {"CONFIRMED_DEAD": "FALSE_POSITIVE",
            "RECIPIENT_HELD": "TRIGGER_ONLY",
            "REOPENED": "UNVERIFIED"}
    for path in sorted(audit_dir.glob("audit_w*.jsonl")):
        for row in iter_jsonl(path):
            rec = get_rec(store, row.get("chain"), row.get("address"))
            if rec is None:
                continue
            rec.sources.add("fp_audit")
            if row.get("name") and not rec.name:
                rec.name = str(row["name"])
            rec.set_value(fnum(row.get("live_value_usd")))
            res = str(row.get("audit_result") or "").upper()
            rec.set_verdict(amap.get(res), 4, row.get("kill_reason_class"))
            if row.get("kill_reason_class") == "holder_self":
                rec.recipients.add("HOLDER-SELF")
            n += 1
    for row in iter_jsonl(audit_dir / "queue_fp.jsonl"):
        rec = get_rec(store, row.get("chain"), row.get("address"))
        if rec is None:
            continue
        rec.sources.add("fp_audit")
        if row.get("name") and not rec.name:
            rec.name = str(row["name"])
        rec.set_value(fnum(row.get("live_value_usd")))
        rec.set_verdict("FALSE_POSITIVE", 2)
        for fn in row.get("fns") or []:
            if isinstance(fn, str) and _FUNC_NAME_OK.match(fn):
                rec.functions.add(fn)
        n += 1
    return n


def load_watchlist(store: Dict[Tuple[str, str], Rec], path: Path) -> int:
    n = 0
    for row in iter_jsonl(path):
        rec = get_rec(store, row.get("chain"), row.get("address"))
        if rec is None:
            continue
        rec.sources.add("transition_watch")
        if row.get("symbol") and not rec.symbol:
            rec.symbol = str(row["symbol"])
        rec.set_value(fnum(row.get("stake_usd")))
        n += 1
    return n


def load_existing_corpus(store: Dict[Tuple[str, str], Rec],
                         path: Path) -> int:
    """Seed the store from a previously built corpus (ingest mode)."""
    if not path.exists():
        return 0
    n = 0
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", errors="replace") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if "_meta" in obj or "chain" not in obj:
                continue
            rec = get_rec(store, obj["chain"], obj["address"])
            if rec is None:
                continue
            rec.name = obj.get("name") or rec.name
            rec.symbol = obj.get("symbol") or rec.symbol
            rec.set_value(fnum(obj.get("value_usd")))
            rec.has_source = bool(obj.get("has_source"))
            rec.functions.update(obj.get("functions") or [])
            rec.selectors.update(obj.get("selectors") or [])
            rec.plugins.update(obj.get("plugins") or [])
            rec.kinds.update(obj.get("kinds") or [])
            rec.recipients.update(obj.get("recipients") or [])
            rec.reasons = list(obj.get("reasons") or [])
            rec.sources.update(obj.get("sources") or [])
            rec.first_seen = obj.get("first_seen")
            rec.last_seen = obj.get("last_seen")
            for v in obj.get("verdicts") or []:
                rec.set_verdict(v, 0)
            if obj.get("verdict"):
                rec.set_verdict(obj["verdict"], 5)
            # keep the old doc's tail tokens: doc = fields + tokens;
            # re-derive the token set from the doc so a later fold can
            # only grow it (doc text beyond the structured fields is
            # stored verbatim in `tokens` via a marker split).
            rec.tokens.update(_doc_tokens(obj.get("doc") or ""))
            n += 1
    return n


def _doc_tokens(doc: str) -> Set[str]:
    """Best-effort recovery of the token set from a stored doc.

    The doc is: chain address name symbol functions kinds plugins
    reasons tokens. Structured parts are re-added at write time from
    the record fields; anything in the doc that is a bare identifier
    and not part of reasons is treated as a token. Reasons are short
    prose — their words also become tokens, which is harmless for
    presence search (they were searchable before too).
    """
    return {t for t in _IDENT.findall(doc) if len(t) > 1}


# ---------------------------------------------------------------------
# main
# ---------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kwindex-db", type=Path, default=DEFAULT_KWINDEX)
    ap.add_argument("--continuous-home", type=Path,
                    default=DEFAULT_CONT_HOME)
    ap.add_argument("--hunt-dir", type=Path, default=DEFAULT_HUNT_DIR)
    ap.add_argument("--audit-dir", type=Path, default=DEFAULT_AUDIT_DIR)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--ingest-batches", type=Path, default=None,
                    help="fold ONLY these batch rows into the existing "
                         "corpus at --out (incremental update)")
    args = ap.parse_args()

    t0 = time.time()
    # keccak self-test: transfer(address,uint256)=a9059cbb,
    # approve(address,uint256)=095ea7b3
    want_selectors = (
        selector_of("transfer(address,uint256)") == "0xa9059cbb" and
        selector_of("approve(address,uint256)") == "0x095ea7b3")
    if not want_selectors:
        print("WARNING: keccak self-test failed; selectors skipped",
              file=sys.stderr)

    store: Dict[Tuple[str, str], Rec] = {}
    stats: Dict[str, int] = {}
    if args.ingest_batches:
        stats["existing"] = load_existing_corpus(store, args.out)
        stats["ingested_rows"] = load_batches(store, args.ingest_batches)
    else:
        stats["kwindex"] = load_kwindex(store, args.kwindex_db,
                                        want_selectors)
        stats["verdicts"] = load_hunt_verdicts(store, args.hunt_dir)
        stats["audit"] = load_audit(store, args.audit_dir)
        stats["batches"] = load_batches(
            store, args.continuous_home / "results" / "batches.jsonl")
        stats["candidates"] = load_candidates(
            store, args.continuous_home / "results" / "candidates.jsonl")
        stats["watchlist"] = load_watchlist(
            store, args.continuous_home / "state" / "watchlist.jsonl")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    by_chain: Dict[str, int] = {}
    by_verdict: Dict[str, int] = {}
    meta = {"_meta": {"built_at": time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "contracts": len(store), "stats": stats}}
    tmp = args.out.with_suffix(args.out.suffix + ".tmp")
    with gzip.open(tmp, "wt") as f:
        f.write(json.dumps(meta) + "\n")
        for rec in store.values():
            by_chain[rec.chain] = by_chain.get(rec.chain, 0) + 1
            if rec.verdict:
                by_verdict[rec.verdict] = by_verdict.get(rec.verdict, 0) + 1
            f.write(json.dumps(rec.to_json()) + "\n")
    tmp.replace(args.out)
    size = args.out.stat().st_size
    print(json.dumps({"contracts": len(store), "by_chain": by_chain,
                      "by_verdict": by_verdict, "stats": stats,
                      "out": str(args.out), "bytes": size,
                      "secs": round(time.time() - t0, 1)}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
