"""Cross-modal / multimodal vector embeddings for ReconAnything triage.

One shared embedding space combining three modalities per
contract/finding, pure Python stdlib (no new dependencies):

  (a) verified source text  -- the Solidity excerpt in
      evidence["code"], plus contract name / function / selectors.
  (b) deployed bytecode     -- opcode n-grams. Consumes whatever the
      row actually carries: an opcode-count histogram
      (evidence["opcodes"] as a dict, the shape contract_recon and
      bytecode_deep_analysis emit), a mnemonic sequence string, or
      raw hex bytecode (decoded to mnemonics with the EVM table
      below, then unigram + bigram tokens). Hex byte bigrams are
      kept as a fallback token family.
  (c) finding text          -- plugin id + finding key + value +
      detail / check / remediation / function / risk strings.

Method: hashed TF-IDF per modality (SHA-256 token -> fixed bucket,
IDF fit on TRAIN rows only, never on the test holdout), per-modality
L2 normalisation, weighted concatenation into one shared space
(640 dims: 256 source + 128 bytecode + 256 finding), L2-normalised
again. Cosine similarity in that space is the neighbour metric:
similar contracts and similar findings land close together.

A fixed seeded random projection (640 -> 32, rebuilt deterministically
from its seed, never stored as a matrix) gives the dense block the
triage MLP consumes: 32 projected dims + 3 modality-presence flags.
A k-NN triage head over the projected train index is the second
consumer: knn_score is the similarity-weighted label mean of the
k nearest train rows.

Missing modalities are normal, not an error: external audit rows
carry no source text and no training row carries bytecode (see
coverage in docs/nn-multimodal.md). A missing modality contributes
a zero block and a 0.0 presence flag; the vector is renormalised
over the modalities that are present. An all-empty row embeds to
the zero vector and the k-NN head falls back to the train base rate.

Triage only. Embeddings rank findings by similarity to past
findings; they never verify anything and never predict
VERIFIED_REAL. Detection only, read-only, no transactions.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
import re
from typing import Dict, List, Optional, Sequence, Tuple

# --- shared-space layout -------------------------------------------------
SOURCE_BUCKETS = 256
BYTECODE_BUCKETS = 128
FINDING_BUCKETS = 256
SHARED_DIM = SOURCE_BUCKETS + BYTECODE_BUCKETS + FINDING_BUCKETS
BYTECODE_OFFSET = SOURCE_BUCKETS
FINDING_OFFSET = SOURCE_BUCKETS + BYTECODE_BUCKETS

# Dense block the MLP consumes: projected dims + presence flags.
PROJ_DIM = 32
PROJ_SEED = 1234
N_PRESENCE = 3
EXTRA_DIM = PROJ_DIM + N_PRESENCE

MODALITY_WEIGHTS = {"source": 1.0, "bytecode": 1.0, "finding": 1.0}

# k-NN triage head.
KNN_K = 15
BLEND_MLP = 0.7
BLEND_KNN = 0.3

FORMAT = "recon-nn-multimodal/1"

_STOPWORDS = frozenset(
    "the a an and or of to in on for with is are was were be by at as it "
    "this that from".split()
)

# --- EVM opcode table (mnemonic by byte) ---------------------------------
# PUSH1..PUSH32, DUP1..DUP16, SWAP1..SWAP16, LOG0..LOG4 are ranges and
# are handled in _decode_hex_bytecode; the table below covers the rest.
_OPCODES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD",
    0x09: "MULMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
    0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
    0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR", 0x1D: "SAR",
    0x20: "SHA3", 0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN",
    0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH", 0x40: "BLOCKHASH", 0x41: "COINBASE",
    0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "DIFFICULTY",
    0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE",
    0x48: "BASEFEE", 0x49: "BLOBHASH", 0x4A: "BLOBBASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
    0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
    0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS", 0x5B: "JUMPDEST",
    0x5C: "TLOAD", 0x5D: "TSTORE", 0x5E: "MCOPY",
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN",
    0xF4: "DELEGATECALL", 0xF5: "CREATE2", 0xFA: "STATICCALL",
    0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}
_KNOWN_MNEMONICS = frozenset(_OPCODES.values()) | frozenset(
    [f"PUSH{i}" for i in range(1, 33)]
    + [f"DUP{i}" for i in range(1, 17)]
    + [f"SWAP{i}" for i in range(1, 17)]
    + [f"LOG{i}" for i in range(5)]
)


def _decode_hex_bytecode(hexstr: str) -> List[str]:
    """Raw hex bytecode -> opcode mnemonic sequence.

    Walks the bytes; PUSHn skips its n immediate bytes. Unknown
    bytes are skipped (never invented as an opcode). Returns [] for
    anything that is not plausible hex.
    """
    s = (hexstr or "").strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    if not s or len(s) % 2 or len(s) > 200000:
        return []
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return []
    if len(raw) < 2:
        return []
    out: List[str] = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if 0x60 <= b <= 0x7F:  # PUSH1..PUSH32
            out.append(f"PUSH{b - 0x60 + 1}")
            i += 1 + (b - 0x60 + 1)
        elif 0x80 <= b <= 0x8F:
            out.append(f"DUP{b - 0x80 + 1}")
            i += 1
        elif 0x90 <= b <= 0x9F:
            out.append(f"SWAP{b - 0x90 + 1}")
            i += 1
        elif 0xA0 <= b <= 0xA4:
            out.append(f"LOG{b - 0xA0}")
            i += 1
        elif b in _OPCODES:
            out.append(_OPCODES[b])
            i += 1
        else:
            i += 1  # unknown byte: skip, do not invent
    return out


# --- tokenisation ----------------------------------------------------------

_IDENT_SPLIT = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _split_identifier(tok: str) -> List[str]:
    """camelCase / snake_case / ALLCAPS identifier -> lower word parts."""
    parts: List[str] = []
    for chunk in tok.replace("-", "_").split("_"):
        if not chunk:
            continue
        for p in _IDENT_SPLIT.split(chunk):
            p = p.lower()
            if len(p) >= 2:
                parts.append(p)
    return parts


def tokenize_source(text: str) -> List[str]:
    """Solidity source excerpt -> identifier + word tokens."""
    toks: List[str] = []
    for m in _WORD_RE.finditer(text or ""):
        toks.extend(_split_identifier(m.group(0)))
    return toks


def tokenize_finding(text: str) -> List[str]:
    """Finding text -> word tokens (stopwords dropped) + key trigrams."""
    toks = [t.lower() for t in _WORD_RE.findall(text or "")
            if len(t) >= 2 and t.lower() not in _STOPWORDS]
    return toks


def tokenize_bytecode(opcodes, hexstr: str = "") -> List[str]:
    """Opcode histogram / mnemonic sequence / hex -> opcode tokens.

    Unigrams "op:<MNEMONIC>" plus bigrams "op:<A>><B>" when an
    ordered sequence exists. A histogram (dict) has no order, so it
    yields unigrams only, weighted by count. Hex byte bigrams
    "hx:<AB>" are a fallback family when no mnemonic decodes.
    """
    toks: List[str] = []
    seq: List[str] = []
    if isinstance(opcodes, dict):
        for name, count in opcodes.items():
            name = str(name).upper()
            if name in _KNOWN_MNEMONICS:
                try:
                    n = max(1, int(count))
                except (TypeError, ValueError):
                    n = 1
                toks.extend([f"op:{name}"] * min(n, 50))
    elif isinstance(opcodes, str) and opcodes.strip():
        s = opcodes.strip()
        if re.fullmatch(r"(0x)?[0-9a-fA-F]+", s) and len(s) > 8:
            seq = _decode_hex_bytecode(s)
        else:
            seq = [w.upper() for w in re.split(r"[\s,;]+", s)
                   if w.upper() in _KNOWN_MNEMONICS]
    if hexstr:
        seq = seq or _decode_hex_bytecode(hexstr)
    if seq:
        toks += [f"op:{m}" for m in seq]
        toks += [f"op:{a}>{b}" for a, b in zip(seq, seq[1:])]
    if hexstr and not seq:
        h = (hexstr or "").strip()
        if h.lower().startswith("0x"):
            h = h[2:]
        h = h.lower()
        if re.fullmatch(r"[0-9a-f]+", h) and len(h) >= 4:
            toks += [f"hx:{h[i:i + 4]}" for i in range(0, len(h) - 3, 2)]
    return toks


# --- row -> modality texts -------------------------------------------------

def _s(value, cap: int = 2000) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:cap]
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, default=str)[:cap]
        except Exception:
            return str(value)[:cap]
    return str(value)[:cap]


def extract_modal_texts(row_or_finding: Dict) -> Dict[str, object]:
    """One row dict (finding/label/...) or one finding dict ->
    {"source": str, "opcodes": dict|str, "bytecode_hex": str,
     "finding": str}. Missing fields read as empty, never invented."""
    if isinstance(row_or_finding, dict) and isinstance(
            row_or_finding.get("finding"), dict):
        finding = row_or_finding["finding"]
    else:
        finding = row_or_finding or {}
    ev = finding.get("evidence") or {}
    if not isinstance(ev, dict):
        ev = {}

    source_parts = [_s(ev.get("code"), 4000),
                    _s(ev.get("contract_name"), 200),
                    _s(finding.get("function") or ev.get("function"), 200),
                    _s(ev.get("selectors"), 500)]
    source = " ".join(p for p in source_parts if p)

    opcodes = ev.get("opcodes")
    bytecode_hex = ""
    for key in ("bytecode", "deployed_bytecode", "bytecode_hex",
                "runtime_bytecode"):
        val = ev.get(key)
        if isinstance(val, str) and len(val.strip()) > 8:
            bytecode_hex = val.strip()
            break

    finding_parts = [
        _s(finding.get("plugin"), 200),
        _s(finding.get("key") or ev.get("check"), 200),
        _s(finding.get("value"), 1000),
        _s(ev.get("detail"), 2000),
        _s(ev.get("check"), 500),
        _s(ev.get("remediation"), 1000),
        _s(finding.get("function") or ev.get("function"), 200),
        _s(ev.get("risk"), 100),
        _s(finding.get("severity") or ev.get("severity"), 100),
    ]
    finding_text = " ".join(p for p in finding_parts if p)
    return {"source": source, "opcodes": opcodes,
            "bytecode_hex": bytecode_hex, "finding": finding_text}


def modal_token_counts(texts: Dict[str, object]) -> Dict[str, Dict[str, int]]:
    """Modality texts -> {modality: {token: count}}."""
    out: Dict[str, Dict[str, int]] = {}

    def _count(tokens: List[str]) -> Dict[str, int]:
        d: Dict[str, int] = {}
        for t in tokens:
            d[t] = d.get(t, 0) + 1
        return d

    out["source"] = _count(tokenize_source(str(texts.get("source") or "")))
    out["bytecode"] = _count(tokenize_bytecode(texts.get("opcodes"),
                                               str(texts.get("bytecode_hex") or "")))
    finding_toks = tokenize_finding(str(texts.get("finding") or ""))
    # Char trigrams of the finding key catch near-duplicate keys
    # ("unprotected_drain" vs "unprotected_drain_v2").
    key = ""
    ftext = str(texts.get("finding") or "")
    if ftext:
        key = ftext.split(" ", 1)[0] if " " in ftext else ftext
    for i in range(max(0, len(key) - 2)):
        finding_toks.append(f"key3:{key[i:i + 3].lower()}")
    out["finding"] = _count(finding_toks)
    return out


# --- hashed TF-IDF ---------------------------------------------------------

def _bucket(token: str, n_buckets: int) -> int:
    h = hashlib.sha256(token.encode("utf-8")).digest()
    return int.from_bytes(h[:8], "little") % n_buckets


class MultimodalEmbedder:
    """Fit-on-train hashed TF-IDF embedder + shared-space projection
    + k-NN triage head. Pure stdlib; deterministic given the seed."""

    def __init__(self, source_buckets: int = SOURCE_BUCKETS,
                 bytecode_buckets: int = BYTECODE_BUCKETS,
                 finding_buckets: int = FINDING_BUCKETS,
                 weights: Optional[Dict[str, float]] = None,
                 proj_dim: int = PROJ_DIM, proj_seed: int = PROJ_SEED,
                 knn_k: int = KNN_K) -> None:
        self.source_buckets = int(source_buckets)
        self.bytecode_buckets = int(bytecode_buckets)
        self.finding_buckets = int(finding_buckets)
        self.weights = dict(MODALITY_WEIGHTS)
        if weights:
            self.weights.update(weights)
        self.proj_dim = int(proj_dim)
        self.proj_seed = int(proj_seed)
        self.knn_k = int(knn_k)
        self.idf: Dict[str, List[float]] = {}
        self.n_train = 0
        self.train_pos_rate = 0.0
        self.index: List[Dict] = []  # {dense, label, plugin, key}
        self._proj: Optional[List[List[float]]] = None

    # -- fitting -----------------------------------------------------------
    @property
    def dim(self) -> int:
        return (self.source_buckets + self.bytecode_buckets
                + self.finding_buckets)

    def fit(self, rows: Sequence[Dict]) -> "MultimodalEmbedder":
        """Learn IDF per modality from TRAIN rows only. Also stores
        the train positive rate (k-NN fallback) — never test rows."""
        rows = list(rows)
        self.n_train = len(rows)
        counts = [modal_token_counts(extract_modal_texts(r)) for r in rows]
        buckets = {"source": self.source_buckets,
                   "bytecode": self.bytecode_buckets,
                   "finding": self.finding_buckets}
        self.idf = {}
        for mod, n_b in buckets.items():
            df = [0] * n_b
            for c in counts:
                for tok in c[mod]:
                    df[_bucket(tok, n_b)] += 1
            n = max(1, len(rows))
            self.idf[mod] = [math.log((1.0 + n) / (1.0 + d)) + 1.0
                             for d in df]
        if rows:
            self.train_pos_rate = (
                sum(1 for r in rows if r.get("label") == 1) / len(rows))
        return self

    def build_index(self, rows: Sequence[Dict]) -> "MultimodalEmbedder":
        """Project TRAIN rows into the k-NN index (dense vectors +
        labels + plugin/key). Test rows are never indexed."""
        self.index = []
        for r in rows:
            f = r.get("finding") or r
            emb = self.embed(r)
            self.index.append({
                "dense": emb["dense"],
                "label": int(r.get("label", 0)),
                "plugin": str(f.get("plugin") or ""),
                "key": str(f.get("key") or ""),
            })
        return self

    # -- embedding ---------------------------------------------------------
    def _modality_vector(self, counts: Dict[str, int], mod: str) -> Dict[int, float]:
        n_b = {"source": self.source_buckets,
               "bytecode": self.bytecode_buckets,
               "finding": self.finding_buckets}[mod]
        idf = self.idf.get(mod)
        if idf is None:
            raise ValueError("embedder not fit: call fit() first")
        vec: Dict[int, float] = {}
        for tok, c in counts.items():
            b = _bucket(tok, n_b)
            vec[b] = vec.get(b, 0.0) + (1.0 + math.log(c)) * idf[b]
        norm = math.sqrt(sum(v * v for v in vec.values()))
        if norm <= 0.0:
            return {}
        return {b: v / norm for b, v in vec.items()}

    def embed_sparse(self, row_or_finding: Dict) -> Tuple[Dict[int, float], List[float]]:
        """-> (shared-space sparse vector {global_idx: value},
        presence [source, bytecode, finding]). Unit-norm over the
        modalities present; {} + [0,0,0] when everything is empty."""
        texts = extract_modal_texts(row_or_finding)
        counts = modal_token_counts(texts)
        mods = [("source", 0, self.source_buckets),
                ("bytecode", BYTECODE_OFFSET, self.bytecode_buckets),
                ("finding", FINDING_OFFSET, self.finding_buckets)]
        sparse: Dict[int, float] = {}
        presence: List[float] = []
        for mod, offset, _n in mods:
            vec = self._modality_vector(counts[mod], mod)
            presence.append(1.0 if vec else 0.0)
            w = self.weights.get(mod, 1.0)
            for b, v in vec.items():
                sparse[offset + b] = w * v
        norm = math.sqrt(sum(v * v for v in sparse.values()))
        if norm > 0.0:
            sparse = {i: v / norm for i, v in sparse.items()}
        return sparse, presence

    def _projection(self) -> List[List[float]]:
        if self._proj is None:
            rng = random.Random(self.proj_seed)
            scale = 1.0 / math.sqrt(self.proj_dim)
            self._proj = [[rng.gauss(0.0, scale) for _ in range(self.proj_dim)]
                          for _ in range(self.dim)]
        return self._proj

    def project(self, sparse: Dict[int, float]) -> List[float]:
        """Seeded random projection 640 -> PROJ_DIM, L2-normalised.
        Deterministic: the matrix is rebuilt from proj_seed, never
        stored, so save/load round-trips exactly."""
        proj = self._projection()
        dense = [0.0] * self.proj_dim
        for i, v in sparse.items():
            row = proj[i]
            for j in range(self.proj_dim):
                dense[j] += v * row[j]
        norm = math.sqrt(sum(v * v for v in dense))
        if norm > 0.0:
            dense = [v / norm for v in dense]
        return dense

    def embed(self, row_or_finding: Dict) -> Dict:
        sparse, presence = self.embed_sparse(row_or_finding)
        return {"sparse": sparse, "dense": self.project(sparse),
                "presence": presence}

    def feature_block(self, row_or_finding: Dict) -> List[float]:
        """The 35 extra MLP inputs: 32 projected dims + 3 presence."""
        emb = self.embed(row_or_finding)
        return list(emb["dense"]) + list(emb["presence"])

    # -- similarity + k-NN ---------------------------------------------------
    @staticmethod
    def cosine_sparse(a: Dict[int, float], b: Dict[int, float]) -> float:
        if not a or not b:
            return 0.0
        if len(a) > len(b):
            a, b = b, a
        return sum(v * b.get(i, 0.0) for i, v in a.items())

    @staticmethod
    def cosine_dense(a: Sequence[float], b: Sequence[float]) -> float:
        return sum(x * y for x, y in zip(a, b))

    def neighbours(self, dense: Sequence[float],
                   k: Optional[int] = None) -> List[Dict]:
        """Top-k train neighbours by cosine in projected space."""
        k = k or self.knn_k
        scored = []
        for idx, entry in enumerate(self.index):
            sim = self.cosine_dense(dense, entry["dense"])
            scored.append((sim, idx))
        scored.sort(reverse=True)
        out = []
        for sim, idx in scored[:k]:
            e = self.index[idx]
            out.append({"similarity": round(sim, 4), "label": e["label"],
                        "plugin": e["plugin"], "key": e["key"]})
        return out

    def knn_score(self, dense: Sequence[float],
                  k: Optional[int] = None) -> float:
        """Similarity-weighted label mean of the k nearest train rows.
        Falls back to the train positive rate when nothing is similar
        (e.g. an all-empty row) — never invents a confident score."""
        if not self.index:
            return self.train_pos_rate
        k = k or self.knn_k
        scored = sorted(
            ((self.cosine_dense(dense, e["dense"]), e["label"])
             for e in self.index),
            reverse=True)[:k]
        num = sum(max(0.0, s) * lab for s, lab in scored)
        den = sum(max(0.0, s) for s, _ in scored)
        if den <= 0.0:
            return self.train_pos_rate
        return num / den

    def retrieval_precision_at_k(self, rows: Sequence[Dict],
                                 k: int = 5) -> Dict:
        """Clustering check: for each row, what fraction of its top-k
        train neighbours share its plugin? Reported overall, macro
        (mean per-plugin rate, so the dominant plugin cannot hide a
        failure on rare plugins), and with the single most common
        plugin excluded. Neighbours come from the train index only;
        a test row is never its own neighbour."""
        if not self.index:
            return {"p_at_5": 0.0, "p_at_5_macro": 0.0,
                    "p_at_5_excl_dominant": 0.0, "n": 0}
        per_plugin: Dict[str, List[float]] = {}
        rates: List[float] = []
        dominant = None
        from collections import Counter
        cnt = Counter(str((r.get("finding") or r).get("plugin") or "")
                      for r in rows)
        if cnt:
            dominant = cnt.most_common(1)[0][0]
        excl_rates: List[float] = []
        for r in rows:
            f = r.get("finding") or r
            plugin = str(f.get("plugin") or "")
            emb = self.embed(r)
            neigh = self.neighbours(emb["dense"], k=k)
            if not neigh:
                continue
            rate = sum(1 for nb in neigh if nb["plugin"] == plugin) / len(neigh)
            rates.append(rate)
            per_plugin.setdefault(plugin, []).append(rate)
            if plugin != dominant:
                excl_rates.append(rate)
        def _mean(xs: List[float]) -> float:
            return sum(xs) / len(xs) if xs else 0.0
        macro = _mean([_mean(v) for v in per_plugin.values()])
        return {
            "p_at_5": round(_mean(rates), 4),
            "p_at_5_macro": round(macro, 4),
            "p_at_5_excl_dominant": round(_mean(excl_rates), 4),
            "dominant_plugin": dominant,
            "n": len(rates),
            "per_plugin": {p: round(_mean(v), 4)
                           for p, v in sorted(per_plugin.items())},
        }

    # -- persistence ---------------------------------------------------------
    def to_dict(self) -> Dict:
        return {
            "format": FORMAT,
            "source_buckets": self.source_buckets,
            "bytecode_buckets": self.bytecode_buckets,
            "finding_buckets": self.finding_buckets,
            "weights": self.weights,
            "proj_dim": self.proj_dim,
            "proj_seed": self.proj_seed,
            "knn_k": self.knn_k,
            "idf": self.idf,
            "n_train": self.n_train,
            "train_pos_rate": self.train_pos_rate,
            "index": self.index,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "MultimodalEmbedder":
        if data.get("format") != FORMAT:
            raise ValueError("not a recon-nn-multimodal/1 embedder")
        emb = cls(data.get("source_buckets", SOURCE_BUCKETS),
                  data.get("bytecode_buckets", BYTECODE_BUCKETS),
                  data.get("finding_buckets", FINDING_BUCKETS),
                  weights=data.get("weights"),
                  proj_dim=int(data.get("proj_dim", PROJ_DIM)),
                  proj_seed=int(data.get("proj_seed", PROJ_SEED)),
                  knn_k=int(data.get("knn_k", KNN_K)))
        emb.idf = {m: [float(v) for v in vals]
                   for m, vals in (data.get("idf") or {}).items()}
        emb.n_train = int(data.get("n_train", 0))
        emb.train_pos_rate = float(data.get("train_pos_rate", 0.0))
        emb.index = data.get("index") or []
        return emb

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh)

    @classmethod
    def load(cls, path: str) -> "MultimodalEmbedder":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))
