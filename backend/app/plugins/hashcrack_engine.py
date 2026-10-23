"""Direct-mode hash cracking engine (user-submitted hashes ONLY).

Ported from Jay's standalone hash-cracker tool (jaykk99/hash-cracker)
into ReconAnything. Dictionary + rules attack against the bundled
10,000 most-common-passwords list:

    MD5, NTLM, SHA-1, SHA-224/256/384/512, SHA3-224/256/384/512,
    bcrypt (top candidates only; needs the `bcrypt` package).

BOUNDARY (settled, do not widen): this engine runs ONLY on hashes a
user explicitly submits in direct mode. The scanner never calls it:
hashes found on scanned targets are analysis-only (type, breach-DB
status, crackability verdict, remediation) and scan findings never
contain recovered plaintexts.

Every crack attempt is time-boxed (see `crack_submitted`): the caller
passes a deadline in seconds and the engine stops at the deadline and
reports what it tried, so a request can never wedge a worker.

Wordlist: `data/10k-most-common.txt`, the SecLists 10,000 most common
passwords list by Daniel Miessler and contributors (MIT). See
`data/ATTRIBUTION.txt`.
"""
from __future__ import annotations

import hashlib
import time
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .md4 import ntlm_hex

WORDLIST_PATH = Path(__file__).parent / "data" / "10k-most-common.txt"

# Hard cap for one direct-mode crack request (seconds). The plugin
# passes this to crack_submitted; the engine enforces it internally.
DIRECT_CRACK_TIMEBOX_S = 60.0

# bcrypt is slow by design: only this many top base-form candidates
# are practical to check inside the time box.
BCRYPT_CANDIDATE_LIMIT = 300

_HEX_LEN_TO_ALGOS = {
    32: ["md5", "ntlm"],            # ambiguous: try both
    40: ["sha1"],
    56: ["sha224", "sha3_224"],
    64: ["sha256", "sha3_256"],
    96: ["sha384", "sha3_384"],
    128: ["sha512", "sha3_512"],
}

_ALGO_LABEL = {
    "md5": "MD5", "ntlm": "NTLM", "sha1": "SHA-1",
    "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
    "sha512": "SHA-512", "sha3_224": "SHA3-224", "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384", "sha3_512": "SHA3-512", "bcrypt": "bcrypt",
}


def identify(hash_str: str) -> Tuple[str, List[str]]:
    """Return (kind, algos) where kind is 'fast', 'bcrypt', or 'unknown'."""
    h = (hash_str or "").strip()
    if h.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt", ["bcrypt"]
    low = h.lower()
    if low and all(c in "0123456789abcdef" for c in low) \
            and len(low) in _HEX_LEN_TO_ALGOS:
        return "fast", _HEX_LEN_TO_ALGOS[len(low)]
    return "unknown", []


def label_for(algos: List[str]) -> str:
    return "/".join(_ALGO_LABEL[a] for a in algos)


def _digest_for(algo: str, candidate: str) -> str:
    if algo == "ntlm":
        return ntlm_hex(candidate)
    return hashlib.new(algo, candidate.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Candidate generation: wordlist x rules
# ---------------------------------------------------------------------------

_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5",
                       "A": "4", "E": "3", "I": "1", "O": "0", "S": "5"})

_COMMON_SUFFIXES = ["123", "1234", "12345", "123456", "12345678",
                    "007", "69", "420", "666", "777", "888", "999",
                    "111", "000", "2023", "2024", "2025", "2026"]
_FULL_SUFFIXES = (["", "!"] + [str(d) for d in range(10)]
                  + ["%02d" % d for d in range(100)]
                  + _COMMON_SUFFIXES
                  + [str(y) for y in range(1970, 2031)])
_LIGHT_SUFFIXES = ["", "!"] + [str(d) for d in range(10)]


def _base_forms(word: str):
    """Yield (form, rule_name) case/leet transforms of a word."""
    yield word, "as-is"
    cap = word.capitalize()
    if cap != word:
        yield cap, "capitalized"
    up = word.upper()
    if up != word and up != cap:
        yield up, "upper"
    leet = word.translate(_LEET)
    if leet != word:
        yield leet, "leet"
    cap_leet = cap.translate(_LEET)
    if cap_leet not in (word, cap, leet):
        yield cap_leet, "capitalized+leet"


def candidates(words: List[str]):
    """Yield (plaintext, rule_description) for every word x rule combo."""
    for word in words:
        for form, rule in _base_forms(word):
            suffixes = _FULL_SUFFIXES if rule in ("as-is", "capitalized") \
                else _LIGHT_SUFFIXES
            for suf in suffixes:
                if suf:
                    yield form + suf, "%s + append '%s'" % (rule, suf)
                else:
                    yield form, rule


def slow_candidates(words: List[str], limit: int):
    """First `limit` candidates for slow hashes (bcrypt): base forms only."""
    count = 0
    for word in words:
        for form, rule in _base_forms(word):
            if rule in ("as-is", "capitalized", "upper"):
                yield form, rule
                count += 1
                if count >= limit:
                    return


# ---------------------------------------------------------------------------
# Wordlist
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def load_words() -> List[str]:
    try:
        with open(WORDLIST_PATH, "r", encoding="utf-8",
                  errors="ignore") as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Cracking (deadline-aware)
# ---------------------------------------------------------------------------

def _result(hash_str: str, algos: List[str], **kw) -> Dict:
    r = {"hash": hash_str, "type": label_for(algos), "algo": None,
         "cracked": False, "plaintext": None, "rule": None,
         "candidates_tried": 0, "seconds": 0.0, "timed_out": False}
    r.update(kw)
    return r


def crack_fast(targets: Dict[str, List[str]], words: List[str],
               deadline_s: float) -> Dict[str, Dict]:
    """targets: dict hash->algos. One candidate pass per algorithm group.

    Stops at the deadline (seconds from now); hashes not resolved by
    then come back cracked=False with timed_out=True.
    """
    deadline = time.monotonic() + max(0.0, deadline_s)
    results: Dict[str, Dict] = {}
    algo_targets: Dict[str, set] = {}
    for h, algos in targets.items():
        for a in algos:
            algo_targets.setdefault(a, set()).add(h)
    remaining = set(targets)
    total_tried = 0
    t_start = time.monotonic()

    for algo, hashes in algo_targets.items():
        if not remaining:
            break
        live = hashes & remaining
        if not live:
            continue
        start = time.monotonic()
        tried = 0
        timed_out = False
        for cand, rule in candidates(words):
            tried += 1
            if tried % 1024 == 0 and time.monotonic() >= deadline:
                timed_out = True
                break
            d = _digest_for(algo, cand)
            if d in live:
                results[d] = _result(
                    d, targets[d], algo=algo, cracked=True, plaintext=cand,
                    rule=rule, candidates_tried=tried,
                    seconds=round(time.monotonic() - start, 3))
                remaining.discard(d)
                live.discard(d)
                if not live:
                    break
        total_tried += tried
        if timed_out:
            break
    elapsed = round(time.monotonic() - t_start, 3)
    for h in remaining:
        results[h] = _result(
            h, targets[h], candidates_tried=total_tried, seconds=elapsed,
            timed_out=time.monotonic() >= deadline)
    return results


def crack_bcrypt(hash_str: str, words: List[str], limit: int,
                 deadline_s: float) -> Dict:
    """Try the first `limit` base-form candidates against a bcrypt hash,
    stopping at the deadline."""
    deadline = time.monotonic() + max(0.0, deadline_s)
    start = time.monotonic()
    try:
        import bcrypt as _bcrypt
    except ImportError:
        return _result(hash_str, ["bcrypt"], algo="bcrypt",
                       error="bcrypt package not installed on the server")
    tried = 0
    target = hash_str.encode()
    for cand, rule in slow_candidates(words, limit):
        tried += 1
        if tried % 16 == 0 and time.monotonic() >= deadline:
            return _result(hash_str, ["bcrypt"], algo="bcrypt",
                           candidates_tried=tried,
                           seconds=round(time.monotonic() - start, 3),
                           timed_out=True)
        try:
            if _bcrypt.checkpw(cand.encode(), target):
                return _result(hash_str, ["bcrypt"], algo="bcrypt",
                               cracked=True, plaintext=cand, rule=rule,
                               candidates_tried=tried,
                               seconds=round(time.monotonic() - start, 3))
        except ValueError:
            return _result(hash_str, ["bcrypt"], algo="bcrypt",
                           candidates_tried=tried,
                           seconds=round(time.monotonic() - start, 3),
                           error="invalid bcrypt hash")
    return _result(hash_str, ["bcrypt"], algo="bcrypt",
                   candidates_tried=tried,
                   seconds=round(time.monotonic() - start, 3),
                   note="only the first %d base-form candidates were "
                        "tried (bcrypt is slow by design)" % limit)


def crack_submitted(hash_str: str,
                    deadline_s: float = DIRECT_CRACK_TIMEBOX_S,
                    words: Optional[List[str]] = None) -> Dict:
    """Crack ONE user-submitted hash, time-boxed to `deadline_s`.

    Returns the standalone tool's result dict shape: hash, type, algo,
    cracked, plaintext, rule, candidates_tried, seconds, timed_out,
    plus optional note/error. Never raises for unknown formats.
    """
    if words is None:
        words = load_words()
    kind, algos = identify(hash_str)
    if kind == "unknown":
        return _result((hash_str or "").strip(), [],
                       error="unrecognized hash format")
    if kind == "bcrypt":
        return crack_bcrypt(hash_str.strip(), words,
                            BCRYPT_CANDIDATE_LIMIT, deadline_s)
    key = hash_str.strip().lower()
    out = crack_fast({key: algos}, words, deadline_s)
    return out[key]
