"""Build the labeled regression set for ReconAnything Track 4.

Merges every adjudicated label source on this machine into one
deduplicated JSONL set (one JSON record per case):

  1. recon-million-2026-11-06/results/corrections.jsonl
     Hand-corrected false positives. The first two rows (MVK
     claimReward, aeWETH withdrawTo) are regression cases #1/#2.
  2. recon-v2-run-2026-11-08/results.jsonl
     The 102-candidate validator v2 run (42 FP / 17 TO / 43 UNVERIFIED).
  3. recon-verify/verdicts.jsonl
     The 2026-11-02 verification pass (the verify-182 sync dir
     ~/workspace/recon-verify182-2026-11-07 is absent on this box;
     this is the closest surviving verdicts file). Capped sample,
     contracts with a cached verified source preferred.
  4. your_files/recon-findings-so-far-2026-11-05.md
     The 1,098-finding adjudication doc (864 FP / 50 TRIGGER_ONLY /
     182 STILL_UNVERIFIED / 0 VERIFIED_REAL). Capped samples of the
     FP and UNVERIFIED sections; all TRIGGER_ONLY rows kept.
  5. Repo fixtures: benchmarks/known_vuln_contracts.py CASES (the
     only expected_real_finding=true cases - canonical historical
     drain patterns) and tests/fixtures/fp_clean/*.sol (clean
     controls).

Enrichment: verified source from the v2-run and recon-verify
src_cache dirs, bytecode/source from
recon-rust-engine/sample1000.jsonl, keyed by (chain, address).

Dedupe key: (chain, address) for addressed cases, first writer
wins (priority = source order above). crypto.com / Binance never
appear as scan targets: any case whose contract name or symbol
names them is excluded and counted.

No historical case was ever VERIFIED_REAL, so every addressed
case carries expected_real_finding=false. Offline measurement
only; this builder stamps nothing.
"""
import json
import os
import re
import sys

WS = os.path.expanduser("~/workspace")
HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(HERE, "labeled_set.jsonl")

MAX_SOURCE_CHARS = 100_000
VERIFY_CAP = 120
FINDINGS_FP_CAP = 120
FINDINGS_UNVERIFIED_CAP = 80

EXCLUDE_RE = re.compile(r"crypto\.com|binance", re.IGNORECASE)


def load_src_caches():
    cache = {}
    for d in (os.path.join(WS, "recon-v2-run-2026-11-08", "src_cache"),
              os.path.join(WS, "recon-verify", "src_cache")):
        if not os.path.isdir(d):
            continue
        for fn in os.listdir(d):
            m = re.match(r"(.+)_(0x[0-9a-fA-F]{40})\.json$", fn)
            if not m:
                continue
            key = (m.group(1), m.group(2).lower())
            if key in cache:
                continue
            try:
                doc = json.load(open(os.path.join(d, fn)))
            except Exception:
                continue
            if doc.get("source"):
                cache[key] = {"source": doc["source"],
                              "name": doc.get("name", "")}
    return cache


def load_sample1000():
    path = os.path.join(WS, "recon-rust-engine", "sample1000.jsonl")
    out = {}
    if not os.path.exists(path):
        return out
    for line in open(path):
        r = json.loads(line)
        out[(r["chain"], r["address"].lower())] = r
    return out


class Builder:
    def __init__(self):
        self.cases = []
        self.seen = set()
        self.excluded = 0
        self.stats = {}

    def add(self, case, source_label):
        name_blob = " ".join(str(case.get(k) or "") for k in
                             ("contract_name", "symbol", "notes"))
        if case.get("address") and EXCLUDE_RE.search(name_blob):
            self.excluded += 1
            return False
        key = (case["chain"], (case.get("address") or
                                case["contract_id"]).lower())
        if key in self.seen:
            return False
        self.seen.add(key)
        case["label_source"] = source_label
        self.cases.append(case)
        self.stats[source_label] = self.stats.get(source_label, 0) + 1
        return True


def base_case(chain, address, verdict_class, expected_real,
              vuln_type="", function="", kind="", contract_name="",
              notes="", source=None, bytecode=None):
    cid = f"{chain}:{address}" if address else ""
    return {
        "contract_id": cid,
        "chain": chain,
        "address": address,
        "contract_name": contract_name,
        "function": function,
        "kind": kind,
        "bytecode": bytecode,
        "source": source,
        "expected_real_finding": expected_real,
        "vulnerability_type": vuln_type,
        "verdict_class": verdict_class,
        "notes": notes,
    }


def from_corrections(b):
    path = os.path.join(WS, "recon-million-2026-11-06", "results",
                        "corrections.jsonl")
    if not os.path.exists(path):
        return "missing"
    known_fn = {
        "0x3405ff989f8bb8efd6c85ad6b29219d3383a5fb0": ("claimReward",
                                                       "MetaVerseKombat"),
        "0x8b194beae1d3e0788a1a35173978001acdfba668": ("withdrawTo",
                                                       "aeWETH"),
    }
    for line in open(path):
        r = json.loads(line)
        addr = r["address"].lower()
        fn, cname = known_fn.get(addr, ("", ""))
        if not fn:
            m = re.search(r": ([A-Za-z0-9_, ]+?) FALSE_POSITIVE", r["reason"])
            if m:
                fn = m.group(1).split(",")[0].strip()
        b.add(base_case(
            r["chain"], addr, "FALSE_POSITIVE", False,
            vuln_type="corrected_false_positive", function=fn,
            contract_name=cname,
            notes=("Hand-corrected VERIFIED_REAL stamp, corrected_at="
                   + r.get("corrected_at", "") + ". " + r["reason"])[:1500]),
            "corrections.jsonl (recon-million 2026-11-06)")
    return "used"


def from_v2_run(b):
    path = os.path.join(WS, "recon-v2-run-2026-11-08", "results.jsonl")
    if not os.path.exists(path):
        return "missing"
    for line in open(path):
        r = json.loads(line)
        b.add(base_case(
            r["chain"], r["address"].lower(), r["verdict"], False,
            vuln_type=r.get("kind", ""), function=r.get("function", ""),
            kind=r.get("kind", ""),
            notes=("validator v2 run 2026-11-08, plugin="
                   + str(r.get("plugin")) + ", value_usd="
                   + str(r.get("value_usd")) + ": "
                   + str(r.get("reason", "")))[:1500]),
            "validator v2 run results.jsonl (2026-11-08)")
    return "used"


def from_verify(b, cache_keys):
    path = os.path.join(WS, "recon-verify", "verdicts.jsonl")
    if not os.path.exists(path):
        return "missing"
    norm = {"FALSE POSITIVE": "FALSE_POSITIVE",
            "TRIGGER-ONLY": "TRIGGER_ONLY",
            "UNVERIFIED": "UNVERIFIED"}
    prio = {"TRIGGER_ONLY": 0, "FALSE_POSITIVE": 1, "UNVERIFIED": 2}
    best = {}
    for line in open(path):
        r = json.loads(line)
        vc = norm.get(r.get("verdict"))
        if not vc:
            continue
        key = (r["chain"], r["address"].lower())
        cur = best.get(key)
        if cur is None or prio[vc] < prio[cur[0]]:
            best[key] = (vc, r)
    rows = sorted(best.values(),
                  key=lambda t: (0 if (t[1]["chain"],
                                       t[1]["address"].lower())
                                  in cache_keys else 1,
                                 prio[t[0]]))
    added = 0
    for vc, r in rows:
        if added >= VERIFY_CAP:
            break
        ev = r.get("evidence") or {}
        if b.add(base_case(
                r["chain"], r["address"].lower(), vc, False,
                vuln_type=r.get("class", ""),
                function=r.get("function", ""),
                kind=r.get("class", ""),
                contract_name=ev.get("contract_name", ""),
                notes=("recon-verify pass 2026-11-02, tier="
                       + str(r.get("tier")) + ", recipient="
                       + str(r.get("recipient")) + ": "
                       + str(r.get("reason", "")))[:1500]),
                "recon-verify verdicts.jsonl (2026-11-02)"):
            added += 1
    return "used"


SECTION_CLASS = [
    ("SURVIVOR CANDIDATES", "UNVERIFIED"),
    ("STRONG SUSPECTS", "UNVERIFIED"),
    ("TRIGGER ONLY", "TRIGGER_ONLY"),
    ("STILL UNVERIFIED", "UNVERIFIED"),
    ("DEAD", "FALSE_POSITIVE"),
]
ENTRY_RE = re.compile(
    r"^- \*\*(.+?)\*\* \(([^)]+)\) `(0x[0-9a-fA-F]{40})`"
    r"(?: — \$([\d,]+))?(?: — flagged: (.+))?$")


def from_findings_md(b):
    path = os.path.join(WS, "your_files",
                        "recon-findings-so-far-2026-11-05.md")
    if not os.path.exists(path):
        return "missing"
    text = open(path).read()
    sections = re.split(r"^## ", text, flags=re.M)[1:]
    buckets = {}
    for sec in sections:
        title = sec.split("\n", 1)[0]
        vc = next((v for k, v in SECTION_CLASS if title.startswith(k)),
                  None)
        if not vc:
            continue
        entries = []
        cur = None
        for line in sec.splitlines()[1:]:
            m = ENTRY_RE.match(line)
            if m:
                if cur:
                    entries.append(cur)
                cur = {"name": m.group(1), "chain": m.group(2),
                       "address": m.group(3).lower(),
                       "flagged": m.group(5) or "", "desc": ""}
            elif cur and line.strip():
                cur["desc"] += line.strip() + " "
        if cur:
            entries.append(cur)
        buckets[vc] = buckets.get(vc, []) + entries

    def take(entries, cap):
        if cap is None or len(entries) <= cap:
            return entries
        step = len(entries) / cap
        return [entries[int(i * step)] for i in range(cap)]

    plan = [("TRIGGER_ONLY", None), ("UNVERIFIED", FINDINGS_UNVERIFIED_CAP),
            ("FALSE_POSITIVE", FINDINGS_FP_CAP)]
    # SURVIVOR/ECONOMIC rows were folded into the UNVERIFIED bucket
    # above by section mapping; they enter via that bucket's head.
    for vc, cap in plan:
        for e in take(buckets.get(vc, []), cap):
            b.add(base_case(
                e["chain"], e["address"], vc, False,
                vuln_type=e["flagged"], function="",
                contract_name=e["name"],
                notes=("findings adjudication 2026-11-05: "
                       + e["desc"])[:1500]),
                "recon-findings-so-far-2026-11-05.md")
    return "used"


def from_fixtures(b):
    sys.path.insert(0, BACKEND)
    from benchmarks.known_vuln_contracts import CASES
    for c in CASES:
        case = base_case(
            "fixture", None,
            "KNOWN_VULNERABLE" if c.drainable else "CLEAN_CONTROL",
            c.drainable, vuln_type=c.name,
            notes="known_vuln_contracts.py: " + c.reference
                  + "; expect_any=" + ",".join(sorted(c.expect_any)),
            source=c.source)
        case["contract_id"] = "fixture:" + c.name
        b.add(case, "repo fixture known_vuln_contracts.py")
    fxdir = os.path.join(BACKEND, "tests", "fixtures", "fp_clean")
    manifest = os.path.join(fxdir, "manifest.json")
    if os.path.exists(manifest):
        for item in json.load(open(manifest)):
            src = open(os.path.join(fxdir, item["file"])).read()
            case = base_case(
                "fixture", None, "CLEAN_CONTROL", False,
                vuln_type="fp_clean_fixture",
                contract_name=item["contract_name"],
                notes="fp_clean fixture pair member (clean control): "
                      + item["file"], source=src)
            case["contract_id"] = "fixture:fp_clean/" + item["file"]
            b.add(case, "repo fixture tests/fixtures/fp_clean")
    return "used"


def enrich(b, cache, sample):
    n_src = n_bc = 0
    for case in b.cases:
        if not case.get("address"):
            continue
        key = (case["chain"], case["address"])
        hit = cache.get(key)
        if hit:
            if not case.get("source") and len(hit["source"]) <= MAX_SOURCE_CHARS:
                case["source"] = hit["source"]
                n_src += 1
            if not case.get("contract_name"):
                case["contract_name"] = hit["name"]
        s = sample.get(key)
        if s:
            if not case.get("bytecode") and s.get("bytecode"):
                case["bytecode"] = s["bytecode"]
                n_bc += 1
            if not case.get("source") and s.get("source") \
                    and len(s["source"]) <= MAX_SOURCE_CHARS:
                case["source"] = s["source"]
                n_src += 1
    return n_src, n_bc


def main():
    cache = load_src_caches()
    sample = load_sample1000()
    b = Builder()
    status = {}
    status["corrections"] = from_corrections(b)
    status["v2_run"] = from_v2_run(b)
    status["verify"] = from_verify(b, set(cache.keys()))
    status["findings_md"] = from_findings_md(b)
    status["fixtures"] = from_fixtures(b)
    # Regression order guarantee: MVK then aeWETH are records #1/#2.
    def rank(case):
        if case.get("address") == "0x3405ff989f8bb8efd6c85ad6b29219d3383a5fb0":
            return 0
        if case.get("address") == "0x8b194beae1d3e0788a1a35173978001acdfba668":
            return 1
        return 2
    b.cases.sort(key=rank)  # stable: keeps source order otherwise
    n_src, n_bc = enrich(b, cache, sample)
    with open(OUT, "w") as f:
        for case in b.cases:
            f.write(json.dumps(case) + "\n")
    from collections import Counter
    print("sources:", status)
    print("per-source added:", b.stats)
    print("excluded (crypto.com/binance named):", b.excluded)
    print("total cases:", len(b.cases))
    print("verdict classes:", Counter(c["verdict_class"] for c in b.cases))
    print("expected_real=true:", sum(c["expected_real_finding"]
                                     for c in b.cases))
    print("with source:", sum(1 for c in b.cases if c.get("source")),
          "| with bytecode:", sum(1 for c in b.cases if c.get("bytecode")),
          f"(enriched: +{n_src} sources, +{n_bc} bytecodes)")
    print("wrote", OUT, os.path.getsize(OUT), "bytes")


if __name__ == "__main__":
    main()
