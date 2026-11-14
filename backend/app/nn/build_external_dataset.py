"""Build Jay's own external-findings training set for the NN triage scorer.

Public sources only, no logins, no paywalls:

1. ScaBench curated-2025-08-18 (MIT) — 555 published audit findings
   from Code4rena / Cantina / Sherlock contests, 2024-08 to 2025-08.
   https://github.com/scabench-org/scabench
2. xanoutas/solidity-security-findings (HuggingFace) — confirmed
   Code4rena / Sherlock / Immunefi findings with title, body and the
   original issue URL. Slither-only candidates are dropped (unconfirmed
   tool output, no outcome).

3. DeFiHackLabs incidents via helenmand/DeFi-Hacks-and-GPTScan-Top200
   (defihack.json) — 389 confirmed real-world DeFi exploits with root
   cause, amount lost and analysis. Every row is a successful exploit
   that lost funds, so severity is "high" for all of them (the source
   gives no per-incident severity; a third of rows have no amount).
4. Sherlock judging repos (sherlock-audit org) — issues the judges
   labeled "Invalid". These are the honest likely-FP rows: a human
   judge determined the finding is not a real issue. Label 0.
   Severity comes from the issue's own High/Medium/Low labels when
   present, else blank. "Sponsor Disputed" / "Won't Fix" / "Duplicate"
   issues are NOT used: disputed is not invalid, duplicates are real.

Labeling (honest, from the source's own outcome, never invented):
- label 1 = worth-validating: a judge/audit-confirmed finding at
  High or Medium severity, or a confirmed fund-loss exploit.
  "Confirmed" means it appears in a published audit report, a judged
  findings repo, or a documented exploit — not that a tool flagged it.
- label 0 = likely-false-positive: a Sherlock finding the judges
  labeled Invalid.
- Low / informational audit findings are DROPPED, not relabeled: they
  are real findings, so calling them likely-false-positive would be a
  lie, and calling them worth-validating would teach the model that
  low severity scores high. They are out of scope for this label.

5. audit-findings-dataset (mmlliu / Zaevlad, HuggingFace) — 23,625
   raw audit-contest findings with title, description, PoC,
   recommendation and normalized severity. Titles embed warden
   handles ("Submitted by X, also found by Y"); those suffixes are
   stripped before dedupe and before the title is stored as the
   finding value. License caveat from the dataset card itself:
   authorship of the underlying reports is unclear, treat as
   "license: other" — the findings are public contest submissions
   used here for internal training only, never redistributed.

Field mapping into the NN's finding shape (see features.py):
- plugin: keyword-mapped to a real ReconAnything plugin id where the
  finding title/body clearly names the class (reentrancy, access
  control, oracle, ...). No clear match -> None, which the extractor
  reads as the OTHER bucket. Never guessed.
- key: same keyword map, or the generic "audit_finding" slug.
- severity / bounty_value: the source severity (high/medium only).
- confidence: 85, fixed, for EVERY external row, both classes
  (judge-confirmed outcome). Own scanner findings cluster at
  80-90, so 85 sits inside the real distribution and does not mark
  a row as external. The source gives no confidence, so none is
  claimed; the value only keeps the feature from reading "absent".
  A modeling encoding, applied uniformly, documented here.
- recipient_class: "OTHER" for every external row. The audit text
  does not evidence a drain recipient class, so none is claimed.
- chain: "other". Audits span chains and the source gives no
  per-finding chain.
- function: first Contract.fn( or "function fn(" name found in the
  text, else "". Extracted, never invented.
- value: the finding title.
- evidence: source_origin "other", contract_role "standalone",
  risk = severity. No report_class is set (absent -> "other" bucket);
  setting it from the label would leak the label into the features.
- provenance lives on the row (origin/source), never in evidence.

Output: external_findings.jsonl, one NN row per line, in the same
shape data.py produces (finding/label/verdict/chain/address/plugin/
key/function), plus origin + source provenance per row.

    python -m app.nn.build_external_dataset [--scabench PATH|URL]
        [--xanoutas PATH] [--xanoutas-cap N] [--out PATH]

The ScaBench file is downloaded from GitHub when a URL is passed;
the xanoutas rows file is produced by fetching the public
HuggingFace datasets-server rows API (no key needed) and is expected
to exist already — see backend/docs/nn.md for the fetch command.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import urllib.request
from collections import Counter
from typing import Dict, List, Optional, Tuple

SCABENCH_URL = ("https://raw.githubusercontent.com/scabench-org/scabench/"
                "main/datasets/curated-2025-08-18/curated-2025-08-18.json")

# (phrases, plugin id, finding key) — first match wins, most specific first.
KEYWORD_MAP: List[Tuple[List[str], Optional[str], str]] = [
    (["reentrancy", "re-entrancy", "reentrant"], "readonly_reentrancy_gap", "reentrancy"),
    (["flash loan", "flashloan"], "flash_loan_callback_auth_bypass", "flash_loan"),
    (["sandwich attack", "front-run", "frontrun", "front run"], "mev_sandwich_attack_vulnerability", "frontrunning"),
    (["oracle manipulation", "price manipulation", "oracle", "price feed"], "oracle_trust_assumption_break", "oracle_manipulation"),
    (["access control", "unauthorized", "onlyowner", "only owner", "privilege escalation", "missing authorization", "unprotected function"], "contract_logic", "access_control_flaw"),
    (["unchecked", "integer overflow", "overflow", "underflow", "arithmetic error"], "unchecked_math_user_input", "unchecked_math_user_input"),
    (["weak randomness", "predictable random", "randomness"], "weak_randomness_value_outcome", "weak_randomness_value_outcome"),
    (["signature replay", "replay attack", "replayable", "ecdsa"], "eip712_separator_unbound", "signature_replay"),
    (["uups", "upgradeable"], "uups_authorize_upgrade_missing", "uups_authorize_upgrade_missing"),
    (["arbitrary mint", "unlimited mint", "can mint"], "recipient_mint_to_caller", "recipient_mint_to_caller"),
    (["drain", "steal funds", "steal the funds"], "crypto_drain_scanner", "unprotected_drain"),
    (["denial of service", "griefing"], "push_payment_revert_dos", "denial_of_service"),
    (["precision loss", "rounding"], "rounding_iterated_drain", "rounding"),
    (["timelock"], "timelock_delay_bypass", "timelock_bypass"),
    (["allowance", "approval"], "cp_proto_unchecked_erc20_return", "allowance"),
    (["proxy"], "proxy_implementation_uninitialized", "proxy"),
    (["centralization", "centralized"], "contract_logic", "access_control_flaw"),
]

CONFIRMED_CONFIDENCE = 85

_FN_RE = re.compile(r"(?:::|\.)([A-Za-z_][A-Za-z0-9_]{1,63})\s*\(")
_FN2_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]{1,63})\s*\(")
_FN_STOP = {"if", "for", "while", "return", "require", "assert", "revert",
            "emit", "new", "this", "super", "uint", "address", "bool",
            "bytes", "string", "mapping", "function", "contract"}


def norm_title(title: str) -> str:
    t = (title or "").lower()
    t = re.sub(r"[^a-z0-9]+", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def extract_function(text: str) -> str:
    for m in _FN_RE.finditer(text or ""):
        name = m.group(1)
        if name.lower() not in _FN_STOP:
            return name
    for m in _FN2_RE.finditer(text or ""):
        name = m.group(1)
        if name.lower() not in _FN_STOP:
            return name
    return ""


def map_class(text: str) -> Tuple[Optional[str], str]:
    low = (text or "").lower()
    for phrases, plugin, key in KEYWORD_MAP:
        if any(p in low for p in phrases):
            return plugin, key
    return None, "audit_finding"


def make_row(plugin: Optional[str], key: str, severity: str,
             title: str, text: str, source: Dict,
             label: int = 1,
             verdict: str = "EXTERNAL_CONFIRMED") -> Dict:
    finding = {
        "plugin": plugin,
        "key": key,
        "severity": severity,
        "bounty_value": severity,
        "confidence": CONFIRMED_CONFIDENCE,
        "value": (title or "")[:200],
        "recipient_class": "OTHER",
        "chain": "other",
        "function": extract_function(text or ""),
        "evidence": {
            "source_origin": "other",
            "contract_role": "standalone",
            "risk": severity,
        },
    }
    return {
        "finding": finding,
        "label": label,
        "verdict": verdict,
        "chain": "other",
        "address": "",
        "plugin": plugin,
        "key": key,
        "function": finding["function"],
        "origin": "external",
        "source": source,
    }


def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v)


def clean_audit_title(title: str) -> str:
    """Strip warden-handle suffixes and severity markers from a raw
    audit-contest title, so dedupe and the stored value see the
    finding itself, not who submitted it."""
    t = (title or "").strip()
    # "Submitted by X, also found by Y" and friends.
    t = re.split(r"\bsubmitted by\b", t, flags=re.I)[0].strip()
    t = re.split(r"\balso found by\b", t, flags=re.I)[0].strip()
    # Leading "[H-01]" / "H-01:" / "## [HIGH]" markers.
    t = re.sub(r"^(?:#+\s*)?(?:\[[^\]]*\]\s*)?", "", t).strip()
    t = re.sub(r"^(?:[HMCL]-\d+|Q-\d+)\s*:?\s*", "", t).strip()
    return t


def build_audit_findings_rows(path: str, cap: int, seed: int,
                             seen_titles: set, stats: Counter) -> List[Dict]:
    kept: List[Dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            sev_raw = str(r.get("bug_sev") or "").lower()
            sev = {"critical": "critical", "high": "high",
                   "medium": "medium"}.get(sev_raw)
            if sev is None:
                stats["auditfindings_dropped_severity"] += 1
                continue
            title = clean_audit_title(r.get("bug_title") or "")
            if not title:
                stats["auditfindings_dropped_no_title"] += 1
                continue
            # "critical" collapses to "high" for dedupe: the other
            # sources have no critical bucket.
            dedup_key = (norm_title(title),
                         "high" if sev == "critical" else sev)
            if dedup_key in seen_titles:
                stats["auditfindings_dropped_duplicate_title"] += 1
                continue
            seen_titles.add(dedup_key)
            text = (title + " " + (r.get("bug_desc") or "") + " " +
                    (r.get("bug_rec") or ""))
            plugin, key = map_class(text[:4000])
            kept.append(make_row(
                plugin, key, sev, title, text,
                {"dataset": "audit-findings",
                 "platform": "audit-contest",
                 "source_id": str(r.get("file_name") or r.get("id") or ""),
                 "source_url": ""}))
    rng = random.Random(seed)
    by_sev: Dict[str, List[Dict]] = {}
    for row in kept:
        by_sev.setdefault(row["finding"]["severity"], []).append(row)
    out: List[Dict] = []
    per = max(1, cap // max(1, len(by_sev)))
    for sev, items in sorted(by_sev.items()):
        rng.shuffle(items)
        take = items[:per] if len(items) > per else items
        stats[f"auditfindings_kept_{sev}"] += len(take)
        stats["auditfindings_dropped_over_cap"] += len(items) - len(take)
        out.extend(take)
    rng.shuffle(out)
    return out


def build_defihack_rows(path: str, stats: Counter) -> List[Dict]:
    """Confirmed fund-loss exploits. All severity high (see docstring)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    rows: List[Dict] = []
    for inc in data:
        title = _s(inc.get("title")).strip()
        root = _s(inc.get("root_cause")).strip()
        if not title or not root:
            stats["defihack_dropped_incomplete"] += 1
            continue
        full_title = f"{title} — {root}"
        text = (_s(inc.get("type")) + " " + root + " " +
                _s(inc.get("analysis")) + " " +
                _s(inc.get("vulnerable_code_snippet")))
        plugin, key = map_class(text[:4000])
        rows.append(make_row(
            plugin, key, "high", full_title, text,
            {"dataset": "defihack",
             "platform": "defihacklabs",
             "source_id": f"{_s(inc.get('date'))}-{title}",
             "source_url": _s(inc.get("POC")),
             "lost": _s(inc.get("lost"))}))
        stats["defihack_kept"] += 1
    return rows


def build_sherlock_invalid_rows(path: str, stats: Counter,
                               seen_titles: Optional[set] = None) -> List[Dict]:
    """Judge-labeled Invalid findings from Sherlock judging repos."""
    rows: List[Dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            issue = json.loads(line)
            title = (issue.get("title") or "").strip()
            body = issue.get("body") or ""
            if len(title) < 5 or len(body) < 20:
                stats["sherlock_invalid_dropped_junk"] += 1
                continue
            if seen_titles is not None and norm_title(title) in seen_titles:
                # Same title already kept as a confirmed finding
                # elsewhere; the confirmation wins, drop the conflict.
                stats["sherlock_invalid_dropped_title_conflict"] += 1
                continue
            labels = [str(l) for l in issue.get("labels") or []]
            sev = ""
            if "High" in labels:
                sev = "high"
            elif "Medium" in labels:
                sev = "medium"
            elif "Low/Info" in labels:
                sev = "low"
            plugin, key = map_class(title + " " + body[:4000])
            rows.append(make_row(
                plugin, key, sev, title, title + " " + body,
                {"dataset": "sherlock-invalid",
                 "platform": "sherlock",
                 "source_id": f"{issue.get('repo') or ''}#{issue.get('number')}",
                 "source_url": issue.get("url") or ""},
                label=0, verdict="EXTERNAL_INVALID"))
            stats["sherlock_invalid_kept"] += 1
    return rows


def load_scabench(path_or_url: str) -> List[Dict]:
    if path_or_url.startswith("http"):
        with urllib.request.urlopen(path_or_url, timeout=120) as r:
            data = json.load(r)
    else:
        with open(path_or_url, encoding="utf-8") as fh:
            data = json.load(fh)
    return data


def build_scabench_rows(data: List[Dict], stats: Counter) -> List[Dict]:
    rows: List[Dict] = []
    for project in data:
        platform = project.get("platform", "")
        codebases = project.get("codebases") or []
        repo_url = ""
        if codebases and isinstance(codebases[0], dict):
            repo_url = codebases[0].get("repo_url") or codebases[0].get("url") or ""
        for vuln in project.get("vulnerabilities") or []:
            sev = str(vuln.get("severity") or "").lower()
            if sev not in ("high", "medium"):
                stats["scabench_dropped_low_info"] += 1
                continue
            title = (vuln.get("title") or "").strip()
            desc = vuln.get("description") or ""
            if not title:
                stats["scabench_dropped_no_title"] += 1
                continue
            plugin, key = map_class(title + " " + desc[:4000])
            rows.append(make_row(
                plugin, key, sev, title, title + " " + desc,
                {"dataset": "scabench",
                 "platform": platform,
                 "source_id": vuln.get("finding_id") or "",
                 "source_url": repo_url,
                 "project_id": project.get("project_id") or ""}))
            stats["scabench_kept"] += 1
    return rows


def build_xanoutas_rows(path: str, cap: int, seed: int,
                       seen_titles: set, stats: Counter) -> List[Dict]:
    kept: List[Dict] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("type") != "confirmed_finding":
                stats["xanoutas_dropped_unconfirmed"] += 1
                continue
            sev = str(r.get("severity") or "").lower()
            if sev not in ("high", "medium"):
                stats["xanoutas_dropped_severity"] += 1
                continue
            title = (r.get("title") or "").strip()
            body = r.get("body") or ""
            if not title:
                # Fall back to the report heading.
                m = re.search(r"##\s*\[[^\]]+\]\s*(.+)", r.get("report") or "")
                title = (m.group(1).strip() if m else "")
            if not title:
                stats["xanoutas_dropped_no_title"] += 1
                continue
            dedup_key = (norm_title(title), sev)
            if dedup_key in seen_titles:
                stats["xanoutas_dropped_duplicate_title"] += 1
                continue
            seen_titles.add(dedup_key)
            plugin, key = map_class(title + " " + body[:4000])
            kept.append(make_row(
                plugin, key, sev, title, title + " " + body,
                {"dataset": "xanoutas",
                 "platform": r.get("source") or "",
                 "source_id": r.get("repo") or "",
                 "source_url": r.get("url") or "",
                 "contract_url": r.get("contract_url") or ""}))
    # Stratified cap: keep HIGH/MEDIUM balanced, deterministic sample.
    rng = random.Random(seed)
    by_sev: Dict[str, List[Dict]] = {}
    for row in kept:
        by_sev.setdefault(row["finding"]["severity"], []).append(row)
    out: List[Dict] = []
    per = max(1, cap // max(1, len(by_sev)))
    for sev, items in sorted(by_sev.items()):
        rng.shuffle(items)
        take = items[:per] if len(items) > per else items
        stats[f"xanoutas_kept_{sev}"] += len(take)
        stats["xanoutas_dropped_over_cap"] += len(items) - len(take)
        out.extend(take)
    rng.shuffle(out)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Build the external-findings training set.")
    ap.add_argument("--scabench", default=SCABENCH_URL)
    ap.add_argument("--xanoutas", default=None,
                    help="xanoutas rows JSONL (datasets-server rows API)")
    ap.add_argument("--xanoutas-cap", type=int, default=450)
    ap.add_argument("--defihack", default=None,
                    help="defihack.json (confirmed fund-loss exploits)")
    ap.add_argument("--sherlock-invalid", default=None,
                    help="sherlock-invalid.jsonl (judge-labeled Invalid "
                         "issues from Sherlock judging repos)")
    ap.add_argument("--audit-findings", default=None,
                    help="audit-findings rows JSONL (mmlliu dataset, "
                         "datasets-server rows API)")
    ap.add_argument("--audit-findings-cap", type=int, default=450)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "external_findings.jsonl"))
    args = ap.parse_args(argv)

    stats: Counter = Counter()
    rows: List[Dict] = []
    seen_titles: set = set()

    data = load_scabench(args.scabench)
    sc_rows = build_scabench_rows(data, stats)
    for r in sc_rows:
        seen_titles.add((norm_title(r["finding"]["value"]),
                         r["finding"]["severity"]))
    rows.extend(sc_rows)

    if args.xanoutas:
        rows.extend(build_xanoutas_rows(args.xanoutas, args.xanoutas_cap,
                                        args.seed, seen_titles, stats))

    if args.defihack:
        dh_rows = build_defihack_rows(args.defihack, stats)
        for r in dh_rows:
            seen_titles.add((norm_title(r["finding"]["value"]),
                             r["finding"]["severity"]))
        rows.extend(dh_rows)

    if args.sherlock_invalid:
        bare_titles = {t for (t, _s) in seen_titles}
        for r in rows:
            bare_titles.add(norm_title(r["finding"]["value"]))
        rows.extend(build_sherlock_invalid_rows(args.sherlock_invalid,
                                                stats, bare_titles))

    if args.audit_findings:
        rows.extend(build_audit_findings_rows(
            args.audit_findings, args.audit_findings_cap, args.seed,
            seen_titles, stats))

    # v2 spec: every plugin gets a count input (how many findings it
    # produced on this target). Count per (source group, plugin):
    # ScaBench per project, xanoutas per repo, Sherlock-invalid per
    # repo. Audit-findings and defihack rows have no group to count
    # within, so each counts as 1.
    from collections import Counter as _Counter
    groups: _Counter = _Counter()
    for r in rows:
        src = r["source"]
        if src["dataset"] == "scabench":
            g = ("scabench", src.get("project_id", ""))
        elif src["dataset"] == "xanoutas":
            g = ("xanoutas", src.get("source_id", ""))
        elif src["dataset"] == "sherlock-invalid":
            g = ("sherlock-invalid",
                 (src.get("source_id", "").split("#")[0]))
        else:
            g = ("single", id(r))
        r["_count_group"] = g
        groups[(g, r.get("plugin") or "OTHER")] += 1
    for r in rows:
        r["finding"]["plugin_finding_count"] = groups[
            (r["_count_group"], r.get("plugin") or "OTHER")]
        del r["_count_group"]

    with open(args.out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    mapped = sum(1 for r in rows if r.get("plugin"))
    print(f"wrote {len(rows)} external rows to {args.out}")
    print(f"keyword-mapped plugin: {mapped}/{len(rows)} "
          f"({100.0 * mapped / max(1, len(rows)):.0f}%)")
    print("by dataset/severity:",
          Counter((r["source"]["dataset"],
                   r["finding"]["severity"]) for r in rows))
    print("by mapped plugin:",
          Counter(r.get("plugin") or "OTHER" for r in rows).most_common(12))
    print("dropped:", dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
