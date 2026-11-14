"""Build the multichain external-findings training set (v3).

Starts from the v2 external set (backend/app/nn/external_findings.jsonl:
own 725 rows are NOT here, they come from data.py) and adds real
per-chain / per-domain signal from public sources only, no logins,
no paywalls, no invented rows:

1. Chain re-attribution of the v2 rows. The v2 rows all carried
   chain "other" because their sources give no per-finding chain.
   Here each v2 row is re-read against the full source text it came
   from (fresh ScaBench JSON + fresh defihack.json, matched on
   dataset + source_id) and, when the text itself names exactly one
   chain, the row is stamped with that chain. Title-only fallback:
   rows whose full text is unavailable (xanoutas / audit-findings /
   Sherlock-invalid) are scanned on their stored title only.
   Rule: exactly one distinct chain named -> attribute it; two or
   more distinct chains named (e.g. a cross-chain bridge finding)
   -> stays "other", never guessed. A stablecoin named in the TITLE
   (USDT/USDC/DAI as the finding's subject token) stamps
   chain usdt/usdc/dai + is_stablecoin; named only in the body it
   sets is_stablecoin with the host chain (or "other") kept.

2. NVD CVE rows (new). Published CVEs are confirmed vulnerabilities
   with a CVSS severity from NVD itself — the same "source's own
   outcome" labeling rule as the audit rows. Fetched via the public
   NVD API v2 (no key), newest-first, capped per query so one class
   cannot swamp the set:
     xss 60 / sqli 30 (web), firmware 60 (hardware),
     bitcoin 25 / zcash 15 / monero 5 / solana 6 / cardano 5 /
     polkadot 1 / dogecoin 1 / tron 2 (TronLink wallet only).
   Label 1 only; severity Critical/High/Medium from CVSS (Low and
   un-scored CVEs dropped, same rule as Low audit findings).
   Plugin mapping is strict: xss -> "xss", sqli -> "sqli", clear
   firmware-hardcoded-credential text -> the firmware plugin that
   actually checks for it, CWE-502 -> "deserialization_detect";
   anything without a clear match keeps plugin None (OTHER bucket),
   never guessed. Domain is stamped by the builder (web_api /
   hardware_firmware / node_infra); chain is the CVE's chain for
   chain rows, "other" for web/hardware rows.

Labeling (same honest rules as v2, never invented):
- label 1 = judge/audit-confirmed High/Medium/Critical finding,
  confirmed fund-loss exploit, or published CVE at CVSS
  High/Medium/Critical. "Confirmed" means it appears in a published
  audit report, a judged findings repo, a documented exploit, or
  the NVD — not that a tool flagged it.
- label 0 = only the Sherlock judge-labeled Invalid rows already
  in the v2 set. There is no honest negative set for CVE rows, so
  the CVE rows are all label 1; the skew this adds is reported,
  not hidden (see the data record).
- Low / informational findings are DROPPED, not relabeled.

Rejected sources (documented, not silently skipped):
- ArmurAI/Solana_vulnerability_audit_dataset (HF, 244 rows):
  LLM-generated instruction text ("Give me an audit for this
  code..."), findings are model-written guesses, several entries
  say the flagged behaviour "might be a misunderstanding". Not
  judge/audit-confirmed, so unusable as label-1 rows.
- NVD keyword hits that are not the chain: "dash" matched a
  WordPress plugin ("Sell BTC" calculator, stored XSS) — not Dash;
  "aptos" matched Aptos Wisal payroll software — not the Aptos
  chain; "tron" matched A-V Tronics / Tronclass LMS — only the two
  TronLink Wallet CVEs are real TRON-ecosystem rows. All junk
  matches excluded by hand-checked filters in this builder.
- xrp: xrpl.js supply-chain CVE has no CVSS severity (dropped,
  no severity claimed); go-xrpl CVE is Low (dropped per rule).
- litecoin / bitcoin_cash / toncoin: NVD returns 0 CVEs; no audit
  rows name them in the fetched corpora. Excluded, not faked.

Output: external_findings_multichain.jsonl, same row shape as v2
plus optional finding["domain"] and finding["is_stablecoin"].

    python -m app.nn.build_multichain_dataset [--v2 PATH]
        [--scabench PATH] [--defihack PATH] [--nvd-dir DIR]
        [--out PATH]

Raw fetched sources are kept at ~/workspace/nn-multichain-sources/
(scabench.json, defihack.json, nvd/*.json) so a rebuild does not
need re-fetching; re-fetch commands are in backend/docs/nn.md.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from typing import Dict, List, Optional, Tuple

# (chain, [regexes]) — first family with a hit wins per text; a row is
# attributed only when exactly ONE chain family hits (see docstring).
CHAIN_PATTERNS: List[Tuple[str, List[str]]] = [
    ("solana", [r"\bsolana\b", r"\banchor program\b"]),
    ("tron", [r"\btronlink\b", r"\btron blockchain\b", r"\btron network\b",
              r"\btrx\b"]),
    ("ethereum", [r"\bethereum\b", r"\beth mainnet\b"]),
    ("bnb", [r"\bbnb\b", r"binance smart chain", r"\bbsc\b",
             r"\bbnb chain\b"]),
    ("polygon", [r"\bpolygon\b", r"\bmatic\b"]),
    ("arbitrum", [r"\barbitrum\b"]),
    ("optimism", [r"\boptimism\b", r"\bop mainnet\b"]),
    ("base", [r"\bbase mainnet\b", r"\bbase chain\b", r"\bon base\b"]),
    ("avalanche", [r"\bavalanche\b", r"\bavax\b"]),
    ("cardano", [r"\bcardano\b", r"\bplutus\b"]),
    ("sui", [r"\bsui\b", r"\bsui network\b"]),
    ("aptos", [r"\baptos\b"]),
    ("xrp", [r"\bxrpl\b", r"\bxrp ledger\b", r"\bripple\b"]),
    ("ton", [r"\btoncoin\b", r"\bthe open network\b", r"\bton blockchain\b"]),
    ("polkadot", [r"\bpolkadot\b", r"\bsubstrate\b"]),
    ("bitcoin", [r"\bbitcoin\b"]),
    ("litecoin", [r"\blitecoin\b"]),
    ("dogecoin", [r"\bdogecoin\b", r"\bdoge\b"]),
    ("bitcoin_cash", [r"bitcoin cash", r"\bbch\b"]),
    ("dash", [r"dash cryptocurrency", r"\bdash network\b", r"\bdash core\b"]),
    ("monero", [r"\bmonero\b", r"\bxmr\b"]),
    ("zcash", [r"\bzcash\b", r"\bzec\b"]),
]
CHAIN_RES = [(c, [re.compile(p) for p in pats])
             for c, pats in CHAIN_PATTERNS]
STABLE_RES = [(c, re.compile(r"\b" + c + r"\b"))
              for c in ("usdt", "usdc", "dai", "tether")]
# "tether" in text means the USDT token; map it to the usdt chain label.
STABLE_CHAIN = {"usdt": "usdt", "usdc": "usdc", "dai": "dai",
                "tether": "usdt"}


def _s(v) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v)


def attribute_chains(text: str) -> List[str]:
    """Distinct chains named in text (word-boundary patterns)."""
    low = (text or "").lower()
    return [c for c, res in CHAIN_RES
            if any(r.search(low) for r in res)]


def attribute_stablecoins(text: str) -> List[str]:
    low = (text or "").lower()
    return [c for c, r in STABLE_RES if r.search(low)]


# NVD per-query caps: (file, chain, domain, cap). "tron" rows are
# filtered to TronLink Wallet CVEs only (see _tron_is_real).
NVD_QUERIES = [
    ("xss_new.json", "other", "web_api", 60),
    ("sqli_new.json", "other", "web_api", 30),
    ("firmware_new.json", "other", "hardware_firmware", 60),
    ("bitcoin.json", "bitcoin", "node_infra", 25),
    ("zcash.json", "zcash", "node_infra", 15),
    ("monero.json", "monero", "node_infra", 5),
    ("solana.json", "solana", "node_infra", 6),
    ("cardano.json", "cardano", "node_infra", 5),
    ("polkadot.json", "polkadot", "node_infra", 1),
    ("dogecoin.json", "dogecoin", "node_infra", 1),
    ("tron.json", "tron", "node_infra", 2),
]

CONFIRMED_CONFIDENCE = 85
SEV_RANK = {"critical": 0, "high": 1, "medium": 2}


def _cve_severity(cve: Dict) -> str:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        m = (cve.get("metrics") or {}).get(key)
        if m:
            return str(m[0]["cvssData"]["baseSeverity"]).lower()
    m = (cve.get("metrics") or {}).get("cvssMetricV2")
    if m:
        return str(m[0].get("baseSeverity", "")).lower()
    return ""


def _cve_cwes(cve: Dict) -> List[str]:
    out = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            out.append(str(d.get("value") or ""))
    return out


def _tron_is_real(desc: str) -> bool:
    """Only TronLink Wallet CVEs are real TRON-ecosystem rows; the
    "tron" keyword also matched A-V Tronics and Tronclass LMS."""
    return "tronlink" in desc.lower()


def _cve_plugin(chain: str, domain: str, desc: str,
                cwes: List[str]) -> Optional[str]:
    low = (desc or "").lower()
    if domain == "web_api":
        if "cross-site scripting" in low or "xss" in low:
            return "xss"
        if "sql injection" in low:
            return "sqli"
        return None
    if domain == "hardware_firmware":
        if "hardcoded" in low and any(
                k in low for k in ("password", "credential", "api key",
                                  "secret")):
            return "firmware_hardcoded_api_keys"
        if "hard-coded password" in low or "default password" in low:
            return "firmware_password_shadow_crack"
        return None
    if "CWE-502" in cwes:
        return "deserialization_detect"
    if chain == "solana":
        if "reentrancy" in low or "re-entrancy" in low or "cpi" in low:
            return "solana_reentrancy_scanner"
        if "sysvar" in low:
            return "solana_sysvar_audit"
        return None
    if chain == "bitcoin" and "rpc" in low and any(
            k in low for k in ("exposed", "unauthenticated", "without auth")):
        return "bitcoin"
    return None


def build_cve_rows(nvd_dir: str, stats: Counter) -> List[Dict]:
    rows: List[Dict] = []
    for fname, chain, domain, cap in NVD_QUERIES:
        path = os.path.join(nvd_dir, fname)
        if not os.path.exists(path):
            stats[f"cve_missing_{fname}"] += 1
            continue
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        cands = []
        for v in data.get("vulnerabilities") or []:
            cve = v.get("cve") or {}
            sev = _cve_severity(cve)
            if sev not in SEV_RANK:
                stats["cve_dropped_severity"] += 1
                continue
            desc = ""
            for d in cve.get("descriptions") or []:
                if d.get("lang") == "en":
                    desc = d.get("value") or ""
                    break
            if not desc:
                stats["cve_dropped_no_desc"] += 1
                continue
            if chain == "tron" and not _tron_is_real(desc):
                stats["cve_dropped_tron_junk_match"] += 1
                continue
            cands.append((SEV_RANK[sev], cve.get("published") or "",
                          cve, sev, desc))
        # Severity first (critical > high > medium), then newest.
        cands.sort(key=lambda t: (t[0], t[1]), reverse=False)
        cands.sort(key=lambda t: t[1], reverse=True)
        cands.sort(key=lambda t: t[0])
        for _rank, _pub, cve, sev, desc in cands[:cap]:
            cve_id = cve.get("id") or ""
            cwes = _cve_cwes(cve)
            plugin = _cve_plugin(chain, domain, desc, cwes)
            finding = {
                "plugin": plugin,
                "key": ("cve_" + domain) if plugin is None else
                       f"cve_{plugin}",
                "severity": sev,
                "bounty_value": sev,
                "confidence": CONFIRMED_CONFIDENCE,
                "value": desc[:200],
                "recipient_class": "OTHER",
                "chain": chain,
                "domain": domain,
                "function": "",
                "evidence": {
                    "source_origin": "other",
                    "contract_role": "standalone",
                    "risk": sev,
                },
                "plugin_finding_count": 1,
            }
            rows.append({
                "finding": finding,
                "label": 1,
                "verdict": "EXTERNAL_CONFIRMED",
                "chain": chain,
                "address": "",
                "plugin": plugin,
                "key": finding["key"],
                "function": "",
                "origin": "external",
                "source": {
                    "dataset": "nvd-cve",
                    "platform": "nvd",
                    "source_id": cve_id,
                    "source_url": ("https://nvd.nist.gov/vuln/detail/"
                                   + cve_id),
                },
            })
            stats[f"cve_kept_{chain or domain}"] += 1
    return rows


def reattribute_v2_rows(rows: List[Dict], scabench_path: str,
                       defihack_path: str, stats: Counter) -> None:
    """Stamp chain / is_stablecoin on v2 rows from their source text.
    Mutates rows in place."""
    full_text: Dict[Tuple[str, str], str] = {}
    if scabench_path and os.path.exists(scabench_path):
        with open(scabench_path, encoding="utf-8") as fh:
            data = json.load(fh)
        for project in data:
            for vuln in project.get("vulnerabilities") or []:
                fid = vuln.get("finding_id") or ""
                full_text[("scabench", fid)] = (
                    (vuln.get("title") or "") + " " +
                    (vuln.get("description") or ""))
        stats["scabench_projects_indexed"] = len(data)
    if defihack_path and os.path.exists(defihack_path):
        with open(defihack_path, encoding="utf-8") as fh:
            data = json.load(fh)
        for inc in data:
            sid = f"{_s(inc.get('date'))}-{_s(inc.get('title'))}"
            full_text[("defihack", sid)] = (
                _s(inc.get("title")) + " " + _s(inc.get("type")) + " " +
                _s(inc.get("root_cause")) + " " + _s(inc.get("analysis")))
        stats["defihack_incidents_indexed"] = len(data)

    for row in rows:
        src = row.get("source") or {}
        dataset = src.get("dataset") or ""
        sid = src.get("source_id") or ""
        text = full_text.get((dataset, sid))
        title = (row.get("finding") or {}).get("value") or ""
        if text is None:
            # Title-only fallback for xanoutas / audit-findings /
            # Sherlock-invalid (full bodies were not re-fetched).
            text = title
            stats["reattribute_title_only"] += 1
        chains = attribute_chains(text)
        stables = attribute_stablecoins(text)
        title_stables = attribute_stablecoins(title)
        finding = row["finding"]
        if stables:
            finding["is_stablecoin"] = True
            stats["reattribute_stablecoin"] += 1
        # Stablecoin as the finding's subject (named in the title)
        # stamps the token chain; body-only mentions do not.
        if title_stables:
            token = STABLE_CHAIN[title_stables[0]]
            finding["chain"] = token
            row["chain"] = token
            stats[f"reattribute_chain_{token}"] += 1
        elif len(chains) == 1:
            finding["chain"] = chains[0]
            row["chain"] = chains[0]
            stats[f"reattribute_chain_{chains[0]}"] += 1
        elif len(chains) > 1:
            stats["reattribute_ambiguous_multi_chain"] += 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Build the multichain external-findings set.")
    ap.add_argument("--v2", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "external_findings.jsonl"))
    ap.add_argument("--scabench", default=os.path.expanduser(
        "~/workspace/nn-multichain-sources/scabench.json"))
    ap.add_argument("--defihack", default=os.path.expanduser(
        "~/workspace/nn-multichain-sources/defihack.json"))
    ap.add_argument("--nvd-dir", default=os.path.expanduser(
        "~/workspace/nn-multichain-sources"))
    ap.add_argument("--out", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "external_findings_multichain.jsonl"))
    args = ap.parse_args(argv)

    stats: Counter = Counter()
    rows: List[Dict] = []
    with open(args.v2, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    stats["v2_rows_in"] = len(rows)
    reattribute_v2_rows(rows, args.scabench, args.defihack, stats)

    cve_rows = build_cve_rows(args.nvd_dir, stats)
    rows.extend(cve_rows)
    stats["cve_rows_added"] = len(cve_rows)

    with open(args.out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"wrote {len(rows)} multichain external rows to {args.out}")
    print("by dataset:",
          Counter((r["source"]["dataset"]) for r in rows))
    print("by chain:",
          Counter(r.get("chain") or "other" for r in rows).most_common())
    print("by domain:",
          Counter((r.get("finding") or {}).get("domain") or "derived"
                  for r in rows))
    print("stablecoin rows:",
          sum(1 for r in rows
              if (r.get("finding") or {}).get("is_stablecoin")))
    print("dropped:", {k: v for k, v in stats.items()
                       if "dropped" in k or "missing" in k})
    print("reattribution:", {k: v for k, v in stats.items()
                             if k.startswith("reattribute")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
