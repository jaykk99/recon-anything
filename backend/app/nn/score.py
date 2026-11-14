"""Score any target: run the plugin set against it, rank every finding
with the trained network.

    python -m app.nn.score --target bsc:0x... [--plugin-set curated]
    python -m app.nn.score --target https://example.com
    python -m app.nn.score --target example.com
    python -m app.nn.score --findings findings.jsonl

Targets:
- contract: "chain:0x..." or a bare 0x address (--chain picks the
  chain, default bsc). Runs the contract plugin set (curated 29 by
  default, the same list the continuous scanner uses when no widened
  set is configured; --plugin-set stepb uses the widened 301-plugin
  set from recon-continuous/plugin_set.json when present).
- url / domain: runs the plugins that accept that target type,
  bounded by --max-plugins (default 40) and --timeout-cap seconds
  per plugin, passive plugins first, key-requiring plugins skipped
  (the CLI carries no API keys).

Detection only: plugins read the target (HTTP GETs, eth_calls); the
scorer never sends transactions, never takes funds, never bypasses
auth. Scores are triage ranks, never VERIFIED_REAL.

Output: ranked findings, each with nn_score (0-1), nn_label
(worth-validating / likely-false-positive) and nn_top_features (the 3
features most responsible for the score).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path

from .pipeline import load_model, score_finding_dicts

# Curated contract plugin set: the same 29 ids the continuous scanner
# runs when no widened set is configured (recon-continuous/runner.py:
# CORE + DEEP + DEEP3 + RECIPIENT + LAYERS).
CURATED_IDS = [
    "contract_recon", "crypto_drain_scanner", "contract_logic",
    "vault_share_inflation", "readonly_reentrancy_gap",
    "diamond_cut_ungated", "aa_validation_ungated",
    "ecrecover_zero_signer", "hook_cei_reentrancy",
    "bridge_replay_unbound_digest", "eip7702_unverified_delegate",
    "l2_sequencer_uptime_missing", "fee_on_transfer_overcredit",
    "create2_metamorphic_redeploy",
    "transient_latch_unconsumed", "v4_hook_shared_delta_take_pair",
    "inverted_division_zero_collapse", "share_transfer_cancel_desync",
    "eip712_digest_unbound_to_payload",
    "recipient_mint_to_caller", "recipient_unbacked_claim",
    "recipient_overdraw_withdraw", "recipient_rescue_to_param",
    "recipient_bridge_release_unproven", "recipient_sig_value_to_self",
    "cross_contract_call_graph", "storage_state_analysis",
    "bytecode_deep_analysis", "candidate_confirmation_queue",
]

SOL_IDS = ["solana_contract", "token_rugcheck"]

ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
CHAIN_ADDR_RE = re.compile(
    r"^(bsc|ethereum|base|arbitrum|polygon|optimism|avalanche|solana):(.+)$")


def classify_target(raw: str):
    """-> (kind, chain, normalized) where kind is contract | url |
    domain. Raises ValueError on an unrecognised target."""
    raw = (raw or "").strip()
    m = CHAIN_ADDR_RE.match(raw)
    if m:
        chain, addr = m.group(1), m.group(2)
        if chain == "solana":
            return "contract", chain, addr
        if ADDR_RE.match(addr):
            return "contract", chain, addr.lower()
        raise ValueError(f"not a contract address: {raw}")
    if ADDR_RE.match(raw):
        return "contract", None, raw.lower()
    if raw.startswith(("http://", "https://")):
        return "url", None, raw
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", raw, re.IGNORECASE):
        return "domain", None, raw.lower()
    raise ValueError(
        f"unrecognised target {raw!r}: use chain:0x..., a 0x address, "
        "a URL, or a domain")


def _clean_ev(ev, cap: int = 4000) -> dict:
    out = {}
    for k, v in (ev or {}).items():
        s = v if isinstance(v, str) else json.dumps(v, default=str)
        out[k] = s[:cap]
    return out


def _recipient_class(f: dict) -> str:
    """Same rule as the continuous scanner (recon-continuous/runner.py):
    report_class=candidate + recipient CALLER* wins; trigger_only rows
    are TRIGGER_ONLY; FIXED / HOLDER-SELF stay as-is."""
    ev = f.get("evidence") or {}
    rc = str(ev.get("report_class") or "").lower()
    rec = str(ev.get("recipient") or "").upper()
    if rc == "candidate":
        return rec if rec in ("CALLER", "CALLER-SUPPLIED") else "CALLER-SUPPLIED"
    if rc == "trigger_only":
        return "TRIGGER_ONLY"
    if rec in ("CALLER", "CALLER-SUPPLIED"):
        return rec
    if rec in ("FIXED", "HOLDER-SELF", "HOLDER_SELF"):
        return rec
    return "UNKNOWN"


def _finding_to_dict(plugin_id: str, f) -> dict:
    ev = _clean_ev(getattr(f, "evidence", None))
    sev = ev.get("severity") or getattr(f, "bounty_value", "low")
    rec = {
        "plugin": plugin_id,
        "key": getattr(f, "key", ""),
        "severity": sev,
        "bounty_value": getattr(f, "bounty_value", "low"),
        "confidence": getattr(f, "confidence", 0),
        "value": str(getattr(f, "value", ""))[:2000],
        "evidence": ev,
        # Chain lives in evidence for most contract plugins; stamp it
        # at row level too so the feature extractor sees it.
        "chain": ev.get("chain") or None,
    }
    rec["recipient_class"] = _recipient_class(rec)
    return rec


def _plugin_set_ids(plugin_set: str, kind: str):
    """Resolve a --plugin-set name to plugin ids for this target kind."""
    if kind == "contract":
        if plugin_set == "curated":
            return list(CURATED_IDS)
        if plugin_set == "stepb":
            cfg = Path("~/workspace/recon-continuous/plugin_set.json").expanduser()
            try:
                data = json.loads(cfg.read_text(encoding="utf-8"))
                ids = data.get("stepb")
                if ids:
                    return list(ids)
            except Exception:
                pass
            # Fall back to the registry's web3 contract-capable plugins.
            from app.plugins.registry import discover
            reg = discover()
            ids = [pid for pid, cls in reg.items()
                   if getattr(cls, "group", "") == "web3"
                   and (not cls.accepts or "crypto_wallet" in cls.accepts)
                   and not cls.requires_keys
                   and getattr(cls, "lane", "fast") == "fast"
                   and not getattr(cls, "aggressive", False)]
            return sorted(set(CURATED_IDS) | set(ids))
        raise ValueError(f"unknown contract plugin set: {plugin_set}")
    raise ValueError(f"plugin sets only apply to contract targets")


async def _run_plugins(plugin_ids, target_raw, target_type,
                       timeout_cap_s: int, notes: list):
    """Run plugin ids against one target, sequentially, one finding
    dict per finding (scan_one shape). A plugin that errors or times
    out contributes a note, never an exception."""
    import httpx
    from app.cache import Cache
    from app.plugins.base import Ctx, Target
    from app.plugins.registry import discover
    from app.ratelimit import RateLimiter

    reg = discover()
    findings: list = []
    plugins_run: list = []
    # trust_env=False: proxy env vars on this host break httpx's URL
    # parsing (no_proxy holds bracketed IPv6 entries); the repo's
    # other clients do the same (see app/agent_tools.py). The proxy
    # itself is still honoured explicitly when one is configured
    # (this sandbox reaches the internet only through its egress
    # proxy; Jay's box has no proxy env and goes direct).
    proxy = (os.environ.get("HTTPS_PROXY")
             or os.environ.get("HTTP_PROXY") or None)
    async with httpx.AsyncClient(timeout=30, trust_env=False,
                                 proxy=proxy) as http:
        ctx = Ctx(run_id="nn-score", mode="passive", http=http,
                  cache=Cache(), keys={}, limiter=RateLimiter(),
                  source_type="website")
        target = Target(raw=target_raw, type=target_type,
                        normalized=target_raw)
        for pid in plugin_ids:
            cls = reg.get(pid)
            if cls is None:
                notes.append(f"{pid}: missing from registry")
                continue
            plugin = cls()
            if plugin.requires_keys:
                notes.append(f"{pid}: skipped (needs API keys)")
                continue
            plugins_run.append(pid)
            cap = min(int(getattr(plugin, "timeout_s", 60) or 60),
                      int(timeout_cap_s))
            try:
                res = await asyncio.wait_for(
                    plugin.run(target, ctx), timeout=cap)
            except Exception as e:  # noqa: BLE001 - per-plugin isolation
                notes.append(f"{pid}: {type(e).__name__}: {str(e)[:120]}")
                continue
            for f in res.findings or []:
                findings.append(_finding_to_dict(pid, f))
    # v2 spec count input: how many findings each plugin produced in
    # this run, stamped on every finding it produced.
    counts: dict = {}
    for f in findings:
        counts[f.get("plugin") or "OTHER"] = counts.get(
            f.get("plugin") or "OTHER", 0) + 1
    for f in findings:
        f["plugin_finding_count"] = counts[f.get("plugin") or "OTHER"]
    return findings, plugins_run


async def run_target(raw: str, chain: str = "bsc",
                     plugin_set: str = "curated",
                     max_plugins: int = 40,
                     timeout_cap_s: int = 60) -> dict:
    """Run the plugin set against a target and return the raw scan
    record (findings unscored). Use score_target() for scored output."""
    from app.plugins.registry import for_target

    kind, found_chain, normalized = classify_target(raw)
    notes: list = []
    if kind == "contract":
        chain = found_chain or chain
        if chain == "solana":
            ids = list(SOL_IDS)
        else:
            ids = _plugin_set_ids(plugin_set, kind)
        target_raw = normalized if chain == "solana" else f"{chain}:{normalized}"
        findings, plugins_run = await _run_plugins(
            ids, target_raw, "crypto_wallet", timeout_cap_s, notes)
    else:
        target_type = "url" if kind == "url" else "domain"
        plugins = for_target(target_type)
        # Passive, keyless, fast-lane plugins first; bounded count.
        plugins.sort(key=lambda p: (not p.passive,
                                    bool(p.requires_keys),
                                    getattr(p, "lane", "fast") != "fast",
                                    p.id))
        ids = [p.id for p in plugins
               if not p.requires_keys
               and getattr(p, "lane", "fast") == "fast"][:max_plugins]
        findings, plugins_run = await _run_plugins(
            ids, normalized, target_type, timeout_cap_s, notes)
    return {
        "target": raw,
        "kind": kind,
        "chain": chain if kind == "contract" else None,
        "plugins_run": plugins_run,
        "notes": notes,
        "findings_count": len(findings),
        "findings": findings,
    }


def score_target(raw: str, model=None, threshold: float = 0.5,
                 combined: bool = False, **kwargs) -> dict:
    """Run plugins against a target and score every finding. Returns
    the scan record with ranked, scored findings. With combined=True
    the GNN + symbolic model scores instead of the flat MLP."""
    record = asyncio.run(run_target(raw, **kwargs))
    if combined:
        from .combined import score_finding_dicts_combined
        record["findings"] = score_finding_dicts_combined(
            record["findings"], model=model, threshold=threshold)
    else:
        record["findings"] = score_finding_dicts(record["findings"],
                                                 model=model,
                                                 threshold=threshold)
    return record


def _print_human(record: dict) -> None:
    print(f"target: {record['target']} ({record['kind']}"
          + (f", chain {record['chain']}" if record.get("chain") else "")
          + f")  plugins run: {len(record['plugins_run'])}  "
            f"findings: {record['findings_count']}")
    if record["notes"]:
        print(f"notes: {len(record['notes'])} plugin skips/errors "
              "(first 5):")
        for n in record["notes"][:5]:
            print(f"  - {n}")
    print(f"{'score':>6}  {'label':<20}  plugin / key")
    for f in record["findings"][:30]:
        score = f.get("combined_p", f.get("nn_score"))
        score_s = f"{score:.3f}" if isinstance(score, float) else "  n/a "
        print(f"{score_s:>6}  {str(f.get('nn_label')):<20}  "
              f"{f.get('plugin')} / {f.get('key')}")
        for tf in f.get("nn_top_features") or []:
            print(f"         {tf['direction']} {tf['feature']} "
                  f"({tf['delta']:+.3f})")
    if record["findings_count"] > 30:
        print(f"... and {record['findings_count'] - 30} more (see --json)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Score a target's plugin findings with the NN.")
    ap.add_argument("--target", default=None,
                    help="chain:0x..., 0x address, URL, or domain")
    ap.add_argument("--findings", default=None,
                    help="JSONL file of finding dicts to score instead "
                         "of running plugins")
    ap.add_argument("--chain", default="bsc")
    ap.add_argument("--weights", default=None,
                    help="weights.json path (default: backend/app/nn/)")
    ap.add_argument("--plugin-set", default="curated",
                    help="contract plugin set: curated (29) or stepb (301)")
    ap.add_argument("--max-plugins", type=int, default=40,
                    help="max plugins for URL/domain targets")
    ap.add_argument("--timeout-cap", type=int, default=60,
                    help="per-plugin timeout cap in seconds")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--gnn", action="store_true",
                    help="score with the combined GNN + symbolic model "
                         "instead of the flat MLP (needs gnn-weights.json)")
    ap.add_argument("--json", action="store_true",
                    help="print the full ranked record as JSON")
    args = ap.parse_args(argv)

    if args.gnn:
        from .combined import load_combined_model
        model = load_combined_model(args.weights)
        if model is None:
            print("no trained GNN weights found. Train first:\n"
                  "  python -m app.nn.train_gnn", file=sys.stderr)
            return 2
    else:
        model = load_model(args.weights)
        if model is None:
            print("no trained weights found. Train first:\n"
                  "  python -m app.nn.train", file=sys.stderr)
            return 2

    if args.findings:
        findings = []
        with open(os.path.expanduser(args.findings),
                  encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    findings.append(json.loads(line))
        if args.gnn:
            from .combined import score_finding_dicts_combined
            scored = score_finding_dicts_combined(
                findings, model=model, threshold=args.threshold)
        else:
            scored = score_finding_dicts(
                findings, model=model, threshold=args.threshold)
        record = {"target": args.findings, "kind": "findings-file",
                  "chain": None, "plugins_run": [],
                  "notes": [], "findings_count": len(findings),
                  "findings": scored}
    elif args.target:
        record = score_target(args.target, model=model, chain=args.chain,
                              plugin_set=args.plugin_set,
                              max_plugins=args.max_plugins,
                              timeout_cap_s=args.timeout_cap,
                              threshold=args.threshold,
                              combined=args.gnn)
    else:
        ap.error("give --target or --findings")
        return 2

    if args.json:
        print(json.dumps(record, indent=2, default=str))
    else:
        _print_human(record)
    return 0


if __name__ == "__main__":
    sys.exit(main())
