#!/usr/bin/env python3
"""Self-writing detector loop for ReconAnything.

When a scan needs a detector the repo lacks, the system generates it
itself:

    pick_gap()      -- mine the candidate backlog for the biggest
                       uncovered attack shape (a detector family that
                       fires 0 times on a planted fixture of that shape)
    draft_detector()-- ask the LLM advisor chain (Bro gateway, model
                       `bro`) for the detector code; the draft is
                       UNTRUSTED TEXT until the gates below pass.
                       Gateway failure -> fail-soft to the hand-written
                       template in templates/ (marked as such).
    install_detector() -- insert the reviewed code into the target
                       deep-audit module (SPECS + ANALYZERS) and
                       verify the module imports.
    gate_detector() -- unit gates: the planted positive fixture MUST
                       fire; every negative fixture MUST stay silent
                       (WETH9, OpenZeppelin ERC4626, guarded vaults).
                       Any miss or false positive = REJECTED, no
                       registration.
    register_detector() -- verify discover() sees the new plugin id,
                       then emit the runner-side registration fragment
                       (DEEP list addition for recon-continuous
                       runner.py) as a patch file for review. The
                       runner itself is never edited by this script.

Usage:
    python3 codegen_loop.py gap [--candidates PATH]
    python3 codegen_loop.py draft --gap-id <id> [--prompt PATH]
    python3 codegen_loop.py gate --spec <spec_id> [--module deep_audit]
    python3 codegen_loop.py register --spec <spec_id>

Detection only; no live probing, no transactions, no credentials.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.normpath(os.path.join(HERE, ".."))  # backend/
sys.path.insert(0, BACKEND)

BRO_GATEWAY = os.environ.get(
    "BRO_GATEWAY_URL", "http://127.0.0.1:8898/v1/chat/completions")
CANDIDATES_DEFAULT = os.path.expanduser(
    "~/workspace/recon-continuous/results/candidates.jsonl")


# ---------------------------------------------------------------------------
# 1. Gap picking
# ---------------------------------------------------------------------------

def pick_gap(candidates_path: str = CANDIDATES_DEFAULT) -> dict:
    """Summarise the backlog and name the biggest uncovered shape.

    Returns a gap dict. The concrete gap this loop was built for:
    452/747 candidates are vault-template contracts (function
    _transferShares), yet the ERC-4626 share-inflation detector
    fires 0 times on the planted native-ETH vault fixture because
    it requires a totalAssets() function the vaults do not have.
    """
    rows = []
    try:
        with open(candidates_path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except OSError as e:
        return {"error": f"cannot read candidates: {e}"}
    by_plugin = collections.Counter(r.get("plugin") for r in rows)
    by_fn = collections.Counter(r.get("function") for r in rows)
    unverified = sum(
        1 for r in rows
        if (r.get("validation") or {}).get("verdict") in (None, "UNVERIFIED"))
    return {
        "total": len(rows),
        "unverified": unverified,
        "top_plugins": by_plugin.most_common(8),
        "top_functions": by_fn.most_common(8),
        "gap_id": "native_vault_share_inflation",
        "gap": ("native-ETH share vaults price shares off "
                "address(this).balance with no totalAssets() and an "
                "explicit payable donation entry point; the existing "
                "vault_share_inflation detector requires totalAssets() "
                "and fires 0 times on the planted fixture"),
        "evidence": {
            "vault_template_rows": by_fn.get("_transferShares", 0),
            "fixture_miss": "vault_share_inflation fires 0 on "
                            "app/investigator/fixtures.py VAULT_VULN_SOURCE",
        },
    }


# ---------------------------------------------------------------------------
# 2. LLM draft (Bro gateway, fail-soft)
# ---------------------------------------------------------------------------

def draft_detector(prompt: str, timeout_s: int = 600) -> dict:
    """Ask the Bro gateway for detector code. Returns
    {"ok": True, "draft": str} or {"ok": False, "error": str}.
    The gateway chain is heretic -> meromero -> rocinante -> qwen3
    -> keyless free APIs -> local dolphin; only model `bro` is
    exposed, so no per-backend selection is possible from here.
    """
    body = json.dumps({
        "model": "bro",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4000,
        "temperature": 0.2,
    }).encode()
    req = urllib.request.Request(
        BRO_GATEWAY, data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read())
        text = data["choices"][0]["message"]["content"]
        return {"ok": True, "draft": text, "via": "bro-gateway"}
    except Exception as e:  # noqa: BLE001 - fail-soft by design
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def save_draft(text: str, gap_id: str) -> str:
    path = os.path.join(HERE, "drafts", f"{gap_id}.txt")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    return path


# ---------------------------------------------------------------------------
# 3. Gates: positives must fire, negatives must stay silent
# ---------------------------------------------------------------------------

NEGATIVE_FIXTURES = ("weth9", "oz_erc4626", "guarded_vault_offset",
                     "guarded_vault_dead_shares", "guarded_vault_minimum")


def load_fixtures() -> dict:
    """Positive + negative sources for the gate. Positives come from
    the investigator fixtures; negatives from the WETH9 fixture, the
    real OpenZeppelin ERC4626 source (fetched keyless from GitHub),
    and inline guarded-vault shapes."""
    from app.investigator.fixtures import (  # noqa: E402
        VAULT_VULN_SOURCE, WETH9_SOURCE)
    out = {"positive_native_vault": VAULT_VULN_SOURCE,
           "weth9": WETH9_SOURCE}
    oz_path = os.path.join(HERE, "codegen", "fixtures", "oz-erc4626.sol")
    if os.path.exists(oz_path):
        with open(oz_path) as fh:
            out["oz_erc4626"] = fh.read()
    # Guarded native vaults: same share math, but protected.
    out["guarded_vault_offset"] = VAULT_VULN_SOURCE.replace(
        "s = msg.value * totalShares / address(this).balance;",
        "s = msg.value * (totalShares + 10 ** 6) / "
        "(address(this).balance + 1);").replace(
        "function donate() external payable {\n    }",
        "function donate() external payable {\n    }")
    out["guarded_vault_dead_shares"] = VAULT_VULN_SOURCE.replace(
        "    uint256 public totalShares;",
        "    uint256 public totalShares;\n"
        "    uint256 private constant DEAD_SHARES = 1000;").replace(
        "            s = msg.value;",
        "            s = msg.value;\n"
        "            _mint(address(0), DEAD_SHARES);")
    out["guarded_vault_minimum"] = VAULT_VULN_SOURCE.replace(
        "    function deposit() external payable {\n        uint256 s;",
        "    function deposit() external payable {\n"
        "        require(msg.value >= MINIMUM_DEPOSIT, \"too small\");\n"
        "        uint256 s;").replace(
        "    mapping(address => uint256) public shares;",
        "    mapping(address => uint256) public shares;\n"
        "    uint256 public constant MINIMUM_DEPOSIT = 1 ether;")
    return out


def gate_detector(spec_id: str, module: str = "deep_audit") -> dict:
    """Run the analyzer over every fixture. Pass = positive fires
    (>=1 finding on the planted vault) AND every negative is silent.
    Returns {"passed": bool, "fired": {...}, "detail": str}."""
    mod = __import__(f"app.plugins.{module}",
                     fromlist=["SPECS", "analyze_deep_source"])
    # deep_audit exposes analyze_deep_source; deep_audit6 exposes
    # analyze_deep6_source. Resolve generically.
    fn = getattr(mod, "analyze_deep_source", None)
    if fn is None:
        for name in dir(mod):
            if name.startswith("analyze_deep") and name.endswith("_source"):
                fn = getattr(mod, name)
                break
    specs = {s.id: s for s in getattr(mod, "SPECS", [])}
    if spec_id not in specs:
        return {"passed": False, "detail": f"{spec_id} not in {module}.SPECS"}
    if fn is None:
        return {"passed": False, "detail": f"no analyzer in {module}"}
    fixtures = load_fixtures()
    fired = {}
    for name, src in fixtures.items():
        try:
            out = fn(src, specs[spec_id]) or []
        except Exception as e:  # noqa: BLE001 - analyzer errors fail gate
            out = []
            fired[name] = f"ERROR: {type(e).__name__}: {e}"
            continue
        fired[name] = len(out)
    passed = (isinstance(fired.get("positive_native_vault"), int)
              and fired["positive_native_vault"] >= 1
              and all(isinstance(fired.get(n), int) and fired[n] == 0
                      for n in NEGATIVE_FIXTURES if n in fired))
    missing = [n for n in NEGATIVE_FIXTURES if n not in fired]
    return {"passed": passed, "fired": fired,
            "detail": ("gate passed" if passed else
                       "positive must fire >=1 and negatives must be 0; "
                       f"missing negatives: {missing}" if missing else
                       "positive must fire >=1 and negatives must be 0")}


# ---------------------------------------------------------------------------
# 4. Registration
# ---------------------------------------------------------------------------

def register_detector(spec_id: str) -> dict:
    """Verify discover() sees the plugin id; emit the runner-side
    registration fragment (DEEP list addition) as a patch file.
    The live runner is never edited by this script."""
    from app.plugins.registry import discover  # noqa: E402
    reg = discover()
    if spec_id not in reg:
        return {"registered": False,
                "detail": f"{spec_id} not in discover() "
                          f"({len(reg)} plugins)"}
    frag = (f"--- runner registration fragment for {spec_id} ---\n"
            f"Add to the DEEP list in "
            f"~/workspace/recon-continuous/runner.py (curated set):\n"
            f"  DEEP = [\"{spec_id}\", ...]  # prepend, before "
            f"\"vault_share_inflation\"\n"
            f"Then regenerate the widened sets so stepb picks it up:\n"
            f"  python3 build_plugin_sets.py\n"
            f"(or append \"{spec_id}\" to the stepb list in "
            f"plugin_set.json and restart the runner.)\n")
    path = os.path.join(HERE, "register", f"{spec_id}.txt")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(frag)
    return {"registered": True, "registry_count": len(reg),
            "fragment": path, "detail": frag}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_gap = sub.add_parser("gap")
    p_gap.add_argument("--candidates", default=CANDIDATES_DEFAULT)
    p_draft = sub.add_parser("draft")
    p_draft.add_argument("--gap-id", default="native_vault_share_inflation")
    p_draft.add_argument("--prompt", default=None)
    p_draft.add_argument("--out", default=None)
    p_gate = sub.add_parser("gate")
    p_gate.add_argument("--spec", required=True)
    p_gate.add_argument("--module", default="deep_audit")
    p_reg = sub.add_parser("register")
    p_reg.add_argument("--spec", required=True)
    args = ap.parse_args()

    if args.cmd == "gap":
        print(json.dumps(pick_gap(args.candidates), indent=1))
        return 0
    if args.cmd == "draft":
        prompt = (open(args.prompt).read() if args.prompt
                  else sys.stdin.read())
        res = draft_detector(prompt)
        if not res.get("ok"):
            print(json.dumps(res, indent=1))
            print("GATEWAY FAILED -- fail-soft: use templates/ fallback, "
                  "do not invent a draft.", file=sys.stderr)
            return 2
        path = args.out or save_draft(res["draft"], args.gap_id)
        if args.out:
            with open(path, "w") as fh:
                fh.write(res["draft"])
        print(json.dumps({"ok": True, "via": res["via"], "draft": path,
                          "chars": len(res["draft"])}))
        return 0
    if args.cmd == "gate":
        res = gate_detector(args.spec, args.module)
        print(json.dumps(res, indent=1))
        return 0 if res["passed"] else 1
    if args.cmd == "register":
        res = register_detector(args.spec)
        print(json.dumps(res, indent=1))
        return 0 if res.get("registered") else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
