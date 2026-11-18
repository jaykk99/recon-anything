"""Write code, not just read it: fix patches + runnable PoC skeletons.

These lock in that every artifact is plain generated source (never
executed/sent), that the generators are category-aware, and that the
remediation plan attaches them to its fix items.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import poc_codegen as pc  # noqa: E402
from app import remediation  # noqa: E402


# -- fix patches -----------------------------------------------------------

def test_contract_fix_access_control():
    row = {"key": "access_control_flaw", "value": "function 'withdraw'",
           "evidence": {"function": "withdraw"}}
    fix = pc.fix_patch_for("contract", row)
    assert fix["language"] == "solidity"
    assert "onlyOwner" in fix["code"]
    assert "withdraw" in fix["code"]


def test_contract_fix_reentrancy():
    row = {"key": "readonly_reentrancy_gap", "value": "reentrancy in claim",
           "evidence": {"function": "claim"}}
    fix = pc.fix_patch_for("contract", row)
    assert "nonReentrant" in fix["code"] and "ReentrancyGuard" in fix["code"]


def test_contract_fix_initializer():
    row = {"key": "access_control_unprotected_initializer",
           "value": "unprotected initializer 'initialize'",
           "evidence": {"function": "initialize"}}
    fix = pc.fix_patch_for("contract", row)
    assert "initializer" in fix["code"] and "_disableInitializers" in fix["code"]


def test_secret_fix_is_rotation():
    fix = pc.fix_patch_for("secret", {"key": "exposed_aws_key"})
    assert "rotate" in fix["code"].lower() and fix["language"] == "bash"


def test_web_cors_fix_allowlist():
    fix = pc.fix_patch_for("web_vuln", {"key": "cors_wildcard"})
    assert "Access-Control-Allow-Origin" in fix["code"]
    assert "*" not in fix["code"].split("never")[0]  # not recommending *


# -- PoC skeletons ---------------------------------------------------------

def test_foundry_poc_is_fork_only_and_targets_the_address():
    row = {"key": "contract_verdict", "value": "drain via sweep",
           "evidence": {"verdict": {"verdict": "VERIFIED_REAL"},
                        "function": "sweep",
                        "address": "0x7e772ed6e4bfeae80f2d58e4254f6b6e96669253"}}
    poc = pc.poc_for("contract_verdict", row)
    assert poc is not None
    assert poc["filename"].endswith(".t.sol")
    assert "createSelectFork" in poc["code"]      # fork, not mainnet
    assert "0x7e772ed6e4bfeae80f2d58e4254f6b6e96669253" in poc["code"]
    assert "sweep" in poc["code"]
    # explicit: this is proof to run by hand, not a live send
    assert "sends nothing" in poc["note"].lower()


def test_http_poc_is_read_only():
    row = {"key": "idor_candidate", "source_url": "https://api.x.com/v1/u/1",
           "evidence": {}}
    poc = pc.poc_for("web_vuln", row)
    assert poc is not None
    assert "curl" in poc["code"] and "https://api.x.com/v1/u/1" in poc["code"]
    assert "no payload" in poc["code"].lower()


def test_poc_none_when_not_applicable():
    assert pc.poc_for("hygiene", {"key": "missing_header"}) is None


# -- integration: remediation plan carries the code ------------------------

def test_build_plan_items_carry_generated_code():
    rows = [
        {"id": "c1", "plugin": "crypto_drain_scanner", "key": "contract_verdict",
         "value": "unguarded withdraw drains balance",
         "evidence": {"severity": "high", "function": "withdrawAll",
                      "address": "0x1111111111111111111111111111111111111111",
                      "verdict": {"verdict": "VERIFIED_REAL"}},
         "claim_status": "verified"},
        {"id": "w1", "plugin": "cors", "key": "cors_wildcard",
         "value": "* with credentials",
         "source_url": "https://api.example.com/v1/me",
         "evidence": {"severity": "medium"}, "claim_status": "verified"},
    ]
    plan = remediation.build_plan(rows)
    items = plan["items"]
    assert items, "no fix items built"
    by_fam = {it.get("family"): it for it in items}
    # the contract item ships a Foundry PoC + a solidity fix
    cv = by_fam.get("contract_verdict")
    assert cv and cv["code"]["fix"]["language"] == "solidity"
    assert cv["code"]["poc"]["filename"].endswith(".t.sol")
    # the web item ships a config fix + curl PoC
    wv = by_fam.get("web_vuln")
    assert wv and wv["code"]["fix"]
    assert wv["code"]["poc"]["code"].startswith("#") or "curl" in \
        wv["code"]["poc"]["code"]
