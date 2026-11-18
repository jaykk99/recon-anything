"""Write code, not just read it.

ReconAnything reads a target's code and reports what is wrong. This
module closes the loop: for an adjudicated finding it WRITES two code
artifacts -

  * ``fix``  - a concrete patch/snippet that remediates the finding's
               class (a Solidity modifier, a reentrancy guard, an nginx
               deny rule, a header, a rotation command), and
  * ``poc``  - a runnable proof skeleton (a Foundry test fork-and-call
               for contract families, an HTTP/curl request for web
               families) the operator can run themselves.

Everything here is PURE TEXT GENERATION. It emits source for a human to
read, run and apply; it never compiles, executes, signs or sends
anything. The PoC skeletons fork/replay locally or hit the target
read-only exactly as the detection lane already does - they are
evidence to run by hand, not an exploit the platform fires.

build_plan() in remediation.py attaches the output to each fix item, so
the remediation plan ships the fix code and the proof code beside the
prose steps.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_HTTP_RE = re.compile(r"https?://[^\s\"'<>]+")


def _first_addr(*vals: Any) -> str:
    for v in vals:
        m = _ADDR_RE.search(str(v or ""))
        if m:
            return m.group(0)
    return "0xTARGET"


def _first_url(*vals: Any) -> str:
    for v in vals:
        m = _HTTP_RE.search(str(v or ""))
        if m:
            return m.group(0).rstrip('.,);')
    return ""


def _fn_name(row: Dict[str, Any]) -> str:
    """Best-effort function name from the finding (privileged_function /
    contract findings carry it)."""
    ev = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    for cand in (ev.get("function"), row.get("function")):
        if cand and re.match(r"^[A-Za-z_]\w*$", str(cand)):
            return str(cand)
    m = re.search(r"function '([A-Za-z_]\w*)'", str(row.get("value") or ""))
    return m.group(1) if m else "vulnerableFn"


# --- fix patches ----------------------------------------------------------

def _contract_fix(row: Dict[str, Any]) -> Dict[str, str]:
    key = str(row.get("key") or "").lower()
    val = str(row.get("value") or "").lower()
    fn = _fn_name(row)
    if "reentran" in key or "reentran" in val:
        return {"language": "solidity", "filename": "Fix.sol",
                "code": (
                    "// Add OpenZeppelin ReentrancyGuard and apply the\n"
                    "// Checks-Effects-Interactions order:\n"
                    "import \"@openzeppelin/contracts/utils/"
                    "ReentrancyGuard.sol\";\n\n"
                    f"contract C is ReentrancyGuard {{\n"
                    f"    function {fn}(...) external nonReentrant {{\n"
                    "        // 1. checks  2. state updates  3. external call LAST\n"
                    "        balances[msg.sender] = 0;      // effects first\n"
                    "        (bool ok,) = msg.sender.call{value: amt}(\"\");\n"
                    "        require(ok, \"transfer failed\");\n"
                    "    }\n}\n"),
                "note": "Guard the function and move the external call after "
                        "all state writes."}
    if "initiali" in key or "initiali" in val:
        return {"language": "solidity", "filename": "Fix.sol",
                "code": (
                    "// Gate the initializer so it can run exactly once and\n"
                    "// cannot be front-run on the implementation:\n"
                    "import \"@openzeppelin/contracts-upgradeable/proxy/"
                    "utils/Initializable.sol\";\n\n"
                    f"function {fn}(...) external initializer {{ ... }}\n"
                    "// and in the implementation constructor:\n"
                    "constructor() { _disableInitializers(); }\n"),
                "note": "Use Initializable's `initializer` modifier and "
                        "disable initializers in the implementation."}
    if "ecrecover" in key or "signer" in val or "ecrecover" in val:
        return {"language": "solidity", "filename": "Fix.sol",
                "code": (
                    "address signer = ecrecover(digest, v, r, s);\n"
                    "require(signer != address(0), \"invalid signature\");\n"
                    "require(signer == expected, \"unauthorized\");\n"),
                "note": "Reject the zero address from ecrecover and bind the "
                        "recovered signer to the expected signer."}
    # default: missing access control on a privileged function
    return {"language": "solidity", "filename": "Fix.sol",
            "code": (
                "// Restrict the privileged function to an authorized role:\n"
                "import \"@openzeppelin/contracts/access/"
                "Ownable.sol\";\n\n"
                f"function {fn}(...) external onlyOwner {{ ... }}\n"
                "// or, for granular roles, OpenZeppelin AccessControl:\n"
                "//   function " + fn + "(...) external "
                "onlyRole(ADMIN_ROLE) { ... }\n"),
            "note": "Add an access-control modifier (onlyOwner / "
                    "onlyRole) to the state-changing function."}


def _web_fix(row: Dict[str, Any]) -> Dict[str, str]:
    key = str(row.get("key") or "").lower()
    if "cors" in key:
        return {"language": "nginx", "filename": "cors.conf",
                "code": ("# Reflect only an allow-list, never '*' with "
                         "credentials:\n"
                         "set $cors \"\";\n"
                         "if ($http_origin ~* ^https://(app|admin)\\."
                         "example\\.com$) { set $cors $http_origin; }\n"
                         "add_header Access-Control-Allow-Origin $cors "
                         "always;\n"),
                "note": "Echo only trusted origins; never pair "
                        "Allow-Origin:* with Allow-Credentials:true."}
    if "header" in key or "hsts" in key or "csp" in key:
        return {"language": "nginx", "filename": "headers.conf",
                "code": ("add_header Strict-Transport-Security "
                         "\"max-age=63072000; includeSubDomains; preload\" "
                         "always;\n"
                         "add_header Content-Security-Policy "
                         "\"default-src 'self'\" always;\n"
                         "add_header X-Content-Type-Options nosniff always;\n"
                         "add_header X-Frame-Options DENY always;\n"),
                "note": "Add the missing security headers at the edge."}
    return {"language": "text", "filename": "fix.md",
            "code": ("# Validate and encode all user input on this "
                     "endpoint; enforce authz server-side and re-test with "
                     "the verification command.\n"),
            "note": "Fix the application-layer weakness, then re-run the "
                    "verification command."}


def fix_patch_for(family: str, row: Dict[str, Any]) -> Dict[str, str]:
    """A concrete remediation code snippet for the finding's family."""
    if family in ("contract", "contract_verdict"):
        return _contract_fix(row)
    if family == "secret":
        return {"language": "bash", "filename": "rotate.sh",
                "code": ("# 1. Revoke/rotate the exposed credential at the "
                         "provider NOW.\n"
                         "# 2. Purge it from history:\n"
                         "git filter-repo --invert-paths --path "
                         "<leaked-file>\n"
                         "# 3. Move the secret to a secrets manager / env, "
                         "never source.\n"),
                "note": "Rotate first (assume compromised), then remove from "
                        "code and history."}
    if family == "takeover":
        return {"language": "bash", "filename": "fix.sh",
                "code": ("# Remove the dangling record, or (re)claim the "
                         "resource it points at.\n"
                         "# e.g. delete the CNAME, or create the missing "
                         "bucket/app it targets.\n"),
                "note": "Remove or reclaim the unclaimed target the record "
                        "points to."}
    if family == "cve":
        return {"language": "bash", "filename": "patch.sh",
                "code": ("# Upgrade the affected package to a fixed "
                         "release, then redeploy and re-scan.\n"),
                "note": "Patch to a non-vulnerable version."}
    return _web_fix(row)


# --- PoC skeletons --------------------------------------------------------

def _foundry_poc(family: str, row: Dict[str, Any]) -> Dict[str, str]:
    ev = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    addr = _first_addr(ev.get("address"), ev.get("contract"),
                       row.get("value"), ev.get("target"))
    fn = _fn_name(row)
    code = (
        "// SPDX-License-Identifier: UNLICENSED\n"
        "pragma solidity ^0.8.20;\n"
        "import \"forge-std/Test.sol\";\n\n"
        "interface ITarget { function " + fn + "() external; }\n\n"
        "contract PoC is Test {\n"
        f"    address constant TARGET = {addr};\n"
        "    address attacker = address(0xA11CE);\n\n"
        "    function setUp() public {\n"
        "        // fork current mainnet state (read-only clone)\n"
        "        vm.createSelectFork(vm.rpcUrl(\"mainnet\"));\n"
        "    }\n\n"
        "    function test_poc() public {\n"
        "        vm.startPrank(attacker);   // call as an unprivileged stranger\n"
        "        // Demonstrate the flagged behaviour; assert the bad outcome,\n"
        "        // e.g. attacker balance increased / call did NOT revert:\n"
        "        ITarget(TARGET)." + fn + "();\n"
        "        vm.stopPrank();\n"
        "    }\n"
        "}\n")
    return {"language": "solidity", "filename": "PoC.t.sol", "code": code,
            "note": "Save under test/ and run: forge test --match-contract "
                    "PoC -vvvv --fork-url $RPC . Fork-only; sends nothing to "
                    "mainnet."}


def _http_poc(row: Dict[str, Any]) -> Optional[Dict[str, str]]:
    url = _first_url(row.get("source_url"), row.get("value"),
                     (row.get("evidence") or {}).get("url")
                     if isinstance(row.get("evidence"), dict) else None)
    if not url:
        return None
    return {"language": "bash", "filename": "poc.sh",
            "code": ("# Read-only reproduction (no payload):\n"
                     f"curl -sSi '{url}'\n"),
            "note": "Reproduce the observation read-only, then confirm the "
                    "fix removes it."}


def poc_for(family: str, row: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """A runnable proof skeleton for the finding's family, or None when
    code proof does not apply."""
    if family in ("contract", "contract_verdict"):
        return _foundry_poc(family, row)
    if family in ("web_vuln", "secret", "takeover", "cve", "exposure",
                  "service"):
        return _http_poc(row)
    return None


def code_for_item(family: str, row: Dict[str, Any]) -> Dict[str, Any]:
    """Both artifacts for a representative finding of a fix item."""
    out: Dict[str, Any] = {"fix": fix_patch_for(family, row)}
    poc = poc_for(family, row)
    if poc:
        out["poc"] = poc
    return out
