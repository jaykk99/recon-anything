"""Audit Toolbox: the standard smart-contract auditor's external
tools, wired in as adapters behind ONE plugin (id "audit_toolbox").

Jay pasted the auditor tool list (Slither, Aderyn, Mythril, Echidna,
...) and ordered "add these". This module is the integration layer
for the tools that are real, keyless, and runnable in this
environment. One plugin id (not one per tool) because the registry
count is asserted across the suite and because the tools share one
orchestration story: fetch the contract once (keyless Blockscout /
Sourcify verified source + deployed bytecode via contract_chain,
proxy implementation followed one level), then run every AVAILABLE
tool over that same material and normalize each tool's output into
the repo finding schema - key per tool+detector, severity mapped to
the repo's low|medium|high, evidence carrying the tool's own
message plus the code snippet, source labeled with the tool name
(e.g. source="slither").

Architecture (Jay's constraints, 2026-11-02):

1. FAST vs HEAVY lanes. The web request path kills plugins at
   MAX_PLUGIN_TIMEOUT_S (120s) and the default request timeout is
   20s, so heavy tools (Slither, Aderyn, solc SMTChecker, Echidna,
   Medusa - seconds to minutes each) NEVER run blindly inside a
   scan. This plugin declares lane="heavy" and the runner honors
   RECON_HEAVY_TIMEOUT (default 1800s) as its cap. Inside run(),
   heavy adapters only execute when the heavy lane is explicitly
   enabled for the run (env RECON_HEAVY_LANE=1, or
   ctx.shared["allow_heavy"], or module override
   audit_toolbox=heavy) - that is the scan-worker / offline-harness
   context the 1000/1M contract sweeps already use. In a quick or
   bulk context the heavy adapters return ONE info finding naming
   the available heavy tools that were not run, and the light
   adapters (Semgrep, Heimdall disassembly, GoPlus, Honeypot.is)
   still run within their small budgets.
2. NO IMAGE BLOAT. Tools install OUTSIDE the app image under
   ~/workspace/tools/audit/ (bin/ + venv-*/), reproducible via
   scripts/install-audit-tools.sh. Adapters detect binaries (PATH
   plus the audit tool dir) and skip silently when absent - a
   graceful availability=false, never a crash - so the slim
   deployed backend is completely unaffected.
3. PASSIVE / KEYLESS. Verified source comes only from the existing
   keyless contract_chain routes. No Etherscan key, no new API
   keys: GoPlus and Honeypot.is are keyless public APIs. No local
   node or fork replay in this lane (documented future work).

Fuzz adapters (Echidna / Medusa) are candidates-only like the
simulation lane: property fuzzing arbitrary verified source with no
test harness proves nothing, so they run ONLY when the run context
supplies a prepared fuzz project (ctx.shared["fuzz_project"] =
{"dir": ..., "contract": ..., "target": "File.sol"}), and always
inside strict per-tool budgets. Findings from fuzz lanes are
labeled simulation candidates pending human review.

SWC: findings from pattern detectors carry an swc_id in evidence
where a clean SWC Registry mapping exists (SWC_TABLE below).

Detection only. No transactions are ever sent.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc

# ---------------------------------------------------------------------------
# Install layout (outside the app image; see scripts/install-audit-tools.sh)
# ---------------------------------------------------------------------------

AUDIT_DIR = os.environ.get(
    "RECON_AUDIT_TOOLS_DIR",
    os.path.expanduser("~/workspace/tools/audit"))
AUDIT_BIN = os.path.join(AUDIT_DIR, "bin")
SLITHER_VENV = os.path.join(AUDIT_DIR, "venv-slither")
SEMGREP_VENV = os.path.join(AUDIT_DIR, "venv-semgrep")
SEMGREP_RULES_DIR = os.path.join(AUDIT_DIR, "cache", "semgrep-solidity")
Z3_LIB_DIR = os.path.join(SLITHER_VENV, "lib", "python3.12",
                          "site-packages", "z3", "lib")

MAX_ADDRESSES = 2        # contracts analyzed per run (tools are slow)
MAX_CHAIN_PAIRS = 2

# Per-tool subprocess budgets (seconds). Heavy adapters additionally
# share the plugin's overall heavy deadline.
TOOL_BUDGETS = {
    "slither": 600, "aderyn": 600, "smtchecker": 600,
    "echidna": 900, "medusa": 900,
    "semgrep": 45, "heimdall": 45,
}

TOOL_LANES = {
    "slither": "static", "aderyn": "static", "semgrep": "static",
    "smtchecker": "symbolic", "heimdall": "bytecode",
    "echidna": "fuzz", "medusa": "fuzz",
    "goplus": "api", "honeypot": "api",
}

HEAVY_TOOLS = ("slither", "aderyn", "smtchecker", "echidna", "medusa")
LIGHT_TOOLS = ("semgrep", "heimdall")

_SEVERITY = {
    "critical": "high", "high": "high", "error": "high",
    "medium": "medium", "warning": "medium", "med": "medium",
    "low": "low", "informational": "low", "info": "low",
    "optimization": "low", "gas": "low",
}


def map_severity(raw: Any) -> str:
    """Map any tool severity string onto low|medium|high."""
    return _SEVERITY.get(str(raw or "").strip().lower(), "low")


# ---------------------------------------------------------------------------
# SWC Registry mapping (detector name / pattern -> SWC id), where a clean
# mapping exists. Used for our own detectors' vocabulary as well as the
# external tools' detector names.
# ---------------------------------------------------------------------------

SWC_TABLE: Dict[str, str] = {
    "reentrancy-eth": "SWC-107", "reentrancy-no-eth": "SWC-107",
    "reentrancy-benign": "SWC-107", "reentrancy-events": "SWC-107",
    "reentrancy-state-change": "SWC-107",
    "tx-origin": "SWC-115", "tx-origin-used-for-auth": "SWC-115",
    "suicidal": "SWC-106", "selfdestruct": "SWC-106",
    "uninitialized-state": "SWC-109", "uninitialized-local": "SWC-109",
    "uninitialized-storage": "SWC-109",
    "arbitrary-send-eth": "SWC-105", "arbitrary-send-erc20": "SWC-105",
    "controlled-delegatecall": "SWC-112",
    "delegatecall-to-arbitrary-address": "SWC-112",
    "weak-prng": "SWC-120", "weak-randomness": "SWC-120",
    "timestamp": "SWC-116", "block-timestamp": "SWC-116",
    "unchecked-lowlevel": "SWC-104", "unchecked-send": "SWC-104",
    "unchecked-call": "SWC-104",
    "integer-overflow": "SWC-101", "overflow": "SWC-101",
    "underflow": "SWC-101",
    "divide-before-multiply": "SWC-101",
    "unprotected-upgrade": "SWC-105", "missing-access-control": "SWC-105",
    "unrestricted-mint": "SWC-105",
    "shadowing-state": "SWC-119", "shadowing-local": "SWC-119",
    "shadowing-builtin": "SWC-119",
    "unary-operation": "SWC-129", "incorrect-equality": "SWC-132",
    "locked-ether": "SWC-132", "dos-with-failed-call": "SWC-113",
    "dos-gaslimit": "SWC-128", "gas-limit": "SWC-128",
    "erc20-indexed": "SWC-121", "missing-zero-check": "SWC-123",
    "requirement-violation": "SWC-123",
    "assert-state-change": "SWC-110", "assert-violation": "SWC-110",
    "deprecated-origins": "SWC-115",
}

_SWC_TEXT_RULES: List[Tuple["re.Pattern[str]", str]] = [
    (re.compile(r"reentrancy", re.I), "SWC-107"),
    (re.compile(r"tx\.?origin", re.I), "SWC-115"),
    (re.compile(r"selfdestruct|suicidal", re.I), "SWC-106"),
    (re.compile(r"overflow|underflow", re.I), "SWC-101"),
    (re.compile(r"delegatecall", re.I), "SWC-112"),
    (re.compile(r"unchecked.*(call|send|return)", re.I), "SWC-104"),
    (re.compile(r"uninitialized.*(storage|state)", re.I), "SWC-109"),
    (re.compile(r"timestamp|block\.number.*random|weak.*random", re.I),
     "SWC-120"),
    (re.compile(r"access.control|onlyowner|authorization", re.I),
     "SWC-105"),
]


def swc_for(detector: str, text: str = "") -> str:
    """SWC id for a detector name (exact table first, then a
    conservative text-pattern pass), or "" when there is no clean
    mapping."""
    key = (detector or "").strip().lower()
    if key in SWC_TABLE:
        return SWC_TABLE[key]
    blob = f"{detector} {text}"
    for pat, swc in _SWC_TEXT_RULES:
        if pat.search(blob):
            return swc
    return ""


# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------

def _tool_paths() -> Dict[str, List[str]]:
    """Candidate locations per tool binary (audit dir first, then
    PATH via shutil.which at lookup time)."""
    return {
        "slither": [os.path.join(SLITHER_VENV, "bin", "slither")],
        "solc": [os.path.join(SLITHER_VENV, "bin", "solc")],
        "aderyn": [os.path.join(AUDIT_BIN, "aderyn")],
        "semgrep": [os.path.join(SEMGREP_VENV, "bin", "semgrep")],
        "heimdall": [os.path.join(AUDIT_BIN, "heimdall")],
        "echidna": [os.path.join(AUDIT_BIN, "echidna")],
        "medusa": [os.path.join(AUDIT_BIN, "medusa")],
    }


def tool_binary(name: str) -> Optional[str]:
    """Resolve a tool binary: configured audit dirs first, then PATH.
    None when the tool is not installed here."""
    for cand in _tool_paths().get(name, []):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which(name)


def tool_available(name: str) -> bool:
    return tool_binary(name) is not None


def availability() -> Dict[str, Dict[str, Any]]:
    """{tool: {available, path, lane}} for every adapter tool. The
    API adapters are always 'available' (keyless HTTP)."""
    out: Dict[str, Dict[str, Any]] = {}
    for name, lane in TOOL_LANES.items():
        if lane == "api":
            out[name] = {"available": True, "path": "https",
                         "lane": lane}
            continue
        if name == "smtchecker":
            # Not a binary of its own: it is solc's built-in checker.
            path = tool_binary("solc")
            out[name] = {"available": path is not None,
                         "path": path or "", "lane": lane}
            continue
        path = tool_binary(name)
        out[name] = {"available": path is not None, "path": path or "",
                     "lane": lane}
    return out


def _tool_env() -> Dict[str, str]:
    """Environment for tool subprocesses: audit bin + venv bins on
    PATH (solc-select's solc shim lives in the slither venv), and the
    z3 4.12 shared library from the z3-solver wheel on
    LD_LIBRARY_PATH so solc's SMTChecker can actually load a solver
    (without it CHC/BMC silently report 'solver not available')."""
    env = dict(os.environ)
    extra = [AUDIT_BIN, os.path.join(SLITHER_VENV, "bin"),
             os.path.join(SEMGREP_VENV, "bin")]
    env["PATH"] = os.pathsep.join(
        [p for p in extra if os.path.isdir(p)] +
        [env.get("PATH", "")])
    if os.path.isdir(Z3_LIB_DIR):
        env["LD_LIBRARY_PATH"] = os.pathsep.join(
            [Z3_LIB_DIR, env.get("LD_LIBRARY_PATH", "")]).strip(os.pathsep)
    return env


async def run_tool(cmd: List[str], cwd: str, budget_s: float,
                   env: Optional[Dict[str, str]] = None
                   ) -> Tuple[int, str, str]:
    """Run a tool as an async subprocess with a hard budget.
    Returns (exit_code, stdout, stderr); exit_code -1 on timeout,
    -2 when the binary could not be started. Never raises."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env or _tool_env())
    except Exception:
        return -2, "", ""
    try:
        out, err = await asyncio.wait_for(proc.communicate(),
                                          timeout=max(1.0, budget_s))
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        try:
            out, err = await proc.communicate()
        except Exception:
            out, err = b"", b""
        return -1, out.decode("utf-8", "replace"), \
            err.decode("utf-8", "replace")
    return proc.returncode or 0, out.decode("utf-8", "replace"), \
        err.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Output parsers (pure functions - unit-tested on saved fixture outputs)
# ---------------------------------------------------------------------------

def _snippet(source: str, lines: List[int]) -> str:
    """The source lines a tool pointed at (1-based, capped)."""
    if not source or not lines:
        return ""
    src_lines = source.splitlines()
    picked = []
    for ln in lines:
        if 1 <= ln <= len(src_lines):
            picked.append(src_lines[ln - 1].rstrip())
    return "\n".join(picked)[:1200]


def _norm(tool: str, detector: str, severity: str, message: str,
          code: str = "", extra: Optional[Dict[str, Any]] = None
          ) -> Dict[str, Any]:
    """One normalized detector hit, pre-Finding."""
    slug = re.sub(r"[^a-z0-9]+", "_", detector.lower()).strip("_")
    hit = {
        "tool": tool,
        "detector": detector,
        "key": f"{tool}_{slug}",
        "severity": map_severity(severity),
        "message": (message or "").strip(),
        "code": code or "",
    }
    swc = swc_for(detector, message)
    if swc:
        hit["swc_id"] = swc
    if extra:
        hit.update(extra)
    return hit


def parse_slither(data: Dict[str, Any], source: str = ""
                  ) -> List[Dict[str, Any]]:
    """Slither --json output -> normalized hits."""
    out: List[Dict[str, Any]] = []
    detectors = ((data or {}).get("results") or {}).get("detectors") or []
    for det in detectors:
        if not isinstance(det, dict):
            continue
        check = str(det.get("check") or "unknown")
        el = (det.get("elements") or [{}])[0] or {}
        mapping = el.get("source_mapping") or {}
        lines = mapping.get("lines") or []
        msg = str(det.get("description") or "").strip()
        out.append(_norm(
            "slither", check, str(det.get("impact") or "low"), msg,
            code=_snippet(source, lines),
            extra={"lines": lines,
                   "confidence": str(det.get("confidence") or ""),
                   "element": str(el.get("name") or "")}))
    return out


def parse_aderyn(data: Dict[str, Any], source: str = ""
                 ) -> List[Dict[str, Any]]:
    """Aderyn report.json -> normalized hits."""
    out: List[Dict[str, Any]] = []
    for tier, sev in (("high_issues", "high"), ("low_issues", "low")):
        issues = ((data or {}).get(tier) or {}).get("issues") or []
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            detector = str(issue.get("detector_name") or "unknown")
            inst = (issue.get("instances") or [{}])[0] or {}
            line = inst.get("line_no")
            lines = [line] if isinstance(line, int) else []
            out.append(_norm(
                "aderyn", detector, sev,
                str(issue.get("title") or issue.get("description")
                    or ""),
                code=_snippet(source, lines),
                extra={"lines": lines,
                       "contract_path": str(
                           inst.get("contract_path") or "")}))
    return out


def parse_semgrep(data: Dict[str, Any], source: str = ""
                  ) -> List[Dict[str, Any]]:
    """Semgrep --json output -> normalized hits."""
    out: List[Dict[str, Any]] = []
    for res in (data or {}).get("results") or []:
        if not isinstance(res, dict):
            continue
        check = str(res.get("check_id") or "unknown")
        detector = check.rsplit(".", 1)[-1]
        extra = res.get("extra") or {}
        start = (res.get("start") or {}).get("line")
        lines = [start] if isinstance(start, int) else []
        lines_txt = str(extra.get("lines") or "").strip()
        if lines_txt == "requires login":
            # Registry-pack rules redact the matched code unless
            # logged in; use our own snippet of the same line.
            lines_txt = ""
        out.append(_norm(
            "semgrep", detector,
            str(extra.get("severity") or "warning"),
            str(extra.get("message") or ""),
            code=(lines_txt or _snippet(source, lines)),
            extra={"lines": lines, "check_id": check}))
    return out


_SMT_RE = re.compile(
    r"Warning:\s*(CHC|BMC):\s*(.+?)(?:\n|$)")


def parse_smtchecker(text: str) -> List[Dict[str, Any]]:
    """solc SMTChecker compiler output -> normalized hits. Lines
    like 'Warning: CHC: Overflow ... happens here.' are findings;
    'solver not available' output yields NO hits (the lane simply
    did not run - absence, not a clean bill)."""
    out: List[Dict[str, Any]] = []
    for m in _SMT_RE.finditer(text or ""):
        engine, msg = m.group(1), m.group(2).strip()
        if "not available" in msg or "not possible" in msg:
            continue
        detector = ("overflow" if "verflow" in msg else
                    "assertion" if "ssertion" in msg else
                    "verification")
        out.append(_norm("smtchecker", f"{engine.lower()}_{detector}",
                         "medium", f"{engine}: {msg}",
                         extra={"engine": engine}))
    return out


_HEIMDALL_OPS = {
    "SELFDESTRUCT": ("high", "bytecode contains SELFDESTRUCT: the "
                     "contract can be destroyed and its balance "
                     "force-sent"),
    "DELEGATECALL": ("medium", "bytecode contains DELEGATECALL: "
                     "foreign code runs in this contract's storage "
                     "context"),
    "CALLCODE": ("medium", "bytecode contains CALLCODE (legacy "
                 "delegatecall variant)"),
    "CREATE2": ("low", "bytecode contains CREATE2: deterministic "
              "address deployment"),
}


def parse_heimdall_asm(asm: str) -> List[Dict[str, Any]]:
    """Heimdall disassembly (.asm text) -> normalized hits for the
    sensitive opcodes present. Bytecode lane: heuristics only, so
    severities are capped and labeled bytecode-only."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for line in (asm or "").splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        op = parts[1].upper()
        if op in _HEIMDALL_OPS and op not in seen:
            seen.add(op)
            sev, msg = _HEIMDALL_OPS[op]
            out.append(_norm(
                "heimdall", f"opcode_{op.lower()}", sev, msg,
                code=line.strip(),
                extra={"opcode": op, "bytecode_only": True}))
    return out


def parse_echidna(text: str) -> List[Dict[str, Any]]:
    """Echidna text output -> failed property/assertion hits.
    Lines look like '<name>: failed!' / 'Test <name> falsified!'."""
    out: List[Dict[str, Any]] = []
    for m in re.finditer(r"^([A-Za-z0-9_]+)\(\):\s*failed", text or "",
                         re.M):
        out.append(_norm(
            "echidna", f"assertion_{m.group(1)}", "high",
            f"Echidna falsified {m.group(1)}(): a property/assertion "
            "in the test harness does not hold under fuzzed call "
            "sequences. Simulation candidate - human review required.",
            extra={"review_status": "pending",
                   "simulation_candidate": True}))
    return out


def parse_medusa(text: str) -> List[Dict[str, Any]]:
    """Medusa text output -> [FAILED] assertion/property hits."""
    out: List[Dict[str, Any]] = []
    for m in re.finditer(
            r"\[FAILED\]\s*(?:Assertion Test|Property Test):\s*"
            r"([A-Za-z0-9_.:()]+)", text or ""):
        out.append(_norm(
            "medusa", f"assertion_{m.group(1)}", "high",
            f"Medusa falsified {m.group(1)}: a property/assertion "
            "in the test harness does not hold under fuzzed call "
            "sequences. Simulation candidate - human review required.",
            extra={"review_status": "pending",
                   "simulation_candidate": True}))
    return out


# ---------------------------------------------------------------------------
# API adapters (keyless): GoPlus token security + Honeypot.is
# ---------------------------------------------------------------------------

_GOPLUS_HIGH_FLAGS = [
    ("is_honeypot", "Token is flagged as a HONEYPOT by GoPlus: "
     "buyers may be unable to sell"),
    ("cannot_sell_all", "Holders cannot sell their full balance "
     "(GoPlus cannot_sell_all)"),
    ("can_take_back_ownership", "Ownership can be taken back by the "
     "creator (GoPlus can_take_back_ownership)"),
    ("hidden_owner", "The contract has a HIDDEN owner (GoPlus)"),
    ("selfdestruct", "The contract can selfdestruct (GoPlus)"),
]
_GOPLUS_MED_FLAGS = [
    ("is_mintable", "Token is mintable by a privileged account "
     "(GoPlus is_mintable)"),
    ("external_call", "Token makes external calls in transfer paths "
     "(GoPlus external_call)"),
    ("is_blacklisted", "Token has a blacklist function (GoPlus)"),
]


def parse_goplus(data: Dict[str, Any], address: str
                 ) -> List[Dict[str, Any]]:
    """GoPlus token_security response -> normalized hits. Pure: the
    fetch lives in the plugin."""
    out: List[Dict[str, Any]] = []
    result = (data or {}).get("result") or {}
    entry = None
    for k, v in result.items():
        if isinstance(v, dict) and k.lower() == address.lower():
            entry = v
            break
    if entry is None and result:
        entry = next((v for v in result.values() if isinstance(v, dict)),
                     None)
    if not entry:
        return out
    flagged = False
    for field_name, msg in _GOPLUS_HIGH_FLAGS:
        if str(entry.get(field_name)) == "1":
            flagged = True
            out.append(_norm("goplus", field_name, "high", msg,
                             extra={"field": field_name}))
    for field_name, msg in _GOPLUS_MED_FLAGS:
        if str(entry.get(field_name)) == "1":
            flagged = True
            out.append(_norm("goplus", field_name, "medium", msg,
                             extra={"field": field_name}))
    for tax_field in ("buy_tax", "sell_tax"):
        try:
            tax = float(entry.get(tax_field) or 0)
        except (TypeError, ValueError):
            tax = 0.0
        if tax >= 0.10:
            flagged = True
            out.append(_norm(
                "goplus", tax_field, "medium",
                f"{tax_field.replace('_', ' ').title()} is "
                f"{tax:.0%} (GoPlus) - very high transfer tax",
                extra={"field": tax_field, "tax": tax}))
    if not flagged:
        out.append(_norm(
            "goplus", "token_security_profile", "low",
            "GoPlus token security profile: no honeypot, mint, "
            "ownership-takeback, hidden-owner, blacklist or "
            "high-tax flags raised",
            extra={"owner_address": str(entry.get("owner_address")
                                        or ""),
                   "is_open_source": str(entry.get("is_open_source")
                                         or ""),
                   "is_proxy": str(entry.get("is_proxy") or "")}))
    return out


def parse_honeypot(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Honeypot.is IsHoneypot response -> normalized hits."""
    out: List[Dict[str, Any]] = []
    data = data or {}
    res = data.get("honeypotResult") or {}
    sim = data.get("simulationResult") or {}
    summary = data.get("summary") or {}
    if res.get("isHoneypot") is True:
        out.append(_norm(
            "honeypot", "is_honeypot", "high",
            "Honeypot.is SIMULATION flags this token as a honeypot: "
            "a simulated buy succeeds but the sell fails",
            extra={"simulation": True}))
        return out
    worst_tax = 0.0
    for field_name in ("buyTax", "sellTax", "transferTax"):
        try:
            worst_tax = max(worst_tax, float(sim.get(field_name) or 0))
        except (TypeError, ValueError):
            pass
    if worst_tax >= 10:
        out.append(_norm(
            "honeypot", "high_tax", "medium",
            f"Honeypot.is simulation shows a worst transfer tax of "
            f"{worst_tax:.0f}%",
            extra={"worst_tax": worst_tax}))
        return out
    risk = str(summary.get("risk") or "unknown")
    out.append(_norm(
        "honeypot", "simulation_profile", "low",
        f"Honeypot.is simulation: not a honeypot (risk={risk}, "
        f"buy tax {sim.get('buyTax')}, sell tax "
        f"{sim.get('sellTax')})",
        extra={"risk": risk,
               "risk_level": summary.get("riskLevel")}))
    return out


# ---------------------------------------------------------------------------
# Adapters: each returns normalized hits, [] when the tool is absent or
# produced nothing parseable. None of them ever raise.
# ---------------------------------------------------------------------------

def _pragma_version(source: str) -> str:
    m = re.search(r"pragma\s+solidity\s+[^;]*?(\d+)\.(\d+)\.(\d+)",
                  source or "")
    if not m:
        return ""
    return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"


def _solc_for(source: str) -> Optional[str]:
    """The solc-select artifact matching the source's pragma
    (same major.minor, highest patch installed), else the default
    `solc` on the tool PATH."""
    want = _pragma_version(source)
    artifacts = os.path.expanduser("~/.solc-select/artifacts")
    try:
        installed = sorted(
            (d[len("solc-"):] for d in os.listdir(artifacts)
             if d.startswith("solc-")),
            key=lambda v: [int(x) for x in v.split(".")])
    except Exception:
        installed = []
    if want:
        major_minor = ".".join(want.split(".")[:2])
        matches = [v for v in installed
                   if ".".join(v.split(".")[:2]) == major_minor]
        if matches:
            pick = matches[-1]
            path = os.path.join(artifacts, f"solc-{pick}",
                                f"solc-{pick}")
            if os.path.isfile(path):
                return path
    return tool_binary("solc")


def _write_source(workdir: str, source: str) -> str:
    path = os.path.join(workdir, "Contract.sol")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(source)
    return path


async def _adapt_slither(workdir: str, source: str, budget: float
                         ) -> List[Dict[str, Any]]:
    binary = tool_binary("slither")
    if not binary:
        return []
    # Own subdir: crytic-compile caches compilation artifacts
    # (crytic-export/) in the cwd and a second slither run in the
    # same directory can silently reuse the PREVIOUS contract's
    # compilation (verified live: a clean control came back with
    # the canary's findings). Never share the directory.
    workdir = os.path.join(workdir, "slither")
    os.makedirs(workdir, exist_ok=True)
    _write_source(workdir, source)
    out_json = os.path.join(workdir, "slither.json")
    await run_tool([binary, "Contract.sol", "--json", out_json,
                    "--disable-color"],
                   cwd=workdir, budget_s=budget)
    try:
        with open(out_json, encoding="utf-8") as fh:
            return parse_slither(json.load(fh), source)
    except Exception:
        return []


async def _adapt_aderyn(workdir: str, source: str, budget: float
                        ) -> List[Dict[str, Any]]:
    binary = tool_binary("aderyn")
    if not binary:
        return []
    proj = os.path.join(workdir, "proj")
    contracts = os.path.join(proj, "contracts")
    os.makedirs(contracts, exist_ok=True)
    with open(os.path.join(contracts, "Contract.sol"), "w",
              encoding="utf-8") as fh:
        fh.write(source)
    with open(os.path.join(proj, "foundry.toml"), "w",
              encoding="utf-8") as fh:
        fh.write('[profile.default]\nsrc = "contracts"\n')
    await run_tool([binary, ".", "--output", "report.json",
                    "--no-snippets"], cwd=proj, budget_s=budget)
    try:
        with open(os.path.join(proj, "report.json"),
                  encoding="utf-8") as fh:
            return parse_aderyn(json.load(fh), source)
    except Exception:
        return []


async def _adapt_semgrep(workdir: str, source: str, budget: float
                         ) -> List[Dict[str, Any]]:
    binary = tool_binary("semgrep")
    if not binary:
        return []
    _write_source(workdir, source)
    config = SEMGREP_RULES_DIR if os.path.isdir(SEMGREP_RULES_DIR) \
        else os.environ.get("SEMGREP_CONFIG", "p/solidity")
    _rc, out, _err = await run_tool(
        [binary, "--json", "--quiet", "--timeout", "20",
         "--metrics", "off", "--config", config, "Contract.sol"],
        cwd=workdir, budget_s=budget)
    try:
        return parse_semgrep(json.loads(out), source)
    except Exception:
        return []


async def _adapt_smtchecker(workdir: str, source: str, budget: float
                            ) -> List[Dict[str, Any]]:
    solc = _solc_for(source)
    if not solc:
        return []
    _write_source(workdir, source)
    _rc, out, err = await run_tool(
        [solc, "--model-checker-engine", "all",
         "--model-checker-targets", "all",
         "--base-path", workdir, "Contract.sol"],
        cwd=workdir, budget_s=budget)
    return parse_smtchecker(out + "\n" + err)


async def _adapt_heimdall(workdir: str, code_hex: str, budget: float
                          ) -> List[Dict[str, Any]]:
    binary = tool_binary("heimdall")
    if not binary or not code_hex or code_hex == "0x":
        return []
    outdir = os.path.join(workdir, "heimdall-out")
    os.makedirs(outdir, exist_ok=True)
    await run_tool([binary, "disassemble", code_hex,
                    "--output", outdir],
                   cwd=workdir, budget_s=budget)
    try:
        with open(os.path.join(outdir, "disassembled.asm"),
                  encoding="utf-8") as fh:
            return parse_heimdall_asm(fh.read())
    except Exception:
        return []


async def _adapt_echidna(project: Dict[str, Any], budget: float
                         ) -> List[Dict[str, Any]]:
    binary = tool_binary("echidna")
    src_dir = str(project.get("dir") or "")
    if not binary or not src_dir or not os.path.isdir(src_dir):
        return []
    workdir = tempfile.mkdtemp(prefix="toolbox-echidna-")
    proj = os.path.join(workdir, "proj")
    try:
        shutil.copytree(src_dir, proj)
        target = str(project.get("target") or "")
        contract = str(project.get("contract") or "")
        cmd = [binary, target or ".", "--test-mode", "assertion",
               "--test-limit", str(int(project.get("test_limit")
                                       or 50000)),
               "--seed", "42"]
        if contract:
            cmd += ["--contract", contract]
        _rc, out, err = await run_tool(cmd, cwd=proj,
                                       budget_s=budget)
        return parse_echidna(out + "\n" + err)
    except Exception:
        return []
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


async def _adapt_medusa(project: Dict[str, Any], budget: float
                        ) -> List[Dict[str, Any]]:
    binary = tool_binary("medusa")
    src_dir = str(project.get("dir") or "")
    if not binary or not src_dir or not os.path.isdir(src_dir):
        return []
    if not os.path.isfile(os.path.join(src_dir, "medusa.json")):
        return []
    workdir = tempfile.mkdtemp(prefix="toolbox-medusa-")
    proj = os.path.join(workdir, "proj")
    try:
        shutil.copytree(src_dir, proj)
        _rc, out, err = await run_tool([binary, "fuzz"], cwd=proj,
                                       budget_s=budget)
        clean = re.sub(r"\x1b\[[0-9;]*m", "", out + "\n" + err)
        return parse_medusa(clean)
    except Exception:
        return []
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

_REMEDIATION = (
    "Review this finding from {tool} against the contract source. "
    "External-tool hits are detector output, not proof: confirm the "
    "code path is reachable and ungated, then fix or document why "
    "it is safe.")


class AuditToolboxPlugin(Plugin):
    id = "audit_toolbox"
    label = "Audit Toolbox (Slither/Aderyn/Semgrep/SMT/Fuzz/APIs)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []  # keyless: Blockscout/Sourcify + public APIs
    description = (
        "Runs the standard auditor toolbox over a contract's "
        "verified source and bytecode: Slither and Aderyn static "
        "analysis, Semgrep Solidity rules, solc SMTChecker, "
        "Heimdall bytecode disassembly, Echidna/Medusa property "
        "fuzzing (prepared harnesses only), plus GoPlus and "
        "Honeypot.is token-risk APIs. Heavy tools run only in the "
        "heavy lane (RECON_HEAVY_LANE / worker context); absent "
        "binaries skip silently - tools live outside the app image "
        "under ~/workspace/tools/audit.")
    phase = 2
    lane = "heavy"          # runner cap = RECON_HEAVY_TIMEOUT
    timeout_s = 1800

    # -- context gates -------------------------------------------------
    def _heavy_enabled(self, ctx: Ctx) -> bool:
        if os.environ.get("RECON_HEAVY_LANE", "").lower() in (
                "1", "true", "yes"):
            return True
        if ctx.shared.get("allow_heavy"):
            return True
        return ctx.module_overrides.get(self.id) == "heavy"

    # -- target collection (mirrors crypto_drain) ----------------------
    def _collect(self, target: Target,
                 ctx: Ctx) -> List[Tuple[Optional[str], str]]:
        out: List[Tuple[Optional[str], str]] = []
        seen = set()

        def add(chain_hint: Optional[str], addr: str) -> None:
            addr = (addr or "").strip()
            if not cc.ADDRESS_RE.match(addr):
                return
            if addr.lower() == cc.ZERO_ADDRESS:
                return
            k = addr.lower()
            if k in seen:
                return
            seen.add(k)
            out.append((chain_hint, addr))

        for raw in (target.normalized, target.raw):
            chain_hint, addr = cc.parse_target_address(raw or "")
            if addr:
                add(chain_hint, addr)
                break
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else \
                    str(item.get("address", ""))
                add(None, a)
        for item in ctx.consume("chain_contracts"):
            if isinstance(item, dict):
                hint = item.get("chain")
                add(hint if isinstance(hint, str) and
                    hint in cc.CHAINS else None,
                    str(item.get("address", "")))
        return out[:MAX_ADDRESSES]

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        work = self._collect(target, ctx)
        if not work:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed) or a web target "
                "whose pages reference one")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        heavy = self._heavy_enabled(ctx)
        try:
            from .. import config as _cfg
            heavy_budget = float(getattr(_cfg, "HEAVY_TIMEOUT_S",
                                         1800))
        except Exception:
            heavy_budget = 1800.0
        deadline = t0 + heavy_budget

        findings: List[Finding] = []
        analyzed = 0
        fuzz_project = ctx.shared.get("fuzz_project")
        fuzz_done = False
        for chain_hint, addr in work:
            try:
                got = await self._scan_address(
                    ctx, key, chain_hint, addr, findings, heavy,
                    deadline, fuzz_project if not fuzz_done else None)
            except Exception:
                got = False
            if got:
                analyzed += 1
                fuzz_done = True

        avail = availability()
        avail_names = [n for n, a in avail.items() if a["available"]]
        res = self._ok(
            findings,
            f"toolbox-analyzed {analyzed} contract(s); tools "
            f"available here: {', '.join(avail_names) or 'none'}; "
            f"heavy lane {'on' if heavy else 'off'}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _scan_address(self, ctx: Ctx, key: Optional[str],
                            chain_hint: Optional[str], addr: str,
                            findings: List[Finding], heavy: bool,
                            deadline: float,
                            fuzz_project: Optional[Dict[str, Any]]
                            ) -> bool:
        chain_ids = [chain_hint] if chain_hint else \
            list(cc.DEFAULT_CHAIN_ORDER)
        done_any = False
        for cid in chain_ids:
            if done_any:
                break
            chain = cc.CHAINS[cid]
            code = await cc.rpc_get_code(ctx, chain, addr)
            if code is None or code == "0x" or len(code) < 4:
                continue
            done_any = True
            src = await cc.fetch_verified_source(ctx, chain, addr, key)
            res = {"implementation": "", "via": "", "beacon": ""}
            try:
                res = await cc.resolve_implementation(
                    ctx, chain, addr, code,
                    {"implementation": (src or {}).get(
                        "implementation", "")})
            except Exception:
                pass
            impl = res.get("implementation") or ""
            role = "proxy_shell" if impl else "standalone"
            await self._analyze(ctx, chain, addr, src, code, role,
                                findings, heavy, deadline,
                                fuzz_project, token_level=True)
            if impl:
                impl_code = None
                impl_src = None
                try:
                    impl_code = await cc.rpc_get_code(ctx, chain, impl)
                    impl_src = await cc.fetch_verified_source(
                        ctx, chain, impl, key)
                except Exception:
                    impl_code, impl_src = None, None
                if impl_code and impl_code != "0x" and \
                        len(impl_code) >= 4:
                    await self._analyze(
                        ctx, chain, impl, impl_src, impl_code,
                        "implementation", findings, heavy, deadline,
                        None, token_level=False)
        return done_any

    # -- one contract, all adapters -------------------------------------
    async def _analyze(self, ctx: Ctx, chain: cc.ChainConfig,
                       addr: str, src: Optional[Dict[str, Any]],
                       code_hex: str, role: str,
                       findings: List[Finding], heavy: bool,
                       deadline: float,
                       fuzz_project: Optional[Dict[str, Any]],
                       token_level: bool) -> None:
        url = cc.explorer_url(chain, addr)
        source_text = (src or {}).get("source") or ""
        base_ev = {"address": addr, "chain": chain.id,
                   "chain_id": chain.chain_id, "contract_role": role}

        def emit(hit: Dict[str, Any]) -> None:
            ev = dict(base_ev)
            ev.update({
                "severity": hit["severity"], "tool": hit["tool"],
                "detector": hit["detector"],
                "code": hit.get("code", ""),
                "remediation": _REMEDIATION.format(
                    tool=hit["tool"]),
            })
            for extra_key in ("swc_id", "lines", "confidence",
                              "element", "contract_path", "check_id",
                              "engine", "opcode", "bytecode_only",
                              "field", "tax", "owner_address",
                              "is_open_source", "is_proxy", "risk",
                              "risk_level", "worst_tax",
                              "review_status", "simulation_candidate",
                              "simulation"):
                if extra_key in hit:
                    ev[extra_key] = hit[extra_key]
            value = (f"{hit['severity'].upper()}: {hit['tool']}: "
                     f"{hit['message']} [{addr} on {chain.name}, "
                     f"{role}]")
            if hit.get("code"):
                value += f"\n\nCode:\n{hit['code']}"
            findings.append(self._f(
                "web3", hit["key"], value, source=hit["tool"],
                source_url=url,
                confidence=85 if hit["tool"] in ("slither", "goplus")
                else 75,
                passive=True, evidence=ev))

        workdir = tempfile.mkdtemp(prefix="toolbox-")
        try:
            # --- light lane (fits the fast request budget) ---------
            if code_hex:
                for hit in await _adapt_heimdall(
                        workdir, code_hex,
                        TOOL_BUDGETS["heimdall"]):
                    emit(hit)
            if source_text:
                for hit in await _adapt_semgrep(
                        workdir, source_text,
                        TOOL_BUDGETS["semgrep"]):
                    emit(hit)
            if token_level:
                for hit in await self._api_hits(ctx, chain, addr):
                    emit(hit)

            # --- heavy lane -----------------------------------------
            if heavy and source_text:
                for name, adapter in (
                        ("slither", _adapt_slither),
                        ("aderyn", _adapt_aderyn),
                        ("smtchecker", _adapt_smtchecker)):
                    remaining = deadline - time.monotonic()
                    if remaining <= 30:
                        break
                    budget = min(TOOL_BUDGETS[name], remaining)
                    for hit in await adapter(workdir, source_text,
                                             budget):
                        emit(hit)
                if fuzz_project:
                    for name, adapter in (("echidna", _adapt_echidna),
                                          ("medusa", _adapt_medusa)):
                        remaining = deadline - time.monotonic()
                        if remaining <= 30:
                            break
                        budget = min(TOOL_BUDGETS[name], remaining)
                        for hit in await adapter(fuzz_project,
                                                 budget):
                            emit(hit)
            elif not heavy:
                avail = availability()
                ready = [n for n in HEAVY_TOOLS
                         if avail.get(n, {}).get("available")]
                if ready:
                    ev = dict(base_ev)
                    ev.update({
                        "severity": "low", "tools_not_run": ready,
                        "remediation": "Re-run this contract from "
                                       "the scan worker / offline "
                                       "harness with the heavy lane "
                                       "enabled (RECON_HEAVY_LANE=1) "
                                       "to execute these tools."})
                    findings.append(self._f(
                        "web3", "heavy_lane_not_run",
                        "LOW: audit toolbox: heavy tools available "
                        f"but not run in the fast lane: "
                        f"{', '.join(ready)} [{addr} on "
                        f"{chain.name}, {role}]",
                        source="audit_toolbox", source_url=url,
                        confidence=100, passive=True, evidence=ev))
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # -- keyless risk APIs ----------------------------------------------
    async def _api_hits(self, ctx: Ctx, chain: cc.ChainConfig,
                        addr: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        try:
            from ..ratelimit import fetch
        except Exception:
            return hits
        cache_ns = "toolbox-api"

        async def get_json(url: str, cache_key: str) -> Dict[str, Any]:
            try:
                cached = ctx.cache.get(cache_ns, cache_key)
                if isinstance(cached, dict) and cached:
                    return cached
            except Exception:
                pass
            try:
                if ctx.limiter is not None:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                    timeout=15, max_retries=0)
                else:
                    # ratelimit.fetch dereferences the limiter; in
                    # limiter-less contexts (offline harnesses) fall
                    # back to the shared client directly.
                    r = await ctx.http.get(url, timeout=15)
                if r.status_code != 200:
                    return {}
                data = r.json()
            except Exception:
                return {}
            if isinstance(data, dict) and data:
                try:
                    ctx.cache.set(cache_ns, cache_key, data, ttl=3600)
                except Exception:
                    pass
                return data
            return {}

        goplus = await get_json(
            "https://api.gopluslabs.io/api/v1/token_security/"
            f"{chain.chain_id}?contract_addresses={addr}",
            f"goplus:{chain.chain_id}:{addr.lower()}")
        if goplus:
            hits.extend(parse_goplus(goplus, addr))
        honeypot = await get_json(
            "https://api.honeypot.is/v2/IsHoneypot"
            f"?address={addr}&chainID={chain.chain_id}",
            f"honeypot:{chain.chain_id}:{addr.lower()}")
        if honeypot:
            hits.extend(parse_honeypot(honeypot))
        return hits
