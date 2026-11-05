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

Round 2 (Jay's Nov 3 lists, ~185 names over three pastes): the
genuinely integrable additions are wired here too - Mythril
promoted from the simulation lane's opt-in side venv to a
first-class heavy adapter, Wake (Ackee) detectors, Solhint's
security ruleset, Slitherin (Pessimistic's extra Slither detectors,
auto-registered into the Slither run when installed in the slither
venv; their hits are re-tagged source="slitherin"), Securify 2.0
(eth-sri, Souffle-backed), Surya's call graph (the one output the
first-party ast_visual_audit plugin does not already produce as
structured data), and a 4byte.directory selector lookup for
bytecode-only targets (function identification Heimdall's opcode
scan does not do). Everything else on the lists is a VS Code /
browser / Remix extension, a paid or keyed SaaS, a marketplace, a
wallet, a formatter, or a non-EVM/dev-infra tool - the PR body
carries the full availability matrix with the exact reason per
name. Nothing is faked: an adapter exists only where the real tool
installed and ran against the canary fixtures.

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
MYTHRIL_VENV = os.path.join(AUDIT_DIR, "venv-mythril")
WAKE_VENV = os.path.join(AUDIT_DIR, "venv-wake")
SECURIFY_VENV = os.path.join(AUDIT_DIR, "venv-securify")
NODE_TOOLS_BIN = os.path.join(AUDIT_DIR, "node-tools",
                              "node_modules", ".bin")
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
    "mythril": 600, "wake": 300, "securify": 600,
    "semgrep": 45, "heimdall": 45, "solhint": 45, "surya": 45,
}

TOOL_LANES = {
    "slither": "static", "aderyn": "static", "semgrep": "static",
    "smtchecker": "symbolic", "heimdall": "bytecode",
    "echidna": "fuzz", "medusa": "fuzz",
    "goplus": "api", "honeypot": "api",
    "mythril": "symbolic", "wake": "static", "solhint": "static",
    "securify": "static", "surya": "static", "fourbyte": "bytecode",
}

HEAVY_TOOLS = ("slither", "aderyn", "smtchecker", "echidna", "medusa",
               "mythril", "wake", "securify")
LIGHT_TOOLS = ("semgrep", "heimdall", "solhint", "surya")

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

def _repo_root() -> str:
    """The repo checkout root (backend/app/plugins -> up 3). The
    simulation lane's Mythril side venv lives there (.venv-mythril,
    the local-dev pattern PR #76 established)."""
    from pathlib import Path
    return str(Path(__file__).resolve().parents[3])


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
        "mythril": [os.environ.get("RECON_MYTHRIL_BIN") or "",
                    os.path.join(MYTHRIL_VENV, "bin", "myth"),
                    os.path.join(_repo_root(), ".venv-mythril",
                                 "bin", "myth"),
                    os.path.join(AUDIT_BIN, "myth")],
        "wake": [os.path.join(WAKE_VENV, "bin", "wake")],
        "securify": [os.path.join(SECURIFY_VENV, "bin", "securify")],
        "solhint": [os.path.join(NODE_TOOLS_BIN, "solhint")],
        "surya": [os.path.join(NODE_TOOLS_BIN, "surya")],
    }


# Tool key -> executable name when they differ (PATH fallback).
_WHICH_ALIASES = {"mythril": "myth"}


def tool_binary(name: str) -> Optional[str]:
    """Resolve a tool binary: configured audit dirs first, then PATH.
    None when the tool is not installed here."""
    for cand in _tool_paths().get(name, []):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which(_WHICH_ALIASES.get(name, name))


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
        if name == "fourbyte":
            # Keyless public API like the other API adapters, but
            # classified bytecode-lane (it identifies functions in
            # unverified bytecode).
            out[name] = {"available": True, "path": "https",
                         "lane": lane}
            continue
        if name == "smtchecker":
            # Not a binary of its own: it is solc's built-in checker.
            path = tool_binary("solc")
            out[name] = {"available": path is not None,
                         "path": path or "", "lane": lane}
            continue
        if name == "securify":
            # The CLI also needs the Souffle Datalog engine on PATH
            # at runtime; without it every run errors before any
            # pattern executes, so availability must say so.
            path = tool_binary("securify")
            souffle = shutil.which("souffle", path=_tool_env()["PATH"])
            out[name] = {"available": bool(path and souffle),
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
             os.path.join(SEMGREP_VENV, "bin"),
             os.path.join(WAKE_VENV, "bin"),
             os.path.join(SECURIFY_VENV, "bin"), NODE_TOOLS_BIN]
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
        hit = _norm(
            "slither", check, str(det.get("impact") or "low"), msg,
            code=_snippet(source, lines),
            extra={"lines": lines,
                   "confidence": str(det.get("confidence") or ""),
                   "element": str(el.get("name") or "")})
        if check.startswith("pess-"):
            # Slitherin (Pessimistic) detector, auto-registered into
            # the Slither run when slitherin is installed in the
            # slither venv. Re-tag so provenance is honest: the
            # detector is Slitherin's, the runner was Slither.
            hit["tool"] = "slitherin"
            hit["key"] = f"slitherin_{hit['detector'].replace('-', '_')}"
            hit["via"] = "slither"
        out.append(hit)
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


def parse_mythril(data: Any, source: str = ""
                  ) -> List[Dict[str, Any]]:
    """Mythril `analyze -o json` output -> normalized hits. Accepts
    the top-level {"issues": [...]} object (and the per-file list
    shape some versions emit). The tool's own SWC id is carried
    through verbatim. An {"error": ...} payload yields no hits -
    the lane did not run, which is absence, not a clean bill."""
    out: List[Dict[str, Any]] = []
    issues: List[Dict[str, Any]] = []
    if isinstance(data, dict):
        if data.get("error"):
            return out
        raw = data.get("issues")
        if isinstance(raw, list):
            issues = [i for i in raw if isinstance(i, dict)]
    elif isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and \
                    isinstance(entry.get("issues"), list):
                issues.extend(i for i in entry["issues"]
                              if isinstance(i, dict))
    for issue in issues:
        title = str(issue.get("title") or "unknown issue")
        detector = re.sub(r"[^a-z0-9]+", "_",
                          title.lower()).strip("_")
        lineno = issue.get("lineno")
        lines = lineno if isinstance(lineno, list) else \
            [lineno] if isinstance(lineno, int) else []
        lines = [ln for ln in lines if isinstance(ln, int)]
        msg = str(issue.get("description") or title).strip()
        extra: Dict[str, Any] = {
            "lines": lines, "title": title,
            "function": str(issue.get("function") or ""),
            "contract": str(issue.get("contract") or ""),
        }
        # Mythril emits the bare registry number ("106"); the
        # repo vocabulary is the prefixed id ("SWC-106").
        swc = str(issue.get("swc-id") or "").strip()
        if swc.isdigit():
            swc = f"SWC-{swc}"
        if swc:
            extra["swc_id"] = swc
        hit = _norm("mythril", detector,
                    str(issue.get("severity") or "medium"), msg,
                    code=(str(issue.get("code") or "")
                          or _snippet(source, lines)),
                    extra=extra)
        if swc:
            hit["swc_id"] = swc
        out.append(hit)
    return out


# Solhint rules whose findings are security-relevant enough to keep
# at medium; everything else the security ruleset emits is low.
_SOLHINT_MEDIUM = {
    "avoid-tx-origin", "reentrancy", "avoid-suicide",
    "check-send-result", "avoid-call-value", "multiple-sends",
    "avoid-low-level-calls",
}


def parse_solhint(data: Any, source: str = ""
                  ) -> List[Dict[str, Any]]:
    """Solhint `--formatter json` output -> normalized hits. The
    formatter emits one array mixing per-file reports and
    {"conclusion": ...} summary objects; entries without a ruleId
    are skipped. Style rules never reach this parser: the adapter's
    config enables the security ruleset only."""
    out: List[Dict[str, Any]] = []
    if not isinstance(data, list):
        return out
    for item in data:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("ruleId") or "")
        if not rule:
            continue
        line = item.get("line")
        lines = [line] if isinstance(line, int) else []
        sev = "medium" if rule in _SOLHINT_MEDIUM else "low"
        out.append(_norm(
            "solhint", rule, sev,
            str(item.get("message") or ""),
            code=_snippet(source, lines),
            extra={"lines": lines,
                   "column": item.get("column")}))
    return out


def parse_wake(data: Any, source: str = ""
               ) -> List[Dict[str, Any]]:
    """Wake detections.json -> normalized hits. Shape: a list of
    {detector_name, impact, confidence, detection: {message,
    location: {start_line, source, ...}}}."""
    out: List[Dict[str, Any]] = []
    if not isinstance(data, list):
        return out
    for det in data:
        if not isinstance(det, dict) or det.get("suppressed"):
            continue
        name = str(det.get("detector_name") or "unknown")
        body = det.get("detection") or {}
        loc = body.get("location") or {}
        line = loc.get("start_line")
        lines = [line] if isinstance(line, int) else []
        snippet = str(loc.get("source") or "").strip()
        out.append(_norm(
            "wake", name, str(det.get("impact") or "low"),
            str(body.get("message") or ""),
            code=(snippet[:1200] if snippet
                  else _snippet(source, lines)),
            extra={"lines": lines,
                   "confidence": str(det.get("confidence") or ""),
                   "contract": str(loc.get("contract") or "")}))
    return out


_SECURIFY_BLOCK_RE = re.compile(
    r"^Severity:\s+(?P<severity>[A-Z]+)\s*\n"
    r"Pattern:\s+(?P<pattern>.+?)\s*\n"
    r"Description:\s+(?P<description>.*?)\n"
    r"Type:\s+(?P<mtype>[A-Za-z]+)\s*\n"
    r"(?:Contract:\s+(?P<contract>.*?)\s*\n"
    r"Line:\s+(?P<line>\d+)\s*\n)?",
    re.M | re.S)


def parse_securify(text: Any, source: str = ""
                   ) -> List[Dict[str, Any]]:
    """Securify 2.0 TEXT report -> normalized hits. The git
    release's CLI has no JSON mode; main() prints one block per
    pattern match (Severity / Pattern / Description / Type /
    Contract / Line) - the format is taken from the installed
    package's own analyses/analysis.py format_match(). Type is
    Violation / Warning / Compliant / Conflict. Only violations
    and warnings are findings: a Compliant match means the
    pattern HOLDS (surfacing it would invert the tool's meaning)
    and Conflict is the tool's own internal inconsistency."""
    out: List[Dict[str, Any]] = []
    if not isinstance(text, str) or "Pattern:" not in text:
        return out
    for m in _SECURIFY_BLOCK_RE.finditer(text):
        mtype = m.group("mtype").lower()
        if mtype not in ("violation", "warning"):
            continue
        pattern = " ".join(m.group("pattern").split())
        desc = " ".join(m.group("description").split())
        lines = [int(m.group("line"))] if m.group("line") else []
        hit = _norm(
            "securify",
            re.sub(r"[^a-z0-9]+", "_", pattern.lower()).strip("_"),
            m.group("severity").lower(),
            f"Securify {mtype}: {pattern} - {desc}",
            code=_snippet(source, lines),
            extra={"lines": lines, "title": pattern,
                   "contract": (m.group("contract") or "").strip(),
                   "match_type": mtype})
        hit["pattern"] = pattern
        out.append(hit)
    return out


_SURYA_EDGE_RE = re.compile(
    r"^\s*\"?([A-Za-z0-9_.<> ]+?)\"?\s*->\s*\"?([A-Za-z0-9_.<> ]+?)\"?",
    re.M)


def parse_surya_graph(dot: str) -> List[Dict[str, Any]]:
    """Surya `graph` DOT output -> ONE info hit carrying the call
    graph. The structural describe/inheritance map itself is NOT
    duplicated here: ast_visual_audit computes that from the solc
    AST as structured evidence. The DOT call graph is the output
    Surya adds on top of it (a renderable caller->callee graph)."""
    if "digraph" not in (dot or ""):
        return []
    edges = sorted({f"{a}->{b}" for a, b in
                    _SURYA_EDGE_RE.findall(dot)})
    if not edges:
        return []
    return [_norm(
        "surya", "call_graph", "low",
        f"Surya call graph: {len(edges)} caller->callee edge(s) "
        "across the contract's functions (DOT in evidence)",
        extra={"edges": edges[:200], "call_graph_dot": dot[:8000]})]


_PUSH4_RE = re.compile(r"63([0-9a-fA-F]{8})")


def extract_selectors(code_hex: str, cap: int = 32) -> List[str]:
    """Function selectors (PUSH4 immediates) in deployed bytecode,
    deduped, dispatcher-order. Heuristic (a PUSH4 can also be data),
    which is why the 4byte findings are labeled as identifications,
    not facts about intent."""
    out: List[str] = []
    seen = set()
    body = (code_hex or "").lower().removeprefix("0x")
    for m in _PUSH4_RE.finditer(body):
        sel = "0x" + m.group(1)
        if sel not in seen:
            seen.add(sel)
            out.append(sel)
        if len(out) >= cap:
            break
    return out


def parse_fourbyte(data: Any, selector: str) -> List[Dict[str, Any]]:
    """4byte.directory signature lookup -> normalized hits. The API
    returns newest-first and the directory is permissionless, so
    recent spam registrations pollute every popular selector; the
    canonical signature is the OLDEST registration (for
    0xa9059cbb, transfer(address,uint256) from 2016, id 145, sits
    under five later junk entries). Results are sorted by id
    ascending and the oldest wins; the rest are listed as
    alternates. Identifications, not facts about intent."""
    out: List[Dict[str, Any]] = []
    results = [r for r in (data or {}).get("results") or []
               if isinstance(r, dict) and r.get("text_signature")]
    results.sort(key=lambda r: r.get("id") if
                 isinstance(r.get("id"), int) else 1 << 62)
    sigs = [str(r.get("text_signature") or "") for r in results]
    if not sigs:
        return out
    out.append(_norm(
        "fourbyte", "selector_identified", "low",
        f"Selector {selector} is registered on 4byte.directory as "
        f"{sigs[0]}" + (f" (also: {', '.join(sigs[1:3])})"
                        if len(sigs) > 1 else ""),
        extra={"selector": selector, "signature": sigs[0],
               "signatures": sigs[:5]}))
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


_PESS_DETECTORS_CACHE: Dict[str, List[str]] = {}


async def _pess_detectors(binary: str, budget: float) -> List[str]:
    """The Slitherin (pess-*) detector names registered in this
    slither install, parsed from --list-detectors (cached per
    binary). Empty when slitherin is not installed."""
    if binary in _PESS_DETECTORS_CACHE:
        return _PESS_DETECTORS_CACHE[binary]
    _rc, out, err = await run_tool([binary, "--list-detectors"],
                                   cwd=tempfile.gettempdir(),
                                   budget_s=min(60.0, budget))
    names = sorted(set(re.findall(r"pess-[a-z0-9-]+", out + err)))
    _PESS_DETECTORS_CACHE[binary] = names
    return names


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
        pass
    # No JSON: the run died. A known cause since Slitherin joined
    # the venv: a pess-* detector raising on a call pattern kills
    # the WHOLE slither process (verified live: pess-public-vs-
    # external throws AttributeError on the DeFiVulnLabs
    # EtherStore canary, taking every core detector's findings
    # with it). Retry once with the add-on detectors excluded so
    # core Slither output survives a Slitherin crash.
    pess = await _pess_detectors(binary, budget)
    if not pess:
        return []
    retry_json = os.path.join(workdir, "slither-core.json")
    await run_tool([binary, "Contract.sol", "--json", retry_json,
                    "--disable-color",
                    "--exclude", ",".join(pess)],
                   cwd=workdir, budget_s=budget)
    try:
        with open(retry_json, encoding="utf-8") as fh:
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


async def _adapt_mythril(workdir: str, source: str, budget: float
                         ) -> List[Dict[str, Any]]:
    """Mythril as a first-class toolbox tool (promoted from the
    simulation lane, where it sat behind RECON_SIM_SYMBOLIC=1 in a
    side venv). Same bounded invocation contract_sim proved:
    --max-depth 16 and an execution timeout inside the budget."""
    binary = tool_binary("mythril")
    if not binary:
        return []
    workdir = os.path.join(workdir, "mythril")
    os.makedirs(workdir, exist_ok=True)
    _write_source(workdir, source)
    env = _tool_env()
    solc = _solc_for(source)
    if solc:
        env["SOLC"] = solc
    exec_timeout = max(10, int(min(budget, TOOL_BUDGETS["mythril"])))
    _rc, out, _err = await run_tool(
        [binary, "analyze", "Contract.sol", "-o", "json",
         "--execution-timeout", str(exec_timeout),
         "--max-depth", "16"],
        cwd=workdir, budget_s=budget + 30, env=env)
    text = (out or "").strip()
    data: Any = None
    for chunk in (text, text[text.find("{"):], text[text.find("["):]):
        if not chunk:
            continue
        try:
            data = json.loads(chunk)
            break
        except Exception:
            continue
    if data is None:
        return []
    return parse_mythril(data, source)


# Solhint config: the security ruleset ONLY. Style, naming, ordering
# and gas-suggestion rules are deliberately absent (noise for an
# audit lane); every rule solhint 6.x ships that speaks to a
# security property is on at warn.
SOLHINT_CONFIG: Dict[str, Any] = {
    "rules": {
        "avoid-call-value": "warn",
        "avoid-low-level-calls": "warn",
        "avoid-suicide": "warn",
        "avoid-throw": "warn",
        "avoid-tx-origin": "warn",
        "check-send-result": "warn",
        "compiler-version": ["warn", "^0.8.0"],
        "func-visibility": ["warn", {"ignoreConstructors": True}],
        "multiple-sends": "warn",
        "no-complex-fallback": "warn",
        "no-inline-assembly": "warn",
        "not-rely-on-block-hash": "warn",
        "not-rely-on-time": "warn",
        "reentrancy": "warn",
        "state-visibility": "warn",
    }
}


async def _adapt_solhint(workdir: str, source: str, budget: float
                         ) -> List[Dict[str, Any]]:
    binary = tool_binary("solhint")
    if not binary:
        return []
    workdir = os.path.join(workdir, "solhint")
    os.makedirs(workdir, exist_ok=True)
    _write_source(workdir, source)
    with open(os.path.join(workdir, ".solhint.json"), "w",
              encoding="utf-8") as fh:
        json.dump(SOLHINT_CONFIG, fh)
    _rc, out, _err = await run_tool(
        [binary, "--formatter", "json", "Contract.sol"],
        cwd=workdir, budget_s=budget)
    try:
        return parse_solhint(json.loads(out), source)
    except Exception:
        return []


# Solc versions scripts/install-audit-tools.sh seeds into Wake's
# own compiler cache (Wake downloads compilers itself; in sandboxed
# environments that download can fail, so the installer pre-seeds
# the same versions solc-select carries).
_WAKE_SEEDED_SOLC = ("0.8.26", "0.8.20", "0.7.6", "0.6.12", "0.5.17")


def _wake_target_version(source: str) -> str:
    """The seeded Wake solc matching the source pragma's
    major.minor (highest patch), or "" to let Wake auto-select
    (which may need a download)."""
    want = _pragma_version(source)
    if not want:
        return ""
    major_minor = ".".join(want.split(".")[:2])
    matches = [v for v in _WAKE_SEEDED_SOLC
               if ".".join(v.split(".")[:2]) == major_minor]
    return matches[0] if matches else ""


async def _adapt_wake(workdir: str, source: str, budget: float
                      ) -> List[Dict[str, Any]]:
    binary = tool_binary("wake")
    if not binary:
        return []
    workdir = os.path.join(workdir, "wake")
    os.makedirs(workdir, exist_ok=True)
    _write_source(workdir, source)
    target = _wake_target_version(source)
    toml = '[compiler.solc]\nexclude_paths = []\nremappings = []\n'
    if target:
        toml += f'target_version = "{target}"\n'
    with open(os.path.join(workdir, "wake.toml"), "w",
              encoding="utf-8") as fh:
        fh.write(toml)
    await run_tool([binary, "detect", "--export", "json", "all"],
                   cwd=workdir, budget_s=budget)
    try:
        with open(os.path.join(workdir, ".wake", "detections.json"),
                  encoding="utf-8") as fh:
            return parse_wake(json.load(fh), source)
    except Exception:
        return []


async def _adapt_securify(workdir: str, source: str, budget: float
                          ) -> List[Dict[str, Any]]:
    binary = tool_binary("securify")
    if not binary:
        return []
    workdir = os.path.join(workdir, "securify")
    os.makedirs(workdir, exist_ok=True)
    _write_source(workdir, source)
    # Securify 2.0 (git) prints its report as TEXT on stdout (no
    # JSON mode) and needs the `souffle` binary on PATH at runtime;
    # without it the run errors out and yields no blocks, which the
    # parser honestly reads as no findings. Its pragma fixer writes
    # /tmp/fixed_pragma.sol - heavy-lane runs are sequential, so
    # that shared path cannot race within one plugin run.
    _rc, out, _err = await run_tool(
        [binary, "Contract.sol"], cwd=workdir, budget_s=budget)
    text = re.sub(r"\x1b\[[0-9;]*m", "", out or "")
    return parse_securify(text, source)


async def _adapt_surya(workdir: str, source: str, budget: float
                       ) -> List[Dict[str, Any]]:
    binary = tool_binary("surya")
    if not binary:
        return []
    workdir = os.path.join(workdir, "surya")
    os.makedirs(workdir, exist_ok=True)
    _write_source(workdir, source)
    _rc, out, _err = await run_tool(
        [binary, "graph", "Contract.sol"], cwd=workdir,
        budget_s=budget)
    return parse_surya_graph(out)


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
    label = ("Audit Toolbox (Slither/Slitherin/Aderyn/Mythril/Wake/"
             "Securify/Semgrep/Solhint/SMT/Fuzz/APIs)")
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []  # keyless: Blockscout/Sourcify + public APIs
    description = (
        "Runs the standard auditor toolbox over a contract's "
        "verified source and bytecode: Slither (with Slitherin's "
        "extra detectors when installed) and Aderyn static "
        "analysis, Mythril symbolic execution, Wake detectors, "
        "Securify 2.0 pattern analysis, Semgrep Solidity rules, "
        "Solhint's security ruleset, solc SMTChecker, Heimdall "
        "bytecode disassembly, a Surya call graph, 4byte.directory "
        "selector identification for unverified bytecode, "
        "Echidna/Medusa property fuzzing (prepared harnesses only), "
        "plus GoPlus and Honeypot.is token-risk APIs. Heavy tools "
        "run only in the heavy lane (RECON_HEAVY_LANE / worker "
        "context); absent binaries skip silently - tools live "
        "outside the app image under ~/workspace/tools/audit.")
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
                              "simulation", "title", "function",
                              "contract", "column", "via",
                              "edges", "call_graph_dot",
                              "selector", "signature", "signatures"):
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
                for hit in await _adapt_solhint(
                        workdir, source_text,
                        TOOL_BUDGETS["solhint"]):
                    emit(hit)
                for hit in await _adapt_surya(
                        workdir, source_text,
                        TOOL_BUDGETS["surya"]):
                    emit(hit)
            if token_level:
                for hit in await self._api_hits(ctx, chain, addr):
                    emit(hit)
            if not source_text and code_hex:
                # Bytecode-only target: identify its public
                # functions by selector (4byte.directory) - the
                # semantic layer Heimdall's opcode scan lacks.
                for hit in await self._selector_hits(ctx, code_hex):
                    emit(hit)

            # --- heavy lane -----------------------------------------
            if heavy and source_text:
                for name, adapter in (
                        ("slither", _adapt_slither),
                        ("aderyn", _adapt_aderyn),
                        ("smtchecker", _adapt_smtchecker),
                        ("mythril", _adapt_mythril),
                        ("wake", _adapt_wake),
                        ("securify", _adapt_securify)):
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

    # -- keyless HTTP JSON (shared by the API adapters) ------------------
    async def _get_json(self, ctx: Ctx, url: str, cache_key: str
                        ) -> Dict[str, Any]:
        cache_ns = "toolbox-api"
        try:
            cached = ctx.cache.get(cache_ns, cache_key)
            if isinstance(cached, dict) and cached:
                return cached
        except Exception:
            pass
        try:
            from ..ratelimit import fetch
        except Exception:
            return {}
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

    # -- 4byte.directory selector identification (bytecode-only) ---------
    async def _selector_hits(self, ctx: Ctx, code_hex: str
                             ) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for sel in extract_selectors(code_hex, cap=12):
            data = await self._get_json(
                ctx,
                "https://www.4byte.directory/api/v1/signatures/"
                f"?hex_signature={sel}",
                f"fourbyte:{sel}")
            if data:
                hits.extend(parse_fourbyte(data, sel))
        return hits

    # -- keyless risk APIs ----------------------------------------------
    async def _api_hits(self, ctx: Ctx, chain: cc.ChainConfig,
                        addr: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []

        async def get_json(url: str, cache_key: str) -> Dict[str, Any]:
            return await self._get_json(ctx, url, cache_key)

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
