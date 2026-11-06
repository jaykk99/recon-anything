"""Meta Orchestrator: the industry-standard external engines -
OWASP Amass, ProjectDiscovery Nuclei, and SpiderFoot - wired in as
adapters behind ONE plugin (id "meta_orchestrator"), plus a Maltego
data mapper that turns assets already on the discovery bus into
graph edges.

Why one plugin and not four: the tools share one orchestration
story - translate the run's target into each tool's input form, run
the available tools concurrently under hard budgets, and normalize
every result into the repo finding schema (string value, severity
mapped to low|medium|high, evidence carrying the tool's own fields)
so the attack-path correlation engine consumes them exactly like
native findings. Amass subdomains use the same dns/subdomain key
the native enumerators emit; Nuclei matches carry template id, CVE
(when the template declares one), and severity in evidence.

Architecture (Jay's constraints, 2026-11-02, same as audit_toolbox):

1. FAST vs HEAVY lanes. Amass, Nuclei, and SpiderFoot run for
   seconds to minutes, so this plugin declares lane="heavy" and the
   adapters only execute when the heavy lane is explicitly enabled
   (env RECON_HEAVY_LANE=1, ctx.shared["allow_heavy"], or module
   override meta_orchestrator=heavy). In a quick or bulk scan the
   adapters do NOT run: the plugin returns one info finding naming
   the available tools that were not run, and the (instant, free)
   Maltego bus mapping still runs.
2. NO IMAGE BLOAT. Tools install OUTSIDE the app image under
   ~/workspace/tools/audit/ via scripts/install-audit-tools.sh.
   Adapters detect binaries (audit dir first, then PATH) and skip
   silently when absent - never a crash - so the slim deployed
   backend is completely unaffected.
3. NO SHELL, EVER. Subprocesses are exec-form argument lists
   (asyncio.create_subprocess_exec). The target is validated
   against a strict host grammar before it can become an argument,
   so a target string can never become shell syntax or a tool flag.
4. NO FABRICATED DATA. Every finding comes from a tool's real
   output or from a real asset on the discovery bus. There is no
   mock/sample adapter: a tool that is absent or returns nothing
   produces nothing. (An earlier draft of this plugin shipped a
   SpiderFoot "mock" that emitted a placeholder tracking-id edge
   for every target - invented evidence; removed by design.)
5. MALTEGO IS A MAPPER, NOT A BINARY. Maltego is a commercial GUI
   with no headless CLI to orchestrate. What transfers is its link
   analysis model: assets the run already discovered (subdomains,
   emails) become graph edges (subdomain -> parent domain,
   mailbox -> its domain). Real data only; an empty bus maps to
   zero edges.
6. DETECTION ONLY. Nuclei runs with the dos, intrusive, fuzz, and
   bruteforce template tags excluded and interactsh (OOB) disabled:
   template matching against responses, never exploitation. In
   passive mode only Amass passive enum and the bus mapper run;
   Nuclei and SpiderFoot wait for an active heavy run.

Authorized targets only, per the ReconAnything scope rules.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# ---------------------------------------------------------------------------
# Install layout (outside the app image; see scripts/install-audit-tools.sh)
# ---------------------------------------------------------------------------

AUDIT_DIR = os.environ.get(
    "RECON_AUDIT_TOOLS_DIR",
    os.path.expanduser("~/workspace/tools/audit"))
AUDIT_BIN = os.path.join(AUDIT_DIR, "bin")

# Per-tool subprocess budgets (seconds). All three adapters also
# share the plugin's overall heavy deadline.
TOOL_BUDGETS = {"amass": 600, "nuclei": 900, "spiderfoot": 1200}

# Nuclei template tags that cross from detection into exploitation
# or load generation. Always excluded.
NUCLEI_EXCLUDE_TAGS = "dos,intrusive,fuzz,bruteforce"

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")

_SEVERITY = {
    "critical": "high", "high": "high",
    "medium": "medium", "moderate": "medium",
    "low": "low", "info": "low", "informational": "low",
    "unknown": "low", "none": "low", "": "low",
}


def map_severity(raw: Any) -> str:
    """Map any tool severity string onto low|medium|high."""
    return _SEVERITY.get(str(raw or "").strip().lower(), "low")


# ---------------------------------------------------------------------------
# Target translation: framework target -> per-tool input forms
# ---------------------------------------------------------------------------

def translate_target(target: Target) -> Optional[Dict[str, str]]:
    """Return {"host", "domain", "nuclei"} or None when the target
    cannot be expressed safely as a tool argument.

    host    - bare hostname or IP (Amass/SpiderFoot form)
    domain  - registrable-style parent used for scope checks and
              bus edges ("" for raw IPs)
    nuclei  - the URL/host string Nuclei expects

    Anything outside a strict host grammar (spaces, shell
    metacharacters, leading dashes that a tool would read as flags,
    credentials in URLs) is rejected outright.
    """
    raw = (target.normalized or target.raw or "").strip()
    if not raw or any(c in raw for c in " \t\r\n;|&$`\"'<>\\"):
        return None
    ttype = (target.type or "").lower()
    host = ""
    nuclei = ""
    if ttype == "url" or "://" in raw:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        if parsed.username or parsed.password:
            return None
        host = (parsed.hostname or "").lower()
        if not host:
            return None
        nuclei = raw if "://" in raw else f"https://{raw}"
    else:
        host = raw.lower().rstrip(".")
        nuclei = host
    # IP literal?
    try:
        ip = ipaddress.ip_address(host)
        return {"host": host, "domain": "",
                "nuclei": nuclei, "ip": str(ip)}
    except ValueError:
        pass
    if not _HOST_RE.match(host):
        return None
    if "." not in host and ttype == "ip":
        return None
    return {"host": host, "domain": host, "nuclei": nuclei, "ip": ""}


# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------

def _tool_paths() -> Dict[str, List[str]]:
    return {
        "amass": [os.path.join(AUDIT_BIN, "amass")],
        "nuclei": [os.path.join(AUDIT_BIN, "nuclei")],
        "spiderfoot": [os.path.join(AUDIT_BIN, "spiderfoot"),
                       os.path.join(AUDIT_BIN, "sf.py")],
    }


def tool_binary(name: str) -> Optional[str]:
    """Resolve a tool binary: audit dir first, then PATH.
    None when the tool is not installed here."""
    for cand in _tool_paths().get(name, []):
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which(name) or shutil.which(
        {"spiderfoot": "sf.py"}.get(name, name))


def tool_available(name: str) -> bool:
    return tool_binary(name) is not None


def availability() -> Dict[str, Dict[str, Any]]:
    """{tool: {available, path}} for every adapter tool."""
    out: Dict[str, Dict[str, Any]] = {}
    for name in TOOL_BUDGETS:
        path = tool_binary(name)
        out[name] = {"available": path is not None, "path": path or ""}
    out["maltego_mapper"] = {"available": True, "path": ""}
    return out


async def run_tool(cmd: List[str], cwd: str, budget_s: float
                   ) -> Tuple[int, str, str]:
    """Run a tool as an async subprocess (exec-form, never a shell)
    with a hard budget. Returns (exit_code, stdout, stderr);
    exit_code -1 on timeout, -2 when the binary could not be
    started. Never raises."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
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
# Output parsers (pure functions - unit-tested on fixture outputs)
# ---------------------------------------------------------------------------

def parse_amass(text: str, domain: str) -> List[str]:
    """Amass -json output (one JSON object per line) -> in-scope
    subdomain names, deduped and sorted. Out-of-scope names (Amass
    can wander via related domains) are dropped."""
    dom = (domain or "").lower().rstrip(".")
    found = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except Exception:
            continue
        name = str(data.get("name") or "").lower().rstrip(".")
        if not name or not _HOST_RE.match(name):
            continue
        if dom and not (name == dom or name.endswith("." + dom)):
            continue
        found.add(name)
    return sorted(found)


def parse_nuclei(text: str) -> List[Dict[str, Any]]:
    """Nuclei -jsonl output -> normalized hit dicts."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        tid = str(data.get("template-id") or
                  data.get("templateID") or "unknown")
        info = data.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        matched = str(data.get("matched-at") or data.get("host") or "")
        key = (tid, matched)
        if key in seen:
            continue
        seen.add(key)
        classification = info.get("classification") or {}
        cves: List[str] = []
        if isinstance(classification, dict):
            raw_cve = classification.get("cve-id")
            if isinstance(raw_cve, list):
                cves = [str(c) for c in raw_cve if c]
            elif raw_cve:
                cves = [str(raw_cve)]
        out.append({
            "template_id": tid,
            "name": str(info.get("name") or tid),
            "severity": map_severity(info.get("severity")),
            "description": str(info.get("description") or "").strip(),
            "remediation": str(info.get("remediation") or "").strip(),
            "cves": cves,
            "matcher": str(data.get("matcher-name") or ""),
            "matched_at": matched,
            "type": str(data.get("type") or ""),
        })
    return out


# SpiderFoot event type -> (category, key). Anything not listed is
# context noise for this pipeline and is ignored, not approximated.
_SF_MAP = {
    "INTERNET_NAME": ("dns", "subdomain"),
    "DOMAIN_NAME": ("dns", "subdomain"),
    "EMAILADDR": ("identity", "email"),
    "IP_ADDRESS": ("infra", "ip_address"),
    "TCP_PORT_OPEN": ("infra", "open_port"),
}


def parse_spiderfoot(text: str) -> List[Dict[str, Any]]:
    """SpiderFoot JSON output -> normalized hit dicts.

    Accepts the CLI's JSON array, or JSON-lines of event objects.
    Events are dicts with at least "type" and "data"; anything else
    is skipped. Unknown event types are ignored.
    """
    events: List[Any] = []
    blob = (text or "").strip()
    if not blob:
        return []
    try:
        parsed = json.loads(blob)
        if isinstance(parsed, list):
            events = parsed
    except Exception:
        events = []
    if not events:
        for line in blob.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    events.append(json.loads(line))
                except Exception:
                    continue
    out: List[Dict[str, Any]] = []
    seen = set()
    for ev in events:
        if not isinstance(ev, dict):
            continue
        etype = str(ev.get("type") or "")
        data = str(ev.get("data") or "").strip()
        if etype not in _SF_MAP or not data:
            continue
        if (etype, data) in seen:
            continue
        seen.add((etype, data))
        category, key = _SF_MAP[etype]
        out.append({
            "category": category, "key": key, "value": data,
            "event_type": etype,
            "module": str(ev.get("module") or ""),
            "source_event": str(ev.get("source") or ""),
        })
    return out


def maltego_edges(shared: Dict[str, List[Any]], domain: str
                  ) -> List[Dict[str, str]]:
    """Maltego-style link map over REAL discovery-bus assets.

    Edges: each discovered subdomain -> the target domain
    (resolves_under); each discovered email -> its mailbox domain
    (mailbox_domain). Nothing on the bus means no edges - the
    mapper never invents nodes.
    """
    dom = (domain or "").lower().rstrip(".")
    edges: List[Dict[str, str]] = []
    seen = set()

    def add(a: str, b: str, relation: str) -> None:
        k = (a, b, relation)
        if a and b and a != b and k not in seen:
            seen.add(k)
            edges.append({"from": a, "to": b, "relation": relation})

    if dom:
        for sub in shared.get("subdomains", []) or []:
            name = str(sub).lower().rstrip(".")
            if name.endswith("." + dom):
                add(name, dom, "resolves_under")
    for email in shared.get("emails", []) or []:
        addr = str(email).strip().lower()
        if "@" in addr:
            add(addr, addr.rsplit("@", 1)[1], "mailbox_domain")
    return edges


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class MetaOrchestratorPlugin(Plugin):
    id = "meta_orchestrator"
    label = "Meta Engine (Amass + Nuclei + SpiderFoot + Maltego Mapper)"
    accepts = ["domain", "url", "ip"]
    requires_keys = []  # keyless: local tool binaries only
    passive = False     # wraps active engines (Nuclei/SpiderFoot)
    cost = Cost.FREE
    group = "network"
    description = (
        "Orchestrates the external industry engines behind one "
        "adapter: OWASP Amass passive subdomain enumeration, "
        "ProjectDiscovery Nuclei template matching (detection tags "
        "only - dos/intrusive/fuzz/bruteforce excluded, OOB off), "
        "SpiderFoot OSINT collection, and a Maltego-style link "
        "mapper over the discovery bus. Heavy lane only "
        "(RECON_HEAVY_LANE / worker context); absent binaries skip "
        "silently - tools live outside the app image under "
        "~/workspace/tools/audit.")
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

    # -- adapters --------------------------------------------------------
    async def _run_amass(self, binary: str, domain: str,
                         budget: float) -> List[str]:
        """Amass passive enum. JSON goes to a temp file (Amass has
        no stdout JSON mode); the file is read back and removed."""
        with tempfile.TemporaryDirectory() as td:
            out_path = os.path.join(td, "amass.json")
            cmd = [binary, "enum", "-passive", "-d", domain,
                   "-json", out_path, "-silent"]
            code, _, _ = await run_tool(cmd, td, budget)
            if code == -2 or not os.path.isfile(out_path):
                return []
            try:
                with open(out_path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    return parse_amass(fh.read(), domain)
            except Exception:
                return []

    async def _run_nuclei(self, binary: str, nuclei_target: str,
                          budget: float) -> List[Dict[str, Any]]:
        with tempfile.TemporaryDirectory() as td:
            cmd = [binary, "-u", nuclei_target, "-jsonl", "-silent",
                   "-nc", "-duc", "-no-interactsh",
                   "-timeout", "5", "-retries", "1",
                   "-rate-limit", "50", "-c", "25", "-bulk-size", "25",
                   "-exclude-tags", NUCLEI_EXCLUDE_TAGS]
            _, out, _ = await run_tool(cmd, td, budget)
            return parse_nuclei(out)

    async def _run_spiderfoot(self, binary: str, host: str,
                              budget: float) -> List[Dict[str, Any]]:
        with tempfile.TemporaryDirectory() as td:
            cmd = [binary, "-s", host, "-o", "json", "-q"]
            _, out, _ = await run_tool(cmd, td, budget)
            return parse_spiderfoot(out)

    # -- main ------------------------------------------------------------
    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        forms = translate_target(target)
        if forms is None:
            res = self._skipped(
                "target cannot be expressed as a safe tool "
                "argument (host grammar check failed)")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        seen_f: set = set()

        def add(f: Finding) -> None:
            k = (f.category, f.key, f.value)
            if k not in seen_f:
                seen_f.add(k)
                findings.append(f)

        # Maltego bus mapping runs in every lane: it is instant,
        # free, and only ever maps assets this run really found.
        for edge in maltego_edges(ctx.shared, forms["domain"]):
            add(self._f(
                "graph", "asset_edge",
                f"{edge['from']} -> {edge['to']} "
                f"({edge['relation']})",
                source="maltego_mapper", passive=True, confidence=85,
                evidence={"severity": "low", "from": edge["from"],
                          "to": edge["to"],
                          "relation": edge["relation"],
                          "remediation": "Review this connection "
                                         "for unintended exposure "
                                         "between assets."}))

        avail = availability()
        present = [n for n in TOOL_BUDGETS if avail[n]["available"]]
        heavy = self._heavy_enabled(ctx)
        if not heavy:
            if present:
                add(self._f(
                    "infra", "heavy_lane_not_run",
                    "external engines available but not run in the "
                    f"fast lane: {', '.join(present)}",
                    source="meta_orchestrator", passive=True,
                    confidence=100,
                    evidence={"severity": "low",
                              "tools": present,
                              "remediation": "Re-run in the heavy "
                                             "lane (RECON_HEAVY_LANE=1 "
                                             "or worker context) to "
                                             "execute the external "
                                             "engines."}))
            res = self._ok(
                findings,
                "meta orchestrator: heavy lane off; mapped "
                f"{len(findings)} bus edge(s), engines not run")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        if not present:
            res = self._ok(
                findings,
                "meta orchestrator: no external engine binaries "
                "installed here (see scripts/install-audit-tools.sh)"
                "; bus mapping only")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        try:
            from .. import config as _cfg
            heavy_budget = float(getattr(_cfg, "HEAVY_TIMEOUT_S",
                                         1800))
        except Exception:
            heavy_budget = 1800.0
        deadline = t0 + heavy_budget

        def left(tool: str) -> float:
            return max(1.0, min(TOOL_BUDGETS[tool],
                                deadline - time.monotonic()))

        jobs = {}
        if "amass" in present and forms["domain"]:
            jobs["amass"] = self._run_amass(
                avail["amass"]["path"], forms["domain"], left("amass"))
        if "spiderfoot" in present and ctx.mode == "active":
            jobs["spiderfoot"] = self._run_spiderfoot(
                avail["spiderfoot"]["path"], forms["host"],
                left("spiderfoot"))
        if "nuclei" in present and ctx.mode == "active":
            jobs["nuclei"] = self._run_nuclei(
                avail["nuclei"]["path"], forms["nuclei"],
                left("nuclei"))

        results = await asyncio.gather(*jobs.values(),
                                       return_exceptions=True)
        ran: List[str] = []
        for tool, result in zip(jobs.keys(), results):
            if isinstance(result, Exception):
                continue
            ran.append(tool)
            if tool == "amass":
                for sub in result:  # type: ignore[union-attr]
                    ctx.publish("subdomains", sub)
                    if sub == forms["domain"]:
                        continue
                    add(self._f(
                        "dns", "subdomain", sub, source="amass",
                        passive=True, confidence=85,
                        evidence={"severity": "low", "tool": "amass",
                                  "remediation": "Review this DNS "
                                                 "record. Remove "
                                                 "stale or unclaimed "
                                                 "records (subdomain "
                                                 "takeover risk) and "
                                                 "enable DNSSEC."}))
            elif tool == "spiderfoot":
                for hit in result:  # type: ignore[union-attr]
                    if hit["key"] == "subdomain":
                        ctx.publish("subdomains", hit["value"])
                    elif hit["key"] == "email":
                        ctx.publish("emails", hit["value"])
                    add(self._f(
                        hit["category"], hit["key"], hit["value"],
                        source="spiderfoot",
                        passive=(ctx.mode == "passive"),
                        confidence=75,
                        evidence={"severity": "low",
                                  "tool": "spiderfoot",
                                  "event_type": hit["event_type"],
                                  "module": hit["module"]}))
            elif tool == "nuclei":
                for hit in result:  # type: ignore[union-attr]
                    sev = hit["severity"]
                    value = (f"{sev.upper()}: {hit['name']} "
                             f"[{hit['template_id']}] at "
                             f"{hit['matched_at']}")
                    ev: Dict[str, Any] = {
                        "severity": sev, "tool": "nuclei",
                        "template_id": hit["template_id"],
                        "matcher": hit["matcher"],
                        "description": hit["description"],
                    }
                    if hit["cves"]:
                        ev["cve"] = hit["cves"][0]
                        ev["cves"] = hit["cves"]
                    if hit["remediation"]:
                        ev["remediation"] = hit["remediation"]
                    add(self._f(
                        "web", "nuclei_match", value,
                        source="nuclei",
                        source_url=hit["matched_at"] or None,
                        passive=False,
                        confidence={"high": 90, "medium": 80,
                                    "low": 60}[sev],
                        exploitability=("nuclei" if sev == "high"
                                        else "unknown"),
                        evidence=ev))

        self._checkpoint(findings)
        absent = [n for n in TOOL_BUDGETS if n not in present]
        res = self._ok(
            findings,
            f"meta orchestrator: ran {', '.join(ran) or 'none'}; "
            f"absent here: {', '.join(absent) or 'none'}; "
            f"mode {ctx.mode}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
