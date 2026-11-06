"""Cent: nuclei-template pack manager / linter (Tier-4 Vuln/CVE).

Cent's job in the nuclei ecosystem is herding community templates:
validating their structure, counting them by severity and tag, and
surfacing the broken ones before they silently never fire. This
plugin does exactly that for a templates directory:

  * directory source: $CENT_TEMPLATES_DIR (or $NUCLEI_TEMPLATES_DIR)
    when set and present; otherwise the bundled starter set below
    (validated through the identical code path).
  * every *.yaml / *.yml file is parsed and linted for the required
    nuclei template structure: id, info.name, info.severity in the
    known set, and at least one request block with a matcher.
  * malformed templates are findings (they are real defects: a broken
    template is a detection that will never happen).
  * the inventory (counts by severity/tag, malformed count) is
    reported in the result reason.

Read-only: it never writes to the templates directory.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Dict, List, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}

# Bundled starter set: (filename, yaml text). Two are intentionally
# well-formed; the set is the fallback when no directory is configured.
BUNDLED: List[Tuple[str, str]] = [
    ("starter-server-version.yaml", """\
id: starter-server-version
info:
  name: Server version disclosure
  severity: low
  tags: [exposure, generic]
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers:
      - type: regex
        part: header
        regex: ["Server: .*\\\\d+\\\\.\\\\d+"]
"""),
    ("starter-git-head.yaml", """\
id: starter-git-head
info:
  name: Exposed .git/HEAD
  severity: high
  tags: [exposure, git]
http:
  - method: GET
    path: ["{{BaseURL}}/.git/HEAD"]
    matchers:
      - type: word
        words: ["ref: refs/"]
"""),
    ("starter-actuator.yaml", """\
id: starter-actuator
info:
  name: Spring actuator health
  severity: medium
  tags: [exposure, spring]
requests:
  - method: GET
    path: ["{{BaseURL}}/actuator/health"]
    matchers:
      - type: status
        status: [200]
"""),
]


def lint_template(name: str, text: str) -> List[str]:
    """Structural lint of one template; [] means well-formed."""
    problems: List[str] = []
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
    except Exception as e:  # unparseable YAML
        return [f"YAML parse error: {type(e).__name__}"]
    if not isinstance(data, dict):
        return ["template is not a YAML mapping"]
    if not data.get("id"):
        problems.append("missing id")
    info = data.get("info")
    if not isinstance(info, dict):
        problems.append("missing info block")
    else:
        if not info.get("name"):
            problems.append("missing info.name")
        sev = str(info.get("severity", "")).lower()
        if sev not in SEVERITIES:
            problems.append(f"invalid info.severity: {sev!r}")
    blocks = data.get("http") or data.get("requests") or []
    if not isinstance(blocks, list) or not blocks:
        problems.append("no http/requests block")
    else:
        has_matcher = any(
            isinstance(b, dict) and b.get("matchers") for b in blocks)
        if not has_matcher:
            problems.append("no matchers in any request block")
    return problems


def template_stats(name: str, text: str) -> Dict:
    """(severity, tags) for inventory counting; tolerant of defects."""
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        info = (data or {}).get("info") or {}
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        return {"severity": str(info.get("severity", "unknown")).lower(),
                "tags": [str(t) for t in tags]}
    except Exception:
        return {"severity": "unknown", "tags": []}


def collect_templates() -> List[Tuple[str, str]]:
    """Directory templates when configured, else the bundled set."""
    for env in ("CENT_TEMPLATES_DIR", "NUCLEI_TEMPLATES_DIR"):
        d = os.environ.get(env)
        if d and Path(d).is_dir():
            out = []
            for p in sorted(Path(d).rglob("*.y*ml")):
                try:
                    out.append((str(p), p.read_text(errors="replace")))
                except Exception:
                    continue
            if out:
                return out
    return list(BUNDLED)


class CentTemplatesPlugin(Plugin):
    id = "cent_templates"
    label = "Cent Template Manager"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Cent-style nuclei template pack manager: lints "
                   "template YAML structure, inventories templates by "
                   "severity/tag, reports malformed templates that "
                   "would never fire.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        templates = collect_templates()
        findings: List[Finding] = []
        by_sev: Dict[str, int] = {}
        by_tag: Dict[str, int] = {}
        malformed = 0
        for name, text in templates:
            stats = template_stats(name, text)
            by_sev[stats["severity"]] = by_sev.get(stats["severity"], 0) + 1
            for tag in stats["tags"]:
                by_tag[tag] = by_tag.get(tag, 0) + 1
            problems = lint_template(name, text)
            if problems:
                malformed += 1
                findings.append(self._f(
                    "web", "cent_malformed_template",
                    f"Malformed nuclei template {name}: "
                    + "; ".join(problems),
                    source="cent template lint", confidence=95,
                    passive=True,
                    evidence={"severity": "low", "template": name,
                              "problems": problems,
                              "remediation": (
                                  "Fix the template structure (id, "
                                  "info.name, valid info.severity, a "
                                  "request block with matchers) - until "
                                  "then this detection never fires.")}))
        sev_s = ", ".join(f"{k}:{v}" for k, v in sorted(by_sev.items()))
        tag_s = ", ".join(f"{k}:{v}" for k, v in
                          sorted(by_tag.items(), key=lambda kv: -kv[1])[:8])
        return PluginResult(
            plugin_id=self.id, status="ok", findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=(f"cent inventory: {len(templates)} templates "
                    f"({sev_s}); tags [{tag_s}]; "
                    f"{malformed} malformed"))
