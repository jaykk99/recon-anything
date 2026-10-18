"""Dependency confusion detection plugin.

Looks for exposed dependency manifests (package.json, requirements.txt,
Gemfile, composer.json, go.mod), parses dependency names, and flags
internal-looking package names against the public registries. Detection
only: nothing is ever published, installed, or modified. Registry checks
are read-only existence lookups (npm / PyPI), capped and cached.
"""
from __future__ import annotations

import json
import re
import time
from typing import Dict, List, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MANIFESTS = {
    "/package.json": "npm",
    "/package-lock.json": "npm",
    "/requirements.txt": "pypi",
    "/Gemfile": "gem",
    "/composer.json": "composer",
    "/go.mod": "go",
}

INTERNAL_HINTS = ("internal", "private", "corp", "inhouse", "proprietary",
                  "secret", "confidential")


def _looks_internal(name: str) -> bool:
    n = name.lower()
    if n.startswith("@") and "/" in n:  # org-scoped: usually private
        return True
    return any(h in n for h in INTERNAL_HINTS)


def _parse_npm(text: str) -> List[str]:
    names: List[str] = []
    try:
        data = json.loads(text)
        for section in ("dependencies", "devDependencies",
                        "peerDependencies", "optionalDependencies"):
            deps = data.get(section)
            if isinstance(deps, dict):
                names.extend(deps.keys())
        return names
    except Exception:
        pass
    # regex fallback on dep blocks
    for section in ("dependencies", "devDependencies"):
        m = re.search(rf'"{section}"\s*:\s*\{{(.*?)\}}', text, re.S)
        if m:
            names.extend(re.findall(r'"(@?[\w.\-]+(?:/[\w.\-]+)?)"\s*:', m.group(1)))
    return names


def _parse_pypi(text: str) -> List[str]:
    names: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)", line)
        if m:
            names.append(m.group(1))
    return names


def _parse_gem(text: str) -> List[str]:
    return re.findall(r"""gem\s+['"]([\w.\-]+)['"]""", text)


def _parse_composer(text: str) -> List[str]:
    try:
        data = json.loads(text)
        req = data.get("require", {})
        reqd = data.get("require-dev", {})
        out = []
        if isinstance(req, dict):
            out.extend(k for k in req.keys() if "/" in k)
        if isinstance(reqd, dict):
            out.extend(k for k in reqd.keys() if "/" in k)
        return out
    except Exception:
        return []


def _parse_go(text: str) -> List[str]:
    names: List[str] = []
    in_require = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_require = True
            continue
        if in_require and s == ")":
            in_require = False
            continue
        if in_require or s.startswith("require "):
            m = re.match(r"(?:require\s+)?([\w.\-/]+)\s+v", s)
            if m:
                names.append(m.group(1))
    return names

PARSERS = {"npm": _parse_npm, "pypi": _parse_pypi, "gem": _parse_gem,
           "composer": _parse_composer, "go": _parse_go}


class DependencyConfPlugin(Plugin):
    id = "dependency_conf"
    label = "Dependency Confusion Detector"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Finds exposed dependency manifests and flags "
                   "internal-looking packages against public registries.")
    phase = 2

    async def _registry_exists(self, ctx: Ctx, eco: str, name: str,
                               cache: Dict[str, bool]) -> bool | None:
        """Read-only public-registry existence check. None = unknown."""
        key = f"{eco}:{name}"
        if key in cache:
            return cache[key]
        url = None
        if eco == "npm":
            url = f"https://registry.npmjs.org/{name}"
        elif eco == "pypi":
            url = f"https://pypi.org/pypi/{name}/json"
        if not url:
            return None
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=8,
                            max_retries=1, follow_redirects=False)
            exists = r.status_code == 200
            cache[key] = exists
            return exists
        except Exception:
            return None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")

        findings: List[Finding] = []
        reg_cache: Dict[str, bool] = {}
        lookups = 0
        MAX_LOOKUPS = 30
        MAX_FLAGS = 20

        for path, eco in MANIFESTS.items():
            url = base + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10,
                                max_retries=1, follow_redirects=True)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            try:
                text = r.text[:200000]
            except Exception:
                continue
            if len(text.strip()) < 10:
                continue

            names = PARSERS[eco](text)
            if not names:
                continue
            findings.append(self._f(
                "web", "manifest_exposed",
                f"Dependency manifest publicly accessible: {path} "
                f"({len(names)} {eco} dependencies listed) - leaks internal "
                "package names and versions",
                source="Dependency confusion detector", source_url=url,
                confidence=90, passive=True,
                evidence={"severity": "medium", "exploitability": "theoretical",
                          "remediation": f"Remove {path} from the public web "
                          "root; manifests belong in source control, not on "
                          "the web server."}))

            for name in names:
                if len(findings) >= MAX_FLAGS or lookups >= MAX_LOOKUPS:
                    break
                if not _looks_internal(name):
                    continue
                exists = None
                if eco in ("npm", "pypi"):
                    exists = await self._registry_exists(ctx, eco, name, reg_cache)
                    lookups += 1
                if exists is False:
                    findings.append(self._f(
                        "web", "depconfusion_candidate",
                        f"Dependency confusion candidate: internal-looking "
                        f"package '{name}' ({eco}) in {path} is NOT on the "
                        "public registry - an attacker can publish it "
                        "publicly with a higher version and hijack installs",
                        source="Dependency confusion detector",
                        source_url=url,
                        confidence=75, passive=True,
                        evidence={"severity": "high",
                                  "exploitability": "public_poc",
                                  "remediation": "Reserve the name on the "
                                  "public registry (publish a placeholder or "
                                  "claim the namespace), pin the internal "
                                  "registry as the sole source for this "
                                  "package, and scope installs to it."}))
                elif exists is True:
                    findings.append(self._f(
                        "web", "depconfusion_public",
                        f"Internal-looking package '{name}' ({eco}) in {path} "
                        "EXISTS on the public registry - verify it is yours; "
                        "a public package with an internal name is a classic "
                        "confusion/compromise vector",
                        source="Dependency confusion detector",
                        source_url=url,
                        confidence=70, passive=True,
                        evidence={"severity": "medium",
                                  "exploitability": "theoretical",
                                  "remediation": "Confirm the public package "
                                  "is published by your org; if not, treat it "
                                  "as hostile, pin to your internal registry, "
                                  "and audit what was installed."}))
                else:
                    findings.append(self._f(
                        "web", "depconfusion_unchecked",
                        f"Internal-looking package '{name}' ({eco}) in {path} "
                        "- public registry unreachable, could not verify "
                        "whether the name is claimable",
                        source="Dependency confusion detector",
                        source_url=url,
                        confidence=55, passive=True,
                        evidence={"severity": "low",
                                  "exploitability": "unknown",
                                  "remediation": "Manually check whether this "
                                  "package name exists on the public "
                                  "registry and reserve it if not."}))

        if not findings:
            findings.append(self._f(
                "web", "depconfusion_clean",
                "No exposed dependency manifests found (package.json, "
                "requirements.txt, Gemfile, composer.json, go.mod)",
                source="Dependency confusion detector", source_url=base,
                confidence=70, passive=True,
                evidence={"severity": "low", "exploitability": "unknown",
                          "remediation": "No action needed."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"probed {len(MANIFESTS)} manifests, "
                                 f"{lookups} registry lookups")
        res.duration_ms = dur
        return res
