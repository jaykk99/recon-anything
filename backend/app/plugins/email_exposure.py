"""Exposed credential hunter (defensive OSINT only).

Finds credentials tied to the target that are ALREADY PUBLIC:

- GitHub code search for the domain + credential keywords (needs
  GITHUB_TOKEN in ctx.keys as "github_token"; without it the plugin
  tries keyless Sourcegraph public code search and emits one-click
  manual dork URLs). Read-only searches, never clones private repos.
- ProxyNova COMB public breach-compilation search (keyless) for emails
  on this domain, with exposed password counts.
- Live probes for exposed config files on the target itself
  (/.env, wp-config backups, .git/config) via the shared probe cache.
  Only flagged when the content actually contains secret-looking values.

Never attempts logins, never brute-forces, never touches anything that
is not already public. Secrets are redacted in the finding value; the
full match sits in evidence["match"] so the owner can verify and rotate.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Dict, List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   safe_json_dict)
from .secretutils import evidence_block, is_placeholder, redact

# GitHub code-search queries (quoted). Rate-limited to a few per run.
GH_QUERIES = [
    '"{d}" password',
    '"{d}" db_password',
    '"{d}" api_key',
    'filename:.env "{d}"',
    '"{d}" smtp_password',
]

# Sourcegraph public code search (keyless, unauthenticated API).
# Best-effort: the streaming API returns event-stream lines; we parse
# the first page of results. If the format changes, we degrade to the
# clickable manual-search finding below.
SOURCEGRAPH_STREAM = ("https://sourcegraph.com/.api/search/stream"
                      "?q=context:global+{q}&v=V3&t=keyword&display=25")
SG_QUERIES = [
    '{d} password',
    '{d} api_key',
    '{d} db_password',
]

# Manual search URLs emitted as clickable findings when no GITHUB_TOKEN
# is configured, so Jay can run the dorks himself in one click.
MANUAL_DORKS = [
    ("GitHub code search",
     'https://github.com/search?q={q}&type=code'),
    ("Sourcegraph public code search",
     'https://sourcegraph.com/search?q=context:global+{q}&patternType=keyword'),
    ("Google paste search",
     'https://www.google.com/search?q=site%3Apastebin.com+%22{d}%22'),
]

# Paste / compilation aggregator (public, no key): ProxyNova COMB API.
# Supports domain queries like @example.com and returns email:password
# lines from the public Collection of Many Breaches.
COMB_URL = "https://api.proxynova.com/comb?query=%40{d}"

# Config paths probed on the target itself (active mode only). Flagged
# only when the body looks like it holds real secrets.
CONFIG_PATHS = [
    "/.env", "/.env.bak", "/.env.old", "/.env.production",
    "/config.php", "/config.php.bak", "/wp-config.php.bak",
    "/.git/config", "/database.yml", "/settings.py.bak",
]

SECRET_HINT = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|db[_-]?pass|smtp[_-]?pass)"
    r"\s*[:=]\s*['\"]?([^'\"\s&;]{4,80})",
    re.M,
)
# Marker that the probe hit a real .env / config, not a 404 page.
ENV_MARKER = re.compile(r"(?i)(APP_KEY=|DB_HOST=|DATABASE_URL=|SECRET_KEY=)")


class EmailExposurePlugin(Plugin):
    id = "email_exposure"
    label = "Exposed Credentials"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "identity"
    description = ("Hunt publicly exposed credentials for the target: "
                   "GitHub code search, paste compilations, exposed "
                   ".env/config files.")
    # Several slow external searches; 90s so it finishes instead of being
    # cut mid-sweep and losing every finding (2026-10-20).
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        # Run the independent external searches concurrently (2026-10-20):
        # sequentially they stacked 20-25s timeouts and the plugin was
        # killed before returning anything. Each writes to its own list
        # and results merge in a fixed order, so findings stay
        # deterministic run to run.
        gh_findings: List[Finding] = []
        comb_findings: List[Finding] = []
        comb_state: List[bool] = []

        async def _comb_wrap() -> None:
            comb_state.append(
                await self._comb_domain(domain, ctx, comb_findings))

        await asyncio.gather(
            self._github_search(domain, ctx, gh_findings), _comb_wrap())
        findings.extend(gh_findings)
        findings.extend(comb_findings)
        comb_ok = comb_state[0] if comb_state else False
        if not passive:
            await self._config_probes(domain, target, ctx, findings)

        # Never silent: if every source came back empty, say what ran and
        # what was missing so a zero is always explained.
        if not findings:
            parts = []
            parts.append("GitHub code search: "
                         + ("keyless Sourcegraph ran" if not ctx.keys.get(
                             "github_token") else "authenticated search ran"))
            parts.append("COMB compilation lookup "
                         + ("ran clean" if comb_ok else "unreachable"))
            if not passive:
                parts.append("exposed-config probes ran clean")
            findings.append(self._f(
                "leak", "exposure_note",
                f"No public credential exposures found for {domain} "
                f"({'; '.join(parts)}).",
                source="exposure sweep", confidence=60, passive=passive,
                evidence=evidence_block("", "exposure_clean", "credential",
                                        "low")))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{len(findings)} public credential exposures for {domain}")
        res.duration_ms = dur
        return res

    async def _github_search(self, domain: str, ctx: Ctx,
                             findings: List[Finding]) -> None:
        token = ctx.keys.get("github_token")
        if not token:
            # No token: try keyless Sourcegraph public code search, and
            # always emit one-click manual dork URLs so the dorks still
            # get run by Jay in his browser.
            sg_hits = await self._sourcegraph_search(domain, ctx, findings)
            links = []
            qtext = GH_QUERIES[0].format(d=domain)
            for label, tpl in MANUAL_DORKS:
                links.append(
                    (label, tpl.format(q=quote(qtext),
                                       d=quote(domain, safe=""))))
            link_lines = "\n".join(f"- {label}: {url}" for label, url in links)
            value = ("Keyless credential dorking (no GITHUB_TOKEN): "
                     f"Sourcegraph public search returned {sg_hits} hits. "
                     f"Run these dorks manually:\n{link_lines}\n"
                     "Add GITHUB_TOKEN in Keys for automatic API code search.")
            ev = evidence_block(link_lines, "keyless_dork_links",
                                "credential", "medium",
                                {"sourcegraph_hits": sg_hits,
                                 "links": [u for _, u in links]})
            findings.append(self._f(
                "leak", "github_manual_dorks", value,
                source="keyless code-search fallbacks",
                source_url=links[0][1] if links else None,
                confidence=55, passive=True, evidence=ev))
            return
        for q in GH_QUERIES:
            url = ("https://api.github.com/search/code?q="
                   + quote(q.format(d=domain)) + "&per_page=10")
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25,
                                headers={"Authorization": f"Bearer {token}",
                                         "Accept": "application/vnd.github+json"})
            except Exception as e:
                findings.append(self._f(
                    "leak", "github_note",
                    f"GitHub search error: {str(e)[:120]}",
                    source="GitHub", confidence=40, passive=True,
                    evidence=evidence_block("", "gh_error", "credential", "low")))
                return
            if r.status_code in (401, 403):
                findings.append(self._f(
                    "leak", "github_note",
                    f"GitHub API rejected the token (HTTP {r.status_code})",
                    source="GitHub", confidence=50, passive=True,
                    evidence=evidence_block("", "gh_auth", "credential", "low")))
                return
            if r.status_code != 200:
                continue
            jd = safe_json_dict(r)
            items = jd.get("items", [])
            if not isinstance(items, list):
                continue
            for it in items:
                if not isinstance(it, dict):
                    continue
                repo_obj = it.get("repository")
                repo = (repo_obj.get("full_name", "?")
                        if isinstance(repo_obj, dict) else "?")
                path = it.get("path", "?")
                value = (f"Public code hit for credential query "
                         f"'{q.format(d=domain)}': {repo}/{path}")
                ev = evidence_block(path, "gh_credential_dork", "credential",
                                    "high",
                                    {"repo": repo, "query": q.format(d=domain)})
                findings.append(self._f(
                    "leak", "github_credential_hit", value,
                    source="GitHub code search",
                    source_url=it.get("html_url"), confidence=70,
                    passive=True, evidence=ev))
            # GitHub code search: 10 req/min authenticated. Stop if the
            # bucket is empty so we never burn the whole budget.
            if r.headers.get("x-ratelimit-remaining") == "0":
                findings.append(self._f(
                    "leak", "github_note",
                    "GitHub code-search rate limit reached; "
                    "remaining queries skipped",
                    source="GitHub", confidence=40, passive=True,
                    evidence=evidence_block("", "gh_429", "credential",
                                            "low")))
                break

    async def _sourcegraph_search(self, domain: str, ctx: Ctx,
                                  findings: List[Finding]) -> int:
        """Keyless Sourcegraph public code search (best-effort). Returns
        the number of hits appended. Any failure (network, format change,
        non-200) silently returns 0; the manual-dork finding covers it."""
        total = 0
        # Fetch all queries concurrently (was sequential: 3 x 20s timeouts
        # stacked past the plugin timeout and everything was lost), then
        # parse in query order so output is deterministic.
        async def _sg_fetch(q: str):
            url = SOURCEGRAPH_STREAM.format(q=quote(q.format(d=domain)))
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                timeout=20,
                                headers={"Accept": "text/event-stream",
                                         "User-Agent": "ReconAnything/1.0"})
            except Exception:
                return None
            if r.status_code != 200:
                return None
            try:
                return r.text
            except Exception:
                return None

        sg_texts = await asyncio.gather(
            *[_sg_fetch(q) for q in SG_QUERIES])
        for q, text in zip(SG_QUERIES, sg_texts):
            qtext = q.format(d=domain)
            if text is None:
                continue
            # Event-stream format: lines starting with "data: {json}".
            for line in text.splitlines()[:400]:
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if not payload or payload == "[DONE]":
                    continue
                try:
                    obj = json.loads(payload)
                except Exception:
                    continue
                # Sourcegraph stream events arrive as a JSON LIST of
                # event objects, not a single dict - the old obj.get()
                # crashed with "'list' object has no attribute 'get'"
                # and errored the whole plugin (fixed 2026-10-20).
                events = obj if isinstance(obj, list) else [obj]
                results = []
                for ev_obj in events:
                    if isinstance(ev_obj, dict):
                        r = ev_obj.get("results")
                        if isinstance(r, list):
                            results.extend(r)
                if not results:
                    continue
                for item in results[:25]:
                    if not isinstance(item, dict):
                        continue
                    repo = str(item.get("repository") or
                               item.get("repo") or "?")
                    fobj = item.get("file")
                    path = str(fobj.get("path") if isinstance(fobj, dict)
                               else item.get("path") or "?")
                    if total >= 20:
                        break
                    total += 1
                    value = (f"Public code hit for '{qtext}': "
                             f"{repo}/{path}")
                    ev = evidence_block(
                        path, "sourcegraph_credential_dork", "credential",
                        "medium", {"repo": repo, "query": qtext})
                    findings.append(self._f(
                        "leak", "sourcegraph_credential_hit", value,
                        source="Sourcegraph public code search (keyless)",
                        confidence=60, passive=True, evidence=ev))
            if total >= 20:
                break
        return total

    async def _comb_domain(self, domain: str, ctx: Ctx,
                           findings: List[Finding]) -> bool:
        """Public COMB compilation lookup for the whole domain (keyless).
        Returns True when the API answered (even with zero hits); False
        when unreachable. Never fails the plugin."""
        url = COMB_URL.format(d=quote(domain, safe=""))
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25,
                            headers={"User-Agent": "ReconAnything/1.0"})
        except Exception:
            return False
        if r.status_code != 200:
            return False
        jd = safe_json_dict(r)
        lines = jd.get("lines")
        if not isinstance(lines, list):
            return False
        try:
            count = int(jd.get("count", 0) or 0)
        except (ValueError, TypeError):
            count = 0
        emails = set()
        for line in lines[:200]:
            if not isinstance(line, str) or ":" not in line:
                continue
            addr, _, _pw = line.partition(":")
            addr = addr.strip().lower()
            if "@" in addr and addr.endswith("@" + domain):
                emails.add(addr)
        if emails:
            sample = ", ".join(redact(e, 3) for e in sorted(emails)[:8])
            value = (f"HIGH: {len(emails)} addresses on {domain} appear in "
                     f"the public COMB breach compilation "
                     f"({count:,}+ password pairs total). Samples: "
                     f"{sample}")
            ev = evidence_block(sample, "comb_domain_exposure",
                                "credential", "high",
                                {"domain": domain,
                                 "email_count": len(emails),
                                 "password_pairs": count,
                                 "verify_url": url,
                                 "action": ("Force password resets for "
                                            "every address on this domain.")})
            findings.append(self._f(
                "leak", "compilation_exposure", value,
                source="ProxyNova COMB (keyless public breach data)",
                source_url=url, confidence=80, passive=True, evidence=ev))
        return True

    async def _config_probes(self, domain: str, target: Target, ctx: Ctx,
                             findings: List[Finding]) -> None:
        base = (await web_base(ctx, target, domain)).rstrip("/")
        # Parallel probes (same pattern as backup/artifacts/hiddenpaths):
        # sequential probing makes an unreachable target burn the whole
        # plugin timeout and discards the findings gathered earlier.
        sem = asyncio.Semaphore(6)

        async def check(path: str):
            url = base + path
            try:
                async with sem:
                    data = await ctx.probe(url, timeout=8)
            except Exception:
                return None
            if data.get("status") != 200:
                return None
            body = data.get("text", "")
            if len(body) < 20:
                return None
            if not ENV_MARKER.search(body):
                return None
            secrets: Dict[str, str] = {}
            for m in SECRET_HINT.finditer(body):
                name, val = m.group(1).lower(), m.group(2)
                if is_placeholder(val) or len(val) < 4:
                    continue
                secrets[name] = redact(val)
            if not secrets and "APP_KEY" not in body and "SECRET_KEY" not in body:
                return None
            return path, url, body, secrets

        for result in await asyncio.gather(*[check(p) for p in CONFIG_PATHS]):
            if not result:
                continue
            path, url, body, secrets = result
            detail = ", ".join(f"{k}={v}" for k, v in list(secrets.items())[:5])
            value = (f"HIGH: exposed config file {path} on {domain} "
                     f"contains secrets ({detail or 'secret markers'})")
            ev = evidence_block(detail or path, "exposed_config", "credential",
                                "high", {"path": path, "url": url})
            findings.append(self._f(
                "leak", "exposed_config", value, source="config probe",
                source_url=url, confidence=90, passive=False, evidence=ev))
