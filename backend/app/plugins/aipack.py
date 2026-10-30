"""AI-crawler surface pack (ai_*): read the target's AI-facing files.

Until this pack, the scanner knew nothing about the surface sites now
publish FOR AI crawlers and training-data miners:

Already existed (checked, not rebuilt):
- robots.py parses robots.txt for sitemap URLs and hidden paths; it
  never inventories which AI crawlers (GPTBot, ClaudeBot, CCBot ...)
  are allowed or blocked, and never reads the TDM reservation lines.
- well_known_audit.py fetches /.well-known/ files (security.txt,
  assetlinks, gpc.json); it never touches /.well-known/tdmrep.json.
- Nothing anywhere fetched /llms.txt or /llms-full.txt (the 2025
  llms.txt proposal: a markdown index of a site's content, written
  for LLM crawlers), followed the markdown links inside it, or
  mined the linked .md docs - even though llms.txt routinely points
  at internal guides, staging docs and API references that the
  homepage never links.

This pack (5 detectors, one shared discovery pass per run):
- ai_llms_index       - /llms.txt + /llms-full.txt presence; every
                        same-origin markdown link feeds the hunter
                        bus ("endpoints"); links to sensitive-looking
                        paths (admin / internal / staging / private)
                        become findings; external links are
                        reported, never fetched.
- ai_llms_secrets     - gitleaks RULES (same engine as the JS/XML
                        scanners) over llms.txt, llms-full.txt and
                        the same-origin .md docs it links to, all
                        masked + SHA-256 fingerprinted.
- ai_robots_ai        - robots.txt inventory of known AI-crawler
                        user-agents: which bots are allowed, which
                        are blocked, which are partially restricted.
- ai_llms_conflict    - llms.txt links that robots.txt Disallow
                        covers: the site invites AI crawlers into
                        paths its own robots file tells crawlers
                        to stay out of.
- ai_tdm              - W3C TDM Reservation Protocol: robots.txt
                        tdm-reservation / tdm-policy lines plus
                        /.well-known/tdmrep.json when present.

SAFETY: detection only, passive GETs of the target's own public
files. No AI crawler is impersonated, no training-opt-out is
bypassed, no external host linked from llms.txt is ever fetched,
and no full secret ever reaches a Finding (masked + fingerprint).
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .gitleaks_scan import RULES as _GIT_RULES
from .secretutils import is_placeholder

AI_IDS: List[str] = [
    "ai_llms_index",
    "ai_llms_secrets",
    "ai_robots_ai",
    "ai_llms_conflict",
    "ai_tdm",
]

_REMEDIATION = (
    "Review what the AI-facing files expose, remove internal or "
    "sensitive paths from llms.txt, and make robots.txt, llms.txt "
    "and the TDM reservation agree with each other. Detection only: "
    "nothing found was used.")

_MAX_FILE_BYTES = 500_000
_MAX_MD_DOCS = 10
_MAX_MD_BYTES = 200_000

# Known AI crawlers / training-data miners, by user-agent token.
# Matching is case-insensitive substring on the robots.txt agent line.
AI_BOTS = (
    "GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot",
    "anthropic-ai", "Claude-Web", "CCBot", "PerplexityBot",
    "Perplexity-User", "Google-Extended", "Applebot-Extended",
    "Meta-ExternalAgent", "Meta-ExternalFetcher", "Bytespider",
    "Amazonbot", "cohere-ai", "YouBot", "DuckAssistBot",
    "MistralAI-User", "FacebookBot", "Applebot",
)

_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(admin|internal|staging|private|intranet|wp-admin|"
    r"dashboard|config|credentials|secret|backup|\.env|"
    r"api[-_]?key|token|password|devops|ops/|staff|employee)")

_MD_LINK_RE = re.compile(
    r"\[[^\]]*\]\(\s*([^)\s]+)\s*\)"
    r"|^\s*[-*]\s+(https?://[^\s]+)"
    r"|^\s*https?://[^\s]+\.md(?:\?[^\s]*)?\s*$",
    re.MULTILINE)
_BARE_MD_RE = re.compile(r"^\s*(/[^\s]+\.md(?:\?[^\s]*)?)\s*$",
                         re.MULTILINE)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(
        (value or "").encode("utf-8", "ignore")).hexdigest()


def _host_of(target: Target) -> Optional[str]:
    if target.type == "url":
        return urlparse(target.normalized).hostname
    return domain_from_target(target.type, target.normalized)


async def _origin(ctx: Ctx, target: Target) -> Optional[str]:
    if target.type == "url":
        p = urlparse(target.normalized)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
        return target.normalized.rstrip("/")
    domain = domain_from_target(target.type, target.normalized)
    if not domain:
        return None
    return (await web_base(ctx, target, domain)).rstrip("/")


def _looks_text(text: str, url: str) -> bool:
    """A 200 on an AI-file path is often an SPA fallback page."""
    head = (text or "")[:2000].lstrip("\ufeff \t\r\n")
    if "<html" in head[:600].lower():
        return False
    if head.startswith("<"):
        return False
    return bool((text or "").strip())


async def _fetch_text(ctx: Ctx, url: str, cap: int) -> Optional[Dict[str, Any]]:
    try:
        page = await ctx.fetch_page(url, timeout=12)
    except Exception:
        return None
    if not page:
        return None
    try:
        if (page.get("status_code") or 0) != 200:
            return None
        text = page.get("text") or ""
        final = page.get("url") or url
    except Exception:
        return None
    if not _looks_text(text, final):
        return None
    return {"url": final, "text": text[:cap]}


def parse_robots_groups(text: str) -> List[Dict[str, Any]]:
    """robots.txt -> [{agents: [...], disallow: [...], allow: [...],
    tdm_reservation, tdm_policy}]. Never raises."""
    groups: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    tdm_reservation: Optional[str] = None
    tdm_policy: Optional[str] = None
    try:
        for raw in (text or "").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key == "user-agent":
                if cur is None or cur.get("has_rules"):
                    cur = {"agents": [], "disallow": [], "allow": [],
                           "has_rules": False}
                    groups.append(cur)
                cur["agents"].append(val)
            elif key == "disallow" and cur is not None:
                cur["disallow"].append(val)
                cur["has_rules"] = True
            elif key == "allow" and cur is not None:
                cur["allow"].append(val)
                cur["has_rules"] = True
            elif key == "tdm-reservation":
                tdm_reservation = val
            elif key == "tdm-policy":
                tdm_policy = val
    except Exception:
        return []
    out = groups
    # Stash TDM lines on the first group for convenience; the ai_tdm
    # detector reads them from the shared discovery dict instead.
    if out and (tdm_reservation is not None or tdm_policy is not None):
        out[0]["tdm_reservation"] = tdm_reservation
        out[0]["tdm_policy"] = tdm_policy
    return out


def parse_llms_links(text: str, origin: str) -> List[Dict[str, Any]]:
    """Markdown links + bare .md paths in llms.txt, resolved.

    Returns [{url, same_origin, raw}]. Never raises, dedupes."""
    links: List[Dict[str, Any]] = []
    seen = set()
    origin_host = urlparse(origin).hostname or ""

    def add(raw: str) -> None:
        raw = (raw or "").strip().strip("<>")
        if not raw or raw.startswith(("#", "mailto:")):
            return
        try:
            url = urljoin(origin + "/", raw)
        except Exception:
            return
        if url in seen:
            return
        seen.add(url)
        links.append({"url": url,
                      "same_origin": (urlparse(url).hostname or "")
                      == origin_host,
                      "raw": raw})

    for m in _MD_LINK_RE.finditer(text or ""):
        add(m.group(1) or m.group(2) or "")
    for m in _BARE_MD_RE.finditer(text or ""):
        add(m.group(1))
    return links


def disallowed_by_robots(path: str, groups: List[Dict[str, Any]],
                         bot: Optional[str] = None) -> bool:
    """True if `path` is Disallow-covered for * (or for `bot`).

    Longest-match wins; an Allow that is at least as long as the
    matching Disallow re-allows the path (robots.txt semantics)."""
    best_dis = -1
    best_allow = -1
    for g in groups:
        agents = [a.lower() for a in g.get("agents", [])]
        applies = ("*" in agents) or (
            bot and any(bot.lower() in a for a in agents))
        if not applies:
            continue
        for d in g.get("disallow", []):
            if d and path.startswith(d) and len(d) > best_dis:
                best_dis = len(d)
        for a in g.get("allow", []):
            if a and path.startswith(a) and len(a) > best_allow:
                best_allow = len(a)
    return best_dis >= 0 and best_allow < best_dis


async def discover_ai_docs(ctx: Ctx, target: Target) -> Dict[str, Any]:
    """One shared pass: llms.txt, llms-full.txt, robots.txt, tdmrep.

    Cached on ctx.shared so all five detectors share the fetches."""
    cached = ctx.shared.get("_ai_docs_v1")
    if isinstance(cached, dict):
        return cached
    docs: Dict[str, Any] = {"llms": None, "llms_full": None,
                            "robots": None, "tdmrep": None,
                            "origin": None, "robots_groups": []}
    origin = await _origin(ctx, target)
    docs["origin"] = origin
    if origin:
        docs["llms"] = await _fetch_text(ctx, origin + "/llms.txt",
                                        _MAX_FILE_BYTES)
        docs["llms_full"] = await _fetch_text(
            ctx, origin + "/llms-full.txt", _MAX_FILE_BYTES)
        robots = await _fetch_text(ctx, origin + "/robots.txt",
                                   _MAX_FILE_BYTES)
        docs["robots"] = robots
        if robots:
            docs["robots_groups"] = parse_robots_groups(robots["text"])
        docs["tdmrep"] = await _fetch_text(
            ctx, origin + "/.well-known/tdmrep.json", _MAX_FILE_BYTES)
        if docs["llms"]:
            docs["llms_links"] = parse_llms_links(
                docs["llms"]["text"], origin)
        else:
            docs["llms_links"] = []
    ctx.shared["_ai_docs_v1"] = docs
    return docs


class _AiPlugin(Plugin):
    """Base for the pack: web group, domain/url, passive, never raises."""
    id = ""
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            res = await self.check(target, ctx)
        except Exception as e:  # noqa: BLE001 - degrade, never throw
            res = self._ok([], f"{self.id}: check could not complete "
                               f"({type(e).__name__})")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        raise NotImplementedError

    def ai_finding(self, category: str, key: str, value: str,
                   source_url: Optional[str], severity: str,
                   remediation: str = _REMEDIATION,
                   confidence: int = 85, **evidence) -> Finding:
        ev = {"severity": severity, "detector": self.id,
              "remediation": remediation}
        ev.update(evidence)
        return self._f(category, key, value,
                       source="ai-crawler surface pack",
                       source_url=source_url, confidence=confidence,
                       passive=True, evidence=ev)


# ---------------------------------------------------------------------------
# ai_llms_index
# ---------------------------------------------------------------------------

class AiLlmsIndex(_AiPlugin):
    id = "ai_llms_index"
    label = "llms.txt Index & Link Map"
    description = ("Read /llms.txt and /llms-full.txt, feed their "
                   "same-origin links to the hunters, and flag links "
                   "to sensitive-looking paths.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        docs = await discover_ai_docs(ctx, target)
        if not docs.get("llms") and not docs.get("llms_full"):
            return self._ok([], "no llms.txt or llms-full.txt found")
        findings: List[Finding] = []
        seen = set()
        published = 0
        if docs.get("llms"):
            llms = docs["llms"]
            links = docs.get("llms_links", [])
            findings.append(self.ai_finding(
                "web", "ai_llms_present",
                f"llms.txt present ({len(llms['text'])} bytes, "
                f"{len(links)} links) - AI crawlers are handed a "
                f"content index for this site",
                llms["url"], "low"))
            for link in links:
                url = link["url"]
                if link["same_origin"] and published < 300:
                    ctx.publish("endpoints", url)
                    published += 1
                path = urlparse(url).path
                if _SENSITIVE_PATH_RE.search(path):
                    key = (url, "sensitive")
                    if key not in seen:
                        seen.add(key)
                        findings.append(self.ai_finding(
                            "web", "ai_llms_sensitive_link",
                            f"llms.txt links a sensitive-looking path: "
                            f"{path}",
                            llms["url"], "medium",
                            linked_url=url))
                if not link["same_origin"]:
                    key = (url, "external")
                    if key not in seen:
                        seen.add(key)
                        findings.append(self.ai_finding(
                            "web", "ai_llms_external_link",
                            f"llms.txt links an external host "
                            f"({urlparse(url).hostname}) - not fetched, "
                            f"reported only",
                            llms["url"], "low",
                            linked_url=url))
        if docs.get("llms_full"):
            full = docs["llms_full"]
            findings.append(self.ai_finding(
                "web", "ai_llms_full_present",
                f"llms-full.txt present ({len(full['text'])} bytes) - "
                f"the full site content in one AI-readable file",
                full["url"], "low"))
        return self._ok(findings,
                        f"llms index mapped, {published} links fed "
                        f"to hunters")


# ---------------------------------------------------------------------------
# ai_llms_secrets
# ---------------------------------------------------------------------------

class AiLlmsSecrets(_AiPlugin):
    id = "ai_llms_secrets"
    label = "llms.txt & Linked Docs Secret Miner"
    description = ("Mine llms.txt, llms-full.txt and the same-origin "
                   ".md docs they link for credentials and secrets, "
                   "masked + fingerprinted.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        docs = await discover_ai_docs(ctx, target)
        texts: List[Tuple[str, str]] = []
        if docs.get("llms"):
            texts.append((docs["llms"]["url"], docs["llms"]["text"]))
        if docs.get("llms_full"):
            texts.append((docs["llms_full"]["url"],
                          docs["llms_full"]["text"]))
        # Same-origin .md docs linked from llms.txt, capped. External
        # links are never fetched.
        md_fetched = 0
        for link in docs.get("llms_links", []):
            if md_fetched >= _MAX_MD_DOCS:
                break
            if not link["same_origin"]:
                continue
            if not urlparse(link["url"]).path.lower().endswith(".md"):
                continue
            doc = await _fetch_text(ctx, link["url"], _MAX_MD_BYTES)
            if doc:
                texts.append((doc["url"], doc["text"]))
                md_fetched += 1
        if not texts:
            return self._ok([], "no llms.txt, llms-full.txt or linked "
                                "docs to mine")
        findings: List[Finding] = []
        seen = set()

        def emit(f: Finding, dedupe_key: Tuple) -> None:
            if dedupe_key not in seen and len(findings) < 60:
                seen.add(dedupe_key)
                findings.append(f)

        for url, text in texts:
            for name, pat, conf, sev in _GIT_RULES:
                try:
                    rx = re.compile(pat)
                except Exception:
                    continue
                for m in rx.finditer(text):
                    val = m.group(0)
                    if is_placeholder(val):
                        continue
                    fp = _fingerprint(val)
                    emit(self.ai_finding(
                        "leak", "ai_llms_secret",
                        f"{sev.upper()}: {name} {val} in "
                        f"AI-facing document {url}",
                        url, "high" if sev in ("critical", "high")
                        else "medium",
                        fingerprint_sha256=fp, rule=name,
                        full_value=val), (fp, url))
        return self._ok(findings,
                        f"mined {len(texts)} AI-facing documents, "
                        f"{md_fetched} linked .md docs fetched")


# ---------------------------------------------------------------------------
# ai_robots_ai
# ---------------------------------------------------------------------------

class AiRobotsAi(_AiPlugin):
    id = "ai_robots_ai"
    label = "AI Crawler robots.txt Inventory"
    description = ("Inventory which AI crawlers robots.txt allows, "
                   "blocks, or partially restricts.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        docs = await discover_ai_docs(ctx, target)
        groups = docs.get("robots_groups", [])
        if not groups or not docs.get("robots"):
            return self._ok([], "no robots.txt to inventory")
        findings: List[Finding] = []
        for g in groups:
            bots = []
            for agent in g.get("agents", []):
                low = agent.lower()
                for bot in AI_BOTS:
                    if bot.lower() in low and bot not in bots:
                        bots.append(bot)
            if not bots:
                continue
            dis = g.get("disallow", [])
            blocked = any(d == "/" for d in dis)
            partial = bool(dis) and not blocked
            state = ("blocked" if blocked else
                     "partially restricted" if partial else "allowed")
            findings.append(self.ai_finding(
                "web", "ai_robots_bot_rule",
                f"robots.txt {state} AI crawler(s) "
                f"{', '.join(bots)}"
                + (f" (disallows: {', '.join(dis)})" if dis else ""),
                docs["robots"]["url"], "low",
                bots=bots, state=state))
        if not findings:
            return self._ok([], "robots.txt has no AI-crawler rules")
        return self._ok(findings,
                        f"inventoried {len(findings)} AI-crawler "
                        f"robots.txt rule groups")


# ---------------------------------------------------------------------------
# ai_llms_conflict
# ---------------------------------------------------------------------------

class AiLlmsConflict(_AiPlugin):
    id = "ai_llms_conflict"
    label = "llms.txt vs robots.txt Conflicts"
    description = ("Flag llms.txt links to paths robots.txt tells "
                   "crawlers to stay out of.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        docs = await discover_ai_docs(ctx, target)
        if not docs.get("llms") or not docs.get("robots"):
            return self._ok([], "need both llms.txt and robots.txt "
                                "to compare")
        groups = docs.get("robots_groups", [])
        findings: List[Finding] = []
        seen = set()
        for link in docs.get("llms_links", []):
            if not link["same_origin"]:
                continue
            path = urlparse(link["url"]).path or "/"
            if disallowed_by_robots(path, groups) and path not in seen:
                seen.add(path)
                findings.append(self.ai_finding(
                    "web", "ai_llms_robots_conflict",
                    f"llms.txt links {path}, but robots.txt "
                    f"Disallow covers it - the AI index invites "
                    f"crawlers into a blocked path",
                    docs["llms"]["url"], "medium",
                    linked_url=link["url"]))
        return self._ok(findings,
                        f"checked {len(docs.get('llms_links', []))} "
                        f"llms.txt links against robots.txt")


# ---------------------------------------------------------------------------
# ai_tdm
# ---------------------------------------------------------------------------

class AiTdm(_AiPlugin):
    id = "ai_tdm"
    label = "TDM Reservation Protocol Audit"
    description = ("Audit the W3C TDM reservation: robots.txt "
                   "tdm-reservation / tdm-policy lines and "
                   "/.well-known/tdmrep.json.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        docs = await discover_ai_docs(ctx, target)
        groups = docs.get("robots_groups", [])
        tdm_res = None
        tdm_policy = None
        for g in groups:
            tdm_res = tdm_res or g.get("tdm_reservation")
            tdm_policy = tdm_policy or g.get("tdm_policy")
        findings: List[Finding] = []
        robots_url = docs["robots"]["url"] if docs.get("robots") else None
        if tdm_res is not None:
            reserved = tdm_res.strip() == "1"
            note = ("content reserved from text-and-data mining"
                    if reserved else "TDM explicitly allowed")
            findings.append(self.ai_finding(
                "web", "ai_tdm_reservation",
                f"robots.txt tdm-reservation: {tdm_res} ({note})",
                robots_url, "low", reserved=reserved))
        if tdm_policy:
            findings.append(self.ai_finding(
                "web", "ai_tdm_policy",
                f"robots.txt declares a TDM policy at {tdm_policy} "
                f"- reported only, not fetched unless same-origin",
                robots_url, "low", policy_url=tdm_policy))
        if docs.get("tdmrep"):
            rep = docs["tdmrep"]
            findings.append(self.ai_finding(
                "web", "ai_tdmrep_present",
                "/.well-known/tdmrep.json present - machine-readable "
                "TDM reservation published",
                rep["url"], "low"))
        if not findings:
            return self._ok([], "no TDM reservation declared")
        return self._ok(findings,
                        f"TDM surface: reservation={tdm_res}, "
                        f"policy={'yes' if tdm_policy else 'no'}, "
                        f"tdmrep={'yes' if docs.get('tdmrep') else 'no'}")
