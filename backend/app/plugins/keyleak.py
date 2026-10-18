"""Key leak checker (defensive tool).

HONEST SCOPE: nobody can derive a private key from a public key or
address. That is the entire point of public-key cryptography. What
this plugin does is check whether a key or address you own has been
LEAKED in public sources (pastes, GitHub code, leak aggregators).

On domain/url/ip targets it runs in phase 2 and checks identifiers
harvested by phase-1 plugins (emails from the discovery bus) plus any
identifier given directly as the target.

Searches (all in parallel, 5s timeout each):
- psbdmp.ws paste search API (free, no key)
- grep.app code search API (free, no key, indexes public GitHub)
- GitHub code search API (needs GITHUB_TOKEN, graceful skip)
- Google dork links for manual checking (no request sent)

A hit means: this identifier appears in public leak chatter. Treat
any associated private key as burned: sweep funds immediately.

This is a DEFENSIVE tool for checking your own keys. It cannot crack
or derive keys.
"""
from __future__ import annotations

import asyncio
import time
from typing import List
from urllib.parse import quote_plus

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DISCLAIMER = ("This checks whether your identifier appears in PUBLIC leak "
              "sources. It cannot crack, derive, or recover private keys "
              "from public keys or addresses. That is mathematically "
              "infeasible by design.")

SOURCE_TIMEOUT = 5
MAX_IDENTIFIERS = 5


class KeyleakPlugin(Plugin):
    id = "keyleak"
    label = "Key Leak Checker"
    accepts = ["domain", "url", "ip", "crypto_wallet", "username", "email"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    phase = 2
    description = "Defensive: check if identifiers appear in public leaks (fast parallel)."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        identifiers: List[str] = []

        # Direct identifier targets
        if target.type in ("crypto_wallet", "username", "email"):
            q = target.normalized.strip()
            if len(q) >= 4:
                identifiers.append(q)

        # Harvested identifiers from phase-1 plugins (discovery bus)
        for email in ctx.consume("emails"):
            e = str(email).strip()
            if "@" in e and len(e) >= 6 and e not in identifiers:
                identifiers.append(e)
            if len(identifiers) >= MAX_IDENTIFIERS:
                break

        identifiers = identifiers[:MAX_IDENTIFIERS]

        # Smart cache: never check the same identifier twice in a run
        checked = ctx.shared.setdefault("keyleak_checked", [])
        fresh = [i for i in identifiers if i not in checked]
        for i in fresh:
            checked.append(i)

        findings: List[Finding] = []
        findings.append(self._f(
            "identity", "keyleak_scope",
            f"Checking public leak sources for {len(fresh)} identifier(s). {DISCLAIMER}",
            source="key leak checker", confidence=100, passive=True,
            evidence={"severity": "medium", "note": DISCLAIMER}))

        if not fresh:
            findings.append(self._f(
                "identity", "keyleak_no_identifiers",
                "No new identifiers to check (none harvested, or already checked).",
                source="key leak checker", confidence=60, passive=True))
            res = self._ok(findings, "key leak check: nothing new")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # Check every identifier against every source concurrently
        for ident in fresh:
            src_results = await asyncio.gather(
                self._check_psbdmp(ident, ctx),
                self._check_grepapp(ident, ctx),
                self._check_github(ident, ctx),
            )
            for hit_findings in src_results:
                findings.extend(hit_findings)
            # Manual dork links (no request sent, instant)
            for site, label in (("pastebin.com", "Pastebin"),
                                ("github.com", "GitHub"),
                                ("paste.rs", "paste.rs")):
                dq = ("https://www.google.com/search?q=" +
                      quote_plus(f'site:{site} "{ident}"'))
                findings.append(self._f(
                    "identity", "keyleak_dork",
                    f"Manual check ({label}) for '{ident[:20]}...': {dq[:90]}...",
                    source="key leak checker", source_url=dq,
                    confidence=45, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"key leak check: {len(fresh)} identifiers, {len(findings)} findings")
        res.duration_ms = dur
        return res

    # -- sources (each: 5s max, never raises) --------------------------------

    async def _check_psbdmp(self, query: str, ctx: Ctx) -> List[Finding]:
        out: List[Finding] = []
        url = f"https://psbdmp.ws/api/search/{quote_plus(query)}"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=SOURCE_TIMEOUT)
            if r.status_code != 200:
                return out
            data = r.json()
            pastes = []
            count = 0
            if isinstance(data, dict):
                pastes = data.get("data", []) or []
                count = data.get("count", len(pastes))
            elif isinstance(data, list):
                pastes = data
                count = len(data)
            try:
                count = int(count)
            except (TypeError, ValueError):
                count = len(pastes)
            if count > 0:
                for p in pastes[:5]:
                    pid = (p.get("id") or p.get("paste_id") or "") if isinstance(p, dict) else ""
                    when = (p.get("time") or p.get("date") or "") if isinstance(p, dict) else ""
                    paste_url = f"https://psbdmp.ws/paste/{pid}" if pid else url
                    out.append(self._f(
                        "leak", "keyleak_paste_hit",
                        f"CRITICAL: '{query[:20]}...' appears in a paste "
                        f"{'from ' + str(when) if when else ''} at {paste_url}. "
                        f"If a private key is in that paste, sweep funds to a new wallet NOW.",
                        source="psbdmp.ws", source_url=paste_url,
                        confidence=80, passive=True,
                        evidence={"severity": "critical",
                                  "identifier": query[:40],
                                  "found_at": paste_url,
                                  "indexed": str(when) if when else "unknown",
                                  "remediation": "Open the paste URL, verify what leaked. "
                                                 "If any private key material is exposed, it is burned: "
                                                 "sweep funds to a fresh offline-generated wallet immediately."}))
                if count > 5:
                    out.append(self._f(
                        "leak", "keyleak_paste_more",
                        f"{count - 5} more paste(s) mention this identifier. See {url}",
                        source="psbdmp.ws", source_url=url,
                        confidence=75, passive=True,
                        evidence={"severity": "high"}))
            else:
                out.append(self._f(
                    "identity", "keyleak_paste_clean",
                    f"No pastes found mentioning '{query[:20]}...' on psbdmp.ws.",
                    source="psbdmp.ws", confidence=70, passive=True,
                    evidence={"severity": "medium",
                              "note": "Clean on this source is good news, not a guarantee."}))
        except Exception as e:
            out.append(self._f(
                "identity", "keyleak_paste_error",
                f"psbdmp.ws check failed: {str(e)[:100]}",
                source="psbdmp.ws", confidence=40, passive=True))
        return out

    async def _check_grepapp(self, query: str, ctx: Ctx) -> List[Finding]:
        """grep.app: free unauthenticated code search over public GitHub."""
        out: List[Finding] = []
        url = f"https://grep.app/api/search?q={quote_plus(query)}"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=SOURCE_TIMEOUT)
            if r.status_code != 200:
                return out
            data = r.json()
            hits = ((data.get("hits") or {}).get("hits") or []) if isinstance(data, dict) else []
            if hits:
                for h in hits[:5]:
                    repo = ((h.get("repo") or {}).get("raw")) if isinstance(h, dict) else ""
                    path = ((h.get("path") or {}).get("raw")) if isinstance(h, dict) else ""
                    file_url = f"https://grep.app/search?q={quote_plus(query)}"
                    out.append(self._f(
                        "leak", "keyleak_grepapp_hit",
                        f"HIGH: '{query[:20]}...' appears in public code {repo}/{path}. "
                        f"Review it: {file_url}",
                        source="grep.app code search", source_url=file_url,
                        confidence=80, passive=True,
                        evidence={"severity": "high",
                                  "identifier": query[:40],
                                  "repo": repo or "",
                                  "path": path or "",
                                  "remediation": "Review the file. Rotate anything exposed."}))
            else:
                out.append(self._f(
                    "identity", "keyleak_grepapp_clean",
                    f"No public code matches for '{query[:20]}...' on grep.app.",
                    source="grep.app code search", confidence=70, passive=True,
                    evidence={"severity": "medium"}))
        except Exception as e:
            out.append(self._f(
                "identity", "keyleak_grepapp_error",
                f"grep.app check failed: {str(e)[:100]}",
                source="grep.app code search", confidence=40, passive=True))
        return out

    async def _check_github(self, query: str, ctx: Ctx) -> List[Finding]:
        out: List[Finding] = []
        if self.missing_keys(ctx):
            dq = (f"https://github.com/search?q={quote_plus(chr(34) + query + chr(34))}"
                  f"&type=code")
            out.append(self._f(
                "identity", "keyleak_github_dork",
                f"GitHub code search needs a token. Manual check: {dq[:90]}...",
                source="key leak checker", source_url=dq,
                confidence=50, passive=True))
            return out
        try:
            gurl = ("https://api.github.com/search/code?q=" +
                    quote_plus(f'"{query}"'))
            r = await fetch(
                ctx.http, ctx.limiter, "GET", gurl, timeout=SOURCE_TIMEOUT,
                headers={"Authorization": f"Bearer {ctx.keys.get('github')}",
                         "Accept": "application/vnd.github+json"})
            if r.status_code != 200:
                return out
            jd = r.json()
            total = jd.get("total_count", 0)
            items = jd.get("items", [])[:5]
            if total > 0:
                for it in items:
                    file_url = it.get("html_url", gurl)
                    repo = (it.get("repository") or {}).get("full_name", "")
                    path = it.get("path", "")
                    out.append(self._f(
                        "leak", "keyleak_github_hit",
                        f"CRITICAL: '{query[:20]}...' appears in GitHub file "
                        f"{repo}/{path}. Open it: {file_url}",
                        source="GitHub code search", source_url=file_url,
                        confidence=85, passive=True,
                        evidence={"severity": "critical",
                                  "identifier": query[:40],
                                  "found_at": file_url,
                                  "repo": repo, "path": path,
                                  "remediation": "Review the file. Rotate anything exposed. "
                                                 "Use git history rewriting only after rotation."}))
                if total > len(items):
                    out.append(self._f(
                        "leak", "keyleak_github_more",
                        f"{total - len(items)} more GitHub code result(s). See {gurl}",
                        source="GitHub code search", source_url=gurl,
                        confidence=80, passive=True,
                        evidence={"severity": "high"}))
        except Exception:
            pass
        return out
