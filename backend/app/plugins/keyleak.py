"""Key leak checker (defensive tool).

HONEST SCOPE: nobody can derive a private key from a public key or
address. That is the entire point of public-key cryptography. What
this plugin does is check whether a key or address you own has been
LEAKED in public sources (pastes, GitHub code, leak aggregators).

Input: a wallet address (BTC/ETH), a public key, or a username.
Searches:
- psbdmp.ws paste search API (free, no key)
- GitHub code search (needs GITHUB_TOKEN, graceful skip)
- Google dork links for manual checking (pastebin, github)

A hit means: this identifier appears in public leak chatter. Treat
any associated private key as burned: sweep funds immediately.

This is a DEFENSIVE tool for checking your own keys. It cannot crack
or derive keys.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote_plus

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DISCLAIMER = ("This checks whether your identifier appears in PUBLIC leak "
              "sources. It cannot crack, derive, or recover private keys "
              "from public keys or addresses. That is mathematically "
              "infeasible by design.")


class KeyleakPlugin(Plugin):
    id = "keyleak"
    label = "Key Leak Checker"
    accepts = ["crypto_wallet", "username", "email"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = "Defensive: check if your address/key appears in public leaks."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        query = target.normalized.strip()
        if not query or len(query) < 4:
            return self._skipped("no identifier provided")
        findings: List[Finding] = []

        findings.append(self._f(
            "identity", "keyleak_scope",
            f"Checking public leak sources for '{query[:24]}...'. {DISCLAIMER}",
            source="key leak checker", confidence=100, passive=True,
            evidence={"severity": "medium",
                      "note": DISCLAIMER}))

        # 1. psbdmp.ws paste search (free API)
        try:
            url = f"https://psbdmp.ws/api/search/{quote_plus(query)}"
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                pastes = []
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
                    # show where each paste lives
                    for p in pastes[:5]:
                        pid = (p.get("id") or p.get("paste_id") or "") if isinstance(p, dict) else ""
                        when = (p.get("time") or p.get("date") or "") if isinstance(p, dict) else ""
                        paste_url = f"https://psbdmp.ws/paste/{pid}" if pid else url
                        findings.append(self._f(
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
                    if count > len(pastes[:5]):
                        findings.append(self._f(
                            "leak", "keyleak_paste_more",
                            f"{count - min(count, 5)} more paste(s) mention this identifier. "
                            f"See {url}",
                            source="psbdmp.ws", source_url=url,
                            confidence=75, passive=True,
                            evidence={"severity": "high"}))
                else:
                    findings.append(self._f(
                        "identity", "keyleak_paste_clean",
                        f"No pastes found mentioning this identifier on psbdmp.ws.",
                        source="psbdmp.ws", confidence=70, passive=True,
                        evidence={"severity": "medium",
                                  "note": "Clean on this source is good news, not a guarantee."}))
        except Exception as e:
            findings.append(self._f(
                "identity", "keyleak_paste_error",
                f"psbdmp.ws check failed: {str(e)[:100]}",
                source="psbdmp.ws", confidence=40, passive=True))

        # 2. GitHub code search (needs token)
        if not self.missing_keys(ctx):
            try:
                gurl = ("https://api.github.com/search/code?q=" +
                        quote_plus(f'"{query}"'))
                r = await fetch(
                    ctx.http, ctx.limiter, "GET", gurl, timeout=15,
                    headers={"Authorization": f"Bearer {ctx.keys.get('github')}",
                             "Accept": "application/vnd.github+json"})
                if r.status_code == 200:
                    jd = r.json()
                    total = jd.get("total_count", 0)
                    items = jd.get("items", [])[:5]
                    if total > 0:
                        for it in items:
                            file_url = it.get("html_url", gurl)
                            repo = (it.get("repository") or {}).get("full_name", "")
                            path = it.get("path", "")
                            findings.append(self._f(
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
                            findings.append(self._f(
                                "leak", "keyleak_github_more",
                                f"{total - len(items)} more GitHub code result(s). See {gurl}",
                                source="GitHub code search", source_url=gurl,
                                confidence=80, passive=True,
                                evidence={"severity": "high"}))
            except Exception:
                pass
        else:
            findings.append(self._f(
                "identity", "keyleak_github_dork",
                "GitHub code search needs a token. Manual check: "
                f"https://github.com/search?q={quote_plus(chr(34) + query + chr(34))}&type=code",
                source="key leak checker",
                source_url=f"https://github.com/search?q={quote_plus(chr(34) + query + chr(34))}&type=code",
                confidence=50, passive=True))

        # 3. manual dork links
        for site, label in (("pastebin.com", "Pastebin"),
                            ("github.com", "GitHub"),
                            ("paste.rs", "paste.rs")):
            dq = f"https://www.google.com/search?q=" + quote_plus(
                f'site:{site} "{query}"')
            findings.append(self._f(
                "identity", "keyleak_dork",
                f"Manual check ({label}): {dq[:90]}...",
                source="key leak checker", source_url=dq,
                confidence=45, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"key leak check: {len(findings)} findings")
        res.duration_ms = dur
        return res
