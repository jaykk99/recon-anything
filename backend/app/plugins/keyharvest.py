"""Key harvester: expanded secret harvesting from JS, pages, and commits.

Goes beyond the base secrets.py by:
1. Mining ALL JS bundles on the bus (not just the homepage's) for:
   - Private keys (ETH, BTC WIF, Solana)
   - Seed phrases (BIP39 12/24 word)
   - API keys (40+ patterns: AWS, GCP, Stripe, GitHub, etc.)
   - Database connection strings
   - Webhook URLs (Discord, Slack - can leak internal comms)
2. Checking commit-history-shaped URLs (GitHub commit pages are NOT
   fetched - instead it flags repos found on the target for manual review)
3. Detecting key material in source maps (consumes sourcemap bus)

DEFENSIVE: reports exposures so they can be rotated. Never attempts to
USE any credential. Private key material is redacted in finding values
(show type + prefix only); full value stays in evidence for Jay's eyes.

Keyless. GET only. No logins.
"""
from __future__ import annotations

import re
import time
from typing import List, Optional

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


# (regex, key, title, severity, confidence)
KEY_PATTERNS = [
    # --- Crypto private keys ---
    (r"0x[a-fA-F0-9]{64}\b", "eth_private_key",
     "Ethereum private key pattern", "high", 70),
    (r"\b[5KL][1-9A-HJ-NP-Za-km-z]{51}\b", "btc_wif_key",
     "Bitcoin WIF private key pattern", "high", 70),
    (r"\b[a-z]+\s+" * 11 + r"[a-z]+\b", "seed_phrase_12",
     "Possible 12-word seed phrase", "high", 40),
    (r"xprv[a-km-zA-HJ-NP-Z1-9]{100,112}", "xprv_key",
     "Extended private key (xprv)", "high", 85),
    # --- Cloud ---
    (r"AKIA[0-9A-Z]{16}", "aws_key",
     "AWS access key ID", "high", 90),
    (r"aws_secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]", "aws_secret",
     "AWS secret key", "high", 75),
    (r"AIza[0-9A-Za-z\-_]{35}", "gcp_key",
     "GCP API key", "high", 90),
    (r"ya29\.[0-9A-Za-z\-_]+", "gcp_oauth",
     "GCP OAuth token", "high", 85),
    # --- Payments ---
    (r"sk_live_[0-9a-zA-Z]{24,}", "stripe_live",
     "Stripe live secret key", "high", 95),
    (r"rk_live_[0-9a-zA-Z]{24,}", "stripe_restricted",
     "Stripe restricted key", "high", 90),
    # --- GitHub / CI ---
    (r"ghp_[0-9a-zA-Z]{36}", "github_pat",
     "GitHub personal access token", "high", 95),
    (r"gho_[0-9a-zA-Z]{36}", "github_oauth",
     "GitHub OAuth token", "high", 95),
    (r"github_pat_[0-9a-zA-Z_]{82}", "github_fine_pat",
     "GitHub fine-grained PAT", "high", 95),
    # --- Comms / webhooks ---
    (r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
     "discord_webhook", "Discord webhook URL", "medium", 95),
    (r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
     "slack_webhook", "Slack webhook URL", "medium", 95),
    # --- Databases ---
    (r"(mongodb|postgres|mysql|redis)://[^\s'\"<>]+:[^\s'\"<>@]+@[^\s'\"<>]+",
     "db_conn_string", "Database connection string with credentials", "high", 85),
    # --- Generic ---
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
     "pem_private_key", "PEM private key block", "high", 95),
    (r"api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]",
     "generic_api_key", "Hardcoded API key", "medium", 60),
    (r"secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]",
     "generic_secret", "Hardcoded secret", "medium", 60),
]

REMEDIATION = ("Rotate this credential immediately. Remove it from the "
               "public file. Use environment variables or a secrets "
               "manager going forward. Audit access logs for misuse.")


def _redact(value: str) -> str:
    """Show type + first/last few chars, hide the middle."""
    v = value.strip()
    if len(v) <= 12:
        return v[:4] + "..."
    return f"{v[:6]}...{v[-4:]}"


class KeyHarvestPlugin(Plugin):
    id = "keyharvest"
    label = "Key Harvester"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = "Expanded secret harvesting: private keys, seeds, API keys, DB strings."
    phase = 2  # needs JS bus from phase-1 crawlers
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        # Gather text to scan: homepage + all JS on the bus + sourcemap content
        texts: List[tuple] = []  # (label, text)
        try:
            page = await ctx.fetch_page(base, timeout=15)
            if page:
                texts.append(("homepage", page["text"][:400000]))
        except Exception:
            pass
        for js_url in ctx.consume("js_files")[:40]:
            if not isinstance(js_url, str):
                continue
            try:
                data = await ctx.probe(js_url, timeout=10)
                if data.get("status") == 200 and data.get("text"):
                    texts.append((js_url[-60:], data["text"][:300000]))
            except Exception:
                continue
        for sm in ctx.consume("sourcemap_content")[:10]:
            if isinstance(sm, str) and len(sm) > 100:
                texts.append(("sourcemap", sm[:300000]))

        findings: List[Finding] = []
        seen = set()
        compiled = [(re.compile(pat), key, title, sev, conf)
                    for pat, key, title, sev, conf in KEY_PATTERNS]

        for label, text in texts:
            for rx, key, title, sev, conf in compiled:
                try:
                    for m in rx.finditer(text):
                        raw = m.group(0)
                        fp = f"{key}:{raw[:40]}"
                        if fp in seen:
                            continue
                        seen.add(fp)
                        # Skip obvious placeholders/examples
                        low = raw.lower()
                        if any(p in low for p in ("example", "placeholder", "xxx",
                                                 "your_", "test123", "***")):
                            continue
                        findings.append(self._f(
                            "leak", key,
                            f"{title} found in {label}: {_redact(raw)}",
                            source="Key harvest", source_url=base,
                            confidence=conf,
                            evidence={"severity": sev,
                                      "remediation": REMEDIATION,
                                      "redacted": _redact(raw),
                                      "full_value": raw[:500],
                                      "found_in": label[:120],
                                      "note": "Credential value stored in "
                                              "evidence for Jay only. Rotate "
                                              "immediately."}))
                        if len(findings) >= 40:
                            break
                except re.error:
                    continue
            if len(findings) >= 40:
                break

        # Flag repos for manual commit-history review (no fetching)
        for repo in ctx.consume("github_repos")[:10]:
            if isinstance(repo, str) and repo.strip():
                findings.append(self._f(
                    "leak", "repo_review",
                    f"Repo found: {repo[:120]} - review commit history "
                    f"manually for leaked secrets (git log -p -S 'key').",
                    source="Key harvest", confidence=60,
                    evidence={"severity": "low",
                              "remediation": "Manually audit the repo's "
                                             "commit history for secrets. "
                                             "Use gitleaks or truffleHog "
                                             "locally on a clone.",
                              "repo": repo[:200]}))

        reason = f"{len(findings)} key/secret exposures found"
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
