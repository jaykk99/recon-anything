"""S3 / cloud storage bucket finder (high payout findings).

Extracts bucket names from page HTML, JS bundles, and responses, then
checks if they are publicly accessible. Read-only: only sends HEAD/GET
to the bucket root, never writes or deletes. A publicly listable or
readable bucket with sensitive data is a top-tier bug bounty finding.
Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Bucket name patterns in code and responses
BUCKET_PATTERNS = [
    # s3.amazonaws.com/bucket or bucket.s3.amazonaws.com
    (r"https?://([a-z0-9][a-z0-9\-.]{1,61}[a-z0-9])\.s3[.-][a-z0-9\-]*\.amazonaws\.com", "aws"),
    (r"https?://s3[.-][a-z0-9\-]*\.amazonaws\.com/([a-z0-9][a-z0-9\-.]{1,61}[a-z0-9])", "aws"),
    # GCS
    (r"https?://([a-z0-9][a-z0-9\-_.]{1,61})\.storage\.googleapis\.com", "gcp"),
    (r"https?://storage\.googleapis\.com/([a-z0-9][a-z0-9\-_.]{1,61})", "gcp"),
    # Azure blob
    (r"https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net", "azure"),
    # Generic bucket variable assignments in JS
    (r"""['"](?:s3_?bucket|bucket_?name|aws_?bucket)['"]\s*[:=]\s*['"]([a-z0-9][a-z0-9\-.]{2,61})['"]""", "aws"),
]

REMEDIATION = ("Block public access at the bucket level (S3 Block Public "
               "Access), use least-privilege bucket policies, never hardcode "
               "bucket names with sensitive data, and audit with tools like "
               "Prowler or ScoutSuite.")


class S3Plugin(Plugin):
    id = "s3"
    label = "Cloud Bucket Finder"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find S3/GCS/Azure buckets and test public access."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:400000]
            page_url = str(r.url)
        except Exception as e:
            res = self._error(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # Collect candidate bucket names
        buckets: Set[tuple] = set()
        texts = [html]
        # Also scan JS bundles
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(page_url, m.group(1))
            if urlparse(full).netloc.endswith(domain):
                try:
                    jr = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=15)
                    if jr.status_code == 200:
                        texts.append(jr.text[:500000])
                        ctx.publish("js_files", full)
                except Exception:
                    continue
            if len(texts) > 10:
                break

        for text in texts:
            for pat, provider in BUCKET_PATTERNS:
                for m in re.finditer(pat, text, re.I):
                    name = m.group(1).lower().strip(".")
                    if len(name) >= 3 and "." not in name.split(".")[0][:0]:
                        buckets.add((name, provider))

        # Also check discovery bus for bucket names from other plugins
        for item in ctx.consume("endpoints"):
            if isinstance(item, str):
                for pat, provider in BUCKET_PATTERNS[:3]:
                    m = re.search(pat, item, re.I)
                    if m:
                        buckets.add((m.group(1).lower(), provider))

        tested = 0
        for name, provider in list(buckets)[:15]:
            # Report the bucket reference first
            findings.append(self._f(
                "leak", "cloud_bucket_ref",
                f"HIGH: cloud storage bucket referenced: {name} ({provider}). "
                f"Testing public access.",
                source="bucket mining", source_url=page_url,
                confidence=70, passive=passive,
                evidence={"severity": "high", "bucket": name,
                          "provider": provider,
                          "remediation": REMEDIATION}))

            if passive:
                continue

            # Test public access (read-only)
            test_urls = []
            if provider == "aws":
                test_urls = [f"https://{name}.s3.amazonaws.com/",
                             f"https://s3.amazonaws.com/{name}/"]
            elif provider == "gcp":
                test_urls = [f"https://storage.googleapis.com/{name}/"]
            elif provider == "azure":
                test_urls = [f"https://{name}.blob.core.windows.net/?restype=container&comp=list"]

            for turl in test_urls:
                try:
                    tested += 1
                    tr = await fetch(ctx.http, ctx.limiter, "GET", turl,
                                     timeout=12, follow_redirects=False)
                    body = tr.text[:5000]
                    # Publicly listable?
                    if tr.status_code == 200 and ("<ListBucketResult" in body or
                                                  "<EnumerationResults" in body):
                        findings.append(self._f(
                            "leak", "s3_public_list",
                            f"CRITICAL: bucket {name} is PUBLICLY LISTABLE. "
                            f"Anyone can enumerate its contents.",
                            source="bucket access test", source_url=turl,
                            confidence=95, passive=False,
                            evidence={"severity": "critical", "bucket": name,
                                      "provider": provider,
                                      "access": "public-list",
                                      "remediation": REMEDIATION,
                                      "scope_note": "Read-only test. Do not download sensitive files."}))
                        break
                    # Check ACL via error messages
                    if tr.status_code == 403 and "AccessDenied" in body:
                        pass  # properly locked
                    elif tr.status_code == 200:
                        findings.append(self._f(
                            "leak", "s3_public_read",
                            f"HIGH: bucket {name} returns 200 to anonymous requests. "
                            f"May expose files.",
                            source="bucket access test", source_url=turl,
                            confidence=80, passive=False,
                            evidence={"severity": "high", "bucket": name,
                                      "provider": provider,
                                      "access": "public-read",
                                      "remediation": REMEDIATION}))
                        break
                except Exception:
                    continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(buckets)} buckets found, {tested} access tests, "
                                 f"{len(findings)} findings")
        res.duration_ms = dur
        return res
