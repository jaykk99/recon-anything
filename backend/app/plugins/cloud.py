"""Cloud platform misconfiguration detector.

Detects cloud provider from target and checks provider-specific issues:
Azure Blob storage, GCP buckets, AWS CloudFront, exposed IAM. S3 is
covered by s3.py. Read-only. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

CLOUD_PATTERNS = [
    (r"[a-z0-9-]+\.blob\.core\.windows\.net", "Azure Blob storage reference", "azure"),
    (r"[a-z0-9-]+\.storage\.googleapis\.com|storage\.googleapis\.com/[a-z0-9-]+",
     "GCP Storage bucket reference", "gcp"),
    (r"[a-z0-9-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com", "AWS S3 bucket reference", "aws"),
    (r"[a-z0-9-]+\.cloudfront\.net", "AWS CloudFront distribution", "aws"),
    (r"iam\.amazonaws\.com|sts\.amazonaws\.com", "AWS IAM/STS reference", "aws"),
    (r"management\.azure\.com", "Azure management endpoint", "azure"),
]

AZURE_PATHS = ["/?restype=container&comp=list", "/?comp=list"]
GCP_PATHS = ["/?prefix="]

REMEDIATION = ("Block public access on storage, use private endpoints, "
               "enforce least-privilege IAM, and audit bucket policies.")


class CloudPlugin(Plugin):
    id = "cloud"
    label = "Cloud Misconfig Scout"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = "Detect Azure/GCP/AWS cloud misconfigurations."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        try:
            # Shared homepage cache: first plugin pays, the rest read from cache.
            page = await ctx.fetch_page(base, timeout=25)
            if page is None:
                raise RuntimeError("homepage fetch failed")
            html = page["text"][:400000]
            page_url = page["url"]
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        seen = set()
        for pat, label, provider in CLOUD_PATTERNS:
            for m in re.finditer(pat, html, re.I):
                sample = m.group(0)[:70]
                if sample in seen:
                    continue
                seen.add(sample)
                findings.append(self._f(
                    "infra", "cloud_reference",
                    f"Cloud reference ({provider}): {label} '{sample}'. "
                    f"Verify it is not publicly accessible.",
                    source="Cloud scan", source_url=page_url,
                    confidence=65, passive=passive,
                    evidence={"severity": "medium", "provider": provider,
                              "remediation": REMEDIATION,
                              "scope_note": "Reference only. Authorized testing only."}))
                ctx.publish("cloud_refs", sample)
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} cloud references")
        res.duration_ms = dur
        return res
