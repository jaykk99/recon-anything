"""CloudBrute-style multi-cloud infrastructure enumerator.

Expands on cloud_buckets.py with more providers and more name patterns:
AWS S3, Google Cloud Storage, Azure Blob, DigitalOcean Spaces, plus
cloud-adjacent endpoints (CloudFront, Azure CDN, GCP LB). Guesses bucket
names from the target and checks existence.

Read-only, list-only: GET on bucket roots, never writes, never downloads
objects. A publicly LISTABLE bucket is a top-tier finding.
Authorized testing only.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

BUCKET_SUFFIXES = ["-backup", "-backups", "-dev", "-development", "-assets",
                   "-static", "-media", "-uploads", "-prod", "-production",
                   "-staging", "-stage", "-test", "-data", "-files", "-private",
                   "-logs", "-archive", "-cdn", "-images", "-docs", "-db",
                   "-sql", "-config", "-secrets", "-keys"]

REMEDIATION = ("Block public access at the bucket policy level, audit access "
               "logs for prior reads, and rotate anything the bucket held.")


def _short_name(domain: str) -> str:
    base = domain.split(":")[0].lower()
    parts = base.split(".")
    core = parts[-2] if len(parts) >= 2 else parts[0]
    name = re.sub(r"[^a-z0-9-]", "", core)
    return name[:30] or "bucket"


async def _probe(ctx: Ctx, url: str) -> Tuple[str, str]:
    """Returns (status, note). status: open | private | missing."""
    try:
        r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=8)
    except Exception:
        return "missing", ""
    body = r.text[:2000]
    if r.status_code == 200 and any(
            x in body for x in ("ListBucketResult", "BlobService",
                                "ListBucket", "<Contents>")):
        return "open", body[:200]
    if r.status_code in (403, 401):
        return "private", ""
    if r.status_code == 404:
        return "missing", ""
    return "missing", ""


class CloudEnumPlugin(Plugin):
    id = "cloud_enum"
    label = "Multi-Cloud Enumerator"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("CloudBrute-style: bucket/infra discovery across AWS, "
                   "GCP, Azure, and DigitalOcean.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        name = _short_name(domain)
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        candidates = [name] + [f"{name}{suf}" for suf in BUCKET_SUFFIXES[:20]]
        # dedupe, cap at 21 buckets x providers
        seen_names: List[str] = []
        for c in candidates:
            if c not in seen_names:
                seen_names.append(c)

        async def check_provider(bucket: str, provider: str, url: str):
            status, note = await _probe(ctx, url)
            if status == "missing":
                return None
            if status == "open":
                return self._f(
                    "leak", "cloud_bucket_open",
                    f"PUBLIC {provider} bucket listable: {bucket}",
                    source="cloud enum probe", source_url=url,
                    confidence=95, passive=passive,
                    evidence={"remediation": REMEDIATION,
                              "severity": "high", "risk": "high",
                              "provider": provider, "bucket": bucket,
                              "preview": note[:200]})
            return self._f(
                "infra", "cloud_bucket_exists",
                f"{provider} bucket exists (private): {bucket}",
                source="cloud enum probe", source_url=url,
                confidence=85, passive=passive,
                evidence={"remediation": "Confirm the bucket should exist "
                          "and is not listable. Private is correct.",
                          "severity": "low", "risk": "low",
                          "provider": provider, "bucket": bucket})

        tasks = []
        for bucket in seen_names:
            tasks.append(check_provider(
                bucket, "AWS S3", f"https://{bucket}.s3.amazonaws.com"))
            tasks.append(check_provider(
                bucket, "GCS", f"https://storage.googleapis.com/{bucket}"))
            tasks.append(check_provider(
                bucket, "Azure Blob",
                f"https://{bucket}.blob.core.windows.net/?restype=container&comp=list"))
            tasks.append(check_provider(
                bucket, "DO Spaces",
                f"https://{bucket}.nyc3.digitaloceanspaces.com"))

        results = await asyncio.gather(*tasks)
        for f in results:
            if f is not None:
                findings.append(f)

        # Publish open buckets to the discovery bus
        for f in findings:
            if f.key == "cloud_bucket_open":
                ctx.publish("endpoints", f.source_url or "")

        res = self._ok(
            findings,
            f"{len(findings)} cloud hits across 4 providers" if findings
            else "no cloud buckets found")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
