"""Cloud bucket name-probing plugin (read-only, list-only).

Guesses common bucket names from the target ({name}-backup, {name}-dev,
{name}-assets, ...) and checks S3, GCS, and Azure Blob for existence.
List-only: GET on the bucket root, never writes, never downloads objects.

A publicly LISTABLE bucket is a top-tier finding. A bucket that EXISTS
but is private is still worth noting (name confirmed for further testing).
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
                   "-staging", "-stage", "-test", "-data", "-files", "-private"]

REMEDIATION = ("Block public access at the bucket policy level, audit access "
               "logs for prior reads, and rotate anything the bucket held.")


def _short_name(domain: str) -> str:
    # example.com -> example ; sub.example.com -> subexample
    base = domain.split(":")[0].lower()
    parts = base.split(".")
    core = parts[-2] if len(parts) >= 2 else parts[0]
    name = re.sub(r"[^a-z0-9-]", "", core)
    return name[:30] or "bucket"


async def _check_s3(ctx: Ctx, bucket: str) -> Tuple[str, Optional[str]]:
    """Returns (status, url). status: open | private | missing."""
    for tmpl in (f"https://{bucket}.s3.amazonaws.com",
                 f"https://s3.amazonaws.com/{bucket}"):
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", tmpl, timeout=10)
        except Exception:
            continue
        if r.status_code == 200 and "ListBucketResult" in r.text:
            return "open", tmpl
        if r.status_code == 403:
            return "private", tmpl
        if r.status_code == 404 and "NoSuchBucket" in r.text:
            return "missing", tmpl
    return "missing", f"https://{bucket}.s3.amazonaws.com"


async def _check_gcs(ctx: Ctx, bucket: str) -> Tuple[str, Optional[str]]:
    url = f"https://storage.googleapis.com/{bucket}"
    try:
        r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10)
    except Exception:
        return "missing", url
    if r.status_code == 200 and "ListBucketResult" in r.text:
        return "open", url
    if r.status_code == 403:
        return "private", url
    return "missing", url


async def _check_azure(ctx: Ctx, bucket: str) -> Tuple[str, Optional[str]]:
    # Azure container names: 3-63 chars, lowercase, no consecutive dashes
    name = re.sub(r"-+", "-", bucket.lower())[:55]
    if len(name) < 3:
        return "missing", ""
    url = f"https://{name}.blob.core.windows.net/?restype=container&comp=list"
    try:
        r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10)
    except Exception:
        return "missing", url
    if r.status_code == 200 and "EnumerationResults" in r.text:
        return "open", url
    if r.status_code in (400, 403, 409):
        return "private", url
    return "missing", url


class CloudBucketsPlugin(Plugin):
    id = "cloud_buckets"
    label = "Cloud Bucket Probe"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "infra"
    description = "Probe common bucket names on S3, GCS, Azure (list-only)."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        name = _short_name(domain)

        candidates = [name + s for s in BUCKET_SUFFIXES[:10]] + [name]
        # Probe all bucket/provider combos concurrently (was sequential:
        # 33 x 10s timeouts could stall this plugin for 5+ minutes).
        # Same probes, same findings - just in parallel.
        checks = [(bucket, provider, checker)
                  for bucket in candidates
                  for provider, checker in (("aws", _check_s3), ("gcp", _check_gcs),
                                            ("azure", _check_azure))]
        bucket_sem = asyncio.Semaphore(8)

        async def check_one(bucket, provider, checker):
            async with bucket_sem:
                try:
                    status, url = await checker(ctx, bucket)
                except Exception:
                    return None
                return (bucket, provider, status, url)

        results = await asyncio.gather(
            *(check_one(b, p, c) for b, p, c in checks))
        checked = sum(1 for r in results if r is not None)
        for item in results:
            if not item:
                continue
            bucket, provider, status, url = item
            if len(findings) >= 12:
                break  # enough signal; stay fast
            if status == "open":
                findings.append(self._f(
                    "leak", "bucket_public_list",
                    f"HIGH: {provider.upper()} bucket '{bucket}' is PUBLICLY LISTABLE - "
                    f"anyone can enumerate its objects. Proved with: curl -s {url} | head -5",
                    source="bucket probe", source_url=url,
                    confidence=95, passive=False,
                    exploitability="public_poc",
                    evidence={"severity": "high", "remediation": REMEDIATION,
                              "provider": provider, "bucket": bucket,
                              "poc_command": f"curl -s '{url}' | head -c 500"}))
            elif status == "private":
                findings.append(self._f(
                    "infra", "bucket_exists_private",
                    f"Bucket '{bucket}' exists on {provider.upper()} but is private - "
                    f"name confirmed for further authorized testing",
                    source="bucket probe", source_url=url,
                    confidence=80, passive=False,
                    evidence={"severity": "low",
                              "remediation": "Confirm the bucket policy blocks public access."}))

        dur = int((time.monotonic() - t0) * 1000)
        note = f"probed {checked} bucket endpoints"
        if not findings:
            note += " - no guessable buckets found"
        res = self._ok(findings, note)
        res.duration_ms = dur
        return res
