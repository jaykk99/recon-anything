"""JS bundle mining + source-map recovery plugin (Milestone 3).

Fetches every <script src>, regex-mines endpoints, API hosts, GraphQL
paths, feature flags, buckets, keys and configs. Detects .map files,
downloads them and reconstructs the original file tree from sources.
"""
from __future__ import annotations

import json
import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

SECRET_PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", 95),
    ("aws_secret_hint", r"aws_secret_access_key[^a-zA-Z0-9]{0,10}[A-Za-z0-9/+=]{20,}", 70),
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}", 90),
    ("stripe_pk", r"pk_(live|test)_[0-9A-Za-z]{10,}", 90),
    ("stripe_sk_hint", r"sk_(live|test)_[0-9A-Za-z]{10,}", 95),
    ("firebase_config", r"firebase[a-zA-Z]*\.appspot\.com|firebaseio\.com", 80),
    ("sentry_dsn", r"https://[0-9a-f]{10,}@[a-z0-9.-]*sentry[a-z0-9.-]*/\d+", 85),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z-]{10,}", 95),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{20,}", 95),
    ("jwt_token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 70),
    ("private_key", r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", 99),
    ("s3_bucket", r"https?://[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com", 85),
    ("gcs_bucket", r"https?://storage\.googleapis\.com/[a-z0-9_.-]+", 85),
]

ENDPOINT_PATTERNS = [
    ("api_endpoint", r"['\"`](/(?:api|v\d|graphql|rest|internal|admin)[A-Za-z0-9/_.\-?=&%{}]*)['\"`]", 75),
    ("api_host", r"https?://([a-z0-9.-]*api[a-z0-9.-]*\.[a-z]{2,24})[/\"']", 80),
    ("graphql_path", r"['\"`]([^'\"`]*graphql[^'\"`]*)['\"`]", 80),
    ("websocket", r"wss?://[a-zA-Z0-9.:\-/_?=&%]+", 85),
    ("feature_flag", r"(?:feature[_-]?flag|ff_|isEnabled\(['\"])([A-Za-z0-9_.-]{3,40})", 60),
]


class JsMinerPlugin(Plugin):
    id = "jsminer"
    label = "JS Bundle Miner"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Mine JS bundles for endpoints, hosts, keys; recover source maps."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        async def get_home():
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                                follow_redirects=True)
                return {"html": r.text[:500000], "url": str(r.url)}
            except Exception as e:
                return {"error": str(e)[:200]}

        home, _ = await ctx.cache.cached("http", f"jsminer:{base}", get_home)
        if home.get("error"):
            res = self._degraded(f"fetch failed: {home['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        html = home["html"]
        page_url = home["url"]
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        # also Next.js chunk manifests
        srcs = [s for s in srcs if not s.startswith("data:")][:30]
        findings.append(self._f("web", "js_bundle_count", str(len(srcs)),
                                source="HTML script tags", confidence=95, passive=passive))

        seen_vals = set()

        def emit(kind: str, val: str, source: str, conf: int, url: str | None = None):
            key = (kind, val)
            if key in seen_vals or len(val) > 400:
                return
            seen_vals.add(key)
            findings.append(self._f("api" if kind in ("api_endpoint", "api_host",
                                                      "graphql_path", "websocket")
                                    else "leak", kind, val, source=source,
                                    source_url=url, confidence=conf, passive=passive))

        # mine the home page HTML itself (inline scripts often leak keys)
        for kind, pat, conf in SECRET_PATTERNS:
            for m in re.finditer(pat, html[:500000]):
                emit(kind, m.group(0)[:200], "inline page HTML", conf, page_url)
        for kind, pat, conf in ENDPOINT_PATTERNS:
            for m in re.finditer(pat, html[:500000]):
                emit(kind, m.group(1) if m.groups() else m.group(0),
                     "inline page HTML", conf, page_url)

        for src in srcs:
            full = urljoin(page_url, src)
            ctx.publish("js_files", full)
            # skip third-party CDNs for deep mining (still note them)
            host = urlparse(full).netloc
            third = host and not host.endswith(domain)
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=20)
                if r.status_code != 200:
                    continue
                js = r.text[:1000000]
            except Exception:
                continue

            # sourceMappingURL
            sm = re.search(r"//# sourceMappingURL=(\S+)", js)
            if sm:
                sm_url = urljoin(full, sm.group(1).strip())
                emit("source_map", sm_url, "JS bundle", 95, full)
                await self._mine_sourcemap(ctx, sm_url, emit, full)

            if third and len(js) > 200000:
                continue  # do not deep-mine huge vendor bundles
            for kind, pat, conf in SECRET_PATTERNS:
                for m in re.finditer(pat, js):
                    emit(kind, m.group(0)[:200], f"JS bundle {host or 'inline'}",
                         conf, full)
            for kind, pat, conf in ENDPOINT_PATTERNS:
                for m in re.finditer(pat, js):
                    emit(kind, m.group(1) if m.groups() else m.group(0),
                         f"JS bundle {host or 'inline'}", conf, full)

            # deeper: JS comments often contain TODOs, paths, disabled code
            for cm in re.finditer(r"/\*(.*?)\*/", js, re.S):
                c = cm.group(1).strip()
                if 10 < len(c) < 500 and re.search(
                        r"(todo|fixme|hack|secret|key|password|url|http|/api)",
                        c, re.I):
                    emit("js_comment", c[:200], f"JS bundle {host or 'inline'}",
                         60, full)
            for cm in re.finditer(r"^\s*//(.+)$", js, re.M):
                c = cm.group(1).strip()
                if 10 < len(c) < 300 and re.search(
                        r"(todo|fixme|hack|secret|key|password|http|/api)",
                        c, re.I):
                    emit("js_comment", c[:200], f"JS bundle {host or 'inline'}",
                         55, full)

            # deeper: all hardcoded absolute URLs (internal hosts are gold)
            for m in re.finditer(
                    r"https?://[a-zA-Z0-9.-]+\.[a-z]{2,24}(?:/[A-Za-z0-9/_.?=&%-]*)?",
                    js):
                u = m.group(0)
                h = urlparse(u).netloc
                if h and (h.endswith(domain) or h == domain):
                    emit("internal_url", u[:200],
                         f"JS bundle {host or 'inline'}", 70, full)
                    ctx.publish("endpoints", u)

            # deeper: interesting string literals (paths, keys, debug flags)
            for m in re.finditer(
                    r"['\"`]([A-Za-z0-9_.\-/]{3,80})['\"`]", js):
                s = m.group(1)
                if re.match(r"^(?:/[A-Za-z0-9_.\-/]+|DEBUG|TEST_MODE|"
                            r"STAGING|API_KEY|SECRET)(?:[A-Za-z0-9_.\-/]*)$",
                            s) and len(s) > 6:
                    emit("js_string", s[:120],
                         f"JS bundle {host or 'inline'}", 45, full)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"mined {len(srcs)} bundles, {len(findings)} findings")
        res.duration_ms = dur
        return res

    async def _mine_sourcemap(self, ctx: Ctx, sm_url: str, emit, bundle_url: str):
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", sm_url, timeout=20)
            if r.status_code != 200:
                return
            data = json.loads(r.text[:5000000])
        except Exception:
            return
        sources = data.get("sources", []) or []
        emit("sourcemap_sources", f"{len(sources)} original files recoverable",
             "source map", 90, sm_url)
        for s in sources[:40]:
            if s and "node_modules" not in s:
                emit("sourcemap_file", s[:200], "source map", 85, sm_url)
        # sourcesContent may hold original source: scan it too
        contents = data.get("sourcesContent") or []
        blob = "\n".join(c for c in contents[:20] if isinstance(c, str))[:500000]
        for kind, pat, conf in SECRET_PATTERNS:
            for m in re.finditer(pat, blob):
                emit(kind, m.group(0)[:200], "source map content", conf, sm_url)
