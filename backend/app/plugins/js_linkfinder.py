"""LinkFinder-style JS endpoint mining with masked secret shapes.

js_endpoints.py reconstructs API calls from fetch/axios patterns and
jsminer.py mines bundles (and reports key material it finds). This
plugin is the LinkFinder pass, with a different output contract:

- One broad sweep over every first-party bundle for ALL URL shapes
  (absolute, root-relative, relative-with-extension, query-bearing),
  not just fetch() call sites: endpoints AND their parameter names,
  each attributed to the bundle it came from, all published to the
  discovery bus for chain plugins (param discovery, template
  verification, the lifecycle orchestrator).
- Hardcoded-secret SHAPES are reported the safe way: type, a masked
  preview (first 4 / last 2 characters), and a truncated SHA-256
  fingerprint of the value. The full secret value NEVER appears in
  a finding's value, evidence, or raw fields - enough to identify
  and rotate the credential, never enough to use it.

Read-only GETs of public JS files. Keyless.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Dict, List, Set, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import same_domain

# LinkFinder-style URL shapes inside quoted strings.
URL_RES = [
    re.compile(r"""['"`](https?://[^'"`\s<>]{4,300})['"`]"""),
    re.compile(r"""['"`](//[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^'"`\s<>]{0,300})['"`]"""),
    re.compile(r"""['"`](/(?:[a-zA-Z0-9_\-.~%]+/)*[a-zA-Z0-9_\-.~%]*"""
               r"""(?:\?[a-zA-Z0-9_\-=&%.~]*)?)['"`]"""),
    re.compile(r"""['"`]([a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-.~%]+)+"""
               r"""(?:\.[a-zA-Z]{1,5})?(?:\?[a-zA-Z0-9_\-=&%.~]*)?)['"`]"""),
]

STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
              ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
              ".map")
API_HINT = ("/api", "/v1", "/v2", "/v3", "/rest", "/graphql", "/auth",
            "/admin", "/user", "/account", "/internal")

# (shape name, regex with the secret in group 1, severity)
SECRET_SHAPES: List[Tuple[str, re.Pattern, str]] = [
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "high"),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b"), "high"),
    ("stripe_secret_key", re.compile(r"\b(sk_(?:live|test)_[0-9A-Za-z]{10,})\b"), "high"),
    ("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b"), "high"),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "medium"),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
                       r"[A-Za-z0-9_-]{10,})\b"), "medium"),
    ("private_key_block", re.compile(
        r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"), "high"),
    ("generic_secret_assignment", re.compile(
        r"""(?i)(?:api[_-]?key|secret|passwd|password|auth[_-]?token)"""
        r"""\s*[:=]\s*['"]([^'"]{8,120})['"]"""), "medium"),
]

from .. import config

# Tunable via RECON_JS_* (see app/config.py); deeper defaults than the
# original 8 / 25 so more of a site's JS is mined for endpoints and secrets.
MAX_BUNDLES = config.JS_MAX_BUNDLES
MAX_ENDPOINT_FINDINGS = config.JS_MAX_ENDPOINT_FINDINGS


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "********"
    return f"{value[:4]}...{value[-2:]}"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:12]


def _extract_urls(js: str) -> Set[str]:
    out: Set[str] = set()
    for rx in URL_RES:
        for m in rx.finditer(js):
            u = m.group(1).strip()
            if len(u) >= 2 and not u.startswith("data:"):
                out.add(u)
    return out


class JsEndpointMiningLinkfinderPlugin(Plugin):
    id = "js_endpoint_mining_linkfinder"
    label = "JS Endpoint Mining (LinkFinder-style)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    phase = 2
    timeout_s = 90
    description = ("LinkFinder-style sweep of JS bundles for endpoints "
                   "and parameter names (published to the discovery "
                   "bus), plus hardcoded-secret shapes reported as "
                   "masked fingerprint + type only, never the value.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        start = time.time()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        base = await web_base(ctx, target, domain)

        bundle_urls: List[str] = []
        for item in ctx.consume("js_files"):
            if isinstance(item, str) and same_domain(item, domain):
                bundle_urls.append(item)
        page = await ctx.fetch_page(base)
        if page:
            html = page.get("text") or ""
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']',
                                 html, re.I):
                u = urljoin(base, m.group(1))
                if same_domain(u, domain):
                    bundle_urls.append(u)
        seen_bundles: Set[str] = set()
        bundles: List[str] = []
        for u in bundle_urls:
            if u not in seen_bundles:
                seen_bundles.add(u)
                bundles.append(u)
        bundles = bundles[:MAX_BUNDLES]
        if not bundles:
            return self._ok([], "no first-party JS bundles found")

        findings: List[Finding] = []
        endpoints: Set[str] = set()
        secret_seen: Set[Tuple[str, str]] = set()
        for burl in bundles:
            resp = await ctx.fetch_page(burl)
            if not resp:
                continue
            js = resp.get("text") or ""
            if not js:
                continue
            for raw_u in _extract_urls(js):
                full = urljoin(burl, raw_u)
                if not same_domain(full, domain):
                    continue
                pu = urlparse(full)
                if pu.path.lower().endswith(STATIC_EXT):
                    continue
                clean = f"{pu.scheme}://{pu.netloc}{pu.path}"
                if pu.query:
                    clean += "?" + pu.query
                if clean not in endpoints:
                    endpoints.add(clean)
                    ctx.publish("endpoints", clean)
                    for pname, _ in parse_qsl(pu.query):
                        ctx.publish("params", f"{clean.split('?')[0]}"
                                              f"?{pname}=")
            for shape, rx, severity in SECRET_SHAPES:
                for m in rx.finditer(js):
                    value = m.group(1)
                    fp = _fingerprint(value)
                    if (shape, fp) in secret_seen:
                        continue
                    secret_seen.add((shape, fp))
                    findings.append(self._f(
                        "leak", "js_secret_shape",
                        f"{shape} shape in {burl} "
                        f"(masked {_mask(value)}, sha256:{fp})",
                        source="linkfinder-style js mining",
                        source_url=burl, confidence=75, passive=True,
                        evidence={
                            "severity": severity,
                            "secret_type": shape,
                            "masked": _mask(value),
                            "sha256_fingerprint": fp,
                            "bundle": burl,
                            "value_stored": False,
                            "remediation": ("Remove the credential from "
                                            "client-side code and rotate "
                                            "it; anything shipped in a "
                                            "JS bundle is public.")}))
        api_like = sorted(
            e for e in endpoints
            if any(h in urlparse(e).path.lower() for h in API_HINT)
            or "?" in e)
        for ep in api_like[:MAX_ENDPOINT_FINDINGS]:
            findings.append(self._f(
                "api", "mined_endpoint",
                f"Endpoint mined from JS: {ep}",
                source="linkfinder-style js mining", source_url=ep,
                confidence=70, passive=True,
                evidence={"severity": "low",
                          "remediation": ("Audit this endpoint for "
                                          "authentication and object-"
                                          "level authorization.")}))
        result = self._ok(
            findings,
            f"{len(endpoints)} endpoints mined from "
            f"{len(bundles)} bundles, {len(secret_seen)} secret shapes")
        result.duration_ms = int((time.time() - start) * 1000)
        return result
