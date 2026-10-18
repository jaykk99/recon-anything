"""Out-of-Band Callback Trigger (SSRF / blind-RCE canary).

Detection-only. This plugin does NOT set up a listener - it only injects
unique, safe, identifiable callback URLs and documents every payload sent
so Jay can check his own Interactsh/listener for hits.

Callback base domain comes from the environment:

    RECON_OOB_DOMAIN  - Jay's Interactsh/callback domain
                        (default: "your-interactsh-domain" placeholder)

Each injection uses a unique per-run token so hits can be correlated:

    https://<runid>-<rand>.RECON_OOB_DOMAIN/ssrf-test

Injection points:
  - URL parameters (one at a time, safe alphanumeric token appended)
  - Headers: X-Forwarded-For, Referer, User-Agent get the full URL.
             Host gets the unique hostname only (a full URL is not a
             valid Host value).
  - JSON body values: one POST per target with a harmless JSON document
    containing the callback URL in "url"/"webhook" fields (no real
    action fields - nothing to trigger state changes).

Payloads are inert: they are plain URLs pointing at Jay's own domain.
No third-party request is triggered by the scanner itself.

A finding is recorded for every payload injected, with the exact payload
text and a note telling Jay what to look for in his Interactsh listener.
A hit on the listener = confirmed SSRF/blind injection; no hit only
means "no callback observed", not "definitely safe".
"""
from __future__ import annotations

import json
import os
import time
import uuid
from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Plugin, PluginResult, Target

ENV_DOMAIN = "RECON_OOB_DOMAIN"
PLACEHOLDER = "your-interactsh-domain"
MAX_PARAM_URLS = 8
MAX_PARAMS_PER_URL = 3
MAX_BUS_ENDPOINTS = 5

HEADER_TARGETS = ["X-Forwarded-For", "Referer", "User-Agent"]
# Header value per name: Host takes the bare hostname, the rest the URL.
INJECTED_HEADERS_LABEL = "X-Forwarded-For / Referer / User-Agent (full URL), Host (hostname only)"

REMEDIATION = ("Validate and allowlist every URL the server fetches: block "
               "private/loopback/metadata ranges, enforce a scheme "
               "allowlist (https only), and disable redirects to "
               "untrusted hosts. For blind callbacks, monitor egress "
               "traffic from the server.")


def _unique_host(ctx: Ctx) -> str:
    token = f"{ctx.run_id[:8]}-{uuid.uuid4().hex[:8]}"
    domain = os.environ.get(ENV_DOMAIN, PLACEHOLDER).strip() or PLACEHOLDER
    return f"{token}.{domain}"


def _placeholder_note(domain: str) -> str:
    if PLACEHOLDER in domain:
        return (f" {ENV_DOMAIN} is not set (using '{PLACEHOLDER}' placeholder). "
                "Payloads were still injected and documented, but no real "
                "callback can arrive. Set RECON_OOB_DOMAIN to your "
                "Interactsh domain and re-run to get live hits.")
    return ""


class OobCallbackPlugin(Plugin):
    id = "oob_callback"
    label = "Out-of-Band Callback Trigger"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = "Inject unique OOB callback canaries; documents payloads for Jay to check."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (injects OOB callback payloads)")

        host = _unique_host(ctx)
        callback_url = f"https://{host}/ssrf-test"
        note = _placeholder_note(host)

        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List = []

        def doc(payload_desc: str, where: str, url: str) -> None:
            findings.append(self._f(
                "web", "oob_callback_sent",
                f"OOB callback canary sent via {where}: {payload_desc}.{note}",
                source="OOB callback trigger", source_url=url,
                confidence=50, passive=False,
                evidence={"severity": "medium",
                          "injection_point": where,
                          "payload": payload_desc,
                          "callback_host": host,
                          "listener_check": f"Check your Interactsh/listener for a hit on '{host}'. A hit = confirmed server-side request to an attacker-controlled URL (SSRF/blind injection).",
                          "remediation": REMEDIATION,
                          "scope_note": "Authorized testing only. No listener was set up; verify on your own asset."}))

        # 1) URL parameters: take param URLs from the discovery bus.
        param_urls = []
        for eu in ctx.consume("endpoints"):
            eu = str(eu)
            if "?" in eu and domain in urlparse(eu).netloc:
                param_urls.append(eu)
            if len(param_urls) >= MAX_PARAM_URLS:
                break
        for u in param_urls:
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            for name, val in params[:MAX_PARAMS_PER_URL]:
                probe = [(n, callback_url if n == name else v) for n, v in params]
                purl = urlunparse(parts._replace(query=urlencode(probe)))
                try:
                    await fetch(ctx.http, ctx.limiter, "GET", purl,
                                timeout=12, follow_redirects=True, max_retries=1)
                except Exception:
                    continue
                doc(callback_url, f"URL parameter '{name}'", u)

        # 2) Headers on the base URL.
        headers: Dict[str, str] = {
            "X-Forwarded-For": callback_url,
            "Referer": callback_url,
            "User-Agent": f"recon-oob/{callback_url}",
            "Host": host,  # hostname only; a URL is not a valid Host value
        }
        try:
            await fetch(ctx.http, ctx.limiter, "GET", base,
                        headers=headers, timeout=12,
                        follow_redirects=True, max_retries=1)
            doc(INJECTED_HEADERS_LABEL, "request headers", base)
        except Exception:
            pass

        # 3) JSON body values: one POST per known endpoint with a harmless
        # document. No action-oriented fields - just the callback URL.
        body = {"url": callback_url, "webhook": callback_url,
                "callback": callback_url}
        bus_targets = [base]
        for eu in ctx.consume("endpoints"):
            eu = str(eu)
            if domain in urlparse(eu).netloc and eu not in bus_targets:
                bus_targets.append(eu)
            if len(bus_targets) > MAX_BUS_ENDPOINTS:
                break
        for u in bus_targets:
            try:
                await fetch(ctx.http, ctx.limiter, "POST", u,
                            content=json.dumps(body),
                            headers={"Content-Type": "application/json"},
                            timeout=12, follow_redirects=True, max_retries=1)
                doc(json.dumps(body), "JSON body values (POST)", u)
            except Exception:
                continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} OOB canaries sent; check listener for '{host}'")
        res.duration_ms = dur
        return res
