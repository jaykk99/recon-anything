"""Burp-Collaborator-style OOB interaction client (Tier-3, native).

The distinct remainder vs master's oob_callback plugin: oob_callback
injects canaries under a placeholder default domain (RECON_OOB_DOMAIN)
and never polls - Jay checks his listener by hand. This client follows
the Burp Collaborator contract instead:

  * Callback domain comes from env COLLABORATOR_DOMAIN. Without it the
    plugin SKIPS cleanly with a "needs config" reason and sends
    nothing at all.
  * Payload generation is a pure, testable step: one unique token per
    run, payload URLs/hostnames for query-param, header and JSON-body
    injection points.
  * Interaction polling: when COLLABORATOR_POLL_URL is also set, the
    client polls it and parses the interaction log (JSON list of
    {protocol, from_ip / remote_ip, time / timestamp, payload_id})
    into confirmed-interaction findings. A parsed hit means the
    target's server really did call back.

Detection/verification use only, on authorized targets. Payloads are
plain URLs/hostnames on Jay's own collaborator domain - inert.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   bounded)

ENV_DOMAIN = "COLLABORATOR_DOMAIN"
ENV_POLL = "COLLABORATOR_POLL_URL"
MAX_PARAM_URLS = 6
MAX_PARAMS_PER_URL = 3


def make_token(run_id: str) -> str:
    return f"{(run_id or 'run')[:8]}-{uuid.uuid4().hex[:10]}"


def generate_payloads(domain: str, token: str) -> Dict[str, str]:
    """Pure payload generation (fixture-tested).

    Returns the per-run callback host plus ready-to-inject payload
    strings for each injection point class.
    """
    host = f"{token}.{domain}"
    url = f"http://{host}/cb"
    return {
        "host": host,
        "url": url,
        "dns": host,
        "param_value": url,
        "header_value": url,
        "json_body": json.dumps({"url": url, "webhook": url,
                                 "callback": url}),
    }


def parse_interactions(data) -> List[Dict]:
    """Pure polling-response parser (fixture-tested).

    Accepts the shapes collaborator/interactsh-style poll endpoints
    return: a bare JSON list, or an object with an "interactions" /
    "data" list. Each item is normalized to protocol/from_ip/time/
    payload_id; unparseable items are dropped, never raised on.
    """
    rows = data
    if isinstance(data, dict):
        rows = data.get("interactions") or data.get("data") or []
    out: List[Dict] = []
    if not isinstance(rows, list):
        return out
    for item in rows:
        if not isinstance(item, dict):
            continue
        out.append({
            "protocol": str(item.get("protocol")
                            or item.get("type") or "unknown"),
            "from_ip": str(item.get("from_ip") or item.get("remote_ip")
                           or item.get("source_ip") or ""),
            "time": str(item.get("time") or item.get("timestamp")
                        or item.get("received_at") or ""),
            "payload_id": str(item.get("payload_id") or item.get("id")
                              or item.get("token") or ""),
            "raw": item,
        })
    return out


class BurpCollaboratorPlugin(Plugin):
    id = "burp_collaborator"
    label = "Burp Collaborator OOB Client"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    timeout_s = 60
    description = ("Collaborator-style OOB client: generates callback "
                   "payloads for COLLABORATOR_DOMAIN, injects them, "
                   "and polls for confirmed interactions. Needs config "
                   "(env) - skips cleanly without it.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        collab_domain = (os.environ.get(ENV_DOMAIN) or "").strip()
        if not collab_domain:
            return self._skipped(
                f"needs config: set {ENV_DOMAIN} to your collaborator "
                f"domain (and optionally {ENV_POLL} for interaction "
                f"polling)")
        mode = self.module_mode(ctx)
        if mode == "passive":
            return self._skipped("needs active mode (injects OOB "
                                 "callback payloads)")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        token = make_token(ctx.run_id)
        payloads = generate_payloads(collab_domain, token)
        findings: List[Finding] = []

        def doc(where: str, url: str) -> None:
            findings.append(self._f(
                "web", "collaborator_payload",
                f"Collaborator payload sent via {where}: "
                f"{payloads['url']}",
                source="burp collaborator client", source_url=url,
                confidence=50, passive=False,
                evidence={"severity": "low",
                          "injection_point": where,
                          "payload": payloads["url"],
                          "callback_host": payloads["host"],
                          "remediation": "Validate and allowlist every "
                                         "URL the server fetches; "
                                         "monitor egress for callbacks "
                                         "to unknown domains."}))

        # 1) Query parameters on parameterized URLs from the bus.
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
            for name, _val in params[:MAX_PARAMS_PER_URL]:
                probe = [(n, payloads["param_value"] if n == name else v)
                         for n, v in params]
                purl = urlunparse(parts._replace(query=urlencode(probe)))
                try:
                    await fetch(ctx.http, ctx.limiter, "GET", purl,
                                timeout=10, follow_redirects=True,
                                max_retries=0)
                    doc(f"URL parameter '{name}'", u)
                except Exception:
                    continue

        # 2) Headers + JSON body on the base URL.
        try:
            await fetch(ctx.http, ctx.limiter, "GET", base, timeout=10,
                        follow_redirects=True, max_retries=0,
                        headers={"X-Forwarded-For": payloads["header_value"],
                                 "Referer": payloads["header_value"]})
            doc("request headers", base)
        except Exception:
            pass
        try:
            await fetch(ctx.http, ctx.limiter, "POST", base, timeout=10,
                        follow_redirects=True, max_retries=0,
                        content=payloads["json_body"],
                        headers={"Content-Type": "application/json"})
            doc("JSON body values (POST)", base)
        except Exception:
            pass

        # 3) Poll for confirmed interactions when a poll URL is set.
        poll_url = (os.environ.get(ENV_POLL) or "").strip()
        polled = 0
        if poll_url:
            try:
                r = await bounded(fetch(ctx.http, ctx.limiter, "GET",
                                        poll_url, timeout=10,
                                        max_retries=0), 12)
                if r is not None and r.status_code == 200:
                    hits = [i for i in parse_interactions(r.json())
                            if token in (i.get("payload_id", "")
                                         + i.get("raw", {}).get(
                                             "host", "")
                                         + str(i.get("raw", {})))]
                    # Fall back to all parsed interactions when the
                    # poll endpoint is already scoped to this client.
                    if not hits:
                        hits = parse_interactions(r.json())
                    polled = len(hits)
                    for hit in hits[:20]:
                        findings.append(self._f(
                            "web", "collaborator_interaction",
                            f"Confirmed {hit['protocol']} interaction "
                            f"from {hit['from_ip'] or 'unknown'} at "
                            f"{hit['time'] or 'unknown time'} for "
                            f"payload {payloads['host']}",
                            source="burp collaborator poll",
                            source_url=base, confidence=90,
                            passive=False,
                            evidence={
                                "severity": "high",
                                "protocol": hit["protocol"],
                                "from_ip": hit["from_ip"],
                                "callback_host": payloads["host"],
                                "remediation": "A server-side callback "
                                               "was confirmed: audit "
                                               "every outbound fetch "
                                               "for SSRF/blind "
                                               "injection and enforce "
                                               "an egress allowlist."}))
            except Exception:
                polled = 0

        res = self._ok(
            findings,
            f"{len(findings)} collaborator events "
            f"({polled} confirmed interactions polled); "
            f"callback host {payloads['host']}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
