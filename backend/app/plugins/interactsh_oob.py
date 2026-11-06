"""Interactsh out-of-band VERIFICATION for blind SSRF/XXE classes.

DETECTION/VERIFICATION ONLY (Tier-6 rule). The probe value injected
is nothing but a callback URL under a domain the operator controls -
no SSRF payload beyond the URL itself, no XXE entity definitions,
no file or metadata content is ever requested. Configuration:

    INTERACTSH_DOMAIN   - your interactsh domain (required; without
                          it the plugin skips cleanly and injects
                          NOTHING - a placeholder callback can never
                          verify anything)
    INTERACTSH_POLL_URL - interactions endpoint to poll, may contain
                          {token}; interactsh-client style JSON is
                          parsed (a list, or {"data": [...]} /
                          {"interactions": [...]}), records matched
                          by full-id / unique-id containing the token

The verification gate is the point: a finding is emitted ONLY when
an interaction for this run's unique token is actually observed at
poll time. Injected-but-unverified payloads are documented in the
result reason, never as findings.

Distinct remainder vs existing plugins (checked against master 847
and Tier-3's burp_collaborator):
- oob_callback.py injects canaries and emits a finding PER INJECTION
  (hit or not), happily using a placeholder domain when
  RECON_OOB_DOMAIN is unset. It never polls and never verifies.
- burp_collaborator (Tier 3) documents Burp-format payloads and
  parses a Burp poll feed when configured, but likewise reports
  payload findings without an observed interaction.
This plugin is the interactsh-format, verified-only variant: no
config = no injection, no observed callback = no finding.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage, param_urls, probe_url, sample_urls

ENV_DOMAIN = "INTERACTSH_DOMAIN"
ENV_POLL = "INTERACTSH_POLL_URL"
MAX_URLS = 4

REMEDIATION = ("Validate and allowlist every URL the server fetches; "
               "block private/loopback/metadata ranges, disable XML "
               "external entities, and monitor server egress - a "
               "verified callback proves the server fetched an "
               "attacker-chosen URL.")


def make_token(run_id: str) -> str:
    seed = (run_id or "") + uuid.uuid4().hex
    return uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex[:16]


def parse_interactions(data) -> List[Dict]:
    """Normalize an interactsh-style poll payload to record dicts."""
    records = []
    if isinstance(data, dict):
        for key in ("data", "interactions", "aes_key"):
            if isinstance(data.get(key), list):
                records = data[key]
                break
        else:
            records = [data] if data else []
    elif isinstance(data, list):
        records = data
    out = []
    for r in records:
        if not isinstance(r, dict):
            continue
        out.append({
            "protocol": str(r.get("protocol") or "unknown"),
            "full_id": str(r.get("full-id") or r.get("full_id")
                           or r.get("unique-id") or r.get("unique_id")
                           or r.get("payload_id") or ""),
            "remote_address": str(r.get("remote-address")
                                  or r.get("remote_address")
                                  or r.get("from_ip") or ""),
            "timestamp": str(r.get("time-stamp") or r.get("timestamp")
                             or r.get("time") or ""),
        })
    return out


def matching(records: List[Dict], token: str) -> List[Dict]:
    return [r for r in records if token and token in r["full_id"]]


class InteractshOobPlugin(Plugin):
    id = "interactsh_oob"
    label = "Interactsh OOB Verification"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = ("Blind SSRF/XXE-class verification via interactsh: "
                   "injects only a callback URL and reports ONLY "
                   "callbacks actually observed at poll time.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("needs active mode (injects callback "
                                 "URLs)")
        oob_domain = (os.environ.get(ENV_DOMAIN) or "").strip()
        if not oob_domain:
            return self._skipped(
                f"needs config: set {ENV_DOMAIN} to your interactsh "
                f"domain - without it nothing is injected (a "
                f"placeholder callback can never verify)")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        try:
            html, page_url = await fetch_homepage(ctx, base)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:160]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        token = make_token(ctx.run_id)
        host = f"{token}.{oob_domain}"
        callback = f"http://{host}/"
        urls = param_urls(html, page_url, domain, ctx)
        injected = 0
        injected_at: List[str] = []
        for u in sample_urls(urls, MAX_URLS):
            parts = urlparse(u)
            params = parse_qsl(parts.query)
            if not params:
                continue
            name = params[0][0]
            purl = probe_url(parts, params, name, callback)
            try:
                await fetch(ctx.http, ctx.limiter, "GET", purl,
                            timeout=10, max_retries=0)
                injected += 1
                injected_at.append(f"{parts.path}?{name}")
            except Exception:
                continue
        # One header-based injection at the homepage (Referer is the
        # classic blind-XXE/SSRF logging path).
        try:
            await fetch(ctx.http, ctx.limiter, "GET", base,
                        timeout=10, max_retries=0,
                        headers={"Referer": callback,
                                 "X-Forwarded-For": callback})
            injected += 1
            injected_at.append("homepage headers")
        except Exception:
            pass

        poll_url = (os.environ.get(ENV_POLL) or "").strip()
        verified: List[Dict] = []
        if poll_url and injected:
            try:
                pr = await fetch(ctx.http, ctx.limiter, "GET",
                                 poll_url.replace("{token}", token),
                                 timeout=12, max_retries=0)
                verified = matching(
                    parse_interactions(json.loads(pr.text)), token)
            except Exception:
                verified = []
        for rec in verified:
            remote = rec["remote_address"] or "unknown host"
            when = rec["timestamp"] or "poll time"
            findings.append(self._f(
                "web", "oob_interaction_verified",
                f"HIGH: VERIFIED out-of-band interaction "
                f"({rec['protocol']}) from {remote} at {when} "
                f"for this run's callback {host} - the target fetched "
                f"a scanner-supplied URL (blind SSRF/XXE class "
                f"confirmed, not just suspected).",
                source="interactsh poll verification",
                source_url=f"http://{host}/", confidence=95,
                evidence={"severity": "high",
                          "remediation": REMEDIATION,
                          "interaction": rec,
                          "injected_at": injected_at},
                passive=False, bounty_value="high"))

        if verified:
            reason = (f"{len(verified)} verified interaction(s) after "
                      f"{injected} callback injection(s)")
        elif poll_url:
            reason = (f"{injected} callback injection(s) sent; no "
                      f"interaction observed at poll time (not a "
                      f"finding - absence of a callback is not proof "
                      f"of safety)")
        else:
            reason = (f"{injected} callback injection(s) sent; set "
                      f"{ENV_POLL} to poll for verification - "
                      f"unverified injections are not findings")
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
