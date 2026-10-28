"""Finding-chaining executor (phase 2, graph group).

Turns the discovery bus into audited follow-up work, on the same
run/target only, deeper than pattern matches. See
app/finding_chain.py for the full rule map, depth limit (2),
caps, and scope rules.

What this plugin itself executes, through ctx.probe's cached,
single-flight path (so a URL probed by an earlier plugin costs
nothing again):
- depth 1: subdomain, endpoint, and JS items are probed for real:
  subdomain -> chain_subdomain_live, endpoint/JS -> chain_endpoint_
  status when the probe answers 2xx/3xx. This confirms public
  exposure instead of stopping at the pattern that found the item.
- depth 2: links actually present in a depth-1 probe's text (href,
  src, or bare same-target URLs, including config/JS references
  the page itself links to) are probed once more, same target
  only, finding key chain_subfinding_link when live. Depth 2 is
  never followed further.

What it only plans (delegated, not duplicated):
- contract/wallet items -> contract_audit / chain_osint, which run
  in their own phase-2 slots and already do the read-only chain
  enrichment. This plugin emits a chain_plan finding naming the
  followup, so the chain is visible, and makes no chain API call.
- email/graphql/tech items -> their phase-2 consumers, same deal.

Hard boundaries, all enforced here and in finding_chain.py:
- only URLs actually present in probed text are followed; paths
  are never guessed or brute-forced.
- no host outside the target domain, crypto.com refused outright.
- no login, no auth bypass, no credential use: a URL carrying
  userinfo is skipped, and a secret-shaped item is masked, never
  probed and never shown raw.
- it publishes NOTHING back into the bus: a chained result never
  spawns another chain step, so chaining cannot loop or fan out.
  A target that exposes no secret gets no secret finding, honestly.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..finding_chain import (MAX_CHAIN_PROBES, MAX_SUBLINKS_PER_ITEM,
                             in_scope, is_blocked_domain, plan_from_bus)
from .base import Cost, Ctx, Plugin, PluginResult, Target

_LINK_RES = (
    re.compile(r'''(?:href|src)\s*=\s*["']([^"']+)["']''', re.I),
    re.compile(r'''(https?://[^\s"'<>]+)'''),
)


def extract_links(text: str, base_url: str, domain: str) -> List[str]:
    """Same-target URLs actually present in text, deduped, in order.

    Never invents a path: only href/src values and bare URLs that
    the text itself contains. Credential URLs (userinfo present)
    and off-target URLs are dropped here, before any probe.
    """
    out: List[str] = []
    for rx in _LINK_RES:
        for m in rx.finditer(text or ""):
            raw = m.group(1).strip()
            if raw.startswith(("javascript:", "mailto:", "tel:", "data:",
                               "#")):
                continue
            try:
                url = urljoin(base_url, raw)
                if urlparse(url).username is not None:
                    continue
            except Exception:
                continue
            if url not in out and in_scope(url, domain):
                out.append(url)
    return out

# Rules this plugin executes itself (probe) vs only plans (delegated).
_EXECUTED = {"cmd_http"}
_PLANNED = {"cmd_dns", "endpointauth", "jsdeep", "contract_audit",
            "chain_osint", "email_breach", "keyleak", "graphql_deep",
            "appintel"}


class ChainFollowupsPlugin(Plugin):
    id = "chain_followups"
    label = "Finding Chaining"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    description = ("Phase-2 chaining: every phase-1 finding feeds a "
                   "real follow-up probe or a named follow-up plugin, "
                   "same target only, depth 2, capped, fully "
                   "audit-logged. Links in probed pages are followed "
                   "one level deeper; secrets are never used.")
    phase = 2
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        if is_blocked_domain(domain):
            res = self._skipped("blocked target domain: chaining refused")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        bus = {k: ctx.consume(k) for k in (
            "subdomains", "endpoints", "js", "contract_addresses",
            "emails", "graphql_endpoints", "tech")}
        plan, audit = plan_from_bus(bus, domain, depth=1)
        findings: List = []
        executed = 0
        probed_urls = set()
        for step in plan:
            plugin = step["followup_plugin"]
            if plugin in _PLANNED:
                findings.append(self._f(
                    "graph", "chain_plan",
                    f"Chain plan: {step['command']}",
                    source=self.label, confidence=70,
                    evidence={"detector": self.id, "source": step["source"],
                              "item": step["item"],
                              "followup_plugin": plugin,
                              "command": step["command"], "depth": 1,
                              "status": "planned_delegated"}))
                continue
            if plugin not in _EXECUTED or executed >= MAX_CHAIN_PROBES:
                continue
            item = step["item"]
            if step["source"] == "subdomains" and not item.startswith("http"):
                # A subdomain item is a hostname, not a path: probing it
                # as a path on the apex host would hit the wrong URL.
                url = f"https://{item}/"
            else:
                url = item if item.startswith("http") else urljoin(
                    f"https://{domain}/", item.lstrip("/"))
            if not in_scope(url, domain) or url in probed_urls:
                continue
            try:
                probe = await ctx.probe(url, timeout=8)
                status = probe.get("status", 0) if isinstance(probe, dict) else 0
                text = probe.get("text", "") if isinstance(probe, dict) else ""
            except Exception:
                status, text = 0, ""
            probed_urls.add(url)
            executed += 1
            audit.append({"source": step["source"], "item": item,
                          "followup_plugin": plugin,
                          "command": step["command"], "depth": 1,
                          "status": "executed", "http_status": status})
            if status and 200 <= status < 400:
                if step["source"] == "subdomains":
                    findings.append(self._f(
                        "graph", "chain_subdomain_live",
                        f"Chained probe live: {item} -> HTTP {status}",
                        source=self.label, source_url=url, confidence=75,
                        evidence={"detector": self.id,
                                  "followup_plugin": plugin,
                                  "command": step["command"], "depth": 1,
                                  "http_status": status}))
                else:
                    findings.append(self._f(
                        "graph", "chain_endpoint_status",
                        f"Chained probe: {item} -> HTTP {status}",
                        source=self.label, source_url=url, confidence=70,
                        evidence={"detector": self.id,
                                  "followup_plugin": plugin,
                                  "command": step["command"], "depth": 1,
                                  "http_status": status}))
                # Depth 2: follow links actually present in this
                # probed page, same target only, once, then stop.
                # No guessed paths, no credentials, no off-target hosts.
                for sub in extract_links(text, url, domain)[:MAX_SUBLINKS_PER_ITEM]:
                    if executed >= MAX_CHAIN_PROBES or sub in probed_urls:
                        continue
                    try:
                        sub_probe = await ctx.probe(sub, timeout=8)
                        sub_status = sub_probe.get("status", 0) \
                            if isinstance(sub_probe, dict) else 0
                    except Exception:
                        sub_status = 0
                    probed_urls.add(sub)
                    executed += 1
                    audit.append({"source": step["source"], "item": sub,
                                  "followup_plugin": plugin,
                                  "command": f"GET {sub} (depth-2 follow)",
                                  "depth": 2, "status": "executed",
                                  "http_status": sub_status,
                                  "followed_from": url})
                    if sub_status and 200 <= sub_status < 400:
                        findings.append(self._f(
                            "graph", "chain_subfinding_link",
                            f"Chained sub-finding: {sub} -> HTTP {sub_status}",
                            source=self.label, source_url=sub,
                            confidence=70,
                            evidence={"detector": self.id,
                                      "followup_plugin": plugin,
                                      "depth": 2,
                                      "http_status": sub_status,
                                      "followed_from": url}))
        # Audit trail on the bus (for later phases / reporting) and in
        # the run result reason; never published as new bus items, so
        # chaining cannot re-trigger itself.
        try:
            ctx.shared.setdefault("chain_audit", []).extend(audit)
        except Exception:
            pass
        res = self._ok(
            findings,
            f"{len(plan)} chained step(s) planned, {executed} probe(s) "
            f"executed, {len(findings)} chain finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
