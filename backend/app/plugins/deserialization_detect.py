"""Insecure-deserialization EXPOSURE detection (Ysoserial surface).

DETECTION ONLY (Tier-6 rule) - the strongest line in this tier:
Ysoserial's gadget chains are never built, loaded, or sent. This
plugin only maps the surface a gadget chain would need:

  1. ViewState MAC posture: a homepage __VIEWSTATE with NO
     __EVENTVALIDATION field alongside it is the classic indicator
     that ASP.NET event validation / ViewState MAC protection is
     off, which is what makes a forged ViewState deserializable at
     all. (Presence of ViewState alone is NOT flagged - the fmtpack
     plugin already reports that passively.)
  2. Known deserialization endpoints: a short list of famous
     invoker/serialization servlet paths, flagged only when the
     response carries the endpoint's own marker text (a bare 200 or
     SPA shell proves nothing).
  3. Input-side serialized parameters: links/forms the target itself
     advertises whose parameter VALUES are serialized-object blobs
     (Java rO0AB, PHP O:n:, .NET BinaryFormatter AAEAAAD, Python
     pickle gASV) - i.e. serialized data flowing IN from users,
     which is the exploitable direction.

Distinct remainder vs existing plugins (checked against master 847):
fx_deserialization_surface (fmtpack.py) is PASSIVE and OUTPUT-side:
it fingerprints serialized objects in traffic the target sends
(Set-Cookie values, response bodies) plus ViewState presence. It
does not assess ViewState MAC posture, probe invoker endpoints, or
inspect input-side parameter values. Those three are this plugin's
scope; marker-in-cookie/body detection is deliberately not repeated.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import parse_qsl, urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import fetch_homepage

REMEDIATION = ("Never deserialize untrusted input. Replace native "
               "serialized objects in parameters with signed tokens "
               "or plain JSON, enforce ViewState MAC + encryption "
               "(and keep machineKey secret), and remove invoker "
               "servlets from production deployments.")

# Famous deserialization entry points: (path, marker regex, label)
ENDPOINTS = [
    ("/invoker/JMXInvokerServlet", r"JMXInvoker|javax\.management|"
     r"org\.jboss", "JBoss JMX invoker servlet"),
    ("/invoker/EJBInvokerServlet", r"EJBInvoker|org\.jboss",
     "JBoss EJB invoker servlet"),
    ("/jmx-console/HtmlAdaptor", r"JMX MBean|HtmlAdaptor|jboss",
     "JBoss JMX console"),
    ("/web-console/Invoker", r"Invoker|org\.jboss",
     "JBoss web console invoker"),
]

# Serialized-object markers inside a parameter VALUE.
INPUT_MARKERS = [
    (re.compile(r"rO0AB[A-Za-z0-9+/=]{8,}"), "Java serialized object"),
    (re.compile(r"O:\d+:\"[^\"]{1,60}\":\d+:\{"), "PHP serialized object"),
    (re.compile(r"AAEAAAD[A-Za-z0-9+/=]{8,}"),
     ".NET BinaryFormatter payload"),
    (re.compile(r"gASV[A-Za-z0-9+/=]{6,}"), "Python pickle payload"),
]

_VIEWSTATE_RX = re.compile(r"__VIEWSTATE", re.I)
_EVENTVALIDATION_RX = re.compile(r"__EVENTVALIDATION", re.I)
_LINK_RX = re.compile(r"""(?:href|action)\s*=\s*["']([^"']+)["']""",
                      re.I)


class DeserializationDetectPlugin(Plugin):
    id = "deserialization_detect"
    label = "Deserialization Exposure"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = ("Insecure-deserialization surface only: ViewState "
                   "MAC posture, known invoker endpoints, serialized "
                   "blobs in input parameters. No gadget is ever "
                   "built or sent.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        mode = self.module_mode(ctx)
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        try:
            html, page_url = await fetch_homepage(ctx, base)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:160]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        html = html or ""

        # 1. ViewState MAC posture (passive read of the homepage).
        if _VIEWSTATE_RX.search(html) and \
                not _EVENTVALIDATION_RX.search(html):
            findings.append(self._f(
                "web", "viewstate_mac_disabled",
                "HIGH: ASP.NET __VIEWSTATE present with NO "
                "__EVENTVALIDATION field - the posture that indicates "
                "ViewState MAC / event validation is disabled, so a "
                "forged ViewState would be deserialized unchecked.",
                source="homepage form analysis", source_url=page_url,
                confidence=65,
                evidence={"severity": "high",
                          "remediation": REMEDIATION},
                passive=True, bounty_value="high"))

        if mode == "passive":
            res = self._ok(findings, "passive checks only")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # 2. Known deserialization endpoints (marker-verified).
        root = base.rstrip("/")
        for path, marker, label in ENDPOINTS:
            url = root + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url,
                                timeout=8, max_retries=0,
                                follow_redirects=False)
                body = r.text[:60000]
            except Exception:
                continue
            if r.status_code in (200, 401, 403) and \
                    re.search(marker, body, re.I):
                findings.append(self._f(
                    "web", "deser_endpoint_exposed",
                    f"HIGH: {label} reachable at {path} "
                    f"(HTTP {r.status_code}, endpoint marker in "
                    f"response) - a known Java deserialization entry "
                    f"point is exposed.",
                    source="deserialization endpoint probe",
                    source_url=url, confidence=85,
                    evidence={"severity": "high",
                              "remediation": REMEDIATION,
                              "endpoint": path},
                    passive=False, bounty_value="high"))

        # 3. Input-side serialized parameter values in the target's
        # own links/forms (+ discovery-bus endpoints).
        candidates = [urljoin(page_url, m.group(1))
                      for m in _LINK_RX.finditer(html)]
        candidates += [str(x) for x in ctx.consume("endpoints")]
        seen = set()
        for u in candidates[:40]:
            parts = urlparse(u)
            for name, val in parse_qsl(parts.query):
                if len(val) < 8:
                    continue
                for rx, label in INPUT_MARKERS:
                    if rx.search(val):
                        dedupe = (parts.path, name, label)
                        if dedupe in seen:
                            continue
                        seen.add(dedupe)
                        findings.append(self._f(
                            "web", "deser_input_surface",
                            f"{label} supplied as input parameter "
                            f"'{name}' at {parts.path} - serialized "
                            f"data flows from users into the "
                            f"application (the deserialization attack "
                            f"surface).",
                            source="input parameter analysis",
                            source_url=u, confidence=70,
                            evidence={"severity": "medium",
                                      "remediation": REMEDIATION,
                                      "param": name, "format": label},
                            passive=True, bounty_value="medium"))
                        break

        res = self._ok(findings, "deserialization surface mapped")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
