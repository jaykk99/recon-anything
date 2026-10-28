"""OpenID Connect discovery document audit plugin.

Fetches the target's standardized OIDC discovery document
(/.well-known/openid-configuration, RFC 8414 / OpenID Connect
Discovery 1.0) and parses it — it does not authenticate, send
credentials, or probe any endpoint it finds.

What it reports:
- the discovery document exists, with its issuer and endpoint inventory
- issuer-host mismatch: the document names an issuer on a different
  host than the target (a pivot to another auth service, or a
  misconfiguration worth checking)
- every endpoint the document advertises (authorization, token,
  userinfo, JWKS, registration, revocation, end-session), published
  to the discovery bus so chain plugins can use them
- weak configuration: implicit flow response types, the resource-owner
  password grant, and PKCE advertised without S256

Passive: one plain GET of a standardized public document. No login
attempts, no token requests, no brute-forcing.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, Target

DISCOVERY_PATH = "/.well-known/openid-configuration"

# endpoint field -> human label, in the order they appear in the doc
ENDPOINT_FIELDS = (
    ("authorization_endpoint", "authorization"),
    ("token_endpoint", "token"),
    ("userinfo_endpoint", "userinfo"),
    ("jwks_uri", "JWKS"),
    ("registration_endpoint", "registration"),
    ("revocation_endpoint", "revocation"),
    ("end_session_endpoint", "end-session"),
)

WEAK_RESPONSE_TYPES = ("token", "id_token")  # implicit flow, no code


def issuer_host(issuer: str) -> str:
    """Host part of an issuer URL, lowercased, or '' when unparseable."""
    try:
        return (urlparse(issuer).hostname or "").lower()
    except Exception:
        return ""


def discovery_issues(doc: Dict[str, Any], domain: str) -> List[Dict[str, Any]]:
    """Pure analysis of a parsed discovery document.

    Returns finding dicts (key, value, severity, confidence) so the
    logic is unit-testable without HTTP. The caller turns these into
    Finding objects.
    """
    issues: List[Dict[str, Any]] = []
    issuer = doc.get("issuer", "") if isinstance(doc, dict) else ""
    if issuer:
        host = issuer_host(issuer)
        if host and domain and host != domain.lower():
            issues.append({
                "key": "oidc_issuer_mismatch",
                "value": (f"OIDC issuer is on a different host than the "
                          f"target: {issuer}"),
                "severity": "medium",
                "confidence": 75,
                "evidence": {"issuer": issuer, "target_domain": domain},
            })

    response_types = doc.get("response_types_supported") or []
    if isinstance(response_types, list):
        implicit = sorted({t for t in response_types
                           if any(w in t.split() for w in WEAK_RESPONSE_TYPES)
                           and "code" not in t.split()})
        if implicit:
            issues.append({
                "key": "oidc_implicit_flow",
                "value": ("OIDC implicit flow enabled: response types "
                          f"{', '.join(implicit)} return tokens without "
                          f"an authorization code"),
                "severity": "medium",
                "confidence": 80,
                "evidence": {"response_types": implicit},
            })

    grant_types = doc.get("grant_types_supported") or []
    if isinstance(grant_types, list) and "password" in grant_types:
        issues.append({
            "key": "oidc_password_grant",
            "value": ("OIDC resource-owner password grant enabled: "
                       "clients may collect user passwords directly"),
            "severity": "medium",
            "confidence": 80,
            "evidence": {"grant_types": grant_types},
        })

    methods = doc.get("code_challenge_methods_supported")
    if isinstance(methods, list) and methods and "S256" not in methods:
        issues.append({
            "key": "oidc_no_pkce_s256",
            "value": ("OIDC PKCE advertised without S256: code challenge "
                       f"methods are {', '.join(methods)}"),
            "severity": "low",
            "confidence": 75,
            "evidence": {"code_challenge_methods": methods},
        })
    return issues


class OpenIdDiscoveryPlugin(Plugin):
    id = "openid_discovery"
    label = "OIDC Discovery"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Parse /.well-known/openid-configuration: issuer, "
                   "endpoints, and weak OIDC configuration.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        url = base + DISCOVERY_PATH
        try:
            resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=12)
        except Exception:
            resp = None
        if resp is None or resp.status_code != 200:
            return self._ok([], "no OIDC discovery document found")
        try:
            doc = resp.json()
        except Exception:
            return self._ok([], "OIDC discovery document is not valid JSON")
        if not isinstance(doc, dict) or not doc:
            return self._ok([], "OIDC discovery document is empty")

        findings = []
        endpoints: List[Tuple[str, str]] = []
        for field, label in ENDPOINT_FIELDS:
            value = doc.get(field)
            if isinstance(value, str) and value.startswith("http"):
                endpoints.append((label, value))
        issuer = doc.get("issuer", "")
        summary = (f"OIDC discovery document found (issuer: {issuer or 'unknown'}, "
                   f"{len(endpoints)} endpoints advertised)")
        findings.append(self._f(
            "web", "oidc_discovery", summary,
            source="OIDC discovery", source_url=url, confidence=85,
            passive=True, evidence={
                "severity": "low",
                "issuer": issuer,
                "endpoints": [label for label, _ in endpoints],
                "scopes_supported": doc.get("scopes_supported") or [],
                "grant_types_supported": doc.get("grant_types_supported") or [],
                "response_types_supported": doc.get("response_types_supported") or [],
            }))
        for label, endpoint_url in endpoints:
            findings.append(self._f(
                "web", "oidc_endpoint",
                f"OIDC {label} endpoint: {endpoint_url}",
                source="OIDC discovery", source_url=url, confidence=85,
                passive=True, evidence={"severity": "low",
                                        "endpoint_type": label}))
            ctx.publish("endpoints", endpoint_url)
        for issue in discovery_issues(doc, domain):
            findings.append(self._f(
                "web", issue["key"], issue["value"],
                source="OIDC discovery", source_url=url,
                confidence=issue["confidence"], passive=True,
                evidence={"severity": issue["severity"],
                          **issue.get("evidence", {})}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"parsed OIDC discovery document ({len(findings)} findings)")
        res.duration_ms = dur
        return res
