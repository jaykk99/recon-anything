"""OAuth redirect URI validator (variant of bounty): bounty's
open-redirect probe appends generic redirect params to the
homepage. This delta is OAuth/OIDC-specific, over operator-supplied
client registrations / discovery documents (or the target's own
/.well-known/openid-configuration, fetched read-only):

- registered redirect_uri with a wildcard host/path
- http:// redirect_uri for a non-localhost host
- an observed authorize URL whose redirect_uri is NOT in the
  registered list (unregistered host / subdomain differential)
- discovery advertising the implicit flow (response_type token)

Validation is differential analysis of supplied/test-client data;
no authorize flow is driven against a third-party IdP.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, text_of

_URI_RE = re.compile(r"https?://[^\s\"'<>]+")
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")


def _registered_and_observed(text: str):
    registered: List[str] = []
    observed: List[str] = []
    try:
        obj = json.loads(text)
    except Exception:
        obj = None
    if isinstance(obj, dict):
        for key in ("redirect_uris", "registered", "redirectUris"):
            val = obj.get(key)
            if isinstance(val, list):
                registered.extend(str(v) for v in val)
        for key in ("observed_authorize_url", "authorize_url",
                    "observed"):
            val = obj.get(key)
            if isinstance(val, str):
                observed.append(val)
        if obj.get("response_types_supported"):
            observed.append("RESP_TYPES:" + " ".join(
                str(v) for v in obj["response_types_supported"]))
    if not registered:
        m = re.search(r"(?is)redirect_uris?\W{1,4}\[(.*?)\]", text)
        if m:
            registered.extend(_URI_RE.findall(m.group(1)))
    for uri in _URI_RE.findall(text):
        if "redirect_uri=" in uri or "/authorize" in uri:
            observed.append(uri)
    return registered, observed


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    text = text_of(data)
    if not text:
        return hits
    registered, observed = _registered_and_observed(text)
    for uri in registered:
        host = (urlparse(uri).hostname or "")
        if "*" in uri:
            hits.append({
                "key": "oauth_redirect_uri_wildcard",
                "severity": "high",
                "value": f"Registered OAuth redirect_uri contains "
                         f"a wildcard: {uri[:120]} - authorization "
                         "codes can be redirected to attacker hosts",
                "evidence": {"redirect_uri": uri[:200],
                             "remediation": "Register exact-match "
                             "redirect URIs only (RFC 6749 / OAuth "
                             "Security BCP); wildcards are not "
                             "permitted for confidential clients."}})
        elif uri.lower().startswith("http://") and \
                host not in _LOCAL_HOSTS:
            hits.append({
                "key": "oauth_redirect_uri_cleartext",
                "severity": "medium",
                "value": f"Registered OAuth redirect_uri is "
                         f"cleartext http: {uri[:120]}",
                "evidence": {"redirect_uri": uri[:200],
                             "remediation": "Use https redirect URIs "
                             "(loopback excepted) so codes are not "
                             "sent over cleartext."}})
    reg_hosts = {(urlparse(u).hostname or "") for u in registered}
    for obs in observed:
        if obs.startswith("RESP_TYPES:"):
            if re.search(r"\btoken\b", obs) and "code" in obs:
                hits.append({
                    "key": "oauth_implicit_flow_advertised",
                    "severity": "medium",
                    "value": "OIDC discovery advertises the implicit "
                             "flow (response_type containing token) "
                             "alongside code",
                    "evidence": {"remediation": "Disable implicit "
                                 "flow; authorization code + PKCE "
                                 "only."}})
            continue
        qs = parse_qs(urlparse(obs).query)
        for cand in qs.get("redirect_uri", []):
            chost = (urlparse(cand).hostname or "")
            if registered and chost and chost not in reg_hosts:
                hits.append({
                    "key": "oauth_redirect_uri_unregistered_host",
                    "severity": "high",
                    "value": f"Observed authorize request uses "
                             f"redirect_uri host '{chost}' which is "
                             f"not among the registered hosts "
                             f"{sorted(reg_hosts)[:5]} - the client "
                             "accepts unregistered redirect targets",
                    "evidence": {"redirect_uri": cand[:200],
                                 "remediation": "Enforce exact "
                                 "string matching of redirect_uri "
                                 "against the registration; reject "
                                 "unregistered hosts and subdomains."}})
            if "#" in cand:
                hits.append({
                    "key": "oauth_redirect_uri_fragment",
                    "severity": "low",
                    "value": "redirect_uri in an authorize request "
                             "carries a fragment component",
                    "evidence": {"redirect_uri": cand[:200],
                                 "remediation": "Reject redirect_uri "
                                 "values containing fragments."}})
    # Dedupe by key.
    seen, out = set(), []
    for h in hits:
        if h["key"] not in seen:
            seen.add(h["key"])
            out.append(h)
    return out[:10]


class OauthRedirectUriValidatorPlugin(Plugin):
    id = "oauth_redirect_uri_validator"
    label = "OAuth Redirect URI Validator"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "api"
    phase = 2
    description = ("OAuth/OIDC-specific redirect_uri validation "
                   "over supplied registrations / discovery docs: "
                   "wildcards, cleartext URIs, unregistered-host "
                   "differentials, implicit flow. Test clients only.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "api",
                          ("oauth_configs", "oidc_configs"))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        # Live read-only lane: the target's own discovery document.
        base = (target.normalized or "").rstrip("/")
        if not base.startswith("http"):
            base = "https://" + base
        try:
            page = await ctx.fetch_page(
                base + "/.well-known/openid-configuration")
        except Exception:
            page = None
        if not page or not page.get("text"):
            return self._ok([], "no supplied OAuth config and no "
                            "discovery document on the target")
        findings = []
        for hit in analyze(page["text"].encode("utf-8", "ignore"),
                           "openid-configuration"):
            ev = {"severity": hit["severity"]}
            ev.update(hit.get("evidence") or {})
            findings.append(self._f("api", hit["key"], hit["value"],
                                    source="openid-configuration",
                                    confidence=80, evidence=ev))
        return self._ok(findings, "discovery document analysed")
