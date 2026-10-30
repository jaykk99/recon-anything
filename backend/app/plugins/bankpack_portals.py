"""Bank web-app detectors (fin_* pack, portals family).

Eight detection-only checks on a bank's public web surface: leaked
front-end configuration, partner/agent portals, API documentation
carrying live-looking example credentials, mobile-banking config
files, OIDC / SAML federation metadata leaking internal hosts,
branch/ATM locator APIs returning internal fields, and treasury /
corporate portals. Read-only GETs only - nothing here logs in,
submits a form, or uses a credential it finds.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .bankpack_util import (FinPlugin, collect_texts, fetch_paths,
                            find_internal_leaks, looks_like_placeholder,
                            mask_secret, parse_json_text)
from .base import Ctx, PluginResult, Target

# ---------------------------------------------------------------------------
# 1. fin_js_config - banking front-end config objects leaking internals
# ---------------------------------------------------------------------------

_ENV_RE = re.compile(
    r"""["']?(?:env|environment|stage)["']?\s*[:=]\s*["']"""
    r"""(production|prod|live)["']""", re.IGNORECASE)
_CONFIG_HINT_RE = re.compile(
    r"(__[A-Z_]*CONFIG|window\.\w*[Cc]onfig|appConfig|BANK_CONFIG|"
    r"environment\s*[:=]|apiBase|apiHost|idpHost)", re.IGNORECASE)


def find_config_leaks(text: str) -> List[Dict]:
    """Config-object leaks in a page/script.

    A leak needs BOTH a config context (a named config object, an
    apiBase/apiHost assignment, an env marker) AND internal material
    (RFC1918 IP, internal hostname, loopback URL). Production env
    markers raise severity.
    """
    out: List[Dict] = []
    if not text or not _CONFIG_HINT_RE.search(text):
        return out
    prod = bool(_ENV_RE.search(text))
    for kind, value in find_internal_leaks(text):
        out.append({"kind": kind, "value": value, "production": prod})
    return out


class FinJsConfigPlugin(FinPlugin):
    id = "fin_js_config"
    label = "Banking JS Config Leak"
    description = ("Front-end banking config objects (window.__CONFIG__, "
                   "apiBase, env blocks) that publish internal API hosts, "
                   "IdP hosts or RFC1918 addresses to every visitor.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        texts = await collect_texts(ctx, base, extra_paths=(
            "/config.js", "/assets/config.js", "/static/config.js"))
        findings = []
        for url, text in texts:
            for leak in find_config_leaks(text):
                sev = "high" if leak["production"] else "medium"
                findings.append(self.fin_finding(
                    "fin_js_config_leak",
                    f"Banking front-end config on {url} exposes internal "
                    f"{leak['kind'].replace('_', ' ')} {leak['value']}"
                    + (" in a production config" if leak["production"]
                       else ""),
                    url, sev,
                    "Move internal endpoints out of shipped front-end "
                    "config; the browser bundle must only contain public "
                    "API hosts. Rotate anything secret the config held.",
                    production=leak["production"],
                    leak_kind=leak["kind"], leaked_value=leak["value"]))
        if not findings:
            return self._ok([], f"no config leaks in shipped JS on {domain}")
        return self._ok(findings, f"{len(findings)} config leak(s) on {domain}")


# ---------------------------------------------------------------------------
# 2. fin_partner_portal - partner / agent / broker portals
# ---------------------------------------------------------------------------

PARTNER_PATHS = (
    "/partner", "/partners", "/partner-login", "/partnerportal",
    "/agent", "/agents", "/agent-login", "/broker", "/brokers",
    "/dealer-portal", "/advisor", "/advisor-login",
)
PARTNER_FINGERPRINTS = (
    ("Partner Portal", r"partner\s+portal"),
    ("Agent Portal", r"agent\s+(portal|login|sign\s?in)"),
    ("Broker Portal", r"broker\s+(portal|login)"),
    ("Dealer Portal", r"dealer\s+(portal|login)"),
    ("Advisor Portal", r"(advisor|adviser)\s+portal"),
    ("Partner Login", r"(partner|brokers?|dealers?)\s+log\s?in"),
)


def match_partner_portal(text: str) -> List[str]:
    low = (text or "").lower()
    return [name for name, pat in PARTNER_FINGERPRINTS
            if re.search(pat, low)]


class FinPartnerPortalPlugin(FinPlugin):
    id = "fin_partner_portal"
    label = "Partner / Agent Portal Exposure"
    description = ("Partner, agent, broker and advisor portals reachable "
                   "on the public bank domain. Existence + fingerprint "
                   "only; no login is attempted.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, PARTNER_PATHS):
            hits = match_partner_portal(text)
            if hits:
                findings.append(self.fin_finding(
                    "fin_partner_portal",
                    f"Partner-channel portal exposed at {url}: "
                    f"{', '.join(hits)}",
                    url, "medium",
                    "Confirm this portal is meant to be public; enforce "
                    "MFA and IP allowlisting for partner channels and "
                    "keep it off the retail domain where possible.",
                    portals=hits))
        if not findings:
            return self._ok([], f"no partner portals found on {domain}")
        return self._ok(findings,
                        f"{len(findings)} partner portal page(s) on {domain}")


# ---------------------------------------------------------------------------
# 3. fin_api_docs_secrets - API docs carrying live-looking credentials
# ---------------------------------------------------------------------------

DOC_PATHS = (
    "/api/docs", "/api-docs", "/openbanking/docs", "/open-banking/docs",
    "/banking/api-docs", "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/openapi.json", "/open-banking/swagger.json", "/developer/docs",
)
_CRED_ASSIGN_RE = re.compile(
    r"""(client_secret|clientSecret|api[_-]?key|x-api-key|apikey|"""
    r"""access[_-]?token|secret[_-]?key)["']?\s*[:=]\s*["']"""
    r"""([A-Za-z0-9_\-\.]{16,})["']""", re.IGNORECASE)


def find_doc_credentials(text: str) -> List[Tuple[str, str]]:
    """(field, raw value) credential-looking examples inside docs.

    Placeholders (your-key, example..., xxx) are skipped - this fires
    on values shaped like real issued credentials.
    """
    out: List[Tuple[str, str]] = []
    seen = set()
    for m in _CRED_ASSIGN_RE.finditer(text or ""):
        field, value = m.group(1), m.group(2)
        if looks_like_placeholder(value):
            continue
        key = (field.lower(), value)
        if key not in seen:
            seen.add(key)
            out.append((field, value))
    return out


class FinApiDocsSecretsPlugin(FinPlugin):
    id = "fin_api_docs_secrets"
    label = "API Docs Credential Leak"
    description = ("Banking API documentation (Swagger/OpenAPI/developer "
                   "docs) whose examples embed live-looking client "
                   "secrets, API keys or tokens. Values are masked.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, DOC_PATHS):
            for field, value in find_doc_credentials(text):
                masked, fp = mask_secret(value)
                findings.append(self.fin_finding(
                    "fin_api_docs_credential",
                    f"API documentation at {url} embeds a live-looking "
                    f"{field}: {value}",
                    url, "high",
                    "Scrub real credentials from documentation examples; "
                    "use obviously fake placeholders and rotate the "
                    "exposed credential.",
                    field=field, masked_value=masked, full_value=value,
                    fingerprint=fp))
        if not findings:
            return self._ok([], f"no credentials in API docs on {domain}")
        return self._ok(findings,
                        f"{len(findings)} doc credential(s) on {domain}")


# ---------------------------------------------------------------------------
# 4. fin_mobile_config - served mobile-banking config files
# ---------------------------------------------------------------------------

MOBILE_CONFIG_PATHS = (
    "/config.json", "/app-config.json", "/appconfig.json",
    "/mobile/config.json", "/mobile-config.json",
    "/assets/app-config.json", "/static/config.json",
)
_INTERNAL_HOST_RE = re.compile(
    r"(?:[a-z0-9-]+\.)+(?:local|lan|corp|internal|intranet)\b|"
    r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    re.IGNORECASE)


def analyze_mobile_config(data) -> List[Dict]:
    """Sensitive entries in a served JSON app config (parsed walk)."""
    out: List[Dict] = []
    if not isinstance(data, dict):
        return out

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{path}.{k}" if path else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            kl = path.lower()
            if _INTERNAL_HOST_RE.search(node):
                out.append({"field": path, "issue": "internal_host",
                            "value": node})
            if any(s in kl for s in ("apikey", "api_key", "secret",
                                    "token", "password")) \
                    and len(node) >= 12 and not looks_like_placeholder(node):
                masked, fp = mask_secret(node)
                out.append({"field": path, "issue": "embedded_secret",
                            "value": node, "masked_value": masked,
                            "fingerprint": fp})

    walk(data)
    return out


class FinMobileConfigPlugin(FinPlugin):
    id = "fin_mobile_config"
    label = "Mobile Banking Config Exposure"
    description = ("JSON config files served for the mobile-banking app "
                   "that disclose internal backend hosts or embed API "
                   "keys/secrets. Secret values are shown in full.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base,
                                               MOBILE_CONFIG_PATHS):
            data = parse_json_text(text)
            for issue in analyze_mobile_config(data):
                sev = "high" if issue["issue"] == "embedded_secret" \
                    else "medium"
                findings.append(self.fin_finding(
                    "fin_mobile_config_leak",
                    f"Mobile config {url} field {issue['field']}: "
                    f"{issue['issue'].replace('_', ' ')} {issue['value']}",
                    url, sev,
                    "Serve mobile config with public endpoints only; "
                    "never ship secrets in app config - anything in it "
                    "is public. Rotate exposed keys.",
                    field=issue["field"], issue=issue["issue"],
                    full_value=(issue["value"]
                                if issue["issue"] == "embedded_secret"
                                else None),
                    fingerprint=issue.get("fingerprint")))
        if not findings:
            return self._ok([], f"no mobile config leaks on {domain}")
        return self._ok(findings,
                        f"{len(findings)} mobile config issue(s) on {domain}")


# ---------------------------------------------------------------------------
# 5. fin_oidc_config - OIDC / OAuth well-known config leaking internals
# ---------------------------------------------------------------------------

OIDC_PATHS = (
    "/.well-known/openid-configuration",
    "/oauth2/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/auth/.well-known/openid-configuration",
)


def analyze_oidc_config(data) -> List[Dict]:
    """Internal hosts / risky grants in an OIDC discovery document."""
    out: List[Dict] = []
    if not isinstance(data, dict):
        return out
    for field in ("issuer", "authorization_endpoint", "token_endpoint",
                  "jwks_uri", "userinfo_endpoint", "registration_endpoint"):
        v = data.get(field)
        if isinstance(v, str) and _INTERNAL_HOST_RE.search(v):
            out.append({"issue": "internal_host", "field": field,
                        "value": v})
    grants = data.get("grant_types_supported") or []
    if isinstance(grants, list) and "password" in grants:
        out.append({"issue": "password_grant", "field": "grant_types_supported",
                    "value": "password"})
    return out


class FinOidcConfigPlugin(FinPlugin):
    id = "fin_oidc_config"
    label = "Banking OIDC Config Leak"
    description = ("OpenID Connect discovery documents on the bank "
                   "domain that point at internal issuers/token hosts "
                   "or advertise legacy password grants.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, OIDC_PATHS):
            for issue in analyze_oidc_config(parse_json_text(text)):
                sev = "medium" if issue["issue"] == "internal_host" \
                    else "low"
                findings.append(self.fin_finding(
                    "fin_oidc_config_issue",
                    f"OIDC discovery at {url}: {issue['field']} = "
                    f"{issue['value']} ({issue['issue'].replace('_', ' ')})",
                    url, sev,
                    "Publish discovery documents with public endpoints "
                    "only; disable the resource-owner password grant on "
                    "retail issuers.",
                    field=issue["field"], issue=issue["issue"]))
        if not findings:
            return self._ok([], f"no OIDC config issues on {domain}")
        return self._ok(findings,
                        f"{len(findings)} OIDC issue(s) on {domain}")


# ---------------------------------------------------------------------------
# 6. fin_saml_metadata - SAML federation metadata leaking internals
# ---------------------------------------------------------------------------

SAML_PATHS = (
    "/saml/metadata", "/saml2/metadata", "/saml/metadata.xml",
    "/federationmetadata/2007-06/federationmetadata.xml",
    "/adfs/ls", "/auth/saml/metadata",
)


def analyze_saml_metadata(text: str) -> List[Dict]:
    """Internal hosts / staging entityIDs inside SAML metadata XML."""
    out: List[Dict] = []
    if not text or "EntityDescriptor" not in text:
        return out
    for kind, value in find_internal_leaks(text):
        out.append({"issue": f"internal_{kind}", "value": value})
    m = re.search(r'entityID="([^"]+)"', text)
    if m and re.search(r"(staging|stage|dev|test|uat|qa)", m.group(1),
                       re.IGNORECASE):
        out.append({"issue": "nonprod_entity", "value": m.group(1)})
    return out


class FinSamlMetadataPlugin(FinPlugin):
    id = "fin_saml_metadata"
    label = "SAML Metadata Leak"
    description = ("SAML federation metadata served on the bank domain "
                   "that exposes internal IdP/SSO hostnames or "
                   "non-production entity IDs.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, SAML_PATHS):
            for issue in analyze_saml_metadata(text):
                findings.append(self.fin_finding(
                    "fin_saml_metadata_leak",
                    f"SAML metadata at {url}: "
                    f"{issue['issue'].replace('_', ' ')} {issue['value']}",
                    url, "medium",
                    "Publish federation metadata with public IdP "
                    "endpoints only; keep staging federations off the "
                    "production domain.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"no SAML metadata leaks on {domain}")
        return self._ok(findings,
                        f"{len(findings)} SAML issue(s) on {domain}")


# ---------------------------------------------------------------------------
# 7. fin_locator_api - branch/ATM locator APIs returning internal fields
# ---------------------------------------------------------------------------

LOCATOR_API_PATHS = (
    "/api/branches", "/api/locations", "/api/branch-locator",
    "/api/v1/branches", "/api/v1/locations", "/locations.json",
    "/branches.json",
)
_SENSITIVE_FIELD_RE = re.compile(
    r"(internal|private|manager|staff|vault|safe|cash|host|ipaddr|"
    r"ip_address|server|employee)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",
                       re.IGNORECASE)


def analyze_locator_payload(data) -> List[Dict]:
    """Sensitive fields inside a locator API payload (branches list)."""
    out: List[Dict] = []
    items = []
    if isinstance(data, list):
        items = [d for d in data if isinstance(d, dict)]
    elif isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                items = [d for d in v if isinstance(d, dict)]
                break
        if not items:
            items = [data]
    seen = set()
    reported_fields = set()
    for item in items[:50]:
        for k, v in item.items():
            if _SENSITIVE_FIELD_RE.search(str(k)) and v not in (None, ""):
                key = ("field", str(k))
                if key not in seen:
                    seen.add(key)
                    reported_fields.add(str(k))
                    val = str(v)
                    if _EMAIL_RE.fullmatch(val):
                        val = _EMAIL_RE.sub(lambda m: m.group(0)[:3]
                                            + "***@" + m.group(0)
                                            .split("@")[-1], val)
                    out.append({"issue": "sensitive_field", "field": str(k),
                                "value": val[:80]})
            if isinstance(v, str) and str(k) not in reported_fields:
                for kind, leak in find_internal_leaks(v):
                    key = ("leak", leak)
                    if key not in seen:
                        seen.add(key)
                        out.append({"issue": f"internal_{kind}",
                                    "field": str(k), "value": leak})
    return out


class FinLocatorApiPlugin(FinPlugin):
    id = "fin_locator_api"
    label = "Locator API Internal Fields"
    description = ("Branch/ATM locator APIs that return more than "
                   "public data: internal IPs/hostnames, staff emails, "
                   "vault or cash-handling fields.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base,
                                               LOCATOR_API_PATHS):
            for issue in analyze_locator_payload(parse_json_text(text)):
                findings.append(self.fin_finding(
                    "fin_locator_api_field",
                    f"Locator API {url} exposes field {issue['field']}: "
                    f"{issue['value']}",
                    url, "medium",
                    "Trim locator API responses to public fields only "
                    "(name, address, hours); internal IPs, staff "
                    "contacts and vault data must stay server-side.",
                    field=issue["field"], issue=issue["issue"]))
        if not findings:
            return self._ok([], f"locator APIs clean on {domain}")
        return self._ok(findings,
                        f"{len(findings)} locator field(s) on {domain}")


# ---------------------------------------------------------------------------
# 8. fin_treasury_portal - treasury / corporate banking portals
# ---------------------------------------------------------------------------

TREASURY_PATHS = (
    "/treasury", "/treasury-services", "/treasury-login",
    "/cash-management", "/corporate-banking", "/corporate",
    "/business/treasury", "/commercial-banking",
)
TREASURY_FINGERPRINTS = (
    ("Treasury Management Portal", r"treasury\s+(management|services)\s+(portal|login)"),
    ("Cash Management Portal", r"cash\s+management\s+(portal|login|platform)"),
    ("Bottomline Treasury", r"bottomline"),
    ("Q2 Treasury", r"q2\s+treasury|treasury\s+iq"),
    ("FIS Treasury", r"fis\s+treasury|integrity\s+treasury"),
    ("Corporate Banking Portal", r"corporate\s+banking\s+(portal|login)"),
)


def match_treasury_portal(text: str) -> List[str]:
    low = (text or "").lower()
    return [name for name, pat in TREASURY_FINGERPRINTS
            if re.search(pat, low)]


class FinTreasuryPortalPlugin(FinPlugin):
    id = "fin_treasury_portal"
    label = "Treasury Portal Exposure"
    description = ("Treasury / cash-management / corporate banking "
                   "portals reachable on the public domain. Existence "
                   "+ fingerprint only; no login is attempted.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, TREASURY_PATHS):
            hits = match_treasury_portal(text)
            if hits:
                findings.append(self.fin_finding(
                    "fin_treasury_portal",
                    f"Treasury/corporate portal exposed at {url}: "
                    f"{', '.join(hits)}",
                    url, "medium",
                    "Treasury portals are high-value targets; enforce "
                    "hardware-backed MFA, IP allowlisting and keep "
                    "admin functions off the public portal.",
                    portals=hits))
        if not findings:
            return self._ok([], f"no treasury portals found on {domain}")
        return self._ok(findings,
                        f"{len(findings)} treasury portal page(s) on {domain}")
