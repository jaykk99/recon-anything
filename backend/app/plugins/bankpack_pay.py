"""Payments & cards detectors (fin_* pack, payments family).

Eight detection-only checks on the payment surface: processor SECRET
keys in public code/configs, webhook signing secrets, BIN-lookup
service configs, sandbox credentials sitting in production configs,
card forms posting to unexpected hosts, merchant portals, POS
terminal configs, and ACH/Nacha file-transfer configs. Read-only
GETs only; every credential-shaped value is reported masked with a
fingerprint, never in full, and never used.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from .bankpack_util import (FinPlugin, collect_texts, fetch_paths,
                            looks_like_placeholder, mask_secret,
                            parse_json_text)
from .base import Ctx, PluginResult, Target

# ---------------------------------------------------------------------------
# 17. fin_payment_secrets - processor SECRET keys in public code/config
# ---------------------------------------------------------------------------

# Server-side secret formats only. Publishable keys (pk_live_, Square
# sandbox application ids) are designed to be public and are excluded.
SECRET_PATTERNS = (
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")),
    ("Stripe restricted key", re.compile(r"\brk_live_[0-9a-zA-Z]{16,}\b")),
    ("Adyen API key", re.compile(r"\bAQEyhm[0-9a-zA-Z+/=_\-]{20,}\b")),
    ("Square access token", re.compile(r"\bEAAA[0-9a-zA-Z_\-]{20,}\b")),
    ("Braintree access token",
     re.compile(r"\baccess_token\$[a-z]+\$[0-9a-f]{32}\b")),
    ("Checkout.com secret key", re.compile(r"\bsk_(?:sbox_)?[0-9a-zA-Z]{24,}\b")),
)
PAYMENT_PATHS = ("/checkout", "/pay", "/payment", "/checkout.js",
                 "/js/payment.js", "/payment-config.json")


def find_payment_secrets(text: str) -> List[Tuple[str, str]]:
    """(processor, raw secret) pairs - caller masks before reporting."""
    out: List[Tuple[str, str]] = []
    seen = set()
    for name, pat in SECRET_PATTERNS:
        for m in pat.finditer(text or ""):
            v = m.group(0)
            if v not in seen and not looks_like_placeholder(v):
                seen.add(v)
                out.append((name, v))
    return out


class FinPaymentSecretsPlugin(FinPlugin):
    id = "fin_payment_secrets"
    label = "Payment Secret Key Exposure"
    description = ("Payment-processor SECRET keys (Stripe sk_live, "
                   "Adyen, Square, Braintree, Checkout.com) sitting in "
                   "public pages, scripts or configs. Masked + "
                   "fingerprinted; never used.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        texts = await collect_texts(ctx, base, extra_paths=PAYMENT_PATHS)
        findings = []
        for url, text in texts:
            for name, raw in find_payment_secrets(text):
                masked, fp = mask_secret(raw)
                findings.append(self.fin_finding(
                    "fin_payment_secret_key",
                    f"{name} exposed in public content at {url}: {masked}",
                    url, "high",
                    "Remove the secret from client-side code/config "
                    "immediately and rotate it in the processor "
                    "dashboard; server secrets must never ship to "
                    "browsers.",
                    processor=name, masked_value=masked, fingerprint=fp))
        if not findings:
            return self._ok([], f"no payment secret keys exposed on {domain}")
        return self._ok(findings,
                        f"{len(findings)} payment secret(s) on {domain}")


# ---------------------------------------------------------------------------
# 18. fin_webhook_secrets - webhook signing secrets in public code/config
# ---------------------------------------------------------------------------

_WEBHOOK_VALUE_RES = (
    ("Stripe webhook secret", re.compile(r"\bwhsec_[0-9a-zA-Z]{16,}\b")),
    ("Square signature key", re.compile(r"\bsq0csp-[0-9a-zA-Z_\-]{20,}\b")),
)
_WEBHOOK_ASSIGN_RE = re.compile(
    r"""(webhook[_-]?secret|signing[_-]?secret|webhook[_-]?signing[_-]?key)"""
    r"""["']?\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,})["']""", re.IGNORECASE)
WEBHOOK_PATHS = ("/webhooks", "/webhook", "/api/webhooks", "/hooks")


def find_webhook_secrets(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    seen = set()
    for name, pat in _WEBHOOK_VALUE_RES:
        for m in pat.finditer(text or ""):
            v = m.group(0)
            if v not in seen and not looks_like_placeholder(v):
                seen.add(v)
                out.append((name, v))
    for m in _WEBHOOK_ASSIGN_RE.finditer(text or ""):
        v = m.group(2)
        if v not in seen and not looks_like_placeholder(v):
            seen.add(v)
            out.append((f"webhook secret ({m.group(1)})", v))
    return out


class FinWebhookSecretsPlugin(FinPlugin):
    id = "fin_webhook_secrets"
    label = "Webhook Signing Secret Exposure"
    description = ("Webhook signing secrets (Stripe whsec_, Square "
                   "signature keys, generic webhook_secret assignments) "
                   "in public scripts/configs of a payment surface. "
                   "Masked + fingerprinted; never used.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        texts = await collect_texts(ctx, base, extra_paths=WEBHOOK_PATHS)
        findings = []
        for url, text in texts:
            for name, raw in find_webhook_secrets(text):
                masked, fp = mask_secret(raw)
                findings.append(self.fin_finding(
                    "fin_webhook_secret",
                    f"{name} exposed in public content at {url}: {masked}",
                    url, "high",
                    "Rotate the webhook signing secret and keep it "
                    "server-side only; anyone holding it can forge "
                    "payment events.",
                    masked_value=masked, fingerprint=fp))
        if not findings:
            return self._ok([], f"no webhook secrets exposed on {domain}")
        return self._ok(findings,
                        f"{len(findings)} webhook secret(s) on {domain}")


# ---------------------------------------------------------------------------
# 19. fin_bin_config - BIN/IIN lookup service config exposure
# ---------------------------------------------------------------------------

BIN_PATHS = (
    "/bin-lookup", "/api/bin", "/bin/config", "/card-bin",
    "/api/v1/bin", "/binlookup", "/api/bin-lookup",
)
_BIN_KEY_RE = re.compile(
    r"""(api[_-]?key|access[_-]?key|token)["']?\s*[:=]\s*["']"""
    r"""([A-Za-z0-9_\-]{16,})["']""", re.IGNORECASE)
_BIN_DB_RE = re.compile(r"[\w.\-/]*bin[\w.\-/]*\.(?:csv|zip|json|db)\b",
                        re.IGNORECASE)


def analyze_bin_surface(text: str) -> List[Dict]:
    out: List[Dict] = []
    if not text:
        return out
    for m in _BIN_KEY_RE.finditer(text):
        if not looks_like_placeholder(m.group(2)):
            masked, fp = mask_secret(m.group(2))
            out.append({"issue": "bin_api_key", "value": masked,
                        "fingerprint": fp})
            break
    for m in _BIN_DB_RE.finditer(text):
        out.append({"issue": "bin_database_file", "value": m.group(0)})
        break
    return out


class FinBinConfigPlugin(FinPlugin):
    id = "fin_bin_config"
    label = "BIN Lookup Config Exposure"
    description = ("BIN/IIN lookup endpoints or configs exposing the "
                   "service API key or a downloadable full BIN database.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, BIN_PATHS):
            for issue in analyze_bin_surface(text):
                findings.append(self.fin_finding(
                    "fin_bin_config_leak",
                    f"BIN lookup surface at {url}: "
                    f"{issue['issue'].replace('_', ' ')} {issue['value']}",
                    url, "medium",
                    "Keep BIN-service keys server-side and do not "
                    "publish the full BIN database; license terms and "
                    "issuer mappings are sensitive.",
                    issue=issue["issue"],
                    fingerprint=issue.get("fingerprint")))
        if not findings:
            return self._ok([], f"no BIN config leaks on {domain}")
        return self._ok(findings, f"{len(findings)} BIN issue(s) on {domain}")


# ---------------------------------------------------------------------------
# 20. fin_sandbox_live_mismatch - test credentials in production config
# ---------------------------------------------------------------------------

_SANDBOX_MARKERS = (
    ("Stripe test key", re.compile(r"\b[sp]k_test_[0-9a-zA-Z]{10,}\b")),
    ("Checkout sandbox key", re.compile(r"\bsk_sbox_[0-9a-zA-Z]{10,}\b")),
    ("PayPal sandbox", re.compile(r"sandbox\.paypal\.com|paypal.*sandbox",
                                  re.IGNORECASE)),
    ("sandbox API host", re.compile(
        r"(sandbox|api-m\.sandbox|test-api|staging-api)\.[a-z0-9.-]+",
        re.IGNORECASE)),
    ("test mode flag", re.compile(
        r"""["']?(test[_-]?mode|sandbox)["']?\s*[:=]\s*["']?(true|on|1)""",
        re.IGNORECASE)),
)
_PROD_MARKER_RE = re.compile(
    r"""["']?(env|environment|mode)["']?\s*[:=]\s*["'](production|prod|live)["']""",
    re.IGNORECASE)
CONFIG_PATHS = ("/payment-config.json", "/config.json",
                "/checkout/config.js", "/payments/config.json",
                "/static/payment-config.js")


def find_sandbox_mismatch(text: str) -> List[str]:
    """Sandbox/test payment markers inside a PRODUCTION-marked config.
    Both halves must be present in the same document."""
    if not text or not _PROD_MARKER_RE.search(text):
        return []
    return [name for name, pat in _SANDBOX_MARKERS if pat.search(text)]


class FinSandboxMismatchPlugin(FinPlugin):
    id = "fin_sandbox_live_mismatch"
    label = "Sandbox Credentials in Production Config"
    description = ("Production-marked payment configs that still carry "
                   "sandbox/test credentials or test endpoints - the "
                   "classic sign the live site never got its real (or "
                   "its test) configuration separated.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        texts = await collect_texts(ctx, base, extra_paths=CONFIG_PATHS)
        findings = []
        for url, text in texts:
            hits = find_sandbox_mismatch(text)
            if hits:
                findings.append(self.fin_finding(
                    "fin_sandbox_in_production",
                    f"Production config at {url} carries sandbox/test "
                    f"payment material: {', '.join(hits)}",
                    url, "medium",
                    "Separate test and production configuration; audit "
                    "which environment actually processes live payments "
                    "and purge test credentials from the live config.",
                    markers=hits))
        if not findings:
            return self._ok([], f"no sandbox/production mixups on {domain}")
        return self._ok(findings,
                        f"{len(findings)} config mixup(s) on {domain}")


# ---------------------------------------------------------------------------
# 21. fin_card_form_action - card forms posting somewhere unexpected
# ---------------------------------------------------------------------------

_CARD_INPUT_RE = re.compile(
    r"<input[^>]*(?:card[_-]?(?:number|num)|cc[_-]?num|credit[_-]?card)"
    r"[^>]*>", re.IGNORECASE)
_FORM_RE = re.compile(r"<form[^>]*action=[\"']([^\"']*)[\"'][^>]*>(.*?)</form>",
                      re.IGNORECASE | re.DOTALL)
FORM_PATHS = ("/checkout", "/pay", "/payment", "/card-payment",
              "/billing", "/donate")


def analyze_card_forms(html: str, page_url: str) -> List[Dict]:
    """Card-entry forms whose action is plain HTTP or a foreign host."""
    out: List[Dict] = []
    page = urlparse(page_url)
    for m in _FORM_RE.finditer(html or ""):
        action, body = m.group(1), m.group(2)
        if not _CARD_INPUT_RE.search(body):
            continue
        a = urlparse(action)
        if action.startswith("http://"):
            out.append({"issue": "http_action", "value": action})
        elif a.netloc and a.netloc != page.netloc:
            out.append({"issue": "foreign_action", "value": action})
    return out


class FinCardFormActionPlugin(FinPlugin):
    id = "fin_card_form_action"
    label = "Card Form Posts Off-Site / Over HTTP"
    description = ("Payment forms collecting card numbers whose form "
                   "action posts over plain HTTP or to a foreign host "
                   "instead of the bank/processor - a skimming red "
                   "flag. Forms are read, never submitted.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        pages = await fetch_paths(ctx, base, FORM_PATHS)
        home = await fetch_paths(ctx, base, ("/",))
        for url, text, _h in home + pages:
            for issue in analyze_card_forms(text, url):
                findings.append(self.fin_finding(
                    "fin_card_form_action",
                    f"Card form on {url} posts to {issue['value']} "
                    f"({issue['issue'].replace('_', ' ')})",
                    url, "high",
                    "Card data must post only to the bank or its "
                    "PCI-validated processor over HTTPS; audit this "
                    "form for skimming or misconfiguration.",
                    issue=issue["issue"], action=issue["value"]))
        if not findings:
            return self._ok([], f"card forms look sane on {domain}")
        return self._ok(findings, f"{len(findings)} card form(s) on {domain}")


# ---------------------------------------------------------------------------
# 22. fin_merchant_portal - merchant acquiring portals
# ---------------------------------------------------------------------------

MERCHANT_PATHS = (
    "/merchant", "/merchant-login", "/merchant-admin", "/merchants",
    "/pos-login", "/merchantportal", "/merchant-services",
)
MERCHANT_FINGERPRINTS = (
    ("Moneris Merchant Portal", r"moneris"),
    ("Elavon Merchant Portal", r"elavon"),
    ("Worldpay Merchant Portal", r"worldpay"),
    ("Global Payments Merchant Portal", r"global\s+payments"),
    ("First Data Merchant Portal", r"first\s+data"),
    ("Chase Merchant Portal", r"chase\s+merchant"),
    ("Merchant Portal", r"merchant\s+(portal|login|sign\s?in)"),
)


def match_merchant_portal(text: str) -> List[str]:
    low = (text or "").lower()
    return [name for name, pat in MERCHANT_FINGERPRINTS
            if re.search(pat, low)]


class FinMerchantPortalPlugin(FinPlugin):
    id = "fin_merchant_portal"
    label = "Merchant Portal Exposure"
    description = ("Merchant acquiring portals (Moneris, Elavon, "
                   "Worldpay, Global Payments...) reachable on the "
                   "public domain. Existence + fingerprint only.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, MERCHANT_PATHS):
            hits = match_merchant_portal(text)
            if hits:
                findings.append(self.fin_finding(
                    "fin_merchant_portal",
                    f"Merchant portal exposed at {url}: "
                    f"{', '.join(hits)}",
                    url, "medium",
                    "Confirm the merchant portal is intentionally "
                    "public; enforce MFA and monitor for credential "
                    "stuffing.",
                    portals=hits))
        if not findings:
            return self._ok([], f"no merchant portals found on {domain}")
        return self._ok(findings,
                        f"{len(findings)} merchant portal page(s) on {domain}")


# ---------------------------------------------------------------------------
# 23. fin_pos_config - POS / terminal configuration files
# ---------------------------------------------------------------------------

POS_CONFIG_PATHS = (
    "/pos/config.json", "/terminal/config.json", "/pos-config.json",
    "/config/pos.json", "/pointofsale/config.json", "/pos/config",
)
_POS_FIELD_RE = re.compile(
    r"(merchant_?id|terminal_?id|store_?id|processor_?host|host_?ip|"
    r"key_?id|kid|encryption)", re.IGNORECASE)


def analyze_pos_config(data) -> List[Dict]:
    """Merchant/terminal identifiers + processor hosts in a POS config."""
    out: List[Dict] = []
    if not isinstance(data, dict):
        return out
    for k, v in data.items():
        if _POS_FIELD_RE.search(str(k)) and v not in (None, ""):
            out.append({"field": str(k), "value": str(v)[:60]})
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if _POS_FIELD_RE.search(str(k2)) and v2 not in (None, ""):
                    out.append({"field": f"{k}.{k2}", "value": str(v2)[:60]})
    return out[:10]


class FinPosConfigPlugin(FinPlugin):
    id = "fin_pos_config"
    label = "POS Terminal Config Exposure"
    description = ("Point-of-sale configuration files served publicly "
                   "with merchant IDs, terminal IDs, processor hosts "
                   "or key IDs.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, POS_CONFIG_PATHS):
            for issue in analyze_pos_config(parse_json_text(text)):
                findings.append(self.fin_finding(
                    "fin_pos_config_leak",
                    f"POS config {url} exposes {issue['field']}: "
                    f"{issue['value']}",
                    url, "medium",
                    "POS configs identify live terminals and their "
                    "processor routes; serve them only to "
                    "authenticated terminals.",
                    field=issue["field"]))
        if not findings:
            return self._ok([], f"no POS config leaks on {domain}")
        return self._ok(findings,
                        f"{len(findings)} POS config field(s) on {domain}")


# ---------------------------------------------------------------------------
# 24. fin_ach_config - ACH / Nacha file-transfer configuration
# ---------------------------------------------------------------------------

ACH_PATHS = (
    "/ach-config.json", "/ach/config.json", "/ach/config",
    "/payments/ach/config.json", "/nacha/config.json", "/ach",
)
_ACH_HOST_RE = re.compile(
    r"""(sftp|ftp|host|server|endpoint)["']?\s*[:=]\s*["']?"""
    r"""([a-z0-9.\-]+(?:\.corp|\.local|\.internal|\.lan)\b"""
    r"""|\d{1,3}(?:\.\d{1,3}){3})""", re.IGNORECASE)
_ACH_MARKER_RE = re.compile(r"(nacha|odfi|ach\s+file|immediate\s+"
                            r"destination)", re.IGNORECASE)


def analyze_ach_config(text: str) -> List[Dict]:
    """ACH transfer endpoints: needs ACH context AND a file-transfer
    host (internal hostname or IP) to fire."""
    out: List[Dict] = []
    if not text or not _ACH_MARKER_RE.search(text):
        return out
    for m in _ACH_HOST_RE.finditer(text):
        out.append({"field": m.group(1).lower(), "value": m.group(2)})
    return out[:5]


class FinAchConfigPlugin(FinPlugin):
    id = "fin_ach_config"
    label = "ACH Transfer Config Exposure"
    description = ("ACH/Nacha processing configs disclosing the "
                   "file-transfer (SFTP) hosts used to move payment "
                   "files - internal hostnames or IPs included.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, ACH_PATHS):
            for issue in analyze_ach_config(text):
                findings.append(self.fin_finding(
                    "fin_ach_config_leak",
                    f"ACH config at {url} discloses transfer "
                    f"{issue['field']}: {issue['value']}",
                    url, "high",
                    "ACH file-transfer endpoints are core payment "
                    "infrastructure; never publish them in web-served "
                    "configs - restrict to the payments network.",
                    field=issue["field"]))
        if not findings:
            return self._ok([], f"no ACH config leaks on {domain}")
        return self._ok(findings,
                        f"{len(findings)} ACH endpoint(s) on {domain}")
