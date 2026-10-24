"""Private-findings pack (pf_*): 100 detectors for privately-sensitive
material a target has PUBLICLY EXPOSED - leaked secrets, credentials,
connection strings, tokens, wallet material, and personal-data leaks in
public pages, JS bundles, and served files.

Detection only. Nothing here uses, validates, or transmits a found
secret anywhere. Every secret-shaped match is stored MASKED (first/last
few chars via secretutils.redact) plus a SHA-256 fingerprint of the
full value; the full value never reaches a Finding, the DB, exports,
or logs. Personal-data findings mask all but two characters and carry
a distinct-value count.

Surfaces:
- PfContent plugins scan the homepage + same-domain JS bundles through
  the shared Ctx.fetch_page cache (same surface as the crypto pack).
- PfPath plugins probe a small set of well-known secret-bearing file
  paths / console endpoints with Ctx.probe (active mode only, like the
  artifacts/backup sweepers) and require a content marker in the body,
  so a soft-404 never fires them.

Every detector here was deduped against the pre-existing registry
(412 plugins on 2026-10-23): plugin ids AND detection patterns. Where a
generic detector already covers a format (AWS keys, GitHub tokens,
PEM blocks, postgres/mysql/mongo/redis/amqp URLs, phpMyAdmin, .env,
backup archives...), it is deliberately NOT repeated.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from typing import Callable, Dict, List, Optional

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import (XRP_ALPHABET, b58check_verify, collect_texts,
                              crc16_xmodem)
from .secretutils import redact

_REMEDIATION = (
    "Remove the exposed material from the public surface immediately, "
    "rotate/revoke the credential or key (treat it as compromised), "
    "and audit access logs for misuse. Detection only: this finding "
    "was reported, never used.")


def _fingerprint(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8", "ignore")).hexdigest()


# ---------------------------------------------------------------------------
# Validators (real format checks; a regex shape alone is not enough)
# ---------------------------------------------------------------------------

def _digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def v_ssn(value: str) -> bool:
    d = _digits(value)
    if len(d) != 9:
        return False
    area, group, serial = int(d[:3]), int(d[3:5]), int(d[5:])
    return not (area == 0 or area == 666 or area >= 900
                or group == 0 or serial == 0)


def v_sin(value: str) -> bool:
    d = _digits(value)
    if len(d) != 9:
        return False
    total = 0
    for i, ch in enumerate(d):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def v_nhs(value: str) -> bool:
    d = _digits(value)
    if len(d) != 10:
        return False
    total = sum(int(d[i]) * (10 - i) for i in range(9))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    if check == 10:
        return False
    return check == int(d[9])


def v_nino(value: str) -> bool:
    return re.fullmatch(
        r"[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]",
        (value or "").upper()) is not None


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def v_aadhaar(value: str) -> bool:
    d = _digits(value)
    if len(d) != 12 or d[0] in "01":
        return False
    c = 0
    for i, ch in enumerate(reversed(d)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def v_pan(value: str) -> bool:
    v = (value or "").upper()
    return (re.fullmatch(r"[A-Z]{5}\d{4}[A-Z]", v) is not None
            and v[3] in "PCHFATBLJG")


def v_tfn(value: str) -> bool:
    d = _digits(value)
    if len(d) != 9:
        return False
    weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
    return sum(int(d[i]) * weights[i] for i in range(9)) % 11 == 0


def v_iban(value: str) -> bool:
    s = re.sub(r"\s", "", value or "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    numeric = ""
    for ch in rearranged:
        numeric += str(int(ch, 36)) if ch.isalpha() else ch
    # mod-97 in chunks (the numeric string can exceed int comfort zones
    # on some builds; Python handles big ints, chunking is belt+braces)
    rem = 0
    for i in range(0, len(numeric), 7):
        rem = int(str(rem) + numeric[i:i + 7]) % 97
    return rem == 1


def v_xrp_seed(value: str) -> bool:
    # XRP family seeds are Base58Check in the XRP alphabet (which is
    # why they start with 's'), payload = version 0x21 + 16B entropy.
    payload = b58check_verify(value or "", XRP_ALPHABET)
    return payload is not None and len(payload) == 17 and payload[0] == 0x21


def v_stellar_secret(value: str) -> bool:
    s = (value or "").upper()
    try:
        raw = base64.b32decode(s + "=" * ((8 - len(s) % 8) % 8))
    except Exception:
        return False
    if len(raw) != 35 or raw[0] != 0x90:  # 0x90 = secret-seed version byte
        return False
    return crc16_xmodem(raw[:-2]) == int.from_bytes(raw[-2:], "little")


VALIDATORS: Dict[str, Callable[[str], bool]] = {
    "ssn": v_ssn, "sin": v_sin, "nhs": v_nhs, "nino": v_nino,
    "aadhaar": v_aadhaar, "pan": v_pan, "tfn": v_tfn, "iban": v_iban,
    "xrp_seed": v_xrp_seed, "stellar_secret": v_stellar_secret,
}


# ---------------------------------------------------------------------------
# Content detectors (homepage + same-domain JS, shared fetch cache)
# ---------------------------------------------------------------------------

class PfContent(Plugin):
    """One pattern, one detector. Subclasses are generated from SPECS."""

    id = None  # abstract; registry skips id-less classes
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 45

    PATTERN: str = ""
    KEY: str = ""
    LABEL: str = ""
    CONF: int = 90
    CATEGORY: str = "leak"
    SEVERITY: str = "high"
    CONTEXT_RE: Optional[str] = None
    WINDOW: int = 160
    VALIDATOR: Optional[str] = None
    SHOW: int = 4
    MAX_FINDINGS: int = 25
    _rx: Optional[re.Pattern] = None
    _ctx_rx: Optional[re.Pattern] = None

    def _compiled(self):
        if type(self)._rx is None:
            type(self)._rx = re.compile(self.PATTERN, re.I)
            type(self)._ctx_rx = (re.compile(self.CONTEXT_RE, re.I)
                                  if self.CONTEXT_RE else None)
        return type(self)._rx, type(self)._ctx_rx

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        rx, ctx_rx = self._compiled()
        validator = VALIDATORS.get(self.VALIDATOR) if self.VALIDATOR else None
        hits: Dict[str, tuple] = {}
        for where, text, url in texts:
            for m in rx.finditer(text):
                value = m.group(1) if m.groups() else m.group(0)
                if not value or value in hits:
                    continue
                if validator is not None:
                    try:
                        if not validator(value):
                            continue
                    except Exception:
                        continue
                if ctx_rx is not None:
                    lo = max(0, m.start() - self.WINDOW)
                    hi = min(len(text), m.end() + self.WINDOW)
                    if not ctx_rx.search(text[lo:hi]):
                        continue
                hits[value] = (where, url)
                if len(hits) >= self.MAX_FINDINGS:
                    break
            if len(hits) >= self.MAX_FINDINGS:
                break
        findings: List[Finding] = []
        for value, (where, url) in hits.items():
            ev = {
                "severity": self.SEVERITY,
                "detector": self.id,
                "matched": self.LABEL,
                "where": where,
                "match_redacted": redact(value, show=self.SHOW),
                "fingerprint_sha256": _fingerprint(value),
                "remediation": _REMEDIATION,
            }
            if self.CATEGORY == "identity":
                ev["values_count"] = len(hits)
            findings.append(self._f(
                self.CATEGORY, self.KEY,
                f"{self.LABEL}: {redact(value, show=self.SHOW)}",
                source=f"private findings: {self.LABEL}",
                source_url=url, confidence=self.CONF, passive=True,
                evidence=ev))
        res = self._ok(findings, f"{len(findings)} {self.LABEL} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


# ---------------------------------------------------------------------------
# Path detectors (secret-bearing files / consoles, content-marker gated)
# ---------------------------------------------------------------------------

class PfPath(Plugin):
    """Probe a few well-known paths; fire only on a body marker."""

    id = None  # abstract
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    timeout_s = 45

    PATHS: List[str] = []
    BODY_RE: str = ""
    KEY: str = ""
    LABEL: str = ""
    CONF: int = 90
    CATEGORY: str = "leak"
    SEVERITY: str = "high"
    _rx: Optional[re.Pattern] = None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if self.module_mode(ctx) == "passive":
            return self._ok([], "path probing is active-mode only")
        if target.type == "url":
            base = target.normalized.rstrip("/")
        else:
            domain = domain_from_target(target.type, target.normalized)
            if not domain:
                return self._skipped("no domain for this target type")
            base = f"https://{domain}"
        if type(self)._rx is None:
            type(self)._rx = re.compile(self.BODY_RE, re.I)
        findings: List[Finding] = []
        for path in self.PATHS:
            full = base + path
            try:
                probed = await ctx.probe(full, timeout=8)
            except Exception:
                continue
            if probed.get("status") != 200:
                continue
            text = probed.get("text") or ""
            if not text or not type(self)._rx.search(text):
                continue
            findings.append(self._f(
                self.CATEGORY, self.KEY,
                f"{self.LABEL}: {path} is publicly served",
                source=f"private findings: {self.LABEL}",
                source_url=full, confidence=self.CONF, passive=False,
                evidence={
                    "severity": self.SEVERITY,
                    "detector": self.id,
                    "path": path,
                    "marker_matched": True,
                    "body_sha256": _fingerprint(text),
                    "size": probed.get("length", len(text)),
                    "remediation": _REMEDIATION,
                }))
            if len(findings) >= 3:
                break
        res = self._ok(findings, f"{len(findings)} {self.LABEL} hit(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


# ---------------------------------------------------------------------------
# Detector specs. Fields:
#   id, key, label, pattern (group 1 = the secret value), confidence,
#   group, category, severity, show (mask chars), context_re, validator
# ---------------------------------------------------------------------------

def _c(pid, key, label, pattern, conf=90, group="web", category="leak",
       severity="high", show=4, context=None, validator=None):
    return {"id": pid, "key": key, "label": label, "pattern": pattern,
            "conf": conf, "group": group, "category": category,
            "severity": severity, "show": show, "context": context,
            "validator": validator}


CONTENT_SPECS = [
    # -- Family A: cloud & SaaS secrets (30) -------------------------------
    _c("pf_stripe_webhook_secret", "stripe_webhook_secret",
       "Stripe webhook signing secret", r"(whsec_[A-Za-z0-9]{16,64})", 95),
    _c("pf_supabase_service_key", "supabase_service_key",
       "Supabase service-role secret key", r"(sb_secret_[A-Za-z0-9_-]{16,})", 95),
    _c("pf_vault_token", "vault_token",
       "HashiCorp Vault token", r"\b(hv[bs]\.[A-Za-z0-9_-]{16,})", 95),
    _c("pf_terraform_cloud_token", "terraform_cloud_token",
       "Terraform Cloud API token",
       r"([A-Za-z0-9_-]{10,}\.atlasv1\.[A-Za-z0-9_-]{30,})", 90),
    _c("pf_figma_token", "figma_token",
       "Figma personal access token", r"(figd_[A-Za-z0-9_-]{30,})", 90),
    _c("pf_linear_api_key", "linear_api_key",
       "Linear API key", r"(lin_api_[A-Za-z0-9]{32,})", 90),
    _c("pf_groq_api_key", "groq_api_key",
       "Groq API key", r"(gsk_[A-Za-z0-9]{32,})", 90),
    _c("pf_xai_api_key", "xai_api_key",
       "xAI API key", r"\b(xai-[A-Za-z0-9]{32,})", 90),
    _c("pf_replicate_token", "replicate_token",
       "Replicate API token", r"(r8_[A-Za-z0-9]{32,})", 90),
    _c("pf_perplexity_key", "perplexity_key",
       "Perplexity API key", r"(pplx-[A-Za-z0-9]{32,})", 90),
    _c("pf_alibaba_access_key", "alibaba_access_key",
       "Alibaba Cloud AccessKey ID", r"\b(LTAI[A-Za-z0-9]{12,24})\b", 85),
    _c("pf_tencent_secret_id", "tencent_secret_id",
       "Tencent Cloud SecretId", r"\b(AKID[A-Za-z0-9]{16,32})\b", 85),
    _c("pf_gcp_sa_token", "gcp_service_agent_token",
       "Google Cloud service-agent token", r"(glsa_[A-Za-z0-9_-]{20,})", 85),
    _c("pf_doppler_token", "doppler_token",
       "Doppler service token", r"(dp\.(?:st|pt|ct|sa)\.[A-Za-z0-9_-]{30,})", 90),
    _c("pf_buildkite_token", "buildkite_token",
       "Buildkite API token", r"(bkua_[A-Za-z0-9_-]{30,})", 90),
    _c("pf_gitlab_runner_token", "gitlab_runner_token",
       "GitLab runner authentication token", r"(glrt-[A-Za-z0-9_-]{20,})", 90),
    _c("pf_sentry_org_token", "sentry_org_token",
       "Sentry organization auth token", r"(sntrys_[A-Za-z0-9_-]{30,})", 90),
    _c("pf_newrelic_api_key", "newrelic_api_key",
       "New Relic user API key", r"(NRAK-[A-Z0-9]{27})", 90),
    _c("pf_posthog_personal_key", "posthog_personal_key",
       "PostHog personal API key", r"(phx_[A-Za-z0-9]{32,})", 90),
    _c("pf_notion_secret", "notion_integration_secret",
       "Notion integration secret", r"(ntn_[0-9]{6,}[A-Za-z0-9_-]{24,})", 90),
    _c("pf_airtable_pat", "airtable_pat",
       "Airtable personal access token",
       r"\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b", 95),
    _c("pf_contentful_token", "contentful_cma_token",
       "Contentful management token", r"(CFPAT-[A-Za-z0-9_-]{32,})", 90),
    _c("pf_flutterwave_secret", "flutterwave_secret_key",
       "Flutterwave secret key", r"(FLWSECK(?:_TEST)?-[A-Za-z0-9-]{10,})", 95),
    _c("pf_facebook_token", "facebook_access_token",
       "Facebook access token", r"\b(EAA[A-Za-z0-9]{30,})\b", 85),
    _c("pf_age_secret_key", "age_secret_key",
       "age encryption secret key", r"(AGE-SECRET-KEY-1[0-9A-Z]{40,})", 95),
    _c("pf_google_oauth_access", "google_oauth_access_token",
       "Google OAuth access token", r"(ya29\.[A-Za-z0-9_-]{30,})", 90),
    _c("pf_google_refresh_token", "google_oauth_refresh_token",
       "Google OAuth refresh token", r"\b(1//[A-Za-z0-9_-]{28,})", 95),
    _c("pf_aws_session_token", "aws_session_token",
       "AWS session token", r"(FQoGZXIvYXdzE[A-Za-z0-9+/=_-]{40,})", 90),
    _c("pf_otpauth_seed", "otpauth_totp_seed",
       "TOTP/HOTP shared secret (otpauth URL)",
       r"(otpauth://(?:totp|hotp)/[^\s\"'<>]+)", 90),
    _c("pf_square_oauth_secret", "square_oauth_secret",
       "Square OAuth application secret", r"(sq0csp-[A-Za-z0-9_-]{30,})", 90),

    # -- Family B (content): DB & infra connection material (13) -----------
    _c("pf_amqps_url", "amqps_url_with_credentials",
       "AMQP-over-TLS URL with credentials",
       r"(amqps://[^\s:\"'@/]+:[^\s\"'@/]+@[^\s\"'<>]+)", 90, group="infra"),
    _c("pf_nats_url", "nats_url_with_credentials",
       "NATS URL with credentials",
       r"(nats://[^\s:\"'@/]+:[^\s\"'@/]+@[^\s\"'<>]+)", 90, group="infra"),
    _c("pf_mqtt_url", "mqtt_url_with_credentials",
       "MQTT URL with credentials",
       r"(mqtts?://[^\s:\"'@/]+:[^\s\"'@/]+@[^\s\"'<>]+)", 90, group="infra"),
    _c("pf_clickhouse_url", "clickhouse_url_with_credentials",
       "ClickHouse URL with credentials",
       r"((?:clickhouse|clickhouses)://[^\s:\"'@/]+:[^\s\"'@/]+@[^\s\"'<>]+)",
       90, group="infra"),
    _c("pf_sqlserver_url", "sqlserver_url_with_credentials",
       "SQL Server URL with credentials",
       r"((?:sqlserver|mssql)://[^\s:\"'@/]+:[^\s\"'@/]+@[^\s\"'<>]+)",
       90, group="infra"),
    _c("pf_oracle_url", "oracle_url_with_credentials",
       "Oracle DB URL with credentials",
       r"(oracle://[^\s:\"'@/]+:[^\s\"'@/]+@[^\s\"'<>]+)", 90, group="infra"),
    _c("pf_cassandra_url", "cassandra_url_with_credentials",
       "Cassandra URL with credentials",
       r"(cassandra://[^\s:\"'@/]+:[^\s\"'@/]+@[^\s\"'<>]+)", 90, group="infra"),
    _c("pf_s3_cred_url", "s3_url_with_credentials",
       "S3 URL with embedded credentials",
       r"(s3://[A-Za-z0-9]{16,}:[^\s\"'@/]+@[^\s\"'<>]+)", 90, group="infra"),
    _c("pf_smtp_url", "smtp_url_with_credentials",
       "SMTP URL with credentials",
       r"(smtps?://[^\s:\"'@/]+:[^\s\"'@/]+@[^\s\"'<>]+)", 90, group="infra"),
    _c("pf_ldap_url", "ldap_url_with_credentials",
       "LDAP bind URL with credentials",
       r"(ldaps?://[^\s:\"'@/]+:[^\s\"'@/]+@[^\s\"'<>]+)", 90, group="infra"),
    _c("pf_presigned_s3_url", "presigned_s3_url",
       "Leaked presigned S3 URL",
       r"(https?://[^\s\"'<>]*[?&]X-Amz-Signature=[0-9a-f]{32,}[^\s\"'<>]*)",
       80, group="infra", show=10),
    _c("pf_gcs_signed_url", "gcs_signed_url",
       "Leaked Google Cloud Storage signed URL",
       r"(https?://[^\s\"'<>]*[?&]X-Goog-Signature=[0-9a-f]{32,}[^\s\"'<>]*)",
       80, group="infra", show=10),
    _c("pf_azure_sas_url", "azure_sas_url",
       "Leaked Azure Storage SAS URL",
       r"(https?://[a-z0-9.-]+\.(?:blob|queue|table|file)\.core\.windows\.net/[^\s\"'<>]*[?&]sig=[A-Za-z0-9%+/=]{20,}[^\s\"'<>]*)",
       85, group="infra", show=10),

    # -- Family C (content): wallets & crypto beyond the cp pack (13) ------
    _c("pf_sui_private_key", "sui_private_key",
       "Sui private key", r"(suiprivkey1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{40,})",
       95, group="web3", category="crypto"),
    _c("pf_aptos_private_key", "aptos_private_key",
       "Aptos private key", r"(ed25519-priv-0x[0-9a-fA-F]{64})",
       95, group="web3", category="crypto"),
    _c("pf_zcash_spending_key", "zcash_spending_key",
       "Zcash unified spending key", r"(secret-extended-key-main1[0-9a-z]{60,})",
       95, group="web3", category="crypto"),
    _c("pf_zcash_viewing_key", "zcash_viewing_key",
       "Zcash Sapling viewing key", r"\b(zxview[0-9a-z]{80,})",
       75, group="web3", category="crypto", severity="medium"),
    _c("pf_hedera_private_key", "hedera_private_key",
       "Hedera private key (DER ed25519)",
       r"(302e020100300506032b657004220420[0-9a-fA-F]{64})",
       95, group="web3", category="crypto"),
    _c("pf_filecoin_key_export", "filecoin_key_export",
       "Filecoin wallet key export",
       r"\"PrivateKey\"\s*:\s*\"([A-Za-z0-9+/=]{40,})\"",
       90, group="web3", category="crypto",
       context=r"secp256k1|\"Type\"\s*:\s*\"bls\"|filecoin"),
    _c("pf_tendermint_privkey", "tendermint_privkey",
       "Tendermint/Cosmos validator private key",
       r"\"type\"\s*:\s*\"tendermint/PrivKey\w+\"\s*,\s*\"value\"\s*:\s*\"([A-Za-z0-9+/=]{40,})\"",
       95, group="web3", category="crypto"),
    _c("pf_xrp_family_seed", "xrp_family_seed",
       "XRP family seed", r"\b(s[0-9A-HJ-NP-Za-km-z]{25,34})\b",
       95, group="web3", category="crypto",
       context=r"xrp|ripple|family[ _-]?seed", validator="xrp_seed"),
    _c("pf_monero_spend_key", "monero_spend_key",
       "Monero secret spend key", r"\b([0-9a-f]{64})\b",
       85, group="web3", category="crypto",
       context=r"monero|secret[ _-]?spend|spend[ _-]?key"),
    _c("pf_stellar_secret_key", "stellar_secret_key",
       "Stellar secret key", r"\b(S[A-Z2-7]{55})\b",
       95, group="web3", category="crypto", validator="stellar_secret"),
    _c("pf_cardano_signing_key", "cardano_signing_key",
       "Cardano payment signing key (CBOR)", r"\b(5820[0-9a-fA-F]{64})\b",
       90, group="web3", category="crypto",
       context=r"PaymentSigningKey|cardano|\.skey"),
    _c("pf_near_secret_key", "near_secret_key",
       "NEAR account secret key",
       r"(?:secret_key|private_key)[\"']?\s*[:=]\s*[\"']ed25519:([1-9A-HJ-NP-Za-km-z]{43,44})",
       90, group="web3", category="crypto", context=r"near"),
    _c("pf_lnd_macaroon", "lnd_macaroon",
       "LND macaroon (hex)", r"\b(0201[0-9a-f]{2}6c6e64[0-9a-f]{60,})\b",
       90, group="web3", category="crypto"),

    # -- Family E: personal-data exposure (8) -------------------------------
    _c("pf_pii_ssn_us", "us_ssn",
       "US Social Security number", r"\b(\d{3}-\d{2}-\d{4})\b",
       90, group="identity", category="identity", show=2, validator="ssn"),
    _c("pf_pii_sin_ca", "canadian_sin",
       "Canadian Social Insurance Number", r"\b(\d{3}[ -]\d{3}[ -]\d{3})\b",
       90, group="identity", category="identity", show=2, validator="sin"),
    _c("pf_pii_nhs_uk", "uk_nhs_number",
       "UK NHS number", r"\b(\d{3} \d{3} \d{4})\b",
       90, group="identity", category="identity", show=2, validator="nhs"),
    _c("pf_pii_nino_uk", "uk_national_insurance_number",
       "UK National Insurance number", r"\b([A-Z]{2}\d{6}[A-D])\b",
       85, group="identity", category="identity", show=2, validator="nino"),
    _c("pf_pii_aadhaar_in", "india_aadhaar_number",
       "India Aadhaar number", r"\b(\d{4} \d{4} \d{4})\b",
       90, group="identity", category="identity", show=2, validator="aadhaar"),
    _c("pf_pii_pan_in", "india_pan",
       "India PAN", r"\b([A-Z]{5}\d{4}[A-Z])\b",
       85, group="identity", category="identity", show=2, validator="pan"),
    _c("pf_pii_tfn_au", "australia_tfn",
       "Australian Tax File Number", r"\b(\d{3} \d{3} \d{3})\b",
       90, group="identity", category="identity", show=2, validator="tfn"),
    _c("pf_pii_iban", "iban",
       "IBAN (validated)", r"\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b",
       85, group="identity", category="identity", show=4, validator="iban"),

    # -- Family F: tokens & session material (7) ----------------------------
    _c("pf_jwk_private_key", "jwk_private_key",
       "JWK private key material", r"\"d\"\s*:\s*\"([A-Za-z0-9_-]{40,})\"",
       90, context=r"\"kty\"|\"kid\"|jwk"),
    _c("pf_ably_api_key", "ably_api_key",
       "Ably API key", r"([A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{6}:[A-Za-z0-9_-]{24,})",
       85, context=r"ably"),
    _c("pf_session_cookie_leak", "session_cookie_value",
       "Session cookie value in served text",
       r"\b((?:connect\.sid|PHPSESSID|sessionid|JSESSIONID)=[A-Za-z0-9%._-]{24,})",
       85),
    _c("pf_token_in_url", "token_in_public_url",
       "Access token embedded in a public URL",
       r"(https?://[^\s\"'<>]*[?&](?:access_token|api_key)=[A-Za-z0-9._-]{16,}[^\s\"'<>]*)",
       80, show=10),
    _c("pf_reset_link_leak", "password_reset_link",
       "Password-reset / magic-login link",
       r"(https?://[^\s\"'<>]*/(?:reset-password|password-reset|magic-login|verify-email)[^\s\"'<>]*[?&](?:token|code)=[A-Za-z0-9_-]{16,}[^\s\"'<>]*)",
       85, show=10),
    _c("pf_auth_secret_env", "framework_auth_secret",
       "Framework auth secret (env-style)",
       r"(?i)\b(?:NEXTAUTH_SECRET|SESSION_SECRET|JWT_SECRET|AUTH_SECRET)\s*=\s*([^\s\"']{16,})",
       90),
    _c("pf_webhook_secret_env", "webhook_signing_secret_env",
       "Webhook signing secret (env-style)",
       r"(?i)\b(?:WEBHOOK_SECRET|WEBHOOK_SIGNING_SECRET|SIGNING_SECRET)\s*=\s*([^\s\"']{12,})",
       90),
]


def _p(pid, key, label, paths, body_re, conf=90, group="web",
       category="leak", severity="high"):
    return {"id": pid, "key": key, "label": label, "paths": paths,
            "body_re": body_re, "conf": conf, "group": group,
            "category": category, "severity": severity}


PATH_SPECS = [
    # -- Family B (paths): exposed admin consoles / info endpoints (7) -----
    _p("pf_mongo_express_console", "mongo_express_console",
       "Mongo Express console (DB contents browsable)",
       ["/mongo-express/"], r"Mongo Express|mongo-express",
       group="infra", category="infra"),
    _p("pf_redis_commander_console", "redis_commander_console",
       "Redis Commander console",
       ["/redis-commander/"], r"Redis Commander|redis-commander",
       group="infra", category="infra"),
    _p("pf_portainer_console", "portainer_console",
       "Portainer container console",
       ["/portainer/", "/portainer"], r"Portainer",
       group="infra", category="infra"),
    _p("pf_elasticsearch_info", "elasticsearch_cluster_info",
       "Elasticsearch cluster info (unauthenticated)",
       ["/_cluster/health", "/"], r"cluster_name",
       group="infra", category="infra"),
    _p("pf_solr_admin", "solr_admin_info",
       "Apache Solr admin info",
       ["/solr/admin/info/system", "/solr/"], r"solr|lucene",
       group="infra", category="infra"),
    _p("pf_etcd_version", "etcd_version_disclosure",
       "etcd version endpoint (unauthenticated)",
       ["/version"], r"etcdserver|etcdcluster",
       group="infra", category="infra"),
    _p("pf_consul_agent_info", "consul_agent_info",
       "Consul agent info (unauthenticated)",
       ["/v1/agent/self", "/ui/"], r"consul|\"Datacenter\"",
       group="infra", category="infra"),

    # -- Family C (paths): wallet / validator key files (2) -----------------
    _p("pf_priv_validator_key_file", "priv_validator_key_file",
       "Cosmos validator private key file",
       ["/priv_validator_key.json", "/config/priv_validator_key.json"],
       r"priv_key", group="web3", category="crypto"),
    _p("pf_deposit_data_file", "eth2_deposit_data_file",
       "Eth2 validator deposit data file",
       ["/deposit_data.json", "/deposit-data.json"],
       r"withdrawal_credentials", group="web3", category="crypto"),

    # -- Family D: leaked secret-bearing files (20) --------------------------
    _p("pf_tfstate_file", "terraform_state_file",
       "Terraform state file (contains secrets)",
       ["/terraform.tfstate", "/terraform.tfstate.backup"],
       r"terraform_version|\"resources\""),
    _p("pf_tfvars_file", "terraform_vars_file",
       "Terraform variables file with secrets",
       ["/terraform.tfvars", "/main.tfvars"],
       r"(?i)(password|secret|access_key|token)\s*="),
    _p("pf_terraformrc_file", "terraformrc_credentials",
       "Terraform CLI config with registry token",
       ["/.terraformrc"], r"(?i)credentials|token"),
    _p("pf_rails_master_key", "rails_master_key",
       "Rails master key file",
       ["/config/master.key"], r"(?m)^[0-9a-f]{32}\s*$"),
    _p("pf_auth_json_file", "docker_auth_json",
       "Registry auth.json with credentials",
       ["/auth.json"], r"\"auths\""),
    _p("pf_docker_config_file", "docker_config_json",
       "Docker client config with registry credentials",
       ["/.docker/config.json", "/docker-config.json"], r"\"auths\""),
    _p("pf_kubeconfig_file", "kubeconfig_file",
       "Kubernetes kubeconfig with client keys",
       ["/.kube/config", "/kubeconfig.yaml", "/kubeconfig"],
       r"client-key-data|client-certificate-data"),
    _p("pf_edgerc_file", "akamai_edgerc",
       "Akamai .edgerc API credentials",
       ["/.edgerc"], r"client_secret|client_token"),
    _p("pf_pypirc_file", "pypirc_credentials",
       "PyPI .pypirc with repository password",
       ["/.pypirc"], r"(?i)password"),
    _p("pf_ssh_ed25519_file", "ssh_ed25519_private_key_file",
       "SSH ed25519 private key file",
       ["/.ssh/id_ed25519", "/id_ed25519"], r"PRIVATE KEY"),
    _p("pf_google_services_json", "google_services_json",
       "Firebase google-services.json (mobile backend config)",
       ["/google-services.json"], r"\"api_key\"|\"project_id\"",
       group="mobile", category="mobile"),
    _p("pf_apple_service_plist", "google_service_info_plist",
       "Firebase GoogleService-Info.plist (mobile backend config)",
       ["/GoogleService-Info.plist"], r"API_KEY|BUNDLE_ID",
       group="mobile", category="mobile"),
    _p("pf_appsettings_json", "aspnet_appsettings",
       "ASP.NET appsettings with connection strings",
       ["/appsettings.json", "/appsettings.Production.json"],
       r"ConnectionStrings|Password"),
    _p("pf_serverless_yml", "serverless_config",
       "Serverless Framework config with secrets",
       ["/serverless.yml", "/serverless.yaml"],
       r"(?i)(secret|password|api[_-]?key)\s*:"),
    _p("pf_postman_collection", "postman_collection_with_auth",
       "Postman collection with embedded auth",
       ["/postman_collection.json", "/collection.json",
        "/api.postman_collection.json"],
       r"(?i)\"auth\"|bearer|api_key"),
    _p("pf_laravel_log", "laravel_log_with_secrets",
       "Laravel log file with secrets",
       ["/storage/logs/laravel.log"],
       r"(?i)(password|secret|token|api[_-]?key)"),
    _p("pf_electrum_wallet_file", "electrum_wallet_file",
       "Electrum wallet file",
       ["/wallet.json", "/electrum_wallet.json"], r"seed_version|\"keystore\"",
       group="web3", category="crypto"),
    _p("pf_idea_workspace", "jetbrains_workspace_with_secrets",
       "JetBrains workspace.xml with credentials",
       ["/.idea/workspace.xml"], r"(?i)password|token"),
    _p("pf_notebook_creds", "jupyter_notebook_with_credentials",
       "Jupyter notebook with embedded credentials",
       ["/notebook.ipynb", "/Untitled.ipynb", "/analysis.ipynb"],
       r"(?i)(password|api[_-]?key|secret|token)\s*[\"']?\s*[:=]"),
    _p("pf_cookies_txt", "cookies_txt_session_file",
       "cookies.txt session file",
       ["/cookies.txt"], r"Netscape HTTP Cookie File|session"),
]


# ---------------------------------------------------------------------------
# Generate one Plugin subclass per spec (registry discovers them by id)
# ---------------------------------------------------------------------------

def _class_name(pid: str) -> str:
    return "Pf" + "".join(w.capitalize() for w in pid[3:].split("_"))


def _make_content(spec: dict):
    attrs = {
        "id": spec["id"], "label": spec["label"],
        "description": (f"Private findings: detects {spec['label']} publicly "
                        "exposed in page/JS text. Masked + fingerprinted; "
                        "detection only."),
        "group": spec["group"], "PATTERN": spec["pattern"],
        "KEY": spec["key"], "LABEL": spec["label"], "CONF": spec["conf"],
        "CATEGORY": spec["category"], "SEVERITY": spec["severity"],
        "SHOW": spec["show"], "CONTEXT_RE": spec["context"],
        "VALIDATOR": spec["validator"],
        "__module__": __name__,
    }
    return type(_class_name(spec["id"]), (PfContent,), attrs)


def _make_path(spec: dict):
    attrs = {
        "id": spec["id"], "label": spec["label"],
        "description": (f"Private findings: detects {spec['label']} publicly "
                        "served at a well-known path. Marker-gated; "
                        "detection only."),
        "group": spec["group"], "PATHS": spec["paths"],
        "BODY_RE": spec["body_re"], "KEY": spec["key"],
        "LABEL": spec["label"], "CONF": spec["conf"],
        "CATEGORY": spec["category"], "SEVERITY": spec["severity"],
        "__module__": __name__,
    }
    return type(_class_name(spec["id"]), (PfPath,), attrs)


PRIVFIND_IDS: List[str] = []


def _register() -> None:
    for spec in CONTENT_SPECS:
        cls = _make_content(spec)
        globals()[cls.__name__] = cls
        PRIVFIND_IDS.append(spec["id"])
    for spec in PATH_SPECS:
        cls = _make_path(spec)
        globals()[cls.__name__] = cls
        PRIVFIND_IDS.append(spec["id"])


_register()
