"""Secret-exposure detector pack (sec_*): publicly EXPOSED credential material.

Five detectors for the five families Jay specified, all detection of
material that is already publicly reachable on an authorized scan target.
Read-only GETs, passive, no payloads, no scope-gating changes.

EVIDENCE RULE (non-negotiable): no finding ever carries a full secret,
key, seed phrase, or token in `value`, `evidence`, or `raw`. Findings
carry a masked value plus a SHA-256 fingerprint of the matched material
so the owner can confirm rotation, plus the location and remediation.
Seed phrases are never shown even in part: only the word count.

Families:
  sec_js_hardcoded     hardcoded credentials in public JS / web roots /
                       publicly linked mobile binaries
  sec_committed_config committed config files with raw key material
                       (.env, .pem, id_rsa, credentials files)
  sec_public_storage   misconfigured public storage: bucket listings,
                       backup/dump archives, public storage listings
  sec_log_exposure     raw keys/tokens in publicly readable logs
  sec_weak_crypto      weak/broken hashing (unsalted MD5, SHA-1) in
                       password/token contexts, with the honest nuance
                       that cracking a hash recovers the secret string,
                       not an asymmetric private key, unless that secret
                       was used as an unseeded deterministic key source
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import is_placeholder

SEC_IDS = [
    "sec_js_hardcoded",
    "sec_committed_config",
    "sec_public_storage",
    "sec_log_exposure",
    "sec_weak_crypto",
]

SCOPE_NOTE = ("Authorized testing only: verify you own this asset or it "
              "is in an approved bounty scope before acting on this "
              "finding.")


# ---------------------------------------------------------------------------
# Masking / fingerprint helpers. The full match NEVER leaves this module
# except as a SHA-256 fingerprint.
# ---------------------------------------------------------------------------

def mask_secret(s: str, show: int = 4) -> str:
    s = (s or "").strip()
    if len(s) <= show:
        return "***"
    if len(s) <= show * 2 + 3:
        return s[:show] + "..." + s[-show:]
    return s[:show] + "..." + s[-show:]


def fingerprint(s: str) -> str:
    return hashlib.sha256((s or "").encode()).hexdigest()


def safe_evidence(severity: str, pattern: str, masked: str, fp: str,
                  remediation: str, extra: Dict | None = None) -> Dict:
    ev: Dict = {
        "severity": severity,
        "pattern": pattern,
        "redacted": masked,
        "fingerprint_sha256": fp,
        "remediation": remediation,
        "scope_note": SCOPE_NOTE,
    }
    if extra:
        ev.update(extra)
    return ev


PLACEHOLDER_HINTS = (
    "example", "sample", "test", "testing", "demo", "placeholder",
    "changeme", "xxx", "todo", "yourkey", "your_key", "fakekey",
    "lorem", "dummy",
)


def _looks_fake(value: str) -> bool:
    if not value or is_placeholder(value):
        return True
    low = value.lower()
    return any(h in low for h in PLACEHOLDER_HINTS)


# ---------------------------------------------------------------------------
# Detection patterns (public formats, not secret values).
# ---------------------------------------------------------------------------

AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PEM_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
                    r"[A-Za-z0-9_-]{10,}\b")
BEARER_RE = re.compile(r"Bearer\s+([A-Za-z0-9_\-~+/=]{20,200})")
ASSIGN_RE = re.compile(
    r"(?i)(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|"
    r"client[_-]?secret|auth[_-]?token|access[_-]?token|"
    r"private[_-]?key|passwd|password|pwd|secret|token)"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9_\-+/=.]{16,200})['\"]?")
ENV_LINE_RE = re.compile(
    r"(?m)^\s*([A-Z0-9_]{2,64})\s*=\s*['\"]?([^'\"\s]{8,200})['\"]?\s*$")
SEED_CTX_RE = re.compile(
    r"(?i)(?:mnemonic|seed[\s_-]?phrase|recovery[\s_-]?phrase)"
    r"\s*[:=]\s*['\"]([^'\"]{20,600})['\"]")
MD5_USAGE_RE = re.compile(
    r"(?i)\bmd5\s*\(|createHash\s*\(\s*['\"]md5['\"]|"
    r"hashlib\.md5\s*\(")
SHA1_USAGE_RE = re.compile(
    r"(?i)\bsha1\s*\(|createHash\s*\(\s*['\"]sha1['\"]|"
    r"hashlib\.sha1\s*\(")
HEX_CTX_RE = re.compile(
    r"(?i)(?:password[_-]?hash|pass[_-]?hash|passwd|pwd|password|"
    r"hash|token)['\"\s:=\]]{0,12}([a-f0-9]{32}|[a-f0-9]{40})\b")
BUCKET_XML_RE = re.compile(r"<ListBucketResult[\s>]")
BUCKET_KEY_RE = re.compile(r"<Key>([^<]{1,200})</Key>")
DIR_LIST_RE = re.compile(
    r"(?i)(?:<title>Index of /|Directory listing for|"
    r"<h1>Index of /)")
LINK_RE = re.compile(r"""href=["']([^"']+)["']""", re.I)
SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src=["']([^"']+)["']""", re.I)
INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]+src=)[^>]*>(.*?)</script>", re.I | re.S)
ARCHIVE_NAMES = (".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar",
                 ".sql", ".sql.gz", ".db", ".sqlite", ".dump", ".bak")
LOG_NAMES = (".log",)
SENSITIVE_ARCHIVE_MARKERS = (
    "BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
    "AWS_SECRET_ACCESS_KEY", "AKIA",
)


def _same_domain(url: str, domain: str) -> bool:
    try:
        return domain.lower() in urlparse(url).netloc.lower()
    except Exception:
        return False


class _SecBase(Plugin):
    """Shared run plumbing for the sec_* pack."""

    # Empty id so the registry (which collects every Plugin subclass
    # with a truthy id) never registers this abstract base itself.
    id = ""
    cost = Cost.FREE
    group = "web"
    accepts = ["domain", "url"]

    async def _base(self, target: Target, ctx: Ctx):
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return None, None, None
        base = await web_base(ctx, target, domain)
        return domain, base, (ctx.mode == "passive")

    def _emit(self, findings: List[Finding], category: str, key: str,
              severity: str, value: str, source: str, source_url: str,
              pattern: str, masked: str, fp: str, remediation: str,
              confidence: int, passive: bool, extra: Dict | None = None):
        findings.append(self._f(
            category, key, value, source, source_url=source_url,
            confidence=confidence,
            evidence=safe_evidence(severity, pattern, masked, fp,
                                   remediation, extra),
            passive=passive))


# ---------------------------------------------------------------------------
# Family 1: hardcoded credentials in public assets
# ---------------------------------------------------------------------------

class SecJsHardcodedPlugin(_SecBase):
    id = "sec_js_hardcoded"
    label = "Hardcoded Credentials in Public Assets"
    description = (
        "Private keys, API secrets, seed phrases, and tokens embedded in "
        "client-side JavaScript, inline scripts, and publicly linked "
        "mobile binaries. Findings are masked with a fingerprint only.")
    passive = True

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain, base, passive = await self._base(target, ctx)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        seen: Set[Tuple[str, str]] = set()
        page = await ctx.fetch_page(base, timeout=12)
        if not page:
            return self._degraded("homepage unreachable")
        html = page.get("text", "") or ""
        texts: List[Tuple[str, str, str]] = []
        for sm in INLINE_SCRIPT_RE.finditer(html):
            body = sm.group(1).strip()
            if len(body) > 20:
                texts.append((body[:500000], base, "inline script"))
        js_urls: Set[str] = set()
        for sm in SCRIPT_SRC_RE.finditer(html):
            full = urljoin(base, sm.group(1))
            if _same_domain(full, domain):
                js_urls.add(full)
        for ju in ctx.consume("js_files"):
            if isinstance(ju, str) and domain in urlparse(ju).netloc:
                js_urls.add(ju)
        for ju in sorted(js_urls)[:15]:
            try:
                jr = await ctx.fetch_page(ju, timeout=12)
                if jr and (jr.get("status_code") == 200):
                    texts.append((jr.get("text", "")[:500000], ju,
                                  "JS bundle"))
            except Exception:
                continue
        # Publicly linked mobile binaries: scan the reachable bytes for
        # key material without executing anything.
        bin_urls: Set[str] = set()
        for sm in LINK_RE.finditer(html):
            href = sm.group(1)
            if href.lower().split("?")[0].endswith((".apk", ".ipa", ".aab")):
                full = urljoin(base, href)
                if _same_domain(full, domain):
                    bin_urls.add(full)
        for bu in sorted(bin_urls)[:3]:
            try:
                br = await ctx.fetch_page(bu, timeout=15)
                if br and (br.get("status_code") == 200):
                    texts.append((br.get("text", "")[:500000], bu,
                                  "mobile binary"))
            except Exception:
                continue
        for text, src_url, kind in texts:
            self._scan_text(text, src_url, kind, findings, seen, passive)
        return self._ok(findings, f"scanned {len(texts)} public assets")

    def _scan_text(self, text, src_url, kind, findings, seen, passive):
        # Private key blocks: masked, never shown.
        for m in PEM_RE.finditer(text):
            block = text[m.start():m.start() + 200]
            fp = fingerprint(block)
            if ("sec_js_private_key", fp) in seen:
                continue
            seen.add(("sec_js_private_key", fp))
            self._emit(
                findings, "leak", "sec_js_private_key", "high",
                f"HIGH: private key block exposed in {kind} "
                f"(fingerprint {fp[:16]})",
                f"Hardcoded credential in {kind}", src_url,
                "PEM private key block", "***", fp,
                "Treat this key as burned: rotate it immediately, remove "
                "it from client-side code and binaries, and move secrets "
                "server-side behind your own API.", 90, passive,
                {"asset_kind": kind})
        # Seed phrases: word count only, never the words.
        for m in SEED_CTX_RE.finditer(text):
            phrase = m.group(1).strip()
            words = phrase.split()
            if len(words) not in (12, 15, 18, 21, 24):
                continue
            fp = fingerprint(phrase)
            if ("sec_js_seed_phrase", fp) in seen:
                continue
            seen.add(("sec_js_seed_phrase", fp))
            self._emit(
                findings, "leak", "sec_js_seed_phrase", "high",
                f"HIGH: {len(words)}-word seed phrase exposed in {kind} "
                f"(fingerprint {fp[:16]}, words never shown)",
                f"Hardcoded credential in {kind}", src_url,
                "seed/mnemonic phrase", "[phrase redacted]", fp,
                "Funds are at risk. Sweep funds to a new wallet generated "
                "offline, then treat this phrase as burned. Never ship "
                "seed material in client code.", 90, passive,
                {"asset_kind": kind, "word_count": len(words)})
        # AWS-style keys.
        for m in AWS_KEY_RE.finditer(text):
            raw = m.group(0)
            fp = fingerprint(raw)
            if ("sec_js_credential", fp) in seen:
                continue
            seen.add(("sec_js_credential", fp))
            self._emit(
                findings, "leak", "sec_js_credential", "high",
                f"HIGH: cloud access key {mask_secret(raw)} in {kind} "
                f"(fingerprint {fp[:16]})",
                f"Hardcoded credential in {kind}", src_url,
                "cloud access key", mask_secret(raw), fp,
                "Rotate this key immediately in the provider dashboard, "
                "then remove it from client-side code. Move it "
                "server-side behind your own API.", 85, passive,
                {"asset_kind": kind})
        # JWTs.
        for m in JWT_RE.finditer(text):
            raw = m.group(0)
            if _looks_fake(raw):
                continue
            fp = fingerprint(raw)
            if ("sec_js_token", fp) in seen:
                continue
            seen.add(("sec_js_token", fp))
            self._emit(
                findings, "leak", "sec_js_token", "medium",
                f"MEDIUM: bearer token {mask_secret(raw)} in {kind} "
                f"(fingerprint {fp[:16]})",
                f"Hardcoded credential in {kind}", src_url,
                "JWT", mask_secret(raw), fp,
                "Revoke this token now, audit access logs for misuse, "
                "and move tokens server-side.", 75, passive,
                {"asset_kind": kind})
        # Generic key/secret assignments.
        for m in ASSIGN_RE.finditer(text):
            raw = m.group(1)
            if _looks_fake(raw) or len(raw) < 16:
                continue
            fp = fingerprint(raw)
            if ("sec_js_credential", fp) in seen:
                continue
            seen.add(("sec_js_credential", fp))
            self._emit(
                findings, "leak", "sec_js_credential", "high",
                f"HIGH: hardcoded secret {mask_secret(raw)} in {kind} "
                f"(fingerprint {fp[:16]})",
                f"Hardcoded credential in {kind}", src_url,
                "secret assignment", mask_secret(raw), fp,
                "Rotate this secret immediately, then remove it from "
                "client-side code. Move secrets server-side behind "
                "your own API.", 85, passive,
                {"asset_kind": kind})


# ---------------------------------------------------------------------------
# Family 2: committed config files with raw key material
# ---------------------------------------------------------------------------

CONFIG_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.env.bak", "/.env.old", "/config/.env", "/app/.env",
    "/.aws/credentials", "/.git-credentials", "/.npmrc",
    "/secrets.json", "/credentials.json", "/config.json",
    "/id_rsa", "/id_dsa", "/.ssh/id_rsa", "/server.key",
    "/private.key", "/key.pem", "/private.pem", "/server.pem",
    "/.docker/config.json", "/wp-config.php", "/config.php",
]


class SecCommittedConfigPlugin(_SecBase):
    id = "sec_committed_config"
    label = "Committed Config Files with Raw Key Material"
    description = (
        "Configuration files reachable in public web roots that contain "
        "raw key material (.env, .pem, id_rsa, credentials files). "
        "Fires only when the body actually contains credential "
        "patterns. Findings are masked with a fingerprint only.")
    passive = True

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain, base, passive = await self._base(target, ctx)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        seen: Set[Tuple[str, str]] = set()
        for path in CONFIG_PATHS:
            url = base.rstrip("/") + path
            try:
                r = await ctx.probe(url, timeout=8)
            except Exception:
                continue
            if not r or r.get("status") != 200:
                continue
            body = r.get("text", "") or ""
            if not body.strip():
                continue
            self._scan_body(body, url, path, findings, seen, passive)
        return self._ok(findings, f"probed {len(CONFIG_PATHS)} config paths")

    def _scan_body(self, body, url, path, findings, seen, passive):
        # PEM block anywhere in the file.
        if PEM_RE.search(body):
            fp = fingerprint("pem:" + path)
            if ("sec_exposed_config", fp) not in seen:
                seen.add(("sec_exposed_config", fp))
                self._emit(
                    findings, "leak", "sec_exposed_config", "high",
                    f"HIGH: private key material in public file {path} "
                    f"(fingerprint {fp[:16]})",
                    "Exposed config file", url,
                    "PEM private key block", "***", fp,
                    "Treat this key as burned: rotate it immediately, "
                    "remove the file from the public web root and from "
                    "version control history, and move secrets to a "
                    "vault.", 90, passive, {"path": path})
        # AWS-style key.
        m = AWS_KEY_RE.search(body)
        if m:
            raw = m.group(0)
            fp = fingerprint(raw)
            if ("sec_exposed_config", fp) not in seen:
                seen.add(("sec_exposed_config", fp))
                self._emit(
                    findings, "leak", "sec_exposed_config", "high",
                    f"HIGH: cloud access key {mask_secret(raw)} in "
                    f"public file {path} (fingerprint {fp[:16]})",
                    "Exposed config file", url,
                    "cloud access key", mask_secret(raw), fp,
                    "Rotate this key immediately in the provider "
                    "dashboard, remove the file from the public web "
                    "root and from version control history.", 90,
                    passive, {"path": path})
        # KEY=VALUE lines with real-looking values.
        for em in ENV_LINE_RE.finditer(body):
            name, raw = em.group(1), em.group(2)
            if _looks_fake(raw):
                continue
            if not re.search(r"(?i)key|secret|token|pass|pwd|auth",
                             name):
                continue
            fp = fingerprint(raw)
            if ("sec_exposed_config", fp) in seen:
                continue
            seen.add(("sec_exposed_config", fp))
            self._emit(
                findings, "leak", "sec_exposed_config", "high",
                f"HIGH: credential {name}={mask_secret(raw)} in public "
                f"file {path} (fingerprint {fp[:16]})",
                "Exposed config file", url,
                "config credential assignment", mask_secret(raw), fp,
                "Rotate this credential now, audit access logs for "
                "misuse, remove the file from the public web root "
                "and from version control history, and move secrets "
                "to a vault.", 85, passive,
                {"path": path, "variable": name})


# ---------------------------------------------------------------------------
# Family 3: misconfigured public storage
# ---------------------------------------------------------------------------

STORAGE_PATHS = [
    "/storage/", "/backups/", "/backup/", "/dumps/", "/dump/",
    "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/site.zip",
    "/www.zip", "/db.sql", "/dump.sql", "/database.sql",
    "/backup.sql", "/backup.db", "/site.db", "/app.db",
]


class SecPublicStoragePlugin(_SecBase):
    id = "sec_public_storage"
    label = "Misconfigured Public Storage"
    description = (
        "Publicly readable cloud storage listings, backup files, "
        "database dumps, and application logs in storage containers "
        "with public read or list permissions. Archives fire only "
        "when their readable content carries environment or keystore "
        "markers. Findings are masked with a fingerprint only.")
    passive = True

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain, base, passive = await self._base(target, ctx)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        seen: Set[Tuple[str, str]] = set()
        for path in STORAGE_PATHS:
            url = base.rstrip("/") + path
            try:
                r = await ctx.probe(url, timeout=8)
            except Exception:
                continue
            if not r or r.get("status") != 200:
                continue
            body = r.get("text", "") or ""
            if not body.strip():
                continue
            self._scan_body(body, url, path, findings, seen, passive)
        return self._ok(findings, f"probed {len(STORAGE_PATHS)} storage paths")

    def _scan_body(self, body, url, path, findings, seen, passive):
        # Bucket listing XML: object names are not secrets, safe to show.
        if BUCKET_XML_RE.search(body):
            keys = BUCKET_KEY_RE.findall(body)[:20]
            fp = fingerprint("bucket:" + path + ":" + "|".join(keys))
            if ("sec_bucket_listing", fp) not in seen:
                seen.add(("sec_bucket_listing", fp))
                shown = ", ".join(keys[:8])
                self._emit(
                    findings, "leak", "sec_bucket_listing", "high",
                    f"HIGH: public bucket listing at {path} "
                    f"(fingerprint {fp[:16]}): {shown}",
                    "Public storage listing", url,
                    "bucket listing XML", "***", fp,
                    "Restrict this container to private access "
                    "immediately, audit download logs, and rotate "
                    "any credential or keystore material the listed "
                    "objects contain.", 85, passive,
                    {"path": path, "object_count": len(keys)})
            return
        # Directory listing exposing backup/dump/log objects.
        if DIR_LIST_RE.search(body):
            links = [h for h in LINK_RE.findall(body)
                     if h.lower().split("?")[0].endswith(
                         ARCHIVE_NAMES + LOG_NAMES)]
            if links:
                fp = fingerprint("listing:" + path + ":" + "|".join(links))
                if ("sec_storage_listing", fp) not in seen:
                    seen.add(("sec_storage_listing", fp))
                    self._emit(
                        findings, "leak", "sec_storage_listing", "medium",
                        f"MEDIUM: public storage listing at {path} "
                        f"exposes {len(links)} backup/log objects "
                        f"(fingerprint {fp[:16]})",
                        "Public storage listing", url,
                        "directory listing", "***", fp,
                        "Restrict this directory to private access, "
                        "remove backup and log objects from public "
                        "reach, and audit download logs.", 70, passive,
                        {"path": path, "object_count": len(links)})
                return
        # Archive/dump content carrying env or keystore markers.
        markers = [mk for mk in SENSITIVE_ARCHIVE_MARKERS if mk in body]
        env_hit = bool(ENV_LINE_RE.search(body)) and bool(
            re.search(r"(?i)key|secret|token|pass", body))
        if markers or env_hit:
            fp = fingerprint("archive:" + path + ":" +
                             "|".join(sorted(markers)))
            if ("sec_storage_archive_secrets", fp) not in seen:
                seen.add(("sec_storage_archive_secrets", fp))
                self._emit(
                    findings, "leak", "sec_storage_archive_secrets",
                    "high",
                    f"HIGH: publicly readable archive/dump at {path} "
                    f"contains environment or key material markers "
                    f"(fingerprint {fp[:16]})",
                    "Public storage content", url,
                    "archive/dump secret markers", "***", fp,
                    "Restrict this object to private access "
                    "immediately, audit download logs, and rotate "
                    "any credential or keystore material it "
                    "contains.", 85, passive,
                    {"path": path, "markers": sorted(markers)})


# ---------------------------------------------------------------------------
# Family 4: insecure application logging
# ---------------------------------------------------------------------------

LOG_PATHS = [
    "/logs/", "/logs/app.log", "/logs/error.log", "/logs/laravel.log",
    "/logs/access.log", "/error.log", "/debug.log", "/app.log",
    "/laravel.log", "/trace.log", "/logs/trace.log", "/php_error.log",
    "/logs/debug.log",
]


class SecLogExposurePlugin(_SecBase):
    id = "sec_log_exposure"
    label = "Insecure Application Logging"
    description = (
        "Raw private keys or authorization tokens in error logs or "
        "transaction traces stored in publicly readable log "
        "directories. Public logs are routinely indexed by search "
        "engines, so public readability is the exposure. Findings "
        "are masked with a fingerprint only.")
    passive = True

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain, base, passive = await self._base(target, ctx)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        seen: Set[Tuple[str, str]] = set()
        for path in LOG_PATHS:
            url = base.rstrip("/") + path
            try:
                r = await ctx.probe(url, timeout=8)
            except Exception:
                continue
            if not r or r.get("status") != 200:
                continue
            body = r.get("text", "") or ""
            if not body.strip():
                continue
            self._scan_body(body, url, path, findings, seen, passive)
        return self._ok(findings, f"probed {len(LOG_PATHS)} log paths")

    def _scan_body(self, body, url, path, findings, seen, passive):
        if DIR_LIST_RE.search(body):
            links = [h for h in LINK_RE.findall(body)
                     if h.lower().split("?")[0].endswith(LOG_NAMES)]
            if links:
                fp = fingerprint("loglisting:" + path)
                if ("sec_log_listing", fp) not in seen:
                    seen.add(("sec_log_listing", fp))
                    self._emit(
                        findings, "leak", "sec_log_listing", "medium",
                        f"MEDIUM: public log directory listing at "
                        f"{path} exposes {len(links)} log files "
                        f"(fingerprint {fp[:16]})",
                        "Public log directory", url,
                        "log directory listing", "***", fp,
                        "Restrict log directories to private access, "
                        "remove logs from the web root, and stop "
                        "writing secrets to logs.", 70, passive,
                        {"path": path, "object_count": len(links)})
                return
        if PEM_RE.search(body):
            fp = fingerprint("logpem:" + path)
            if ("sec_log_key", fp) not in seen:
                seen.add(("sec_log_key", fp))
                self._emit(
                    findings, "leak", "sec_log_key", "high",
                    f"HIGH: private key material in public log {path} "
                    f"(fingerprint {fp[:16]})",
                    "Public log content", url,
                    "PEM private key block", "***", fp,
                    "Treat this key as burned: rotate it immediately, "
                    "remove the log from public reach, and stop "
                    "writing secrets to logs.", 90, passive,
                    {"path": path})
        for m in BEARER_RE.finditer(body):
            raw = m.group(1)
            if _looks_fake(raw):
                continue
            fp = fingerprint(raw)
            if ("sec_log_token", fp) in seen:
                continue
            seen.add(("sec_log_token", fp))
            self._emit(
                findings, "leak", "sec_log_token", "high",
                f"HIGH: authorization token {mask_secret(raw)} in "
                f"public log {path} (fingerprint {fp[:16]})",
                "Public log content", url,
                "bearer token", mask_secret(raw), fp,
                "Revoke this token now, audit access logs for "
                "misuse, remove the log from public reach, and "
                "stop writing tokens to logs.", 85, passive,
                {"path": path})
        for m in ASSIGN_RE.finditer(body):
            raw = m.group(1)
            if _looks_fake(raw) or len(raw) < 16:
                continue
            fp = fingerprint(raw)
            if ("sec_log_token", fp) in seen:
                continue
            seen.add(("sec_log_token", fp))
            self._emit(
                findings, "leak", "sec_log_token", "high",
                f"HIGH: logged secret {mask_secret(raw)} in public "
                f"log {path} (fingerprint {fp[:16]})",
                "Public log content", url,
                "secret assignment", mask_secret(raw), fp,
                "Rotate this secret now, audit access logs for "
                "misuse, remove the log from public reach, and "
                "stop writing secrets to logs.", 85, passive,
                {"path": path})


# ---------------------------------------------------------------------------
# Family 5: cryptographic algorithm weaknesses
# ---------------------------------------------------------------------------

WEAK_CRYPTO_NUANCE = (
    "Cracking a hash recovers the underlying secret string (such as a "
    "password). It does not directly derive an asymmetric private key "
    "unless that secret was used as an unseeded deterministic key "
    "generation source.")


class SecWeakCryptoPlugin(_SecBase):
    id = "sec_weak_crypto"
    label = "Cryptographic Algorithm Weaknesses"
    description = (
        "Weak or broken hashing (unsalted MD5, SHA-1) used for "
        "password storage or token generation, observed in public "
        "JavaScript and pages. MD5 and SHA-1 are broken for password "
        "storage regardless of salt: they are fast and collision-"
        "prone. Use bcrypt or Argon2. Findings carry the honest "
        "nuance that cracking a hash recovers the secret string, "
        "not an asymmetric private key, unless that secret fed "
        "unseeded deterministic key generation.")
    passive = True

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain, base, passive = await self._base(target, ctx)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        seen: Set[Tuple[str, str]] = set()
        page = await ctx.fetch_page(base, timeout=12)
        if not page:
            return self._degraded("homepage unreachable")
        html = page.get("text", "") or ""
        texts: List[Tuple[str, str, str]] = [(html, base, "homepage")]
        js_urls: Set[str] = set()
        for sm in SCRIPT_SRC_RE.finditer(html):
            full = urljoin(base, sm.group(1))
            if _same_domain(full, domain):
                js_urls.add(full)
        for ju in ctx.consume("js_files"):
            if isinstance(ju, str) and domain in urlparse(ju).netloc:
                js_urls.add(ju)
        for ju in sorted(js_urls)[:15]:
            try:
                jr = await ctx.fetch_page(ju, timeout=12)
                if jr and (jr.get("status_code") == 200):
                    texts.append((jr.get("text", "")[:500000], ju,
                                  "JS bundle"))
            except Exception:
                continue
        for text, src_url, kind in texts:
            self._scan_text(text, src_url, kind, findings, seen, passive)
        return self._ok(findings, f"scanned {len(texts)} public assets")

    def _scan_text(self, text, src_url, kind, findings, seen, passive):
        if MD5_USAGE_RE.search(text):
            fp = fingerprint("md5usage:" + src_url)
            if ("sec_weak_hash_md5", fp) not in seen:
                seen.add(("sec_weak_hash_md5", fp))
                self._emit(
                    findings, "web", "sec_weak_hash_md5", "medium",
                    "MEDIUM: MD5 used for password/token hashing in "
                    f"{kind} (fingerprint {fp[:16]}). " +
                    WEAK_CRYPTO_NUANCE,
                    "Weak hashing observed", src_url,
                    "MD5 usage", "***", fp,
                    "Migrate password storage to bcrypt or Argon2 "
                    "with a per-password salt, force password "
                    "resets for affected accounts, and stop using "
                    "MD5 for tokens.", 75, passive,
                    {"asset_kind": kind, "algorithm": "MD5"})
        if SHA1_USAGE_RE.search(text):
            fp = fingerprint("sha1usage:" + src_url)
            if ("sec_weak_hash_sha1", fp) not in seen:
                seen.add(("sec_weak_hash_sha1", fp))
                self._emit(
                    findings, "web", "sec_weak_hash_sha1", "medium",
                    "MEDIUM: SHA-1 used for password/token hashing in "
                    f"{kind} (fingerprint {fp[:16]}). " +
                    WEAK_CRYPTO_NUANCE,
                    "Weak hashing observed", src_url,
                    "SHA-1 usage", "***", fp,
                    "Migrate password storage to bcrypt or Argon2 "
                    "with a per-password salt, force password "
                    "resets for affected accounts, and stop using "
                    "SHA-1 for tokens.", 75, passive,
                    {"asset_kind": kind, "algorithm": "SHA-1"})
        for m in HEX_CTX_RE.finditer(text):
            digest = m.group(1)
            algo = "MD5" if len(digest) == 32 else "SHA-1"
            key = ("sec_weak_hash_md5" if algo == "MD5"
                   else "sec_weak_hash_sha1")
            fp = fingerprint(digest)
            if (key, fp) in seen:
                continue
            seen.add((key, fp))
            self._emit(
                findings, "web", key, "medium",
                f"MEDIUM: {algo} password/token digest "
                f"{mask_secret(digest)} exposed in {kind} "
                f"(fingerprint {fp[:16]}). " + WEAK_CRYPTO_NUANCE,
                "Weak hash digest observed", src_url,
                f"{algo} digest", mask_secret(digest), fp,
                f"Migrate password storage to bcrypt or Argon2 "
                f"with a per-password salt and force password "
                f"resets for affected accounts. {algo} digests "
                f"are fast to crack.", 75, passive,
                {"asset_kind": kind, "algorithm": algo})
