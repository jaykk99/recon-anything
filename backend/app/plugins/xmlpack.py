"""XML reader pack (xml_*): turn a target's XML files into findings.

Jay's order (2026-10-23): "Add xml file reader makes them into more
findings." Until this pack, the scanner fetched XML files in a few
places but never READ them as a class:

Already existed (checked, not rebuilt):
- robots.py parses /sitemap.xml (URL count + generic keyword hits from
  that one file only) and flags robots-declared sitemaps; it never
  opens robots-declared sitemap CONTENTS or sitemap-index children.
- crawler.py follows sitemap indexes to CRAWL the listed URLs; it
  never mines the XML bodies for secrets, hosts or policies.
- artifacts.py / hiddenpaths.py / dir_brute.py note that
  /crossdomain.xml and /clientaccesspolicy.xml EXIST; nobody parses
  the policies they carry.
- gitleaks_scan / secrets / js_secrets / privfind scan homepage + JS
  (+ .env on crypto runs) via collect_texts; XML documents are never
  in that pool, so config XML, feeds and WSDLs went unread.
- Nothing anywhere looked for external entity / DTD declarations
  (XXE surface), WSDL service addresses, or config-XML connection
  strings.

This pack (5 detectors, one shared discovery pass per run):
- xml_secrets        - secrets/credentials/PII inside any discovered
                       XML doc: gitleaks RULES (same engine as the JS
                       scanners) + credential elements/attributes +
                       connection strings, all masked + fingerprinted.
- xml_sitemap_paths  - sitemap contents from EVERY source (path
                       probes, robots.txt Sitemap: lines, index
                       children one level deep): sensitive-path URLs
                       become findings and all listed URLs feed the
                       hunter bus ("endpoints").
- xml_xxe_surface    - external entity / external DTD / parameter
                       entity / XInclude declarations in served XML.
                       Detection only: the declared URI is reported,
                       never fetched.
- xml_policy         - crossdomain.xml / clientaccesspolicy.xml
                       content: wildcard grants and permissive
                       site-control (existence was already known;
                       the policy itself was never read).
- xml_wsdl           - WSDL documents: service addresses (internal
                       ones flagged), operations, schema imports.

SAFETY OF THE READER ITSELF: our parser can never be XXE'd by a
target. DOCTYPE declarations are located and stripped before the
stdlib parser ever sees the document (ElementTree does not fetch
external entities, and with no DTD left there is nothing to expand -
no billion-laughs either). Input is size-capped, malformed XML falls
back to regex mining, and a broken document degrades to silence,
never a crash. Secrets follow the pack rule: MASKED + SHA-256
fingerprint; the full value never reaches a Finding.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import collect_texts
from .gitleaks_scan import RULES as _GIT_RULES
from .privfind import v_iban, v_ssn
from .secretutils import is_placeholder, redact

XML_IDS: List[str] = [
    "xml_secrets",
    "xml_sitemap_paths",
    "xml_xxe_surface",
    "xml_policy",
    "xml_wsdl",
]

_REMEDIATION = (
    "Remove the exposure from the public surface, treat any secret or "
    "internal detail it revealed as compromised (rotate/revoke), and "
    "audit access logs. Detection only: nothing found was used.")

_MAX_DOC_BYTES = 1_000_000
_MAX_DOCS = 30

# XML resources probed on every run, highest-signal first (fetch_page
# cache shares the cost with robots/crawler/artifacts, which probe
# overlapping paths).
_FIXED_PATHS = (
    "/web.config", "/config.xml", "/appconfig.xml", "/settings.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml",
    "/browserconfig.xml",
    "/feed", "/feed.xml", "/rss.xml", "/atom.xml",
)
_WSDL_PATHS = (
    "/service.wsdl", "/services.wsdl", "/wsdl", "/?wsdl",
    "/soap?wsdl", "/ws?wsdl",
)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(
        (value or "").encode("utf-8", "ignore")).hexdigest()


def _host_of(target: Target) -> Optional[str]:
    if target.type == "url":
        return urlparse(target.normalized).hostname
    return domain_from_target(target.type, target.normalized)


async def _origin(ctx: Ctx, target: Target) -> Optional[str]:
    if target.type == "url":
        p = urlparse(target.normalized)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
        return target.normalized.rstrip("/")
    domain = domain_from_target(target.type, target.normalized)
    if not domain:
        return None
    return (await web_base(ctx, target, domain)).rstrip("/")


def _looks_xml(text: str, url: str) -> bool:
    """A 200 on an XML-intended path is often an SPA fallback page.
    Accept only bodies that plausibly are XML."""
    head = (text or "")[:2000].lstrip("﻿ \t\r\n")
    if not head.startswith("<"):
        return False
    if "<html" in head[:600].lower():
        return False
    return True


def _kind_for(url: str, text: str) -> str:
    low = url.lower()
    path = urlparse(url).path.lower()
    head = (text or "")[:1500].lower()
    if path.endswith(("crossdomain.xml", "clientaccesspolicy.xml")):
        return "policy"
    if "wsdl" in low or "<definitions" in head or ":definitions" in head:
        return "wsdl"
    if "sitemap" in path or "<urlset" in head or "<sitemapindex" in head:
        return "sitemap"
    if "<rss" in head or "<feed" in head:
        return "feed"
    return "xml"


# ---------------------------------------------------------------------------
# Hardened parsing: strip DOCTYPE (with its internal subset) before the
# stdlib parser runs. ElementTree never resolves external entities, and
# with the DTD gone there are no entity definitions left to expand.
# ---------------------------------------------------------------------------

def _strip_doctype(text: str) -> str:
    i = text.find("<!DOCTYPE")
    if i < 0:
        i = text.find("<!doctype")
    if i < 0:
        return text
    depth = 0
    quote = ""
    j = i
    while j < len(text):
        ch = text[j]
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        elif ch == ">" and depth == 0:
            return text[:i] + text[j + 1:]
        j += 1
    return text[:i]  # unterminated doctype: drop the tail, stay safe


_ENTITY_REF_RE = re.compile(r"&(?!amp;|lt;|gt;|quot;|apos;|#)"
                            r"([\w.:-]+);")


def _parse(text: str):
    """ElementTree root or None. Never raises, never resolves entities.

    After the DTD is stripped, references to entities it defined
    would be undefined and fail the parse - neutralize them to inert
    bracketed text so the document structure stays readable."""
    if not text or len(text) > _MAX_DOC_BYTES * 2:
        return None
    body = _strip_doctype(text[:_MAX_DOC_BYTES])
    body = _ENTITY_REF_RE.sub(r"[entity:\1]", body)
    try:
        return ElementTree.fromstring(body)
    except Exception:
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


# ---------------------------------------------------------------------------
# Discovery: one pass per run, cached on the shared bus. Every fetch
# rides Ctx.fetch_page (the run-wide page cache) - no parallel crawler.
# ---------------------------------------------------------------------------

_SITEMAP_LINE_RE = re.compile(r"(?im)^\s*sitemap:\s*(\S+)\s*$")
_XML_LINK_RE = re.compile(
    r"""(?:href|src)\s*=\s*["']([^"']+\.xml(?:\?[^"']*)?)["']"""
    r"""|["'(](https?://[^"'\s<>\)]+\.xml(?:\?[^"'\s<>\)]*)?)"""
    r"""|["'](/[\w./-]+\.xml(?:\?[^"']*)?)["']""",
    re.IGNORECASE)
_LOC_RE = re.compile(r"<loc>\s*([^<]+?)\s*</loc>", re.IGNORECASE)


async def _fetch_doc(ctx: Ctx, url: str) -> Optional[Dict[str, Any]]:
    try:
        page = await ctx.fetch_page(url, timeout=12)
    except Exception:
        return None
    if not page:
        return None
    try:
        if (page.get("status_code") or 0) != 200:
            return None
        text = page.get("text") or ""
        final = page.get("url") or url
    except Exception:
        return None
    if not text or not _looks_xml(text, final):
        return None
    return {"url": final, "text": text[:_MAX_DOC_BYTES],
            "kind": _kind_for(final, text)}


async def discover_docs(ctx: Ctx, target: Target) -> List[Dict[str, Any]]:
    cached = ctx.shared.get("_xml_docs_v1")
    if isinstance(cached, list):
        return cached
    docs: List[Dict[str, Any]] = []
    seen = set()

    def add(doc: Optional[Dict[str, Any]]) -> None:
        if doc and doc["url"] not in seen and len(docs) < _MAX_DOCS:
            seen.add(doc["url"])
            docs.append(doc)

    origin = await _origin(ctx, target)
    if origin:
        # robots.txt: its Sitemap: lines point at sitemaps robots.py
        # reports but never opens.
        robots_doc = None
        try:
            page = await ctx.fetch_page(origin + "/robots.txt", timeout=10)
            if page and (page.get("status_code") or 0) == 200:
                robots_doc = page.get("text") or ""
        except Exception:
            robots_doc = None
        sitemap_seeds: List[str] = []
        if robots_doc:
            for m in _SITEMAP_LINE_RE.finditer(robots_doc):
                u = urljoin(origin + "/", m.group(1))
                if u not in sitemap_seeds:
                    sitemap_seeds.append(u)

        for path in _FIXED_PATHS + _WSDL_PATHS:
            add(await _fetch_doc(ctx, urljoin(origin + "/", path.lstrip("/"))
                                 if "?" not in path
                                 else origin + path))
        for seed in sitemap_seeds[:4]:
            add(await _fetch_doc(ctx, seed))

        # Sitemap indexes: follow ONE level into child sitemaps.
        children: List[str] = []
        for doc in list(docs):
            if doc["kind"] != "sitemap":
                continue
            if "<sitemapindex" not in doc["text"][:2000].lower():
                continue
            for loc in _LOC_RE.findall(doc["text"]):
                u = urljoin(doc["url"], loc.strip())
                if u not in seen and u not in children:
                    children.append(u)
        for child in children[:4]:
            add(await _fetch_doc(ctx, child))

        # .xml URLs the run's own page/JS collection already surfaces.
        try:
            texts = await collect_texts(ctx, target)
        except Exception:
            texts = []
        origin_host = urlparse(origin).hostname or ""
        links: List[str] = []
        for _where, text, url in texts:
            for m in _XML_LINK_RE.finditer(text or ""):
                raw = (m.group(1) or m.group(2) or m.group(3)
                       or "").strip()
                if not raw:
                    continue
                full = urljoin(url, raw)
                host = urlparse(full).hostname or ""
                if host != origin_host and not host.endswith(
                        "." + origin_host):
                    continue
                if full not in seen and full not in links:
                    links.append(full)
                if len(links) >= 6:
                    break
            if len(links) >= 6:
                break
        for link in links:
            add(await _fetch_doc(ctx, link))

    ctx.shared["_xml_docs_v1"] = docs
    return docs


# ---------------------------------------------------------------------------
# Shared extraction helpers
# ---------------------------------------------------------------------------

_PRIV_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|127\.0\.0\.1)\b")
_PRIV_IP_FULL = re.compile(
    r"^(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    r"|^172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$"
    r"|^192\.168\.\d{1,3}\.\d{1,3}$"
    r"|^169\.254\.\d{1,3}\.\d{1,3}$")
_INTERNAL_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:local|internal|intranet|corp|lan)\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# spaced or compact; the mod-97 validator is the real gate
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9 ]{11,34}\b")


def _valid_ip(s: str) -> bool:
    try:
        return all(0 <= int(p) <= 255 for p in s.split("."))
    except Exception:
        return False


def _is_private_host(host: str) -> bool:
    h = (host or "").lower()
    if h == "localhost" or h.endswith(
            (".local", ".internal", ".intranet", ".corp", ".lan")):
        return True
    return bool(_PRIV_IP_FULL.match(h))


class _XmlPlugin(Plugin):
    """Base for the pack: web group, domain/url, passive, and a run()
    wrapper that can never raise out (degrade to ok(0) with a note)."""
    id = ""
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 90

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            res = await self.check(target, ctx)
        except Exception as e:  # noqa: BLE001 - degrade, never throw
            res = self._ok([], f"{self.id}: check could not complete "
                               f"({type(e).__name__})")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        raise NotImplementedError

    def xml_finding(self, category: str, key: str, value: str,
                    source_url: Optional[str], severity: str,
                    remediation: str = _REMEDIATION,
                    confidence: int = 85, **evidence) -> Finding:
        ev = {"severity": severity, "detector": self.id,
              "remediation": remediation}
        ev.update(evidence)
        return self._f(category, key, value,
                       source="xml reader pack",
                       source_url=source_url, confidence=confidence,
                       passive=True, evidence=ev)


# ---------------------------------------------------------------------------
# xml_secrets: credentials, secrets and PII inside XML documents
# ---------------------------------------------------------------------------

_CRED_ELEMENTS = {
    "password", "passwd", "pwd", "secret", "clientsecret",
    "client_secret", "apikey", "api_key", "api-key", "apitoken",
    "api_token", "accesskey",
    "access_key", "access-key", "privatekey", "private_key",
    "authtoken", "auth_token", "token", "accesstoken", "access_token",
    "refresh_token", "refreshtoken", "signingkey", "signing_key",
    "encryptionkey", "encryption_key",
}
_TOKENISH = {"token", "authtoken", "auth_token", "accesstoken",
             "access_token", "refresh_token", "refreshtoken"}
_CONN_ELEMENTS = {"connectionstring", "connection_string",
                  "connectionstrings"}
_ATTR_CRED_RE = re.compile(
    r"""(?i)\b(password|passwd|pwd|secret|client[-_]?secret|"""
    r"""api[-_]?key|access[-_]?key|auth[-_]?token|access[-_]?token)"""
    r"""\s*=\s*["']([^"']{4,300})["']""")
_CONNSTR_RE = re.compile(
    r"(?i)(?:server|data\s*source|datasource|host|addr|address|"
    r"initial\s*catalog|database|uid|user\s*id|userid|user|username)"
    r"\s*=\s*[^;\"<]{1,160}(?:;[^\"<]{0,240}){0,8}")
_CONN_PWD_RE = re.compile(r"(?i)(?:password|pwd)\s*=\s*([^;\s\"<]{1,200})")
_ENV_REF_RE = re.compile(r"^(\$\{|%[^%]+%|\{\{?|vault:|env:)")


def _cred_value_ok(value: str, tokenish: bool = False) -> bool:
    v = (value or "").strip()
    if len(v) < 4 or (tokenish and len(v) < 8):
        return False
    if _ENV_REF_RE.match(v):
        return False  # env/vault reference: a pointer, not a secret
    if is_placeholder(v):
        return False
    if set(v) <= set("xX*.-_ "):
        return False
    return True


def _scan_connstr(text: str) -> List[Tuple[str, str]]:
    """(password_value, connstr_context) pairs from connection strings."""
    out = []
    for m in _CONNSTR_RE.finditer(text or ""):
        seg = m.group(0)
        pm = _CONN_PWD_RE.search(seg)
        if not pm:
            continue
        pwd = pm.group(1).strip()
        if _cred_value_ok(pwd):
            out.append((pwd, seg.strip()[:200]))
    return out


class XmlSecrets(_XmlPlugin):
    id = "xml_secrets"
    label = "XML Secrets & Config Miner"
    description = ("Read the target's XML files (config XML, feeds, "
                   "WSDLs, discovered .xml) for credentials, "
                   "connection strings, secrets and PII.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        docs = await discover_docs(ctx, target)
        if not docs:
            return self._ok([], "no XML documents discovered")
        target_host = (_host_of(target) or "").lower()
        findings: List[Finding] = []
        seen = set()

        def emit(f: Finding, dedupe_key: Tuple) -> None:
            if dedupe_key not in seen and len(findings) < 60:
                seen.add(dedupe_key)
                findings.append(f)

        for doc in docs:
            url, text, kind = doc["url"], doc["text"], doc["kind"]

            # 1) gitleaks rule engine over the raw XML (same rules
            #    the JS/page scanners use; XML was never in their pool)
            for name, pat, conf, sev in _GIT_RULES:
                try:
                    rx = re.compile(pat)
                except Exception:
                    continue
                for m in rx.finditer(text):
                    val = m.group(0)
                    if is_placeholder(val):
                        continue
                    fp = _fingerprint(val)
                    emit(self.xml_finding(
                        "leak", "xml_secret",
                        f"{sev.upper()}: {name} {redact(val)} in XML "
                        f"document {url}",
                        url, "high" if sev in ("critical", "high")
                        else "medium",
                        confidence=conf, pattern=name,
                        fingerprint_sha256=fp, redacted=True),
                        ("rule", name, fp))

            # 2) connection strings (Server=...;Password=...)
            for pwd, seg in _scan_connstr(text):
                fp = _fingerprint(pwd)
                emit(self.xml_finding(
                    "leak", "xml_connection_string",
                    f"CRITICAL: connection string with password "
                    f"{redact(pwd)} exposed in XML document {url}",
                    url, "high", confidence=92, password_included=True,
                    fingerprint_sha256=fp, redacted=True),
                    ("connstr", fp))

            # 3) credential attributes: password="..." / api-key="..."
            for m in _ATTR_CRED_RE.finditer(text):
                val = m.group(2).strip()
                if not _cred_value_ok(val):
                    continue
                fp = _fingerprint(val)
                emit(self.xml_finding(
                    "leak", "xml_credential_attribute",
                    f"HIGH: credential in XML attribute "
                    f"{m.group(1)}=\"{redact(val)}\" in {url}",
                    url, "high", confidence=88,
                    attribute=m.group(1), fingerprint_sha256=fp,
                    redacted=True),
                    ("attr", m.group(1).lower(), fp))

            # 4) credential elements (tree walk when parseable)
            root = _parse(text)
            if root is not None:
                for el in root.iter():
                    name = _local(el.tag)
                    if name in _CONN_ELEMENTS:
                        for attr_val in list(el.attrib.values()) + \
                                [el.text or ""]:
                            for pwd, _seg in _scan_connstr(attr_val):
                                fp = _fingerprint(pwd)
                                emit(self.xml_finding(
                                    "leak", "xml_connection_string",
                                    f"CRITICAL: connection string "
                                    f"with password {redact(pwd)} in "
                                    f"<{name}> in {url}",
                                    url, "high", confidence=94,
                                    fingerprint_sha256=fp,
                                    redacted=True),
                                    ("connstr", fp))
                        continue
                    if name in _CRED_ELEMENTS:
                        val = (el.text or "").strip()
                        tokenish = name in _TOKENISH
                        if not _cred_value_ok(val, tokenish=tokenish):
                            continue
                        fp = _fingerprint(val)
                        emit(self.xml_finding(
                            "leak", "xml_credential_element",
                            f"HIGH: credential in XML element "
                            f"<{name}>: {redact(val)} in {url}",
                            url, "high", confidence=90, element=name,
                            fingerprint_sha256=fp, redacted=True),
                            ("elem", name, fp))

            # 5) PII: checksum/format-validated, like the pf pack
            for m in _SSN_RE.finditer(text):
                if v_ssn(m.group(0)):
                    masked = "***-**-" + m.group(0)[-2:]
                    emit(self.xml_finding(
                        "identity", "xml_pii_ssn",
                        f"HIGH: US SSN {masked} inside XML document "
                        f"{url}", url, "high", confidence=90,
                        fingerprint_sha256=_fingerprint(m.group(0)),
                        redacted=True),
                        ("ssn", _fingerprint(m.group(0))))
            for m in _IBAN_RE.finditer(text):
                if v_iban(m.group(0)):
                    emit(self.xml_finding(
                        "identity", "xml_pii_iban",
                        f"HIGH: IBAN ...{m.group(0)[-4:]} inside XML "
                        f"document {url}", url, "high", confidence=88,
                        fingerprint_sha256=_fingerprint(m.group(0)),
                        redacted=True),
                        ("iban", _fingerprint(m.group(0))))

            if kind == "feed":
                continue  # feed bodies are content: endpoints/hosts
                # below are config signal, not blog-roll noise

            # 6) internal references (private IPs, internal hostnames)
            for m in _PRIV_IP_RE.finditer(text):
                ip = m.group(0)
                if not _valid_ip(ip):
                    continue
                if ip == target_host or ip in ("127.0.0.1",) and \
                        target_host in ("localhost", "127.0.0.1"):
                    continue
                emit(self.xml_finding(
                    "infra", "xml_internal_reference",
                    f"Internal IP {ip} referenced in XML document "
                    f"{url}", url, "medium", confidence=85, host=ip),
                    ("ip", ip, url))
            for m in _INTERNAL_HOST_RE.finditer(text):
                host = m.group(0).lower()
                if host == target_host:
                    continue
                emit(self.xml_finding(
                    "infra", "xml_internal_reference",
                    f"Internal hostname {host} referenced in XML "
                    f"document {url}", url, "medium", confidence=82,
                    host=host),
                    ("host", host, url))
            for m in re.finditer(r"\blocalhost\b", text, re.IGNORECASE):
                if target_host not in ("localhost", "127.0.0.1"):
                    emit(self.xml_finding(
                        "infra", "xml_internal_reference",
                        f"localhost referenced in XML document {url}",
                        url, "low", confidence=70, host="localhost"),
                        ("host", "localhost", url))
                break

            # 7) external service endpoints named in config-style XML
            endpoints = set()
            for m in _URL_RE.finditer(text):
                u = m.group(0).rstrip(".,;")
                host = (urlparse(u).hostname or "").lower()
                if not host or host == target_host:
                    continue
                if _is_private_host(host):
                    continue  # already an internal-reference finding
                endpoints.add(u)
            for u in sorted(endpoints)[:8]:
                host = urlparse(u).hostname or ""
                emit(self.xml_finding(
                    "infra", "xml_service_endpoint",
                    f"External service endpoint referenced in XML: "
                    f"{u[:160]}", url, "low", confidence=65, host=host),
                    ("endpoint", u))

        return self._ok(findings,
                        f"mined {len(docs)} XML document(s)")


# ---------------------------------------------------------------------------
# xml_sitemap_paths: sitemap contents from every source
# ---------------------------------------------------------------------------

_SENSITIVE_HIGH = (
    ".git", ".env", ".sql", ".bak", ".pem", ".key", "wp-config",
    "id_rsa", ".aws", "/backup", "/config", "/internal", "/private",
    "/debug", "/actuator", "/phpmyadmin", "/.well-known/security",
    "/admin", "/console", "/upload",
)
_SENSITIVE_MED = (
    "/login", "/export", "/staging", "/dev/", "/test/", "/beta",
    "/manage", "/settings", "/account", "/download",
)
_ARCHIVE_EXTS = (".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar",
                 ".dump", ".db")


def _sitemap_severity(u: str) -> Optional[str]:
    low = u.lower()
    path = urlparse(low).path
    if any(k in low for k in _SENSITIVE_HIGH) or \
            path.endswith(_ARCHIVE_EXTS):
        return "high"
    if any(k in path for k in _SENSITIVE_MED):
        return "medium"
    return None


class XmlSitemapPaths(_XmlPlugin):
    id = "xml_sitemap_paths"
    label = "XML Sitemap Path Miner"
    description = ("Parse sitemap contents from every source (probes, "
                   "robots.txt declarations, index children): "
                   "sensitive-path URLs become findings and all URLs "
                   "feed the hunter bus.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        docs = [d for d in await discover_docs(ctx, target)
                if d["kind"] == "sitemap"]
        if not docs:
            return self._ok([], "no sitemap documents discovered")
        target_host = (_host_of(target) or "").lower()
        findings: List[Finding] = []
        seen_f = set()
        published = 0
        total = 0
        for doc in docs:
            root = _parse(doc["text"])
            locs: List[str] = []
            if root is not None:
                for el in root.iter():
                    if _local(el.tag) == "loc" and el.text:
                        locs.append(el.text.strip())
            if not locs:
                locs = [m.strip() for m in _LOC_RE.findall(doc["text"])]
            for u in locs:
                if not u:
                    continue
                total += 1
                if published < 300:
                    ctx.publish("endpoints", u)
                    published += 1
                host = (urlparse(u).hostname or "").lower()
                if host and host != target_host and \
                        _is_private_host(host):
                    key = ("sm-internal", u)
                    if key not in seen_f and len(findings) < 40:
                        seen_f.add(key)
                        findings.append(self.xml_finding(
                            "infra", "xml_sitemap_internal_url",
                            f"Sitemap lists an internal URL: {u[:160]}",
                            doc["url"], "high", confidence=85,
                            host=host, listed_in=doc["url"]))
                    continue
                sev = _sitemap_severity(u)
                if sev:
                    key = ("sm-sens", u)
                    if key not in seen_f and len(findings) < 40:
                        seen_f.add(key)
                        findings.append(self.xml_finding(
                            "web", "xml_sitemap_sensitive_url",
                            f"Sensitive URL listed in sitemap: "
                            f"{u[:160]}", doc["url"], sev,
                            confidence=80, listed_in=doc["url"]))
        return self._ok(
            findings,
            f"{total} URL(s) across {len(docs)} sitemap(s), "
            f"{published} fed to hunters")


# ---------------------------------------------------------------------------
# xml_xxe_surface: external entity / DTD declarations in served XML
# ---------------------------------------------------------------------------

_DOCTYPE_RE = re.compile(r"<!DOCTYPE[^[>]*(?:\[[\s\S]*?\])?\s*>",
                         re.IGNORECASE)
_ENTITY_EXT_RE = re.compile(
    r"""<!ENTITY\s+(%\s+)?([\w.:-]+)\s+(?:SYSTEM|PUBLIC)\s+"""
    r"""(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)
_DTD_EXT_RE = re.compile(
    r"""<!DOCTYPE\s+[\w.:-]+\s+(?:SYSTEM|PUBLIC)\s+"""
    r"""(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)
_ENTITY_ANY_RE = re.compile(r"<!ENTITY\s+(%\s+)?([\w.:-]+)\s+"
                            r"""(?:"([^"]*)"|'([^']*)')""",
                            re.IGNORECASE)
_XINCLUDE_RE = re.compile(
    r"""<xi:include[^>]*href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


class XmlXxeSurface(_XmlPlugin):
    id = "xml_xxe_surface"
    label = "XML External Entity Surface"
    description = ("Detect external entity, external DTD, parameter "
                   "entity and XInclude declarations in the target's "
                   "served XML (XXE surface). The declared URIs are "
                   "reported, never fetched.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        docs = await discover_docs(ctx, target)
        if not docs:
            return self._ok([], "no XML documents discovered")
        findings: List[Finding] = []
        seen = set()
        xxe_remed = (
            "Disable DTD processing / external entities in every XML "
            "parser that consumes this document format (XXE). A served "
            "document declaring external entities proves the format "
            "expects DTD support - any consumer parsing it unsafely "
            "can be made to read local files or reach internal "
            "services. Detection only: the declared URI was never "
            "fetched.")
        for doc in docs:
            url, text = doc["url"], doc["text"]
            head = text[:60000]
            for m in _ENTITY_EXT_RE.finditer(head):
                is_param = bool(m.group(1))
                name = m.group(2)
                uri = m.group(3) or m.group(4) or ""
                key = ("ent", name, uri, url)
                if key in seen or len(findings) >= 30:
                    continue
                seen.add(key)
                kind = "parameter entity" if is_param else "entity"
                findings.append(self.xml_finding(
                    "web", "xml_external_entity",
                    f"External {kind} '{name}' declared in XML "
                    f"(SYSTEM {uri[:120]}): {url}",
                    url, "high", remediation=xxe_remed,
                    confidence=90, entity=name, system_id=uri,
                    parameter_entity=is_param))
            for m in _DTD_EXT_RE.finditer(head):
                uri = m.group(1) or m.group(2) or ""
                key = ("dtd", uri, url)
                if key in seen or len(findings) >= 30:
                    continue
                seen.add(key)
                findings.append(self.xml_finding(
                    "web", "xml_external_dtd",
                    f"XML document pulls an external DTD "
                    f"({uri[:120]}): {url}",
                    url, "medium", remediation=xxe_remed,
                    confidence=85, system_id=uri))
            # entity-expansion shape: entity values referencing other
            # entities (billion-laughs fuel) - declaration count only
            nested = 0
            total_entities = 0
            for m in _ENTITY_ANY_RE.finditer(head):
                total_entities += 1
                val = m.group(3) or m.group(4) or ""
                if "&" in val:
                    nested += 1
            if nested >= 2:
                key = ("laughs", url)
                if key not in seen and len(findings) < 30:
                    seen.add(key)
                    findings.append(self.xml_finding(
                        "web", "xml_entity_expansion",
                        f"XML declares {total_entities} entities, "
                        f"{nested} referencing other entities "
                        f"(entity-expansion / billion-laughs shape): "
                        f"{url}", url, "medium", remediation=xxe_remed,
                        confidence=75, entities=total_entities,
                        nested=nested))
            for m in _XINCLUDE_RE.finditer(head):
                href = m.group(1)
                key = ("xi", href, url)
                if key in seen or len(findings) >= 30:
                    continue
                seen.add(key)
                sev = "high" if href.lower().startswith(
                    ("file:", "/", "http://localhost")) else "medium"
                findings.append(self.xml_finding(
                    "web", "xml_xinclude",
                    f"XInclude directive pulls {href[:120]}: {url}",
                    url, sev, remediation=xxe_remed, confidence=85,
                    href=href))
        return self._ok(findings, f"scanned {len(docs)} XML "
                                  f"document(s) for DTD surface")


# ---------------------------------------------------------------------------
# xml_policy: cross-domain policy contents
# ---------------------------------------------------------------------------

_ALLOW_FROM_RE = re.compile(
    r"""allow-access-from[^>]*?domain\s*=\s*["']([^"']+)["']"""
    r"""([^>]*)""", re.IGNORECASE)
_SITE_CONTROL_RE = re.compile(
    r"""site-control[^>]*?permitted-cross-domain-policies\s*=\s*"""
    r"""["']([^"']+)["']""", re.IGNORECASE)
_HEADERS_FROM_RE = re.compile(
    r"""allow-http-request-headers-from[^>]*?domain\s*=\s*"""
    r"""["']([^"']+)["'][^>]*?headers\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE)
_CAP_DOMAIN_RE = re.compile(
    r"""<domain\s+uri\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


class XmlPolicy(_XmlPlugin):
    id = "xml_policy"
    label = "XML Cross-Domain Policy Reader"
    description = ("Parse crossdomain.xml / clientaccesspolicy.xml "
                   "contents: wildcard cross-domain grants let any "
                   "site read this origin's data with a victim's "
                   "session (existence probes existed; the policy "
                   "itself was never read).")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        docs = [d for d in await discover_docs(ctx, target)
                if d["kind"] == "policy"]
        if not docs:
            return self._ok([], "no cross-domain policy files found")
        findings: List[Finding] = []
        seen = set()
        remed = (
            "Restrict crossdomain.xml / clientaccesspolicy.xml to "
            "the exact domains that need cross-domain access. A "
            "wildcard grant lets any website make credentialed "
            "requests to this origin from a visitor's browser.")
        for doc in docs:
            url, text = doc["url"], doc["text"]
            is_cap = "clientaccesspolicy" in url.lower()
            for m in _ALLOW_FROM_RE.finditer(text):
                domain = m.group(1)
                rest = m.group(2) or ""
                insecure = 'secure="false"' in rest.lower()
                if domain == "*":
                    key = ("wild", url)
                    if key not in seen:
                        seen.add(key)
                        findings.append(self.xml_finding(
                            "web", "xml_crossdomain_wildcard",
                            f"crossdomain.xml grants EVERY domain "
                            f"cross-domain access"
                            f"{' over insecure channels' if insecure else ''}"
                            f": {url}", url, "high", remediation=remed,
                            confidence=95, domain=domain,
                            secure_false=insecure))
                elif domain.startswith("*."):
                    key = ("wildsub", domain, url)
                    if key not in seen:
                        seen.add(key)
                        findings.append(self.xml_finding(
                            "web", "xml_crossdomain_wildcard",
                            f"crossdomain.xml grants all subdomains "
                            f"of {domain[2:]} cross-domain access: "
                            f"{url}", url, "medium", remediation=remed,
                            confidence=85, domain=domain,
                            secure_false=insecure))
            for m in _HEADERS_FROM_RE.finditer(text):
                if m.group(1) == "*" and m.group(2) == "*":
                    key = ("hdrwild", url)
                    if key not in seen:
                        seen.add(key)
                        findings.append(self.xml_finding(
                            "web", "xml_crossdomain_wildcard",
                            f"crossdomain.xml lets every domain send "
                            f"arbitrary request headers cross-domain: "
                            f"{url}", url, "medium", remediation=remed,
                            confidence=85, domain="*", headers="*"))
            for m in _SITE_CONTROL_RE.finditer(text):
                if m.group(1).lower() == "all":
                    key = ("sc-all", url)
                    if key not in seen:
                        seen.add(key)
                        findings.append(self.xml_finding(
                            "web", "xml_policy_site_control_all",
                            f"crossdomain.xml site-control permits "
                            f"ALL cross-domain policy files "
                            f"(permitted-cross-domain-policies="
                            f"\"all\"): {url}", url, "medium",
                            remediation=remed, confidence=85))
            if is_cap:
                for m in _CAP_DOMAIN_RE.finditer(text):
                    uri = m.group(1)
                    if uri in ("*", "http://*", "https://*"):
                        key = ("capwild", url)
                        if key not in seen:
                            seen.add(key)
                            findings.append(self.xml_finding(
                                "web", "xml_clientaccess_wildcard",
                                f"clientaccesspolicy.xml grants "
                                f"every origin access (domain "
                                f"uri=\"{uri}\"): {url}", url, "high",
                                remediation=remed, confidence=92,
                                domain=uri))
        return self._ok(findings, f"read {len(docs)} policy "
                                  f"file(s)")


# ---------------------------------------------------------------------------
# xml_wsdl: WSDL service surface
# ---------------------------------------------------------------------------

_LOCATION_RE = re.compile(r"""\blocation\s*=\s*["']([^"']+)["']""",
                          re.IGNORECASE)
_OPERATION_RE = re.compile(
    r"""<[\w.-]*:?operation[^>]*\bname\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE)
_TARGET_NS_RE = re.compile(
    r"""targetNamespace\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_IMPORT_RE = re.compile(
    r"""<(?:[\w.-]+:)?(?:import|include)\b[^>]*?"""
    r"""(?:schemaLocation|location)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE)


class XmlWsdl(_XmlPlugin):
    id = "xml_wsdl"
    label = "XML WSDL Service Reader"
    description = ("Read WSDL documents: published service addresses "
                   "(internal ones flagged), operation names and "
                   "imported schemas map the SOAP attack surface.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        docs = [d for d in await discover_docs(ctx, target)
                if d["kind"] == "wsdl"]
        if not docs:
            return self._ok([], "no WSDL documents discovered")
        target_host = (_host_of(target) or "").lower()
        findings: List[Finding] = []
        seen = set()
        for doc in docs:
            url, text = doc["url"], doc["text"]
            ops = []
            for m in _OPERATION_RE.finditer(text):
                if m.group(1) not in ops:
                    ops.append(m.group(1))
            ns = _TARGET_NS_RE.search(text)
            key = ("svc", url)
            if key not in seen:
                seen.add(key)
                findings.append(self.xml_finding(
                    "api", "xml_wsdl_service",
                    f"WSDL published: {len(ops)} operation(s)"
                    f"{' (' + ', '.join(ops[:8]) + ')' if ops else ''}"
                    f" at {url}", url, "low", confidence=80,
                    operations=ops[:20], operation_count=len(ops),
                    target_namespace=ns.group(1) if ns else ""))
            for m in _IMPORT_RE.finditer(text):
                loc = m.group(1)
                key = ("imp", loc, url)
                if key in seen or len(findings) >= 40:
                    continue
                seen.add(key)
                findings.append(self.xml_finding(
                    "api", "xml_wsdl_import",
                    f"WSDL imports external schema {loc[:140]}: "
                    f"{url}", url, "low", confidence=70, location=loc))
            for m in _LOCATION_RE.finditer(text):
                loc = m.group(1)
                if loc.lower().endswith((".xsd", ".wsdl")) or \
                        loc in (ns.group(1) if ns else ""):
                    continue  # schema imports handled above
                host = (urlparse(loc).hostname or "").lower()
                key = ("loc", loc, url)
                if key in seen or len(findings) >= 40:
                    continue
                seen.add(key)
                if host and _is_private_host(host):
                    findings.append(self.xml_finding(
                        "api", "xml_wsdl_internal_endpoint",
                        f"WSDL service address points at an INTERNAL "
                        f"endpoint: {loc[:160]} (from {url})",
                        url, "high", confidence=90, location=loc,
                        host=host))
                elif host and host != target_host:
                    findings.append(self.xml_finding(
                        "api", "xml_wsdl_endpoint",
                        f"WSDL service address: {loc[:160]} "
                        f"(from {url})", url, "low", confidence=70,
                        location=loc, host=host))
        return self._ok(findings, f"read {len(docs)} WSDL "
                                  f"document(s)")
