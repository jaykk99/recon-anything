"""Shared engine for the exchange-web detector family (exch_*).

One hundred detection-only plugins for exchange-type websites and
web apps (crypto exchanges are the archetype class), built in ten
blocks of ten in exchange_web1.py .. exchange_web10.py. Every
detector is a passive code/config/response-pattern analysis:

- text detectors scan the target's own public homepage HTML and
  same-domain JS bundles for a vulnerable code/config pattern;
- header detectors grade the homepage response headers.

No detector sends a payload, attempts a login, bypasses anything,
or accesses private data. It reads what the site itself serves to
any visitor and reports the pattern.

EVIDENCE RULE (same as secretpack): a finding never carries a full
secret, key, seed or token. Snippets are masked (long tokens are
replaced by first4...last4) and carry a SHA-256 fingerprint of the
matched material so the owner can confirm rotation.

The pure analyze() entry point is what the fixture tests exercise:
analyze(text, spec, headers) returns hit dicts
{kind, severity, code, detail, pattern} - a hit only when the
vulnerable pattern is present and no guard pattern appears in the
window around the match.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

FLAGS = re.I | re.S

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_~\-]{12,}")


def mask_token(tok: str) -> str:
    if len(tok) <= 8:
        return "***"
    return tok[:4] + "..." + tok[-4:]


def fingerprint(s: str) -> str:
    return hashlib.sha256((s or "").encode()).hexdigest()


def masked_snippet(text: str, start: int, end: int,
                   radius: int = 90) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snip = text[lo:hi].replace("\n", " ").strip()
    return _TOKEN_RE.sub(lambda m: mask_token(m.group(0)), snip)[:300]


@dataclass
class ExchSpec:
    id: str
    label: str
    severity: str = "medium"
    detail: str = ""
    fix: str = ""
    patterns: Tuple[str, ...] = ()
    negatives: Tuple[str, ...] = ()
    kind: str = "text"  # text | header_missing | header_weak |
    #                     cookie_flag | cors_star_credentials |
    #                     header_below
    header: str = ""
    flag: str = ""
    threshold: int = 0
    alt_header: str = ""       # header that satisfies a missing check
    alt_pattern: str = ""      # pattern in alt_header that satisfies it
    category: str = "web"

    @property
    def class_name(self) -> str:
        return "".join(p.capitalize() for p in self.id.split("_")) + "Plugin"


def S(id: str, label: str, severity: str, detail: str, fix: str,
      patterns=(), negatives=(), kind: str = "text", header: str = "",
      flag: str = "", threshold: int = 0, alt_header: str = "",
      alt_pattern: str = "", category: str = "web") -> ExchSpec:
    return ExchSpec(id=id, label=label, severity=severity, detail=detail,
                    fix=fix, patterns=tuple(patterns),
                    negatives=tuple(negatives), kind=kind, header=header,
                    flag=flag, threshold=threshold, alt_header=alt_header,
                    alt_pattern=alt_pattern, category=category)


def _hit(spec: ExchSpec, code: str, pattern: str,
         raw_for_fp: str) -> Dict:
    return {"kind": spec.id, "severity": spec.severity, "code": code,
            "detail": spec.detail, "pattern": pattern,
            "fingerprint_sha256": fingerprint(raw_for_fp)}


def _norm_headers(headers: Optional[Dict]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        out[str(k).lower()] = str(v)
    return out


def analyze(text: str, spec: ExchSpec,
            headers: Optional[Dict] = None) -> List[Dict]:
    """Run ONE exch_* detector over text (+ optional headers).

    Text detectors: fire on the first pattern match whose window
    carries no negative (guard) pattern. Header detectors grade
    the supplied headers dict only.
    """
    text = text or ""
    hdrs = _norm_headers(headers)
    if spec.kind == "text":
        for pat in spec.patterns:
            for m in re.finditer(pat, text, FLAGS):
                lo = max(0, m.start() - 200)
                hi = min(len(text), m.end() + 200)
                window = text[lo:hi]
                if any(re.search(n, window, FLAGS)
                       for n in spec.negatives):
                    continue
                return [_hit(spec, masked_snippet(text, m.start(),
                                                  m.end()),
                             pat, m.group(0))]
        return []
    if spec.kind == "header_missing":
        if spec.header in hdrs:
            return []
        if spec.alt_header and spec.alt_pattern:
            alt = hdrs.get(spec.alt_header, "")
            if alt and re.search(spec.alt_pattern, alt, FLAGS):
                return []
        return [_hit(spec, f"(no {spec.header} header in response)",
                     f"missing header: {spec.header}", spec.header)]
    if spec.kind == "header_weak":
        value = hdrs.get(spec.header, "")
        if not value:
            return []
        for pat in spec.patterns:
            m = re.search(pat, value, FLAGS)
            if m:
                return [_hit(spec, masked_snippet(value, m.start(),
                                                  m.end()),
                             pat, m.group(0))]
        return []
    if spec.kind == "header_below":
        value = hdrs.get(spec.header, "")
        if not value:
            return []
        m = re.search(r"max-age\s*=\s*(\d+)", value, FLAGS)
        if not m:
            return []
        if int(m.group(1)) < spec.threshold:
            return [_hit(spec, masked_snippet(value, m.start(), m.end()),
                         f"max-age below {spec.threshold}", m.group(0))]
        return []
    if spec.kind == "cookie_flag":
        raw = hdrs.get("set-cookie", "")
        if not raw:
            return []
        cookies = [c.strip() for c in raw.split("\n") if c.strip()]
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip().lower()
            if not re.search(r"session|sid|token|auth|exchange|trade",
                             name):
                continue
            low = cookie.lower()
            if spec.flag == "samesite":
                if "samesite=" not in low:
                    return [_hit(spec, masked_snippet(cookie, 0,
                                                      len(cookie)),
                                 "session cookie without SameSite",
                                 cookie)]
                if "samesite=none" in low and "secure" not in low:
                    return [_hit(spec, masked_snippet(cookie, 0,
                                                      len(cookie)),
                                 "SameSite=None without Secure",
                                 cookie)]
                continue
            if spec.flag not in low:
                return [_hit(spec, masked_snippet(cookie, 0, len(cookie)),
                             f"session cookie without {spec.flag}",
                             cookie)]
        return []
    if spec.kind == "cors_star_credentials":
        acao = hdrs.get("access-control-allow-origin", "").strip()
        acac = hdrs.get("access-control-allow-credentials",
                        "").strip().lower()
        if acao == "*" and acac == "true":
            return [_hit(spec, "Access-Control-Allow-Origin: * with "
                               "Access-Control-Allow-Credentials: true",
                         "wildcard origin with credentials", acao + acac)]
        return []
    return []


_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)


def _same_domain(url: str, domain: str) -> bool:
    try:
        return domain.lower() in urlparse(url).netloc.lower()
    except Exception:
        return False


class ExchangeWebPlugin(Plugin):
    """Shared run plumbing for the exch_* family."""

    id = ""
    label = "Exchange Web Detector"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ""
    timeout_s = 45
    _spec: Optional[ExchSpec] = None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        spec = self._spec
        t0 = time.monotonic()
        if spec is None:
            return self._skipped("abstract base")
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable, nothing to "
                                  "analyze")
        headers = {str(k).lower(): str(v)
                   for k, v in dict(resp.headers).items()}
        html = resp.text or ""
        texts: List[Tuple[str, str]] = [(html, base + "/")]
        if spec.kind == "text":
            js_urls = set()
            for sm in _SCRIPT_SRC_RE.finditer(html):
                full = urljoin(base + "/", sm.group(1))
                if _same_domain(full, domain):
                    js_urls.add(full)
            for ju in ctx.consume("js_files"):
                if isinstance(ju, str) and _same_domain(ju, domain):
                    js_urls.add(ju)
            for ju in sorted(js_urls)[:12]:
                try:
                    jr = await ctx.fetch_page(ju, timeout=12)
                except Exception:
                    continue
                if jr and jr.get("status_code") == 200:
                    texts.append(((jr.get("text", "") or "")[:500000], ju))
        findings: List[Finding] = []
        seen = set()
        for text, src_url in texts:
            for hit in analyze(text, spec, headers):
                fp = hit["fingerprint_sha256"]
                if fp in seen:
                    continue
                seen.add(fp)
                findings.append(self._f(
                    spec.category, spec.id,
                    f"{spec.severity.upper()}: {spec.label}: "
                    f"{hit['detail']}\n\nCode:\n{hit['code']}",
                    source="exchange web detector (public assets)",
                    source_url=src_url, confidence=80, passive=True,
                    evidence={"severity": spec.severity,
                              "check": spec.id,
                              "pattern": hit["pattern"],
                              "fingerprint_sha256": fp,
                              "remediation": spec.fix}))
        res = self._ok(
            findings,
            f"{spec.id}: analyzed {len(texts)} public asset(s), "
            f"{len(findings)} finding(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


def build_plugin_class(spec: ExchSpec, module: str) -> type:
    return type(spec.class_name, (ExchangeWebPlugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (f"Exchange-web detector for "
                        f"{spec.label.lower()}: {spec.detail} "
                        f"Passive public-asset analysis, detection "
                        f"only."),
        "__module__": module,
    })


def register(specs: List[ExchSpec], module: str,
             namespace: Dict) -> Dict[str, ExchSpec]:
    by_id = {}
    for spec in specs:
        by_id[spec.id] = spec
        namespace[spec.class_name] = build_plugin_class(spec, module)
    return by_id
