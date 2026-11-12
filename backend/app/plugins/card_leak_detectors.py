"""Card leak + card-to-crypto on-ramp detectors (fingerprint-only).

Two detection-only plugins, same fingerprint-only pattern as the
exchange-key-leak pack (PR #172):

  exposed_card_number_leak - Luhn-valid payment card numbers (PANs)
    exposed in publicly fetched text: homepage, inline scripts,
    same-domain JS bundles, public config files, discovery-bus text
    assets, and verified contract source. Findings carry brand, BIN
    (first 6), last 4, and a SHA-256 fingerprint - NEVER the full PAN
    in `value`, `evidence`, or `raw`. Well-known test card numbers
    are ignored, as is any digit string that fails Luhn or has no
    valid brand BIN. Status is always UNVERIFIED: liveness is never
    probed (no charge, no balance check, no transaction of any kind).
  cc_to_crypto_onramp - card-to-crypto on-ramp surfaces on scanned
    websites/APIs: provider SDK/widget references (MoonPay, Simplex,
    Ramp Network, Transak, Banxa, Mercuryo, Alchemy Pay, Wert, Wyre)
    and card-funded crypto purchase flows. Surface finding only;
    no card data of any kind.

Detection only: read-only GETs of public pages / keyless explorer
routes. No transactions, no auth attempts, no card charging, no
cash-out, no mixer flow. A bare brand mention with no SDK, script,
or checkout-flow marker does not fire.
"""

from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cards import BRANDS, CARD_CTX, PAN_RE, luhn_ok
from .secretpack import SCOPE_NOTE, fingerprint, safe_evidence
from .secretutils import is_placeholder

# ---------------------------------------------------------------------------
# Shared text collection (mirrors exchange_key_leak: homepage + inline
# scripts + same-domain JS bundles + public config files).
# ---------------------------------------------------------------------------

SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]+src=)[^>]*>(.*?)</script>", re.I | re.S)

CONFIG_PATHS = ["/.env", "/.env.local", "/.env.production",
                "/config.json", "/config.js"]

MAX_JS_BUNDLES = 15
MAX_FINDINGS = 10

# ---------------------------------------------------------------------------
# Plugin 1: exposed_card_number_leak
# ---------------------------------------------------------------------------

# Well-known published test card numbers. These appear in docs, test
# suites, and Stripe/test-gateway fixtures everywhere; they are not
# leaks and must never fire.
TEST_PANS = frozenset({
    "4111111111111111",  # Visa test
    "4222222222222",     # Visa 13-digit test
    "4242424242424242",  # Stripe Visa test
    "4000056655665556",  # Stripe Visa debit test
    "5555555555554444",  # Stripe Mastercard test
    "5200828282828210",  # Stripe Mastercard debit test
    "378282246310005",   # Amex test
    "371449635398431",   # Amex test
    "6011111111111117",  # Discover test
    "6011000990139424",  # Discover test
    "30569309025904",    # Diners test
    "6759649826438453",  # Laser test
    "3530111333300000",  # JCB test
})

# How far around a PAN we look for card context (chars).
RECORD_WINDOW = 400


def brand_of(digits: str) -> Optional[str]:
    """Card brand from the BIN prefix, or None for an unknown BIN."""
    for name, rx in BRANDS:
        if rx.match(digits):
            return name
    return None


def is_test_pan(digits: str) -> bool:
    return digits in TEST_PANS


def scan_text_for_pans(text: str,
                       require_context: bool = True) -> List[Dict]:
    """Find leaked PANs in one text blob. Returns fingerprint-only
    dicts {brand, bin6, last4, fp} - the full PAN never leaves this
    function. Config files (require_context=False) fire on any
    Luhn-valid non-test PAN; web/contract text needs card context
    nearby so a stray long number is not flagged."""
    out: List[Dict] = []
    seen: Set[str] = set()
    text = text or ""
    for m in PAN_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[^0-9]", "", raw)
        if len(digits) < 13 or len(digits) > 19:
            continue
        # Formatted PANs use 4+ digit groups (4-4-4-4, Amex 4-6-5,
        # Diners 4-6-4). A match with a 1-3 digit group is numeric
        # soup, not a card: SVG path data ("M50 100C77.6142 100 ...
        # 22.3858 ...") matched as 3858 0 0 22.3858 0 on moonpay.com
        # and passed Luhn by chance. Bare (unseparated) PANs are a
        # single group and are unaffected.
        groups = [g for g in re.split(r"[^0-9]", raw) if g]
        if len(groups) > 1 and any(len(g) < 4 for g in groups):
            continue
        if is_test_pan(digits):
            continue
        if not luhn_ok(digits):
            continue
        brand = brand_of(digits)
        if not brand:
            continue
        if require_context:
            lo = max(0, m.start() - RECORD_WINDOW)
            hi = min(len(text), m.end() + RECORD_WINDOW)
            if not CARD_CTX.search(text[lo:hi]):
                continue
        fp = fingerprint(digits)
        if fp in seen:
            continue
        seen.add(fp)
        out.append({"brand": brand, "bin6": digits[:6],
                    "last4": digits[-4:], "fp": fp})
    return out


class ExposedCardNumberLeakPlugin(Plugin):
    id = "exposed_card_number_leak"
    label = "Exposed Card Number Leak (Fingerprint-Only)"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "financial"
    description = (
        "Luhn-valid payment card numbers exposed in publicly fetched "
        "text (homepage, scripts, public config files, verified "
        "contract source). Findings carry brand, BIN, last 4, and a "
        "SHA-256 fingerprint only - never the full card number. "
        "Test card numbers are ignored; status is always UNVERIFIED "
        "(liveness is never probed).")
    phase = 2
    timeout_s = 60

    async def _collect_texts(self, target: Target, ctx: Ctx,
                             base: str, domain: str
                             ) -> List[Tuple[str, str, str, bool]]:
        """(text, url, kind, require_context) blobs to scan."""
        texts: List[Tuple[str, str, str, bool]] = []
        page = await ctx.fetch_page(base, timeout=12)
        if page:
            html = page.get("text", "") or ""
            for sm in INLINE_SCRIPT_RE.finditer(html):
                body = sm.group(1).strip()
                if len(body) > 20:
                    texts.append((body[:500000], base, "inline script",
                                  True))
            js_urls: Set[str] = set()
            for sm in SCRIPT_SRC_RE.finditer(html):
                full = urljoin(base, sm.group(1))
                try:
                    if domain in urlparse(full).netloc:
                        js_urls.add(full)
                except Exception:
                    continue
            for ju in ctx.consume("js_files"):
                if isinstance(ju, str):
                    try:
                        if domain in urlparse(ju).netloc:
                            js_urls.add(ju)
                    except Exception:
                        continue
            for ju in sorted(js_urls)[:MAX_JS_BUNDLES]:
                try:
                    jr = await ctx.fetch_page(ju, timeout=12)
                    if jr and jr.get("status_code") == 200:
                        texts.append((jr.get("text", "")[:500000], ju,
                                      "JS bundle", True))
                except Exception:
                    continue
            texts.append((html[:500000], base, "homepage", True))
        for path in CONFIG_PATHS:
            url = base.rstrip("/") + path
            try:
                r = await ctx.probe(url, timeout=8)
            except Exception:
                continue
            if not r or r.get("status") != 200:
                continue
            body = r.get("text", "") or ""
            if body.strip():
                # Config files are ungated: any Luhn-valid non-test
                # PAN in a public .env/config is a leak by construction.
                texts.append((body[:500000], url, f"public file {path}",
                              False))
        return texts

    def _collect_addresses(self, target: Target, ctx: Ctx
                           ) -> List[Tuple[Optional[str], str]]:
        """Contract addresses from the target / discovery bus (same
        collection shape as the deep-audit packs)."""
        try:
            from . import contract_chain as cc
        except Exception:
            return []
        out: List[Tuple[Optional[str], str]] = []
        seen = set()

        def add(chain_hint: Optional[str], addr: str) -> None:
            addr = (addr or "").strip()
            if not cc.ADDRESS_RE.match(addr):
                return
            if addr.lower() == cc.ZERO_ADDRESS:
                return
            k = addr.lower()
            if k in seen:
                return
            seen.add(k)
            out.append((chain_hint, addr))

        for raw in (target.normalized, target.raw):
            chain_hint, addr = cc.parse_target_address(raw or "")
            if addr:
                add(chain_hint, addr)
                break
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else \
                    str(item.get("address", ""))
                add(None, a)
        for item in ctx.consume("chain_contracts"):
            if isinstance(item, dict):
                hint = item.get("chain")
                add(hint if isinstance(hint, str) and
                    hint in cc.CHAINS else None,
                    str(item.get("address", "")))
        return out[:5]

    @staticmethod
    def _source_to_text(src: Optional[Dict]) -> str:
        """Verified-source dict -> flat text (handles plain string,
        standard-JSON {sources: {file: {content}}}, and lists)."""
        if not src:
            return ""
        raw = src.get("source", "")
        if isinstance(raw, str):
            return raw
        if isinstance(raw, dict):
            parts = []
            sources = raw.get("sources", raw)
            if isinstance(sources, dict):
                for v in sources.values():
                    if isinstance(v, dict) and "content" in v:
                        parts.append(str(v["content"]))
                    elif isinstance(v, str):
                        parts.append(v)
            return "\n".join(parts)
        if isinstance(raw, list):
            return "\n".join(str(x) for x in raw)
        return str(raw)

    async def _scan_contracts(self, target: Target, ctx: Ctx,
                              findings: List[Finding],
                              seen_fp: Set[str]) -> int:
        """Scan verified contract source for PANs. Returns the number
        of contract addresses analyzed. Keyless explorer routes only;
        no source -> skipped, no guess made."""
        try:
            from . import contract_chain as cc
        except Exception:
            return 0
        key = ctx.keys.get("etherscan")
        analyzed = 0
        for chain_hint, addr in self._collect_addresses(target, ctx):
            if analyzed >= 3:
                break
            chain_ids = [chain_hint] if chain_hint else \
                list(cc.DEFAULT_CHAIN_ORDER)
            for cid in chain_ids:
                chain = cc.CHAINS[cid]
                try:
                    code = await cc.rpc_get_code(ctx, chain, addr)
                except Exception:
                    continue
                if code is None or code == "0x" or len(code) < 4:
                    continue
                try:
                    src = await cc.fetch_verified_source(
                        ctx, chain, addr, key)
                except Exception:
                    src = None
                analyzed += 1
                text = self._source_to_text(src)
                if not text:
                    break
                url = cc.explorer_url(chain, addr)
                for hit in scan_text_for_pans(text, require_context=True):
                    if hit["fp"] in seen_fp:
                        continue
                    seen_fp.add(hit["fp"])
                    findings.append(self._make_finding(
                        hit, url,
                        f"verified contract source ({chain.id} {addr})"))
                    if len(findings) >= MAX_FINDINGS:
                        return analyzed
                break
        return analyzed

    def _make_finding(self, hit: Dict, url: str, kind: str) -> Finding:
        masked = f"{hit['bin6']}******{hit['last4']}"
        ev = safe_evidence(
            "high",
            "exposed card number (PAN) in public text",
            masked,
            hit["fp"],
            "Remove the card number from the public text immediately "
            "and report it to the site/contract owner so the card can "
            "be reissued. Treat exposed PANs as toxic data: never "
            "store, share, or attempt to use them. Rotate any "
            "credential that shipped alongside it.",
            {"brand": hit["brand"],
             "bin6": hit["bin6"],
             "last4": hit["last4"],
             "tag": "UNVERIFIED",
             "fingerprint16": hit["fp"][:16],
             "source_url": url,
             "source_kind": kind,
             "leak": True,
             "fingerprint_only": True})
        return self._f(
            "leak", "exposed_card_number_leak",
            f"UNVERIFIED: {hit['brand']} card number exposed in "
            f"{kind} (BIN {hit['bin6']}, last4 {hit['last4']}, "
            f"sha256 {hit['fp'][:16]}...).",
            "Exposed card number leak detector (fingerprint-only)",
            source_url=url, confidence=75, evidence=ev, passive=True)

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain and target.type not in ("crypto_wallet",):
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        seen_fp: Set[str] = set()
        scanned = 0
        if domain:
            base = await web_base(ctx, target, domain)
            for text, url, kind, req_ctx in await self._collect_texts(
                    target, ctx, base, domain):
                scanned += 1
                for hit in scan_text_for_pans(text, req_ctx):
                    if hit["fp"] in seen_fp:
                        continue
                    seen_fp.add(hit["fp"])
                    findings.append(self._make_finding(hit, url, kind))
                    if len(findings) >= MAX_FINDINGS:
                        break
                if len(findings) >= MAX_FINDINGS:
                    break
        contracts = await self._scan_contracts(target, ctx, findings,
                                               seen_fp)
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"scanned {scanned} web source(s) + {contracts} contract "
            f"source(s), {len(findings)} leaked PAN(s) "
            f"(fingerprint-only, UNVERIFIED)")
        res.duration_ms = dur
        return res


# ---------------------------------------------------------------------------
# Plugin 2: cc_to_crypto_onramp
# ---------------------------------------------------------------------------

# Provider -> strong markers (SDK identifiers / script domains). A bare
# brand mention with no marker does not fire.
ONRAMP_PROVIDERS: Dict[str, List[str]] = {
    "moonpay": [r"moonpay\.com", r"moonpay-js", r"MoonPayWebSdk",
                r"@moonpay/"],
    "simplex": [r"simplex\.com", r"SimplexPayment", r"simplex\.payment"],
    "ramp": [r"ramp\.network", r"@ramp-network/", r"ramp-instant-sdk",
             r"RampInstant"],
    "transak": [r"transak\.com", r"@transak/", r"transak-sdk",
                r"TransakConfig"],
    "banxa": [r"banxa\.com", r"\bbanxa\b"],
    "mercuryo": [r"mercuryo\.io", r"\bmercuryo\b"],
    "alchemypay": [r"alchemypay\.org", r"alchemypay", r"AlchemyPay"],
    "wert": [r"wert\.io", r"\bwert\b"],
    "wyre": [r"sendwyre", r"\bwyre\b"],
}

# Card-funded crypto purchase flow, with no provider named.
FLOW_RE = re.compile(
    r"(?i)buy\s+(crypto|bitcoin|btc|ethereum|eth|usdt|usdc)\s+"
    r"(with|using|via)\s+(a\s+)?(credit|debit)\s+card")


class CcToCryptoOnrampPlugin(Plugin):
    id = "cc_to_crypto_onramp"
    label = "Card-to-Crypto On-Ramp Surface"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "financial"
    description = (
        "Card-to-crypto on-ramp surfaces on scanned websites/APIs: "
        "provider SDK/widget references (MoonPay, Simplex, Ramp "
        "Network, Transak, Banxa, Mercuryo, Alchemy Pay, Wert, Wyre) "
        "and card-funded crypto purchase flows. Surface finding "
        "only; no card data of any kind.")
    phase = 1
    timeout_s = 60

    def _find_provider(self, text: str, src_url: str
                       ) -> List[Tuple[str, str, str]]:
        """(provider, marker, kind) hits in one text blob."""
        hits: List[Tuple[str, str, str]] = []
        for provider, patterns in ONRAMP_PROVIDERS.items():
            for pat in patterns:
                m = re.search(pat, text)
                if m:
                    hits.append((provider, m.group(0),
                                 "SDK/widget reference"))
                    break
        return hits

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        texts: List[Tuple[str, str]] = []
        page = await ctx.fetch_page(base, timeout=12)
        if page:
            html = page.get("text", "") or ""
            for sm in INLINE_SCRIPT_RE.finditer(html):
                body = sm.group(1).strip()
                if len(body) > 20:
                    texts.append((body[:500000], base))
            js_urls: Set[str] = set()
            for sm in SCRIPT_SRC_RE.finditer(html):
                full = urljoin(base, sm.group(1))
                try:
                    if domain in urlparse(full).netloc:
                        js_urls.add(full)
                except Exception:
                    continue
            for ju in ctx.consume("js_files"):
                if isinstance(ju, str):
                    try:
                        if domain in urlparse(ju).netloc:
                            js_urls.add(ju)
                    except Exception:
                        continue
            for ju in sorted(js_urls)[:MAX_JS_BUNDLES]:
                try:
                    jr = await ctx.fetch_page(ju, timeout=12)
                    if jr and jr.get("status_code") == 200:
                        texts.append((jr.get("text", "")[:500000], ju))
                except Exception:
                    continue
            texts.append((html[:500000], base))
        # Script-src domains are the strongest signal: check them first.
        script_srcs: List[str] = []
        if page:
            html = page.get("text", "") or ""
            for sm in SCRIPT_SRC_RE.finditer(html):
                script_srcs.append(urljoin(base, sm.group(1)))
        found: Dict[str, Tuple[str, str, str]] = {}
        for provider, patterns in ONRAMP_PROVIDERS.items():
            for src in script_srcs:
                hit = None
                for pat in patterns:
                    m = re.search(pat, src)
                    if m:
                        hit = m.group(0)
                        break
                if hit:
                    found[provider] = (hit, "script src", src)
                    break
        for text, url in texts:
            for provider, marker, kind in self._find_provider(text, url):
                if provider not in found:
                    found[provider] = (marker, kind, url)
        flow = False
        flow_url = base
        for text, url in texts:
            if FLOW_RE.search(text):
                flow = True
                flow_url = url
                break
        findings: List[Finding] = []
        for provider, (marker, kind, url) in sorted(found.items()):
            conf = 90 if kind == "script src" else 85
            ev = safe_evidence(
                "low",
                "card-to-crypto on-ramp surface",
                provider,
                fingerprint(f"{provider}:{marker}"),
                "Review the on-ramp integration: card data must be "
                "handled by the provider (PCI scope stays with them), "
                "confirm the checkout settles in crypto as advertised, "
                "and verify the provider is legitimate before users "
                "pay through it.",
                {"provider": provider,
                 "marker": marker,
                 "marker_kind": kind,
                 "tag": "SURFACE",
                 "source_url": url,
                 "on_ramp": True,
                 "scope_note": SCOPE_NOTE})
            findings.append(self._f(
                "web", "cc_to_crypto_onramp",
                f"{provider} card-to-crypto on-ramp surface "
                f"({kind}: {marker})",
                "Card-to-crypto on-ramp detector",
                source_url=url, confidence=conf, evidence=ev,
                passive=True))
        if flow and not found:
            ev = safe_evidence(
                "low",
                "card-to-crypto on-ramp surface",
                "generic card-funded crypto purchase flow",
                fingerprint("generic-cc-crypto-flow"),
                "Review the card-funded crypto purchase flow: card "
                "data must be handled by a PCI-compliant provider, "
                "and confirm the checkout settles in crypto as "
                "advertised.",
                {"provider": "generic",
                 "marker": "buy crypto with card",
                 "marker_kind": "checkout flow",
                 "tag": "SURFACE",
                 "source_url": flow_url,
                 "on_ramp": True,
                 "scope_note": SCOPE_NOTE})
            findings.append(self._f(
                "web", "cc_to_crypto_onramp",
                "generic card-funded crypto purchase flow "
                "(buy crypto with card)",
                "Card-to-crypto on-ramp detector",
                source_url=flow_url, confidence=75, evidence=ev,
                passive=True))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"scanned {len(texts)} source(s), "
            f"{len(findings)} on-ramp surface(s)")
        res.duration_ms = dur
        return res
