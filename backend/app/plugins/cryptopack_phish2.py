"""Crypto pack wave 2: named drainer kits, Permit2 bait, scam
funnel pages, and typosquat/homoglyph links.

Wave 1 caught the generic kit behaviours (seed forms, claim
funnels, approval bait). Wave 2 names the drainer-as-a-service
brands whose loaders and config endpoints incident responders
signature on - Inferno, Pink, Angel, MS (Monkey) - plus the
Permit2-specific bait that wave 1's generic permit detector
misses, and the typosquat domains a page sends its users to.
Detection only: signatures and link analysis, nothing is
submitted anywhere.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urlparse

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import PackPlugin, collect_texts


def _drainer(id_, brand, patterns):
    return type(id_, (PackPlugin,), {
        "id": id_,
        "label": f"Drainer kit: {brand}",
        "description": f"{brand} drainer-as-a-service kit signatures "
                       "(loader strings, config names, brand marks) "
                       "in the target's served content.",
        "__module__": __name__,
        "PATTERNS": patterns,
    })


CpDrainerInferno = _drainer("cp_drainer_inferno", "Inferno Drainer", [
    (r"(?:inferno[-_ ]?drainer|InfernoDrainer|drainer[-_ ]?inferno|"
     r"inferno[-_ ]?multichain)",
     "inferno_drainer", "Inferno Drainer signature", 88, None),
])

CpDrainerPink = _drainer("cp_drainer_pink", "Pink Drainer", [
    (r"(?:pink[-_ ]?drainer|PinkDrainer|pinkdrainer)",
     "pink_drainer", "Pink Drainer signature", 88, None),
])

CpDrainerAngel = _drainer("cp_drainer_angel", "Angel Drainer", [
    (r"(?:angel[-_ ]?drainer|AngelDrainer|angeldrainer)",
     "angel_drainer", "Angel Drainer signature", 88, None),
])

CpDrainerMs = _drainer("cp_drainer_ms", "MS / Monkey Drainer", [
    (r"(?:ms[-_ ]?drainer|MSDrainer|msdrainer|monkey[-_ ]?drainer|"
     r"MonkeyDrainer)",
     "ms_drainer", "MS/Monkey Drainer signature", 88, None),
])


class CpDrainerPermit2(PackPlugin):
    id = "cp_drainer_permit2"
    label = "Drainer pattern: Permit2 approval bait"
    description = ("Permit2-specific signature bait: the canonical "
                   "Permit2 contract, SignatureTransfer and witness "
                   "permit flows - one signature can authorize "
                   "unlimited token movement, which is why drainers "
                   "standardized on it.")
    PATTERNS = [
        (r"\b0x000000000022D473030F116dDEE9F6B43aC78BA3\b",
         "permit2_contract", "Permit2 contract reference", 80, None),
        (r"(?:SignatureTransfer|permitWitness|PermitBatch|IPermit2|"
         r"AllowanceTransfer)",
         "permit2_flow", "Permit2 signature flow", 85, None),
    ]


class CpPhishEligibilityScam(PackPlugin):
    id = "cp_phish_eligibility_scam"
    label = "Phishing: fake airdrop eligibility checker"
    description = ("'Check your eligibility' funnels wired to a "
                   "wallet connect - the current dominant airdrop "
                   "scam shape (the check is fake; the approval is "
                   "real).")
    CONTEXT_RE = r"connect wallet|airdrop"
    PATTERNS = [
        (r"(?:check (?:your )?eligibility|eligibility checker|"
         r"verify (?:your )?allocation|check (?:your )?allocation)",
         "eligibility_scam", "Fake eligibility checker lure", 82,
         None),
    ]


class CpPhishPresaleScam(PackPlugin):
    id = "cp_phish_presale_scam"
    label = "Phishing: fake token presale"
    description = ("Presale pages that take payment by direct "
                   "transfer to a wallet address instead of a "
                   "contract - the standard rug funnel.")
    CONTEXT_RE = r"presale|pre-sale|token sale"
    PATTERNS = [
        (r"(?:send (?:exactly )?(?:\d+(?:\.\d+)?\s*)?(?:eth|bnb|sol|"
         r"usdt) to|transfer to (?:this|the) address to (?:buy|join|"
         r"participate))",
         "presale_direct_send", "Presale direct-send instruction",
         85, None),
        (r"(?:presale (?:ends|price|hardcap)|hardcap\s*[:=])",
         "presale_page", "Presale page markers", 62, None),
    ]


# ---------------------------------------------------------------------------
# Typosquat / homoglyph links
# ---------------------------------------------------------------------------

_BRANDS = {
    "metamask.io": "MetaMask",
    "binance.com": "Binance",
    "coinbase.com": "Coinbase",
    "kraken.com": "Kraken",
    "ledger.com": "Ledger",
    "trezor.io": "Trezor",
    "trustwallet.com": "Trust Wallet",
    "phantom.app": "Phantom",
    "uniswap.org": "Uniswap",
    "opensea.io": "OpenSea",
    "pancakeswap.finance": "PancakeSwap",
    "kucoin.com": "KuCoin",
    "bybit.com": "Bybit",
    "okx.com": "OKX",
}

_HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "@": "a", "$": "s",
})

_LINK_RE = re.compile(r"(?:href|src|action)\s*=\s*[\"'](https?://[^\"']+)",
                      re.I)


def _levenshtein(a: str, b: str, cap: int = 2) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (ca != cb))
            best = min(best, cur[j])
        if best > cap:
            return cap + 1
        prev = cur
    return prev[len(b)]


def _typosquat_brand(domain: str):
    """Return (brand, reason) if domain impersonates a brand."""
    d = domain.lower().strip(".")
    if d.startswith("xn--"):
        try:
            d = d.encode().decode("idna")
        except Exception:
            pass
    labels = d.split(".")
    for official, brand in _BRANDS.items():
        if d == official or d.endswith("." + official):
            return None  # the real thing (or its subdomain)
    for official, brand in _BRANDS.items():
        token = official.split(".")[0]
        if token in d.replace("-", "").replace(".", ""):
            if d != official:
                return brand, "brand name embedded in a lookalike domain"
        norm = d.translate(_HOMOGLYPHS).replace("rn", "m")
        if norm == official:
            return brand, "homoglyph lookalike of the official domain"
        for cand in (norm, d):
            dist = _levenshtein(cand, official)
            if dist in (1, 2):
                return brand, f"edit distance {dist} from {official}"
    return None


class CpPhishTyposquatLinks(Plugin):
    id = "cp_phish_typosquat_links"
    label = "Phishing: typosquat/homoglyph brand links"
    description = ("Outbound links on the target that impersonate "
                   "wallet/exchange brands: brand names embedded in "
                   "lookalike domains, homoglyph swaps, punycode, "
                   "or 1-2 edit distance from the real domain.")
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        texts = await collect_texts(ctx, target)
        if not texts:
            return self._degraded("homepage fetch failed")
        findings: List[Finding] = []
        seen = set()
        for where, text, url in texts:
            for m in _LINK_RE.finditer(text):
                link = m.group(1)
                try:
                    domain = urlparse(link).hostname or ""
                except Exception:
                    continue
                if not domain or domain in seen:
                    continue
                seen.add(domain)
                hit = _typosquat_brand(domain)
                if not hit:
                    continue
                brand, reason = hit
                findings.append(self._f(
                    "phishing", "typosquat_link",
                    f"Link impersonates {brand}: {domain} ({reason})",
                    source=self.label, source_url=url, confidence=85,
                    passive=True,
                    evidence={"domain": domain, "brand": brand,
                              "reason": reason, "link": link[:200]}))
                if len(findings) >= 10:
                    break
        res = self._ok(findings,
                       f"{len(findings)} typosquat link(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
