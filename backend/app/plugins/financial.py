"""Financial footprint finder.

Finds every financial/banking/payment reference on the target:
payment processors, bank references in code, crypto wallets,
exchange APIs, billing endpoints. Shows ALL of it.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urljoin

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Payment processor signatures
PROCESSORS = [
    ("Stripe", r"stripe\.com|stripe\.js|pk_live_|sk_live_"),
    ("PayPal", r"paypal\.com|paypalobjects\.com"),
    ("Square", r"squareup\.com|square\.js"),
    ("Braintree", r"braintree"),
    ("Adyen", r"adyen\.com"),
    ("Checkout.com", r"checkout\.com"),
    ("Razorpay", r"razorpay"),
    ("Paddle", r"paddle\.com"),
    ("Chargebee", r"chargebee"),
    ("Recurly", r"recurly"),
    ("Apple Pay", r"apple-pay|ApplePaySession"),
    ("Google Pay", r"google\.com/pay|GooglePay"),
]

# Bank/financial references in code
BANK_PATTERNS = [
    ("bank_account", r"\b(bank[_-]?account|account[_-]?number)\b", 70),
    ("routing_number", r"\brouting[_-]?number\b", 75),
    ("iban", r"\bIBAN\b", 75),
    ("swift_code", r"\bSWIFT\b", 70),
    ("credit_card", r"\b(credit[_-]?card|card[_-]?number)\b", 65),
    ("billing_endpoint", r"/(?:billing|invoice|payment|checkout|subscribe|subscription)", 80),
]

# Crypto references
CRYPTO_PATTERNS = [
    ("btc_address", r"\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", 85),
    ("eth_address", r"\b0x[a-fA-F0-9]{40}\b", 85),
    ("exchange_api", r"(binance|coinbase|kraken|bitfinex|kucoin)[-_.]?(api|key)", 80),
    ("web3_provider", r"web3|ethers\.js|metamask|walletconnect", 70),
    ("smart_contract", r"0x[a-fA-F0-9]{40}", 60),
]


class FinancialPlugin(Plugin):
    id = "financial"
    label = "Financial Footprint"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find payment processors, bank refs, crypto wallets, billing."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []

        # Fetch homepage + common billing pages
        pages = [base + "/"]
        for path in ["/pricing", "/billing", "/checkout", "/payment", "/subscribe"]:
            pages.append(base + path)

        all_text = ""
        for url in pages[:3]:  # limit to avoid hammering
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url)
                if resp and resp.status_code == 200:
                    all_text += resp.text[:200000] + "\n"
                    # Check JS files too
                    for m in re.finditer(r'src=["\']([^"\']+\.js)["\']', resp.text):
                        js_url = urljoin(url, m.group(1))
                        try:
                            jr = await fetch(ctx.http, ctx.limiter, "GET", js_url)
                            if jr and jr.status_code == 200:
                                all_text += jr.text[:100000] + "\n"
                        except Exception:
                            pass
                        if len(all_text) > 500000:
                            break
            except Exception:
                continue
            if len(all_text) > 500000:
                break

        if not all_text:
            return self._skipped("could not fetch pages")

        # Payment processors
        for name, pattern in PROCESSORS:
            if re.search(pattern, all_text, re.I):
                findings.append(self._f(
                    "financial", "payment_processor", name,
                    f"financial: {name} payment processor detected",
                    confidence=90,
                    evidence={"severity": "info",
                              "why": "Payment processor integration found"}))
                ctx.publish("financial_processors", name)

        # Bank patterns
        for key, pattern, conf in BANK_PATTERNS:
            for m in re.finditer(pattern, all_text, re.I):
                val = m.group(0)
                # Skip if it's just a label without value
                ctx_text = all_text[max(0, m.start()-50):m.end()+50]
                findings.append(self._f(
                    "financial", f"bank_{key}", val,
                    f"financial: bank reference '{val}' in code",
                    confidence=conf,
                    evidence={"severity": "medium" if conf >= 75 else "low",
                              "context": ctx_text[:200]}))
                if len([f for f in findings if f.key.startswith("bank_")]) > 20:
                    break

        # Billing endpoints
        for m in re.finditer(r'["\']((?:/[\w\-.]+)*(?:/billing|/invoice|/payment|/checkout|/subscribe)[\w\-.?=&%]*)["\']', all_text):
            ep = m.group(1)
            findings.append(self._f(
                "financial", "billing_endpoint", ep,
                "financial: billing/payment endpoint found",
                confidence=80))
            ctx.publish("endpoints", urljoin(base, ep))

        # Crypto
        for key, pattern, conf in CRYPTO_PATTERNS:
            for m in re.finditer(pattern, all_text):
                val = m.group(0) if m.groups() else m.group(0)
                # Avoid duplicates from eth_address/smart_contract overlap
                findings.append(self._f(
                    "financial", f"crypto_{key}", val[:100],
                    f"financial: crypto reference '{key}' found",
                    confidence=conf))
                if len([f for f in findings if f.key.startswith("crypto_")]) > 20:
                    break

        findings.append(self._f(
            "financial", "financial_summary",
            f"{len([f for f in findings if f.key == 'payment_processor'])} processors, "
            f"{len([f for f in findings if f.key.startswith('bank_')])} bank refs, "
            f"{len([f for f in findings if f.key.startswith('crypto_')])} crypto refs",
            "financial", confidence=90))

        return self._ok(findings, f"found {len(findings)} financial references")
