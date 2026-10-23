"""Operator/brand -> primary domain resolution for Bank/ATM mode.

A location search returns OpenStreetMap POIs (name, operator, brand,
address). To assess the operator's public web surface we need its
primary domain. Resolution order:

1. The POI's own ``website`` / ``contact:website`` tag (ground truth).
2. A built-in mapping for major Canadian + US banks and ATM networks,
   matched against operator, then brand, then name.

Returns None when nothing resolves - the caller keeps the POI as an
informational finding ("no public domain resolved"). Detection support
only: this module never fetches anything.
"""
from __future__ import annotations

import re
from typing import Dict, Optional

from .classifier import domain_from_target

# Normalized operator/brand key -> primary public domain. Keys are
# matched after _normalize() (lowercase, punctuation stripped), first
# as a whole token sequence, then as a substring for keys of len >= 4.
OPERATOR_DOMAINS: Dict[str, str] = {
    # -- Canada ------------------------------------------------------
    "rbc": "rbcroyalbank.com",
    "royal bank": "rbcroyalbank.com",
    "royal bank of canada": "rbcroyalbank.com",
    "rbc royal bank": "rbcroyalbank.com",
    "td": "td.com",
    "td bank": "td.com",
    "td canada trust": "td.com",
    "toronto dominion": "td.com",
    "toronto dominion bank": "td.com",
    "scotiabank": "scotiabank.com",
    "bank of nova scotia": "scotiabank.com",
    "scotia bank": "scotiabank.com",
    "bmo": "bmo.com",
    "bank of montreal": "bmo.com",
    "bmo bank of montreal": "bmo.com",
    "cibc": "cibc.com",
    "canadian imperial bank of commerce": "cibc.com",
    "canadian imperial bank": "cibc.com",
    "desjardins": "desjardins.com",
    "caisse desjardins": "desjardins.com",
    "mouvement desjardins": "desjardins.com",
    "atb": "atb.com",
    "atb financial": "atb.com",
    "simplii": "simplii.com",
    "simplii financial": "simplii.com",
    "tangerine": "tangerine.ca",
    "tangerine bank": "tangerine.ca",
    "national bank": "nbc.ca",
    "national bank of canada": "nbc.ca",
    "banque nationale": "nbc.ca",
    "laurentian bank": "laurentianbank.ca",
    "banque laurentienne": "laurentianbank.ca",
    "hsbc canada": "hsbc.ca",
    "eq bank": "eqbank.ca",
    "manulife bank": "manulifebank.ca",
    "conexus": "conexus.ca",
    "conexus credit union": "conexus.ca",
    "servus": "servus.ca",
    "servus credit union": "servus.ca",
    "meridian": "meridiancu.ca",
    "meridian credit union": "meridiancu.ca",
    "altern a": "alterna.ca",
    "alterna savings": "alterna.ca",
    "access credit union": "accesscu.ca",
    "steinbach credit union": "scu.net",
    # -- United States -------------------------------------------------
    "chase": "chase.com",
    "jpmorgan chase": "chase.com",
    "jp morgan chase": "chase.com",
    "chase bank": "chase.com",
    "bank of america": "bankofamerica.com",
    "bofa": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
    "citibank": "citi.com",
    "citi": "citi.com",
    "citi bank": "citi.com",
    "capital one": "capitalone.com",
    "us bank": "usbank.com",
    "u s bank": "usbank.com",
    "pnc": "pnc.com",
    "pnc bank": "pnc.com",
    "truist": "truist.com",
    "truist bank": "truist.com",
    "goldman sachs": "goldmansachs.com",
    "marcus": "marcus.com",
    "morgan stanley": "morganstanley.com",
    "american express": "americanexpress.com",
    "amex": "americanexpress.com",
    "discover": "discover.com",
    "fifth third": "53.com",
    "fifth third bank": "53.com",
    "citizens bank": "citizensbank.com",
    "keybank": "key.com",
    "regions bank": "regions.com",
    "huntington": "huntington.com",
    "huntington bank": "huntington.com",
    "ally": "ally.com",
    "ally bank": "ally.com",
    "navy federal": "navyfederal.org",
    "navy federal credit union": "navyfederal.org",
    # -- ATM networks / white-label operators --------------------------
    "cardtronics": "cardtronics.com",
    "allpoint": "allpointnetwork.com",
    "brinks": "brinks.com",
    "payment alliance": "paymentallianceintl.com",
}

# Sorted longest-first so multi-word keys win over short ones.
_KEYS = sorted(OPERATOR_DOMAINS, key=len, reverse=True)


def _normalize(s: str) -> str:
    """Lowercase, punctuation -> space, collapse whitespace."""
    s = (s or "").lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _match(text: str) -> Optional[str]:
    """Match one free-text field against the mapping."""
    norm = _normalize(text)
    if not norm:
        return None
    if norm in OPERATOR_DOMAINS:
        return OPERATOR_DOMAINS[norm]
    padded = f" {norm} "
    for key in _KEYS:
        # Whole token-sequence match (safe for short keys like "td").
        if f" {key} " in padded:
            return OPERATOR_DOMAINS[key]
    for key in _KEYS:
        # Substring match only for longer keys ("citi" in "citibank").
        if len(key) >= 4 and key in norm:
            return OPERATOR_DOMAINS[key]
    return None


def resolve_domain(name: str = "", operator: str = "",
                   brand: str = "", website: str = "") -> Optional[str]:
    """Resolve a POI to its operator's primary domain, or None.

    The POI's own website tag wins; then operator, brand, name are
    matched against the built-in mapping in that order.
    """
    site = (website or "").strip()
    if site:
        dom = domain_from_target("url", site) or \
            domain_from_target("domain", site)
        if dom:
            dom = dom.lower()
            # Bare operator domain, so a website-derived domain dedupes
            # against the same operator resolved via the mapping.
            if dom.startswith("www."):
                dom = dom[4:]
            return dom
    for field in (operator, brand, name):
        dom = _match(field or "")
        if dom:
            return dom
    return None
