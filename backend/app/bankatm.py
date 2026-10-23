"""Bank / ATM mode (source_type="bankatm").

Jay's spec: ONE input, NO options. The user types either a bank URL /
domain or a location, and the mode does the rest:

- URL / domain input -> the full financial detection set runs against
  that domain.
- Location input (city, address, "ATMs near <place>", or lat,lon) ->
  nearby banks AND ATMs are listed from OpenStreetMap, each operator is
  resolved to its primary domain, and the financial set runs against
  each unique resolved domain. Locations with no resolvable domain stay
  as informational findings. One run carries everything.

Detection only throughout: public web surface of bank domains + public
map data. Nothing here touches an ATM device, a banking session, card
data, or a login.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .classifier import classify_batch
from .geo import parse_coords

SOURCE_TYPE = "bankatm"

# The full financial detection set. Every id here must exist in the
# plugin registry and accept domain/url targets (asserted by tests).
FINANCIAL_PLUGIN_IDS: Tuple[str, ...] = (
    "bank",            # banking platforms, portals, admin panels, APIs
    "atm",             # ATM subdomains, portals, mgmt paths, vendor CVEs
    "bank_surface",    # internal leaks on locator pages + fleet panels
    "financial",       # payment processors / bank refs in pages
    "email_infra",     # SPF / DMARC / DKIM posture (phishing risk)
    "email_breach",    # breach exposure for the domain's email patterns
    "email_exposure",  # public email exposure on the domain
    "tls",             # TLS posture on banking hosts
    "tls_config",      # TLS configuration audit
    "smtp_tls",        # mail-server TLS posture
    "caa_audit",       # CAA records (cert issuance control)
    "headers",         # security headers
    "dns",             # DNS records + infra
    "subdomains",      # subdomain discovery (vpn./mail./portal hosts)
    "edge_appliances", # VPN / gateway fingerprints + CVEs
    "ports",           # open-port surface
)

# Location-mode bounds (honest caps, surfaced in the run summary).
MAX_POIS = 25            # bank + ATM locations listed per run
MAX_DOMAINS = 5          # unique operator domains assessed per run
POI_RADIUS_M = 5000      # search radius around the geocoded point


def parse_bankatm_input(raw: str) -> Dict:
    """Classify the single bankatm input.

    Returns one of:
      {"kind": "domain", "target_type": "domain"|"url",
       "normalized": <classified target>, "raw": <first line>}
      {"kind": "location", "location": <text>, "raw": <first line>}

    Coordinates ("49.8951,-97.1384") are locations, not domains.
    Anything that does not classify as a domain/URL is treated as a
    location and handed to the geocoder.
    """
    text = (raw or "").strip()
    first = ""
    for line in text.splitlines():
        if line.strip():
            first = line.strip()
            break
    if not first:
        return {"kind": "location", "location": "", "raw": ""}
    if parse_coords(first):
        return {"kind": "location", "location": first, "raw": first}
    classified = classify_batch(first)
    if classified:
        c = classified[0]
        if c.get("type") in ("domain", "url"):
            return {"kind": "domain", "target_type": c["type"],
                    "normalized": c["normalized"], "raw": first}
    return {"kind": "location", "location": first, "raw": first}


def financial_plugin_ids(available_ids: List[str],
                         excluded: Optional[List[str]] = None) -> List[str]:
    """The financial set, intersected with what the registry has and
    minus plan-excluded ids. Order follows FINANCIAL_PLUGIN_IDS."""
    avail = set(available_ids)
    excl = set(excluded or [])
    return [pid for pid in FINANCIAL_PLUGIN_IDS
            if pid in avail and pid not in excl]
