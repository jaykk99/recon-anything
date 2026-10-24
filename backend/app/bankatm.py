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
    # fin_* bank/ATM detector pack (bankpack_*.py, added 2026-10-23):
    # portals & configs
    "fin_js_config",          # front-end config objects leaking internals
    "fin_partner_portal",     # partner / agent / broker portals
    "fin_api_docs_secrets",   # API docs embedding live-looking credentials
    "fin_mobile_config",      # served mobile-banking config files
    "fin_oidc_config",        # OIDC discovery leaking internal hosts
    "fin_saml_metadata",      # SAML metadata leaking internal hosts
    "fin_locator_api",        # locator APIs returning internal fields
    "fin_treasury_portal",    # treasury / corporate portals
    # ATM surface
    "fin_atm_monitor",        # ATM monitoring dashboards
    "fin_atm_status_api",     # per-terminal status API fields
    "fin_atm_updates",        # ATM software distribution points
    "fin_atm_locator_feed",   # locator feeds with hardware data
    "fin_atm_remote_access",  # remote-access gateways
    "fin_atm_journal",        # electronic journal / receipt data
    "fin_atm_switch_config",  # terminal switch config files
    "fin_atm_network_status", # network status pages naming internals
    # payments & cards
    "fin_payment_secrets",      # processor SECRET keys in public code
    "fin_webhook_secrets",      # webhook signing secrets
    "fin_bin_config",           # BIN lookup configs / databases
    "fin_sandbox_live_mismatch",# sandbox creds in production configs
    "fin_card_form_action",     # card forms posting off-site / over HTTP
    "fin_merchant_portal",      # merchant acquiring portals
    "fin_pos_config",           # POS terminal config files
    "fin_ach_config",           # ACH file-transfer configs
    # documents & data
    "fin_statement_sample",   # statement samples with internal data
    "fin_report_exports",     # financial report exports
    "fin_docstore_listing",   # document-store directory listings
    "fin_core_backup",        # core-banking database backups
    "fin_form_hidden_fields", # application forms' hidden internal fields
    "fin_tax_sample_data",    # tax samples with TIN-shaped values
    "fin_staff_directory",    # staff directories with internal fields
    "fin_doc_metadata",       # PDF metadata naming internal users/paths
    # infrastructure
    "fin_cert_expired",       # expired banking certificates
    "fin_cert_mismatch",      # certificate name mismatch
    "fin_cert_weak",          # weak keys / signatures / protocols
    "fin_staging_env",        # staging/UAT banking environments
    "fin_ct_internal_names",  # CT logs betraying internal hostnames
    "fin_status_internals",   # status pages naming internal systems
    "fin_alerts_mail_posture",# alert subdomains without SPF
    "fin_login_thirdparty_scripts",  # skimming-risk scripts on login pages
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
