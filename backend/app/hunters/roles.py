"""The 23 hunter roles and the known-set expansion rules.

Each role: name, specialty, what it consumes (asset types and finding
keys), what it produces (asset types), and the detection plugins it
dispatches for verification. Hunters never verify anything themselves
with custom probes: the existing plugin set is the verifier, which
keeps the whole layer detection-only.

EXPANSION maps an asset type to ordered (hunter, [plugin ids]) rules.
When an asset of that type is confirmed into the known set, the rules
generate follow-up plugin jobs on a target built from the asset. The
engine intersects the plugin ids with the registry and each plugin's
accepted target types, and dedupes against jobs already in the run.
"""
from __future__ import annotations

HUNTERS = [
    {"name": "subdomain_hunter", "specialty": "Subdomain expansion",
     "consumes": ["domain", "cert"],
     "produces": ["subdomain"],
     "plugins": ["subdomains", "subdomain_brute", "subdomain_compiler"]},
    {"name": "endpoint_hunter", "specialty": "Endpoint and API discovery",
     "consumes": ["url", "domain", "js_file"],
     "produces": ["endpoint", "url"],
     "plugins": ["apidiscover", "crawler", "param_discovery"]},
    {"name": "js_miner", "specialty": "JS asset mining",
     "consumes": ["url", "endpoint"],
     "produces": ["js_file", "endpoint"],
     "plugins": ["jsminer", "jsdeep", "js_secrets"]},
    {"name": "secret_hunter", "specialty": "Secret-pattern hunting",
     "consumes": ["url", "js_file", "repo"],
     "produces": ["endpoint"],
     "plugins": ["secrets", "keyleak", "keyharvest"]},
    {"name": "cloud_hunter", "specialty": "Cloud asset hunting",
     "consumes": ["domain", "org"],
     "produces": ["url", "domain"],
     "plugins": ["cloud_buckets", "s3", "cloud_enum"]},
    {"name": "cert_hunter", "specialty": "Certificate transparency pivoting",
     "consumes": ["domain", "subdomain"],
     "produces": ["subdomain", "cert"],
     "plugins": ["tls"]},
    {"name": "dns_hunter", "specialty": "DNS pivoting",
     "consumes": ["domain", "subdomain", "ip"],
     "produces": ["ip", "subdomain"],
     "plugins": ["dns", "rdap"]},
    {"name": "port_hunter", "specialty": "Port and service pivoting",
     "consumes": ["ip", "subdomain", "domain"],
     "produces": ["url"],
     "plugins": ["ports", "port_scan", "banners"]},
    {"name": "wallet_hunter", "specialty": "Wallet hunting",
     "consumes": ["domain", "url"],
     "produces": ["wallet"],
     "plugins": ["wallets", "walletcheck"]},
    {"name": "contract_hunter", "specialty": "Token and contract hunting",
     "consumes": ["wallet", "url"],
     "produces": ["wallet"],
     "plugins": ["token_rugcheck", "rugpull", "smartcontract"]},
    {"name": "osint_hunter", "specialty": "Social and OSINT pivoting",
     "consumes": ["org", "domain"],
     "produces": ["email", "domain", "url"],
     "plugins": ["social", "dorks", "allsources"]},
    {"name": "email_hunter", "specialty": "Email and mail-infra hunting",
     "consumes": ["domain"],
     "produces": ["email", "domain"],
     "plugins": ["emails", "email_infra", "email_breach"]},
    {"name": "archive_hunter", "specialty": "Wayback and archive mining",
     "consumes": ["domain", "url"],
     "produces": ["url", "endpoint", "subdomain"],
     "plugins": ["wayback", "waybackurls", "gau"]},
    {"name": "fingerprint_hunter", "specialty": "Favicon and tech fingerprint pivoting",
     "consumes": ["url", "subdomain", "domain"],
     "produces": ["url", "domain"],
     "plugins": ["webtech", "tech_fingerprint", "favicon_hash", "headers"]},
    {"name": "repo_hunter", "specialty": "Repo and code-search pivoting",
     "consumes": ["domain", "org"],
     "produces": ["repo", "url", "domain"],
     "plugins": ["github", "github_dorking", "gitleaks_scan"]},
    {"name": "breach_hunter", "specialty": "Breach-data cross-reference (metadata only)",
     "consumes": ["email"],
     "produces": ["domain"],
     "plugins": ["breachwatch", "email_breach", "leaks", "pastes"]},
    {"name": "redirect_hunter", "specialty": "Redirect and chain following",
     "consumes": ["url", "domain"],
     "produces": ["url", "domain"],
     "plugins": ["crawler", "headers", "connections"]},
    {"name": "supplychain_hunter", "specialty": "Third-party and supply-chain mapping",
     "consumes": ["url", "domain", "repo"],
     "produces": ["domain", "url"],
     "plugins": ["supplychain", "dependency_conf", "assetgraph"]},
    {"name": "mobile_hunter", "specialty": "Mobile-app asset pivoting",
     "consumes": ["domain", "org"],
     "produces": ["url", "endpoint"],
     "plugins": ["appintel", "mobile", "binex"]},
    {"name": "graph_gap_hunter", "specialty": "Graph-gap hunting: under-explored nodes",
     "consumes": ["domain", "subdomain", "ip", "url", "email", "wallet", "repo"],
     "produces": ["domain", "subdomain", "ip", "url", "email", "wallet", "repo"],
     "plugins": ["assetgraph", "pivots", "autotriage"]},
    {"name": "neighbor_hunter", "specialty": "Related-domain and co-host discovery",
     "consumes": ["ip", "cert"],
     "produces": ["domain"],
     "plugins": ["reverse_ip"]},
    {"name": "passive_dns_hunter", "specialty": "Passive DNS history pivoting",
     "consumes": ["domain", "subdomain", "url"],
     "produces": ["ip", "subdomain", "domain"],
     "plugins": ["passive_dns"]},
    {"name": "rapiddns_hunter", "specialty": "RapidDNS deep subdomain enumeration",
     "consumes": ["domain"],
     "produces": ["subdomain"],
     "plugins": ["rapiddns"]},
]

HUNTER_NAMES = [h["name"] for h in HUNTERS]

# Finding key -> (asset type, attributing hunter). Extraction also uses
# value shape (URLs, wallet addresses, repo URLs) in the engine.
KEY_TO_ASSET = {
    "subdomain": ("subdomain", "subdomain_hunter"),
    "tls_san": ("subdomain", "cert_hunter"),
    "cert_cn": ("cert", "cert_hunter"),
    "certificate": ("cert", "cert_hunter"),
    "a": ("ip", "dns_hunter"),
    "aaaa": ("ip", "dns_hunter"),
    "ptr": ("subdomain", "dns_hunter"),
    "cname": ("subdomain", "dns_hunter"),
    "mx": ("domain", "dns_hunter"),
    "ns": ("domain", "dns_hunter"),
    "archived_url": ("url", "archive_hunter"),
    "wayback_interesting_url": ("url", "archive_hunter"),
    "graphql_endpoint": ("endpoint", "endpoint_hunter"),
    "endpoint_js": ("endpoint", "endpoint_hunter"),
    "js_file_deep": ("js_file", "js_miner"),
    "profile_url": ("url", "osint_hunter"),
    "cohosted_domain": ("domain", "neighbor_hunter"),
    "passive_ip": ("ip", "passive_dns_hunter"),
    "passive_host": ("domain", "passive_dns_hunter"),
    "endpoint": ("endpoint", "endpoint_hunter"),
    "api_endpoint": ("endpoint", "endpoint_hunter"),
    "rendered_endpoint": ("endpoint", "endpoint_hunter"),
    "js_endpoint": ("endpoint", "js_miner"),
    "js_file": ("js_file", "js_miner"),
    "script_src": ("js_file", "js_miner"),
    "email": ("email", "email_hunter"),
    "registrant_org": ("org", "osint_hunter"),
    "linked_contract": ("wallet", "contract_hunter"),
    "crypto_btc_address": ("wallet", "wallet_hunter"),
    "crypto_eth_address": ("wallet", "wallet_hunter"),
    "wallet_address": ("wallet", "wallet_hunter"),
    "github_repo": ("repo", "repo_hunter"),
    "apk_url": ("url", "mobile_hunter"),
    "mobile_url": ("url", "mobile_hunter"),
}

# Asset type -> ordered expansion rules: (hunter, [plugin ids]).
# domain -> certs (tls), subdomains, wayback URLs, cloud buckets, DNS.
# ip -> reverse DNS + records (dns/rdap), sibling service surface (ports).
# email -> related infra (email_infra) + breach cross-reference.
# wallet -> read-only chain/counterparty checks via wallet plugins.
# js_file -> endpoints and key patterns inside it (jsdeep/js_secrets),
#            then the endpoints themselves get scanned as url targets.
# repo -> org repos and hosts in history (github plugins).
EXPANSION = {
    "domain": [
        ("subdomain_hunter", ["subdomains", "subdomain_compiler",
                              "subdomain_brute"]),
        ("cert_hunter", ["tls"]),
        ("dns_hunter", ["dns"]),
        ("passive_dns_hunter", ["passive_dns"]),
        ("rapiddns_hunter", ["rapiddns"]),
        ("archive_hunter", ["wayback"]),
        ("cloud_hunter", ["cloud_buckets", "s3"]),
        ("email_hunter", ["emails", "email_infra"]),
    ],
    "subdomain": [
        # A newly found subdomain is a fresh web target: run the core
        # DISCOVERY set a human would run on it, not just fingerprinting.
        # These surface the signals (tech, endpoints, API maps, forms,
        # headers, CORS) that finding-driven chaining then cascades on.
        # Bounded by MAX_PLUGINS_PER_ASSET and the hunter task budget.
        ("dns_hunter", ["dns"]),
        ("fingerprint_hunter", ["webtech", "headers", "favicon_hash"]),
        ("cert_hunter", ["tls"]),
        ("port_hunter", ["ports", "banners"]),
        ("endpoint_hunter", ["apidiscover", "js_endpoints"]),
        ("redirect_hunter", ["http_methods", "cors"]),
    ],
    "cert": [
        ("cert_hunter", ["tls"]),
        ("subdomain_hunter", ["subdomains", "subdomain_compiler"]),
    ],
    "ip": [
        # Only plugins that accept an `ip` target (dns/passive_dns take
        # domain/url and were silently filtered here before).
        ("dns_hunter", ["rdap"]),
        ("port_hunter", ["ports", "port_scan", "banners"]),
        ("neighbor_hunter", ["reverse_ip"]),
    ],
    "url": [
        ("endpoint_hunter", ["apidiscover", "crawler"]),
        ("js_miner", ["jsminer", "js_endpoints"]),
        ("secret_hunter", ["secrets"]),
        ("fingerprint_hunter", ["headers", "webtech"]),
        ("redirect_hunter", ["http_methods", "cors"]),
        ("archive_hunter", ["waybackurls", "gau"]),
    ],
    "endpoint": [
        ("endpoint_hunter", ["apidiscover", "param_discovery"]),
        ("secret_hunter", ["secrets"]),
    ],
    "js_file": [
        ("js_miner", ["jsdeep", "js_secrets"]),
        ("secret_hunter", ["secrets", "keyharvest"]),
    ],
    "email": [
        ("email_hunter", ["email_infra"]),
        ("breach_hunter", ["breachwatch", "email_breach", "leaks"]),
    ],
    "wallet": [
        ("wallet_hunter", ["walletcheck", "keyleak"]),
        # A "wallet" asset that is actually a CONTRACT (e.g. a linked
        # oracle/admin/registry surfaced by contract_recon) gets the core
        # contract-analysis stack, so the dependency graph is scanned, not
        # just rug-checked. On an EOA these degrade cheaply (no code).
        ("contract_hunter", ["token_rugcheck", "rugpull", "contract_recon",
                             "contract_logic", "crypto_drain_scanner"]),
    ],
    "repo": [
        ("repo_hunter", ["github", "github_dorking", "gitleaks_scan"]),
    ],
    "org": [
        ("osint_hunter", ["social", "dorks"]),
        ("repo_hunter", ["github"]),
        ("email_hunter", ["emails"]),
    ],
}

# Asset types a hunter pass will turn into scan targets. "org" expands
# through person_or_company targets; everything maps through the
# classifier at enqueue time.
EXPANDABLE_TYPES = set(EXPANSION.keys())
