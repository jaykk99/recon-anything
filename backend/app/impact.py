"""Attacker-impact statements for findings.

Every finding answers one question in plain language: "what could an
attacker actually DO with this?" The vuln advisor already explains why a
candidate attack path is viable (why_viable); this module is the
per-finding equivalent. It is descriptive impact only - what the finding
enables - never exploit steps or how-to instructions.

Resolution order (most specific first):
  1. IMPACT_BY_KEY     - exact finding key (e.g. "git_exposed")
  2. IMPACT_PREFIXES   - key families (e.g. "exposed_*", "tls_*")
  3. IMPACT_BY_PLUGIN  - the plugin that produced the finding
  4. IMPACT_BY_CATEGORY- the finding category (dns/web/api/...)
  5. GENERIC           - honest recon-level fallback

base.Plugin._f stamps evidence["attacker_impact"] at creation time;
reporting.findings_dump backfills the top-level field at read time so
old runs (and the few findings built outside _f) get it too.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 1. Exact finding keys.
# ---------------------------------------------------------------------------
IMPACT_BY_KEY: Dict[str, str] = {
    # -- source code / secret exposure -------------------------------------
    "git_exposed": "An attacker can download the entire source code and "
                   "commit history, then audit it offline for secrets, "
                   "hidden endpoints and logic flaws at zero risk of "
                   "being noticed.",
    "git_head_exposed": "An attacker can confirm the repo is public and "
                        "start reconstructing the full source tree, "
                        "including deleted files and old credentials in "
                        "history.",
    "git_file_exposed": "An attacker can read individual files from the "
                        "repo (config, .env, keys) directly over HTTP "
                        "without any login.",
    "git_full_recon": "An attacker gets the complete repository: source, "
                      "history and every secret ever committed, enough "
                      "to plan a full compromise offline.",
    "git_exposed_archived": "An archived copy of the repo is public, so an "
                            "attacker can mine old source and any secrets "
                            "that were committed back then.",
    "exposed_env": "An attacker can read live configuration secrets - "
                   "database passwords, API keys, session secrets - and "
                   "use them to log in as the application itself.",
    "laravel_env": "An attacker can read the Laravel .env: the APP_KEY "
                   "lets them forge encrypted cookies and sessions, and "
                   "the DB/mail credentials hand over the data behind "
                   "the app.",
    "laravel_env_inline": "An attacker can read the Laravel .env served "
                          "inline: APP_KEY, database and mail credentials "
                          "are all directly usable.",
    "rails_secret": "An attacker with the Rails secret key base can forge "
                    "signed session cookies and log in as any user, "
                    "including admins.",
    "artifact_exposed": "An attacker can download this exposed file "
                        "directly - depending on the file that means "
                        "source code, backups, credentials or customer "
                        "data, no login required.",
    "backup_exposed": "An attacker can download a full backup: the entire "
                      "site or database in one file, including password "
                      "hashes and customer records.",
    "backup_archived": "An old backup is still reachable in an archive, "
                       "so an attacker can pull a full copy of the site "
                       "or database as it existed then.",
    "artifact_archived": "An archived copy of this file is public, giving "
                         "an attacker the data it contains (often source, "
                         "config or credentials) even if the live copy "
                         "was removed.",
    "phpinfo_exposed": "An attacker learns exact PHP version, loaded "
                       "extensions, server paths and environment "
                       "variables - a shopping list for picking the "
                       "right exploit and finding secrets.",
    "phpinfo_page": "An attacker learns exact PHP version, extensions, "
                    "paths and environment variables from this phpinfo "
                    "page, which tells them precisely what will work "
                    "against the server.",
    "phpinfo_inline": "An attacker can read phpinfo output inline: exact "
                      "versions, paths and env vars to target exploits "
                      "and locate secrets.",
    "sourcemap_secret": "An attacker can read the original source from the "
                        "source map and extract the secret embedded in "
                        "it, exactly as the developers wrote it.",
    "sourcemap_exposed": "An attacker can reconstruct the full original "
                         "frontend source code from the source map, then "
                         "audit it offline for API keys, hidden routes "
                         "and logic bugs.",
    "sourcemap_cred_comment": "An attacker can read a credential left in a "
                              "source comment and try it against the "
                              "app, its database and anywhere it was "
                              "reused.",
    "sourcemap_internal_url": "An attacker learns internal URLs that were "
                              "never meant to be public, giving them new "
                              "targets that may skip the normal auth "
                              "checks.",
    "sourcemap_api_route": "An attacker learns undocumented API routes "
                           "from the source map and can call them "
                           "directly, including ones the UI never shows.",
    "sourcemap_debug_flag": "An attacker learns the app ships with debug "
                            "behavior enabled, which often unlocks "
                            "verbose errors and extra endpoints to probe.",
    "js_secret": "An attacker can extract this secret from the JavaScript "
                 "and use it against the service it belongs to - anyone "
                 "who loads the page already has it.",
    "entropy_secret": "An attacker can pull this high-entropy string (very "
                      "likely a live key or token) out of the page and "
                      "use it wherever it is accepted.",
    "comment_secret": "An attacker can read a secret left in an HTML "
                      "comment - it is sent to every visitor's browser, "
                      "no special access needed.",
    "comment_credential": "An attacker can read working-looking "
                          "credentials from an HTML comment and try them "
                          "on the app, the VPN and anywhere passwords "
                          "get reused.",
    "comment_internal_host": "An attacker learns an internal hostname "
                             "that is not public anywhere else, giving "
                             "them a target inside the network perimeter "
                             "if they ever get a foothold or SSRF.",
    "mnemonic_exposed": "An attacker with this seed phrase controls the "
                        "wallet outright - every coin in it can be moved "
                        "in minutes, irreversibly.",
    "wallet_file_exposed": "An attacker can download the wallet file; "
                           "combined with a weak or known password it "
                           "gives full control of the funds.",
    "plaintext_password": "An attacker can read a password in plain text "
                          "and log in with it directly - and try it on "
                          "every other service where it might be reused.",
    "hash_cracked_public": "This password hash is already cracked in "
                           "public databases, so an attacker effectively "
                           "knows the plain password and can log in with "
                           "it anywhere it is reused.",
    "hash_analyzed": "An attacker can take this hash offline and crack it "
                     "at full GPU speed with no lockouts - weak passwords "
                     "fall in hours.",
    "hash_cracked_direct": "This hash was submitted for checking and the "
                           "built-in dictionary attack recovered the "
                           "password on the spot - anyone who obtains "
                           "the hash can do exactly the same.",
    "hash_crack_attempt": "The submitted hash resisted the built-in "
                          "dictionary attack; a larger wordlist or a GPU "
                          "rig may still recover a weak password from it.",
    "hash_identified": "Knowing the exact hash type lets an attacker pick "
                       "the fastest cracking setup and recover weak "
                       "passwords offline, unthrottled.",
    # -- injection / execution (detection-confirmed) -------------------------
    "sqli_error_based": "An attacker can inject SQL through this "
                        "parameter and read, modify or delete database "
                        "contents - user tables first.",
    "sqli_union_based": "An attacker can append their own SELECT to the "
                        "app's query and dump database rows straight into "
                        "the page, table by table.",
    "sqli_boolean_blind": "An attacker can extract the database one yes/no "
                          "question at a time - slower than a direct "
                          "dump, but the whole database is reachable.",
    "sqli_time_based": "An attacker can extract database contents by "
                       "timing the server's responses, even when no data "
                       "is ever shown on the page.",
    "sqli_time_blind": "An attacker can extract database contents by "
                       "timing the server's responses, even when no data "
                       "is ever shown on the page.",
    "nosqli_error_based": "An attacker can inject operators into the "
                          "NoSQL query to bypass login checks or pull "
                          "documents they should never see.",
    "nosqli_time_based": "An attacker can probe the NoSQL database with "
                         "timing side channels and bypass or extract "
                         "data without any output on the page.",
    "cmdi_error_based": "An attacker can run operating-system commands on "
                        "the server through this parameter - effectively "
                        "a shell with the web server's privileges.",
    "cmdi_time_based": "An attacker can run operating-system commands on "
                       "the server (proven by timing), which means full "
                       "control of the host is on the table.",
    "rce_error_based": "An attacker can execute code on the server "
                       "remotely - the single most direct path to owning "
                       "the machine, its data and its network position.",
    "rce_time_based": "An attacker can execute code on the server "
                      "remotely (proven by timing): full host compromise "
                      "is realistic from here.",
    "ssti_error_based": "An attacker can get the template engine to "
                        "evaluate their input, which in most engines "
                        "escalates to running code on the server.",
    "ssti_template_evaluated": "The server evaluated attacker-controlled "
                               "template syntax, which typically chains "
                               "to remote code execution.",
    "xpath_injection": "An attacker can rewrite the XML query to read "
                       "nodes outside their account - other users' data "
                       "stored in the same document.",
    "ldap_injection": "An attacker can inject into the directory query to "
                      "bypass the login or enumerate staff accounts and "
                      "attributes from the directory.",
    "logic_injection": "An attacker can manipulate the app's own logic "
                        "inputs to skip steps, change prices or approve "
                        "their own requests.",
    "html_injection": "An attacker can inject markup into a page other "
                      "users see - the stepping stone to phishing forms "
                      "and script injection on a trusted domain.",
    "xss_reflected": "An attacker can craft a link that runs their "
                     "JavaScript in a victim's browser on this trusted "
                     "domain - stealing sessions or acting as the victim.",
    "xss_context_probe": "User input lands inside a script context, so an "
                         "attacker can likely break out and run their own "
                         "JavaScript in victims' browsers.",
    "dir_traversal_confirmed": "An attacker can read files outside the "
                               "web root - configuration, credentials and "
                               "source code - by walking the filesystem.",
    "proto_pollution_reflection": "An attacker can pollute the shared "
                                  "object prototype, flipping application "
                                  "defaults for every user - a common "
                                  "chain into auth bypass or code "
                                  "execution.",
    "cache_poisoning_reflection": "An attacker can get their input stored "
                                  "in the shared cache, so every visitor "
                                  "is served the poisoned response until "
                                  "it expires.",
    "unkeyed_header_reflection": "An attacker can reflect a header value "
                                 "into cached responses, letting them "
                                 "poison pages for all visitors behind "
                                 "that cache.",
    "oob_callback_sent": "The server made an outbound request to an "
                         "attacker-controlled address, proving server-side "
                         "request forgery is reachable from this input.",
    "ssrf_cloud_metadata": "An attacker can make the server fetch the "
                           "cloud metadata service and hand back cloud "
                           "credentials - usually full account takeover "
                           "of the cloud environment.",
    "ssrf_canary_reflected": "The server fetched an attacker URL, so an "
                             "attacker can make it call internal services "
                             "that are unreachable from the internet.",
    "ssrf_prone_param": "This parameter takes a URL the server fetches, "
                        "so an attacker can aim it at internal services "
                        "and the cloud metadata endpoint.",
    "ssrf_error_leak": "Server fetch errors leak internal details, "
                       "helping an attacker map internal services for "
                       "SSRF even if blind.",
    "ssrf_open_redirect": "An open redirect in the fetch chain lets an "
                          "attacker bounce the server's requests past "
                          "allowlist checks to internal targets.",
    "race_no_ratelimit": "An attacker can fire many requests in parallel "
                         "with nothing slowing them down - coupon, "
                         "balance and one-time-action limits can be "
                         "raced past.",
    "race_no_idempotency": "An attacker can replay or parallel-submit the "
                           "same action to get it applied many times - "
                           "double charges, double credits, double "
                           "redemptions.",
    "fuzz_param_anomaly": "This parameter behaves abnormally under fuzz "
                          "input - an attacker fuzzing the same way can "
                          "find the input that turns it into an injection "
                          "or a crash.",
}
IMPACT_BY_KEY.update({
    # -- auth / API ----------------------------------------------------------
    "idor_candidate": "An attacker can change the ID in the request and "
                      "try to read or modify other users' objects - the "
                      "classic account-data leak.",
    "idor_confirmed": "An attacker can pull other users' records simply "
                      "by changing an ID - confirmed working, no special "
                      "tools needed.",
    "idor_surface": "An attacker can enumerate object IDs in these "
                    "endpoints and probe each one for missing "
                    "object-level authorization.",
    "error_response_disclosure": "An attacker who is refused an object "
                                 "still receives its data inside the "
                                 "error response - the denial itself "
                                 "leaks the record.",
    "idor_error_leak_path": "An attacker can walk sequential object IDs "
                            "and harvest each denied object's data from "
                            "its error response - a full read of the "
                            "collection without ever passing the "
                            "authorization check.",
    "bola_candidate": "An attacker with any low-privilege account can "
                      "aim this endpoint at other users' object IDs and "
                      "read or change data that is not theirs.",
    "blogic_candidate": "An attacker can abuse this business flow "
                        "(skipping steps, replaying actions, negative "
                        "amounts) to get outcomes the app never intended "
                        "- free goods, credits or approvals.",
    "unauthenticated_api": "An attacker can call this API with no login "
                           "at all and get data or actions that should "
                           "sit behind authentication.",
    "endpoint_not_auth_enforced": "An attacker can use this endpoint "
                                  "without the authorization it is "
                                  "supposed to check - data and actions "
                                  "are effectively public.",
    "auth_required_endpoint": "This endpoint at least asks for auth - an "
                              "attacker still learns it exists and what "
                              "it protects, and will target its login "
                              "and token handling.",
    "jwt_alg_none": "An attacker can forge a token with no signature and "
                    "present themselves as any user, including admins, "
                    "if the server accepts alg=none.",
    "jwt_empty_sig": "An attacker can present unsigned tokens; any "
                     "endpoint trusting them hands over the account the "
                     "token names.",
    "jwt_weak_secret": "An attacker can crack the signing secret offline "
                       "and then mint valid tokens for any account - "
                       "full, persistent authentication bypass.",
    "jwt_weak": "The token setup is weak, so an attacker can tamper with "
                "claims (user id, role) and have the server accept the "
                "forgery.",
    "jwt_sensitive_payload": "Anyone holding this token can read the "
                             "sensitive data baked into it - tokens leak "
                             "via logs, URLs and browser storage.",
    "jwt_sensitive_claims": "Anyone holding this token can read the "
                            "sensitive claims inside it; tokens are "
                            "copied into logs and browser storage where "
                            "they leak.",
    "jwt_no_exp": "A stolen token never expires, so an attacker who gets "
                  "one keeps access forever until it is manually revoked.",
    "jwt_missing_exp": "A stolen token has no expiry, so one leak gives "
                       "an attacker permanent access.",
    "jwt_long_exp": "A stolen token stays valid for a very long time, "
                    "giving an attacker a wide window to abuse it.",
    "jwt_kid_suspicious": "The kid parameter looks injectable, so an "
                          "attacker may be able to point verification at "
                          "a key they control and forge tokens.",
    "jwt_localstorage": "Tokens in localStorage are readable by any "
                        "script that runs on the page, so one XSS hands "
                        "an attacker the full session token.",
    "jwt_sessionstorage": "Tokens in sessionStorage can be read by any "
                          "injected script, turning a minor XSS into "
                          "account takeover.",
    "jwt_claims": "The claims show an attacker exactly how identity and "
                  "roles are structured, which accounts to target and "
                  "what to forge if signing is weak.",
    "jwt_header": "The header shows an attacker the algorithm and key id "
                  "in use - the two facts needed to pick a forgery "
                  "strategy.",
    "graphql_introspection_enabled": "An attacker can download the entire "
                                     "API schema - every type, query and "
                                     "mutation - and shop for the ones "
                                     "missing authorization.",
    "graphql_introspection": "An attacker can download the entire API "
                             "schema and map every operation, including "
                             "ones the frontend never uses.",
    "graphql_schema_enum": "An attacker can enumerate the schema field "
                           "by field even without introspection, building "
                           "the same full API map more slowly.",
    "graphql_batching": "An attacker can batch many operations into one "
                        "request, multiplying brute-force speed against "
                        "logins and one-time codes.",
    "graphql_verbose_errors": "GraphQL errors leak field names, types and "
                              "internals, guiding an attacker to valid "
                              "queries and weak spots.",
    "graphiql_ui": "A public GraphiQL console gives an attacker an "
                   "interactive query workbench against the live API, "
                   "schema included.",
    "graphql_endpoint": "An attacker learns a GraphQL endpoint exists and "
                        "will probe it for introspection and "
                        "unauthenticated operations.",
    "graphql_types": "The type list shows an attacker what data the API "
                     "holds - users, payments, admin types - and which "
                     "to go after.",
    "openapi_paths": "An attacker gets the documented path list - the "
                     "complete attack surface, including admin and debug "
                     "routes the UI hides.",
    "api_docs": "Public API docs hand an attacker the full endpoint map "
                "with parameters, so they can skip discovery and go "
                "straight to testing authorization.",
    "hidden_api_endpoint": "An undocumented endpoint is still reachable - "
                           "attackers find these too, and hidden usually "
                           "means untested authorization.",
    "hidden_endpoint": "An attacker who finds this unlinked path reaches "
                       "functionality the site never meant to publish - "
                       "often with weaker checks than the public pages.",
    "hidden_path": "An attacker can open this unlinked path directly; "
                   "hidden admin and debug paths are a standard entry "
                   "point.",
    "debug_endpoint": "A debug endpoint in production often exposes "
                      "internals or test actions an attacker can use to "
                      "learn the system or trigger behavior directly.",
    "enterprise_admin": "An attacker who reaches this admin surface "
                        "without proper gating gets the keys to the "
                        "tenant - user management, data and settings.",
    "bank_admin_panel": "A bank admin panel exposed to the internet is a "
                        "prime target: one weak login stands between an "
                        "attacker and back-office functions.",
    "atm_exposed_mgmt": "An exposed ATM management interface lets an "
                        "attacker probe device controls that should only "
                        "exist on a private network.",
    "atm_mgmt_interface": "A management interface reachable here gives an "
                          "attacker a login surface for device-level "
                          "control of the ATM.",
    # -- headers / TLS-config style web misconfig -----------------------------
    "hsts_missing": "An attacker on the same network (cafe Wi-Fi, "
                    "compromised router) can downgrade visitors to plain "
                    "HTTP and read or modify their traffic, including "
                    "session cookies.",
    "hsts_bare_domain_downgrade": "The bare domain answers over plain "
                                  "HTTP, so an attacker can SSL-strip "
                                  "the first visit and intercept logins "
                                  "before HSTS ever applies.",
    "hsts_short": "The short HSTS lifetime means returning visitors are "
                  "only briefly protected - a network attacker gets "
                  "regular downgrade windows.",
    "hsts_short_max_age": "The short HSTS max-age leaves returning "
                          "visitors unprotected most of the time, so a "
                          "network attacker can downgrade them to HTTP.",
    "hsts_no_subdomains": "Subdomains are not covered by HSTS, so an "
                          "attacker can downgrade a subdomain visit and "
                          "intercept or alter that traffic.",
    "hsts_no_includesubdomains": "Subdomains skip HSTS protection, so an "
                                 "attacker can downgrade subdomain "
                                 "traffic and intercept it.",
    "hsts_no_preload": "Without preload, a browser's very first visit is "
                       "unprotected - a network attacker can intercept "
                       "that first connection.",
    "hsts_invalid_max_age": "A broken HSTS value is ignored by browsers, "
                            "so visitors get no downgrade protection at "
                            "all despite the header being present.",
    "fast_hsts_weak": "Weak HSTS means a network attacker can downgrade "
                      "visitors to plain HTTP and read or alter their "
                      "traffic, sessions included.",
    "csp_missing": "With no Content-Security-Policy, any injected script "
                   "runs unrestricted - one XSS becomes full session "
                   "theft and page control.",
    "csp_unsafe_inline": "The policy allows inline scripts, so an "
                         "attacker who finds any injection point can run "
                         "their JavaScript despite the CSP.",
    "csp_unsafe_eval": "The policy allows eval(), so injected strings can "
                       "be executed as code - most of the CSP's XSS "
                       "protection is gone.",
    "csp_wildcard": "A wildcard script source lets an attacker load their "
                    "script from any domain they control once they find "
                    "an injection point.",
    "csp_wildcard_script_src": "Wildcard script sources let an attacker "
                               "host the payload anywhere, defeating the "
                               "point of the allowlist.",
    "csp_data_uri": "Allowing data: script sources gives an attacker a "
                    "built-in payload carrier wherever injection exists.",
    "csp_data_script_src": "data: script sources let an attacker smuggle "
                           "executable payloads past the policy.",
    "xfo_missing": "Without frame protection, an attacker can embed this "
                   "site in their page and trick logged-in users into "
                   "clicking buttons that perform real actions "
                   "(clickjacking).",
    "clickjack_vulnerable": "An attacker can frame this page and trick "
                            "signed-in users into clicking hidden actions "
                            "- settings changes, transfers, deletes.",
    "clickjack": "An attacker can frame this page and trick signed-in "
                 "users into clicking hidden actions (clickjacking).",
    "clickjack_weak": "Framing protection is partial, so an attacker may "
                      "still embed the page on some origins and run "
                      "clickjacking against signed-in users.",
    "clickjack_csp_bypass": "The frame policy has a bypass, so an "
                            "attacker can still frame the page and "
                            "clickjack signed-in users.",
    "xcto_missing": "Without nosniff, an attacker who uploads or injects "
                    "a file can get victims' browsers to execute it as "
                    "script from this trusted domain.",
    "referrer_policy_missing": "URLs (which can contain tokens and reset "
                               "links) leak to third parties via the "
                               "Referer header when users click out.",
    "permissions_policy_missing": "Browser features like camera, mic and "
                                  "geolocation are not restricted, so "
                                  "injected or embedded content can "
                                  "request them on this origin.",
    "coep_missing": "Without Cross-Origin-Embedder-Policy the page "
                    "cannot isolate itself, weakening defenses against "
                    "cross-origin data leaks.",
    "coop_missing": "Without Cross-Origin-Opener-Policy, a malicious "
                    "page that opens this one can keep a window handle "
                    "and probe it (tab-nabbing / XS-Leak class).",
    "corp_missing": "Without Cross-Origin-Resource-Policy, other sites "
                    "can embed and read timing/size signals from this "
                    "origin's resources.",
    "cache_control_missing": "Sensitive pages can be stored by browsers "
                             "and shared caches, so the next user of a "
                             "shared machine or proxy may read them.",
    "missing_security_header": "Each missing security header removes a "
                               "browser protection, widening what an "
                               "attacker can do with any other bug they "
                               "find.",
    "fast_missing_headers": "Missing security headers strip browser "
                            "protections, so any other weakness an "
                            "attacker finds goes further.",
    "server_header": "The banner tells an attacker the exact server "
                     "software and version, so they can pick known "
                     "exploits instead of guessing.",
    "x_powered_by": "This header advertises the framework and version, "
                    "letting an attacker match the stack to known "
                    "vulnerabilities.",
    "powered_by_header": "This header advertises the framework and "
                         "version, letting an attacker match the stack "
                         "to known vulnerabilities.",
    "cookie_flags_missing": "Cookies without Secure/HttpOnly/SameSite "
                            "can be stolen by injected scripts, sent over "
                            "plain HTTP, or ridden by cross-site requests "
                            "- session hijack material.",
    "cookie_no_httponly": "Any script running on the page can read this "
                          "cookie - one XSS and an attacker owns the "
                          "session.",
    "cookie_no_secure": "This cookie travels over plain HTTP too, so a "
                        "network attacker can sniff it and reuse the "
                        "session.",
    "cookie_no_samesite": "Without SameSite, other sites can send this "
                          "cookie with cross-site requests - the setup "
                          "for CSRF attacks.",
    "cookie_host_prefix_violation": "The __Host- prefix is undermined, "
                                    "so a subdomain can set cookies that "
                                    "shadow the real session cookie.",
    "cookie_secure_prefix_violation": "The __Secure- prefix rules are "
                                      "broken, letting a weaker context "
                                      "plant cookies the browser treats "
                                      "as trusted.",
    "cookie_name_collision": "Duplicate cookie names let an attacker "
                             "(e.g. from a subdomain) shadow the "
                             "legitimate cookie and confuse session "
                             "handling.",
    "fast_cookie_flags": "Weak cookie flags mean sessions can be stolen "
                         "by scripts, sniffed on the network, or abused "
                         "cross-site.",
    "cors_misconfig": "A web page an attacker controls can read this "
                      "site's authenticated API responses from a victim's "
                      "browser, stealing their data cross-origin.",
    "cors_wildcard": "Any website can read responses from this API in a "
                     "visitor's browser - with credentials allowed, that "
                     "means cross-site data theft.",
    "cors_reflect": "The API reflects arbitrary origins, so an attacker's "
                    "site can make credentialed requests from a victim's "
                    "browser and read the results.",
    "cors_methods": "The allowed-methods list shows an attacker which "
                    "verbs (PUT, DELETE) the API accepts cross-origin "
                    "and may not check properly.",
    "dangerous_methods": "An attacker can use these HTTP methods "
                         "(PUT/DELETE/TRACE) to modify content or probe "
                         "the server in ways normal browsing never does.",
    "http_methods": "The method list tells an attacker which verbs the "
                    "server honors - writable methods are worth testing "
                    "for unauthorized changes.",
    "http_unusual_verbs": "Unusual verbs are often handled by code paths "
                          "with weaker checks - an attacker will test "
                          "them for bypasses.",
    "options_allow": "The Allow header hands an attacker the list of "
                     "methods to try on this resource.",
    "open_redirect": "An attacker can craft links on this trusted domain "
                     "that bounce victims to a phishing site - the "
                     "domain's reputation does the convincing.",
    "redirect_off_domain": "Redirects leaving the domain can be aimed by "
                           "an attacker to send users (and their trust) "
                           "to a lookalike site.",
    "redirect_chain_long": "Long redirect chains give an attacker more "
                           "hops to abuse - an open hop anywhere in the "
                           "chain can reroute victims.",
    "redirect_loop": "A redirect loop is mostly a reliability bug, but "
                     "attackers use broken redirect logic to mask "
                     "phishing hops.",
    "redirect_plaintext_first_hop": "The first hop is plaintext HTTP, so "
                                    "a network attacker can rewrite the "
                                    "redirect and send victims anywhere.",
    "sri_missing": "Without Subresource Integrity, a compromised CDN or "
                   "script host can serve altered JavaScript to every "
                   "visitor and nothing would notice.",
    "rate_limit_no_signals": "No visible rate limiting means an attacker "
                             "can brute-force logins, codes and coupons "
                             "at full speed.",
    "rate_limit_documented": "Documented limits tell an attacker exactly "
                             "how fast they may probe without tripping "
                             "anything - useful for staying just under "
                             "the wire.",
    # -- breach / leak intel ----------------------------------------------------
    "breach": "This address appears in a known breach, so an attacker "
              "already has its old passwords to try against this and "
              "every other service (credential stuffing).",
    "breach_account": "This account is in a breach corpus - an attacker "
                      "can pair it with its leaked password and walk "
                      "straight in where it was reused.",
    "breach_domain": "Domain addresses appear in breaches, giving an "
                     "attacker a ready list of staff accounts and their "
                     "old passwords to stuff against the login.",
    "comb_exposure": "This email/password pair circulates in combo "
                     "lists, so an attacker can try the exact pair "
                     "against the login with no guessing.",
    "dork": "This search result is publicly indexed - an attacker using "
            "the same dork finds the same exposed file, panel or "
            "document in seconds.",
    "google_dork": "This dork result is public: an attacker can pull the "
                   "same exposed content with one search query.",
    "keyleak_dork": "A public dork query surfaces this key material - an "
                    "attacker searching the same way gets the key too.",
    "github_hit": "This repository or file is public and matches a "
                  "sensitive search - an attacker browsing GitHub finds "
                  "the same code, secrets or internal details.",
    "github_secret_dork_hit": "A public GitHub search exposes this "
                              "secret-bearing file to anyone, including "
                              "attackers who scan for exactly this.",
    "github_secret_file": "This public file contains secret material - "
                          "an attacker can copy the key and use it "
                          "wherever it is valid.",
    "keyleak_github_hit": "This key appears in public GitHub results, so "
                          "an attacker already has it - rotation is the "
                          "only fix.",
    "keyleak_grepapp_hit": "This string is searchable in public code "
                           "search, so an attacker can find the key or "
                           "config with one query.",
    "keyleak_paste_hit": "This content sits on a public paste site where "
                         "attackers routinely harvest fresh credentials.",
    "paste_found": "This paste is public - attackers scrape paste sites "
                   "continuously for credentials and internal data.",
    "exposed_document": "This document is publicly reachable: an "
                        "attacker can read internal details, names or "
                        "data it contains without any account.",
    "exposed_file": "This file is publicly downloadable - source, config "
                    "or data an attacker was never meant to reach.",
    "exposed_config": "This configuration is public: an attacker reads "
                      "connection strings, keys and internal addresses "
                      "straight from it.",
    "exposed_database": "A database service is reachable - an attacker "
                        "can attempt direct connections and, with weak "
                        "or default credentials, read everything in it.",
    "exposed_asset": "This asset is exposed to the internet, giving an "
                     "attacker another service to fingerprint and attack.",
    "docker_exposed": "An exposed Docker API is effectively root on the "
                      "host: an attacker can start a privileged container "
                      "and own the machine.",
    "k8s_exposed": "An exposed Kubernetes API lets an attacker list pods "
                   "and secrets and schedule their own workloads - "
                   "cluster takeover.",
    "exposed_card_number": "A full card number is exposed: an attacker "
                           "can attempt purchases or sell the number - "
                           "and the business faces PCI fallout.",
    "card_full_record": "A complete card record is visible, enough for "
                        "an attacker to attempt card-not-present fraud "
                        "directly.",
})
IMPACT_BY_KEY.update({
    # -- DNS / email authentication ------------------------------------------
    "spf_missing": "With no SPF record, an attacker can send email that "
                   "claims to be from this domain and passes basic "
                   "checks - convincing phishing of customers and staff.",
    "spf_weak": "A permissive SPF policy lets an attacker send mail that "
                "soft-passes as this domain, making phishing far more "
                "believable.",
    "spf": "The SPF policy shows an attacker exactly which servers may "
           "send for the domain - and any weak include in it is a "
           "spoofing path.",
    "spf_record": "The SPF record maps the domain's mail infrastructure "
                  "for an attacker, and any permissive mechanism in it is "
                  "a spoofing path.",
    "spf_too_many_lookups": "An over-limit SPF record fails validation "
                            "entirely, so spoofed mail stops being "
                            "filtered as SPF would intend.",
    "dmarc_missing": "With no DMARC, spoofed mail from this domain is "
                     "never rejected by policy - an attacker can "
                     "impersonate the brand at will.",
    "dmarc_weak": "A monitor-only DMARC policy means spoofed mail is "
                  "still delivered - an attacker can impersonate the "
                  "domain and victims' mailboxes will accept it.",
    "dmarc": "The DMARC policy sets how spoofed mail is handled; "
             "anything short of reject leaves an impersonation window "
             "an attacker can use.",
    "dmarc_record": "The DMARC record shows how spoofed mail is treated; "
                    "a non-enforcing policy leaves the domain open to "
                    "impersonation.",
    "dkim_missing": "Unsigned mail cannot be verified, so receivers "
                    "cannot tell genuine mail from an attacker's forgery "
                    "by signature.",
    "dkim": "DKIM selectors show an attacker the domain's signing setup; "
            "weak or test keys, if present, undermine forgery detection.",
    "dkim_present": "DKIM is present; its value to an attacker is mostly "
                    "recon - knowing forged mail will be checked shapes "
                    "their phishing approach.",
    "mta_sts": "MTA-STS tells an attacker how strictly mail transport is "
               "protected - a permissive mode means interception is "
               "easier.",
    "bimi": "BIMI details are mostly recon for an attacker: they "
            "confirm the brand's mail setup and logo source for "
            "building lookalike phishing.",
    "email_spoofing_risk": "Weak mail authentication means an attacker "
                           "can send convincing email as this domain to "
                           "customers and staff.",
    "mx_missing": "No MX records mostly breaks legitimate mail; an "
                  "attacker gains little beyond knowing the domain does "
                  "not receive mail directly.",
    "mx_records": "MX records show an attacker which mail provider hosts "
                  "the domain - the exact login and phishing target for "
                  "staff mailboxes.",
    "caa_missing": "With no CAA record, any certificate authority can "
                   "issue for this domain, so an attacker who compromises "
                   "or abuses any CA can get a trusted cert for phishing.",
    "caa_policy": "The CAA policy shows an attacker which CAs may issue "
                  "- useful for picking the weakest path to a fraudulent "
                  "certificate.",
    "caa_forbids_issuance": "CAA forbids issuance; for an attacker this "
                            "is a dead end for fraudulent certificates, "
                            "but it also flags the domain as carefully "
                            "run.",
    "caa_no_issuewild": "Wildcard issuance is unrestricted by CAA, so an "
                        "attacker who can get any CA to issue a wildcard "
                        "cert gains a phishing-ready subdomain cert.",
    "caa_inherited": "The inherited CAA policy applies here; an attacker "
                     "reads from it which CAs could issue for this host.",
    "dnssec": "The DNSSEC status tells an attacker whether DNS answers "
              "can be forged - without it, cache poisoning can redirect "
              "the domain's traffic.",
    "zone_transfer": "A successful zone transfer hands an attacker the "
                     "complete DNS zone - every hostname, including "
                     "internal and staging systems, in one request.",
    "wildcard_dns": "Wildcard DNS means any invented subdomain "
                    "resolves, which an attacker can abuse for "
                    "credential-phishing hosts that look official.",
    "subdomain_takeover": "This subdomain points at a service nobody "
                          "claims anymore - an attacker can register it "
                          "and serve content as the real brand, cookies "
                          "and all.",
    "takeover_possible": "The dangling record suggests an attacker could "
                         "claim the underlying service and take the "
                         "subdomain over, inheriting its trust and "
                         "cookies.",
    "dead_asset": "A dead asset still referenced by the domain is a "
                  "takeover candidate - an attacker can often claim the "
                  "abandoned service behind it.",
    "orphan_asset": "Orphaned assets are unmaintained by definition - an "
                    "attacker targets them for old bugs and takeover.",
    "dns_lame_delegation": "A lame delegation breaks DNS reliability and "
                           "can let an attacker influence resolution for "
                           "the zone.",
    "dns_single_ns": "A single nameserver is a single point of failure "
                     "an attacker can flood to take the domain's "
                     "resolution offline.",
    "dns_missing_glue": "Missing glue records slow and can break "
                        "resolution - mostly a reliability opening an "
                        "attacker can amplify into an outage.",
    "dns_serial_mismatch": "Inconsistent zone data between nameservers "
                           "means some visitors may get stale answers an "
                           "attacker can exploit for confusion or "
                           "hijack of retired records.",
    "soa_expire_short": "A short SOA expire means secondaries drop the "
                        "zone quickly if the primary is attacked - an "
                        "amplification for DNS denial of service.",
    # -- TLS --------------------------------------------------------------------
    "tls_expired": "An expired cert trains users to click through "
                   "warnings and lets an attacker present a fake cert "
                   "with far less suspicion.",
    "tls_expiring": "A soon-to-expire cert pressures rushed renewals; if "
                    "it lapses, users become click-through targets for "
                    "an attacker's fake cert.",
    "tls_self_signed": "A self-signed cert cannot be verified, so users "
                       "must trust blindly - an attacker's fake cert "
                       "looks exactly the same.",
    "tls_weak_cipher": "Weak ciphers can be broken by a network "
                       "attacker, exposing the traffic the TLS was meant "
                       "to protect.",
    "tls_cipher": "The cipher list shows an attacker the weakest "
                  "negotiable option - that is the one they will force "
                  "in a downgrade.",
    "tls_weak_version": "Old TLS versions have known attacks; a network "
                        "attacker can force them and decrypt or tamper "
                        "with sessions.",
    "tls_deprecated_version": "The server still negotiates deprecated "
                              "TLS versions with known weaknesses - a "
                              "network attacker can force them and "
                              "decrypt or tamper with traffic.",
    "tls_no_forward_secrecy": "Without forward secrecy, one stolen "
                              "server key later decrypts every recorded "
                              "session - record now, read years from "
                              "now.",
    "tls_compression": "TLS compression enables CRIME-style attacks that "
                       "recover secrets like session cookies from "
                       "encrypted traffic byte by byte.",
    "tls_version": "The negotiated version tells an attacker which "
                   "protocol attacks are worth trying against this host.",
    "tls_note": "This TLS observation gives an attacker configuration "
                "detail for choosing downgrade or fingerprinting "
                "attacks.",
    "fast_tls": "The TLS summary shows an attacker protocol and cipher "
                "strength at a glance - and which downgrade to attempt.",
    "smtp_no_starttls": "Mail crosses to this server in plaintext, so a "
                        "network attacker can read messages and harvest "
                        "any credentials sent during delivery.",
    "smtp_cleartext_auth": "The server offers plaintext authentication, "
                           "so a network attacker can capture mailbox "
                           "passwords straight off the wire.",
    "smtp_starttls_broken": "Broken STARTTLS means mail silently falls "
                            "back to plaintext - an active attacker can "
                            "force that and read the mail.",
    "smtp_weak_tls": "Weak TLS on the mail server lets a network "
                     "attacker decrypt or tamper with messages in "
                     "transit.",
    # -- ports / services / versions ---------------------------------------------
    "port_open": "An open port is a reachable service an attacker can "
                 "fingerprint and attack directly - every open port is "
                 "a door to knock on.",
    "web_port_open": "This web port answers the internet, giving an "
                     "attacker another full HTTP surface to probe.",
    "web_ports_open": "Multiple web ports are exposed, multiplying the "
                      "HTTP surfaces an attacker can probe for weak apps.",
    "port_scan_clean": "No open ports were found from here - an "
                       "attacker scanning the same way sees the same "
                       "empty surface, which limits them to other "
                       "vectors.",
    "outdated_software": "Outdated software has public vulnerability "
                         "write-ups; an attacker matches the version to "
                         "known exploits instead of discovering new "
                         "ones.",
    "cve_match": "This version matches a published CVE - an attacker "
                 "can look up exactly what is wrong and whether exploit "
                 "code already exists.",
    "new_cve": "A fresh CVE against this stack gives an attacker a "
               "head start while patches lag - the window is the "
               "opportunity.",
    "tech_cve": "The fingerprinted technology has known CVEs; an "
                "attacker matches version to vulnerability directly.",
    "appliance_cve": "This edge appliance has a known CVE - edge devices "
                     "are favorite entry points because they sit on the "
                     "perimeter with high privilege.",
    "appliance_eol": "End-of-life appliances get no more patches, so "
                     "every future vulnerability found in them stays "
                     "open for attackers permanently.",
    "atm_cve": "A known CVE in ATM software or services gives an "
               "attacker a documented path into a cash-handling device.",
    "bank_cve": "A known CVE in the bank's stack gives an attacker a "
                "documented weakness to aim at financial systems.",
    "wp_user_enum": "An attacker can enumerate valid WordPress "
                    "usernames, then aim password attacks at real "
                    "accounts instead of guessing names too.",
    "ip_blocklisted": "A blocklisted IP signals the host may already be "
                      "compromised or abused; attackers also use the "
                      "listing to find neglected machines.",
    "hypervisor_exposed": "An exposed hypervisor interface is a direct "
                          "shot at every virtual machine on the host.",
    "websocket_open": "An open WebSocket endpoint gives an attacker a "
                      "live channel to probe for missing auth and "
                      "cross-site WebSocket hijacking.",
    "open_rpc_endpoint": "An open RPC endpoint lets an attacker call "
                         "node functions directly - including, on some "
                         "chains, wallet and admin methods.",
    "btc_blockbook_exposed": "A public Blockbook backend exposes a full "
                             "blockchain index API an attacker can "
                             "query for address and transaction intel.",
    "btc_esplora_exposed": "A public Esplora API exposes address and "
                           "transaction data an attacker can mine for "
                           "targets holding funds.",
    "bucket_public_list": "Anyone can list this bucket's contents, so an "
                          "attacker can inventory every file and pick "
                          "the valuable ones.",
    "bucket_exists_private": "The bucket exists but is private; an "
                             "attacker learns the name, which is the "
                             "first fact needed for targeted guessing "
                             "and phishing.",
    "s3_public_list": "Anyone can list this bucket, so an attacker can "
                      "inventory every stored file without any account.",
    "s3_public_read": "Anyone can download objects from this bucket - "
                      "an attacker reads whatever is stored there, "
                      "backups and uploads included.",
    "s3_public_write": "Anyone can write to this bucket, so an attacker "
                       "can plant malicious files under the brand's own "
                       "storage domain.",
    "cloud_bucket_open": "This bucket is publicly accessible - an "
                         "attacker can read (and sometimes write) "
                         "whatever the business stored in it.",
    "cloud_bucket_exists": "The bucket name is confirmed real, giving "
                           "an attacker a verified target for access "
                           "attempts and social engineering.",
    "censys_exposed_host": "This host is indexed with open services in "
                           "Censys, so an attacker finds it pre-scanned - "
                           "no noisy probing needed.",
    "shodan_crypto_port": "A crypto node port is indexed and exposed, "
                          "giving an attacker a reachable RPC surface "
                          "tied to funds.",
})
IMPACT_BY_KEY.update({
    # -- recon / inventory (honest: what it enables) -------------------------
    "subdomain": "Each known subdomain is another host an attacker can "
                 "probe - forgotten and staging subdomains are usually "
                 "the softest entry points.",
    "interesting_subdomain": "Names like dev, admin or vpn mark this as "
                             "a high-value host - exactly where an "
                             "attacker concentrates first.",
    "subdomain_brute": "Brute-forced subdomains extend the map well "
                       "beyond what is linked anywhere, exposing hosts "
                       "their owners assumed were unfindable.",
    "endpoint": "A discovered endpoint is a concrete URL an attacker "
                "can test for missing authentication and injection - "
                "the map is the work plan.",
    "param": "A known parameter is a named input an attacker can fuzz "
             "for injection and authorization flaws.",
    "parameter": "A known parameter is a named input an attacker can "
                 "fuzz for injection and authorization flaws.",
    "param_accepted": "The server accepts this parameter, so an "
                      "attacker has a live input to test for injection "
                      "and reflection.",
    "param_reflected": "Input is reflected in the response - an "
                       "attacker will test whether markup or script "
                       "survives, which is the XSS question.",
    "tech": "Knowing the exact stack lets an attacker skip generic "
            "probing and go straight to that technology's known "
            "vulnerabilities and default paths.",
    "tech_version": "An exact version number lets an attacker match "
                    "the stack against CVE lists one-to-one.",
    "framework_detected": "Knowing the framework tells an attacker its "
                          "default routes, debug behavior and known "
                          "weak spots.",
    "enterprise_software": "Enterprise software fingerprints are "
                           "high-value: these products have rich admin "
                           "surfaces and well-documented vulnerabilities.",
    "form_inventory": "Forms show an attacker exactly which inputs the "
                      "app trusts - login, upload and search forms are "
                      "the standard injection targets.",
    "interesting_form": "This form (login, upload, password reset) is "
                        "one an attacker will test first for injection "
                        "and workflow abuse.",
    "form_risky_method": "A sensitive form using GET puts submitted "
                         "data in URLs, logs and browser history where "
                         "an attacker can recover it.",
    "api_pattern": "The API's URL patterns reveal its resource model, "
                   "so an attacker can guess sibling endpoints and "
                   "object IDs systematically.",
    "api_map_entries": "A full API map lets an attacker plan "
                       "authorization tests across every route instead "
                       "of stumbling on them one at a time.",
    "backend_hint": "Hints about the backend stack narrow an attacker's "
                    "exploit choices to what actually runs here.",
    "robots_disallow": "robots.txt disallow entries are a curated list "
                       "of paths the owner considers sensitive - "
                       "attackers read it as a treasure map.",
    "robots_txt": "robots.txt shows an attacker which paths exist and "
                  "which ones the owner would rather hide.",
    "security_txt": "security.txt mainly helps defenders; for an "
                    "attacker it confirms the organization and its "
                    "security contact conventions.",
    "security_txt_missing": "No security contact is published; that "
                            "does not help an attacker directly, but "
                            "vulnerabilities stay unreported longer, "
                            "which quietly helps them.",
    "wayback_interesting_url": "Archived URLs resurface pages the site "
                               "took down - an attacker reads old "
                               "versions for removed-but-still-live "
                               "functionality and leaked data.",
    "archived_url": "Archived copies keep deleted content readable "
                    "forever, so anything once public stays available "
                    "to an attacker.",
    "exif_metadata": "Photo metadata can include GPS coordinates and "
                     "device details - an attacker learns where people "
                     "and assets physically are.",
    "email": "A harvested email address is a phishing and "
             "credential-stuffing target, and it anchors password-reset "
             "abuse.",
    "email_found": "Each found address gives an attacker a named person "
                   "to phish and a username to try against the login.",
    "harvested_emails": "A harvested address list is an attacker's "
                        "phishing roster and password-spray username "
                        "set in one file.",
    "username_found": "A confirmed username is half a login - an "
                      "attacker only needs the password, and will spray "
                      "common ones.",
    "username_candidates": "Candidate usernames let an attacker build a "
                           "spray list targeted at this organization's "
                           "naming pattern.",
    "social_account": "A linked social account gives an attacker a "
                      "channel to impersonate from, or to attack the "
                      "person behind the brand.",
    "phone_found": "A published phone number is a vishing and SIM-swap "
                   "target, and often doubles as an account identifier.",
    "favicon_hash": "The favicon hash lets an attacker search the "
                    "internet for every other server running the same "
                    "product, including forgotten instances of this "
                    "one.",
    "favicon_mmh3": "The favicon hash lets an attacker find every "
                    "server sharing this product's favicon across "
                    "scanning databases.",
    "crawl_summary": "The crawl map shows an attacker the site's "
                     "structure and where the interesting pages cluster.",
    "sitemap": "The sitemap is a complete index of pages an attacker "
               "should review - including ones not linked from the "
               "homepage.",
    "sitemap_interesting": "The sitemap itself flags interesting "
                           "pages, saving an attacker the trouble of "
                           "ranking targets.",
    "screenshot_captured": "A screenshot confirms the service is live "
                           "and shows an attacker exactly what the login "
                           "or app looks like for building a clone.",
    "open_directory": "An open directory listing lets an attacker "
                      "browse every file in it - backups, uploads and "
                      "configs included.",
    "dir_brute_hit": "This path exists and answers - brute-force "
                     "discovery means the path is not secret from "
                     "attackers either.",
    "discovered_path": "A discovered path is a reachable location an "
                       "attacker can probe for weak access control.",
    "unlinked_path": "Unlinked paths are still reachable; an attacker "
                     "with a wordlist finds the same paths and whatever "
                     "protection they lack.",
    "error_debug_mode": "Debug mode leaks stack traces, settings and "
                        "sometimes request data to anyone who triggers "
                        "an error.",
    "error_stack_trace": "Stack traces hand an attacker file paths, "
                         "framework versions and code structure to aim "
                         "the next attack precisely.",
    "error_pages": "Verbose error pages leak internal details an "
                   "attacker uses to fingerprint and target the stack.",
    "endpoint_error_leak": "Error responses from this endpoint leak "
                           "internals an attacker can use to refine "
                           "injection and auth attacks.",
    "debug_django_toolbar": "The Django debug toolbar exposes queries, "
                            "settings and internals to anyone who can "
                            "see it - a guided tour for an attacker.",
    "django_debug": "Django debug output exposes settings, SQL and "
                    "paths to whoever triggers it.",
    "django_traceback": "Tracebacks reveal code layout and library "
                        "versions an attacker uses to pick exploits.",
    "apache_server_status": "server-status shows an attacker live "
                            "requests, client IPs and internal URLs "
                            "hitting the server right now.",
    "server_status_exposed": "The status page leaks live request "
                             "details and worker state an attacker can "
                             "use to find hidden URLs and active "
                             "sessions.",
    "spring_actuator_env": "The actuator env endpoint discloses "
                           "configuration and secrets in JSON to anyone "
                           "who asks.",
    "actuator_env_exposed": "An exposed actuator env endpoint hands an "
                            "attacker configuration values, often "
                            "including credentials, in plain JSON.",
    "mixed_content": "Subresources loaded over HTTP can be swapped by "
                     "a network attacker, undermining the HTTPS page "
                     "they ride on.",
    "mixed_content_active": "Active content over HTTP (scripts) can be "
                            "replaced by a network attacker - full page "
                            "control despite the HTTPS address bar.",
    "mixed_content_passive": "Passive content over HTTP leaks which "
                             "assets load and can be swapped for "
                             "tracking or deception.",
    "http_trace_enabled": "TRACE echoes requests back, which "
                           "historically lets injected scripts read "
                           "HttpOnly cookies (cross-site tracing).",
    "http1_only": "HTTP/1.0-only behavior hints at an old or minimal "
                  "stack - an attacker adjusts expectations toward "
                  "legacy weaknesses.",
    "ipv6_no_aaaa": "No IPv6 presence limits an attacker's options "
                    "here; the finding mainly matters for parity gaps "
                    "when IPv6 is added later, unmonitored.",
    "ipv6_broken": "Broken IPv6 handling can split monitoring from "
                   "traffic - an attacker prefers paths the defenders "
                   "cannot see.",
    # -- mobile -------------------------------------------------------------
    "binex_dangerous_perms": "Dangerous permissions mean a malicious or "
                             "compromised build of this app can read "
                             "messages, location or files well beyond "
                             "its job.",
    "binex_exported": "Exported components can be invoked by any other "
                      "app on the device - an attacker's app can drive "
                      "this app's internals directly.",
    "binex_secrets": "Secrets compiled into the binary are public to "
                     "anyone who downloads the app - an attacker "
                     "extracts and uses them.",
    "binex_hardcoded_urls": "Hardcoded URLs reveal internal and staging "
                            "endpoints an attacker can attack directly, "
                            "bypassing the app's normal discovery.",
    "binex_hardcoded_ips": "Hardcoded IPs point an attacker at "
                           "infrastructure that may sit outside the "
                           "usual monitoring and WAF coverage.",
    "binex_deeplinks": "Deep link schemes can be invoked by web pages "
                       "and other apps - an attacker can drive the app "
                       "into privileged flows.",
    "deep_link_scheme": "A custom scheme lets any web page or app hand "
                        "the app attacker-chosen links, reaching flows "
                        "that assume trusted input.",
    "apk_url": "A directly downloadable APK can be unpacked and "
               "reverse-engineered by an attacker at leisure - secrets, "
               "endpoints and logic included.",
    # -- web3 / financial -----------------------------------------------------
    "contract_unverified": "Unverified contract code cannot be audited "
                           "by users, so an attacker (or a malicious "
                           "operator) can hide behavior the bytecode "
                           "conceals.",
    "defi_unverified": "Unverified DeFi code means nobody outside can "
                       "check for backdoors - an attacker studies the "
                       "bytecode asymmetries users cannot see.",
    "contract_risk_pattern": "This code pattern is one attackers "
                             "actively scan for - it is a known shape "
                             "of exploitable or drainable contracts.",
    "contract_audit_clean": "No known bad pattern matched; an attacker "
                            "gains nothing specific here beyond knowing "
                            "the contract passed these checks.",
    "rugpull_indicator": "Rug indicators tell an attacker the token is "
                         "already suspect - but for victims the impact "
                         "is funds that can be drained or frozen by the "
                         "operator.",
    "meme_unverified": "An unverified meme token contract can hide mint "
                       "and blacklist functions - buyers bear the "
                       "drain risk.",
    "token_approval": "Standing token approvals let an attacker who "
                      "compromises the spender contract (or phishes a "
                      "signature) drain approved balances.",
    "bank_pci_flag": "A PCI-relevant weakness around payments is where "
                     "an attacker aims for card data - and where the "
                     "business's fines land.",
    "bank_login_posture": "The login's posture (MFA, lockout, "
                          "enumeration) tells an attacker exactly how "
                          "hard credential attacks will be here.",
    "bank_missing_header": "A missing security header on a banking "
                           "surface removes a browser protection an "
                           "attacker can combine with any injection "
                           "they find.",
    "giftcard_endpoint": "A gift-card endpoint is a direct money "
                         "surface - attackers probe it for balance "
                         "checks and code enumeration.",
    "billing_endpoint": "A billing endpoint handles payment data and "
                        "state - attackers target it for skimming, "
                        "tampering and subscription abuse.",
    "payment_processor": "Knowing the payment processor tells an "
                         "attacker which integration (and which known "
                         "integration mistakes) to test.",
    "exposed_aws_access_key": "A live AWS access key can hand an "
                              "attacker the cloud account: read "
                              "storage, start resources, pivot "
                              "everywhere the key reaches.",
    "exposed_github_token": "A live GitHub token lets an attacker read "
                            "private code and, with write scope, plant "
                            "backdoored commits.",
    "exposed_stripe_key": "A live Stripe key lets an attacker read "
                          "customer and payment data or move money "
                          "within the account's permissions.",
    "wallet_private_key": "A private key is the wallet: an attacker "
                          "who copies it owns the funds outright.",
    "poi": "A point of interest on the map is context, not a weakness - "
           "its value to an attacker is knowing a physical location "
           "worth targeting.",
})

# ---------------------------------------------------------------------------
# 2. Key prefix families (checked in order; first match wins).
# ---------------------------------------------------------------------------
IMPACT_PREFIXES: List[Tuple[str, str]] = [
    ("exposed_", "An attacker can reach this exposed item directly - "
                 "whatever it contains (keys, codes, data) should be "
                 "treated as already public."),
    ("sqli_", "An attacker can inject SQL here and read or change "
              "database contents."),
    ("jwt_", "Token weaknesses let an attacker forge or abuse session "
             "tokens and impersonate users."),
    ("graphql_", "GraphQL exposure gives an attacker a self-documenting "
                 "API to query for data and missing authorization."),
    ("tls_", "This TLS detail tells an attacker how the encryption can "
             "be weakened, downgraded or fingerprinted."),
    ("spf_", "This SPF weakness lets an attacker send mail that passes "
             "as the domain more easily."),
    ("dmarc_", "This DMARC weakness leaves the domain easier to "
               "impersonate in phishing mail."),
    ("cors_", "This CORS weakness lets an attacker's website read "
              "responses from this site in a victim's browser."),
    ("hsts_", "This HSTS weakness lets a network attacker downgrade "
              "visitors toward plain HTTP and intercept traffic."),
    ("csp_", "This CSP weakness blunts the browser's XSS defenses, so "
             "an injection an attacker finds goes further."),
    ("cookie_", "This cookie weakness helps an attacker steal, plant or "
                "ride a victim's session."),
    ("sourcemap_", "Source maps let an attacker reconstruct the "
                   "original source code and audit it offline for "
                   "secrets and hidden routes."),
    ("fast_", "This quick-check result points an attacker at the same "
              "weakness the full check would confirm."),
    ("breachwatch_", "Breach exposure means an attacker likely already "
                     "has these credentials from public dumps."),
    ("breach", "Breach exposure means an attacker likely already has "
               "these credentials from public dumps."),
    ("keyleak_", "This key material is findable in public sources, so "
                 "an attacker can obtain and use it."),
    ("github_", "Public GitHub exposure means an attacker can read the "
                "same code, files or secrets with a simple search."),
    ("s3_", "This storage finding gives an attacker a path into files "
            "the business stored in the bucket."),
    ("cloud_bucket", "This bucket finding gives an attacker a path "
                     "into stored files."),
    ("wallet_", "Wallet findings put funds at stake: an attacker uses "
                "them to reach or drain the wallet."),
    ("cred_", "Exposed credential material lets an attacker log in "
              "directly or crack the password offline."),
    ("bank_", "On a banking surface, an attacker aims this finding at "
              "accounts, payments or the login itself."),
    ("atm_", "On ATM infrastructure, an attacker aims this finding at "
             "the device, its management plane or its cash functions."),
    ("apk_", "App-package findings let an attacker reverse the mobile "
             "app and extract what is inside it."),
    ("binex_", "Binary-analysis findings show an attacker what the "
               "compiled app exposes or embeds."),
    ("defi_", "DeFi findings point an attacker at contract behavior "
              "that can move or trap funds."),
    ("contract_", "Contract findings point an attacker at on-chain "
                  "behavior that can be abused or drained."),
    ("meme_", "Token findings signal drain or trap risk for holders."),
    ("proto_pollution_", "Prototype pollution lets an attacker flip "
                         "application-wide defaults and chain into "
                         "bigger compromise."),
    ("smuggling_", "Request smuggling lets an attacker poison the "
                   "shared connection queue and hijack other users' "
                   "requests."),
    ("spring_actuator_", "Exposed Spring actuator endpoints leak "
                         "environment, config and sometimes control "
                         "over the running app."),
    ("whois_", "WHOIS/RDAP data gives an attacker registrant names, "
               "contacts and dates for social engineering and "
               "infrastructure mapping."),
    ("wayback_", "Archived data stays public forever - an attacker "
                 "mines it for removed pages, old endpoints and leaked "
                 "content."),
    ("redirect_", "Redirect behavior an attacker can influence sends "
                  "victims (and their trust in the domain) elsewhere."),
    ("xsleak_", "Cross-site leak oracles let an attacker's page infer "
                "a logged-in victim's data from timing and load "
                "behavior."),
    ("jwt", "Token weaknesses let an attacker forge or abuse session "
            "tokens and impersonate users."),
]

# ---------------------------------------------------------------------------
# 3. Per-plugin fallback (used when the key itself has no entry).
# ---------------------------------------------------------------------------
IMPACT_BY_PLUGIN: Dict[str, str] = {
    "dns": "DNS records map the infrastructure for an attacker - hosts, "
           "mail providers and forgotten services to target.",
    "tls": "TLS details show an attacker the encryption posture and "
           "which downgrade or interception attempts are worth trying.",
    "headers": "Header observations show an attacker which browser "
               "protections are missing and safe to ignore.",
    "webtech": "Technology fingerprints let an attacker pick known "
               "exploits for the exact stack instead of probing "
               "blindly.",
    "subdomains": "Every enumerated subdomain is another host for an "
                  "attacker to probe, and the obscure ones are usually "
                  "the least patched.",
    "ports": "Open ports are directly reachable services an attacker "
             "can fingerprint and attack.",
    "port_scan": "Open ports are directly reachable services an "
                 "attacker can fingerprint and attack.",
    "port_audit": "Port and banner data gives an attacker reachable "
                  "services plus versions to match against exploits.",
    "banners": "Service banners hand an attacker exact versions for "
               "exploit matching.",
    "cves": "A CVE match gives an attacker a documented vulnerability "
            "and, often, public exploit code.",
    "secrets": "Anything the secrets scan surfaces should be treated "
               "as already known to an attacker who looks in the same "
               "place.",
    "gitleaks_scan": "Patterns matched here are exactly what "
                     "attackers' scanners look for - treat matched "
                     "secrets as public.",
    "leaks": "Leak and breach data arms an attacker with credentials "
             "and personal details for stuffing and phishing.",
    "sqli": "SQL injection findings give an attacker a path into the "
            "database behind the application.",
    "xss": "Cross-site scripting findings let an attacker run script "
           "in victims' browsers on this domain.",
    "ssrf": "SSRF findings let an attacker make the server call "
            "internal addresses only it can reach.",
    "idor": "Object-reference findings let an attacker reach other "
            "users' records by changing identifiers.",
    "jwt": "Token findings let an attacker forge or hijack sessions "
           "when the checks are weak.",
    "jwt_audit": "Token audit findings show an attacker how sessions "
                 "can be forged, replayed or read.",
    "cors": "CORS findings let an attacker's site read this site's "
            "responses from a victim's browser.",
    "graphql": "GraphQL findings expose a self-describing API an "
               "attacker can query for data and weak authorization.",
    "apidiscover": "Discovered API surface is an attacker's work plan: "
                   "every endpoint is a test target.",
    "takeover": "Dangling DNS gives an attacker a claimable subdomain "
                "that inherits the brand's trust and cookies.",
    "cloud_buckets": "Bucket findings give an attacker paths into "
                     "stored files and backups.",
    "s3": "Bucket findings give an attacker paths into stored files "
          "and backups.",
    "docker": "Container exposure is effectively host access for an "
              "attacker who reaches the API.",
    "k8s": "Kubernetes exposure lets an attacker reach workloads and "
           "secrets across the cluster.",
    "misconfig": "Misconfiguration findings are pre-found weaknesses - "
                 "an attacker skips discovery and goes straight to "
                 "the exposed thing.",
    "misconfig_sweep": "Misconfiguration findings are pre-found "
                       "weaknesses an attacker can use directly.",
    "exposed_debug": "Debug surfaces leak internals an attacker uses "
                     "to aim the real attack.",
    "error_pages": "Verbose errors leak paths, versions and internals "
                   "an attacker uses to aim the next step.",
    "waf": "WAF posture tells an attacker how much filtering stands "
           "between them and the application.",
    "fastmode": "Fast-mode results point an attacker at the same "
                "issues with a fraction of the effort.",
    "hunters": "Hunter findings extend the known attack surface an "
               "attacker could assemble from the same public signals.",
}

# ---------------------------------------------------------------------------
# 4. Category fallbacks + generic.
# ---------------------------------------------------------------------------
IMPACT_BY_CATEGORY: Dict[str, str] = {
    "dns": "This DNS observation helps an attacker map the "
           "infrastructure and choose which hosts and mail paths to "
           "target.",
    "web": "This web observation gives an attacker a concrete weakness "
           "or detail to work into an attack on the site.",
    "api": "This API observation gives an attacker a concrete endpoint "
           "or behavior to test for missing authorization.",
    "mobile": "This mobile observation helps an attacker reverse the "
              "app or abuse what it exposes on the device.",
    "identity": "This identity exposure gives an attacker accounts or "
                "people to impersonate, phish or credential-stuff.",
    "infra": "This infrastructure observation gives an attacker a "
             "reachable service or configuration weakness to probe.",
    "leak": "This exposure should be treated as public: an attacker "
            "can read or use what was found without any access of "
            "their own.",
    "graph": "This connection shows an attacker how assets relate, "
             "which is how they plan pivoting from one weak asset "
             "to the next.",
    "location": "This location detail is context an attacker can use "
                "to target a real-world place or asset.",
}

GENERIC = ("This is reconnaissance data: it does not compromise "
           "anything by itself, but it sharpens the map an attacker "
           "uses to pick the weakest next target.")


def attacker_impact_for(key: str = "", plugin_id: str = "",
                        category: str = "") -> str:
    """Resolve the attacker-impact statement for a finding."""
    k = (key or "").strip()
    if k in IMPACT_BY_KEY:
        return IMPACT_BY_KEY[k]
    for prefix, text in IMPACT_PREFIXES:
        if k.startswith(prefix):
            return text
    if plugin_id and plugin_id in IMPACT_BY_PLUGIN:
        return IMPACT_BY_PLUGIN[plugin_id]
    if category and category in IMPACT_BY_CATEGORY:
        return IMPACT_BY_CATEGORY[category]
    return GENERIC


# ---------------------------------------------------------------------------
# Hash identification + purpose.
#
# When a finding carries a hash, the finding must say WHAT the hash is
# (algorithm, from its format) and WHAT IT IS FOR (purpose, from the
# finding's context). Identification only - nothing here cracks,
# reverses or looks anything up. Format alone cannot always separate
# algorithms (a 32-hex string is the MD5/NTLM shape), so ambiguous
# formats are labeled honestly as such.
# ---------------------------------------------------------------------------
_HASH_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    ("bcrypt", re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")),
    ("Argon2", re.compile(r"\$argon2(?:id|i|d)\$[^\s$]+\$[^\s$]+\$[A-Za-z0-9+/=]+")),
    ("SHA-512 crypt ($6$)", re.compile(r"\$6\$[^\s$]{1,16}\$[./A-Za-z0-9]{86}")),
    ("SHA-256 crypt ($5$)", re.compile(r"\$5\$[^\s$]{1,16}\$[./A-Za-z0-9]{43}")),
    ("SHA-512", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{128}(?![a-fA-F0-9])")),
    ("SHA-256", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])")),
    ("SHA-224", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{56}(?![a-fA-F0-9])")),
    ("SHA-1", re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])")),
    ("MD5 / NTLM (32-hex, same format)", re.compile(
        r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])")),
    ("MySQL old password hash (16 hex)", re.compile(
        r"(?<![a-fA-F0-9])[a-fA-F0-9]{16}(?![a-fA-F0-9])")),
]

_PURPOSE_PASSWORD = (
    "password storage: this is the hashed form of a password. The hash "
    "itself is not the password, but anyone who cracks it offline owns "
    "the account it protects")
_PURPOSE_PASSWORD_CRACKED = (
    "password storage, and this one is already cracked in public "
    "databases: the plain password is effectively known, so the "
    "account must be treated as compromised wherever it was reused")
_PURPOSE_PAGE_CONTENT = (
    "in this context it sits in public page or script content, where "
    "hashes are usually password hashes, file integrity checksums or "
    "token fingerprints left in code - every visitor can read the "
    "value, so if it is a password hash it can be attacked offline")
_PURPOSE_FAVICON = (
    "a website fingerprint: the MurmurHash3 of the site's favicon "
    "file, used to find other servers running the same product (and "
    "forgotten copies of this one) in internet scan databases. It is "
    "not a password or a secret")
_PURPOSE_CHECKSUM = (
    "a file integrity checksum: it fingerprints a file's contents so "
    "changes can be detected. It is not a secret, but it tells an "
    "attacker exactly which file version is present")
_PURPOSE_SESSION = (
    "a session identifier: whoever presents this value is treated as "
    "the logged-in user, so a copy of it is a copy of the session")
_PURPOSE_TOKEN = (
    "an API token or key fingerprint: material tied to an API "
    "credential, usable to identify (and, if it is the credential "
    "itself, to use) the account's API access")
_PURPOSE_GENERIC = (
    "credential or integrity material whose exact role is not labeled "
    "in the finding; treat the value as sensitive, because hashes of "
    "passwords and tokens are attacked offline once exposed")


def identify_hash(text: str) -> Optional[str]:
    """Return the algorithm label for a hash-looking string, or None."""
    if not text:
        return None
    for label, pat in _HASH_PATTERNS:
        if pat.search(text):
            return label
    return None


def _hash_purpose(key: str, plugin_id: str, category: str,
                  evidence: Dict) -> str:
    k = (key or "").lower()
    blob = " ".join(str(evidence.get(f) or "") for f in
                    ("pattern", "field", "label", "name", "note")).lower()
    if k in ("hash_cracked_public",) or "cracked" in blob:
        return _PURPOSE_PASSWORD_CRACKED
    if "checksum" in k or "checksum" in blob or "integrity" in blob:
        return _PURPOSE_CHECKSUM
    if "session" in k or "session" in blob:
        return _PURPOSE_SESSION
    if "token" in k or "api_key" in k or "token" in blob:
        return _PURPOSE_TOKEN
    if plugin_id in ("hashcracker", "credential_strength") \
            or k in ("hash_analyzed", "plaintext_password"):
        return _PURPOSE_PASSWORD
    if plugin_id == "hashid" or k == "hash_identified":
        return _PURPOSE_PAGE_CONTENT
    if category in ("leak", "identity"):
        return _PURPOSE_PASSWORD
    return _PURPOSE_GENERIC


def hash_annotation(key: str = "", plugin_id: str = "",
                    category: str = "", value: str = "",
                    evidence: Optional[Dict] = None) -> Optional[Dict]:
    """Identify a finding's hash (type + purpose), or None if no hash.

    Trusts an algorithm label the producing plugin already stamped in
    evidence.hash_type; otherwise identifies from the hash's format in
    the finding value / evidence match. Never cracks anything.
    """
    ev = evidence if isinstance(evidence, dict) else {}
    k = (key or "").strip()
    if k in ("favicon_mmh3", "favicon_hash"):
        return {"hash_type": "MurmurHash3 (favicon fingerprint)",
                "hash_purpose": _PURPOSE_FAVICON}
    htype = str(ev.get("hash_type") or "").strip()
    if not htype:
        haystacks = [value or "", str(ev.get("match") or ""),
                     str(ev.get("value") or "")]
        for hay in haystacks:
            htype = identify_hash(hay) or ""
            if htype:
                break
    if not htype:
        return None
    return {"hash_type": htype,
            "hash_purpose": _hash_purpose(k, plugin_id or "",
                                           category or "", ev)}


def apply_hash_annotation(ev: Dict, key: str = "", plugin_id: str = "",
                          category: str = "", value: str = "") -> Dict:
    """Stamp hash_type/hash_purpose on an evidence dict and fold the
    identification into attacker_impact. Idempotent: a finding already
    carrying hash_type is left alone. Returns the evidence dict."""
    if not isinstance(ev, dict) or ev.get("hash_type") and \
            ev.get("hash_purpose"):
        return ev
    ann = hash_annotation(key=key, plugin_id=plugin_id,
                          category=category, value=value, evidence=ev)
    if not ann:
        return ev
    ev.setdefault("hash_type", ann["hash_type"])
    ev["hash_purpose"] = ann["hash_purpose"]
    sentence = (f" Hash identified: {ann['hash_type']}. "
                f"What it is for: {ann['hash_purpose']}.")
    impact = str(ev.get("attacker_impact") or "")
    if "Hash identified:" not in impact:
        ev["attacker_impact"] = (impact + sentence).strip()
    return ev


def annotate_attacker_impact(rows: List[Dict]) -> List[Dict]:
    """Stamp finding dicts with a top-level ``attacker_impact``.

    Mirrors prioritizer.annotate_impact: read-time, best-effort, never
    raises, and respects text already stamped at creation time (kept
    in evidence by base.Plugin._f). Rows are dicts as produced by
    reporting.findings_dump.
    """
    for row in rows:
        try:
            if not isinstance(row, dict):
                continue
            ev = row.get("evidence")
            existing = ""
            if isinstance(ev, dict):
                existing = str(ev.get("attacker_impact") or "")
            if not existing:
                existing = attacker_impact_for(
                    key=str(row.get("key") or ""),
                    plugin_id=str(row.get("plugin") or ""),
                    category=str(row.get("category") or ""))
                if isinstance(ev, dict):
                    ev["attacker_impact"] = existing
            row["attacker_impact"] = existing
            # Hash findings also carry their identification + purpose,
            # backfilled the same way (creation time: Plugin._f).
            if isinstance(ev, dict):
                apply_hash_annotation(
                    ev, key=str(row.get("key") or ""),
                    plugin_id=str(row.get("plugin") or ""),
                    category=str(row.get("category") or ""),
                    value=str(row.get("value") or ""))
                row["attacker_impact"] = str(
                    ev.get("attacker_impact") or existing)
        except Exception:
            continue
    return rows
