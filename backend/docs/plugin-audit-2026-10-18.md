# ReconAnything plugin audit - 93 plugins

| plugin | label | live example.com | offline | active | verdict | notes |
|---|---|---|---|---|---|---|
| apidiscover | API Discovery | timeout/0 | ok/0 | timeout/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| artifacts | Exposed Artifacts | timeout/0 | ok/0 | timeout/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| asn_scan | ASN + Infra Map | ok/2 | ok/2 | ok/2 | WORKING | findings: live=2 offline=2 active=2 e.g. target_ips,web_ports_open |
| atm | ATM Security Assessment | ok/0 | ok/0 | ok/0 | QUIET | source_type-gated (atm/bank runs only) |
| auth | Auth Weakness Check | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| auth_surface | Auth Surface Map | timeout/0 | ok/0 | timeout/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| backup | Backup File Sweeper | timeout/0 | ok/0 | timeout/0 | BROKEN->FIXED | hung past 180s timeout (sequential 227-path sweep) -> concurrent |
| bank | Bank Security Assessment | ok/0 | ok/0 | ok/0 | QUIET | source_type-gated (atm/bank runs only) |
| banners | Banner Grabber | ok/1 | ok/1 | ok/5 | WORKING | findings: live=1 offline=1 active=5 e.g. banner_note |
| blogic | Business Logic Scout | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| bola | BOLA API Tester | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| bounty | Bug Bounty Checklist | timeout/0 | ok/1 | timeout/0 | WORKING | findings: live=0 offline=1 active=0 e.g. bounty_note |
| bridge | Bridge Security Scout | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| cards | Exposed Card Numbers | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| clickjack | Clickjack Tester | ok/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| cloud | Cloud Misconfig Scout | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| cloud_buckets | Cloud Bucket Probe | timeout/0 | ok/0 | timeout/0 | BROKEN->FIXED | hung past 90s timeout (sequential 33 checks) -> concurrent |
| cmdi | Command Injection | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| connections | Connection Mapper | ok/1 | ok/1 | ok/1 | WORKING | findings: live=1 offline=1 active=1 e.g. connection_summary |
| cors | CORS Tester | timeout/0 | ok/1 | ok/1 | WORKING | findings: live=0 offline=1 active=1 e.g. cors_ok |
| crawler | Site Crawler | timeout/0 | ok/1 | ok/1 | WORKING | findings: live=0 offline=1 active=1 e.g. crawl_summary |
| credential_strength | Credential Strength | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| creds | Hardcoded Credentials | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| crypto | Crypto Address Finder | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| cryptoconfig | Crypto RPC Checker | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| cves | CVE Matcher | ok/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| db | Exposed Databases | ok/0 | ok/0 | ok/8 | WORKING | findings: live=0 offline=0 active=8 |
| deepcrawl | Deep Source Analyzer | timeout/0 | ok/1 | ok/1 | WORKING | findings: live=0 offline=1 active=1 e.g. crawl_summary |
| defi | DeFi Protocol Scout | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| dns | DNS Records | ok/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| docker | Docker Exposure | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| dorks | Google Dorks | ok/14 | ok/14 | ok/14 | WORKING | findings: live=14 offline=14 active=14 e.g. google_dork |
| email_breach | Email Breach Exposure | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| email_exposure | Exposed Credentials | timeout/0 | ok/1 | ok/1 | WORKING | findings: live=0 offline=1 active=1 e.g. github_note |
| email_infra | Email Security Posture | ok/5 | ok/5 | ok/5 | WORKING | findings: live=5 offline=5 active=5 e.g. dkim_missing,dmarc_missing,email_spoofing_risk |
| emails | Email Harvester | timeout/0 | ok/0 | timeout/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| enterprise | Enterprise Software Scout | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| exif | Image EXIF Extractor | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| favicon_hash | Favicon Hasher | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| financial | Financial Footprint | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| fingerprint | Deep Tech Fingerprinter | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| giftcards | Exposed Gift Card Codes | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| giftinfra | Gift Card Infrastructure Map | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| git | Exposed .git Check | ok/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| github | GitHub Dorker | ok/5 | ok/5 | ok/5 | WORKING | findings: live=5 offline=5 active=5 e.g. github_dork |
| github_dorking | GitHub Secret Dorks | skipped-key/0 | skipped-key/0 | skipped-key/0 | QUIET | needs github_token key; skips cleanly without it |
| hashid | Hash Identifier | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| headers | Security Headers | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| hiddenpaths | Hidden Endpoint Finder | ok/0 | ok/0 | timeout/0 | QUIET | active-mode prober; silent in passive by design |
| htmli | HTML Injection | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| hypervisor | Hypervisor Scout | timeout/0 | ok/0 | timeout/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| idor | IDOR Pattern Finder | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| infodisclosure | Info Disclosure Probe | ok/0 | ok/0 | timeout/0 | QUIET | active-mode prober; silent in passive by design |
| iot | IoT Device Scout | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| jsminer | JS Bundle Miner | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| k8s | Kubernetes Misconfig | timeout/0 | ok/0 | timeout/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| keyleak | Key Leak Checker | ok/2 | ok/2 | ok/2 | WORKING | findings: live=2 offline=2 active=2 e.g. keyleak_no_identifiers,keyleak_scope |
| ldapi | LDAP Injection | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| leaks | Leaks + Identity | ok/9 | ok/9 | ok/9 | WORKING | findings: live=9 offline=9 active=9 e.g. dork,github_note |
| logici | API Logic Injection | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| mobile | Mobile App Analysis | n/a/0 | n/a/0 | n/a/0 | BROKEN->FIXED | unreachable: classifier routed store URLs to 'url' type -> reordered |
| nft | NFT Contract Scout | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| nosqli | NoSQL Injection | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| opendir | Open Directories | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| pastes | Paste Search | ok/3 | ok/3 | ok/3 | WORKING | findings: live=3 offline=3 active=3 e.g. paste_dork |
| phones | Phone Lookup | n/a/0 | n/a/0 | n/a/0 | QUIET | target-type specific (play_store/app_store, phone) |
| pivots | Pivot Finder | ok/5 | ok/5 | ok/5 | WORKING | findings: live=5 offline=5 active=5 e.g. pivot_query,shodan_note |
| ports | Port Scanner | ok/25 | ok/25 | ok/25 | WORKING | findings: live=25 offline=25 active=25 e.g. port_suggestion |
| rce | RCE Time Probe | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| rdap | WHOIS / RDAP | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| robots | Robots / Sitemap | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| rugpull | Rug Pull Indicators | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| s3 | Cloud Bucket Finder | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| secrets | Exposed API Keys | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| smartcontract | Smart Contract Scout | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| social | Social Footprint | ok/4 | ok/4 | ok/4 | WORKING | findings: live=4 offline=4 active=4 e.g. social_guess |
| sqli | SQLi Probe | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| ssrf | SSRF Sink Finder | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| ssti | SSTI Probe | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| subdomains | Subdomain Enum | timeout/0 | ok/1 | ok/1 | WORKING | findings: live=0 offline=1 active=1 e.g. subdomain_enum_note |
| supplychain | Supply Chain Scout | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| takeover | Takeover Checker | ok/1 | ok/1 | ok/1 | WORKING | findings: live=1 offline=1 active=1 e.g. takeover_note |
| tls | TLS + Email Security | ok/3 | ok/3 | ok/3 | WORKING | findings: live=3 offline=3 active=3 e.g. dmarc,spf,tls_note |
| tokenapproval | Token Approval Risk | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| traversal | Path Traversal Check | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| usernames | Username Checker | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| waf | WAF Detector | ok/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| walletcheck | Wallet Security Check | timeout/0 | ok/0 | timeout/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| wallets | Wallet Key Exposure | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| wayback | Wayback History | ok/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| webtech | Web Tech Fingerprint | timeout/0 | ok/0 | ok/0 | QUIET | 0 findings on example.com; target-specific paths intact |
| xpathi | XPath Injection | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
| xss | XSS Canary | ok/0 | ok/0 | ok/0 | QUIET | active-mode prober; silent in passive by design |
