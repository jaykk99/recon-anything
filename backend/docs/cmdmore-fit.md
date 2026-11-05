# Command detectors, pack 2: FIT / NO-FIT map (2026-10-26)

Jay's order: "it should write commands to find more." This pack adds
command-based detectors in the `cmdtools.py` pattern (subprocess exec,
never a shell; strict host validation; tight timeouts; graceful skip
when a tool is missing). Detection ONLY: no exploit confirmation, no
brute-forcing, no auth bypass, no private-data access, no full secrets
in findings. crypto.com is never a scan target.

## Reel 1 — @nightowl_sec.sh: Hermes Agent + HexStrike AI + Qwen3.6

| Item | Verdict | Reason |
|---|---|---|
| Hermes Agent (Nous Research harness) | NOTE ONLY, no code | A harness/model runner, not a detector. ReconAnything's agent-investigation path is the pending /agent fold (PR #42); no Hermes integration is built here. |
| Qwen3.6 (local model) | NOTE ONLY, no code | A model, not a detector. Nothing to wire into the plugin registry. |
| HexStrike: nmap-style port/service probing | FIT, already covered | `cmd_ports` (TCP connect + banners) and `port_audit` (risky-port verdicts) already do this. |
| HexStrike: nikto-style web probing | FIT, already covered | `headers`, `http_methods`, `cmd_http` already report banners, missing headers, and dangerous methods. Nikto's exploit checks are NO-FIT (below). |
| HexStrike: gobuster-style dir/DNS busting | FIT, already covered | `dir_brute` and `feroxbuster` (GET-only path probing) and `subdomains`/`subdomain_compiler` already do this. No new wordlist plugin added. |
| HexStrike: nuclei-style CVE matching | FIT, already covered | `cves` matches banners/versions to CVEs. Nuclei's exploit-confirmation templates are NO-FIT. |
| HexStrike: sqlmap, hydra, evasion payloads, exploit confirmation | NO-FIT, not built | Injection attempts, password guessing, and EDR-evasion payloads violate the detection-only boundary. |
| HexStrike recon subset: NEW in this PR | BUILT | `cmd_dns_recurse`, `cmd_dns_nscheck`, `cmd_ocsp` (see below). |

### New detectors in this PR

- `cmd_dns_recurse` — asks each of the target domain's own nameservers
  for an unrelated name (`example.com`). A nameserver that answers is
  an open resolver (DNS amplification abuse vector). One ordinary
  query per nameserver; no zone data requested or stored.
- `cmd_dns_nscheck` — asks each nameserver for the zone SOA directly.
  Reports lame delegation (a listed NS that answers nothing
  authoritative) and SOA serial disagreement between nameservers.
  Serial numbers are public DNS data; no record contents are stored.
- `cmd_ocsp` — `openssl s_client -status`. Reports a stapled OCSP
  response (with cert status when present), a non-successful stapled
  status, or no stapling at all. No responder certs or hashes stored.

### What was checked and deliberately NOT duplicated

`dns.py` already does AXFR zone-transfer checks, wildcard-DNS tests,
and DNSSEC posture; `email_infra` already audits SPF/DKIM/DMARC;
`tls.py`/`tls_config` already audit self-signed certs, hostname
mismatch, and weak ciphers; `headers` + `cookie_security` already audit
security headers and cookie flags; `http2_check` already covers ALPN /
HTTP/2; `port_audit` already flags risky ports including ADB 5555 and
Telnet 23; `takeover` already covers dangling CNAMEs; `rdap` already
covers registration data. None of those got a second plugin.

## Reel 2 — @trumancyber: Android malware abusing wireless debugging + accessibility

| Item | Verdict | Reason |
|---|---|---|
| ADB port 5555 exposure check | NO-FIT, not built | Already covered: `port_audit` reports `adb_exposed` (high) for open 5555. A second ADB plugin would duplicate it. |
| The attack technique itself | NO-FIT, not built | Device-side adb abuse (pairing, accessibility grants, on-device malware behavior) is outside ReconAnything's web-target scope. There is no web endpoint to probe for it, and building the abuse chain would be an exploit, not detection. |

## Reel 3 — @brochbuilds: "Comment SKILLS and I'll send you all 320, ranked by GitHub stars, with the install command for each"

| Item | Verdict | Reason |
|---|---|---|
| The 320 skills | NO-FIT, not built | The caption names NO specific tool. The 320 skills are not listed anywhere in the reel caption, and comments on it are engagement bait, not tool names. Nothing was invented, scraped, or guessed. |
| The concept ("skills") | NOTE ONLY | Reusable skills resemble ReconAnything's plugin registry and the pending /agent investigation path (PR #42). That is an architectural resemblance, not a build item: no detector maps from this reel. |

## Host note

The SnapDeploy image previously shipped no `dig`, `curl`, `openssl`
CLI, or `nc`, so the `cmd_*` plugins skipped on the live host even
though they run locally. This PR adds `dnsutils curl openssl
netcat-openbsd` to the SnapDeploy image so the command detectors
actually run where scans execute. The Render backend Dockerfile is
untouched.
