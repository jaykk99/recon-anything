"""Vulnerability advisor (heuristic, no LLM).

Takes a completed run's findings and produces ranked "possible vulnerability"
candidates: the most viable attack paths based on what the scan actually found.
Each candidate carries a safe, detection-only PoC snippet plus dry-run steps.

Nothing here exploits anything. PoCs are read-only detection probes.
"""
from __future__ import annotations

import re
from typing import Dict, List

# ---------------------------------------------------------------------------
# Candidate templates. Each template describes WHEN it fires (a matcher over
# the run's findings) and WHAT to show (name, why, PoC, dry-run steps).
# ---------------------------------------------------------------------------

def _find(findings: List[Dict], key: str = None, plugin: str = None,
           category: str = None, value_contains: str = None) -> List[Dict]:
    out = []
    for f in findings:
        if key and f.get("key") != key:
            continue
        if plugin and f.get("plugin") != plugin:
            continue
        if category and f.get("category") != category:
            continue
        if value_contains and value_contains.lower() not in (f.get("value") or "").lower():
            continue
        out.append(f)
    return out


def _first(findings: List[Dict], **kw) -> Dict | None:
    hits = _find(findings, **kw)
    return hits[0] if hits else None


def _targets_of(run_summary: Dict) -> str:
    t = run_summary.get("targets") or []
    if isinstance(t, list) and t:
        first = t[0]
        if isinstance(first, dict):
            return first.get("normalized") or first.get("raw") or "TARGET"
        return str(first)
    return "TARGET"


def _base_url(findings: List[Dict], run_summary: Dict) -> str:
    for f in findings:
        su = f.get("source_url") or ""
        if su.startswith("http"):
            m = re.match(r"(https?://[^/]+)", su)
            if m:
                return m.group(1)
    return _targets_of(run_summary)


def advise(findings: List[Dict], run_summary: Dict) -> List[Dict]:
    """Return ranked vulnerability candidates, most viable first."""
    base = _base_url(findings, run_summary)
    cands: List[Dict] = []

    def add(vuln_id: str, name: str, severity: str, confidence: int,
            why: str, poc: str, poc_lang: str, steps: List[str],
            remediation: str, evidence_refs: List[Dict]):
        cands.append({
            "id": vuln_id,
            "name": name,
            "severity": severity,
            "confidence": confidence,
            "why_viable": why,
            "poc_code": poc,
            "poc_lang": poc_lang,
            "dry_run_steps": steps,
            "remediation": remediation,
            "evidence_count": len(evidence_refs),
        })

    # -- 1. Exposed .git -> full source reconstruction ---------------------
    git = _first(findings, key="git_exposed") or _first(findings, value_contains=".git/HEAD")
    if git:
        add(
            "git-exposed", "Exposed .git directory (source code leak)",
            "critical", 95,
            "Your scan found a live .git directory. That usually means the entire "
            "source code, commit history, and old secrets can be downloaded and audited offline.",
            f"""# Safe detection only: check .git/HEAD is reachable (read-only)
curl -s -o /dev/null -w "%{{http_code}}" {base}/.git/HEAD
# If 200, the repo is exposed. Offline reconstruction (authorized only):
# gitdumper.sh {base}/.git /tmp/leaked-src""",
            "sh",
            [
                "Send one GET request to /.git/HEAD (read-only, no data changed).",
                "If it returns 200 with 'ref: refs/heads/...', the repo is exposed.",
                "On authorized engagements, use gitdumper to reconstruct the source offline.",
                "Grep the reconstructed code for secrets, SQL, and auth logic.",
            ],
            "Block /.git at the web server or CDN. Never deploy the .git folder.",
            [git],
        )

    # -- 2. Exposed .env / secrets ------------------------------------------
    env = _find(findings, key="artifact_exposed", value_contains=".env")
    secrets = _find(findings, category="leak")
    if env or _first(findings, key="exposed_aws_access_key") or _first(findings, value_contains="BEGIN RSA PRIVATE KEY"):
        add(
            "env-secrets", "Exposed secrets / .env (credential leak)",
            "critical", 92,
            f"Your scan flagged {len(env) + len(secrets)} secret or config exposures. "
            "Leaked keys often grant full infrastructure access.",
            f"""# Safe detection only: check if .env is served (read-only)
curl -s -I {base}/.env | head -5
# Look for 200 + text/plain. NEVER print or use leaked keys.""",
            "sh",
            [
                "Send HEAD request to /.env (read-only).",
                "A 200 response with text content means secrets are exposed.",
                "Report immediately so keys can be rotated. Do not retain them.",
            ],
            "Remove .env from web root. Rotate every exposed key immediately.",
            env + secrets[:3],
        )

    # -- 3. SQLi hint ---------------------------------------------------------
    sqli = _find(findings, plugin="sqli") or _find(findings, value_contains="SQL syntax")
    params = _find(findings, key="param") or _find(findings, key="endpoint")
    if sqli or params:
        sample = (sqli[0].get("value") if sqli else params[0].get("value") if params else "/?id=1")
        add(
            "sqli", "SQL injection (detection probe)",
            "critical", 85 if sqli else 55,
            "Your scan found injectable-looking parameters or SQL error text. "
            "A single quote probe distinguishes real SQLi from noise.",
            f"""import requests
url = "{base}/"
# Detection-only: boolean/error probe, extracts nothing
for payload in ["'", "' OR '1'='1", "1; SELECT 1"]:
    r = requests.get(url, params={{"id": "1" + payload}}, timeout=10)
    print(payload, "->", r.status_code, len(r.text))""",
            "py",
            [
                "Send GET with a single-quote appended to the id parameter.",
                "Compare response size/status to the baseline request.",
                "A 500 error or SQL error text confirms injection (detection only).",
                "Stop here and report. Do not extract data.",
            ],
            "Use parameterized queries / ORM. Never concatenate user input into SQL.",
            sqli[:2] + params[:2],
        )

    # -- 4. Exposed API docs -> BOLA ------------------------------------------
    apidoc = _first(findings, value_contains="swagger") or _first(findings, value_contains="openapi")
    api_eps = _find(findings, category="api")
    if apidoc or api_eps:
        add(
            "bola", "Broken object-level authorization (API)",
            "high", 80 if apidoc else 60,
            "Your scan found API documentation or endpoints. Exposed API maps let testers "
            "enumerate every object ID; missing per-object checks are the most common API bug.",
            f"""import requests
# Detection-only: fetch two object IDs, compare (no modification)
base = "{base}"
for oid in ["1", "2"]:
    r = requests.get(base + f"/api/users/{{oid}}", timeout=10)
    print(oid, r.status_code, len(r.text))
# Different users' data with one session = BOLA signal""",
            "py",
            [
                "List API endpoints from the discovered docs.",
                "Request object 1, then object 2, with the same low-privilege session.",
                "If object 2 returns another user's data, BOLA is confirmed.",
                "Report with both responses. Do not access more records.",
            ],
            "Enforce per-object authorization checks on every API endpoint.",
            ([apidoc] if apidoc else []) + api_eps[:2],
        )

    # -- 5. WordPress / CMS version -> CVE ------------------------------------
    wp = _first(findings, value_contains="wordpress") or _first(findings, value_contains="wp-content")
    if wp:
        add(
            "cms-cve", "Outdated CMS components (CVE check)",
            "high", 70,
            "Your scan fingerprinted a CMS. Old CMS versions and plugins carry public CVEs "
            "with ready-made detection probes.",
            f"""# Safe detection: version disclosure only (read-only)
curl -s {base}/wp-json/wp/v2/ | head -c 400
curl -s {base}/readme.html | grep -i "version" | head -3
# Match versions against https://wpscan.com (authorized testing only)""",
            "sh",
            [
                "Fetch /wp-json/wp/v2/ and readme.html (read-only GETs).",
                "Extract the CMS and plugin versions.",
                "Look each version up in a public CVE database.",
                "Use only non-destructive version probes from the CVE entry.",
            ],
            "Update CMS core, themes, and plugins. Remove version disclosure files.",
            [wp],
        )

    # -- 6. CORS misconfiguration ----------------------------------------------
    cors = _first(findings, key="cors_misconfig") or _first(findings, value_contains="Access-Control-Allow-Origin: *")
    if cors:
        add(
            "cors", "CORS misconfiguration (credential theft path)",
            "medium", 75,
            "Your scan found permissive CORS. Wildcard origins with credentials enabled "
            "let any site read authenticated responses.",
            f"""# Safe detection: preflight check (read-only)
curl -s -I -H "Origin: https://evil.example" {base}/api/ | grep -i "access-control"
# Vulnerable if it reflects the evil origin with Allow-Credentials: true""",
            "sh",
            [
                "Send request with Origin: https://evil.example (read-only).",
                "Check if Access-Control-Allow-Origin reflects it back.",
                "If yes with Allow-Credentials: true, the misconfig is confirmed.",
            ],
            "Never reflect arbitrary origins. Allowlist exact trusted domains.",
            [cors],
        )

    # -- 7. Open S3 / cloud bucket ----------------------------------------------
    s3 = _first(findings, plugin="s3") or _find(findings, value_contains="s3.amazonaws")
    if s3:
        add(
            "s3-open", "Public cloud storage bucket",
            "high", 80,
            "Your scan found cloud bucket references. Public buckets often leak backups, "
            "database dumps, and credentials.",
            f"""# Safe detection: anonymous LIST only (read-only)
BUCKET=$(echo "{(s3[0].get('value') if s3 else '')}" | grep -oE '[a-z0-9.-]+\\.s3[.-][a-z0-9.-]+' | head -1)
curl -s "https://$BUCKET" | head -c 500
# <ListBucketResult> in output = publicly listable""",
            "sh",
            [
                "Extract bucket name from scan findings.",
                "Send anonymous GET to the bucket root (read-only list).",
                "A ListBucketResult XML response confirms public access.",
                "Do not download private objects. Report for ACL fix.",
            ],
            "Set bucket ACLs to private. Audit with least-privilege IAM.",
            s3[:2],
        )

    # -- 8. JWT weakness -----------------------------------------------------------
    jwt = _first(findings, key="jwt_weak") or _first(findings, value_contains="eyJ")
    if jwt:
        add(
            "jwt", "Weak JWT validation",
            "high", 70,
            "Your scan spotted JWT tokens or weak validation hints. alg:none and weak "
            "secrets are classic auth bypasses.",
            f"""import base64, json
token = "PASTE_JWT_HERE"  # detection only, local decode
header = json.loads(base64.urlsafe_b64decode(token.split('.')[0] + '=='))
print("alg:", header.get("alg"))
# alg == "none" -> bypass candidate (verify on authorized target only)""",
            "py",
            [
                "Decode the JWT header locally (no requests sent).",
                "Check alg field: 'none' or weak HS256 with guessable secret.",
                "On an authorized target, test one forged token.",
                "Report the weak validation. Do not access other accounts.",
            ],
            "Validate alg against an allowlist. Use strong random secrets. Short expiry.",
            [jwt],
        )

    # -- 9. Interesting subdomain -> forgotten asset ----------------------------------
    shadow = _find(findings, key="interesting_subdomain")
    if shadow:
        sub = shadow[0].get("value", "")
        add(
            "shadow-it", "Forgotten subdomain (shadow IT)",
            "medium", 65,
            f"Your scan flagged {len(shadow)} interesting subdomain(s), e.g. {sub}. "
            "Forgotten assets run old code and are rarely monitored.",
            f"""# Safe detection: banner + headers only (read-only)
curl -s -I https://{sub} | head -10
# Old Server headers / default pages = unpatched asset signal""",
            "sh",
            [
                "Send HEAD request to the subdomain (read-only).",
                "Check Server header and page title for old software.",
                "Default pages or ancient versions mean unpatched code.",
                "Re-run the full recon suite against this subdomain.",
            ],
            "Inventory all subdomains. Decommission or patch forgotten assets.",
            shadow[:3],
        )

    # -- 10. Clickjacking --------------------------------------------------------------
    cj = _first(findings, key="clickjack") or _first(findings, value_contains="X-Frame-Options")
    if cj:
        add(
            "clickjack", "Clickjacking (missing frame protection)",
            "low", 70,
            "Your scan found pages without X-Frame-Options or frame-ancestors. "
            "They can be embedded in an attacker page for UI redressing.",
            f"""<!-- Safe PoC: local HTML file only, no requests to target -->
<iframe src="{base}/" width="800" height="600"></iframe>
<!-- If the page renders inside the frame, protection is missing -->""",
            "html",
            [
                "Create a local HTML file with an iframe pointing at the page.",
                "Open it in your browser (no requests beyond normal page load).",
                "If the target renders inside the frame, clickjacking is possible.",
            ],
            "Set X-Frame-Options: DENY or Content-Security-Policy frame-ancestors.",
            [cj],
        )

    # -- 11. Reflected XSS -----------------------------------------------------
    xss = _first(findings, key="xss_dom_sink") or _first(findings, plugin="xss") \
        or _first(findings, value_contains="<script")
    if xss:
        add(
            "xss-reflected", "Reflected XSS (canary reflection test)",
            "high", 80,
            "Your scan found script sinks or script-ish content. A unique canary proves "
            "raw reflection, which is the real XSS signal, not guesswork.",
            f"""import requests
base = "{base}"
canary = 'qx7Z\\'"<>'  # unique, harmless
for p in ["q", "search", "s", "keyword", "name"]:
    r = requests.get(base, params={{p: canary}}, timeout=10)
    if canary in r.text:
        print("RAW REFLECTION via", p)
        break""",
            "py",
            [
                "Fetch the base page and extract up to 3 form input names.",
                "Send the unique canary in common query params plus the form fields.",
                "If the RAW canary with unencoded < appears in the HTML, XSS is real.",
                "Report which param reflected. Do not try script execution.",
            ],
            "HTML-encode all user input on output. Set Content-Security-Policy.",
            [xss],
        )

    # -- 12. Open redirect -----------------------------------------------------
    ored = _first(findings, value_contains="redirect") or _first(findings, plugin="redirect") \
        or _first(findings, key="endpoint")
    if ored:
        add(
            "open-redirect", "Open redirect (no-follow 3xx check)",
            "medium", 70,
            "Your scan found redirect behavior or endpoint params. A no-follow request "
            "with an external URL proves whether the server redirects off-site.",
            f"""import requests
base = "{base}"
for p in ["next", "redirect", "url", "return", "dest", "target", "continue", "r"]:
    r = requests.get(base, params={{p: "https://example.com/"}},
                     allow_redirects=False, timeout=10)
    if r.status_code in (301, 302, 303, 307, 308) and "example.com" in r.headers.get("location", ""):
        print("OPEN REDIRECT via", p)
        break""",
            "py",
            [
                "Use a client that does NOT follow redirects.",
                "Probe redirect-ish params with https://example.com/ as the value.",
                "A 3xx with Location pointing at example.com confirms the bug.",
                "Check login/logout links too, they often pass next= URLs.",
            ],
            "Allowlist redirect targets. Reject or sanitize absolute URLs.",
            [ored],
        )

    # -- 13. SSRF ----------------------------------------------------------------
    ssrf = _first(findings, key="ssrf_prone_param") or _first(findings, plugin="ssrf")
    if ssrf:
        add(
            "ssrf", "Server-side request forgery (metadata IP probe)",
            "critical", 85,
            "Your scan flagged a URL-taking parameter. If the server fetches the cloud "
            "metadata IP, you have SSRF, and credential exposure is on the table.",
            f"""import requests
base = "{base}"
probe = "http://169.254.169.254/latest/meta-data/ami-id"
for p in ["url", "uri", "path", "file", "dest", "target", "redirect", "u"]:
    r = requests.get(base, params={{p: probe}}, timeout=15)
    if "ami-id" in r.text.lower() or "instance-id" in r.text.lower():
        print("SSRF CONFIRMED via", p)
        break  # report immediately, do not dig for credentials""",
            "py",
            [
                "Probe URL-ish params with the cloud metadata IP address.",
                "If metadata markers come back, SSRF is confirmed.",
                "Report IMMEDIATELY. Do not read or retain any credentials.",
                "Treat the box as potentially compromised until keys are rotated.",
            ],
            "Block cloud metadata IPs. Allowlist outbound fetch targets.",
            [ssrf],
        )

    # -- 14. IDOR -----------------------------------------------------------------
    idor = _first(findings, key="idor_candidate") or _first(findings, plugin="idor")
    if idor:
        add(
            "idor", "Insecure direct object reference (IDOR)",
            "high", 80,
            "Your scan found numeric object IDs in links or params. Fetching a neighbor "
            "ID and comparing JSON bodies proves missing per-object checks.",
            f"""import requests, re, json
base = "{base}"
r = requests.get(base, timeout=10)
ids = re.findall(r"/users/(\\d+)", r.text) + re.findall(r"[?&]id=(\\d+)", r.text)
oid = int(ids[0])
for n in (oid + 1, oid - 1):
    rn = requests.get(base, params={{"id": n}}, timeout=10)
    print(n, rn.status_code, len(rn.text))
# Both 200 with different JSON id values = IDOR signal""",
            "py",
            [
                "Scrape numeric IDs from links or query params on the page.",
                "Request id+1 and id-1 with GET (read-only).",
                "Both 200 with substantial DIFFERENT JSON bodies = IDOR signal.",
                "Otherwise it needs manual testing with an authenticated session.",
            ],
            "Enforce per-object authorization on every endpoint that takes an ID.",
            [idor],
        )

    # -- 15. Auth bypass ----------------------------------------------------------
    ab = _first(findings, value_contains="admin") or _first(findings, plugin="auth")
    if ab:
        add(
            "auth-bypass", "Missing admin authentication gate",
            "high", 75,
            "Your scan mentions admin or auth surfaces. Common admin paths sometimes "
            "return 200 without ever showing a login form.",
            f"""import requests
base = "{base}"
paths = ["/admin", "/admin/", "/administrator", "/wp-admin", "/dashboard", "/manager/html"]
for p in paths:
    r = requests.get(base + p, timeout=10)
    t = r.text.lower()
    if r.status_code == 200 and 'type="password"' not in t and "login" not in t:
        print("UNGATED:", p)
        break""",
            "py",
            [
                "GET common admin paths (read-only, nothing modified).",
                "A 200 with no password field or login markers = ungated area.",
                "Redirects to /login mean the gate is working. Leave it alone.",
            ],
            "Put every admin path behind auth. Deny unknown paths at the edge.",
            [ab],
        )

    # -- 16. Path traversal ---------------------------------------------------------
    trav = _first(findings, value_contains="../") or _first(findings, value_contains="/etc/passwd")
    if trav:
        add(
            "dir-traversal", "Path traversal (read-only passwd check)",
            "high", 75,
            "Your scan saw dot-dot or passwd references. A classic traversal payload in "
            "file-ish params proves the leak with zero damage.",
            f"""import requests
base = "{base}"
payload = "....//....//....//etc/passwd"
for p in ["file", "path", "page", "include", "template", "name", "f"]:
    r = requests.get(base, params={{p: payload}}, timeout=10)
    if "root:x:0:0" in r.text:
        print("TRAVERSAL CONFIRMED via", p)
        break""",
            "py",
            [
                "Probe file-ish params with ....//....//....//etc/passwd.",
                "If 'root:x:0:0' appears in the response, traversal is real.",
                "Read-only check. Do not request other sensitive files.",
            ],
            "Canonicalize paths and reject '..'. Never build paths from user input.",
            [trav],
        )

    # -- 17. XXE -------------------------------------------------------------------
    xxe = _first(findings, value_contains="<?xml") or _first(findings, value_contains="content-type: application/xml")
    if xxe:
        add(
            "xxe", "XML external entity injection (entity expansion test)",
            "high", 70,
            "Your scan found XML handling. A harmless internal entity proves the parser "
            "expands entities, which is the XXE signal.",
            f"""import requests
base = "{base}"
payload = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe "xxeProbe9">]><r>&xxe;</r>'
r = requests.get(base, params={{"xml": payload}}, timeout=10)
print("ENTITY EXPANDED:", "xxeProbe9" in r.text)
# Note: most XXE needs POST, so also test manually if an XML endpoint exists""",
            "py",
            [
                "Send the safe internal-entity payload via ?xml= (GET only).",
                "If 'xxeProbe9' is reflected expanded, XXE is real.",
                "If not, it is inconclusive over GET: test manually with POST.",
                "Never use external entities or file reads in testing.",
            ],
            "Disable DTDs and external entities in the XML parser.",
            [xxe],
        )

    # -- 18. SSTI -------------------------------------------------------------------
    ssti = _first(findings, value_contains="{{") or _first(findings, value_contains="jinja") \
        or _first(findings, value_contains="twig")
    if ssti:
        add(
            "ssti", "Server-side template injection (math evaluation test)",
            "high", 75,
            "Your scan found template syntax hints. A unique math payload proves "
            "evaluation without false positives.",
            f"""import requests
base = "{base}"
for p in ["name", "q", "search", "template", "view"]:
    for payload in ("{{{{1336*7}}}}", "${{1336*7}}"):
        r = requests.get(base, params={{p: payload}}, timeout=10)
        if "9352" in r.text:
            print("SSTI CONFIRMED via", p, payload)
            raise SystemExit""",
            "py",
            [
                "Check the baseline page does not already contain '9352'.",
                "Send {{1336*7}} and ${1336*7} in template-ish params.",
                "If '9352' appears, the server evaluated the template. SSTI real.",
                "Stop there. Do not chain to code execution.",
            ],
            "Never render user input as a template. Use logicless output encoding.",
            [ssti],
        )

    # -- 19. CRLF injection ---------------------------------------------------------
    crlf = _first(findings, key="param") or _first(findings, key="endpoint")
    if crlf:
        add(
            "crlf", "CRLF / header injection (response header check)",
            "medium", 60,
            "Your scan found parameters or endpoints. Some apps reflect input into "
            "response headers without stripping CR/LF, enabling header injection.",
            f"""import requests
base = "{base}"
for p in ["next", "url", "redirect", "q"]:
    # raw URL keeps %0d%0a literal (requests would double-encode via params)
    r = requests.get(base + "/?" + p + "=test%0d%0aX-Injected-Probe9:%20yes", timeout=10)
    if "x-injected-probe9" in {{k.lower() for k in r.headers}}:
        print("CRLF INJECTION via", p)
        break""",
            "py",
            [
                "Send a CRLF payload with an X-Injected-Probe9 header line.",
                "Pass the raw URL so %0d%0a stays literal (GET only).",
                "If the response headers contain x-injected-probe9, it is real.",
            ],
            "Strip CR/LF from anything reflected into headers. Validate redirects.",
            [crlf],
        )

    # -- 20. Host header injection -----------------------------------------------------
    hh = _first(findings, value_contains="password reset") or _first(findings, key="endpoint")
    if hh:
        add(
            "host-header", "Host header injection (reset-link poisoning check)",
            "medium", 65,
            "Your scan hints at password-reset flows or endpoints. If the app trusts "
            "the Host header, reset links can point at an attacker domain.",
            f"""import requests
base = "{base}"
r = requests.get(base, headers={{"Host": "evil.example"}}, allow_redirects=False, timeout=10)
loc = r.headers.get("location", "")
print("LOCATION REFLECTS HOST:", "evil.example" in loc)
print("BODY REFLECTS HOST:", "evil.example" in r.text)
# Poisoned Host -> password reset emails point at evil.example""",
            "py",
            [
                "Send one GET with Host: evil.example, no redirect follow.",
                "If evil.example lands in Location or body links, injection is real.",
                "Check the password-reset flow manually with a test account.",
                "Do not send reset links to real users.",
            ],
            "Validate Host against a whitelist. Build absolute URLs from config.",
            [hh],
        )

    # Rank: severity first, then confidence
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    cands.sort(key=lambda c: (rank.get(c["severity"], 4), -c["confidence"]))
    return cands[:5]


# ---------------------------------------------------------------------------
# Safe-test simulator: dry-run terminal output for a candidate.
# No network calls happen here; it narrates what a safe check would do.
# ---------------------------------------------------------------------------

def dry_run(candidate_id: str, base: str) -> List[str]:
    """Return terminal lines narrating a safe dry-run for a candidate."""
    lines = [
        "$ recon-safe-test --dry-run " + candidate_id,
        "[*] DRY RUN - no requests will be sent to " + base,
        "[*] Loading detection profile: " + candidate_id,
    ]
    profiles = {
        "git-exposed": [
            "[>] Would send: GET /.git/HEAD (1 request, read-only)",
            "[>] Would check: response body starts with 'ref:'",
            "[>] Would NOT: download objects, write anything",
            "[ok] Dry run complete. 1 read-only request planned.",
        ],
        "env-secrets": [
            "[>] Would send: HEAD /.env (1 request, read-only)",
            "[>] Would check: status 200 + non-HTML body",
            "[>] Would NOT: store, print, or reuse any secret found",
            "[ok] Dry run complete. 1 read-only request planned.",
        ],
        "sqli": [
            "[>] Would send: 3 GET requests with quote probes on id param",
            "[>] Would check: error text / status drift vs baseline",
            "[>] Would NOT: UNION SELECT, stacked queries, data extraction",
            "[ok] Dry run complete. 4 read-only requests planned (1 baseline + 3 probes).",
        ],
        "bola": [
            "[>] Would send: 2 GET requests (/api/users/1, /api/users/2)",
            "[>] Would check: whether both return 200 with different user data",
            "[>] Would NOT: modify, delete, or enumerate further IDs",
            "[ok] Dry run complete. 2 read-only requests planned.",
        ],
        "cms-cve": [
            "[>] Would send: GET /wp-json/wp/v2/, GET /readme.html (read-only)",
            "[>] Would check: version strings against local CVE list",
            "[>] Would NOT: run any exploit payload",
            "[ok] Dry run complete. 2 read-only requests planned.",
        ],
        "cors": [
            "[>] Would send: 1 GET with Origin: https://evil.example",
            "[>] Would check: reflected ACAO + Allow-Credentials headers",
            "[>] Would NOT: steal any credentials (needs victim browser anyway)",
            "[ok] Dry run complete. 1 read-only request planned.",
        ],
        "s3-open": [
            "[>] Would send: 1 GET to bucket root (anonymous LIST)",
            "[>] Would check: ListBucketResult XML in response",
            "[>] Would NOT: download objects or write anything",
            "[ok] Dry run complete. 1 read-only request planned.",
        ],
        "jwt": [
            "[>] Would send: 0 requests (fully offline check)",
            "[>] Would do: base64-decode the token header locally",
            "[>] Would check: alg field for 'none' or weak config",
            "[ok] Dry run complete. 0 requests planned.",
        ],
        "shadow-it": [
            "[>] Would send: 1 HEAD request to the subdomain",
            "[>] Would check: Server header, page title, TLS cert age",
            "[>] Would NOT: brute force paths or exploit",
            "[ok] Dry run complete. 1 read-only request planned.",
        ],
        "clickjack": [
            "[>] Would send: 0 requests to target (local iframe test)",
            "[>] Would do: embed page in a local HTML file, open in browser",
            "[>] Would check: whether the page renders inside the frame",
            "[ok] Dry run complete. 0 requests planned.",
        ],
        "xss-reflected": [
            "[>] Would send: 1 baseline GET + up to 8 canary GETs (read-only)",
            "[>] Would check: whether the raw canary qx7Z'\"<> is reflected",
            "[>] Would NOT: execute scripts or steal sessions",
            "[ok] Dry run complete. ~9 read-only requests planned.",
        ],
        "open-redirect": [
            "[>] Would send: 8 GETs with allow_redirects=False (read-only)",
            "[>] Would check: 3xx Location pointing at example.com",
            "[>] Would NOT: send anyone to an attacker site",
            "[ok] Dry run complete. 8 read-only requests planned.",
        ],
        "ssrf": [
            "[>] Would send: 8 GETs with the metadata IP as a param value",
            "[>] Would check: ami-id / instance-id markers in the response",
            "[>] Would NOT: read credentials, fetch other internal hosts",
            "[ok] Dry run complete. 8 read-only requests planned.",
        ],
        "idor": [
            "[>] Would send: 1 page GET + 2 neighbor-ID GETs (read-only)",
            "[>] Would check: both 200 with different JSON object data",
            "[>] Would NOT: enumerate more IDs or touch another account",
            "[ok] Dry run complete. 3 read-only requests planned.",
        ],
        "auth-bypass": [
            "[>] Would send: 6 GETs to common admin paths (read-only)",
            "[>] Would check: 200 with no login form markers",
            "[>] Would NOT: attempt logins or access admin functions",
            "[ok] Dry run complete. 6 read-only requests planned.",
        ],
        "dir-traversal": [
            "[>] Would send: 7 GETs with traversal payload in file-ish params",
            "[>] Would check: 'root:x:0:0' in the response",
            "[>] Would NOT: read other sensitive files",
            "[ok] Dry run complete. 7 read-only requests planned.",
        ],
        "xxe": [
            "[>] Would send: 1 GET with safe internal-entity XML in ?xml=",
            "[>] Would check: whether 'xxeProbe9' expands and reflects",
            "[>] Would NOT: use external entities or file reads",
            "[ok] Dry run complete. 1 read-only request planned.",
        ],
        "ssti": [
            "[>] Would send: 1 baseline GET + 10 math-payload GETs (read-only)",
            "[>] Would check: whether '9352' appears in any response",
            "[>] Would NOT: chain to code execution",
            "[ok] Dry run complete. 11 read-only requests planned.",
        ],
        "crlf": [
            "[>] Would send: 4 GETs with CRLF payload (raw URL, read-only)",
            "[>] Would check: x-injected-probe9 in the response headers",
            "[>] Would NOT: inject real security headers or cookies",
            "[ok] Dry run complete. 4 read-only requests planned.",
        ],
        "host-header": [
            "[>] Would send: 1 GET with Host: evil.example, no redirect follow",
            "[>] Would check: evil.example in Location or body links",
            "[>] Would NOT: trigger reset emails to real users",
            "[ok] Dry run complete. 1 read-only request planned.",
        ],
    }
    lines.extend(profiles.get(candidate_id, [
        "[>] Would send: read-only detection probes",
        "[>] Would NOT: modify data or exploit",
        "[ok] Dry run complete.",
    ]))
    lines.append("[!] Reminder: only test targets you are authorized to test.")
    return lines
