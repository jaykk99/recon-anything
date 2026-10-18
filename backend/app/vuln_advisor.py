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
    }
    lines.extend(profiles.get(candidate_id, [
        "[>] Would send: read-only detection probes",
        "[>] Would NOT: modify data or exploit",
        "[ok] Dry run complete.",
    ]))
    lines.append("[!] Reminder: only test targets you are authorized to test.")
    return lines
