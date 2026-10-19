"""PoC detail generator: proof-of-concept write-ups for findings.

For each significant finding on the bus (high/medium severity), generates:
  - What the finding means (plain language)
  - How to manually verify it (step-by-step, safe)
  - What an attacker could do with it (impact)
  - The fix (remediation)

This is DOCUMENTATION, not exploitation: it describes how to verify,
never performs the verification. No payloads are sent, no requests
beyond what discovery already did.

Pure logic - no network calls. Keyless.
Phase 2 chain plugin: reads findings from the bus.
"""
from __future__ import annotations

import time
from typing import Dict, List

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


# finding key -> (what_it_means, how_to_verify, impact, fix)
POC_TEMPLATES: Dict[str, Dict[str, str]] = {
    "sqli_error_based": {
        "means": "The application puts your input directly into a database query without sanitizing it.",
        "verify": "1. Find the vulnerable parameter\n2. Add a single quote (') and observe the error\n3. Try: ' AND '1'='1 vs ' AND '1'='2 - different responses = injectable\n4. Use sqlmap with --batch --risk=1 for safe confirmation",
        "impact": "Full database read. Depending on DB user: file read, command execution, lateral movement.",
        "fix": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    },
    "xss_reflected": {
        "means": "Your input is reflected in the page HTML without encoding.",
        "verify": "1. Submit <script>alert(1)</script> (or a harmless <img> canary)\n2. Check if it executes or appears unencoded in source\n3. Test context: HTML body, attribute, JS string, URL",
        "impact": "Session hijacking via cookie theft, phishing via page injection, defacement.",
        "fix": "Context-aware output encoding. Set Content-Security-Policy. Use frameworks that auto-escape.",
    },
    "ssrf_cloud_metadata": {
        "means": "The server fetches URLs you supply, including internal cloud metadata IPs.",
        "verify": "1. Find the URL-fetching parameter\n2. Point it at http://169.254.169.254/latest/meta-data/\n3. If cloud credentials return, it is critical\n4. Also test internal hostnames and ports",
        "impact": "Cloud credential theft, internal network scanning, access to internal services.",
        "fix": "Allowlist outbound domains. Block metadata IPs (169.254.169.254, 100.100.100.200). No user-controlled URLs.",
    },
    "idor_candidate": {
        "means": "Object IDs are predictable - changing the ID may show another user's data.",
        "verify": "1. Create two test accounts\n2. Note your object ID (e.g. /api/orders/123)\n3. Change 123 to 124 while logged in as account A\n4. If you see account B's data = confirmed IDOR",
        "impact": "Unauthorized access to other users' data: PII, orders, documents, messages.",
        "fix": "Server-side authorization check on every object access. Use unpredictable UUIDs AND auth checks.",
    },
    "jwt_alg_none": {
        "means": "The app accepts JWTs with algorithm 'none' - no signature needed.",
        "verify": "1. Get a valid JWT\n2. Change header alg to 'none', remove signature\n3. Modify claims (e.g. user_id, role=admin)\n4. If accepted = full auth bypass",
        "impact": "Complete authentication bypass. Forge any user's token, escalate to admin.",
        "fix": "Reject alg=none server-side. Whitelist allowed algorithms (RS256/ES256).",
    },
    "s3_public_read": {
        "means": "A cloud storage bucket allows public listing/reading.",
        "verify": "1. Visit the bucket URL directly\n2. Check if file listing appears\n3. Try common paths: /backup/, /.git/, /config/",
        "impact": "Data breach: backups, source code, credentials, customer data.",
        "fix": "Block public access at the bucket level. Use signed URLs for legitimate sharing.",
    },
    "git_exposed": {
        "means": "The .git directory is downloadable - full source code history is public.",
        "verify": "1. Visit /.git/HEAD - if it returns 'ref: refs/heads/...' it is exposed\n2. Download /.git/config, /.git/logs/HEAD\n3. Use GitTools to reconstruct the repo",
        "impact": "Full source code, commit history, hardcoded secrets, API keys, internal URLs.",
        "fix": "Block .git in web server config. Never deploy .git to production.",
    },
    "subdomain_takeover": {
        "means": "A DNS record points to a service that no longer exists - claimable by an attacker.",
        "verify": "1. Check the CNAME target\n2. Try to claim it on the provider (GitHub Pages, Heroku, S3, etc.)\n3. If claimable = confirmed takeover",
        "impact": "Full control of the subdomain: phishing, cookie theft, brand damage.",
        "fix": "Remove the dangling DNS record, or reclaim the service.",
    },
    "cors_misconfig": {
        "means": "CORS allows any origin (or null) with credentials.",
        "verify": "1. Send Origin: https://evil.com with the request\n2. Check if Access-Control-Allow-Origin reflects it\n3. Check if Allow-Credentials: true",
        "impact": "Any website can make authenticated requests as the victim user.",
        "fix": "Whitelist specific origins. Never reflect Origin with credentials.",
    },
    "open_redirect": {
        "means": "A redirect parameter accepts arbitrary URLs.",
        "verify": "1. Find ?next=, ?url=, ?redirect= parameters\n2. Set to https://evil.com\n3. If it redirects = confirmed",
        "impact": "Phishing: trusted domain redirects to attacker site. OAuth token theft.",
        "fix": "Allowlist redirect destinations. Use relative paths only.",
    },
}

GENERIC_POC = {
    "means": "This finding indicates a potential security weakness.",
    "verify": "1. Review the evidence attached to the finding\n2. Reproduce manually in a browser or with curl\n3. Confirm the behavior matches the finding description",
    "impact": "Varies by finding - see the severity and evidence for specifics.",
    "fix": "See the remediation field on the finding.",
}


# ---------------------------------------------------------------------------
# Manual verification guides, keyed by vuln class.
#
# Each guide is DOCUMENTATION for authorized testing: the exact curl that
# reproduces the detection, what to look for in the response, how to tell
# a real finding from a false positive. Detection only - no exploitation,
# no destructive payloads, no data extraction beyond confirming the
# signal. Every guide carries the authorized-testing scope note.
# ---------------------------------------------------------------------------

# finding-key fragment -> vuln class (first match wins)
CLASS_BY_KEY_FRAGMENT = [
    ("sqli", "sqli"),
    ("xss", "xss"),
    ("ssrf", "ssrf"),
    ("idor", "idor"),
    ("bola", "idor"),
    ("rce", "rce"),
    ("cmdi", "rce"),
    ("traversal", "traversal"),
    ("lfi", "traversal"),
    ("dir_traversal", "traversal"),
    ("cors", "cors"),
    ("ssti", "rce"),
]


def vuln_class_for(key: str) -> str:
    k = (key or "").lower()
    for frag, cls in CLASS_BY_KEY_FRAGMENT:
        if frag in k:
            return cls
    return ""


VERIFY_GUIDES: Dict[str, Dict[str, str]] = {
    "sqli": {
        "curl": ("curl -s 'https://TARGET/page?id=1' -o /tmp/base.html && "
                 "curl -s 'https://TARGET/page?id=1%27' -o /tmp/quote.html && "
                 "diff /tmp/base.html /tmp/quote.html | head -20\n"
                 "# boolean check: compare id=1%20AND%201=1 vs id=1%20AND%201=2"),
        "look_for": ("A database error string in the quote response "
                     "(e.g. 'SQL syntax', 'mysql_fetch', 'ORA-', 'pg_query', "
                     "'SQLite3::query'). For blind: a consistent, repeatable "
                     "difference between the AND-1=1 and AND-1=2 responses "
                     "(content, length, or timing)."),
        "confirm_real": ("The difference must be DETERMINISTIC: repeat each "
                         "request 3 times. Error-based is confirmed when the "
                         "DB error names the query context. Boolean-blind is "
                         "confirmed when true/false conditions flip the "
                         "response every time."),
        "false_positive": ("A generic 500 page or WAF block page identical "
                           "for both requests; a one-off timing blip that "
                           "does not repeat; the app echoing your quote back "
                           "in an error message without any DB error."),
    },
    "xss": {
        "curl": ("curl -s 'https://TARGET/search?q=xsscanary123' | "
                 "grep -o 'xsscanary123[^<]\\{0,40\\}' | head -5\n"
                 "# then view raw source: curl -s 'https://TARGET/search?"
                 "q=%3Cimg%20src=x%3E' | grep -i 'img src=x'"),
        "look_for": ("Your canary reflected in the raw HTML. Then check the "
                     "CONTEXT: straight into HTML body, inside an attribute "
                     "value, inside a <script> block, or into a JS string. "
                     "Unencoded < > \" ' in an HTML/attribute context = "
                     "exploitable reflection."),
        "confirm_real": ("Open the URL in a real browser with a harmless "
                         "canary payload (<img src=x onerror=alert(1)> "
                         "only on targets you are authorized to test) and "
                         "see if it fires. Reflected + unencoded + "
                         "reachable sink = real."),
        "false_positive": ("Canary comes back HTML-encoded (&lt;img&gt;), "
                           "reflected inside a JSON string with proper "
                           "escaping, or only appears inside an HTML comment "
                           "with no scriptable context."),
    },
    "ssrf": {
        "curl": ("# point the URL-fetching parameter at YOUR canary server:\n"
                 "curl -s 'https://TARGET/fetch?url=https://YOUR-CANARY.oast.pro/abc123' "
                 "> /dev/null\n"
                 "# then check your canary server logs for a DNS/HTTP hit\n"
                 "# repeat with a different token to rule out caching"),
        "look_for": ("A DNS lookup or HTTP request arriving at YOUR canary "
                     "domain, stamped with the token you sent. That proves "
                     "the server fetched your URL. Also try "
                     "http://169.254.169.254/latest/meta-data/ ONLY on "
                     "targets you own/are authorized to test."),
        "confirm_real": ("The canary hit arrives with YOUR unique token, "
                         "twice, with fresh tokens. Blind SSRF still counts "
                         "if the server fetched but did not show you the "
                         "result - the callback is the proof."),
        "false_positive": ("No callback after several minutes and fresh "
                           "tokens; the app resolved the domain client-side "
                           "only; a cached/preview fetch by an unrelated "
                           "crawler hitting your domain."),
    },
    "idor": {
        "curl": ("# as USER-A (use your own session cookie):\n"
                 "curl -s -b 'session=USER_A_COOKIE' "
                 "'https://TARGET/api/orders/1001' | head -c 300\n"
                 "# now change ONLY the object id:\n"
                 "curl -s -b 'session=USER_A_COOKIE' "
                 "'https://TARGET/api/orders/1002' | head -c 300"),
        "look_for": ("HTTP 200 returning data that belongs to a DIFFERENT "
                     "user (another name, email, order, document). Compare "
                     "against what user-B sees for the same id - identical "
                     "payload = broken object-level authorization."),
        "confirm_real": ("Create TWO accounts you control. Object 1002 "
                         "belongs to account B; account A's cookie must get "
                         "403/404. If A's cookie gets B's data with a 200, "
                         "it is confirmed. Predictable IDs alone are not "
                         "proof - the cross-account read is."),
        "false_positive": ("403, 404, or redirect-to-login on the foreign "
                           "id; the endpoint returns only your own data "
                           "regardless of id; the id is a signed/opaque "
                           "token that cannot be guessed."),
    },
    "rce": {
        "curl": ("# time-based check, benign payload (sleep only):\n"
                 "time curl -s 'https://TARGET/ping?host=127.0.0.1%3Bsleep%205' "
                 "> /dev/null\n"
                 "time curl -s 'https://TARGET/ping?host=127.0.0.1' > /dev/null\n"
                 "# error-based: look for OS errors in the response body"),
        "look_for": ("A response delay matching your sleep value (5s slower "
                     "than baseline), repeated consistently. Error-based: OS "
                     "command errors ('sh: 1:', 'command not found', "
                     "Windows 'is not recognized') in the response."),
        "confirm_real": ("Run baseline / payload / baseline: the delay must "
                         "track ONLY the payload requests, 3 times in a "
                         "row. Vary the sleep (3s vs 7s) - the delay must "
                         "follow the value. Never run destructive commands; "
                         "timing + error output is enough to confirm."),
        "false_positive": ("Random jitter affecting baseline too; a fixed "
                           "5s delay on ALL requests (slow backend, not "
                           "injection); WAF blocking the payload with an "
                           "instant block page."),
    },
    "traversal": {
        "curl": ("curl -s 'https://TARGET/download?file=../../../../etc/passwd' "
                 "| head -5\n"
                 "# windows variant:\n"
                 "curl -s 'https://TARGET/download?file=..%5C..%5C..%5Cwindows%5Cwin.ini' "
                 "| head -5"),
        "look_for": ("Unix: lines like 'root:x:0:0:' in the response. "
                     "Windows: '[fonts]' / '[extensions]' sections of "
                     "win.ini. Any /etc/passwd, /etc/shadow, or boot.ini "
                     "content = arbitrary file read."),
        "confirm_real": ("Request a file that MUST exist on that OS "
                         "(/etc/passwd on Linux) and a nonsense path - the "
                         "first returns real system content, the second "
                         "404s. Also try a second known file (/etc/hosts) "
                         "to rule out a canned response."),
        "false_positive": ("404 or 'invalid file' for every traversal "
                           "attempt; the app returns its own error template "
                           "with your payload echoed but no file content; "
                           "WAF block page."),
    },
    "cors": {
        "curl": ("curl -s -D - -o /dev/null -H 'Origin: https://evil.example' "
                 "'https://TARGET/api/me'\n"
                 "# and with credentials:\n"
                 "curl -s -D - -o /dev/null -H 'Origin: https://evil.example' "
                 "-b 'session=YOUR_COOKIE' 'https://TARGET/api/me'"),
        "look_for": ("Response headers: 'Access-Control-Allow-Origin: "
                     "https://evil.example' (your arbitrary origin reflected "
                     "verbatim) PLUS 'Access-Control-Allow-Credentials: "
                     "true'. That combination lets any site read "
                     "authenticated responses."),
        "confirm_real": ("Repeat with TWO different evil origins - both must "
                         "be reflected. Then confirm the endpoint actually "
                         "needs auth (200 with cookie, 401 without). "
                         "Reflected origin + credentials + authed endpoint "
                         "= real."),
        "false_positive": ("'Access-Control-Allow-Origin: *' WITHOUT "
                           "Allow-Credentials (limited impact); the origin "
                           "is echoed but the endpoint is public anyway; a "
                           "fixed allowlist that does not include your "
                           "origin."),
    },
}

SCOPE_NOTE = ("Authorized testing only: run these steps solely against "
              "targets you own or are explicitly permitted to test.")


class PocgenPlugin(Plugin):
    id = "pocgen"
    label = "PoC Detail Generator"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Generate verification steps and impact write-ups for findings."
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        # Collect significant findings from the bus.
        # The runner publishes findings; we read what other plugins found.
        # We use the shared bus "findings" if present, else scan evidence.
        findings_in = ctx.consume("poc_findings")
        if not findings_in:
            # Fallback: build from high-value bus signals
            return self._ok([], "no findings on bus to document yet")

        findings: List[Finding] = []
        for item in findings_in[:30]:
            if not isinstance(item, dict):
                continue
            key = item.get("key", "")
            value = item.get("value", "")[:200]
            tmpl = POC_TEMPLATES.get(key, GENERIC_POC)
            # One-click verify guidance: per-vuln-class manual verification
            # (exact curl, what to look for, real-vs-FP) when the finding
            # key maps to a known class (sqli, xss, ssrf, idor, rce,
            # traversal, cors). Detection only, authorized testing only.
            vclass = vuln_class_for(key)
            guide = VERIFY_GUIDES.get(vclass)
            manual_verification = None
            if guide:
                manual_verification = {
                    "vuln_class": vclass,
                    "curl": guide["curl"],
                    "look_for": guide["look_for"],
                    "confirm_real": guide["confirm_real"],
                    "false_positive": guide["false_positive"],
                    "scope": SCOPE_NOTE,
                }
            ev = {"severity": item.get("severity", "medium"),
                  "remediation": tmpl["fix"],
                  "what_it_means": tmpl["means"],
                  "how_to_verify": tmpl["verify"],
                  "attacker_impact": tmpl["impact"],
                  "the_fix": tmpl["fix"],
                  "original_key": key,
                  "scope_note": "Verification steps are for "
                                "authorized testing only."}
            if manual_verification:
                ev["manual_verification"] = manual_verification
            findings.append(self._f(
                "web", "poc_detail",
                f"PoC guide: {value}",
                source="PoC generator", confidence=85,
                evidence=ev))

        reason = f"{len(findings)} PoC guides generated"
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
