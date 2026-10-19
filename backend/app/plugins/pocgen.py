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
            findings.append(self._f(
                "web", "poc_detail",
                f"PoC guide: {value}",
                source="PoC generator", confidence=85,
                evidence={"severity": item.get("severity", "medium"),
                          "remediation": tmpl["fix"],
                          "what_it_means": tmpl["means"],
                          "how_to_verify": tmpl["verify"],
                          "attacker_impact": tmpl["impact"],
                          "the_fix": tmpl["fix"],
                          "original_key": key,
                          "scope_note": "Verification steps are for "
                                        "authorized testing only."}))

        reason = f"{len(findings)} PoC guides generated"
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
