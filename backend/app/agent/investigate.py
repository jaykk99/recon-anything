"""Investigation layer: finds MORE than the scanner, on top of its findings.

For each run finding: verify it live through the browser route.
For a target: run the agent's own direct detectors (security headers,
cookie flags, JS library versions mapped to public OSV advisories, exposed
.git, subdomain expansion via crt.sh) and write every added finding with
real evidence and a plain-language fix.

Evidence hygiene: cookie values are NEVER printed. Cookie evidence shows
the cookie name and the missing flags only, so a session value fetched
from a target can never land in a finding.
"""

from __future__ import annotations

import json
import re
import urllib.parse

from .http_client import client as http_client

from .fetch import fetch_url
from .ssrf import SSRFBlocked

HEADER_FIXES = {
    "strict-transport-security": ("Missing HSTS header",
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains so browsers only use HTTPS."),
    "content-security-policy": ("Missing Content Security Policy",
        "Add a Content-Security-Policy header that only allows scripts and styles from your own domain."),
    "x-frame-options": ("Missing X-Frame-Options / frame-ancestors",
        "Add X-Frame-Options: DENY or a frame-ancestors CSP rule so the page cannot be framed for clickjacking."),
    "x-content-type-options": ("Missing X-Content-Type-Options",
        "Add X-Content-Type-Options: nosniff so browsers do not guess content types."),
    "referrer-policy": ("Missing Referrer-Policy",
        "Add Referrer-Policy: strict-origin-when-cross-origin so full URLs do not leak to other sites."),
    "permissions-policy": ("Missing Permissions-Policy",
        "Add a Permissions-Policy header disabling camera, microphone and geolocation you do not use."),
}

JS_LIBS = [
    ("jquery", r"jquery[/-](\d+\.\d+\.\d+)", "npm"),
    ("bootstrap", r"bootstrap[/-](\d+\.\d+\.\d+)", "npm"),
    ("lodash", r"lodash[/-](\d+\.\d+\.\d+)", "npm"),
    ("moment", r"moment[/-](\d+\.\d+\.\d+)", "npm"),
    ("react", r"react[/-](\d+\.\d+\.\d+)", "npm"),
    ("vue", r"vue[/-](\d+\.\d+\.\d+)", "npm"),
    ("angular", r"angular[/-](\d+\.\d+\.\d+)", "npm"),
]


def verify_finding(finding: dict) -> dict:
    """Re-check one imported finding live. Evidence is a fresh fetch."""
    url = finding.get("source_url") or ""
    if not url.startswith(("http://", "https://")):
        return {"finding_id": finding.get("id"), "status": "no-url",
                "note": "finding has no fetchable source URL to verify"}
    try:
        res = fetch_url(url)
    except SSRFBlocked as e:
        return {"finding_id": finding.get("id"), "status": "blocked",
                "evidence": str(e)}
    if res.get("error"):
        return {"finding_id": finding.get("id"), "status": "fetch-error",
                "evidence": res["error"]}
    return {"finding_id": finding.get("id"), "plugin": finding.get("plugin"),
            "status": "live" if res["status"] == 200 else f"http-{res['status']}",
            "evidence": f"GET {res['url']} -> {res['status']}, "
                        f"{res['bytes']} bytes, snippet: {res['text_snippet'][:200]}"}


def osv_lookup(package: str, version: str, ecosystem: str = "npm") -> list[dict]:
    """Public OSV advisory lookup, keyless. Returns [{id, summary}]."""
    try:
        with http_client(20) as c:
            r = c.post("https://api.osv.dev/v1/query",
                       json={"package": {"name": package, "ecosystem": ecosystem},
                             "version": version})
        if r.status_code != 200:
            return []
        vulns = r.json().get("vulns", [])[:5]
        return [{"id": v.get("id", ""), "summary": v.get("summary", "")[:200]}
                for v in vulns]
    except Exception:
        return []


def analyze_target(url: str) -> dict:
    """Direct detectors for one target. Returns added findings with evidence."""
    try:
        res = fetch_url(url, snippet_chars=20000)
    except SSRFBlocked as e:
        return {"target": url, "error": str(e), "added_findings": []}
    if res.get("error"):
        return {"target": url, "error": res["error"], "added_findings": []}
    headers = res["headers"]
    body = res["text_snippet"]
    added: list[dict] = []

    for name, (title, fix) in HEADER_FIXES.items():
        if name not in headers:
            added.append({"kind": "header", "severity": "low", "title": title,
                          "evidence": f"GET {res['url']} -> {res['status']}; "
                                      f"response headers present: {', '.join(sorted(headers))[:300]}",
                          "fix": fix})

    for cookie in _split_cookies(headers.get("set-cookie", "")):
        flags = cookie.lower()
        missing = [f for f in ("secure", "httponly", "samesite") if f not in flags]
        if missing:
            # Name + flags only: the value after '=' is never printed.
            cname = cookie.split("=", 1)[0].strip() or "cookie"
            added.append({"kind": "cookie", "severity": "low",
                          "title": f"Cookie missing flags: {', '.join(missing)}",
                          "evidence": f"Set-Cookie: {cname}=*** (missing: {', '.join(missing)})",
                          "fix": "Set Secure, HttpOnly and SameSite=Lax on session cookies."})

    server = headers.get("server", "")
    if re.search(r"/\d", server):
        added.append({"kind": "version-disclosure", "severity": "low",
                      "title": f"Server header discloses version: {server[:120]}",
                      "evidence": f"Server: {server[:200]}",
                      "fix": "Strip the version from the Server header so attackers cannot target a known build."})

    for lib, pattern, eco in JS_LIBS:
        for m in re.finditer(pattern, body, re.IGNORECASE):
            version = m.group(1)
            vulns = osv_lookup(lib, version, eco)
            if vulns:
                added.append({"kind": "js-library", "severity": "medium",
                              "title": f"{lib} {version} has {len(vulns)} public advisories",
                              "evidence": f"matched {m.group(0)[:120]} in page; OSV: "
                                          f"{', '.join(v['id'] for v in vulns)}",
                              "fix": f"Upgrade {lib} past the fixed versions in those advisories, then re-scan."})
            break  # one report per library per page

    git = _git_exposure(url)
    if git:
        added.append(git)
    return {"target": url, "status": res["status"], "added_findings": added}


def _split_cookies(raw: str) -> list[str]:
    if not raw:
        return []
    # httpx joins repeated headers with commas; split conservatively.
    return [c.strip() for c in raw.split(",") if "=" in c]


def _git_exposure(url: str) -> dict | None:
    base = url.rstrip("/")
    try:
        res = fetch_url(base + "/.git/HEAD")
    except SSRFBlocked:
        return None
    if res.get("status") == 200 and "ref:" in res.get("text_snippet", ""):
        return {"kind": "exposed-git", "severity": "high",
                "title": "Exposed .git directory",
                "evidence": f"GET {base}/.git/HEAD -> 200, snippet: {res['text_snippet'][:120]}",
                "fix": "Block /.git/ at the web server or CDN and rotate anything that was ever committed."}
    return None


def expand_assets(url: str) -> dict:
    """Related assets: same-site links plus crt.sh subdomains for the domain."""
    try:
        res = fetch_url(url)
    except SSRFBlocked as e:
        return {"target": url, "error": str(e), "subdomains": [], "linked_hosts": []}
    host = urllib.parse.urlparse(url).hostname or ""
    links = set(re.findall(r'href=[\"\'](https?://[^\"\']+)', res.get("text_snippet", "")))
    linked = sorted({urllib.parse.urlparse(l).hostname for l in links if l} - {host, ""})
    subs: list[str] = []
    if host:
        try:
            with http_client(25) as c:
                r = c.get(f"https://crt.sh/?q=%25.{host}&output=json")
            if r.status_code == 200:
                names = set()
                for entry in r.json()[:200]:
                    for n in str(entry.get("name_value", "")).split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if n.endswith(host):
                            names.add(n)
                subs = sorted(names)[:50]
        except Exception:
            subs = []
    return {"target": url, "subdomains": subs, "linked_hosts": linked[:50]}
