"""Cookie security flags audit plugin.

Fetches the target's homepage and audits every Set-Cookie for the
Secure, HttpOnly and SameSite flags plus __Host-/__Secure- prefix
rules. Missing flags are honest, evidence-backed findings with the
exact cookie name and which flag is missing - no guessing.

Passive: one GET of the homepage (shared fetch_page cache), no state
changes, no auth.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, PluginStatus, Target


def _parse_set_cookies(headers) -> List[dict]:
    """Parse Set-Cookie headers into {name, value, attrs} dicts."""
    out = []
    for raw in headers.get_list("set-cookie") if hasattr(headers, "get_list") else []:
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs = {}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                attrs[k.strip().lower()] = v.strip()
            else:
                attrs[p.strip().lower()] = True
        out.append({"name": name, "attrs": attrs, "raw": raw})
    return out


class CookieSecurityPlugin(Plugin):
    id = "cookie_security"
    label = "Cookie Security Flags"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Audit Set-Cookie flags: Secure, HttpOnly, SameSite, "
                   "and __Host-/__Secure- prefix rules.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        is_https = urlparse(base).scheme == "https"

        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable, no cookies to audit")
        cookies = _parse_set_cookies(resp.headers)
        if not cookies:
            return self._skipped("no Set-Cookie headers on homepage")

        findings: List[Finding] = []
        names = {c["name"] for c in cookies}
        for c in cookies:
            name, attrs = c["name"], c["attrs"]
            low = name.lower()
            # __Host- prefix requires Secure + Path=/ + no Domain
            if low.startswith("__host-"):
                problems = []
                if "secure" not in attrs:
                    problems.append("missing Secure (required for __Host-)")
                if attrs.get("path") != "/":
                    problems.append("Path is not / (required for __Host-)")
                if "domain" in attrs:
                    problems.append("has Domain attr (forbidden for __Host-)")
                if problems:
                    findings.append(self._f(
                        "web", "cookie_host_prefix_violation",
                        f"__Host- cookie '{name}' violates prefix rules: "
                        + "; ".join(problems),
                        source="cookie flags audit",
                        source_url=base + "/",
                        confidence=95, passive=True,
                        evidence={"severity": "medium", "cookie": name,
                                  "problems": problems,
                                  "remediation": (
                                      f"Fix the '{name}' cookie: __Host- cookies "
                                      "must be Secure, Path=/, and carry no "
                                      "Domain attribute.")}))
                continue
            # __Secure- prefix requires Secure
            if low.startswith("__secure-") and "secure" not in attrs:
                findings.append(self._f(
                    "web", "cookie_secure_prefix_violation",
                    f"__Secure- cookie '{name}' missing Secure flag",
                    source="cookie flags audit", source_url=base + "/",
                    confidence=95, passive=True,
                    evidence={"severity": "medium", "cookie": name,
                              "remediation": (
                                  f"Add the Secure flag to the '{name}' cookie "
                                  "(__Secure- prefix requires it).")}))
                continue
            missing = []
            if is_https and "secure" not in attrs:
                missing.append("Secure")
            if "httponly" not in attrs:
                missing.append("HttpOnly")
            samesite = str(attrs.get("samesite", "")).lower()
            if samesite not in ("lax", "strict", "none"):
                missing.append("SameSite")
            elif samesite == "none" and "secure" not in attrs:
                missing.append("Secure (required with SameSite=None)")
            if missing:
                # Session-ish names are higher signal than analytics.
                sess = any(k in low for k in
                           ("sess", "session", "auth", "token", "login",
                            "sid", "jwt", "csrf", "xsrf"))
                findings.append(self._f(
                    "web", "cookie_flags_missing",
                    f"Cookie '{name}' missing: {', '.join(missing)}",
                    source="cookie flags audit", source_url=base + "/",
                    confidence=90, passive=True,
                    evidence={"severity": "medium" if sess else "low",
                              "cookie": name, "missing": missing,
                              "remediation": (
                                  f"Set {', '.join(missing)} on the '{name}' "
                                  "cookie (e.g. Set-Cookie: name=value; Secure; "
                                  "HttpOnly; SameSite=Lax).")}))

        # Duplicate cookie names across different paths = session fixation
        # smell; worth one note, not one finding per cookie.
        if len(names) < len(cookies):
            findings.append(self._f(
                "web", "cookie_name_collision",
                f"{len(cookies) - len(names)} duplicate cookie name(s) "
                "set on different paths",
                source="cookie flags audit", source_url=base + "/",
                confidence=70, passive=True,
                evidence={"severity": "low",
                          "remediation": ("Consolidate duplicate cookie names - "
                                          "overlapping names on different paths "
                                          "confuse session handling.")}))

        ctx.publish("cookies", [c["name"] for c in cookies])
        return PluginResult(plugin_id=self.id, status=PluginStatus.OK,
                            findings=findings,
                            duration_ms=int((time.monotonic() - t0) * 1000),
                            reason=f"audited {len(cookies)} cookies, "
                                   f"{len(findings)} findings")
