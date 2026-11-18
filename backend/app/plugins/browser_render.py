"""Headless-browser rendered discovery (the dynamic-surface pass).

Static recon (httpx) sees only the HTML the server ships. On a modern
SPA that is almost nothing - an empty <div id="root">, a bundle, and a
loader. The real attack surface (the API calls the app makes, the
routes it injects, the forms it builds) only exists AFTER JavaScript
runs. A human opens DevTools and watches the Network tab; this plugin
does the same with the pre-installed Chromium:

  1. Render the target in a real headless browser.
  2. Capture every same-site XHR/fetch/API request the page fires while
     it loads and settles (the live API surface).
  3. Read the POST-JS DOM for links, forms and script sources that were
     never in the static HTML.

Everything found is published to the discovery bus (endpoints, js_files,
subdomains, forms) so the finding-driven chaining and hunter expansion
act on it exactly as they do for statically-discovered assets - a
rendered /api/v1/users becomes an apidiscover/IDOR/param target, a
rendered subdomain gets the full web sweep.

Performance gate: rendering is expensive, so it only fires when it adds
value - when the static homepage looks like a JS app (a root mount
node, a framework marker, heavy script-to-text ratio). A content-rich
static page is left to the (cheaper) static crawlers. Detection only:
it navigates and observes; it never submits a form or sends a payload.
Heavy lane, active mode only, single page, hard wall-clock cap.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

RENDER_TIMEOUT_S = 25
SETTLE_MS = 2500          # let XHR/fetch fire after DOMContentLoaded
MAX_ENDPOINTS = 80
MAX_JS = 40
MAX_LINKS = 120

# path shapes that look like a real API/endpoint rather than a static asset
_API_PATH_RE = re.compile(
    r"/(?:api|v\d+|rest|graphql|gql|rpc|ajax|internal|admin|auth|oauth|"
    r"users?|accounts?|orders?|search|query|data|feed|webhook)\b", re.I)
_STATIC_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
               ".woff", ".woff2", ".ttf", ".ico", ".map", ".mp4", ".webm")

# markers that the static homepage is a JS app worth rendering
_SPA_MARKERS = (
    'id="root"', "id='root'", 'id="app"', "id='app'", 'id="__next"',
    "__NEXT_DATA__", "window.__NUXT__", "ng-version", "data-reactroot",
    "data-server-rendered", "svelte", "require('./", 'type="module"',
    "window.__INITIAL_STATE__", "vite/client",
)


def _same_site(url: str, root: str) -> bool:
    try:
        # hostname only - netloc carries the port (127.0.0.1:38475),
        # which must not defeat the same-site check.
        h = (urlparse(url).hostname or "").lower()
        return bool(h) and (h == root or h.endswith("." + root))
    except Exception:
        return False


def looks_like_spa(html: str) -> bool:
    """Heuristic: is this static HTML a JS app whose real surface only
    appears after render?"""
    if not html:
        return False
    low = html.lower()
    if any(m.lower() in low for m in _SPA_MARKERS):
        return True
    # script-heavy, text-light = client-rendered
    scripts = low.count("<script")
    # strip tags cheaply to estimate visible text
    visible = re.sub(r"<[^>]+>", " ", html)
    visible = re.sub(r"\s+", " ", visible).strip()
    return scripts >= 3 and len(visible) < 2000


class BrowserRenderPlugin(Plugin):
    id = "browser_render"
    label = "Headless Browser Rendered Discovery"
    accepts = ["domain", "url"]
    passive = False           # drives a real browser
    cost = Cost.FREE
    group = "web"
    phase = 1                 # discoveries feed phase-2 + chaining
    # Not heavy-lane: bounded to a single page in ~25s like the
    # screenshots plugin, so it runs in a normal active scan rather than
    # self-gating off behind a worker/offline opt-in.
    aggressive = False
    timeout_s = 40
    description = ("Renders a JS/SPA target in headless Chromium and "
                   "captures the live API calls and post-JS DOM that "
                   "static fetching never sees, feeding them to chaining.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if self.module_mode(ctx) == "passive":
            return self._skipped("passive mode: browser render drives a "
                                 "real browser (active mode only)")

        if target.type == "url":
            base = target.normalized
        else:
            domain = domain_from_target(target.type, target.normalized)
            if not domain:
                return self._skipped("no host for this target type")
            base = f"https://{domain}"
        root = urlparse(base).netloc.lower().split(":")[0]

        # Performance gate: only render when the static page is a JS app.
        page_data = await ctx.fetch_page(base, timeout=10)
        static_html = (page_data or {}).get("text", "") if page_data else ""
        if static_html and not looks_like_spa(static_html):
            return self._ok([], "static/content-rich page - browser render "
                                 "skipped (static crawlers cover it)")

        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception:
            return self._ok([], "playwright not installed - browser render "
                                 "skipped (pip install playwright && "
                                 "playwright install chromium to enable)")

        endpoints: Set[str] = set()
        js_files: Set[str] = set()
        links: Set[str] = set()

        def on_request(req) -> None:
            try:
                u = req.url
                rtype = req.resource_type
            except Exception:
                return
            if not u.startswith(("http://", "https://")):
                return
            if not _same_site(u, root):
                return
            path = urlparse(u).path.lower()
            if rtype in ("xhr", "fetch") or _API_PATH_RE.search(path):
                if not path.endswith(_STATIC_EXT):
                    endpoints.add(u.split("#")[0])
            elif rtype == "script" or path.endswith(".js"):
                js_files.add(u.split("#")[0])

        try:
            async with async_playwright() as pw:
                from ..browser import launch_chromium
                try:
                    browser = await launch_chromium(pw, headless=True)
                except Exception as e:
                    return self._degraded(f"browser launch failed: "
                                          f"{str(e)[:120]}")
                try:
                    page = await browser.new_page(
                        viewport={"width": 1280, "height": 900})
                    page.on("request", on_request)
                    deadline_ms = max(
                        3000, int((RENDER_TIMEOUT_S
                                   - (time.monotonic() - t0)) * 1000))
                    try:
                        await page.goto(base, timeout=deadline_ms,
                                        wait_until="domcontentloaded")
                    except Exception as e:
                        await browser.close()
                        return self._degraded(f"render navigation failed: "
                                              f"{str(e)[:120]}")
                    # let the app fire its XHR/fetch and inject routes
                    try:
                        await page.wait_for_timeout(SETTLE_MS)
                    except Exception:
                        pass
                    # post-JS DOM: links, forms, scripts
                    try:
                        dom = await asyncio.wait_for(page.evaluate(
                            """() => ({
                                links: Array.from(document.querySelectorAll('a[href]')).map(a => a.href),
                                scripts: Array.from(document.querySelectorAll('script[src]')).map(s => s.src),
                                forms: Array.from(document.querySelectorAll('form')).map(f => ({
                                    action: f.action || '', method: (f.method||'get').toLowerCase(),
                                    inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(i => i.name||i.id||'').filter(Boolean)
                                }))
                            })"""), timeout=6)
                    except Exception:
                        dom = {}
                finally:
                    try:
                        await browser.close()
                    except Exception:
                        pass
        except Exception as e:
            return self._degraded(f"browser render error: {str(e)[:120]}")

        forms = dom.get("forms", []) if isinstance(dom, dict) else []
        for href in (dom.get("links", []) if isinstance(dom, dict) else []):
            if isinstance(href, str) and href.startswith(("http://", "https://")):
                links.add(href.split("#")[0])
                if _same_site(href, root) and _API_PATH_RE.search(
                        urlparse(href).path.lower()):
                    endpoints.add(href.split("#")[0])
        for s in (dom.get("scripts", []) if isinstance(dom, dict) else []):
            if isinstance(s, str) and s.startswith(("http://", "https://")) \
                    and _same_site(s, root):
                js_files.add(s.split("#")[0])

        # --- publish to the discovery bus so chaining/expansion act ----
        findings: List[Finding] = []
        for ep in sorted(endpoints)[:MAX_ENDPOINTS]:
            ctx.publish("endpoints", ep)
            findings.append(self._f(
                "api", "rendered_endpoint", ep,
                source="headless browser (live XHR/fetch + DOM)",
                source_url=ep, confidence=80, passive=False,
                evidence={"severity": "low", "discovered_by": "browser_render",
                          "remediation": (
                              "Endpoint exposed only after JS render. Audit it "
                              "for authentication and object-level access "
                              "control like any API route.")}))
        for jf in sorted(js_files)[:MAX_JS]:
            ctx.publish("js_files", jf)
        for host in {urlparse(u).netloc.lower().split(":")[0] for u in links}:
            if host and host != root and host.endswith("." + root):
                ctx.publish("subdomains", host)
        n_forms = 0
        for f in forms:
            if not isinstance(f, dict):
                continue
            action = str(f.get("action") or base)
            n_forms += 1
            findings.append(self._f(
                "web", "rendered_form", action,
                source="headless browser (post-JS DOM)",
                source_url=action, confidence=70, passive=False,
                evidence={"severity": "low", "method": f.get("method", "get"),
                          "inputs": f.get("inputs", []),
                          "remediation": (
                              "Dynamically-rendered form. Test its inputs for "
                              "injection and its endpoint for authz.")}))
            if n_forms >= 15:
                break

        if endpoints or js_files or n_forms:
            findings.insert(0, self._f(
                "web", "spa_rendered",
                f"JS app rendered: {len(endpoints)} live endpoints, "
                f"{len(js_files)} scripts, {n_forms} forms recovered that "
                f"static fetching missed",
                source="headless browser", source_url=base,
                confidence=85, passive=False,
                evidence={"severity": "low",
                          "remediation": (
                              "The target is a client-rendered app; its real "
                              "surface is the captured endpoints, not the "
                              "static HTML. Ensure every one enforces auth.")}))

        res = self._ok(findings,
                       f"rendered {base}: {len(endpoints)} endpoints, "
                       f"{len(js_files)} scripts, {n_forms} forms")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
