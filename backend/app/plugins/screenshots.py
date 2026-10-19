"""Screenshot capture (EyeWitness-style): real headless-browser screenshots.

Captures actual rendered screenshots of the target and its discovered
subdomains so Jay can visually vet targets fast. Uses Playwright's
bundled Chromium in headless mode. If Playwright is not installed, the
plugin reports ok(0) with an install note - it NEVER fakes screenshots.

Phase 2: runs after discovery so it can screenshot subdomains found by
phase-1 plugins via the discovery bus.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

MAX_SHOTS = 8
SHOT_TIMEOUT_S = 20


class ScreenshotsPlugin(Plugin):
    id = "screenshots"
    label = "Screenshot Capture"
    accepts = ["domain", "url"]
    passive = False  # renders pages in a real browser
    cost = Cost.FREE
    group = "web"
    phase = 2
    description = ("Headless-browser screenshots of the target and discovered "
                   "subdomains for fast visual vetting.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            from playwright.async_api import async_playwright  # type: ignore
        except Exception:
            return self._ok(
                [], reason=("playwright not installed - screenshots skipped. "
                            "pip install playwright && playwright install "
                            "chromium to enable."))

        # --- collect URLs: target first, then discovered subdomains ---
        urls: List[str] = []
        seen = set()

        def add(u: str) -> None:
            u = u.strip().rstrip("/")
            if not u or u in seen:
                return
            seen.add(u)
            urls.append(u)

        if target.type == "url":
            add(target.normalized)
        else:
            domain = domain_from_target(target.type, target.normalized)
            if domain:
                add(f"https://{domain}")

        for sub in ctx.consume("subdomains"):
            if len(urls) >= MAX_SHOTS:
                break
            s = sub if isinstance(sub, str) else str(sub)
            s = s.strip().lower()
            if not s or "." not in s:
                continue
            if not s.startswith(("http://", "https://")):
                s = f"https://{s}"
            add(s)

        if not urls:
            return self._ok([], reason="no URLs to screenshot")

        out_dir = os.path.join(ctx.evidence_dir, "screenshots", ctx.run_id)
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            return self._degraded("could not create screenshot directory")

        findings: List[Finding] = []
        captured = 0
        failed = 0

        try:
            async with async_playwright() as pw:
                try:
                    browser = await pw.chromium.launch(
                        headless=True,
                        args=["--no-sandbox", "--disable-dev-shm-usage"],
                    )
                except Exception as e:
                    return self._degraded(f"browser launch failed: {e}")
                try:
                    page = await browser.new_page(
                        viewport={"width": 1280, "height": 800})
                    for u in urls[:MAX_SHOTS]:
                        # respect the runner's clock
                        if (time.monotonic() - t0) > 28:
                            break
                        host = urlparse(u).netloc or u
                        safe = "".join(
                            c if c.isalnum() or c in "-_." else "_"
                            for c in host)[:80]
                        path = os.path.join(out_dir, f"{safe}.png")
                        try:
                            await page.goto(
                                u, timeout=SHOT_TIMEOUT_S * 1000,
                                wait_until="domcontentloaded")
                            await page.wait_for_timeout(1200)
                            await page.screenshot(path=path, full_page=False)
                            captured += 1
                            findings.append(self._f(
                                "web", "screenshot_captured",
                                f"screenshot: {host}",
                                source="headless-chromium",
                                source_url=u,
                                confidence=95,
                                evidence={
                                    "severity": "low",
                                    "screenshot_path": path,
                                    "remediation": (
                                        "Visual reference only. Review the "
                                        "screenshot for exposed admin panels, "
                                        "debug banners, or staging markers."),
                                },
                                passive=False,
                            ))
                        except Exception:
                            failed += 1
                            continue
                finally:
                    try:
                        await browser.close()
                    except Exception:
                        pass
        except Exception as e:
            return self._degraded(f"screenshot run failed: {e}")

        reason = f"captured {captured}/{len(urls[:MAX_SHOTS])} screenshots"
        if failed:
            reason += f" ({failed} failed to load)"
        return self._ok(findings, reason=reason)
