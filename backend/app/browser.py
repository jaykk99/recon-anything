"""Resilient headless-Chromium launch, shared by the browser plugins.

Playwright normally bundles a Chromium build and `chromium.launch()`
finds it. But environments drift: a container may ship the browser at a
pinned path that doesn't match the Python package's expected version
(seen here - the package wanted build 1255, the image had 1243), and
then the default launch fails with "Executable doesn't exist" even
though a perfectly good Chromium is present. When that happens the
browser plugins silently degrade to "launch failed" and the whole
dynamic-surface / screenshot capability goes dark.

launch_chromium() tries the default first (the production happy path),
then falls back to an explicit executable: RECON_CHROMIUM_PATH if set,
then the common pre-installed locations. It raises only when no Chromium
can be launched at all, so callers keep their existing degraded-note
behaviour.
"""
from __future__ import annotations

import glob
import os
from typing import List

_DEFAULT_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"]


def _candidate_paths() -> List[str]:
    """Explicit chromium executables to try, best-guess first."""
    out: List[str] = []
    env = os.environ.get("RECON_CHROMIUM_PATH")
    if env:
        out.append(env)
    # Playwright's pre-installed browsers dir on this platform.
    base = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
    # real chrome binaries nested under chromium-*/chrome-linux/chrome
    for pat in (
        f"{base}/chromium-*/chrome-linux/chrome",
        f"{base}/chromium-*/chrome-linux64/chrome",
        f"{base}/chromium_headless_shell-*/chrome-headless-shell-linux64/"
        "chrome-headless-shell",
        f"{base}/chromium/chrome-linux/chrome",
        f"{base}/chromium",
    ):
        out.extend(sorted(glob.glob(pat), reverse=True))
    # system chromium as a last resort
    for p in ("/usr/bin/chromium", "/usr/bin/chromium-browser",
              "/usr/bin/google-chrome"):
        if os.path.exists(p):
            out.append(p)
    # de-dup preserving order
    seen = set()
    uniq = []
    for p in out:
        if p and p not in seen and os.path.exists(p):
            seen.add(p)
            uniq.append(p)
    return uniq


async def launch_chromium(pw, *, headless: bool = True,
                          extra_args: List[str] | None = None):
    """Launch headless Chromium, resilient to a non-default browser path.

    `pw` is the object yielded by `async_playwright()`. Returns a Browser;
    raises the last error if nothing launches.
    """
    args = list(_DEFAULT_ARGS)
    if extra_args:
        args.extend(extra_args)
    last_err: Exception | None = None
    # 1) the default bundled browser (production happy path)
    try:
        return await pw.chromium.launch(headless=headless, args=args)
    except Exception as e:  # noqa: BLE001
        last_err = e
    # 2) explicit fallbacks
    for path in _candidate_paths():
        try:
            return await pw.chromium.launch(
                headless=headless, executable_path=path, args=args)
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue
    raise last_err or RuntimeError("no launchable chromium found")
