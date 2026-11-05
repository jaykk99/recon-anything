"""Shared HTTP helper.

httpx.Client() with trust_env=True parses NO_PROXY into URL patterns, and
some environments hold bare IPv6 entries that crash that parse. So every
client in this app is built with trust_env=False and an explicit proxy URL
taken from the environment when one is set (direct connection otherwise).
The proxy URL itself is never logged or returned.
"""

from __future__ import annotations

import os

import httpx


def _proxy() -> str | None:
    return (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
        or None
    )


def client(timeout: float = 30) -> httpx.Client:
    return httpx.Client(timeout=timeout, trust_env=False, proxy=_proxy())
