"""Unrestricted internet egress for ReconAnything.

Jay's rule: the app can reach anything on the internet. No artificial
restrictions. This module centralizes egress configuration so every HTTP
client in the app behaves the same:

- Proxy: honors HTTP_PROXY / HTTPS_PROXY (and lowercase) from the
  environment, unless it points at localhost (which would loop).
- NO_PROXY / no_proxy is honored per-host via transport mounts: loopback
  and listed hosts bypass the proxy with a direct transport (mounts take
  precedence over the proxy in httpx). Without this, targets like
  127.0.0.1 get blackholed by the egress proxy and every plugin silently
  degrades to zero findings - a false negative.
- NO_PROXY entries are normalized before any httpx client is built
  (sanitize_no_proxy_env): httpx's own env-proxy parser crashes at
  client construction on bracketed IPv6 entries ("[::1]") and on
  IPv6 CIDR ("::1/128") with InvalidURL, which killed the Solana
  program-account fetch outright (2026-11-20, Wrapped SOL scan).
  Brackets/CIDR are rewritten into the form httpx accepts; no host
  is ever dropped by the rewrite.
- TLS: uses the system CA bundle when present (the sandbox egress proxy
  re-signs TLS and certifi lacks its CA); otherwise default verification.
- trust_env=False is deliberate: proxy handling is explicit through
  egress_proxy(), not implicit. Direct connections work everywhere;
  Render has no egress allowlist.

There are no host, port, or scheme blocklists here. The only fetch
restriction in the app is the SSRF guard on the /fetch file-viewer
endpoint (main.py), which is a deliberate security boundary, not an
egress limitation.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Optional
from urllib.parse import urlparse

import httpx


# Connection pool sizing for the scan worker. The worker runs up to
# MAX_CONCURRENCY (32) plugin jobs at once, and time-based detection
# plugins (sqli/cmdi/rce SLEEP payloads) hold connections open for 5-6s
# while the target sleeps. With httpx's default 100-connection pool,
# quick plugins (git: 21 sub-second checks) starve behind the sleeping
# connections and hit their own timeout with zero findings - a false
# negative (seen 2026-10-22: git ran 0.5s solo, timed out at 60s under
# 32-job load). 400 connections comfortably covers 32 jobs x ~10
# in-flight requests each; the direct-mount transports get the same
# limits since NO_PROXY targets (localhost scans) use their own pools.
POOL_LIMITS = httpx.Limits(max_connections=400,
                           max_keepalive_connections=100)


def egress_proxy() -> Optional[str]:
    """Proxy URL from the environment, or None for direct egress."""
    p = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
         or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
         or None)
    if p:
        try:
            if (urlparse(p).hostname or "") in ("localhost", "127.0.0.1", "::1"):
                return None
        except Exception:
            return None
    return p


def ca_bundle():
    """System CA bundle path when present, else True (default verification)."""
    p = "/etc/ssl/certs/ca-certificates.crt"
    return p if os.path.isfile(p) else True


def no_proxy_hosts() -> list:
    """Hostnames from NO_PROXY / no_proxy (lowercased, brackets stripped)."""
    raw = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    hosts = []
    for entry in raw.split(","):
        e = entry.strip().lower().strip("[]")
        if e:
            hosts.append(e)
    return hosts


def _normalize_no_proxy_entry(entry: str) -> str | None:
    """Rewrite one NO_PROXY entry into a form httpx can parse, or None.

    httpx's env-proxy parser (get_environment_proxies) crashes at
    client construction on two shapes this sandbox's environment
    actually contains:
    - bracketed IPv6: "[::1]" -> it builds "all://*[::1]" and dies
      with InvalidURL "Invalid port: ':1]'".
    - IPv6 CIDR: "::1/128" -> same InvalidURL failure.
    Unbracketed IPv6 ("::1") and IPv4 CIDR ("192.168.0.0/16") parse
    fine and are left alone. Returns None only for entries that
    cannot be a host at all (empty, or a non-IP with a slash).
    """
    e = (entry or "").strip()
    if not e:
        return None
    # Strip one pair of surrounding brackets: "[::1]" -> "::1".
    if len(e) >= 2 and e.startswith("[") and e.endswith("]"):
        e = e[1:-1].strip()
        if not e:
            return None
    if "/" in e:
        host_part, _, _prefix = e.partition("/")
        try:
            ip = ipaddress.ip_address(host_part)
        except ValueError:
            return None
        if isinstance(ip, ipaddress.IPv6Address):
            # A /128 is a single host; any other IPv6 prefix cannot
            # be expressed as a mount or a no_proxy host, so keep the
            # bare address (bypassing that host beats crashing).
            e = host_part
        # IPv4 CIDR: keep "a.b.c.d/nn" as-is — httpx understands it.
    return e or None


def sanitize_no_proxy_env() -> bool:
    """Rewrite NO_PROXY / no_proxy in-process so httpx can parse them.

    Fixes the exact crash from the 2026-11-20 Wrapped SOL scan: the
    sandbox sets NO_PROXY to
    "localhost,127.0.0.1,::1,[::1],198.19.0.1,198.19.0.2,
    fd8b:4f84:7d32:99::1,[fd8b:4f84:7d32:99::1],..." and any
    httpx client built with the default trust_env=True dies in
    get_environment_proxies before the first request. Normalizing
    here protects every httpx client in the process, including bare
    httpx.AsyncClient(...) calls that never go through net.async_client.
    Idempotent; returns True when either variable changed. No host
    is dropped except entries that cannot be a host at all.
    """
    changed = False
    for key in ("NO_PROXY", "no_proxy"):
        raw = os.environ.get(key)
        if not raw:
            continue
        seen: set = set()
        cleaned = []
        for entry in raw.split(","):
            norm = _normalize_no_proxy_entry(entry)
            if norm and norm.lower() not in seen:
                seen.add(norm.lower())
                cleaned.append(norm)
        val = ",".join(cleaned)
        if val != raw:
            os.environ[key] = val
            changed = True
    return changed


def _mount_host(host: str) -> str | None:
    """Normalize a NO_PROXY entry into an httpx-mountable host, or None."""
    if host == "*":
        return None
    # strip a leading dot (".example.com" convention); exact-host matching
    # is what httpx mounts provide.
    key_host = host[1:] if host.startswith(".") else host
    if not key_host or "/" in key_host or " " in key_host:
        return None
    # host:port (exactly one colon, numeric port): mounts are per-host,
    # the port is meaningless here, so mount the bare host. Do NOT
    # bracket it — "[localhost:8080]" is not a valid IPv6 literal and
    # httpx dies building the mount (InvalidURL, seen 2026-11-20).
    if key_host.count(":") == 1:
        h, _, port = key_host.partition(":")
        if h and port.isdigit():
            return h
        return None
    if ":" in key_host and not key_host.startswith("["):
        key_host = f"[{key_host}]"  # IPv6 literal needs brackets in a URL
    return key_host


def _direct_mounts() -> dict:
    """httpx mounts that bypass the proxy for NO_PROXY hosts.

    Mounts take precedence over the proxy setting in httpx, so loopback
    and explicitly listed hosts always get a direct transport. Only
    exact hostnames/IPs are mounted (no wildcard expansion).
    """
    mounts = {}
    for host in no_proxy_hosts():
        key_host = _mount_host(host)
        if not key_host:
            continue
        for scheme in ("http", "https"):
            mounts[f"{scheme}://{key_host}"] = httpx.AsyncHTTPTransport(
                limits=POOL_LIMITS)
    return mounts


def _direct_mounts_sync() -> dict:
    mounts = {}
    for host in no_proxy_hosts():
        key_host = _mount_host(host)
        if not key_host:
            continue
        for scheme in ("http", "https"):
            mounts[f"{scheme}://{key_host}"] = httpx.HTTPTransport(
                limits=POOL_LIMITS)
    return mounts


async def web_base(ctx, target, domain: str) -> str:
    """Scheme-aware base URL for web plugins (P0 false-negative fix).

    - url target: the URL exactly as given (scheme preserved).
    - domain target: prefer https, fall back to http when https is
      unreachable at the transport level (connection refused, TLS
      failure, DNS, timeout). HTTP-only sites (e.g. demo.testfire.net)
      otherwise degrade every plugin to zero findings.

    The resolved scheme is cached per run+domain in ctx.shared so the
    probe costs one HEAD request per domain per run, not per plugin.
    A 405/501 on HEAD is retried with GET; HTTP error statuses do NOT
    trigger fallback (the server speaks TLS, so https is correct).
    """
    if target.type != "domain":
        return target.normalized
    cache_key = f"_webscheme:{domain.lower()}"
    hit = ctx.shared.get(cache_key)
    if isinstance(hit, str) and hit:
        return hit
    from .ratelimit import fetch as _fetch
    base = f"https://{domain}"
    try:
        r = await _fetch(ctx.http, ctx.limiter, "HEAD", base, timeout=10,
                         follow_redirects=True, max_retries=1)
        if r.status_code in (405, 501):
            await _fetch(ctx.http, ctx.limiter, "GET", base, timeout=10,
                         follow_redirects=True, max_retries=1)
    except Exception:
        base = f"http://{domain}"
    ctx.shared[cache_key] = base
    return base


def async_client(**kwargs) -> httpx.AsyncClient:
    """httpx.AsyncClient with full, unrestricted egress configured."""
    sanitize_no_proxy_env()
    kwargs.setdefault("proxy", egress_proxy())
    kwargs.setdefault("trust_env", False)
    kwargs.setdefault("verify", ca_bundle())
    # Generous pool: the scan worker runs 32 plugin jobs concurrently
    # and time-based payloads hold connections open for seconds.
    kwargs.setdefault("limits", POOL_LIMITS)
    if "mounts" not in kwargs:
        direct = _direct_mounts()
        if direct:
            kwargs["mounts"] = direct
    return httpx.AsyncClient(**kwargs)


def sync_client(**kwargs) -> httpx.Client:
    """httpx.Client with full, unrestricted egress configured."""
    sanitize_no_proxy_env()
    kwargs.setdefault("proxy", egress_proxy())
    kwargs.setdefault("trust_env", False)
    kwargs.setdefault("verify", ca_bundle())
    # Generous pool: the scan worker runs 32 plugin jobs concurrently
    # and time-based payloads hold connections open for seconds.
    kwargs.setdefault("limits", POOL_LIMITS)
    if "mounts" not in kwargs:
        direct = _direct_mounts_sync()
        if direct:
            kwargs["mounts"] = direct
    return httpx.Client(**kwargs)


# Normalize NO_PROXY at import: any httpx client built in this process
# (including bare httpx.AsyncClient(...) in plugins) reads these vars
# through httpx's trust_env path, and bracketed IPv6 / IPv6-CIDR
# entries crash its parser before the first request (2026-11-20,
# Wrapped SOL scan). Runs once, is idempotent, and never drops a
# host — brackets/CIDR are only rewritten into the form httpx accepts.
try:
    sanitize_no_proxy_env()
except Exception:
    pass
