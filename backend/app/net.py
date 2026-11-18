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

import os
from typing import Optional
from urllib.parse import urlparse

import httpx

from .rpc_guard import assert_payload_read_only, RpcWriteBlocked

try:  # json is stdlib; the try is only to keep import-order robust
    import json as _json
except Exception:  # pragma: no cover
    _json = None


# Read-only transport hardblock. This is NOT an egress restriction - it
# blocks no host, port or scheme, so the "reach anything" rule above still
# holds. It refuses one thing: a JSON-RPC request whose method would
# broadcast a transaction or sign with a key. ReconAnything reads chain
# state and never writes it; enforcing that here, on the shared HTTP client,
# means no plugin can broadcast even if it tries to build the request itself.
def _rpc_body_is_write(content: bytes) -> bool:
    if not content or b'"method"' not in content or _json is None:
        return False
    try:
        payload = _json.loads(content)
    except Exception:
        return False
    try:
        assert_payload_read_only(payload)
    except RpcWriteBlocked:
        return True
    return False


def _guard_request_sync(request: "httpx.Request") -> None:
    if request.method == "POST" and _rpc_body_is_write(request.content):
        raise RpcWriteBlocked(
            "blocked write/broadcast RPC request to "
            f"{request.url.host} (ReconAnything is read-only)")


async def _guard_request_async(request: "httpx.Request") -> None:
    _guard_request_sync(request)


def _merge_request_hook(kwargs: dict, hook) -> None:
    hooks = dict(kwargs.get("event_hooks") or {})
    existing = list(hooks.get("request") or [])
    existing.insert(0, hook)
    hooks["request"] = existing
    kwargs["event_hooks"] = hooks


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


# ---------------------------------------------------------------------------
# Proxy rotation (2026-11-14). One env proxy is fine for a single scan; a
# fleet or a hostile target wants a pool. RECON_PROXY_URLS takes a
# comma-separated list and each new HTTP client gets the next healthy entry
# (round-robin). A proxy that fails at the transport level is put on a
# cooldown instead of being handed out again, so one dead exit node cannot
# fail every plugin. Rotation is per CLIENT (per plugin invocation), which
# keeps each request inside one connection pool - per-request rotation would
# defeat keep-alive and look worse to a WAF, not better.
PROXY_COOLDOWN_S = float(os.environ.get("RECON_PROXY_COOLDOWN_S", "60"))
_PROXY_STATE: dict = {"index": 0, "down": {}}


def proxy_pool() -> list:
    """Configured rotation pool (RECON_PROXY_URLS), empty when unset."""
    raw = os.environ.get("RECON_PROXY_URLS") or ""
    return [u.strip() for u in raw.split(",") if u.strip()]


def _proxy_is_down(url: str) -> bool:
    import time as _time
    until = _PROXY_STATE["down"].get(url, 0.0)
    return until > _time.monotonic()


def select_proxy() -> Optional[str]:
    """Next proxy for a new client: rotated pool entry, else env proxy.

    Deterministic round-robin over healthy entries. When every entry is
    cooling down after a failure, the one whose cooldown expires first is
    used anyway (fail open to the environment instead of to no egress).
    """
    pool = proxy_pool()
    if not pool:
        return egress_proxy()
    for _ in range(len(pool)):
        url = pool[_PROXY_STATE["index"] % len(pool)]
        _PROXY_STATE["index"] = (_PROXY_STATE["index"] + 1) % len(pool)
        if not _proxy_is_down(url):
            return url
    return pool[_PROXY_STATE["index"] % len(pool)]


def note_proxy_failure(url: Optional[str]) -> None:
    """Put a proxy on cooldown after a transport-level failure."""
    if not url:
        return
    import time as _time
    _PROXY_STATE["down"][url] = _time.monotonic() + max(1.0, PROXY_COOLDOWN_S)


def proxy_state() -> dict:
    """Rotation observability: pool size, current index, cooling entries."""
    return {"pool": len(proxy_pool()), "index": _PROXY_STATE["index"],
            "cooling": [u for u in _PROXY_STATE["down"] if _proxy_is_down(u)]}


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


def _mount_host(host: str) -> str | None:
    """Normalize a NO_PROXY entry into an httpx-mountable host, or None."""
    if host == "*":
        return None
    # strip a leading dot (".example.com" convention); exact-host matching
    # is what httpx mounts provide.
    key_host = host[1:] if host.startswith(".") else host
    if not key_host or "/" in key_host or " " in key_host:
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
    if "transport" in kwargs:
        # A caller-supplied transport owns routing (e.g. a MockTransport
        # in tests). The egress proxy installs an all:// mount that would
        # shadow it, and the NO_PROXY direct mounts would too, so neither
        # is applied here. The RPC guard hook below still applies.
        pass
    else:
        kwargs.setdefault("proxy", egress_proxy())
        if "mounts" not in kwargs:
            direct = _direct_mounts()
            if direct:
                kwargs["mounts"] = direct
    kwargs.setdefault("trust_env", False)
    kwargs.setdefault("verify", ca_bundle())
    # Generous pool: the scan worker runs 32 plugin jobs concurrently
    # and time-based payloads hold connections open for seconds.
    kwargs.setdefault("limits", POOL_LIMITS)
    _merge_request_hook(kwargs, _guard_request_async)
    return httpx.AsyncClient(**kwargs)


def sync_client(**kwargs) -> httpx.Client:
    """httpx.Client with full, unrestricted egress configured."""
    if "transport" in kwargs:
        # Caller-supplied transport owns routing; see async_client.
        pass
    else:
        kwargs.setdefault("proxy", egress_proxy())
        if "mounts" not in kwargs:
            direct = _direct_mounts_sync()
            if direct:
                kwargs["mounts"] = direct
    kwargs.setdefault("trust_env", False)
    kwargs.setdefault("verify", ca_bundle())
    # Generous pool: the scan worker runs 32 plugin jobs concurrently
    # and time-based payloads hold connections open for seconds.
    kwargs.setdefault("limits", POOL_LIMITS)
    _merge_request_hook(kwargs, _guard_request_sync)
    return httpx.Client(**kwargs)
