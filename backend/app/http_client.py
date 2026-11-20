import os
import httpx

DEFAULT_HEADERS = {
    "User-Agent": "recon-pipeline/1.0 (+internal-audit)",
    "Accept": "application/json, text/plain, */*",
}


def sanitize_no_proxy() -> None:
    """Normalize NO_PROXY entries that crash httpx's env-proxy parser.

    Previously this dropped every entry containing ':' — which also
    dropped every legitimate IPv6 bypass host. It now delegates to
    app.net.sanitize_no_proxy_env(), which only rewrites the forms
    httpx chokes on (bracketed IPv6 like "[::1]", IPv6 CIDR like
    "::1/128") and keeps the rest, including unbracketed IPv6.
    """
    try:
        from .net import sanitize_no_proxy_env
    except Exception:
        return
    sanitize_no_proxy_env()


def get_http_client(timeout: float = 15.0) -> httpx.Client:
    sanitize_no_proxy()
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=5.0),
        headers=DEFAULT_HEADERS,
        follow_redirects=True,
    )
