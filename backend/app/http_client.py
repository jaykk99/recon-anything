import os
import httpx

DEFAULT_HEADERS = {
    "User-Agent": "recon-pipeline/1.0 (+internal-audit)",
    "Accept": "application/json, text/plain, */*",
}


def sanitize_no_proxy() -> None:
    """Strip IPv6 CIDR/bracket entries in NO_PROXY that crash httpx."""
    raw = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    if not raw:
        return
    cleaned = [
        entry.strip()
        for entry in raw.split(",")
        if entry.strip() and ":" not in entry
    ]
    val = ",".join(cleaned)
    os.environ["NO_PROXY"] = val
    os.environ["no_proxy"] = val


def get_http_client(timeout: float = 15.0) -> httpx.Client:
    sanitize_no_proxy()
    return httpx.Client(
        timeout=httpx.Timeout(timeout, connect=5.0),
        headers=DEFAULT_HEADERS,
        follow_redirects=True,
    )
