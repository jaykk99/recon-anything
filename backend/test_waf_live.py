"""Live WAF comparison: Cloudflare-protected site vs non-protected site.

Run from backend/:  python3 test_waf_live.py
Makes a few ordinary GET requests (like a browser loading a homepage) -
no attack payloads, no challenge solving. Compares limiter behavior:
WAF host -> vendor attributed, graceful mode only if it fights back;
clean host -> untouched.
"""
import asyncio
import sys
import time

import httpx

sys.path.insert(0, ".")

from app import config, net
from app.ratelimit import RateLimiter, fetch
from app.waf import classify_response

WAF_TARGET = "https://www.cloudflare.com"   # Cloudflare-protected
CRYPTO_TARGET = "https://crypto.com"        # Cloudflare-protected (Jay's problem target)
CLEAN_TARGET = "https://example.com"        # no WAF


async def probe(client, limiter, url, n=3):
    verdicts = []
    for _ in range(n):
        r = await fetch(client, limiter, "GET", url, timeout=20,
                        follow_redirects=True)
        v = classify_response(r)
        verdicts.append((r.status_code, v.kind, v.vendor))
    return verdicts


async def main():
    limiter = RateLimiter(default_rps=config.DEFAULT_RPS)
    print(f"default_rps={limiter.default_rps}  UA={config.USER_AGENT}")
    async with net.async_client(headers={"User-Agent": config.USER_AGENT},
                                timeout=20, follow_redirects=True) as client:
        for name, url in [("WAF (cloudflare.com)", WAF_TARGET),
                          ("WAF (crypto.com)", CRYPTO_TARGET),
                          ("clean (example.com)", CLEAN_TARGET)]:
            t0 = time.monotonic()
            try:
                vs = await probe(client, limiter, url)
            except Exception as e:
                print(f"{name}: request failed: {e}")
                continue
            dt = time.monotonic() - t0
            from urllib.parse import urlparse
            host = urlparse(url).netloc
            st = limiter.waf_stats(host)
            for status, kind, vendor in vs:
                print(f"  {name}: {url} -> {status} kind={kind} vendor={vendor}")
            print(f"  limiter[{host}]: active={st['active']} vendor={st['vendor']} "
                  f"blocked={st['blocked']} succeeded={st['succeeded']} "
                  f"rps={limiter._rps.get(host, limiter.default_rps)} "
                  f"({dt:.1f}s for {len(vs)} reqs)")
    print("done")


if __name__ == "__main__":
    asyncio.run(main())
