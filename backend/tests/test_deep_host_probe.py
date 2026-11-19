"""Per-host deep probing: CORS verified not guessed, headers, and
content-verified exposures across live hosts."""
from app.deep_host_probe import (
    analyze_cors, analyze_security_headers, analyze_cookies,
    deep_probe_host, EVIL_ORIGIN)


# --- CORS (the real, verified version) ---------------------------------

def test_cors_reflect_origin_with_credentials_is_high():
    r = analyze_cors(EVIL_ORIGIN, {
        "Access-Control-Allow-Origin": EVIL_ORIGIN,
        "Access-Control-Allow-Credentials": "true"})
    assert r and r["severity"] == "high"


def test_cors_reflect_without_credentials_is_low():
    r = analyze_cors(EVIL_ORIGIN, {"Access-Control-Allow-Origin": EVIL_ORIGIN})
    assert r and r["severity"] == "low"


def test_cors_wildcard_no_credentials_is_not_a_finding():
    # This is the normal public-API config the old detector cried wolf on.
    assert analyze_cors(EVIL_ORIGIN, {"Access-Control-Allow-Origin": "*"}) is None


def test_cors_wildcard_with_credentials_flagged():
    r = analyze_cors(EVIL_ORIGIN, {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"})
    assert r and r["severity"] == "medium"


def test_cors_null_origin_with_credentials_is_high():
    r = analyze_cors(EVIL_ORIGIN, {
        "Access-Control-Allow-Origin": "null",
        "Access-Control-Allow-Credentials": "true"})
    assert r and r["severity"] == "high"


def test_cors_no_header_is_none():
    assert analyze_cors(EVIL_ORIGIN, {"Server": "nginx"}) is None


def test_cors_header_case_insensitive():
    r = analyze_cors(EVIL_ORIGIN, {
        "access-control-allow-origin": EVIL_ORIGIN,
        "ACCESS-CONTROL-ALLOW-CREDENTIALS": "true"})
    assert r and r["severity"] == "high"


# --- headers / cookies --------------------------------------------------

def test_security_headers_all_missing():
    missing = analyze_security_headers({"Server": "nginx"})
    assert len(missing) == 5


def test_security_headers_present_not_flagged():
    hdrs = {"Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer"}
    assert analyze_security_headers(hdrs) == []


def test_cookie_flags():
    issues = analyze_cookies({"Set-Cookie": "sid=abc; Path=/"})
    assert any("Secure" in i for i in issues)
    assert any("HttpOnly" in i for i in issues)


# --- orchestrator (fake fetch, no network) -----------------------------

def _fetch_factory(responses):
    """responses: dict path -> (status, headers, body)."""
    def fetch(url, headers):
        path = url.split(host_of(url), 1)[1] if host_of(url) in url else url
        # crude path extraction
        for p, resp in responses.items():
            if url.endswith(p):
                return resp
        return (404, {}, "")
    return fetch


def host_of(url):
    return url.split("://", 1)[1].split("/", 1)[0]


def test_deep_probe_finds_cors_and_exposed_env():
    responses = {
        "/": (200, {"Access-Control-Allow-Origin": EVIL_ORIGIN,
                    "Access-Control-Allow-Credentials": "true"}, "<html></html>"),
        "/.env": (200, {}, "DB_PASSWORD=s3cret\nAWS_SECRET_ACCESS_KEY=wJalr\n"),
    }
    out = deep_probe_host("api.example.com", _fetch_factory(responses))
    types = {f["type"] for f in out}
    assert "cors" in types
    assert any(f["type"] == "exposed_file" and f["severity"] == "critical"
               for f in out)


def test_deep_probe_spa_catchall_no_false_exposure():
    spa = (200, {}, "<!doctype html><html><body><div id=root></div></html>")
    responses = {p: spa for p in ("/", "/.env", "/.git/config", "/config.json")}
    out = deep_probe_host("spa.example.com", _fetch_factory(responses))
    # SPA returns 200+HTML for everything; no exposed_file should confirm
    assert not any(f["type"] == "exposed_file" for f in out)


def test_deep_probe_clean_host_only_header_gaps():
    responses = {"/": (200, {"Server": "nginx"}, "<html></html>")}
    out = deep_probe_host("www.example.com", _fetch_factory(responses))
    assert out and all(f["type"] == "security_header" for f in out)


def test_deep_probe_never_raises_on_fetch_error():
    def boom(url, headers): raise RuntimeError("conn reset")
    out = deep_probe_host("dead.example.com", boom)
    assert out == []
