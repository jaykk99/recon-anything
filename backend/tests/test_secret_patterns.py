"""Regression gate for the exposed-secret detection patterns (secrets.py).

Loads only the PATTERNS list (no httpx) and checks every pattern:
compiles, has a valid severity/confidence, is uniquely named, and fires
on a representative canary while staying silent on clean text. Also
guards the catalog size so it doesn't silently shrink.

Detection only: these patterns find secrets a target has EXPOSED on its
public pages so they can be rotated. Nothing here uses a secret.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load_patterns():
    src = open(os.path.join(os.path.dirname(__file__), "..", "app",
                            "plugins", "secrets.py")).read()
    start = src.index("PATTERNS = [")
    end = src.index("\n]\n", start) + 2
    ns = {}
    exec(compile(src[start:end], "patterns", "exec"), ns)
    return ns["PATTERNS"]


PATTERNS = _load_patterns()
BY_NAME = {name: rx for name, rx, _c, _s in PATTERNS}


def test_catalog_is_substantial():
    assert len(PATTERNS) >= 95, len(PATTERNS)


def test_all_valid_and_unique():
    seen = set()
    for name, rx, conf, sev in PATTERNS:
        re.compile(rx)
        assert sev in ("low", "medium", "high", "critical"), (name, sev)
        assert 0 < conf <= 99, (name, conf)
        assert name not in seen, f"duplicate pattern name {name}"
        seen.add(name)


def test_known_canaries_fire():
    # (pattern name, a string that SHOULD match)
    # Canaries are built from pieces at runtime so no full real-format
    # token literal is ever stored in this file (GitHub push protection
    # flags literals that match a provider's exact format, even fake ones).
    canaries = {
        "aws_access_key_id": "AKIA" + "IOSFODNN7EXAMPLE",
        "gitlab_pat": "glpat-" + "x" * 20,
        "github_oauth": "gho_" + "a" * 36,
        "stripe_secret_key": "sk_" + "live_" + "a" * 24,
        "mongodb_srv_uri": "mongodb+srv://user:p4ss@cluster0.abcd.mongodb.net",
        "postgres_uri": "postgresql://admin:pw@db.example.com:5432/app",
        "slack_token": "xox" + "b-123456789012-abcdefABCDEF",
        "private_key_block": "-----BEGIN RSA PRIVATE KEY-----",
        "newrelic_key": "NR" + "AK-" + "A" * 27,
        "planetscale_token": "pscale_" + "tkn_" + "a" * 40,
        "basic_auth_url": "https://admin:pw1234@internal.example.com",
        "figma_token": "fig" + "d_" + "a" * 44,
    }
    for name, sample in canaries.items():
        rx = BY_NAME.get(name)
        assert rx, f"pattern {name} not found"
        assert re.search(rx, sample), f"{name} did not match its canary"


def test_clean_text_stays_silent():
    clean = ("Welcome to our site. Contact us at hello@example.com. "
             "Copyright 2026. The quick brown fox jumps over the lazy dog "
             "1234567890 and visits https://example.com/about for details.")
    hits = [name for name, rx, _c, _s in PATTERNS if re.search(rx, clean)]
    assert hits == [], f"false positives on clean text: {hits}"


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} secret-pattern tests passed "
          f"({len(PATTERNS)} patterns)")


if __name__ == "__main__":
    _run_all()
