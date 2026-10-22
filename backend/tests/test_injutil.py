"""Tests for injutil.same_domain / host_of.

Regression: plugins compared urlparse().netloc (which includes ":port")
against the bare domain, so every same-domain asset on a non-default
port was silently dropped - js_secrets found 0 JS bundles on
localhost:port targets (false-neg run 2026-10-22: N01/N02 missed).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins.injutil import host_of, same_domain  # noqa: E402


def test_host_of_strips_port():
    assert host_of("http://127.0.0.1:8471/static/app.js") == "127.0.0.1"
    assert host_of("https://sub.example.com:8443/x") == "sub.example.com"
    assert host_of("https://example.com/x") == "example.com"
    assert host_of("not a url") == ""


def test_same_domain_exact_and_port():
    assert same_domain("http://127.0.0.1:8471/static/app.js", "127.0.0.1")
    assert same_domain("https://example.com:8443/x", "example.com")
    assert same_domain("https://example.com/x", "example.com")


def test_same_domain_subdomain():
    assert same_domain("https://a.b.example.com/x", "example.com")


def test_same_domain_rejects_off_target():
    assert not same_domain("https://evil.com/?next=example.com",
                            "example.com")
    assert not same_domain("https://notexample.com/", "example.com")
    assert not same_domain("https://example.com.evil.com/", "example.com")
    assert not same_domain("not a url", "example.com")
    assert not same_domain("", "example.com")
