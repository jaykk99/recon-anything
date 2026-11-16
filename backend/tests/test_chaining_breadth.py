"""Finding-driven chaining breadth + mode gating.

These lock in the "run like a human" behaviour: a broad set of common,
real finding keys must each pivot to the detection plugins an operator
would run next, every plugin named must exist in the registry, and the
aggressive injection probes must be withheld in passive mode.

Pure functions of their inputs - no network, no DB.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.hunters.chaining import (  # noqa: E402
    _AGGRESSIVE, _signal_plugins, plan_chains)
from app.plugins.registry import discover  # noqa: E402


def _pids(key, value, mode="active"):
    return [p for _s, p in _signal_plugins(key, value, mode)]


# (finding key, value, at least these plugin ids must be chained)
CASES = [
    ("server_header", "nginx/1.18.0", {"cves", "nuclei_cve_pack"}),
    ("tech", "WordPress 5.2", {"cms_probes", "cves", "wpscan_scan"}),
    ("tech", "Cloudflare", {"reverse_ip", "favicon_hash"}),
    ("port_open", "8080/tcp open http", {"banners", "port_scan",
                                         "webtech", "headers"}),
    ("email_found", "a@example.com", {"email_breach", "breachwatch",
                                      "email_infra"}),
    ("param_reflected", "q", {"xss"}),
    ("param_accepted", "id", {"sqli", "param_fuzzer", "idor"}),
    ("open_directory", "/backups/", {"dirsearch", "backup", "secrets"}),
    ("robots_disallow", "/admin/", {"hiddenpaths", "dirsearch"}),
    ("interesting_form", "login", {"auth", "param_fuzzer"}),
    ("graphql_endpoint", "/graphql", {"graphql", "graphql_deep",
                                      "apidiscover"}),
    ("cors_wildcard", "*", {"cors", "jwt_audit", "endpointauth"}),
    ("redirect_off_domain", "evil.com", {"ssrf"}),
    ("s3_public_read", "b", {"cloud_buckets", "s3", "cloud_enum"}),
    ("outdated_software", "Apache 2.4.29", {"cves", "nuclei_cve_pack"}),
    ("sourcemap_exposed", "app.js.map", {"sourcemap", "jsdeep",
                                         "js_secrets"}),
    ("hidden_api_endpoint", "/api/v1/users", {"apidiscover", "bola",
                                              "idor", "param_fuzzer"}),
    ("jwt_alg_none", "eyJ...", {"jwt", "jwt_audit"}),
    ("git_exposed", "/.git/", {"gitleaks_scan", "git"}),
    ("phpinfo_exposed", "/phpinfo.php", {"error_pages", "infodisclosure"}),
]


def test_each_signal_chains_expected_plugins():
    for key, value, expected in CASES:
        got = set(_pids(key, value, "active"))
        missing = expected - got
        assert not missing, f"{key}={value}: missing chains {missing}"


def test_every_chained_plugin_id_exists_in_registry():
    reg = set(discover().keys())
    seen = set()
    for key, value, _exp in CASES:
        seen.update(_pids(key, value, "active"))
    # also sweep the tech/CDN/login value branches
    for v in ("Drupal 9", "GraphQL", "okta login", "akamai", "v2.3.1"):
        seen.update(_pids("tech", v, "active"))
    unknown = {p for p in seen if p not in reg}
    assert not unknown, f"chaining names non-existent plugins: {unknown}"


def test_passive_mode_withholds_aggressive_probes():
    # A passive run must never chain an aggressive injection probe.
    for key, value in [("param_reflected", "q"), ("param_accepted", "id"),
                       ("redirect_off_domain", "x"),
                       ("hidden_api_endpoint", "/a"),
                       ("interesting_form", "login")]:
        passive = set(_pids(key, value, "passive"))
        assert not (passive & _AGGRESSIVE), (
            f"{key} chained aggressive probes in passive mode: "
            f"{passive & _AGGRESSIVE}")


def test_active_mode_includes_aggressive_probes():
    active = set(_pids("param_accepted", "id", "active"))
    assert active & _AGGRESSIVE, "active mode should allow aggressive chains"


def test_breadth_regression_floor():
    # Guard against a future edit quietly narrowing the map back down:
    # count the distinct finding keys that produce at least one chain.
    keys = [
        "server_header", "tech", "x_powered_by", "port_open", "tcp_banner",
        "http_banner", "outdated_software", "email_found", "email_pattern",
        "param_accepted", "param_reflected", "open_directory",
        "dir_brute_hit", "hidden_endpoint", "discovered_path",
        "robots_disallow", "interesting_form", "form_inventory",
        "graphql_endpoint", "graphql_introspection", "cors_wildcard",
        "cors_reflect", "redirect_off_domain", "s3_public_read",
        "cloud_bucket_ref", "sourcemap_exposed", "source_map", "js_endpoint",
        "hidden_api_endpoint", "openapi_paths", "api_docs", "jwt_alg_none",
        "git_exposed", "phpinfo_exposed", "subdomain_takeover",
        "exposed_env", "js_secret",
    ]
    firing = [k for k in keys if _pids(k, "x", "active")]
    assert len(firing) >= 30, (
        f"only {len(firing)} keys chain; the map regressed "
        f"(non-firing: {[k for k in keys if k not in firing]})")


class _F:
    def __init__(self, tid, key, value, sev="medium", bounty="low"):
        self.target_id = tid
        self.key = key
        self.value = value
        self.evidence = {"severity": sev}
        self.bounty_value = bounty


class _T:
    def __init__(self, tid, norm):
        self.id = tid
        self.normalized = norm
        self.type = "domain"


def test_plan_chains_groups_by_target_and_respects_mode():
    tgts = [_T("t1", "a.example.com")]
    finds = [
        _F("t1", "tech", "WordPress 5.8"),
        _F("t1", "param_reflected", "q"),
        _F("t1", "email_found", "a@example.com"),
    ]
    plan_a, hot_a, sig_a = plan_chains(finds, tgts, mode="active")
    plan_p, _hot_p, _sig_p = plan_chains(finds, tgts, mode="passive")
    assert "wpscan_scan" in plan_a["t1"]
    assert "xss" in plan_a["t1"]          # reflected param -> XSS (active)
    assert "xss" not in plan_p.get("t1", [])   # withheld in passive
    assert "email_breach" in plan_p["t1"]      # passive-safe chain stays
    # a finding for an unknown target produces no plan entry
    assert plan_chains([_F("ghost", "tech", "WordPress")], tgts)[0] == {}
