"""Unit gate for the attack-path correlation engine (app/correlate.py).

Pure-stdlib: runs without fastapi/sqlalchemy/httpx, so it works in any
environment. Run directly (`python tests/test_correlate.py`) or under
pytest. Checks that:
  * each rule fires on a realistic finding set that should trigger it,
  * no path fires on a clean set,
  * raw credential values never appear verbatim in a synthesized path,
  * output is deterministic and finding-shaped,
  * the exposure score is bounded and ordered.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.correlate import correlate  # noqa: E402


def _f(plugin, category, key, value, severity="medium", exploitability="unknown",
       confidence=80):
    return {"plugin": plugin, "category": category, "key": key, "value": value,
            "confidence": confidence,
            "evidence": {"severity": severity, "exploitability": exploitability}}


def _names(paths):
    return [p["evidence"]["path_name"] for p in paths]


def _has_tag(paths, tag):
    return any(tag in p["evidence"].get("tags", []) for p in paths)


def test_cloud_credential_blast():
    rows = [
        _f("keyharvest", "leak", "exposed_aws_access_key",
           "AKIAIOSFODNN7EXAMPLEKEY", "high", "weaponized"),
        _f("asm", "infra", "cloud_provider", "hosted on amazonaws ec2", "low"),
        _f("buckets", "leak", "s3_public_write", "s3://acme-backups", "high"),
    ]
    paths, exp = correlate(rows)
    assert any("cloud credential" in n.lower() for n in _names(paths)), _names(paths)
    # the raw key must never appear verbatim in any path
    blob = str(paths)
    assert "AKIAIOSFODNN7EXAMPLEKEY" not in blob, "raw credential leaked into path"
    assert exp["band"] in ("high", "critical")
    assert 0 < exp["score"] <= 100


def test_jwt_auth_bypass():
    rows = [
        _f("jwt", "api", "jwt_alg_none", "token accepts alg:none", "high"),
        _f("apidiscover", "api", "endpoint", "/api/v2/admin/users", "medium"),
    ]
    paths, _ = correlate(rows)
    assert any("forgeable session token" in n.lower() for n in _names(paths)), _names(paths)
    assert _has_tag(paths, "jwt")


def test_jwt_alone_does_not_fire_path():
    # forgeable token but nothing to reach -> no auth-bypass path
    rows = [_f("jwt", "api", "jwt_alg_none", "token accepts alg:none", "high")]
    paths, _ = correlate(rows)
    assert not any("forgeable session token" in n.lower() for n in _names(paths))


def test_source_to_secret():
    rows = [
        _f("artifacts", "leak", "git_exposed", "/.git/config readable", "high"),
        _f("secrets", "leak", "js_secret", "stripe_sk_live_abc123secret", "high"),
    ]
    paths, _ = correlate(rows)
    assert any("exposed source" in n.lower() for n in _names(paths)), _names(paths)
    assert "stripe_sk_live_abc123secret" not in str(paths)


def test_ssrf_metadata():
    rows = [
        _f("ssrf", "web", "ssrf_prone_param", "url= fetches arbitrary host", "high"),
        _f("asm", "infra", "cloud_provider", "amazonaws ec2 instance", "low"),
    ]
    paths, _ = correlate(rows)
    assert any("metadata" in n.lower() for n in _names(paths)), _names(paths)


def test_subdomain_takeover():
    rows = [_f("takeover", "dns", "subdomain_takeover",
               "blog.acme.com -> unclaimed heroku app", "high")]
    paths, _ = correlate(rows)
    assert any("takeover" in n.lower() for n in _names(paths)), _names(paths)


def test_cors_data_theft():
    rows = [
        _f("cors", "web", "cors_misconfig", "reflects Origin with credentials", "medium"),
        _f("apidiscover", "api", "endpoint", "/api/account/profile", "medium"),
    ]
    paths, _ = correlate(rows)
    assert any("cors" in n.lower() for n in _names(paths)), _names(paths)


def test_mgmt_port_with_default_creds():
    rows = [
        _f("port_audit", "infra", "mongodb_open", "27017 open to internet", "high"),
        _f("creds", "infra", "default_credentials", "admin/admin works", "high"),
    ]
    paths, _ = correlate(rows)
    names = _names(paths)
    assert any("management service" in n.lower() for n in names), names
    # with default creds, exploitability should be weaponized on that path
    p = [p for p in paths if "management" in p["evidence"]["path_name"].lower()][0]
    assert p["evidence"]["exploitability"] == "weaponized"


def test_breach_credstuffing():
    rows = [
        _f("breachwatch", "identity", "hibp_breach", "admin@acme.com in 3 breaches", "medium"),
        _f("authscan", "web", "login_form", "/login accepts credentials", "low"),
    ]
    paths, _ = correlate(rows)
    assert any("credential-stuffing" in n.lower() or "breached credentials" in n.lower()
               for n in _names(paths)), _names(paths)


def test_secret_sprawl():
    rows = [
        _f("keyharvest", "leak", "exposed_aws_access_key", "AKIA...", "high"),
        _f("secrets", "leak", "js_secret", "google_api_key AIza...", "high"),
        _f("artifacts", "leak", "exposed_env", "DB_PASSWORD=...", "high"),
        _f("comments", "leak", "slack_token", "xoxb-...", "high"),
    ]
    paths, _ = correlate(rows)
    assert any("secret sprawl" in n.lower() for n in _names(paths)), _names(paths)


def test_api_docs_exposed():
    rows = [_f("apidiscover", "api", "graphql_introspection_enabled",
               "introspection returns full schema", "medium")]
    paths, _ = correlate(rows)
    assert any("self-documenting" in n.lower() for n in _names(paths)), _names(paths)


def test_clean_target_no_paths():
    rows = [
        _f("dns", "dns", "a_record", "93.184.216.34", "low"),
        _f("tls", "web", "tls_protocol", "TLS 1.3", "low"),
        _f("headers", "web", "server_header", "nginx", "low"),
    ]
    paths, exp = correlate(rows)
    assert paths == [], _names(paths)
    assert exp["score"] <= 10
    assert exp["band"] in ("low", "clean")


def test_determinism_and_shape():
    rows = [
        _f("jwt", "api", "jwt_alg_none", "alg none", "high"),
        _f("apidiscover", "api", "endpoint", "/api/admin", "medium"),
        _f("cors", "web", "cors_misconfig", "reflects origin", "medium"),
        _f("apidiscover", "api", "endpoint", "/api/account", "medium"),
    ]
    a, ea = correlate(rows)
    b, eb = correlate(list(reversed(rows)))
    assert _names(a) == _names(b), "order of input changed the output"
    assert ea == eb
    for p in a:
        # finding-shaped: persistable as a FindingRow
        for field in ("category", "key", "value", "confidence", "evidence",
                      "bounty_value"):
            assert field in p, field
        assert p["key"] == "attack_path"
        assert p["category"] == "graph"
        ev = p["evidence"]
        assert ev["attack_path"] is True
        assert ev["narrative"] and ev["remediation"] and ev["attacker_impact"]
        assert isinstance(ev["chain_steps"], list) and ev["chain_steps"]
        assert isinstance(ev["components"], list) and ev["components"]
        assert ev["severity"] in ("low", "medium", "high", "critical")


def test_malformed_rows_never_raise():
    rows = [None, {}, {"key": None}, 42, "nope", {"plugin": "x", "key": "y"}]
    paths, exp = correlate(rows)  # must not raise
    assert isinstance(paths, list)
    assert isinstance(exp["score"], int)


def test_score_ordering_monotonic():
    low = [_f("tls", "web", "tls_protocol", "TLS 1.3", "low")]
    mixed = low + [_f("x", "web", "y", "z", "medium")]
    worse = mixed + [_f("k", "leak", "exposed_aws_access_key", "AKIA", "high", "weaponized")]
    s_low = correlate(low)[1]["score"]
    s_mixed = correlate(mixed)[1]["score"]
    s_worse = correlate(worse)[1]["score"]
    assert s_low < s_mixed < s_worse, (s_low, s_mixed, s_worse)
    assert s_worse <= 100


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} correlation tests passed")


if __name__ == "__main__":
    _run_all()
