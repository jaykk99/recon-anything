"""Unit gate for the manual-testing funnel (app/funnel.py).

Pure stdlib, no network: the funnel is a pure function of finding rows.
Checks that:
  * findings group into the right manual-test classes and assets,
  * stronger evidence outranks weaker evidence,
  * attack-path findings and corroboration lift a lead,
  * every lead carries concrete, read-only manual checks and no payload,
  * malformed rows are skipped instead of raising,
  * the Markdown section is export-shaped and empty on nothing to say.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.funnel import asset_of, build_funnel, classify, render_markdown  # noqa: E402


def _f(plugin, category, key, value="", severity="medium",
       exploitability="unknown", confidence=80, **extra):
    return {"plugin": plugin, "category": category, "key": key, "value": value,
            "confidence": confidence,
            "evidence": {"severity": severity, "exploitability": exploitability,
                         **extra}}


def test_classes_route_by_plugin_vocabulary():
    cases = {
        "jwt_alg_none": "auth_boundary",
        "idor_numeric_object": "object_access",
        "graphql_introspection": "api_schema",
        "xss_reflected_param": "input_handling",
        "file_upload_endpoint": "file_upload",
        "open_redirect_candidate": "redirect_flow",
        "cors_reflect_origin": "cors_trust",
        "checkout_price_param": "business_logic",
        "admin_console_exposed": "exposed_admin",
        "js_secret_exposed": "secret_in_client",
        "reentrancy_withdraw": "crypto_flow",
        "ssh_open_22": "infrastructure",
        "dangling_cname_takeover": "dns_identity",
        "apk_endpoint_leak": "mobile_binary",
    }
    for key, expected in cases.items():
        got = classify(_f("p", "web", key))
        assert got is not None and got["id"] == expected, (key, got and got["id"])


def test_unknown_rows_are_ignored():
    rows = [_f("whois", "web", "registrar", "Example Registrar"),
            {"not": "a finding"}, None, "junk"]
    funnel = build_funnel(rows, host_hint="example.com")
    assert funnel["lead_count"] == 0 and funnel["leads"] == []
    assert render_markdown(rows) == ""


def test_stronger_evidence_ranks_higher():
    rows = [
        _f("headers", "web", "missing_hsts", "no HSTS", "low", "unknown", 40),
        _f("jwt", "api", "jwt_alg_none", "token forgeable", "critical",
           "weaponized", 95),
    ]
    leads = build_funnel(rows, host_hint="example.com")["leads"]
    assert leads[0]["class"] == "auth_boundary"
    assert leads[0]["score"] > leads[1]["score"]


def test_corroboration_and_attack_paths_lift_a_lead():
    single = [_f("js", "web", "js_secret_exposed", "key", "medium",
                 "unknown", 60)]
    corroborated = single + [
        _f("gitleaks", "web", "js_secret_exposed", "key2", "medium",
           "unknown", 60),
        _f("creds", "web", "hardcoded_password", "pw", "high", "unknown", 70),
    ]
    a = build_funnel(single, host_hint="example.com")["leads"][0]
    b = build_funnel(corroborated, host_hint="example.com")["leads"][0]
    assert b["score"] > a["score"]
    assert b["uncertainty"] == "corroborated"
    path = corroborated + [{
        "plugin": "correlation", "category": "graph", "key": "attack_path",
        "value": "Exposed source code leaks application secrets",
        "confidence": 85,
        "evidence": {"severity": "high", "exploitability": "public_poc"},
    }]
    c = build_funnel(path, host_hint="example.com")["leads"][0]
    assert c["score"] > b["score"]


def test_asset_grouping_and_labels():
    rows = [
        _f("idor", "api", "idor_candidate", "https://api.example.com/v1/users/1",
           "high", "public_poc"),
        _f("idor", "api", "idor_candidate", "https://api.example.com/v1/invoices/9",
           "high", "public_poc"),
        _f("idor", "api", "idor_candidate", "https://shop.example.com/orders/9",
           "high", "public_poc"),
    ]
    funnel = build_funnel(rows)
    assert funnel["lead_count"] == 2, funnel["leads"]
    assert asset_of(rows[0]) == "api.example.com"
    lead = next(l for l in funnel["leads"] if l["asset"] == "api.example.com")
    assert lead["finding_count"] == 2


def test_leads_carry_real_read_only_checks():
    rows = [_f("sqli", "web", "sqli_error", "param id", "high", "public_poc")]
    lead = build_funnel(rows, host_hint="example.com")["leads"][0]
    assert len(lead["manual_checks"]) >= 3
    text = " ".join(lead["manual_checks"]).lower()
    for banned in ("drop table", "payload:", "exploit it", "sqlmap"):
        assert banned not in text, banned
    assert lead["evidence"] and lead["evidence"][0]["key"] == "sqli_error"
    assert lead["why"]


def test_markdown_section_shape():
    rows = [
        _f("jwt", "api", "jwt_alg_none", "alg none", "critical",
           "weaponized", 90),
        _f("graphql", "api", "graphql_introspection", "/graphql", "low",
           "unknown", 50),
    ]
    md = render_markdown(rows, host_hint="example.com")
    assert md.startswith("## Manual testing funnel")
    assert "Uncertainty" in md and "Try first" in md
    assert "jwt_alg_none" in md


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} funnel tests passed")


if __name__ == "__main__":
    _run_all()
