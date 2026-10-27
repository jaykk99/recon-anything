"""Unit gate for the verification-command generator (app/commands.py).

Confirms the right command is produced per finding class, that every
command is flagged read-only (safe), and that annotate_commands is
idempotent and never raises.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.commands import commands_for, annotate_commands  # noqa: E402


def _f(key, value, category="web", source_url=None):
    return {"key": key, "value": value, "category": category,
            "source_url": source_url}


def test_git_exposed():
    c = commands_for(_f("git_exposed", "/.git/config", "leak",
                        "https://acme.com/.git/config"))
    assert any("/.git/config" in x["cmd"] for x in c)


def test_env_exposed():
    c = commands_for(_f("exposed_env", "DB_PASS=...", "leak"), host_hint="acme.com")
    assert any("/.env" in x["cmd"] for x in c)


def test_aws_key_identify_only():
    c = commands_for(_f("exposed_aws_access_key", "AKIAEXAMPLE", "leak"))
    assert any("get-caller-identity" in x["cmd"] for x in c)
    # identity check only — never a data-access/exfil command
    assert all("s3 cp" not in x["cmd"] and "rm" not in x["cmd"] for x in c)


def test_jwt_decode():
    c = commands_for(_f("jwt_alg_none", "eyJhbGciOiJub25lIn0.eyJ1IjoiYSJ9.", "api"))
    assert any("base64" in x["cmd"] for x in c)


def test_open_port():
    c = commands_for(_f("mongodb_open", "27017 open on 1.2.3.4", "infra"))
    assert any("nmap" in x["cmd"] or "nc " in x["cmd"] for x in c)


def test_cors():
    c = commands_for(_f("cors_misconfig", "reflects origin", "web",
                        "https://acme.com/api/me"))
    assert any("Origin:" in x["cmd"] for x in c)


def test_graphql():
    c = commands_for(_f("graphql_introspection_enabled", "schema", "api",
                        "https://acme.com/graphql"))
    assert any("__schema" in x["cmd"] for x in c)


def test_fallback_refetch():
    c = commands_for(_f("some_weird_leak", "thing", "leak",
                        "https://acme.com/weird"))
    assert any("curl" in x["cmd"] for x in c)


def test_all_commands_read_only():
    samples = [
        _f("git_exposed", "x", "leak", "https://a.com/.git/config"),
        _f("exposed_aws_access_key", "AKIA", "leak"),
        _f("s3_public_read", "s3://bucket", "leak"),
        _f("subdomain_takeover", "blog.a.com unclaimed", "dns"),
        _f("cors_misconfig", "reflects", "web", "https://a.com/api"),
    ]
    for s in samples:
        for cmd in commands_for(s, host_hint="a.com"):
            assert cmd["safe"] is True
            # no destructive verbs
            low = cmd["cmd"].lower()
            for bad in (" rm ", "delete", "drop table", "s3 rb", "shutdown"):
                assert bad not in low, (bad, cmd["cmd"])


def test_annotate_idempotent_and_safe():
    rows = [_f("git_exposed", "x", "leak", "https://a.com/.git/config"), None, {}]
    annotate_commands([r for r in rows if isinstance(r, dict)], "a.com")
    good = [r for r in rows if isinstance(r, dict) and r.get("key") == "git_exposed"][0]
    first = list(good["evidence"]["commands"])
    annotate_commands([good], "a.com")  # second pass must not duplicate
    assert good["evidence"]["commands"] == first


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} command tests passed")


if __name__ == "__main__":
    _run_all()
