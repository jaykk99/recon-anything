"""Attacker-impact + source gate for ReconAnything findings.

Every finding the system emits must answer two questions:
  - "What an attacker can do" (evidence.attacker_impact, non-empty)
  - "Where it came from"     (source label, non-empty)

Network-free: findings are built through Plugin._f (the single funnel
all plugins use) with synthetic keys, including EVERY literal finding
key the plugins can emit (extracted by AST), plus one generic key per
plugin and per category. The API serialization layer is checked too:
reporting.findings_dump must expose a top-level attacker_impact on
every row, backfilling findings built outside _f (e.g. geo POIs).
"""
import ast
import glob
import importlib
import os
import pkgutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.impact import attacker_impact_for  # noqa: E402
from app.plugins import base  # noqa: E402

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _plugin_classes():
    classes = {}
    pkg = importlib.import_module("app.plugins")
    for mod in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda m: m.name):
        if mod.name in ("base", "registry", "__init__"):
            continue
        module = importlib.import_module(f"app.plugins.{mod.name}")
        for attr in dir(module):
            obj = getattr(module, attr)
            if (isinstance(obj, type) and issubclass(obj, base.Plugin)
                    and obj is not base.Plugin and getattr(obj, "id", None)):
                classes.setdefault(obj.id, obj)
    return classes


def _all_literal_keys():
    """Every string-literal finding key passed to _f anywhere in plugins."""
    keys = set()
    pattern = os.path.join(BACKEND_DIR, "app", "plugins", "*.py")
    for path in glob.glob(pattern):
        tree = ast.parse(open(path).read())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "_f"):
                key_node = node.args[1] if len(node.args) >= 2 else None
                for kw in node.keywords:
                    if kw.arg == "key":
                        key_node = kw.value
                if isinstance(key_node, ast.Constant) \
                        and isinstance(key_node.value, str):
                    keys.add(key_node.value)
                elif isinstance(key_node, ast.JoinedStr):
                    parts = [v.value for v in key_node.values
                             if isinstance(v, ast.Constant)]
                    keys.add("".join(parts) + "x")
    return sorted(keys)


def test_impact_resolver_never_empty():
    # Every extracted key resolves to specific (non-generic) text unless
    # it is a pure inventory key handled by a later layer - but it must
    # always be non-empty at the full _f level (checked below).
    for key in _all_literal_keys():
        text = attacker_impact_for(key=key, plugin_id="", category="")
        assert isinstance(text, str) and len(text) >= 20, key


def test_every_plugin_finding_has_impact_and_source():
    classes = _plugin_classes()
    assert len(classes) > 150  # sanity: registry is the real one
    for pid, cls in sorted(classes.items()):
        plugin = cls()
        f = plugin._f("web", "zz_unmapped_probe_key", "value",
                      "unit test source")
        ev = f.evidence or {}
        assert f.source and f.source.strip(), pid
        assert ev.get("attacker_impact"), pid
        assert len(ev["attacker_impact"]) >= 20, pid


def test_all_known_keys_get_impact_via_funnel():
    classes = _plugin_classes()
    any_plugin = next(iter(classes.values()))()
    for key in _all_literal_keys():
        f = any_plugin._f("web", key, "value", "unit test source")
        assert (f.evidence or {}).get("attacker_impact"), key


def test_specific_keys_have_specific_text():
    # Spot-check the high-value keys carry their own text, not a fallback.
    samples = {
        "git_exposed": "source code",
        "hsts_missing": "plain HTTP",
        "exposed_aws_access_key": "cloud account",
        "sqli_error_based": "SQL",
        "jwt_weak_secret": "mint valid tokens",
        "subdomain_takeover": "register it",
        "zone_transfer": "complete DNS zone",
        "docker_exposed": "root on the host",
    }
    for key, phrase in samples.items():
        text = attacker_impact_for(key=key)
        assert phrase.lower() in text.lower(), (key, text)


def test_plugin_set_impact_is_respected():
    classes = _plugin_classes()
    plugin = next(iter(classes.values()))()
    f = plugin._f("web", "endpoint", "v", "src",
                  evidence={"attacker_impact": "custom impact text"})
    assert f.evidence["attacker_impact"] == "custom impact text"


SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
MD5 = "5d41402abc4b2a76b9719d911017c592"
BCRYPT = "$2b$12$LJ3m4y9cLYpQapfLpJkzuHhbhvJQvXdPJvXy8vP3o0wQp7lGCmAbC"


def test_hash_finding_gets_type_and_purpose():
    classes = _plugin_classes()
    plugin = classes["hashcracker"]()
    # Plugin-stamped label is trusted; purpose comes from context.
    f = plugin._f("leak", "hash_analyzed", f"SHA-256 hash {SHA256[:16]}...",
                  "hash scan", evidence={"hash_type": "SHA-256",
                                          "match": SHA256})
    ev = f.evidence
    assert ev["hash_type"] == "SHA-256"
    assert ev["hash_purpose"] and "password" in ev["hash_purpose"]
    assert "SHA-256" in ev["attacker_impact"]
    assert "Hash identified:" in ev["attacker_impact"]


def test_hash_identified_from_format_without_label():
    classes = _plugin_classes()
    plugin = classes["credential_strength"]()
    f = plugin._f("leak", "hash_analyzed", f"bcrypt hash {BCRYPT}",
                  "page scan")
    ev = f.evidence
    assert ev["hash_type"] == "bcrypt"
    assert ev["hash_purpose"]
    assert "bcrypt" in ev["attacker_impact"]


def test_hash_ambiguous_32hex_labeled_honestly():
    from app.impact import identify_hash
    assert "MD5" in identify_hash(MD5) and "NTLM" in identify_hash(MD5)
    assert identify_hash(SHA256) == "SHA-256"
    assert identify_hash("not a hash at all") is None


def test_favicon_hash_is_fingerprint_not_password():
    classes = _plugin_classes()
    plugin = classes["webtech"]()
    f = plugin._f("identity", "favicon_mmh3", "-2097250959", "favicon.ico")
    ev = f.evidence
    assert "MurmurHash3" in ev["hash_type"]
    assert "fingerprint" in ev["hash_purpose"]
    assert "password storage" not in ev["hash_purpose"]


def test_non_hash_finding_has_no_hash_fields():
    classes = _plugin_classes()
    plugin = classes["headers"]()
    f = plugin._f("web", "hsts_missing", "no HSTS", "header check")
    assert "hash_type" not in (f.evidence or {})


def test_findings_dump_rows_carry_impact_and_source():
    from app import models
    from app.reporting import findings_dump

    class FakeSession:
        def __init__(self, rows):
            self._rows = rows

        def query(self, _model):
            rows = self._rows

            class Q:
                def filter_by(self, **_kw):
                    return self

                def all(self):
                    return rows
            return Q()

    def row(**kw):
        r = models.Finding()
        r.id = kw.get("id", 1)
        r.run_id = "run-test"
        r.target_id = "t1"
        r.plugin_id = kw.get("plugin_id", "geo")
        r.category = kw.get("category", "location")
        r.key = kw.get("key", "poi")
        r.value = kw.get("value", "some place")
        r.source = kw.get("source", "OpenStreetMap")
        r.source_url = kw.get("source_url", "")
        r.confidence = 100
        r.evidence = kw.get("evidence", {"severity": "info"})
        r.passive = True
        r.bounty_value = "low"
        r.first_seen = None
        return r

    rows = findings_dump(FakeSession([
        row(),  # built outside _f: must be backfilled at read time
        row(id=2, plugin_id="headers", category="web", key="hsts_missing",
            source="header check", evidence={"severity": "medium"}),
    ]), "run-test")
    assert len(rows) == 2
    for r in rows:
        assert r["source"] and r["source"].strip(), r
        assert r.get("attacker_impact"), r
        assert len(r["attacker_impact"]) >= 20, r
        assert (r["evidence"] or {}).get("attacker_impact"), r
    # the specific key wins over fallbacks
    assert "plain HTTP" in rows[1]["attacker_impact"]
