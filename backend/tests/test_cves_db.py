"""Regression gate for the version-aware CVE database (cves.py).

Loads only the VERSION_CVES list (no httpx), and checks every entry is
well-formed: required fields, a compiling version_re, valid enum values,
and the version_optional discipline (an empty vuln[] means fingerprint-
only and must be flagged version_optional). Also guards the size so the
curated DB doesn't silently shrink.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load_db():
    src = open(os.path.join(os.path.dirname(__file__), "..", "app",
                            "plugins", "cves.py")).read()
    start = src.index("VERSION_CVES: List[Dict] = [")
    end = src.index("\n]\n", start) + 2
    ns = {"List": list, "Dict": dict}
    exec(compile(src[start:end], "cves_db", "exec"), ns)
    return ns["VERSION_CVES"]


DB = _load_db()
REQUIRED = {"software", "where", "version_re", "vuln", "cve", "severity",
            "exploitability", "title", "remediation"}
WHERES = {"server", "powered_by", "html", "js", "wp_generator"}
SEVS = {"low", "medium", "high", "critical"}
EXPL = {"unknown", "theoretical", "public_poc", "weaponized"}


def test_db_is_substantial():
    assert len(DB) >= 140, len(DB)


def test_every_entry_well_formed():
    for e in DB:
        miss = REQUIRED - set(e)
        assert not miss, f"{e.get('cve')} missing {miss}"
        assert e["where"] in WHERES, (e["cve"], e["where"])
        assert e["severity"] in SEVS, (e["cve"], e["severity"])
        assert e["exploitability"] in EXPL, (e["cve"], e["exploitability"])
        assert e["title"] and e["remediation"]


def test_version_res_compile():
    for e in DB:
        re.compile(e["version_re"])


def test_empty_vuln_requires_version_optional():
    for e in DB:
        if not e["vuln"]:
            assert e.get("version_optional"), \
                f"{e['cve']} has empty vuln[] but is not version_optional"


def test_has_high_value_coverage():
    # the valuable, exploited-in-the-wild edge products should be present
    blob = " ".join(e["software"].lower() + " " + e["version_re"].lower()
                    for e in DB)
    for needle in ("big-ip", "exchange", "vcenter", "moveit", "weblogic",
                   "activemq", "ofbiz", "geoserver", "ivanti", "papercut",
                   "coldfusion", "citrix"):
        assert needle in blob, f"missing high-value coverage: {needle}"


def test_weaponized_share():
    w = sum(1 for e in DB if e["exploitability"] == "weaponized")
    assert w >= 60, w  # the DB should be rich in weaponized entries


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} CVE-DB tests passed ({len(DB)} entries)")


if __name__ == "__main__":
    _run_all()
