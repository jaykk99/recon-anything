"""Permanent plugin-health gate: every plugin vs the fixture site.

tests/test_plugin_resilience.py proves plugins don't crash against a
DEAD target. This gate proves they actually WORK: each plugin runs
against tests/plugin_fixtures.py - a rich fake site (weak HSTS,
flag-less cookie, exposed .git/.env, permissive CORS, secrets in JS,
a sourcemap, OpenAPI, GraphQL, phpinfo, backups) served through the
real Ctx - in both passive and active mode.

Failures this catches (all seen in production):
  - a plugin raising out of run() (contract mismatches),
  - a plugin returning status=error on a healthy target,
  - a plugin silently producing nothing on a fixture built to trigger
    it (the MUST_PRODUCE set below) - e.g. cookie_security returning
    "no cookies" for months because CaseInsensitiveHeaders lacked the
    get_list() its hasattr() guard expected.

Regenerate the full catalog any time with:
    python3 scripts/plugin_audit.py --json-out /tmp/audit.json
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins.registry import discover  # noqa: E402
from plugin_fixtures import run_plugin_fixture, url_target  # noqa: E402

# Plugins that MUST produce >= 1 finding on the fixture (url target).
# Each entry is here because the fixture deliberately contains the
# exact condition the plugin exists to detect. If one of these goes
# silent, the plugin is broken - not "the site got cleaner".
MUST_PRODUCE = {
    # passive mode
    "headers": "passive",          # missing CSP/XFO/etc, version banners
    "hsts": "passive",             # HSTS max-age=300 (far too short)
    "cookie_security": "passive",  # sessionid cookie: no Secure/HttpOnly/SameSite
    "cors": "passive",             # ACAO * with credentials
    "secrets": "passive",          # secrets in JS + sourcemap content
    "keyharvest": "passive",       # AWS-shaped key in app.js
    "html_comments": "passive",    # TODO + password + internal host in a comment
    "sourcemap": "passive",        # app.js.map with sourcesContent
    "trackers": "passive",         # Google tag manager script
    "mixed_content": "passive",    # http:// image on the https page
    "git": "passive",              # .git/HEAD present in the Wayback CDX rows
    "waybackurls": "passive",      # CDX rows for the domain
    "graphql_probe": "passive",    # /graphql answers __typename + introspection
    "apidiscover": "passive",      # /openapi.json + API wordlist hits
    "robots": "passive",           # robots.txt with Disallow entries + sitemap
    "forms": "passive",            # login + search forms on the homepage
    "webtech": "passive",          # WordPress/Apache/PHP fingerprints
    # active mode
    "artifacts": "active",         # direct probes: /.env, /phpinfo.php, ...
    "backup": "active",            # /backup.sql + /backup.zip are served
    "hiddenpaths": "active",       # /admin/, /.git/, /login all resolve
}

# Per-plugin harness timeout in the gate: the runner's own rule is
# min(timeout_s, 120). The gate caps at 60s to stay suite-friendly -
# pacing-bound sweepers (150-probe chunks at the shared 10 rps limit
# take ~15s per chunk even against an instant fixture) need most of
# their production budget just to reach their second chunk.
_SLOW = {"apidiscover": 100.0}


def _timeout_for(cls) -> float:
    if cls.id in _SLOW:
        return _SLOW[cls.id]
    return min(float(getattr(cls, "timeout_s", 60) or 60), 60.0)


async def _run_all():
    classes = discover()
    report = {}
    for pid in sorted(classes):
        cls = classes[pid]
        entry = {}
        for mode in ("passive", "active"):
            status, findings, err = await run_plugin_fixture(
                cls, url_target(), mode=mode, timeout=_timeout_for(cls))
            entry[mode] = (status, len(findings), err)
        report[pid] = entry
    return report


_REPORT = None


def _report():
    global _REPORT
    if _REPORT is None:
        _REPORT = asyncio.run(_run_all())
    return _REPORT


def test_no_plugin_raises_or_errors_on_fixture():
    report = _report()
    bad = []
    for pid, entry in report.items():
        for mode, (status, _n, err) in entry.items():
            if status in ("raised", "error"):
                bad.append(f"{pid} [{mode}] {status}: {err.splitlines()[0] if err else ''}")
    assert not bad, "plugins raised/errored on the fixture site:\n" + \
        "\n".join(bad)


def test_fixture_must_produce():
    report = _report()
    silent = []
    for pid, mode in sorted(MUST_PRODUCE.items()):
        if pid not in report:
            silent.append(f"{pid}: not in registry")
            continue
        status, n, _err = report[pid][mode]
        if n < 1:
            silent.append(f"{pid} [{mode}]: status={status}, 0 findings "
                          "on a fixture designed to trigger it")
    assert not silent, "silently broken plugins:\n" + "\n".join(silent)
