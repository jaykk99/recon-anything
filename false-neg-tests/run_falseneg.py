"""False-negative test harness for ReconAnything.

Runs the REAL scan pipeline (runner.execute_run) against the local VulnTest
app (vulnapp.py, http://127.0.0.1:8471) in active mode, then checks the
ground-truth table: every planted vulnerability must produce its expected
finding. Any miss is a P0 bug.

Usage:
  1. python3 vulnapp.py &   (or it is started automatically below)
  2. DATABASE_URL=sqlite:////tmp/falseneg.db python3 run_falseneg.py
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "backend"))

TARGET = "http://127.0.0.1:8471"

PLUGINS = [
    "sqli", "xss", "headers", "webtech", "cors", "clickjack",
    "traversal", "cmdi", "rce", "ssrf", "backup", "git", "robots",
    "bounty", "crawler", "deepcrawl", "htmli", "ssti", "auth",
    "apidiscover",
    # Jay's "full on danger methods" deep-detection plugins
    "js_secrets", "tech_fingerprint", "misconfig_sweep", "port_scan",
    "dir_brute", "param_discovery", "cms_probes",
    # subdomain_brute needs real DNS; tested separately (wildcard guard)
]

NEW_GROUND_TRUTH = [
    ("N01", "AWS key in JS bundle", "js_secrets", "js_secret"),
    ("N02", "Secret in source map sourcesContent", "js_secrets", "js_secret"),
    ("N03", "EOL tech flagged (jQuery 1.x / PHP 7.4)", "tech_fingerprint", "tech_version"),
    ("N04", "Misconfig sweep fires 10+ checks", "misconfig_sweep", None),
    ("N05", "Open web port found (8000 decoy)", "port_scan", "web_port_open"),
    ("N06", "Hidden paths found (/admin/, /.env)", "dir_brute", "dir_brute_hit"),
    ("N07", "Hidden reflecting param found", "param_discovery", "param_reflected"),
    ("N08", "Outdated WordPress detected (5.8.1)", "cms_probes", None),
]

# vuln id -> (description, plugin_id, finding key or key prefix that proves detection)
GROUND_TRUTH = [
    ("V01", "SQLi error-based (MySQL)", "sqli", "sqli_error_based"),
    ("V02", "SQLi UNION-based", "sqli", "sqli_union_based"),
    ("V03", "SQLi time-based blind", "sqli", "sqli_time_blind"),
    ("V04", "SQLi boolean-based blind", "sqli", "sqli_boolean_blind"),
    ("V05", "Reflected XSS", "xss", "xss_reflected"),
    ("V06", "DOM XSS sinks", "xss", "xss_dom_sink"),
    ("V07", "Path traversal -> /etc/passwd", "traversal", "dir_traversal_confirmed"),
    ("V08", "Command injection (output)", "cmdi", "cmdi_error_based"),
    ("V09", "Command injection (time)", "cmdi", "cmdi_time_based"),
    ("V10", "RCE time-based", "rce", "rce_time_based"),
    ("V11", "Open redirect", "bounty", "open_redirect"),
    ("V12", "CORS origin reflection", "cors", "cors_reflect"),
    ("V13", "Clickjacking (no XFO)", "clickjack", "clickjack_vulnerable"),
    ("V14", "Missing security headers", "headers", "hsts_missing"),
    ("V15", "Info disclosure (Server/X-Powered-By/cookie)", "headers", "server_header"),
    ("V16", "Exposed .git/HEAD", "git", "git_head_exposed"),
    ("V17", "Exposed .env w/ AWS key", "backup", "exposed_env"),  # or secrets/leaks/bounty
    ("V18", "Backup file /backup.zip", "backup", "backup_exposed"),
    ("V19", "robots.txt disallows", "robots", None),  # any robots finding
    ("V20", "SSRF-prone params", "ssrf", "ssrf_prone_param"),
    ("V21", "Tech fingerprint (jQuery/PHP/Apache)", "webtech", "tech"),
]


async def main():
    from app.models import init_db, get_session, Run
    from app.runner import execute_run
    from app.reporting import findings_dump

    init_db()
    run_id = "falseneg-" + os.urandom(3).hex()
    session = get_session()
    if not session.query(Run).filter_by(id=run_id).first():
        session.add(Run(id=run_id, mode="active", status="running"))
        session.commit()
    session.close()

    print(f"=== scanning {TARGET} (active, {len(PLUGINS)} plugins) ===", flush=True)
    await execute_run(run_id, TARGET, "active", plugin_ids=PLUGINS,
                      module_overrides=None, keys={}, source_type="website")

    session = get_session()
    findings = findings_dump(session, run_id)
    session.close()

    seen = {(f["plugin"], f["key"]) for f in findings}
    by_plugin: dict = {}
    for f in findings:
        by_plugin.setdefault(f["plugin"], []).append(f["key"])

    print(f"\n=== {len(findings)} findings ===")
    for p in sorted(by_plugin):
        print(f"  {p:12} {len(by_plugin[p])}")

    print("\n=== GROUND TRUTH (zero false negatives = all DETECTED) ===")
    missed = []
    for vid, desc, plugin, key in GROUND_TRUTH:
        if key is None:
            ok = any(pl == plugin for pl, _ in seen)
        else:
            ok = (plugin, key) in seen
        # V17: .env may be caught by backup, secrets, leaks, or bounty plugins
        if vid == "V17" and not ok:
            ok = any(k in ("exposed_env", "exposed_aws_key", "backup_file",
                           "backup_exposed", "debug_endpoint",
                           "secret_in_backup")
                     for pl, k in seen
                     if pl in ("backup", "secrets", "leaks", "bounty"))
        # V08/V09 are two methods for ONE vuln (command injection in
        # ?ip=). The plugin early-exits after the first confirming method,
        # so detection via either method proves the vuln is found.
        if vid == "V08" and not ok:
            ok = ("cmdi", "cmdi_time_based") in seen
        status = "DETECTED " if ok else "MISSED   "
        print(f"  [{status}] {vid} {desc}  ({plugin}/{key})")
        if not ok:
            missed.append(vid)

    print(f"\nRESULT: {len(GROUND_TRUTH)-len(missed)}/{len(GROUND_TRUTH)} detected; "
          f"missed: {missed or 'none'}")

    # ---- new deep-detection plugins ----
    print("\n=== NEW PLUGINS (Jay's deep-detection set) ===")
    new_missed = []
    for vid, desc, plugin, key in NEW_GROUND_TRUTH:
        if vid == "N04":
            n = sum(1 for pl, _ in seen if pl == plugin)
            ok = n >= 10
            detail = f"{n} checks"
        elif vid == "N08":
            ok = False  # separate /blog scan below
            detail = "see /blog scan"
        elif key is None:
            ok = any(pl == plugin for pl, _ in seen)
            detail = ""
        else:
            ok = (plugin, key) in seen
            detail = ""
        status = "DETECTED " if ok else "MISSED   "
        print(f"  [{status}] {vid} {desc}  ({plugin}/{key}) {detail}")
        if not ok and vid != "N08":
            new_missed.append(vid)

    # N08: cms_probes against the simulated WordPress at /blog/
    print("\n=== N08: cms_probes vs /blog/ (simulated WP 5.8.1) ===")
    run_id2 = "falseneg-blog-" + os.urandom(3).hex()
    session = get_session()
    session.add(Run(id=run_id2, mode="active", status="running"))
    session.commit()
    session.close()
    await execute_run(run_id2, TARGET + "/blog/", "active",
                      plugin_ids=["cms_probes"], module_overrides=None,
                      keys={}, source_type="website")
    session = get_session()
    findings2 = findings_dump(session, run_id2)
    session.close()
    cms_ok = any(f["plugin"] == "cms_probes" and f["key"] in
                 ("cms_detected", "cms_version_disclosure", "cms_user_enum",
                  "cms_eol") for f in findings2)
    for f in findings2:
        print(f"   {f['plugin']} | {f['key']} | {(f['value'] or '')[:80]}")
    print(f"  [{'DETECTED ' if cms_ok else 'MISSED   '}] N08 outdated WordPress")
    if not cms_ok:
        new_missed.append("N08")

    print(f"\nNEW PLUGINS RESULT: "
          f"{len(NEW_GROUND_TRUTH)-len(new_missed)}/{len(NEW_GROUND_TRUTH)} "
          f"detected; missed: {new_missed or 'none'}")

    # dump all findings for inspection
    out = "/tmp/falseneg-findings.json"
    with open(out, "w") as fh:
        json.dump(findings + findings2, fh, indent=1, default=str)
    print(f"findings written to {out}")


if __name__ == "__main__":
    asyncio.run(main())
