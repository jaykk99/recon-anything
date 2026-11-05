"""Snallygaster-style HTTP secret/exposure scanner (Tier-4 Vuln/CVE).

Snallygaster hunts the files and endpoints developers forget:
VCS metadata, environment files, backups, config files, phpinfo,
debug endpoints and actuator-style management paths. HARD RULE for
this implementation (per the lane boundary): findings report the
path NAME and HTTP STATUS ONLY. Secret contents are never
downloaded, parsed, or echoed - the probe cache's body is ignored
for the sensitive classes; existence is the finding.
"""
from __future__ import annotations

import time
from typing import List, Tuple

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (path, key, label, severity, also_flag_403)
# 403 on VCS/env paths still proves the file exists behind a deny
# rule, which is worth a low-confidence note; 200 is the real hit.
CHECKS: List[Tuple[str, str, str, str, bool]] = [
    ("/.git/HEAD", "git_exposed", ".git/HEAD exposed (repo metadata)",
     "high", True),
    ("/.git/config", "git_config_exposed", ".git/config exposed "
     "(repo remotes)", "high", True),
    ("/.svn/entries", "svn_exposed", ".svn/entries exposed", "medium", True),
    ("/.hg/hgrc", "hg_exposed", ".hg/hgrc exposed", "medium", True),
    ("/.env", "exposed_env", ".env file exposed (name+status only)",
     "high", True),
    ("/.env.bak", "exposed_env_bak", ".env.bak exposed", "high", False),
    ("/.env.local", "exposed_env_local", ".env.local exposed",
     "high", False),
    ("/config.yml", "exposed_config_yml", "config.yml exposed",
     "medium", False),
    ("/config.json", "exposed_config_json", "config.json exposed",
     "medium", False),
    ("/settings.py", "exposed_settings_py", "settings.py exposed",
     "medium", False),
    ("/.aws/credentials", "exposed_aws_credentials",
     ".aws/credentials path exposed (name+status only)", "high", True),
    ("/backup.sql", "exposed_backup_sql", "backup.sql exposed "
     "(name+status only)", "high", False),
    ("/db.sql", "exposed_db_sql", "db.sql exposed (name+status only)",
     "high", False),
    ("/dump.sql", "exposed_dump_sql", "dump.sql exposed", "high", False),
    ("/phpinfo.php", "phpinfo_exposed", "phpinfo.php exposed",
     "medium", False),
    ("/info.php", "phpinfo_exposed", "info.php (phpinfo) exposed",
     "medium", False),
    ("/server-status", "server_status_exposed", "Apache server-status "
     "exposed", "medium", False),
    ("/actuator/env", "actuator_env_exposed", "Spring actuator /env "
     "exposed (name+status only)", "high", False),
    ("/actuator/health", "actuator_exposed", "Spring actuator /health "
     "exposed", "low", False),
    ("/actuator/metrics", "actuator_exposed", "Spring actuator "
     "/metrics exposed", "low", False),
    ("/debug/pprof/", "pprof_exposed", "Go debug/pprof exposed",
     "medium", False),
    ("/.DS_Store", "ds_store_exposed", ".DS_Store exposed (directory "
     "listing oracle)", "low", False),
    ("/elmah.axd", "elmah_exposed", "ELMAH error log exposed",
     "medium", False),
    ("/wp-config.php.bak", "wp_config_bak_exposed",
     "wp-config.php.bak exposed (name+status only)", "high", False),
]


# Structural body signatures used ONLY to validate existence on
# catch-all (SPA) hosts that answer 200 for every path: a signature
# match proves the file is real even when status cannot. Finding
# values still carry name + status only.
SIGNATURES = {
    "/.git/HEAD": "ref: refs/",
    "/phpinfo.php": "phpinfo",
    "/info.php": "phpinfo",
    "/server-status": "apache server status",
    "/actuator/health": '"status"',
}

CANARY = "/rx4-canary-7f3a9-nonexistent"


def _differs(resp, canary) -> bool:
    """True when a 200 response materially differs from the canary
    (i.e. it is not the host's catch-all page)."""
    try:
        if abs(int(resp.get("length") or 0)
               - int(canary.get("length") or 0)) > 128:
            return True
        rc = (resp.get("headers") or {}).get("content-type", "")
        cc = (canary.get("headers") or {}).get("content-type", "")
        return bool(rc) and rc != cc
    except Exception:
        return False


class SnallygasterScanPlugin(Plugin):
    id = "snallygaster_scan"
    label = "Snallygaster Exposure Scan"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    description = ("Snallygaster-style exposure scan: .git/.env/backup/"
                   "config/phpinfo/debug/actuator paths by NAME + "
                   "STATUS only; secret contents never read.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        seen_keys = set()
        canary = await ctx.probe(base + CANARY, timeout=8)
        catchall = int(canary.get("status") or 0) == 200
        suppressed = 0
        for path, key, label, sev, flag403 in CHECKS:
            r = await ctx.probe(base + path, timeout=8)
            status = int(r.get("status") or 0)
            if catchall and status == 200:
                sig = SIGNATURES.get(path)
                body_low = (r.get("text") or "").lower()
                if not (_differs(r, canary)
                        or (sig and sig in body_low)):
                    suppressed += 1
                    status = 0  # catch-all page, not the real file
            if status == 200 or (flag403 and status == 403):
                dedupe = (key, path)
                if dedupe in seen_keys:
                    continue
                seen_keys.add(dedupe)
                findings.append(self._f(
                    "leak", key,
                    f"{label} [{path} -> HTTP {status}] "
                    "(existence/status only; contents not read)",
                    source="snallygaster exposure scan",
                    source_url=base + path,
                    confidence=90 if status == 200 else 60,
                    passive=False,
                    evidence={"severity": sev if status == 200 else "low",
                              "path": path, "status": status,
                              "remediation": (
                                  "Remove this file/endpoint from the "
                                  "public web root or restrict it to "
                                  "trusted IPs; rotate any credential "
                                  "it may have contained.")}))
        return PluginResult(
            plugin_id=self.id, status="ok", findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"snallygaster probed {len(CHECKS)} paths: "
                   f"{len(findings)} exposures"
                   + (f"; catch-all host: {suppressed} status-only "
                      "hits suppressed as soft-404s"
                      if catchall else ""))
