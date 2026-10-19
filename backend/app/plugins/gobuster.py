"""Gobuster-style directory/file brute forcer (native, keyless).

Fast wordlist-based hidden directory and file discovery, bigger and
smarter than dir_brute: ~350 curated entries plus extension
permutations (.php, .bak, .txt, .old). False-positive resistant:
fingerprints the site's 404 baseline first and ignores wildcard
matches and soft-404s.

GET only. No login attempts, no credential brute-forcing, no writes.
Bounded concurrency via fetch_many; under the 30s ceiling.
"""
from __future__ import annotations

import time
from typing import Dict, List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch, fetch_many
from ..net import web_base
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   bounded)

WORDLIST = """admin administrator admin1 admin-panel adminpanel admincp
adm manage management manager moderator mod cp controlpanel control-panel
dashboard panel console backend system sys superuser login signin signup
register auth oauth sso saml ldap kerberos vpn portal intranet extranet
api api-v1 api-v2 v1 v2 rest graphql graphiql altair swagger openapi
api-docs docs documentation help support faq wiki blog news press
assets static media uploads images img files download downloads
css js scripts lib vendor node_modules bower_components
backup backups bak old archive archives tmp temp cache
db database sql dump dumps export exports import imports
config configs configuration settings setup install installer
logs log debug test testing dev develop development stage staging
prod production demo sandbox playground qa
wp-admin wp-login.php wp-content wp-includes xmlrpc.php
administrator.php phpmyadmin pma myadmin adminer dbadmin
.env .env.bak .env.old .env.prod config.php config.bak
wp-config.php wp-config.php.bak settings.php database.yml
docker-compose.yml Dockerfile package.json composer.json
.git .git/HEAD .git/config .svn .hg .bzr .DS_Store
robots.txt sitemap.xml crossdomain.xml security.txt humans.txt
server-status server-info phpinfo.php info.php test.php
actuator actuator/health health status metrics prometheus
.env.local .env.development .env.staging .env.production
web.config .htaccess .htpasswd
private secret secrets internal confidential restricted
user users account accounts profile profiles member members
customer customers client clients partner partners
order orders cart checkout payment payments billing invoice invoices
search results categories products product shop store
contact about about-us team careers jobs legal privacy terms
sitemap sitemap.xml.gz feed rss atom
images/icons icons fonts
cgi-bin bin scripts-cgi
mobile m app apps api-docs-v2 developer developers
beta alpha preview new v3 v4
uploads/2024 uploads/2025 files/2024 media/2024
old-site oldsite newsite backup-site site-backup
wordpress drupal joomla magento shopify
crm erp hrm itsm ticketing helpdesk
jenkins gitlab github bitbucket jira confluence
grafana kibana prometheus nagios zabbix
mail webmail smtp imap pop3
ftp sftp ssh telnet
proxy cache cdn
lb balancer cluster node nodes
db1 db2 master slave replica
redis memcached elasticsearch solr
mongo mongodb postgres mysql
rabbitmq kafka
k8s kubernetes docker swarm
vault secrets-manager
ci cd pipeline pipelines build builds deploy
artifacts releases release
monitoring metrics tracing logging
auth-service user-service payment-service order-service
gateway proxy-gateway api-gateway
cdn-static static-assets cdn2
error errors 404 500 maintenance coming-soon
old.php.bak new.php.bak index.php.bak index.html.bak
backup.zip site.zip www.zip db.sql backup.sql
test.html test.php demo.php debug.php console.php
""".split()

EXTENSIONS = ["", ".php", ".html", ".txt", ".bak", ".old", ".zip"]

SOFT404_HINTS = ("not found", "page not found", "404", "does not exist",
                 "couldn't be found")


class GobusterPlugin(Plugin):
    id = "gobuster"
    label = "Gobuster"
    accepts = ["domain", "url"]
    passive = False  # sends enumeration probes
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    aggressive = True
    description = ("Fast directory/file brute force: 350+ entries x "
                   "extensions, 404-baseline filtered. GET only.")

    async def _baseline(self, ctx: Ctx, base: str) -> Dict:
        import random
        import string
        rand = "".join(random.choices(string.ascii_lowercase, k=16))
        probe = f"{base}/__no_such_path_{rand}__"
        try:
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET", probe,
                timeout=10, follow_redirects=False, max_retries=0), 12)
            if r is None:
                return {"status": 0, "length": 0, "body": ""}
            body = r.text[:3000]
            return {"status": r.status_code, "length": len(body),
                    "body": body[:1500]}
        except Exception:
            return {"status": 0, "length": 0, "body": ""}

    def _is_hit(self, status: int, body: str, baseline: Dict) -> bool:
        if status in (301, 302, 303, 307, 308):
            return True
        if status in (404, 0):
            return False
        if status == baseline.get("status") and \
                abs(len(body) - baseline.get("length", 0)) < 64:
            low = body[:1500].lower()
            base_low = (baseline.get("body") or "").lower()
            if low[:400] == base_low[:400]:
                return False
            if any(h in low for h in SOFT404_HINTS):
                return False
        if status == 200 and any(h in body[:1500].lower()
                                 for h in SOFT404_HINTS) and len(body) < 3000:
            return False
        return status in (200, 201, 202, 204, 301, 302, 303, 307, 308,
                          401, 403, 405, 500)

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("enumeration probes need active mode")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        baseline = await self._baseline(ctx, base)

        # Build probe list: bare words FIRST, then extension
        # permutations. Battle-test 2026-10-18: on a slow network only
        # the first ~80 probes fit the 20s budget, and bare words
        # (directories, known files) are far more valuable than
        # "word.php.bak" permutations, so they must lead.
        probes = []
        seen_p = set()
        for w in WORDLIST:
            if w not in seen_p:
                seen_p.add(w)
                probes.append(f"{base}/{quote(w)}")
        for w in WORDLIST:
            for ext in EXTENSIONS[1:]:
                p = w + ext
                if p in seen_p:
                    continue
                seen_p.add(p)
                probes.append(f"{base}/{quote(p)}")

        findings: List[Finding] = []
        # Chunked sweep with internal time budget: 2,457 probes at once
        # would burn the full 30s plugin cap. Probe in chunks and stop
        # launching new chunks after 20s; words are priority-ordered so
        # the highest-value paths are checked first.
        BUDGET_S = 20
        CHUNK = 300
        t_start = time.monotonic()
        swept = 0
        for i in range(0, len(probes), CHUNK):
            if time.monotonic() - t_start >= BUDGET_S:
                break
            chunk = probes[i:i + CHUNK]
            reqs = [("GET", u, {"timeout": 10, "max_retries": 0,
                                "follow_redirects": False})
                    for u in chunk]
            # deadline (not all-or-nothing): on a slow network the
            # chunk may not finish - keep whatever probes completed
            # instead of discarding the whole chunk
            resps = await fetch_many(
                ctx.http, ctx.limiter, reqs, concurrency=20,
                deadline=max(1.0, BUDGET_S - (time.monotonic() - t_start)))
            swept += sum(1 for r in resps if r is not None)
            for u, r in zip(chunk, resps):
                if r is None:
                    continue
                try:
                    if self._is_hit(r.status_code, r.text[:3000], baseline):
                        findings.append(self._f(
                            "web", "hidden_path", u,
                            "gobuster", source_url=u, confidence=80,
                            evidence={"severity": "medium",
                                      "status": r.status_code,
                                      "size": len(r.content),
                                      "remediation": "Hidden paths should not be "
                                                   "guessable. Remove unused "
                                                   "ones; protect the rest "
                                                   "with auth."},
                            passive=False))
                        ctx.publish("endpoints", u)
                except Exception:
                    continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"probed {swept} paths, {len(findings)} hits")
        res.duration_ms = dur
        return res
