"""Hidden endpoint discovery plugin.

Finds endpoints not linked anywhere: brute-forces common paths,
checks JS for API calls, parses sitemaps and robots.txt.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List
from urllib.parse import urljoin

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

HIDDEN_PATHS = """admin administrator admin-panel dashboard panel control
login signin log-in auth authenticate sso oauth callback
api v1 v2 v3 v4 rest graphql graphiql playground
internal private secret hidden test dev staging qa uat sandbox demo
backup bak old tmp temp cache logs log debug
config configuration settings env environment
db database sql dump export import
upload uploads files file media assets static
docs documentation api-docs swagger openapi redoc
health status metrics ping info version
webhook webhooks callback callbacks hook
console terminal shell cmd exec
phpinfo info.php test.php debug.php
.git .svn .hg .env .env.bak
wp-admin wp-login.php xmlrpc.php
phpmyadmin pma adminer
actuator actuator/health actuator/env
.env.local .env.production config.json
server-status server-info
manage management cms backend office
portal client customer partner vendor
register signup join subscribe
profile account settings preferences
billing payment checkout cart order
search results list browse
help support faq contact about
news blog press media careers jobs
legal privacy terms cookies
sitemap robots.txt humans.txt
crossdomain.xml clientaccesspolicy.xml
.well-known/security.txt .well-known/change-password
metrics prometheus grafana kibana
elasticsearch/_cluster/health
solr/admin/info/system
jenkins/script console
druid/coordinator/v1
actuator/beans actuator/configprops actuator/mappings
api/v1/users api/v1/admin api/users
rest/api/2/user rest/api/2/serverInfo
graphql/console graphiql/console
admin/config admin/settings admin/users
manager/html host-manager/html
jmx-console web-console
axis2/axis2-admin
struts/showcase
cgi-bin/test.cgi
server-status?auto
phpmyadmin/index.php
myadmin adminer.php
dbadmin sqlweb
webalizer awstats
plesk-site-preview
cpanel whm webmail
roundcube squirrelmail
horde imp
owa exchange/ ecp/
autodiscover/autodiscover.xml
remote/api jsonrpc
xmlrpc.php?rsd
wp-json/wp/v2/users
wp-content/debug.log
sites/default/settings.php
administrator/index.php
typo3/install.php
umbraco/Umbraco
sitecore/shell
episerver
aem/crx/de
""".split()


class HiddenPathsPlugin(Plugin):
    id = "hiddenpaths"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "Hidden Endpoint Finder"
    accepts = ["domain", "url"]
    passive = False  # active probing
    cost = Cost.FREE
    group = "web"
    description = "Brute-force unlinked paths. Find hidden endpoints."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        if self.module_mode(ctx) == "passive":
            return self._skipped("needs active mode for path probing")
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []

        async def check(path: str):
            url = urljoin(base + "/", path)
            # Shared probe cache: backup.py / artifacts.py may already have
            # fetched this URL in the same run; reuse instead of re-fetching.
            probed = await ctx.probe(url, timeout=8)
            status = probed["status"]
            if status in (200, 301, 302, 401, 403):
                return (path, status)
            return None

        # One concurrent sweep (sem 12); the rate limiter already paces
        # requests, so the old 0.5s inter-batch sleep was pure overhead.
        sem = asyncio.Semaphore(12)

        async def _check(path: str):
            async with sem:
                return await check(path)

        results = [r for r in
                   await asyncio.gather(*[_check(p) for p in HIDDEN_PATHS])
                   if r]

        for path, status in results:
            interesting = status in (200, 401, 403)
            findings.append(self._f(
                "web", "hidden_endpoint", f"/{path} ({status})",
                f"hiddenpaths: /{path} returned {status}",
                source_url=urljoin(base + "/", path),
                confidence=85 if interesting else 60,
                evidence={"severity": "medium" if status == 200 else "low",
                          "why": f"Unlinked path returns {status}"},
                passive=False))
            ctx.publish("endpoints", urljoin(base + "/", path))

        return self._ok(findings, f"probed {len(HIDDEN_PATHS)} paths, {len(results)} hits")
