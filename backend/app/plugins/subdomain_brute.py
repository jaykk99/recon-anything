"""Subdomain brute-forcing with a large embedded wordlist (aggressive detection).

Complements CT-log enumeration: resolves thousands of candidate names via
DNS. Wildcard DNS is detected first (random labels) to avoid flooding
false positives. Rate-limited and capped per run; tune with
RECON_SUBDOMAIN_RPS / RECON_SUBDOMAIN_MAX.

Passive network-wise (DNS only, no HTTP to the target). Each confirmed
subdomain is a finding with its resolved IPs.
"""
from __future__ import annotations

import asyncio
import os
import random
import string
import time
from typing import List, Set

import dns.asyncresolver
import dns.exception

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Curated high-value subdomain names (the head of the top-10k lists).
BASE_WORDS = """www mail ftp webmail smtp pop imap admin administrator api apis
dev development test testing staging stage prod production beta alpha demo
blog shop store support help forum community portal dashboard app apps mobile
m static assets cdn cdn1 cdn2 media images img pics files docs download
downloads secure login signin signup register account accounts billing
payment payments checkout cart status health check monitor metrics stats
analytics search directory members member user users client clients partner
partners partner-portal reseller affiliates affiliate jobs careers news
press media-kit brand assets2 video videos tv radio podcast podcasts wiki
kb knowledgebase faq git svn hg ci jenkins travis circle bamboo teamcity
sonar nexus artifactory docker registry repo repos code review crm erp
hr payroll finance accounting legal compliance audit vpn remote access
gateway proxy firewall dmz internal intranet extranet corp corporate hq
office ny sf la london paris berlin tokyo sydney toronto vancouver calgary
edmonton ottawa montreal winnipeg sfo lax ord dfw atl sea den iad mia bos
eu us asia web web1 web2 web3 www1 www2 www3 www4 www5 mail1 mail2 mx mx1
mx2 mx3 email newsletter smtp1 smtp2 relay pop3 imap4 ns ns1 ns2 ns3 ns4
dns dns1 dns2 cpanel whm webdisk whmcs plesk directadmin cloud cloud1 s3
storage backup backups archive db database mysql postgres pgsql mongo
redis elastic memcache cache session sessions auth oauth sso ldap ad kerberos
radius tacacs ntp syslog log logs audit2 waf ids ips honeypot sandbox lab
labs research rnd innovation poc prototype pilot canary edge origin shield
lb balancer ha cluster node node1 node2 k8s kube openshift rancher consul
vault terraform ansible puppet chef salt nomad mesos swarm etcd zookeeper
kafka rabbitmq activemq mqtt nats pulsar spark hadoop hive presto trino
airflow dbt superset metabase grafana kibana prometheus thanos jaeger zipkin
sentry datadog newrelic appdynamics dynatrace splunk elk logstash fluentd
pagerduty opsgenie victorops xmatters bigpanda moogsoft servicenow jira
confluence bitbucket bamboo crowd crucible fisheye bamboo2 phabricator
gerrit redmine trac mantis bugzilla youtrack asana trello monday clickup
notion coda airtable smartsheet wrike basecamp teamwork zoho freshdesk
zendesk intercom drift hubspot marketo pardot eloqua salesforce netsuite
workday bamboohr greenhouse lever workable icims taleo successfactors
cornerstone litmos docebo talentlms absrob minds touchcast canvas blackboard
moodle sakai brightspace d2l powerschool infinite campus skyward parent
student teacher faculty staff alumni giving donate donation volunteer
events calendar booking reservations tickets boxoffice merch merchandise
giftcard loyalty rewards points wallet checkout2 pay paypal stripe square
adyen braintree worldpay chase firstdata elavon globalpayments tsys
moneris authorize net payflow quickbooks xero freshbooks wave sage intact
acumatica epicor infor sap oracle peoplesoft jd edwards siebel sharepoint
onedrive teams skype lync exchange owa autodiscover lyncdiscover sip
webex zoom teams2 slack discord telegram whatsapp signal viber line wechat
sms voice voip pbx asterisk freeswitch twilio vonage ringcentral 8x8
five9 nice incontact genesys avaya cisco polycom yealink grandstream
printer printers scanner scanners fax copier label badge kiosk pos terminal
atm kiosks digital signage menu board drive thru curbside pickup delivery
dispatch fleet gps tracking telematics eld dashcam security camera cctv
nvr dvr alarm access2 badge2 turnstile intercom door gate parking garage
elevator hvac bms lighting shades av conferencing huddle whiteboard
projector screen mic speakerphone headset webcam printer2 scanner2
plotter fax2 shredder safe vault2 cash atm2 pos2 register2 scale deli
bakery produce meat seafood floral pharmacy clinic dental vision optical
vet pet groom boarding daycare kennel shelter rescue foster adopt cats dogs
birds fish reptiles exotics equine farm ranch vineyard winery brewery
distillery cidery meadery roastery bakery2 cafe coffee tea boba smoothie
juice bar pub tavern brewery2 taproom speakeasy lounge nightclub dj dance
karaoke comedy improv theater cinema drive-in arcade bowling laser-tag
mini-golf go-kart batting-cage trampoline climbing gym yoga pilates barre
crossfit spin boxing mma bjj karate taekwondo judo wrestling fencing
archery range gun range hunting fishing camping hiking biking ski snowboard
surf skate paddle kayak canoe sup sail boat yacht marina dock harbor
lighthouse airport heliport hangar fbo tower approach departure center
radar adsb metar taf notam briefing flightplan dispatch2 crew scheduling
maintenance mro parts inventory warehouse wms tms yms dock2 yard gate2
scale2 fuel def reefer wash inspection compliance2 safety osha epa dot
fmcsa eld2 ivmr tcheck weigh station port terminal intermodal rail spur
transload crossdock 3pl 4pl freight forwarder customs broker drayage
lastmile whiteglove install assembly repair refurbish recycle ewaste
shred2 pallet lumber mill quarry mine pit asphalt concrete cement rebar
steel lumber2 truss panel siding roofing gutter window door2 flooring tile
paint drywall insulation hvac2 plumbing electrical lighting2 fan generator
solar wind geothermal battery ev charger tesla chargepoint electrify
flo blink evgo greenlots semaconnect clippercreek juicebox enelx
""".split()

ENV_PREFIXES = ["dev", "test", "stage", "staging", "qa", "uat", "prod",
                "beta", "alpha", "demo", "sandbox", "lab", "old", "new",
                "v2", "api", "admin", "internal", "corp", "secure"]

APP_CORES = ["api", "app", "portal", "admin", "dashboard", "auth", "login",
             "pay", "shop", "blog", "docs", "status", "cdn", "static",
             "media", "assets", "files", "db", "mail", "vpn", "git",
             "ci", "monitor", "metrics", "search", "support", "help"]


def build_wordlist(max_names: int) -> List[str]:
    names: List[str] = []
    seen: Set[str] = set()

    def add(n: str):
        n = n.strip().lower()
        if n and n not in seen:
            seen.add(n)
            names.append(n)

    for w in BASE_WORDS:
        add(w)
    # env x app combos
    for env in ENV_PREFIXES:
        for core in APP_CORES:
            add(f"{env}-{core}")
            add(f"{env}.{core}")
            add(f"{core}-{env}")
    # numbered variants of the hottest names
    for core in ["www", "web", "mail", "mx", "ns", "ftp", "api", "cdn",
                 "node", "srv", "server", "host", "gw", "fw", "lb"]:
        for i in range(1, 10):
            add(f"{core}{i}")
    return names[:max_names]


class SubdomainBrutePlugin(Plugin):
    id = "subdomain_brute"
    label = "Subdomain Brute Force"
    accepts = ["domain"]
    passive = True
    cost = Cost.FREE
    group = "network"
    timeout_s = 600  # slow enumerator: needs headroom
    description = ("DNS brute-force over a large wordlist with wildcard "
                   "detection. Complements CT-log enumeration.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []

        max_names = int(os.environ.get("RECON_SUBDOMAIN_MAX", "800"))
        rps = float(os.environ.get("RECON_SUBDOMAIN_RPS", "20"))
        words = build_wordlist(max_names)

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 4
        resolver.timeout = 4

        async def resolve(name: str):
            try:
                ans = await resolver.resolve(name, "A")
                return name, sorted({r.address for r in ans})
            except (dns.exception.DNSException, Exception):
                return name, []

        # 1. wildcard detection: 4 random labels must NOT resolve
        rand_labels = ["".join(random.choices(string.ascii_lowercase, k=14))
                       for _ in range(4)]
        wildcard_ips: Set[str] = set()
        for rl in rand_labels:
            _, ips = await resolve(f"{rl}.{domain}")
            wildcard_ips.update(ips)
        if wildcard_ips:
            res = self._ok(findings,
                           f"wildcard DNS detected ({len(wildcard_ips)} IPs) - "
                           f"brute force skipped to avoid false positives")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # 2. brute force, paced
        sem = asyncio.Semaphore(25)
        gap = 1.0 / max(rps, 1)

        async def paced(word: str):
            async with sem:
                name = f"{word}.{domain}"
                _, ips = await resolve(name)
                await asyncio.sleep(gap)
                return word, ips

        hits = 0
        # One gather over the whole wordlist: the semaphore (25) already
        # bounds in-flight DNS. The old batch-of-100 chunking serialized
        # batches behind the slowest resolver in each batch (4s lifetime),
        # which made even small wordlists crawl.
        results = await asyncio.gather(*[paced(w) for w in words])
        for word, ips in results:
            if ips and not set(ips) <= wildcard_ips:
                hits += 1
                findings.append(self._f(
                    "dns", "subdomain_brute",
                    f"Subdomain {word}.{domain} resolves to "
                    f"{', '.join(ips[:4])}",
                    source="DNS brute force", confidence=95,
                    passive=True,
                    evidence={"severity": "medium",
                              "subdomain": f"{word}.{domain}",
                              "ips": ips[:8],
                              "remediation": ("Inventory this subdomain: "
                                              "confirm it is intentional, "
                                              "patched, and behind the "
                                              "same security controls.")}))
                ctx.publish("subdomains", f"{word}.{domain}")
            if hits >= 200:
                break  # enough; avoid runaway on huge zones

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"probed {len(words)} names, {hits} subdomains found")
        res.duration_ms = dur
        return res
