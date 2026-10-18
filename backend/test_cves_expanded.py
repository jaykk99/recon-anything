"""Test the expanded CVE database against mock vulnerable/patched stacks.

Runs CvesPlugin with canned HTTP responses (httpx MockTransport):
  1. vulnerable stack -> exact expected CVEs must fire
  2. boundary versions -> correct branch of each range check
  3. patched stack -> zero findings (no false positives)

Usage: python3 test_cves_expanded.py   (run from backend/)
"""
import asyncio
import sys

import httpx

sys.path.insert(0, ".")

from app.plugins.base import Ctx, Target
from app.plugins.cves import CvesPlugin
from app.ratelimit import RateLimiter

VULN_BODY = """<html><head>
<meta name="generator" content="WordPress 6.4.0" />
<script src="/wp-content/plugins/elementor/assets/js/frontend.min.js"></script>
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js"></script>
<script src="https://cdn.example.com/jquery-3.3.1.min.js"></script>
<script src="https://cdn.example.com/bootstrap-4.0.0/js/bootstrap.min.js"></script>
<script src="https://cdn.example.com/handlebars-4.7.3/handlebars.min.js"></script>
<script src="/assets/chart.js-2.9.3/Chart.min.js"></script>
</head><body>
<h1>Apache Tomcat/8.5.50</h1>
<p>Powered by Django 4.0 and Ruby on Rails</p>
<div class="confluence">Confluence dashboard</div>
<div id="teamcity">TeamCity build</div>
<div class="grafana">Grafana login</div>
<div id="metabase">Metabase</div>
<p>phpmyadmin console</p>
</body></html>"""

PATCHED_BODY = """<html><head>
<meta name="generator" content="WordPress 6.8.2" />
<script src="https://cdn.example.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.example.com/bootstrap-5.3.3/js/bootstrap.min.js"></script>
</head><body><h1>ok</h1></body></html>"""


def make_handler(headers, body):
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith("/wp-json/wp/v2/users"):
            return httpx.Response(404, text="{}")
        return httpx.Response(200, text=body, headers=headers)
    return handler


async def run_case(name, headers, body):
    transport = httpx.MockTransport(make_handler(headers, body))
    async with httpx.AsyncClient(transport=transport) as client:
        ctx = Ctx(run_id="t", mode="passive", http=client, cache=None,
                  keys={}, limiter=RateLimiter())
        plugin = CvesPlugin()
        res = await plugin.run(Target(raw="vuln.test", type="domain"), ctx)
    cves = sorted({f.evidence["cve"] for f in res.findings})
    return res, cves


def check(name, got, want=None, absent=None):
    ok = True
    got_s = set(got)
    for w in (want or []):
        if w not in got_s:
            print(f"  FAIL {name}: expected {w} to fire, got {got}")
            ok = False
    for a in (absent or []):
        if a in got_s:
            print(f"  FAIL {name}: {a} must NOT fire, got {got}")
            ok = False
    if ok:
        print(f"  ok {name}: {len(got)} findings")
    return ok


async def main():
    all_ok = True

    # 1. Fully vulnerable stack
    print("case: vulnerable stack")
    _, cves = await run_case(
        "vuln",
        {"server": "Apache/2.4.49 (Unix) OpenSSL/1.0.1e",
         "x-powered-by": "PHP/7.2.23"},
        VULN_BODY)
    all_ok &= check("vuln", cves,
        want=["CVE-2021-41773", "CVE-2023-25690", "CVE-2023-27522",
              "CVE-2021-44790", "CVE-2022-22720", "CVE-2022-23943",
              "CVE-2014-0160",
              "CVE-2019-11043", "EOL",
              "CVE-2024-4439",
              "CVE-2023-30847", "CVE-2020-35489",
              "CVE-2020-1938", "CVE-2020-9484",
              "CVE-2020-11022 / CVE-2020-11023", "CVE-2019-11358",
              "CVE-2019-8331", "CVE-2021-20922", "CVE-2020-7746",
              "CVE-2022-34265", "CVE-2021-35042",
              "CVE-2022-32224", "CVE-2019-5420",
              "CVE-2023-22515", "CVE-2022-26134", "CVE-2021-26084",
              "CVE-2024-27198", "CVE-2021-43798",
              "CVE-2023-38646",
              "CVE-2020-10804", "CVE-2016-5734"],
        absent=["CVE-2021-42013", "CVE-2022-3602"])

    # 2. Boundary versions
    print("case: boundaries")
    _, cves = await run_case("b1",
        {"server": "Apache/2.4.51", "x-powered-by": "PHP/7.2.24"},
        "<html><body>plain</body></html>")
    all_ok &= check("apache 2.4.51 + php 7.2.24", cves,
        want=["CVE-2021-44790", "CVE-2022-22720", "CVE-2022-23943", "EOL"],
        absent=["CVE-2021-41773", "CVE-2021-42013", "CVE-2019-11043", "CVE-2024-4577"])

    _, cves = await run_case("b1b",
        {"x-powered-by": "PHP/8.2.25"},
        "<html><body>plain</body></html>")
    all_ok &= check("php 8.2.25 patched", cves, want=[], absent=["CVE-2024-4577"])

    _, cves = await run_case("b1c",
        {"x-powered-by": "PHP/8.3.5"},
        "<html><body>plain</body></html>")
    all_ok &= check("php 8.3.5 vuln", cves, want=["CVE-2024-4577"])

    _, cves = await run_case("b2",
        {"server": "nginx/1.17.6"},
        "<html><body>plain</body></html>")
    all_ok &= check("nginx 1.17.6", cves,
        want=["CVE-2019-20372", "CVE-2021-23017"], absent=["CVE-2017-7529"])

    _, cves = await run_case("b2b",
        {"server": "nginx/1.20.1"},
        "<html><body>plain</body></html>")
    all_ok &= check("nginx 1.20.1 patched", cves, want=[], absent=["CVE-2021-23017"])

    _, cves = await run_case("b3",
        {"x-jenkins": "2.440.3"},
        "<html><body>plain</body></html>")
    all_ok &= check("jenkins LTS 2.440.3 patched", cves, want=[], absent=["CVE-2024-23897"])

    _, cves = await run_case("b4",
        {"x-jenkins": "2.440"},
        "<html><body>plain</body></html>")
    all_ok &= check("jenkins weekly 2.440 vuln", cves, want=["CVE-2024-23897"])

    _, cves = await run_case("b5",
        {"x-jenkins": "2.426.2"},
        "<html><body>plain</body></html>")
    all_ok &= check("jenkins LTS 2.426.2 vuln", cves, want=["CVE-2024-23897"])

    _, cves = await run_case("b6",
        {"x-jenkins": "2.137.0"},
        "<html><body>plain</body></html>")
    all_ok &= check("jenkins 2.137 old", cves, want=["CVE-2018-1000861", "CVE-2024-23897"])

    _, cves = await run_case("b7",
        {"server": "Apache-Coyote/1.1"},
        "<html><body><h1>Apache Tomcat/9.0.31</h1></body></html>")
    all_ok &= check("tomcat 9.0.31 patched", cves, want=[],
                    absent=["CVE-2020-1938", "CVE-2020-9484"])

    _, cves = await run_case("b8",
        {"server": "Apache-Coyote/1.1"},
        "<html><body><h1>Apache Tomcat/7.0.99</h1></body></html>")
    all_ok &= check("tomcat 7.0.99 vuln", cves, want=["CVE-2020-1938", "CVE-2020-9484"])

    _, cves = await run_case("b9",
        {},
        '<html><head><meta name="generator" content="Joomla! - Open Source Content Management - Version 3.4.5" /></head></html>')
    all_ok &= check("joomla 3.4.5", cves, want=["CVE-2015-8562"])

    _, cves = await run_case("b10",
        {},
        '<html><head><meta name="generator" content="Joomla! - Open Source Content Management - Version 4.2.9" /></head></html>')
    all_ok &= check("joomla 4.2.9 patched", cves, want=[], absent=["CVE-2015-8562", "CVE-2023-23752"])

    _, cves = await run_case("b11",
        {},
        '<html><head><meta name="generator" content="WordPress 4.7.1" /></head></html>')
    all_ok &= check("wp 4.7.1", cves,
        want=["CVE-2017-1001000", "CVE-2021-29447", "CVE-2022-21661", "CVE-2024-4439"],
        absent=[])

    _, cves = await run_case("b12",
        {"server": "Microsoft-IIS/6.0"},
        "<html><body>plain</body></html>")
    all_ok &= check("iis 6.0", cves, want=["CVE-2017-7269"])

    # 3. Fully patched stack: zero findings expected
    print("case: patched stack")
    res, cves = await run_case("patched",
        {"server": "nginx/1.26.2", "x-powered-by": "PHP/8.3.10"},
        PATCHED_BODY)
    non_wp = [c for c in cves]  # wp-json check adds wp_user_enum, not a cve
    if res.findings:
        print(f"  FAIL patched stack: got {[f.evidence.get('cve') or f.key for f in res.findings]}")
        all_ok = False
    else:
        print("  ok patched stack: 0 findings")

    print("ALL OK" if all_ok else "FAILURES PRESENT")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
