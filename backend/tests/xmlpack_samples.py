"""Canary content for the xml_* reader pack (tests/test_xmlpack.py and
scripts/xmlpack_proof.py share it).

Planted secrets are FRAGMENT-ASSEMBLED at import so the full value
never appears in this source file (GitHub Push Protection). The SSN
and IBAN are the canonical public examples (123-45-6789 passes the
format gate; GB29 NWBK... is the standard mod-97-valid example).

The canary host is canary.test in unit tests (httpx MockTransport).
The proof script serves the same routes over real HTTP on
localhost:8799 and rewrites "canary.test" -> "localhost:8799" in
response bodies so sitemap-index children resolve to the canary.
"""

# --- fragment-assembled planted secrets (never whole in source) ----
CONN_PWD = "Xml" + "Canary" + "#2026" + "Secret"
ATTR_PWD = "Attr" + "Canary" + "#99"
STRIPE_KEY = "sk_" + "live_" + "XMPACK" + "CANARY" + "0001" + "KEYX"
GH_TOKEN = ("ghp_" + "XMLPACK" + "CANARYT" + "OKEN0123" + "456789ab"
            + "cdefXY")
PLANTED_SECRETS = [CONN_PWD, ATTR_PWD, STRIPE_KEY, GH_TOKEN]

CANARY_HTML = f"""<!doctype html><html><head><title>XML Canary</title>
<script src="/static/app.js"></script></head>
<body><h1>xml canary</h1>
<a href="/appconfig.xml">app config</a>
<a href="/broken.xml">broken config</a>
<a href="/legacy.xml">legacy export</a>
<a href="/service.wsdl">soap service</a>
<a href="/feed">blog feed</a>
</body></html>"""

APP_JS = """
async function boot() {
  const cfg = await fetch("/static/endpoints.xml").then(r => r.text());
  return cfg;
}
"""

ROBOTS = """User-agent: *
Disallow: /admin/
Sitemap: https://canary.test/maps/main.xml
Sitemap: https://canary.test/sitemap.xml
"""

SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://canary.test/</loc></url>
  <url><loc>https://canary.test/blog/post-1</loc></url>
  <url><loc>https://canary.test/admin/panel</loc></url>
  <url><loc>https://canary.test/.git/config</loc></url>
  <url><loc>https://canary.test/backup/full.sql</loc></url>
  <url><loc>https://canary.test/uploads/avatar</loc></url>
  <url><loc>https://canary.test/login</loc></url>
  <url><loc>http://intranet.corp/reports</loc></url>
</urlset>
"""

SITEMAP_INDEX = """<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://canary.test/maps/pages.xml</loc></sitemap>
  <sitemap><loc>https://canary.test/maps/extra.xml</loc></sitemap>
</sitemapindex>
"""

SITEMAP_PAGES = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://canary.test/config/settings</loc></url>
  <url><loc>https://canary.test/products</loc></url>
</urlset>
"""

SITEMAP_EXTRA = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://canary.test/about</loc></url>
</urlset>
"""

APPCONFIG = f"""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="mainDb" connectionString="Server=db.internal;Database=appdb;User Id=svc_app;Password={CONN_PWD}" />
  </connectionStrings>
  <users>
    <user name="svc_backup" password="{ATTR_PWD}" />
  </users>
  <appSettings>
    <ApiKey>{STRIPE_KEY}</ApiKey>
    <serviceEndpoint>http://10.20.30.40:8080/api</serviceEndpoint>
    <partnerEndpoint>https://api.partner-example.com/v2</partnerEndpoint>
    <adminSsn>123-45-6789</adminSsn>
    <payoutIban>GB29 NWBK 6016 1331 9268 19</payoutIban>
  </appSettings>
</configuration>
"""

ENDPOINTS_XML = f"""<?xml version="1.0"?>
<endpoints>
  <service name="billing" url="https://billing.internal:8443/api" />
  <apiToken>{GH_TOKEN}</apiToken>
</endpoints>
"""

LEGACY_XML = """<?xml version="1.0"?>
<!DOCTYPE legacy [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % pe SYSTEM "http://canary.test/pe.dtd">
  %pe;
]>
<legacy><data>&xxe;</data></legacy>
"""

WSDL = """<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    targetNamespace="http://canary.test/soap">
  <wsdl:types>
    <xsd:schema>
      <xsd:import namespace="http://canary.test/types"
                  schemaLocation="http://schemas.canary.test/types.xsd" />
    </xsd:schema>
  </wsdl:types>
  <wsdl:portType name="AccountPort">
    <wsdl:operation name="GetAccount" />
    <wsdl:operation name="TransferFunds" />
  </wsdl:portType>
  <wsdl:service name="AccountService">
    <wsdl:port name="InternalPort">
      <soap:address location="http://10.20.30.41:8080/soap" />
    </wsdl:port>
    <wsdl:port name="PublicPort">
      <soap:address location="https://api.canary.test/soap" />
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>
"""

CROSSDOMAIN = """<?xml version="1.0"?>
<cross-domain-policy>
  <site-control permitted-cross-domain-policies="all"/>
  <allow-access-from domain="*"/>
</cross-domain-policy>
"""

CLIENTACCESS = """<?xml version="1.0" encoding="utf-8"?>
<access-policy>
  <cross-domain-access>
    <policy>
      <allow-from http-request-headers="*">
        <domain uri="https://canary.test"/>
      </allow-from>
      <grant-to>
        <resource path="/" include-subpaths="true"/>
      </grant-to>
    </policy>
  </cross-domain-access>
</access-policy>
"""

FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Canary Blog</title>
    <link>https://canary.test/</link>
    <description>Notes about gardening, Winnipeg winters and gutter care.</description>
    <item>
      <title>Spring cleanup checklist</title>
      <link>https://canary.test/blog/post-1</link>
      <description>Leaves, ladders and a thermos of coffee.</description>
    </item>
  </channel>
</rss>
"""

BROKEN_XML = "<configuration><connectionStrings><add name='x'"

# path -> (content_type, body)
ROUTES = {
    "/": ("text/html", CANARY_HTML),
    "/index.html": ("text/html", CANARY_HTML),
    "/static/app.js": ("application/javascript", APP_JS),
    "/robots.txt": ("text/plain", ROBOTS),
    "/sitemap.xml": ("application/xml", SITEMAP),
    "/maps/main.xml": ("application/xml", SITEMAP_INDEX),
    "/maps/pages.xml": ("application/xml", SITEMAP_PAGES),
    "/maps/extra.xml": ("application/xml", SITEMAP_EXTRA),
    "/appconfig.xml": ("application/xml", APPCONFIG),
    "/broken.xml": ("application/xml", BROKEN_XML),
    "/static/endpoints.xml": ("application/xml", ENDPOINTS_XML),
    "/legacy.xml": ("application/xml", LEGACY_XML),
    "/service.wsdl": ("text/xml", WSDL),
    "/crossdomain.xml": ("text/xml", CROSSDOMAIN),
    "/clientaccesspolicy.xml": ("text/xml", CLIENTACCESS),
    "/feed": ("application/rss+xml", FEED),
}

CLEAN_HTML = ("<!doctype html><html><head><title>Clean</title></head>"
              "<body><h1>clean site</h1><p>Nothing to see.</p>"
              "</body></html>")
CLEAN_ROBOTS = "User-agent: *\nAllow: /\n"
