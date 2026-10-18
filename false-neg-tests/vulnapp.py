"""VulnTest - intentionally vulnerable web app for ReconAnything false-negative testing.

Written from scratch for this task. Runs on localhost only. Every
"vulnerability" is a deterministic simulation (no real SQL, no real shell,
no real file reads): error strings are canned, delays are time.sleep,
reflections are string interpolation. All probes are GET-only.

Known vulnerabilities planted (the ground truth for the test):
  V01 SQLi error-based (MySQL)      /artists.php?artist=1'
  V02 SQLi UNION-based              /union.php?cat=1' UNION SELECT 1--
  V03 SQLi time-based blind         /blind.php?id=1' AND SLEEP(5)--
  V04 SQLi boolean-based blind      /bool.php?id=1' AND '1'='1  vs '1'='2
  V05 Reflected XSS                 /search.php?query=<x>
  V06 DOM XSS sinks                 /old-page.php (document.write(location.search), eval)
  V07 Path traversal -> passwd      /product.php?pic=....//....//etc/passwd
  V08 Command injection (output)    /ping.php?ip=127.0.0.1;id
  V09 Command injection (time)      /ping.php?ip=test$(sleep 6)
  V10 RCE time-based                /exec.php?cmd=test; sleep 6
  V11 Open redirect                 /redirect.php?next=https://evil.com  (and /?next=)
  V12 CORS origin reflection        /  (reflects Origin + credentials)
  V13 Clickjacking                  /  (no X-Frame-Options)
  V14 Missing security headers      /  (no HSTS/CSP/XCTO/Referrer/Permissions)
  V15 Info disclosure               /  (Server, X-Powered-By, cookie w/o flags)
  V16 Exposed .git/HEAD             /.git/HEAD
  V17 Exposed .env (AWS key)        /.env
  V18 Backup file                   /backup.zip
  V19 robots.txt disallows          /robots.txt
  V20 SSRF-prone params             /fetch.php?url=  (param mining)
  V21 Tech fingerprint              /  (jQuery, GA, PHP, Apache)
"""
from __future__ import annotations

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = 8471

PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
          "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")

MYSQL_ERROR = ("You have an error in your SQL syntax; check the manual that "
               "corresponds to your MySQL server version for the right syntax "
               "to use near ''' at line 1")

UNION_ERROR = "The used SELECT statements have a different number of columns"

BOILERPLATE = "<p>" + "Lorem ipsum dolor sit amet. " * 120 + "</p>"

HOMEPAGE = """<!DOCTYPE html>
<html><head><title>VulnTest Shop</title>
<script src="/static/jquery-1.11.3.min.js"></script>
<script>
(function(i,s,o,g,r,a,m){{i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){{
(i[r].q=i[r].q||[]).push(arguments)}},i[r].l=1*new Date();a=s.createElement(o),
m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
}})(window,document,'script','https://www.google-analytics.com/analytics.js','ga');
ga('create', 'UA-12345678-1', 'auto');
</script>
</head><body>
<h1>VulnTest Shop</h1>
<ul>
<li><a href="/artists.php?artist=1">Artists</a></li>
<li><a href="/union.php?cat=1">Category</a></li>
<li><a href="/blind.php?id=1">Item</a></li>
<li><a href="/bool.php?id=1">Details</a></li>
<li><a href="/search.php?query=test">Search</a></li>
<li><a href="/product.php?pic=logo.png">Product image</a></li>
<li><a href="/page.php?file=about">About page</a></li>
<li><a href="/ping.php?ip=127.0.0.1">Ping test</a></li>
<li><a href="/exec.php?cmd=ls">Run</a></li>
<li><a href="/fetch.php?url=http://example.com">Fetch URL</a></li>
<li><a href="/redirect.php?next=/">Go</a></li>
<li><a href="/api/user?id=1">API user</a></li>
<li><a href="/old-page.php">Legacy page</a></li>
<li><a href="/legacy.php?x=1">Legacy echo</a></li>
<li><a href="/blog/">Blog</a></li>
</ul>
<!-- TODO: rotate this before launch: aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY12" -->
<script src="/static/app.js"></script>
<form action="/search.php" method="get">
<input type="text" name="query" value="">
<input type="submit" value="Search">
</form>
</body></html>"""

OLD_PAGE = """<!DOCTYPE html><html><head><title>Legacy</title></head><body>
<h1>Legacy page</h1>
<script>
var q = location.search;
document.write("query=" + q);
var legacy = eval("1+1");
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41 (Ubuntu)"
    sys_version = ""

    def log_message(self, *a):
        pass  # quiet

    def _send(self, code, body, ctype="text/html", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/7.4.3")
        # Deliberately NO security headers: no HSTS, no CSP,
        # no X-Frame-Options, no X-Content-Type-Options,
        # no Referrer-Policy, no Permissions-Policy. (V13/V14)
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")  # V15: no flags
        # V12: reflect any Origin with credentials (CORS misconfig)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        if self.command == "OPTIONS":
            self.send_header("Access-Control-Allow-Methods",
                             "GET, POST, PUT, DELETE, OPTIONS")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route()

    def do_OPTIONS(self):
        self._send(200, b"")

    def _route(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path

        # V11b: bounty plugin probes /?next=https://evil.com
        if p == "/" and "next" in q:
            nxt = q["next"][0]
            self.send_response(302)
            self.send_header("Location", nxt)
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.end_headers()
            return

        if p == "/":
            self._send(200, HOMEPAGE)
        elif p == "/artists.php":  # V01 error-based SQLi
            artist = q.get("artist", [""])[0]
            if "'" in artist:
                self._send(200, f"<html><body>DB Error: {MYSQL_ERROR}</body></html>")
            else:
                self._send(200, f"<html><body><h2>artist: r4w8173</h2>{BOILERPLATE}</body></html>")
        elif p == "/union.php":  # V02 union-based SQLi
            cat = q.get("cat", [""])[0]
            if "union" in cat.lower():
                self._send(200, f"<html><body>DB Error: {UNION_ERROR}</body></html>")
            else:
                self._send(200, f"<html><body><h2>category {cat}</h2>{BOILERPLATE}</body></html>")
        elif p == "/blind.php":  # V03 time-based blind SQLi
            i = q.get("id", [""])[0]
            if "sleep(" in i.lower():
                time.sleep(5)  # simulated DB delay
            self._send(200, f"<html><body><h2>item {i}</h2>{BOILERPLATE}</body></html>")
        elif p == "/bool.php":  # V04 boolean-based blind SQLi
            i = q.get("id", [""])[0]
            if "'1'='2" in i:
                self._send(200, "<html><body>no results</body></html>")
            else:
                self._send(200, f"<html><body><h2>details {i}</h2>{BOILERPLATE}</body></html>")
        elif p == "/search.php":  # V05 reflected XSS
            query = q.get("query", [""])[0]
            self._send(200, f"<html><body><h2>Search results for: {query}</h2></body></html>")
        elif p == "/old-page.php":  # V06 DOM sinks
            self._send(200, OLD_PAGE)
        elif p in ("/product.php", "/page.php"):  # V07 traversal
            key = "pic" if p == "/product.php" else "file"
            val = q.get(key, [""])[0]
            if ".." in val or "etc/passwd" in val:
                self._send(200, f"<html><body><pre>{PASSWD}</pre></body></html>")
            else:
                self._send(200, f"<html><body>showing {val}</body></html>")
        elif p == "/ping.php":  # V08/V09 command injection
            ip = q.get("ip", [""])[0]
            if "sleep" in ip.lower():
                time.sleep(6)  # simulated command delay
                self._send(200, "<html><body>PING done</body></html>")
            elif any(c in ip for c in (";", "|", "&", "`", "$(")):
                if "id" in ip:
                    self._send(200, "<html><body><pre>uid=33(www-data) "
                                    "gid=33(www-data) groups=33(www-data)</pre></body></html>")
                else:
                    self._send(200, "<html><body>PING output injected</body></html>")
            else:
                self._send(200, f"<html><body>PING {ip} ... ok</body></html>")
        elif p == "/exec.php":  # V10 RCE time-based
            cmd = q.get("cmd", [""])[0]
            if "sleep" in cmd.lower():
                time.sleep(6)  # simulated command delay
            if "id" in cmd:
                self._send(200, "<html><body><pre>uid=33(www-data)</pre></body></html>")
            else:
                self._send(200, "<html><body>done</body></html>")
        elif p == "/fetch.php":  # V20 SSRF-prone param
            url = q.get("url", [""])[0]
            self._send(200, f"<html><body>Fetched: {url}</body></html>")
        elif p == "/redirect.php":  # V11 open redirect
            nxt = q.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", nxt)
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.end_headers()
        elif p == "/api/user":
            i = q.get("id", ["1"])[0]
            name = "alice" if i == "1" else "bob"
            self._send(200, f'{{"id":{i},"name":"{name}","email":"{name}@example.com"}}',
                       ctype="application/json")
        elif p == "/.git/HEAD":  # V16
            self._send(200, "ref: refs/heads/master\n", ctype="text/plain")
        elif p == "/.env":  # V17
            body = ("APP_ENV=production\n"
                    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                    "DB_PASSWORD=s3cr3t-pass\n")
            self._send(200, body, ctype="text/plain")
        elif p == "/backup.zip":  # V18
            self._send(200, b"PK\x03\x04" + b"\x00" * 200,
                       ctype="application/zip")
        elif p == "/robots.txt":  # V19
            self._send(200, "User-agent: *\nDisallow: /admin/\nDisallow: /backup.zip\n",
                       ctype="text/plain")
        elif p == "/admin/":
            self._send(200, "<html><body><h1>Admin Panel</h1></body></html>")
        elif p == "/favicon.ico":
            self._send(200, b"\x00" * 200, ctype="image/x-icon")
        elif p == "/static/app.js":  # N01/N02: secrets in JS + source map
            js = ('// VulnTest bundle\n'
                  'var AWS_KEY = "AKIAIOSFODNN7FAKEKEY1"; // prod key, do not commit\n'
                  'var cfg = {api: "https://api.vulntest.local/v1"};\n'
                  '//# sourceMappingURL=app.js.map\n')
            self._send(200, js, ctype="application/javascript")
        elif p == "/static/app.js.map":
            import json as _json
            smap = {"version": 3,
                    "sources": ["webpack://vulntest/src/config.ts"],
                    "sourcesContent": [
                        'export const STRIPE_KEY = "sk-4eC39HqLyjWDarjtT1zdp7dc4eC39HqLyj";\n'
                        'export const DB = "postgres://admin:s3cr3t-pass@db:5432/shop";\n']}
            self._send(200, _json.dumps(smap), ctype="application/json")
        elif p == "/legacy.php":  # N07: echoes every param raw (debug echo)
            rows = "".join(f"<li>{k} = {v[0]}</li>"
                            for k, v in q.items())
            self._send(200, f"<html><body><h1>Legacy echo</h1><ul>{rows}</ul></body></html>")
        elif p == "/blog/":  # N08: simulated outdated WordPress
            self._send(200,
                       '<!DOCTYPE html><html><head>'
                       '<meta name="generator" content="WordPress 5.8.1" />'
                       '<link rel="stylesheet" href="/blog/wp-content/themes/twenty21/style.css">'
                       '</head><body><h1>Blog</h1></body></html>')
        elif p == "/blog/readme.html":
            self._send(200, "<html><body><h1>WordPress</h1><p>Version 5.8.1</p></body></html>")
        elif p == "/blog/wp-json/wp/v2/users":
            self._send(200, '[{"id":1,"slug":"admin"},{"id":2,"slug":"editor"}]',
                       ctype="application/json")
        elif p == "/blog/xmlrpc.php":
            self._send(200, "XML-RPC server accepts POST requests only.",
                       ctype="text/plain")
        else:
            self._send(404, "<html><body>not found</body></html>")


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"VulnTest listening on http://{HOST}:{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
