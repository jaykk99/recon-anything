"""Canary sites for the Alt-Svc audit plugin (altsvc_audit).

Each host serves one homepage with one Alt-Svc shape; the clean host
serves none. All hosts are fake .test domains, served via httpx
MockTransport - zero network.
"""

CLEAN_HTML = "<html><head><title>Clean</title></head><body>hi</body></html>"

# host -> Alt-Svc header value (None = header absent)
HOST_HEADERS = {
    "canary-h3.test": 'h3=":443"; ma=86400',
    "canary-legacy.test": 'h3-29=":443"; ma=86400',
    "canary-xorigin.test": 'h2="cdn-other.example:443"; ma=86400',
    "canary-xorigin-h3.test": 'h3="cdn-other.example:443"; ma=86400',
    "canary-malformed.test": 'h3=broken;;',
    "canary-clear.test": "clear",
    "canary-mazero.test": 'h3=":443"; ma=0',
    "canary-cleartext.test": 'h2c=":80"; ma=86400',
    "canary-multi.test": 'h3=":443"; ma=86400, h2=":443"; ma=86400',
    "canary-http.test": 'h3=":443"; ma=86400',
    "clean.test": None,
}
