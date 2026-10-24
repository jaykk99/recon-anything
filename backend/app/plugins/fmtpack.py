"""Format & graph coverage pack (fx_*): detectors for the three areas
Jay's 2026-10-23 research dump called out - binary serialization
(Protobuf/Avro and friends), XML schema depth, and graph/semantic
data (SPARQL, graph DBs).

Deduped against the 575-plugin registry that existed when this pack
was built (ids AND patterns read, not assumed):

- Serialization SCHEMAS: nothing fetched or parsed .proto / .avsc /
  .thrift / .fbs / .capnp files. port_audit maps port 9160 to a
  "Cassandra-thrift" label (a port number, not a schema) - that is
  the only prior mention. -> fx_proto_schema, fx_avro_schema,
  fx_thrift_schema, fx_flatbuffers_schema, fx_capnp_schema.
- Deserialization SURFACES: nothing scanned what a target SENDS
  (Set-Cookie values, page bodies) for serialized-object markers.
  banners.py carries a text note about JBoss deserialization CVEs
  and webtech fingerprints ASP.NET from a __viewstate string in an
  unrelated header - neither inspects a serialized payload.
  -> fx_deserialization_surface (PASSIVE fingerprints only).
- XML SCHEMAS: zero hits for .xsd / .dtd anywhere in the registry.
  The XML data-file reader ordered the same evening was still in
  flight (its worktree sat at the base commit, nothing landed) and
  targets XML *data* files; this pack covers the schema files.
  -> fx_xsd_schema, fx_dtd_schema.
- Graph endpoints: port_audit flags open ports 7474/7687/8529 by
  number only - no HTTP probe of what answers. assetgraph.py pushes
  OUR findings into OUR Neo4j sink (internal plumbing, not a target
  probe). No SPARQL probe existed at all. -> fx_sparql_endpoint,
  fx_neo4j_open, fx_arangodb_open, fx_gremlin_open.

HARD LINES: detection only. Schema files are parsed for NAMES (the
disclosure is the finding). Deserialization detection is passive -
markers in traffic the target already sends; no crafted payload is
ever sent to any endpoint. Graph probes are read-only service
identification requests (a SPARQL service-description GET, a Neo4j
discovery GET, an ArangoDB version GET, a Gremlin root GET) - no
query that pulls data out of a graph database is ever issued.
Evidence is metadata (names/counts/truncated samples); cookie and
payload values are never stored in full.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import collect_texts

_REMEDIATION = (
    "Remove the exposure from the public surface and treat any "
    "internal detail it revealed (service names, schemas, internal "
    "addresses) as disclosed: an attacker uses exactly this material "
    "to build targeted follow-up attacks. Detection only: nothing "
    "found was used, and no payload was ever sent.")

_DESER_REMEDIATION = (
    "Never deserialize untrusted input. Replace native serialized "
    "objects in cookies/parameters with signed (and ideally "
    "encrypted) tokens or plain JSON, enforce ViewState MAC + "
    "encryption, and audit every deserialization entry point "
    "(Java readObject, PHP unserialize, Python pickle, .NET "
    "BinaryFormatter/LosFormatter) reachable from user input.")


def _fingerprint(value: str) -> str:
    return hashlib.sha256(
        (value or "").encode("utf-8", "ignore")).hexdigest()


def _host_of(target: Target) -> Optional[str]:
    if target.type == "url":
        return urlparse(target.normalized).hostname
    return domain_from_target(target.type, target.normalized)


async def _origin(ctx: Ctx, target: Target) -> Optional[str]:
    """The target's own web origin (scheme://netloc)."""
    if target.type == "url":
        p = urlparse(target.normalized)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
        return target.normalized.rstrip("/")
    domain = domain_from_target(target.type, target.normalized)
    if not domain:
        return None
    return (await web_base(ctx, target, domain)).rstrip("/")


async def _service_bases(ctx: Ctx, target: Target,
                         ports: List[int]) -> List[str]:
    """Origin first, then the service's conventional ports."""
    origin = await _origin(ctx, target)
    host = _host_of(target)
    bases: List[str] = []
    if origin:
        bases.append(origin)
    if host:
        for p in ports:
            b = f"http://{host}:{p}"
            if b not in bases:
                bases.append(b)
    return bases


async def _req(ctx: Ctx, method: str, url: str, timeout: int = 6,
               **kw) -> Any:
    try:
        return await fetch(ctx.http, ctx.limiter, method, url,
                           timeout=timeout, max_retries=0, **kw)
    except Exception:
        return None


async def _get_json(ctx: Ctx, url: str, timeout: int = 6
                    ) -> Tuple[int, Any]:
    r = await _req(ctx, "GET", url, timeout=timeout,
                   follow_redirects=True)
    if r is None:
        return 0, None
    try:
        return r.status_code, json.loads(r.text)
    except Exception:
        return r.status_code, None


async def _fetch_200(ctx: Ctx, url: str, timeout: int = 10
                     ) -> Optional[str]:
    """GET via the shared page cache; body text only on HTTP 200."""
    try:
        page = await ctx.fetch_page(url, timeout=timeout)
    except Exception:
        return None
    if page is None:
        return None
    try:
        if page["status_code"] != 200:
            return None
        return (page["text"] or "")[:300_000]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Families 1 + 3: exposed serialization / XML schema files
# ---------------------------------------------------------------------------

class _SchemaMiner(Plugin):
    """Mine one schema-file format from the target's own surface.

    Candidates come from (a) references harvested out of the pages and
    JS the run already collected (collect_texts), in every mode, and
    (b) a handful of conventional paths probed on the origin in active
    mode. A finding requires the body to actually PARSE as the format
    (definition patterns), and the evidence is the disclosed names -
    the schema itself is the finding.
    """

    id = None  # abstract; registry skips id-less classes
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 60

    EXT = ""            # ".proto"
    PATHS: List[str] = []
    KEY = ""
    LABEL = ""
    FORMAT = ""
    CATEGORY = "api"
    SEVERITY = "medium"
    CONF = 90
    MAX_FILES = 3

    def parse(self, text: str) -> Optional[Dict[str, Any]]:
        """Evidence extras when `text` parses as this format."""
        return None

    def _link_re(self) -> re.Pattern:
        return re.compile(
            r"((?:https?://[^\s\"'<>]+|[\w./\-]+)" + re.escape(self.EXT)
            + r"(?:\?[^\s\"'<>]*)?)", re.I)

    def _harvest(self, texts) -> List[str]:
        rx = self._link_re()
        out: List[str] = []
        for _where, text, page_url in texts:
            for m in rx.finditer(text or ""):
                ref = m.group(1).strip().strip("\"'()[]{}")
                if not ref or ref.startswith("data:"):
                    continue
                full = urljoin(page_url, ref)
                if full not in out:
                    out.append(full)
                if len(out) >= 6:
                    return out
        return out

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            return await self._run(target, ctx, t0)
        except Exception as e:  # a miner must never throw out of run()
            return self._degraded(f"{self.FORMAT} miner degraded: "
                                  f"{type(e).__name__}")

    async def _run(self, target: Target, ctx: Ctx,
                   t0: float) -> PluginResult:
        candidates: List[Tuple[str, str]] = []  # (url, via)
        texts = await collect_texts(ctx, target)
        for url in self._harvest(texts):
            candidates.append((url, "linked from the target's pages/JS"))
        if self.module_mode(ctx) != "passive":
            origin = await _origin(ctx, target)
            if origin:
                seen = {u for u, _ in candidates}
                for path in self.PATHS:
                    full = origin + path
                    if full not in seen:
                        candidates.append((full, "conventional path"))
        if not candidates:
            return self._ok([], f"no {self.EXT} references or paths")
        findings: List[Finding] = []
        for url, via in candidates:
            if len(findings) >= self.MAX_FILES:
                break
            text = await _fetch_200(ctx, url)
            if not text:
                continue
            parsed = self.parse(text)
            if not parsed:
                continue
            ev = {"severity": self.SEVERITY, "detector": self.id,
                  "format": self.FORMAT, "file": url, "via": via,
                  "size": len(text),
                  "body_sha256": _fingerprint(text),
                  "remediation": _REMEDIATION}
            ev.update(parsed)
            findings.append(self._f(
                self.CATEGORY, self.KEY,
                f"{self.LABEL} publicly served at {url} ({via}): "
                f"{parsed['summary']}",
                source=f"format pack: {self.LABEL}",
                source_url=url, confidence=self.CONF, passive=True,
                evidence=ev))
        res = self._ok(findings,
                       f"{len(findings)} {self.FORMAT} schema file(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res


def _names(rx: str, text: str, cap: int = 8) -> List[str]:
    out: List[str] = []
    for m in re.finditer(rx, text):
        name = m.group(1)
        if name not in out:
            out.append(name)
        if len(out) >= cap:
            break
    return out


class FxProtoSchema(_SchemaMiner):
    id = "fx_proto_schema"
    label = "Protobuf Schema Exposed"
    description = ("A .proto file served publicly: the service, RPC "
                   "method and message definitions are the API's "
                   "complete blueprint.")
    group = "api"
    EXT = ".proto"
    PATHS = ["/schema.proto", "/api.proto", "/service.proto",
             "/proto/service.proto"]
    KEY = "proto_schema_exposed"
    LABEL = "Protobuf schema"
    FORMAT = "Protobuf (.proto)"
    CATEGORY = "api"

    def parse(self, text):
        services = _names(r"\bservice\s+([A-Za-z_]\w*)\s*\{", text)
        messages = _names(r"\bmessage\s+([A-Za-z_]\w*)\s*\{", text, 10)
        rpcs = _names(r"\brpc\s+([A-Za-z_]\w*)\s*\(", text, 10)
        if not services and not messages:
            return None
        parts = []
        if services:
            parts.append(f"{len(services)} service(s): "
                         f"{', '.join(services)}")
        if rpcs:
            parts.append(f"{len(rpcs)} RPC method(s): "
                         f"{', '.join(rpcs[:5])}")
        if messages:
            parts.append(f"{len(messages)} message(s): "
                         f"{', '.join(messages[:5])}")
        return {"summary": "; ".join(parts), "services": services,
                "rpc_methods": rpcs, "messages": messages,
                "service_count": len(services),
                "message_count": len(messages),
                "rpc_count": len(rpcs)}


class FxAvroSchema(_SchemaMiner):
    id = "fx_avro_schema"
    label = "Avro Schema Exposed"
    description = ("An .avsc Avro schema served publicly: record and "
                   "field names disclose the exact shape of the data "
                   "pipeline's payloads.")
    group = "api"
    EXT = ".avsc"
    PATHS = ["/schema.avsc", "/event.avsc", "/schemas/schema.avsc",
             "/avro/schema.avsc"]
    KEY = "avro_schema_exposed"
    LABEL = "Avro schema"
    FORMAT = "Avro (.avsc)"
    CATEGORY = "api"

    def parse(self, text):
        try:
            doc = json.loads(text)
        except Exception:
            return None
        records: List[str] = []
        fields: List[str] = []

        def walk(node: Any) -> None:
            if isinstance(node, dict):
                if node.get("type") == "record" and node.get("name"):
                    records.append(str(node["name"])[:80])
                    for f in node.get("fields") or []:
                        if isinstance(f, dict) and f.get("name"):
                            fields.append(str(f["name"])[:80])
                            walk(f.get("type"))
                else:
                    for v in node.values():
                        walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(doc)
        if not records:
            return None
        records = list(dict.fromkeys(records))[:8]
        fields = list(dict.fromkeys(fields))[:12]
        ns = doc.get("namespace") if isinstance(doc, dict) else None
        summary = (f"{len(records)} record(s): {', '.join(records)}; "
                   f"{len(fields)} field(s): {', '.join(fields[:6])}")
        if ns:
            summary += f"; namespace {str(ns)[:80]}"
        return {"summary": summary, "records": records,
                "fields": fields, "record_count": len(records),
                "field_count": len(fields),
                "namespace": str(ns)[:80] if ns else None}


class FxThriftSchema(_SchemaMiner):
    id = "fx_thrift_schema"
    label = "Thrift IDL Exposed"
    description = ("A .thrift interface definition served publicly: "
                   "service and struct definitions disclose the RPC "
                   "surface in full.")
    group = "api"
    EXT = ".thrift"
    PATHS = ["/service.thrift", "/api.thrift", "/schema.thrift",
             "/thrift/service.thrift"]
    KEY = "thrift_schema_exposed"
    LABEL = "Thrift IDL"
    FORMAT = "Thrift (.thrift)"
    CATEGORY = "api"

    def parse(self, text):
        services = _names(
            r"\bservice\s+([A-Za-z_]\w*)\s*(?:extends\s+[\w.]+\s*)?\{",
            text)
        structs = _names(
            r"\b(?:struct|exception|union)\s+([A-Za-z_]\w*)\s*\{",
            text, 10)
        enums = _names(r"\benum\s+([A-Za-z_]\w*)\s*\{", text)
        if not services and not structs:
            return None
        parts = []
        if services:
            parts.append(f"{len(services)} service(s): "
                         f"{', '.join(services)}")
        if structs:
            parts.append(f"{len(structs)} struct(s): "
                         f"{', '.join(structs[:5])}")
        if enums:
            parts.append(f"{len(enums)} enum(s): "
                         f"{', '.join(enums[:5])}")
        return {"summary": "; ".join(parts), "services": services,
                "structs": structs, "enums": enums,
                "service_count": len(services),
                "struct_count": len(structs)}


class FxFlatBuffersSchema(_SchemaMiner):
    id = "fx_flatbuffers_schema"
    label = "FlatBuffers Schema Exposed"
    description = ("A .fbs FlatBuffers schema served publicly: "
                   "table/struct definitions disclose the binary "
                   "message layout exactly.")
    group = "api"
    EXT = ".fbs"
    PATHS = ["/schema.fbs", "/flatbuffers/schema.fbs",
             "/fbs/schema.fbs"]
    KEY = "flatbuffers_schema_exposed"
    LABEL = "FlatBuffers schema"
    FORMAT = "FlatBuffers (.fbs)"
    CATEGORY = "api"

    def parse(self, text):
        tables = _names(r"\btable\s+([A-Za-z_]\w*)\s*\{", text, 10)
        structs = _names(r"\bstruct\s+([A-Za-z_]\w*)\s*\{", text)
        rpcs = _names(r"\brpc_service\s+([A-Za-z_]\w*)\s*\{", text)
        if not tables and not structs and not rpcs:
            return None
        parts = []
        if tables:
            parts.append(f"{len(tables)} table(s): "
                         f"{', '.join(tables[:5])}")
        if structs:
            parts.append(f"{len(structs)} struct(s): "
                         f"{', '.join(structs[:5])}")
        if rpcs:
            parts.append(f"RPC service: {', '.join(rpcs)}")
        return {"summary": "; ".join(parts), "tables": tables,
                "structs": structs, "rpc_services": rpcs,
                "table_count": len(tables),
                "struct_count": len(structs)}


class FxCapnpSchema(_SchemaMiner):
    id = "fx_capnp_schema"
    label = "Cap'n Proto Schema Exposed"
    description = ("A .capnp Cap'n Proto schema served publicly: "
                   "struct and interface definitions disclose the "
                   "binary protocol contract.")
    group = "api"
    EXT = ".capnp"
    PATHS = ["/schema.capnp", "/api.capnp", "/capnp/schema.capnp"]
    KEY = "capnp_schema_exposed"
    LABEL = "Cap'n Proto schema"
    FORMAT = "Cap'n Proto (.capnp)"
    CATEGORY = "api"

    def parse(self, text):
        structs = _names(r"\bstruct\s+([A-Za-z_]\w*)\s*(?:@|\{)",
                         text, 10)
        interfaces = _names(
            r"\binterface\s+([A-Za-z_]\w*)\s*(?:@|\{)", text)
        if not structs and not interfaces:
            return None
        parts = []
        if structs:
            parts.append(f"{len(structs)} struct(s): "
                         f"{', '.join(structs[:5])}")
        if interfaces:
            parts.append(f"{len(interfaces)} interface(s): "
                         f"{', '.join(interfaces[:5])}")
        return {"summary": "; ".join(parts), "structs": structs,
                "interfaces": interfaces,
                "struct_count": len(structs),
                "interface_count": len(interfaces)}


class FxXsdSchema(_SchemaMiner):
    id = "fx_xsd_schema"
    label = "XML Schema (XSD) Exposed"
    description = ("An .xsd XML Schema served publicly: element and "
                   "type names disclose the exact document grammar "
                   "the application accepts - the map for XXE and "
                   "schema-complexity attacks.")
    group = "web"
    EXT = ".xsd"
    PATHS = ["/schema.xsd", "/api.xsd", "/service.xsd",
             "/wsdl/schema.xsd"]
    KEY = "xsd_schema_exposed"
    LABEL = "XML Schema (XSD)"
    FORMAT = "XML Schema (.xsd)"
    CATEGORY = "web"

    def parse(self, text):
        if not re.search(r"<(?:\w+:)?schema\b", text) or \
                "2001/XMLSchema" not in text:
            return None
        elements = (_names(
            r"<(?:xs|xsd):element[^>]*?\bname=\"([^\"]+)\"", text, 10)
            or _names(r"<element[^>]*?\bname=\"([^\"]+)\"", text, 10))
        complex_types = _names(
            r"<(?:xs|xsd):complexType[^>]*?\bname=\"([^\"]+)\"",
            text, 10)
        simple_types = _names(
            r"<(?:xs|xsd):simpleType[^>]*?\bname=\"([^\"]+)\"",
            text, 10)
        if not elements and not complex_types and not simple_types:
            return None
        parts = []
        if elements:
            parts.append(f"{len(elements)} element(s): "
                         f"{', '.join(elements[:5])}")
        if complex_types:
            parts.append(f"{len(complex_types)} complexType(s): "
                         f"{', '.join(complex_types[:5])}")
        if simple_types:
            parts.append(f"{len(simple_types)} simpleType(s): "
                         f"{', '.join(simple_types[:5])}")
        return {"summary": "; ".join(parts), "elements": elements,
                "complex_types": complex_types,
                "simple_types": simple_types,
                "element_count": len(elements),
                "complex_type_count": len(complex_types)}


class FxDtdSchema(_SchemaMiner):
    id = "fx_dtd_schema"
    label = "DTD Exposed"
    description = ("A .dtd document type definition served "
                   "publicly: element and entity declarations "
                   "disclose the document grammar; external DTDs are "
                   "also the classic XXE delivery file.")
    group = "web"
    EXT = ".dtd"
    PATHS = ["/schema.dtd", "/doc.dtd", "/dtd/schema.dtd"]
    KEY = "dtd_schema_exposed"
    LABEL = "DTD"
    FORMAT = "DTD (.dtd)"
    CATEGORY = "web"

    def parse(self, text):
        if "<!ELEMENT" not in text and "<!ATTLIST" not in text \
                and "<!ENTITY" not in text:
            return None
        elements = _names(r"<!ELEMENT\s+([\w.:-]+)", text, 10)
        entities = _names(r"<!ENTITY\s+(?:%\s+)?([\w.:-]+)",
                          text, 10)
        attlists = _names(r"<!ATTLIST\s+([\w.:-]+)", text, 10)
        if not elements and not entities and not attlists:
            return None
        parts = []
        if elements:
            parts.append(f"{len(elements)} element(s): "
                         f"{', '.join(elements[:5])}")
        if entities:
            parts.append(f"{len(entities)} entit(ies): "
                         f"{', '.join(entities[:5])}")
        if attlists:
            parts.append(f"{len(attlists)} attlist(s)")
        return {"summary": "; ".join(parts), "elements": elements,
                "entities": entities, "attlists": attlists,
                "element_count": len(elements),
                "entity_count": len(entities)}


# ---------------------------------------------------------------------------
# Family 2: deserialization surface fingerprints (PASSIVE ONLY)
# ---------------------------------------------------------------------------

_JAVA_B64_RX = re.compile(r"rO0AB[A-Za-z0-9+/=_-]{6,}")
_PHP_OBJ_RX = re.compile(r"O:\d+:\"[^\"\r\n]{1,80}\":\d+:\{")
_PHP_ARR_RX = re.compile(r"a:\d+:\{(?:i:\d+;|s:\d+:)")
_B64_TOKEN_RX = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
_VIEWSTATE_RX = re.compile(
    r"name=\"__VIEWSTATE\"[^>]*?value=\"([^\"]{40,})\"", re.I | re.S)
_BINARYFORMATTER_MARK = "AAEAAAD/////"
_JAVA_CT = "application/x-java-serialized-object"
_JAVA_MAGIC = b"\xac\xed\x00\x05"


def _b64_decode(token: str) -> Optional[bytes]:
    t = (token or "").strip()
    if len(t) < 16:
        return None
    pad = "=" * (-len(t) % 4)
    for alt in (None, "-_"):
        try:
            raw = base64.b64decode(t + pad, altchars=alt,
                                   validate=False)
            if raw:
                return raw
        except (binascii.Error, ValueError):
            continue
    return None


def _looks_like_pickle(raw: Optional[bytes]) -> bool:
    if not raw or len(raw) < 10:
        return False
    if raw[0] == 0x80 and len(raw) > 1 and 2 <= raw[1] <= 5:
        return True  # binary protocol 2-5 stream
    head = raw[:80]
    return (b"copyreg" in head or head.startswith(b"(dp")
            or head.startswith(b"c__builtin__"))


class FxDeserializationSurface(Plugin):
    """PASSIVE fingerprints of native deserialization surfaces.

    Only inspects what the target already sends: Set-Cookie values
    and bodies of the pages/JS the run already collects. No probe,
    no payload - a marker in the target's own outbound traffic is
    enough to prove the surface exists. Values are never stored:
    evidence carries a 16-char prefix + the value length only.
    """

    id = "fx_deserialization_surface"
    label = "Deserialization Surface (passive)"
    description = ("Native serialized objects (Java, PHP, Python "
                   "pickle, .NET) observed in the target's own "
                   "cookies and responses - the classic untrusted-"
                   "deserialization attack surface.")
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            res = await self._run(target, ctx)
        except Exception as e:  # never throw out of run()
            res = self._degraded(
                f"deserialization scan degraded: {type(e).__name__}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    def _hit(self, findings, seen, key, fmt, where, sample, length,
             conf=85):
        if key in seen:
            return
        seen.add(key)
        findings.append(self._f(
            "web", key,
            f"{fmt} observed in {where} - if any endpoint accepts "
            f"this format back from a client, it is an untrusted-"
            f"deserialization surface (sample masked, "
            f"{length} chars total)",
            source="format pack: deserialization surface (passive)",
            confidence=conf, passive=True,
            evidence={"severity": "medium", "detector": self.id,
                      "format": fmt, "where": where,
                      "sample_prefix": (sample or "")[:16],
                      "value_length": length,
                      "remediation": _DESER_REMEDIATION}))

    async def _run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings: List[Finding] = []
        seen = set()
        cookies: List[Tuple[str, str]] = []  # (name, value)

        origin = await _origin(ctx, target)
        resp_headers = {}
        resp_body = ""
        if origin:
            r = await _req(ctx, "GET", origin + "/", timeout=10,
                           follow_redirects=True)
            if r is not None:
                resp_headers = r.headers
                resp_body = (r.text or "")[:300_000]
                try:
                    raw_cookies = r.headers.get_list("set-cookie")
                except Exception:
                    raw_cookies = []
                if not raw_cookies:
                    one = r.headers.get("set-cookie")
                    raw_cookies = [one] if one else []
                for raw_cookie in raw_cookies:
                    first = (raw_cookie or "").split(";")[0]
                    if "=" in first:
                        name, value = first.split("=", 1)
                        cookies.append((name.strip(), value.strip()))
                ctype = (r.headers.get("content-type") or "").lower()
                if _JAVA_CT in ctype:
                    self._hit(findings, seen, "java_serialized_object",
                              "Java serialized object stream",
                              "homepage Content-Type", _JAVA_CT,
                              len(_JAVA_CT), conf=90)

        texts = await collect_texts(ctx, target)
        bodies: List[Tuple[str, str]] = []
        if resp_body:
            bodies.append(("homepage body", resp_body))
        for where, text, _url in texts:
            if text:
                bodies.append((where, text))

        scan_values: List[Tuple[str, str]] = [
            (f"Set-Cookie '{n}'", v) for n, v in cookies]
        scan_values += bodies

        # Java serialized object: base64 streams start "rO0AB"
        # (magic AC ED 00 05); also try decoding cookie values.
        for where, value in scan_values:
            m = _JAVA_B64_RX.search(value or "")
            if m:
                self._hit(findings, seen, "java_serialized_object",
                          "Java serialized object (base64)",
                          where, m.group(0), len(m.group(0)))
                break
        if "java_serialized_object" not in seen:
            for name, value in cookies:
                raw = _b64_decode(value)
                if raw and raw.startswith(_JAVA_MAGIC):
                    self._hit(findings, seen,
                              "java_serialized_object",
                              "Java serialized object (base64)",
                              f"Set-Cookie '{name}'", value,
                              len(value))
                    break

        # PHP serialized values in cookies / reflected bodies.
        for where, value in scan_values:
            m = _PHP_OBJ_RX.search(value or "") or \
                _PHP_ARR_RX.search(value or "")
            if m:
                self._hit(findings, seen, "php_serialized_data",
                          "PHP serialized value", where, m.group(0),
                          len(value))
                break

        # Python pickle: base64 tokens that decode to a pickle
        # stream (binary protocols start 0x80 0x02-0x05).
        pickle_checked = 0
        for where, value in scan_values:
            if "python_pickle_data" in seen:
                break
            tokens = [value] if where.startswith("Set-Cookie") else \
                _B64_TOKEN_RX.findall(value or "")
            for token in tokens:
                if pickle_checked >= 300:
                    break
                pickle_checked += 1
                raw = _b64_decode(token)
                if _looks_like_pickle(raw):
                    self._hit(findings, seen, "python_pickle_data",
                              "Python pickle stream (base64)", where,
                              token, len(token), conf=80)
                    break

        # .NET: BinaryFormatter base64 header, ViewState blob.
        for where, value in scan_values:
            idx = (value or "").find(_BINARYFORMATTER_MARK)
            if idx >= 0:
                self._hit(findings, seen,
                          "dotnet_binaryformatter_data",
                          ".NET BinaryFormatter payload", where,
                          value[idx:idx + 32], len(value), conf=80)
                break
        for _where, text in bodies:
            m = _VIEWSTATE_RX.search(text or "")
            if m:
                self._hit(findings, seen, "aspnet_viewstate",
                          "ASP.NET ViewState",
                          "homepage __VIEWSTATE field", m.group(1),
                          len(m.group(1)), conf=90)
                break

        if not scan_values and not cookies:
            return self._degraded("homepage fetch failed")
        return self._ok(
            findings, f"{len(seen)} deserialization surface(s)")


# ---------------------------------------------------------------------------
# Family 4: graph & semantic endpoints (read-only identification)
# ---------------------------------------------------------------------------

class _GraphProbe(Plugin):
    """Probe one graph service's own identification surface.

    Fires only on the service's own response shape - a generic 200,
    a login wall, or a 401 means no finding. Read-only GETs only.
    """

    id = None  # abstract
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    timeout_s = 90

    PORTS: List[int] = []
    PATHS = ["/"]
    KEY = ""
    LABEL = ""
    HEADERS: Optional[Dict[str, str]] = None

    def check(self, status: int, text: str) -> Optional[Dict[str, Any]]:
        return None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            res = await self._run(target, ctx)
        except Exception as e:  # never throw out of run()
            res = self._degraded(
                f"{self.LABEL} probe degraded: {type(e).__name__}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _run(self, target: Target, ctx: Ctx) -> PluginResult:
        if self.module_mode(ctx) == "passive":
            return self._ok([], f"{self.LABEL}: active mode only")
        bases = await _service_bases(ctx, target, self.PORTS)
        if not bases:
            return self._skipped("no resolvable target host")
        for base in bases:
            for path in self.PATHS:
                r = await _req(ctx, "GET", base + path, timeout=6,
                               follow_redirects=True,
                               headers=self.HEADERS or {})
                if r is None:
                    continue
                extras = self.check(r.status_code, r.text or "")
                if extras is None:
                    continue
                url = base + path
                ev = {"severity": "high", "detector": self.id,
                      "url": url, "remediation": _REMEDIATION}
                ev.update(extras)
                value = (f"{self.LABEL} answers at {url} WITHOUT "
                         f"authentication: {extras['summary']}")
                return self._ok([self._f(
                    "graph", self.KEY, value,
                    source=f"format pack: {self.LABEL}",
                    source_url=url, confidence=90, passive=False,
                    evidence=ev)],
                    f"{self.LABEL} open at {url}")
        return self._ok([], f"no open {self.LABEL}")


class FxSparqlEndpoint(_GraphProbe):
    id = "fx_sparql_endpoint"
    label = "Open SPARQL Endpoint"
    description = ("A SPARQL endpoint answering an unauthenticated "
                   "service-description request: the dataset/graph "
                   "summary itself is disclosed, and a query "
                   "endpoint that describes itself usually also "
                   "answers queries.")
    PORTS = [8890, 3030]  # Virtuoso, Jena Fuseki defaults
    PATHS = ["/sparql", "/query"]
    KEY = "sparql_endpoint_open"
    LABEL = "SPARQL endpoint"
    HEADERS = {"Accept": "text/turtle, application/rdf+xml;q=0.9"}

    _MARKERS = ("sd:Service", "sd:defaultDataset", "sd:feature",
                "sd:resultFormat", "void:Dataset")

    def check(self, status, text):
        if status != 200 or not text:
            return None
        hits = [m for m in self._MARKERS if m in text]
        if len(hits) < 2 or not any(h.startswith("sd:")
                                    for h in hits):
            return None
        datasets = text.count("void:Dataset")
        graphs = text.count("sd:NamedGraph") + \
            text.count("sd:namedGraph")
        features = text.count("sd:feature")
        formats = text.count("sd:resultFormat")
        summary = (f"service description lists {datasets} "
                   f"dataset(s), {graphs} named graph ref(s), "
                   f"{features} feature(s), {formats} result "
                   f"format(s)")
        return {"summary": summary, "markers": hits,
                "datasets": datasets, "named_graph_refs": graphs,
                "feature_refs": features, "format_refs": formats}


class FxNeo4jOpen(_GraphProbe):
    id = "fx_neo4j_open"
    label = "Neo4j Discovery Open"
    description = ("Neo4j's HTTP discovery endpoint answering "
                   "without authentication and advertising its Bolt "
                   "address - the graph database's front door.")
    PORTS = [7474]
    PATHS = ["/"]
    KEY = "neo4j_discovery_open"
    LABEL = "Neo4j discovery"

    def check(self, status, text):
        if status != 200 or not text:
            return None
        try:
            data = json.loads(text)
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        if "bolt" not in data and not (
                "data" in data and "management" in data):
            return None
        bolt = str(data.get("bolt") or "")[:100]
        version = data.get("neo4j_version")
        summary = f"discovery JSON advertises Bolt at {bolt}" \
            if bolt else "discovery JSON lists data/management URLs"
        if version:
            summary += f"; Neo4j version {str(version)[:20]}"
        return {"summary": summary, "bolt": bolt,
                "neo4j_version": str(version)[:20] if version
                else None}


class FxArangoOpen(_GraphProbe):
    id = "fx_arangodb_open"
    label = "ArangoDB Open (no auth)"
    description = ("ArangoDB's /_api/version answering without "
                   "authentication - auth is disabled or the "
                   "instance is otherwise wide open.")
    PORTS = [8529]
    PATHS = ["/_api/version"]
    KEY = "arangodb_open"
    LABEL = "ArangoDB"

    def check(self, status, text):
        if status != 200 or not text:
            return None
        try:
            data = json.loads(text)
        except Exception:
            return None
        if not isinstance(data, dict) or \
                data.get("server") != "arango" or \
                data.get("error") is True:
            return None
        version = str(data.get("version") or "")[:20]
        lic = str(data.get("license") or "")[:20]
        return {"summary": f"version {version} ({lic} license), "
                           f"no auth challenge",
                "version": version, "license": lic}


class FxGremlinOpen(_GraphProbe):
    id = "fx_gremlin_open"
    label = "Gremlin Server Open"
    description = ("A Gremlin Server (JanusGraph / TinkerPop) HTTP "
                   "endpoint answering without authentication - "
                   "its traversal endpoint executes submitted "
                   "scripts by design.")
    PORTS = [8182]
    PATHS = ["/"]
    KEY = "gremlin_server_open"
    LABEL = "Gremlin Server"

    def check(self, status, text):
        if status not in (200, 400) or not text:
            return None
        low = text.lower()
        gremlin_shape = "no gremlin script supplied" in low or \
            ('"requestid"' in low and "gremlin" in low)
        if not gremlin_shape:
            return None
        message = ""
        try:
            data = json.loads(text)
            message = str((data.get("status") or {}).get(
                "message") or "")[:120]
        except Exception:
            message = text[:120]
        return {"summary": f"server status reply: {message}",
                "status_message": message}


FX_IDS = ["fx_proto_schema", "fx_avro_schema", "fx_thrift_schema",
          "fx_flatbuffers_schema", "fx_capnp_schema",
          "fx_xsd_schema", "fx_dtd_schema",
          "fx_deserialization_surface", "fx_sparql_endpoint",
          "fx_neo4j_open", "fx_arangodb_open", "fx_gremlin_open"]
