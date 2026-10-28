"""Canary content for the format & graph pack (fx_*) tests / proof.

Planted values are assembled from fragments so no complete fake
secret ever sits in the repo (the lesson from the privfind canary,
which tripped GitHub Push Protection). The deserialization markers
are the real thing on purpose: a Java serialized stream's base64
prefix, a PHP serialized string, a genuine pickle.dumps payload -
that is precisely what the passive detector fingerprints.
"""
from __future__ import annotations

import base64
import pickle

# --- Family 1+3: schema files ----------------------------------------------

PROTO = """// Fx canary protobuf definition.
syntax = "proto3";

package fx.payments;

service FxPayments {
  rpc Charge (ChargeRequest) returns (ChargeReply);
  rpc Refund (RefundRequest) returns (ChargeReply);
}

message ChargeRequest {
  string card_token = 1;
  int64 amount_cents = 2;
}

message RefundRequest {
  string payment_id = 1;
}

message ChargeReply {
  bool ok = 1;
  string receipt_url = 2;
}
"""

AVSC = """{
  "type": "record",
  "name": "FxPaymentEvent",
  "namespace": "fx.events",
  "fields": [
    {"name": "payment_id", "type": "string"},
    {"name": "amount_cents", "type": "long"},
    {"name": "card_token", "type": "string"},
    {"name": "meta", "type": {
      "type": "record",
      "name": "FxEventMeta",
      "fields": [{"name": "source_ip", "type": "string"}]
    }}
  ]
}
"""

THRIFT = """namespace py fx.ledger

struct FxAccount {
  1: i64 id,
  2: string email
}

exception FxLedgerError {
  1: string message
}

service FxLedger {
  FxAccount getAccount(1: i64 id),
  void ping()
}
"""

FBS = """namespace Fx.Game;

table FxSprite {
  name: string;
  hp: int;
}

struct FxVec3 {
  x: float;
  y: float;
  z: float;
}

root_type FxSprite;
"""

CAPNP = """@0xdb4b8d0f9a2c4e71;

struct FxPerson {
  name @0 :Text;
  email @1 :Text;
}

interface FxDirectory {
  lookup @0 (name :Text) -> (person :FxPerson);
}
"""

XSD = """<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           elementFormDefault="qualified">
  <xs:element name="FxInvoice" type="FxInvoiceType"/>
  <xs:complexType name="FxInvoiceType">
    <xs:sequence>
      <xs:element name="fxAmount" type="xs:decimal"/>
      <xs:element name="fxCardToken" type="xs:string"/>
    </xs:sequence>
  </xs:complexType>
  <xs:simpleType name="FxCurrencyCode">
    <xs:restriction base="xs:string"/>
  </xs:simpleType>
</xs:schema>
"""

DTD = """<!ELEMENT fx-note (fx-to, fx-body)>
<!ELEMENT fx-to (#PCDATA)>
<!ELEMENT fx-body (#PCDATA)>
<!ATTLIST fx-note id CDATA #REQUIRED>
<!ENTITY fxco "Fx Canary Co">
"""

# --- Family 2: deserialization markers -------------------------------------

# Base64 of the Java serialization magic (AC ED 00 05) + stream body:
# every real Java serialized object base64-encodes starting "rO0AB".
_JAVA_FRAG = ("rO0A" + "B" + "XyZ9kLm" + "Q" * 20)
JAVA_COOKIE_VALUE = _JAVA_FRAG + "N" * 24

PHP_COOKIE_VALUE = ('O:8:"FxPr' + 'efs":2:{s:4:"user";s:5:"admin";'
                    's:5:"theme";s:4:"dark";}')

VIEWSTATE_VALUE = ("dDwy" + "MDAx" * 40) + "=="

PICKLE_BYTES = pickle.dumps(
    {"session_user": "fx-canary", "role": "admin"}, protocol=4)
PICKLE_B64 = base64.b64encode(PICKLE_BYTES).decode()

BINARYFORMATTER_VALUE = ("AAEA" + "AAD//" + "///" + "AQAA" + "AAAA"
                         + "AA" * 16)

# --- Family 4: graph service replies ---------------------------------------

NEO4J_JSON = {
    "management": "http://canary.test:7474/db/manage/",
    "data": "http://canary.test:7474/db/data/",
    "bolt": "bolt://canary.test:7687",
    "neo4j_version": "5.12.0",
    "neo4j_edition": "community",
}

ARANGO_JSON = {"server": "arango", "license": "community",
               "version": "3.11.4"}

GREMLIN_JSON = {"requestId": "fx-canary-1",
                "status": {"message": "no gremlin script supplied",
                           "code": 400, "attributes": {}}}

SPARQL_TURTLE = """@prefix sd: <http://www.w3.org/ns/sparql-service-description#> .
@prefix void: <http://rdfs.org/ns/void#> .

[] a sd:Service ;
    sd:endpoint <http://canary.test/sparql> ;
    sd:supportedLanguage sd:SPARQL11Query ;
    sd:resultFormat <http://www.w3.org/ns/formats/Turtle> ;
    sd:feature sd:DereferencesURIs ;
    sd:defaultDataset [
        a sd:Dataset, void:Dataset ;
        sd:defaultGraph [
            a sd:Graph ;
            void:triples 4200
        ]
    ] ;
    sd:namedGraph [
        a sd:NamedGraph ;
        sd:name <http://canary.test/graph/fx>
    ] .
"""

SCHEMA_LINKS = ["/schemas/api.proto", "/schemas/user.avsc",
                "/schemas/service.thrift", "/schemas/game.fbs",
                "/schemas/schema.capnp", "/schemas/schema.xsd",
                "/schemas/doc.dtd"]

CANARY_HTML = """<!doctype html>
<html><head><title>FX Canary Holdings</title></head>
<body>
<h1>FX Canary Holdings</h1>
<p>Internal API contracts (do not publish):</p>
<ul>
""" + "\n".join(
    f'  <li><a href="{p}">{p}</a></li>' for p in SCHEMA_LINKS) + """
</ul>
<form method="post" action="/legacy.aspx">
  <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE"
         value=\"""" + VIEWSTATE_VALUE + """\" />
  <input type="hidden" name="__VIEWSTATEGENERATOR"
         id="__VIEWSTATEGENERATOR" value="FXCA12" />
</form>
<script src="/assets/app.js"></script>
</body></html>
"""

CANARY_JS = ('window.FX_LEGACY_STATE = "' + BINARYFORMATTER_VALUE
             + '";\nwindow.FX_SESSION_BLOB = "' + PICKLE_B64
             + '";\n// proto also referenced from JS: '
             + 'fetch("/schemas/api.proto");\n')

ROUTES = {
    "/schemas/api.proto": PROTO,
    "/schemas/user.avsc": AVSC,
    "/schemas/service.thrift": THRIFT,
    "/schemas/game.fbs": FBS,
    "/schemas/schema.capnp": CAPNP,
    "/schemas/schema.xsd": XSD,
    "/schemas/doc.dtd": DTD,
}

CLEAN_HTML = ("<!doctype html><html><head><title>Clean Bakery"
              "</title></head><body><h1>Clean Bakery</h1>"
              "<p>Fresh bread daily. No APIs, no schemas, no "
              "graphs.</p></body></html>")

# Probe-table bait that must NOT fire the graph probes: a generic
# JSON blob with the word gremlin and a requestId but the wrong
# shape lives on the CLEAN host root.
CLEAN_JSON = {"name": "clean-api", "version": "1.0.0"}
