"""Cat-9 (300-expansion) Network & Protocol Traffic Analysis.

Per plugin: fires on a VULN fixture, silent on a CLEAN fixture, no
crash on malformed input. Fixtures are crafted bytes: a pcap with a
plaintext FTP login (password asserted masked), an SDP blob with
host candidates, a shadow-style AS-REP-roastable account record,
IKE proposals/configs with DES/NULL-grade transforms, SMB negotiate
responses, RADIUS packets without Message-Authenticator, and local
127.0.0.1 listeners for the live posture lanes (SOCKS5 / SMB / FTP
PASV / NTP / SSDP / STUN / RPCbind).

Boundary fixtures double as guards: the detection-only plugins
(snmp / radius / kerberos / ftp-pasv) are asserted to report
posture from supplied data and never carry a raw secret.
"""
import asyncio
import json
import os
import socket
import struct
import sys
import threading

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

IDS = [
    "websocket_stream_recorder", "grpc_protobuf_payload_decoder",
    "http2_frame_stream_analyzer", "dns_over_https_sni_extractor",
    "quic_packet_flow_reassembler", "pcap_credential_auto_miner",
    "socks5_proxy_handshake_logger", "stun_turn_ice_candidate_map",
    "custom_tcp_length_fuzzer", "smb_v3_dialect_validator",
    "snmp_community_string_brute", "radius_packet_secret_tester",
    "bgp_route_leak_detector", "ntp_amplification_vector_probe",
    "graphql_subscription_sniffer", "ssdp_msearch_device_harvester",
    "oauth_redirect_uri_validator", "saml_assertion_replay_tester",
    "kerberos_ticket_asrep_roast", "ipsec_ike_transform_scanner",
    "rpcbind_procedure_dump", "webrtc_sdp_media_leak_check",
    "m3u8_stream_ts_decrypter", "ftp_passive_port_hijacker",
    "netflow_traffic_volume_profiler",
    "wireshark_dissector_lua_generator",
]

MODULES = {pid: pid for pid in IDS}


def analyze(pid, data):
    import importlib
    mod = importlib.import_module(f"app.plugins.{MODULES[pid]}")
    return mod.analyze(data, "fixture.bin")


def keys(pid, data):
    return {h["key"] for h in analyze(pid, data)}


def blob(pid, data):
    return json.dumps(analyze(pid, data), default=str)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------

def eth_ip_tcp(payload, sport=12345, dport=21, src="10.0.0.1",
               dst="10.0.0.2"):
    tcp = struct.pack(">HHIIHHHH", sport, dport, 1, 0, 0x5018,
                      8192, 0, 0)
    total = 20 + 20 + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    return eth + ip + tcp + payload


def eth_ip_udp(payload, sport=12345, dport=443, src="10.0.0.1",
               dst="10.0.0.2"):
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0)
    total = 20 + 8 + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17,
                     0, socket.inet_aton(src),
                     socket.inet_aton(dst))
    eth = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00"
    return eth + ip + udp + payload


def build_pcap(packets):
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for p in packets:
        out += struct.pack("<IIII", 0, 0, len(p), len(p)) + p
    return out


def client_hello(sni):
    name = sni.encode()
    sni_entry = b"\x00" + struct.pack(">H", len(name)) + name
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    ext = struct.pack(">H", 0) + struct.pack(">H", len(sni_list)) \
        + sni_list
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + \
        struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" + \
        struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def h2_frame(ftype, flags, sid, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes(
        [ftype, flags]) + struct.pack(">I", sid) + payload


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def smb2_response(dialect=0x0202, security_mode=1):
    body = struct.pack("<HHH", 65, security_mode, dialect) + \
        b"\x00" * 40
    payload = b"\xfeSMB" + b"\x00" * 60 + body
    return struct.pack(">I", len(payload)) + payload


def smb1_response():
    payload = b"\xffSMB" + b"\x72" + b"\x00" * 30
    return struct.pack(">I", len(payload)) + payload


def radius_packet(code=2, with_ma=False):
    attrs = b"\x01\x04ab"
    if with_ma:
        attrs += bytes([80, 18]) + b"\x00" * 16
    ln = 20 + len(attrs)
    return bytes([code, 1]) + struct.pack(">H", ln) + \
        b"\x00" * 16 + attrs


def ike_response(encr=1, integ=1, dh=2):
    def tr(t, i):
        return bytes([0, 0]) + struct.pack(">H", 8) + bytes([t, 0]) \
            + struct.pack(">H", i)
    transforms = tr(1, encr) + tr(3, integ) + tr(4, dh)
    prop = bytes([0, 0]) + struct.pack(">H", 8 + len(transforms)) + \
        bytes([1, 1, 0, 3]) + transforms
    sa = bytes([0, 0]) + struct.pack(">H", 4 + len(prop)) + prop
    hdr = b"\x01" * 8 + b"\x02" * 8 + bytes([33, 0x20, 34, 0x20]) + \
        struct.pack(">I", 0) + struct.pack(">I", 28 + len(sa))
    return hdr + sa


# ---------------------------------------------------------------------------
# 241 websocket stream recorder
# ---------------------------------------------------------------------------

def test_websocket_stream_recorder():
    vuln = (b'{"dir": "c2s", "opcode": 1, "payload": '
            b'"password=Str0ngPass!"}\n'
            b'{"dir": "s2c", "opcode": 2, "len": 70000, '
            b'"payload": ""}\n')
    ks = keys("websocket_stream_recorder", vuln)
    assert "ws_frame_credential_payload" in ks
    assert "ws_frame_oversized" in ks
    assert "Str0ngPass" not in blob("websocket_stream_recorder", vuln)
    clean = b'{"dir": "c2s", "opcode": 1, "payload": "hello"}\n'
    assert analyze("websocket_stream_recorder", clean) == []


# ---------------------------------------------------------------------------
# 243 grpc protobuf decoder
# ---------------------------------------------------------------------------

def test_grpc_protobuf_decoder():
    schema = (b'syntax = "proto3";\nmessage LoginReq {\n'
              b'  string username = 1;\n  string password = 2;\n}\n')
    payload = b"\x0a\x03bob" + b"\x12\x0b" + b"hunter2pass"
    vuln = schema + b"PAYLOAD_HEX: " + payload.hex().encode() + b"\n"
    assert "grpc_sensitive_field_decoded" in keys(
        "grpc_protobuf_payload_decoder", vuln)
    assert "hunter2pass" not in blob(
        "grpc_protobuf_payload_decoder", vuln)
    clean_schema = (b'syntax = "proto3";\nmessage Profile {\n'
                    b'  string display_name = 1;\n}\n')
    clean_payload = b"\x0a\x05alice"
    clean = clean_schema + b"PAYLOAD_HEX: " + \
        clean_payload.hex().encode() + b"\n"
    assert analyze("grpc_protobuf_payload_decoder", clean) == []


# ---------------------------------------------------------------------------
# 244 http2 frame analyzer
# ---------------------------------------------------------------------------

def test_http2_frame_analyzer():
    vuln = H2_PREFACE + h2_frame(0, 0, 1, b"x" * 20000)
    assert "http2_oversized_frame" in keys(
        "http2_frame_stream_analyzer", vuln)
    reset = H2_PREFACE + b"".join(
        h2_frame(1, 0x1, sid) + h2_frame(3, 0, sid)
        for sid in range(1, 26, 2))
    assert "http2_rapid_reset_pattern" in keys(
        "http2_frame_stream_analyzer", reset)
    zero = H2_PREFACE + h2_frame(0, 0, 0, b"abc")
    assert "http2_data_on_stream_zero" in keys(
        "http2_frame_stream_analyzer", zero)
    clean = H2_PREFACE + h2_frame(4, 0, 0) + \
        h2_frame(1, 0x4, 1) + h2_frame(0, 0x1, 1, b"ok")
    assert analyze("http2_frame_stream_analyzer", clean) == []


# ---------------------------------------------------------------------------
# 245 DoH / SNI extractor
# ---------------------------------------------------------------------------

def test_doh_sni_extractor():
    vuln = build_pcap([eth_ip_tcp(client_hello("db.internal.corp"),
                                  dport=443)])
    assert "sni_internal_name_exposure" in keys(
        "dns_over_https_sni_extractor", vuln)
    doh = b"GET /dns-query?name=wiki.corp.internal HTTP/1.1\r\n" \
          b"Accept: application/dns-message\r\n\r\n"
    assert "doh_internal_name_leak" in keys(
        "dns_over_https_sni_extractor", doh)
    clean = build_pcap([eth_ip_tcp(client_hello("www.example.com"),
                                   dport=443)])
    assert analyze("dns_over_https_sni_extractor", clean) == []
    from app.plugins.dns_over_https_sni_extractor import \
        analyze_svcb
    hits = analyze_svcb({"Answer": [{"data":
                        'example.com. 300 IN HTTPS 1 . '
                        'alpn="h2" dohpath="/dns-query{?dns}"'}]},
                        "example.com")
    assert hits and hits[0]["key"] == "doh_endpoint_exposed"
    assert analyze_svcb({"Answer": [{"data":
                        'example.com. 300 IN HTTPS 1 . alpn="h2"'}]},
                        "example.com") == []


# ---------------------------------------------------------------------------
# 246 QUIC reassembler
# ---------------------------------------------------------------------------

def test_quic_reassembler():
    vuln = (b'{"dcid": "abcd", "pn": 7, "type": "initial"}\n'
            b'{"dcid": "abcd", "pn": 7, "type": "initial"}\n'
            b'{"dcid": "abcd", "pn": 8, "type": '
            b'"version_negotiation"}\n')
    ks = keys("quic_packet_flow_reassembler", vuln)
    assert "quic_packet_number_reuse" in ks
    assert "quic_version_negotiation_seen" in ks
    clean = (b'{"dcid": "abcd", "pn": 1, "type": "initial"}\n'
             b'{"dcid": "abcd", "pn": 2, "type": "short"}\n')
    assert analyze("quic_packet_flow_reassembler", clean) == []


# ---------------------------------------------------------------------------
# 247 pcap credential miner
# ---------------------------------------------------------------------------

def test_pcap_credential_miner():
    vuln = build_pcap([eth_ip_tcp(
        b"USER alice\r\nPASS Sup3rSecret!\r\n", dport=21)])
    assert "pcap_cleartext_credential" in keys(
        "pcap_credential_auto_miner", vuln)
    assert "Sup3rSecret!" not in blob(
        "pcap_credential_auto_miner", vuln)
    basic = build_pcap([eth_ip_tcp(
        b"GET / HTTP/1.1\r\nAuthorization: Basic "
        b"Ym9iOlBhc3N3b3JkMTIz\r\n\r\n", dport=80)])
    assert "pcap_cleartext_credential" in keys(
        "pcap_credential_auto_miner", basic)
    assert "Password123" not in blob(
        "pcap_credential_auto_miner", basic)
    clean = build_pcap([eth_ip_tcp(
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        dport=80)])
    assert analyze("pcap_credential_auto_miner", clean) == []


# ---------------------------------------------------------------------------
# 248 socks5 handshake logger (pure part; live part below)
# ---------------------------------------------------------------------------

def test_socks5_pure():
    from app.plugins.socks5_proxy_handshake_logger import \
        analyze_handshake
    hits = analyze_handshake(b"\x05\x00")
    assert hits and hits[0]["key"] == "socks5_no_auth_open_proxy"
    assert analyze_handshake(b"\x05\xff") == []
    assert analyze_handshake(b"\x05\x02") == []
    assert analyze_handshake(b"") == []


# ---------------------------------------------------------------------------
# 249 STUN/TURN ICE map
# ---------------------------------------------------------------------------

SDP_SRFLX = (
    b"v=0\r\na=ice-ufrag:abcd\r\n"
    b"a=candidate:1 1 udp 999 192.168.1.5 50000 typ host\r\n"
    b"a=candidate:2 1 udp 888 8.8.4.4 62000 typ srflx "
    b"raddr 192.168.1.5 rport 50000\r\n"
    b"a=candidate:3 1 udp 777 1.2.3.4 3478 typ relay\r\n"
    b'{"iceServers": [{"urls": "turn:turn.example.com:3478", '
    b'"username": "u", "credential": "p"}]}\r\n')


def test_stun_turn_ice_map():
    ks = keys("stun_turn_ice_candidate_map", SDP_SRFLX)
    assert "stun_srflx_mapping_disclosed" in ks
    assert "turn_relay_open_posture" in ks
    clean = (b"a=candidate:1 1 udp 999 abc123.local 50000 typ host"
             b"\r\n")
    assert analyze("stun_turn_ice_candidate_map", clean) == []
    from app.plugins.stun_turn_ice_candidate_map import (
        build_binding_request, parse_binding_response)
    import struct as st
    req, tid = build_binding_request()
    cookie = 0x2112A442
    ip_int = int.from_bytes(socket.inet_aton("203.0.113.7"), "big")
    port = 40000 ^ (cookie >> 16)
    attr = st.pack(">HHBBH", 0x0020, 8, 0, 1, port) + \
        st.pack(">I", ip_int ^ cookie)
    resp = b"\x01\x01" + st.pack(">H", len(attr)) + \
        b"\x21\x12\xa4\x42" + tid + attr
    assert parse_binding_response(resp, tid) == ("203.0.113.7",
                                                 40000)


# ---------------------------------------------------------------------------
# 250 custom TCP length fuzzer (outcome analysis)
# ---------------------------------------------------------------------------

def test_custom_tcp_length_fuzzer():
    vuln = (b'{"length": 65535, "outcome": "crash"}\n'
            b'{"length": 0, "outcome": "ok"}\n')
    assert "tcp_length_boundary_differential" in keys(
        "custom_tcp_length_fuzzer", vuln)
    clean = (b'{"length": 65535, "outcome": "ok"}\n'
             b'{"length": 0, "outcome": "ok"}\n')
    assert analyze("custom_tcp_length_fuzzer", clean) == []


# ---------------------------------------------------------------------------
# 251 SMB dialect validator
# ---------------------------------------------------------------------------

def test_smb_dialect_validator():
    ks = keys("smb_v3_dialect_validator", smb2_response())
    assert "smb_old_dialect_negotiated" in ks
    assert "smb_signing_not_required" in ks
    assert "smb1_fallback_accepted" in keys(
        "smb_v3_dialect_validator", smb1_response())
    clean = smb2_response(dialect=0x0311, security_mode=3)
    assert analyze("smb_v3_dialect_validator", clean) == []
    cfg = b"[global]\nmin protocol = NT1\nserver signing = auto\n"
    ks2 = keys("smb_v3_dialect_validator", cfg)
    assert "smb1_fallback_accepted" in ks2
    assert "smb_signing_not_required" in ks2


# ---------------------------------------------------------------------------
# 252 SNMP detection-only
# ---------------------------------------------------------------------------

def test_snmp_detection_only():
    vuln = b"snmp-server community Pr1vateComm RW\n"
    ks = keys("snmp_community_string_brute", vuln)
    assert "snmp_v2c_rw_community" in ks
    assert "Pr1vateComm" not in blob(
        "snmp_community_string_brute", vuln)
    ro = b"rocommunity SomeCommStr0ng\n"
    assert "snmp_v1_v2c_in_use" in keys(
        "snmp_community_string_brute", ro)
    clean = (b"snmp-server user ops netops v3 auth sha SomeAuth "
             b"priv aes 128 SomePriv\n"
             b"snmp-server group netops v3 priv\n")
    assert analyze("snmp_community_string_brute", clean) == []


# ---------------------------------------------------------------------------
# 253 RADIUS detection-only (BlastRADIUS posture)
# ---------------------------------------------------------------------------

def test_radius_detection_only():
    assert "radius_response_without_message_authenticator" in keys(
        "radius_packet_secret_tester", radius_packet(with_ma=False))
    assert analyze("radius_packet_secret_tester",
                   radius_packet(with_ma=True)) == []
    cfg = b"[radius]\nrequire-message-authenticator = no\n"
    assert "radius_message_authenticator_not_required" in keys(
        "radius_packet_secret_tester", cfg)


# ---------------------------------------------------------------------------
# 254 BGP route leak detector
# ---------------------------------------------------------------------------

def test_bgp_route_leak_detector():
    vuln = json.dumps({"routes": [{
        "prefix": "203.0.113.0/24", "origin_as": 64500,
        "announced_by": 64600, "rpki_status": "invalid",
        "as_path": [64500, 64500, 64600],
        "received_from": "peer", "sent_to": "provider"}]}).encode()
    ks = keys("bgp_route_leak_detector", vuln)
    assert "bgp_rpki_invalid_origin" in ks
    assert "bgp_as_path_loop" in ks
    assert "bgp_route_leak_pattern" in ks
    clean = json.dumps({"routes": [{
        "prefix": "203.0.113.0/24", "origin_as": 64500,
        "announced_by": 64500, "rpki_status": "valid",
        "as_path": [64500, 64496],
        "received_from": "customer", "sent_to": "peer"}]}).encode()
    assert analyze("bgp_route_leak_detector", clean) == []


# ---------------------------------------------------------------------------
# 255 NTP amplification probe (pure part)
# ---------------------------------------------------------------------------

def test_ntp_pure():
    big = b"\x1f" + b"\x00" * 511  # mode 7, 512 bytes
    ks = keys("ntp_amplification_vector_probe", big)
    assert "ntp_amplification_posture" in ks
    assert "ntp_mode7_private_response" in ks
    clean = b"\x1c" + b"\x00" * 47  # mode 4 server, 48 bytes
    assert analyze("ntp_amplification_vector_probe", clean) == []


# ---------------------------------------------------------------------------
# 256 GraphQL subscription sniffer
# ---------------------------------------------------------------------------

def test_graphql_subscription_sniffer():
    vuln = (b'{"type": "data", "id": "1", "payload": {"data": '
            b'{"userUpdated": {"email": "a@example.com", '
            b'"token": "tok-value-123"}}}}\n'
            b'subscription { userUpdated { email token } }\n')
    assert "graphql_subscription_payload_leak" in keys(
        "graphql_subscription_sniffer", vuln)
    assert "tok-value-123" not in blob(
        "graphql_subscription_sniffer", vuln)
    clean = (b'{"type": "data", "payload": {"data": '
             b'{"__typename": "Subscription"}}}\n')
    assert analyze("graphql_subscription_sniffer", clean) == []


# ---------------------------------------------------------------------------
# 257 SSDP harvester (pure part)
# ---------------------------------------------------------------------------

SSDP_IGD = (b"HTTP/1.1 200 OK\r\n"
            b"ST: urn:schemas-upnp-org:device:"
            b"InternetGatewayDevice:1\r\n"
            b"SERVER: Linux/2.6 UPnP/1.0 MiniUPnPd/1.0\r\n"
            b"LOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n"
            b"USN: uuid:abcd::urn:schemas-upnp-org:device:"
            b"InternetGatewayDevice:1\r\n\r\n")


def test_ssdp_pure():
    assert "ssdp_gateway_device_exposed" in keys(
        "ssdp_msearch_device_harvester", SSDP_IGD)
    clean = (b"HTTP/1.1 200 OK\r\n"
             b"ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n"
             b"SERVER: Linux/5.x UPnP/1.0 Renderer/2.0\r\n\r\n")
    assert analyze("ssdp_msearch_device_harvester", clean) == []


# ---------------------------------------------------------------------------
# 259 OAuth redirect URI validator
# ---------------------------------------------------------------------------

def test_oauth_redirect_uri_validator():
    vuln = json.dumps({"redirect_uris": [
        "https://*.apps.example.com/cb",
        "http://app.example.com/cb"]}).encode()
    ks = keys("oauth_redirect_uri_validator", vuln)
    assert "oauth_redirect_uri_wildcard" in ks
    assert "oauth_redirect_uri_cleartext" in ks
    mismatch = json.dumps({
        "redirect_uris": ["https://app.example.com/cb"],
        "observed_authorize_url":
            "https://idp.example.com/authorize?client_id=1&"
            "redirect_uri=https://evil.example.net/cb"}).encode()
    assert "oauth_redirect_uri_unregistered_host" in keys(
        "oauth_redirect_uri_validator", mismatch)
    clean = json.dumps({"redirect_uris": [
        "https://app.example.com/cb"]}).encode()
    assert analyze("oauth_redirect_uri_validator", clean) == []


# ---------------------------------------------------------------------------
# 260 SAML replay posture
# ---------------------------------------------------------------------------

SAML_META_VULN = (
    b'<EntityDescriptor entityID="https://sp.example.com">'
    b'<SPSSODescriptor protocolSupportEnumeration='
    b'"urn:oasis:names:tc:SAML:2.0:protocol">'
    b'<KeyDescriptor><KeyInfo/></KeyDescriptor>'
    b'</SPSSODescriptor></EntityDescriptor>'
    b'<SignatureMethod Algorithm="http://www.w3.org/2000/09/'
    b'xmldsig#rsa-sha1"/>')

SAML_ASSERTION_VULN = (
    b'<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">'
    b'<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">'
    b'<Subject><NameID>user@example.com</NameID></Subject>'
    b'<AuthnStatement AuthnInstant="2026-01-01T00:00:00Z"/>'
    b'</Assertion></Response>')


def test_saml_replay_tester():
    ks = keys("saml_assertion_replay_tester", SAML_META_VULN)
    assert "saml_want_assertions_signed_absent" in ks
    assert "saml_sha1_signature_algorithm" in ks
    ks2 = keys("saml_assertion_replay_tester", SAML_ASSERTION_VULN)
    assert "saml_missing_validity_window" in ks2
    assert "saml_missing_audience_restriction" in ks2
    clean = (
        b'<EntityDescriptor entityID="https://sp.example.com">'
        b'<SPSSODescriptor WantAssertionsSigned="true" '
        b'WantAssertionsEncrypted="true">'
        b'</SPSSODescriptor></EntityDescriptor>'
        b'<SignatureMethod Algorithm="http://www.w3.org/2001/04/'
        b'xmldsig-more#rsa-sha256"/>')
    assert analyze("saml_assertion_replay_tester", clean) == []


# ---------------------------------------------------------------------------
# 261 Kerberos AS-REP posture (detection-only)
# ---------------------------------------------------------------------------

LDIF_VULN = (b"dn: CN=John Doe,OU=Users,DC=corp,DC=example\n"
             b"sAMAccountName: jdoe\n"
             b"userAccountControl: 4194816\n\n"
             b"dn: CN=Jane Roe,OU=Users,DC=corp,DC=example\n"
             b"sAMAccountName: jroe\n"
             b"userAccountControl: 66048\n")


def test_kerberos_asrep_posture():
    ks = keys("kerberos_ticket_asrep_roast", LDIF_VULN)
    assert "kerberos_asrep_roastable_account" in ks
    hits = analyze("kerberos_ticket_asrep_roast", LDIF_VULN)
    assert len(hits) == 1 and "jdoe" in hits[0]["value"]
    clean = LDIF_VULN.replace(b"4194816", b"512")
    assert analyze("kerberos_ticket_asrep_roast", clean) == []
    js = json.dumps([{"name": "svc-backup",
                      "userAccountControl": 4194816}]).encode()
    assert "kerberos_asrep_roastable_account" in keys(
        "kerberos_ticket_asrep_roast", js)


# ---------------------------------------------------------------------------
# 263 IPsec IKE transform scanner
# ---------------------------------------------------------------------------

def test_ike_transform_scanner():
    ks = keys("ipsec_ike_transform_scanner", ike_response())
    assert "ike_weak_encryption_transform" in ks
    assert "ike_md5_integrity_transform" in ks
    assert "ike_weak_dh_group" in ks
    clean = ike_response(encr=7, integ=2, dh=14)
    # AES-CBC + SHA1-integrity + DH14: only the parser must not
    # flag DES/MD5/weak-DH keys.
    assert "ike_weak_encryption_transform" not in keys(
        "ipsec_ike_transform_scanner", clean)
    assert "ike_weak_dh_group" not in keys(
        "ipsec_ike_transform_scanner", clean)
    cfg = (b"conn vpn\n ike=aes256-sha256-modp2048!\n"
           b" esp=3des-md5-modp1024!\n aggrmode=yes\n")
    ksc = keys("ipsec_ike_transform_scanner", cfg)
    assert "ike_weak_transform_in_config" in ksc
    assert "ikev1_aggressive_mode_enabled" in ksc
    clean_cfg = (b"conn vpn\n ike=aes256-sha256-modp2048!\n"
                 b" esp=aes256-sha256!\n keyexchange=ikev2\n")
    assert analyze("ipsec_ike_transform_scanner", clean_cfg) == []


# ---------------------------------------------------------------------------
# 264 RPCbind procedure dump
# ---------------------------------------------------------------------------

def test_rpcbind_dump():
    vuln = (b"   program vers proto   port  service\n"
            b"    100000    2   tcp    111  rpcbind\n"
            b"    100003    3   tcp   2049  nfs\n"
            b"    100005    3   udp   4002  mountd\n"
            b"    100004    2   tcp   1023  ypserv\n")
    assert "rpcbind_sensitive_program_exposed" in keys(
        "rpcbind_procedure_dump", vuln)
    clean = (b"    100000    2   tcp    111  rpcbind\n"
             b"    100001    3   udp    999  rstatd\n")
    assert analyze("rpcbind_procedure_dump", clean) == []
    from app.plugins.rpcbind_procedure_dump import (
        build_pmap_dump_call, parse_pmap_dump_reply)
    assert len(build_pmap_dump_call()) == 36
    reply = struct.pack(">IIIIII", 0x1234ABCD, 1, 0, 0, 0, 0)
    reply += struct.pack(">IIIII", 1, 100003, 3, 17, 2049)
    reply += struct.pack(">I", 0)
    progs = parse_pmap_dump_reply(reply)
    assert progs and progs[0]["program"] == 100003


# ---------------------------------------------------------------------------
# 265 WebRTC SDP media leak check
# ---------------------------------------------------------------------------

SDP_WEBRTC_VULN = (
    b"v=0\r\na=candidate:1 1 udp 2122260223 192.168.1.50 54400 "
    b"typ host generation 0\r\n"
    b'{"iceServers": [{"urls": '
    b'"turn:turn.example.com:3478?transport=udp", "username": '
    b'"relayuser", "credential": "TurnPass999"}]}\r\n')


def test_webrtc_sdp_leak():
    ks = keys("webrtc_sdp_media_leak_check", SDP_WEBRTC_VULN)
    assert "webrtc_host_candidate_private_ip_leak" in ks
    assert "webrtc_turn_credentials_embedded" in ks
    assert "TurnPass999" not in blob(
        "webrtc_sdp_media_leak_check", SDP_WEBRTC_VULN)
    clean = (
        b"a=candidate:1 1 udp 2122260223 "
        b"a1b2c3d4.local 54400 typ host\r\n"
        b'{"iceServers": [{"urls": "turns:turn.example.com:5349"}]}'
        b"\r\n")
    assert analyze("webrtc_sdp_media_leak_check", clean) == []


# ---------------------------------------------------------------------------
# 266 M3U8 stream protection audit
# ---------------------------------------------------------------------------

def test_m3u8_audit():
    none_pl = (b"#EXTM3U\n#EXT-X-KEY:METHOD=NONE\n"
               b"#EXTINF:6,\nseg1.ts\n")
    assert "hls_cleartext_segments" in keys(
        "m3u8_stream_ts_decrypter", none_pl)
    keyed = (b"#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,"
             b'URI="key.bin",IV=0x00000000000000000000000000000001\n'
             b"#EXTINF:6,\nseg1.ts\n")
    ks = keys("m3u8_stream_ts_decrypter", keyed)
    assert "hls_key_uri_served_with_playlist" in ks
    assert "hls_static_iv_reuse" in ks
    clean = (b"#EXTM3U\n#EXT-X-KEY:METHOD=AES-128,"
             b'URI="https://keys.example.com/keys/42"\n'
             b"#EXTINF:6,\nseg1.ts\n")
    assert analyze("m3u8_stream_ts_decrypter", clean) == []


# ---------------------------------------------------------------------------
# 267 FTP PASV posture (detection-only)
# ---------------------------------------------------------------------------

def test_ftp_pasv_posture():
    vuln = (
        b"control host: 127.0.0.1\n"
        b"227 Entering Passive Mode (127,0,0,1,195,80)\n"
        b"227 Entering Passive Mode (127,0,0,1,195,81)\n"
        b"227 Entering Passive Mode (127,0,0,1,195,82)\n")
    assert "ftp_pasv_predictable_ports" in keys(
        "ftp_passive_port_hijacker", vuln)
    mismatch = (
        b"control host: 10.0.0.9\n"
        b"227 Entering Passive Mode (203,0,113,44,195,80)\n")
    assert "ftp_pasv_address_mismatch" in keys(
        "ftp_passive_port_hijacker", mismatch)
    clean = (
        b"control host: 127.0.0.1\n"
        b"227 Entering Passive Mode (127,0,0,1,201,17)\n"
        b"227 Entering Passive Mode (127,0,0,1,99,240)\n"
        b"227 Entering Passive Mode (127,0,0,1,160,3)\n")
    assert analyze("ftp_passive_port_hijacker", clean) == []


# ---------------------------------------------------------------------------
# 269 NetFlow profiler
# ---------------------------------------------------------------------------

def test_netflow_profiler():
    flows = []
    for i in range(10):
        flows.append({"src": "10.0.0.5", "dst": "45.33.32.156",
                      "bytes": 2_000_000, "ts": 1_700_000_000 + i,
                      "dport": 443})
    flows.append({"src": "10.0.0.5", "dst": "93.184.216.34",
                  "bytes": 1_000_000, "ts": 1_700_000_100,
                  "dport": 443})
    vuln = json.dumps(flows).encode()
    assert "netflow_bulk_exfil_pattern" in keys(
        "netflow_traffic_volume_profiler", vuln)
    beacon = json.dumps([
        {"src": "10.0.0.6", "dst": "91.198.174.2", "bytes": 400,
         "ts": 1_700_000_000 + 60 * i, "dport": 53}
        for i in range(10)]).encode()
    assert "netflow_beacon_pattern" in keys(
        "netflow_traffic_volume_profiler", beacon)
    clean = json.dumps([
        {"src": "10.0.0.7", "dst": "93.184.216.34", "bytes": 5000,
         "ts": 1_700_000_000 + 137 * i, "dport": 443}
        for i in range(6)]).encode()
    assert analyze("netflow_traffic_volume_profiler", clean) == []
    csv_data = (b"src,dst,bytes,ts,dport\n"
                b"10.0.0.5,45.33.32.156,20000000,1700000000,443\n"
                b"10.0.0.5,93.184.216.34,100000,1700000100,443\n")
    assert "netflow_bulk_exfil_pattern" in keys(
        "netflow_traffic_volume_profiler", csv_data)


# ---------------------------------------------------------------------------
# 270 Wireshark dissector generator
# ---------------------------------------------------------------------------

def test_dissector_generator():
    layout = json.dumps({
        "name": "myproto", "transport": "tcp", "ports": [9999],
        "fields": [{"name": "magic", "type": "uint32", "size": 4},
                   {"name": "cmd", "type": "uint8", "size": 1},
                   {"name": "data", "type": "string"}]}).encode()
    assert "wireshark_dissector_generated" in keys(
        "wireshark_dissector_lua_generator", layout)
    from app.plugins.wireshark_dissector_lua_generator import \
        generate_lua, parse_layout
    lua = generate_lua(parse_layout(layout))
    assert "Proto(" in lua and "DissectorTable" in lua
    assert "9999" in lua
    assert analyze("wireshark_dissector_lua_generator",
                   b'{"name": "x"}') == []
    assert analyze("wireshark_dissector_lua_generator",
                   b"random text, no layout") == []


# ---------------------------------------------------------------------------
# Malformed input: nothing crashes, everything returns a list
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pid", IDS)
def test_malformed_no_crash(pid):
    for blobb in (b"", b"\x00", b"\xff" * 37, os.urandom(513),
                  b"hsqs", b"PRI * HTTP/2.0", b"#EXTM3U",
                  b"\xd4\xc3\xb2\xa1" + b"\x00" * 20):
        hits = analyze(pid, blobb)
        assert isinstance(hits, list)


# ---------------------------------------------------------------------------
# run() end-to-end over supplied artifacts (stub ctx, real Ctx)
# ---------------------------------------------------------------------------

def _ctx(shared=None, mode="passive"):
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(404, request=r)),
        follow_redirects=True, trust_env=False)
    ctx = Ctx(run_id="cat9-test", mode=mode, http=client,
              cache=Cache(), keys={}, limiter=RateLimiter(),
              evidence_dir="/tmp", source_type="website")
    for k, v in (shared or {}).items():
        ctx.shared[k] = list(v)
    return ctx


def run_plugin(pid, shared=None, target=None, mode="passive"):
    from app.plugins.registry import discover
    cls = discover()[pid]
    ctx = _ctx(shared, mode=mode)
    tgt = target or Target(raw="supplied-capture", type="artifact",
                           normalized="supplied-capture")

    async def _go():
        try:
            return await asyncio.wait_for(
                cls().run(tgt, ctx), timeout=30)
        finally:
            await ctx.http.aclose()
    return asyncio.run(_go())


def test_run_end_to_end_samples():
    vuln = build_pcap([eth_ip_tcp(
        b"USER alice\r\nPASS Sup3rSecret!\r\n", dport=21)])
    res = run_plugin("pcap_credential_auto_miner",
                     {"captures": [("cap.pcap", vuln)]})
    assert res.status.value == "ok"
    assert {f.key for f in res.findings} >= \
        {"pcap_cleartext_credential"}
    assert "Sup3rSecret!" not in json.dumps(
        [f.value for f in res.findings])
    res = run_plugin("snmp_community_string_brute",
                     {"captures": [("dev.cfg",
                                    b"snmp-server community "
                                    b"Pr1vateComm RW\n")]})
    assert {f.key for f in res.findings} >= \
        {"snmp_v2c_rw_community"}
    res = run_plugin("kerberos_ticket_asrep_roast",
                     {"captures": [("dir.ldif", LDIF_VULN)]})
    assert {f.key for f in res.findings} >= \
        {"kerberos_asrep_roastable_account"}
    res = run_plugin("tlv-nonexistent-guard".replace(
        "tlv-nonexistent-guard", "netflow_traffic_volume_profiler"),
        {"captures": []})
    assert res.status.value == "ok" and res.findings == []


# ---------------------------------------------------------------------------
# Live smoke: local 127.0.0.1 listeners started by this test file
# ---------------------------------------------------------------------------

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve_tcp(handler):
    port = _free_port()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)

    def loop():
        srv.settimeout(15)
        try:
            while True:
                conn, _ = srv.accept()
                threading.Thread(target=handler, args=(conn,),
                                 daemon=True).start()
        except Exception:
            pass
        finally:
            srv.close()
    threading.Thread(target=loop, daemon=True).start()
    return port


def _serve_udp(responder):
    port = _free_port()
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", port))

    def loop():
        srv.settimeout(15)
        try:
            while True:
                data, addr = srv.recvfrom(65535)
                reply = responder(data)
                if reply:
                    srv.sendto(reply, addr)
        except Exception:
            pass
        finally:
            srv.close()
    threading.Thread(target=loop, daemon=True).start()
    return port


def _live(pid, port, shared=None):
    tgt = Target(raw=f"127.0.0.1:{port}", type="ip",
                 normalized=f"127.0.0.1:{port}")
    return run_plugin(pid, shared=shared, target=tgt, mode="active")


def _udp_blocked():
    """Some sandboxes deny UDP sendto for spawned processes
    (EPERM) while allowing TCP; live UDP smoke is impossible
    there and the plugins degrade gracefully instead."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"\x00", ("127.0.0.1", 9))
        s.close()
        return False
    except PermissionError:
        return True
    except Exception:
        return False


UDP_BLOCKED = _udp_blocked()
udp_required = pytest.mark.skipif(
    UDP_BLOCKED, reason="sandbox blocks UDP sendto (EPERM)")


def test_live_socks5_no_auth():
    def handler(conn):
        with conn:
            conn.recv(64)
            conn.sendall(b"\x05\x00")
    port = _serve_tcp(handler)
    res = _live("socks5_proxy_handshake_logger", port)
    assert {f.key for f in res.findings} >= \
        {"socks5_no_auth_open_proxy"}


def test_live_smb_dialects():
    def handler(conn):
        with conn:
            conn.settimeout(5)
            data = conn.recv(4096)
            if b"\xffSMB" in data:
                conn.sendall(smb1_response())
            else:
                conn.sendall(smb2_response())
    port = _serve_tcp(handler)
    res = _live("smb_v3_dialect_validator", port)
    ks = {f.key for f in res.findings}
    assert "smb_old_dialect_negotiated" in ks
    assert "smb1_fallback_accepted" in ks


def test_live_ftp_pasv_predictable():
    state = {"n": 0}

    def handler(conn):
        with conn:
            f = conn.makefile("rw", encoding="latin1",
                              newline="\r\n")
            f.write("220 fake ftp\r\n")
            f.flush()
            while True:
                line = f.readline()
                if not line:
                    break
                cmd = line.strip().upper()
                if cmd.startswith("USER"):
                    f.write("331 ok\r\n")
                elif cmd.startswith("PASS"):
                    f.write("230 ok\r\n")
                elif cmd.startswith("PASV"):
                    p = 50000 + state["n"]
                    state["n"] += 1
                    f.write(f"227 Entering Passive Mode "
                            f"(127,0,0,1,{p // 256},{p % 256})\r\n")
                elif cmd.startswith("QUIT"):
                    f.write("221 bye\r\n")
                    f.flush()
                    break
                else:
                    f.write("200 ok\r\n")
                f.flush()
    port = _serve_tcp(handler)
    res = _live("ftp_passive_port_hijacker", port)
    assert {f.key for f in res.findings} >= \
        {"ftp_pasv_predictable_ports"}


@udp_required
def test_live_ntp_amplification():
    port = _serve_udp(lambda data: b"\x1c" + b"\x00" * 511)
    res = _live("ntp_amplification_vector_probe", port)
    assert {f.key for f in res.findings} >= \
        {"ntp_amplification_posture"}


@udp_required
def test_live_ssdp_igd():
    port = _serve_udp(lambda data: SSDP_IGD)
    res = _live("ssdp_msearch_device_harvester", port)
    assert {f.key for f in res.findings} >= \
        {"ssdp_gateway_device_exposed"}


@udp_required
def test_live_stun_binding():
    cookie = 0x2112A442

    def responder(data):
        tid = data[8:20]
        ip_int = int.from_bytes(
            socket.inet_aton("203.0.113.7"), "big")
        attr = struct.pack(">HHBBH", 0x0020, 8, 0, 1,
                           40000 ^ (cookie >> 16)) + \
            struct.pack(">I", ip_int ^ cookie)
        return b"\x01\x01" + struct.pack(">H", len(attr)) + \
            b"\x21\x12\xa4\x42" + tid + attr
    port = _serve_udp(responder)
    res = _live("stun_turn_ice_candidate_map", port)
    assert {f.key for f in res.findings} >= \
        {"stun_public_mapping_exposed"}


@udp_required
def test_live_rpcbind_dump():
    def responder(data):
        reply = struct.pack(">IIIIII", 0x1234ABCD, 1, 0, 0, 0, 0)
        reply += struct.pack(">IIIII", 1, 100003, 3, 17, 2049)
        reply += struct.pack(">I", 0)
        return reply
    port = _serve_udp(responder)
    res = _live("rpcbind_procedure_dump", port)
    assert {f.key for f in res.findings} >= \
        {"rpcbind_sensitive_program_exposed"}


def test_registry_count_and_ids():
    from app.plugins.registry import discover
    reg = discover()
    assert len(reg) == 1346  # 1165 master + 26 Cat-9 (300-expansion) plugins + 1 cache_control_audit plugin
    for pid in IDS:
        assert pid in reg, pid
