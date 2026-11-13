"""Fixtures for the deep infra detectors (feat/deep-lowlevel-50).

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate";
CLEAN[id] MUST stay silent under ALL 29 infra detectors.

Inputs are dicts consumed by analyze_deep_infra_inputs:
  route_data, quic_versions, alt_svc, ja4_list, tcp_observations,
  nsec3_records, latency_observations, qpack_observations,
  connection_outcomes, artifact_bytes (hex), artifact_text,
  graphql_schema, wire_samples, mqtt_probe, etcd_probe,
  consul_probe, jwks.
"""
import base64
import json
import struct
import zlib


def _wasm_module(with_memory_export: bool, with_max: bool) -> str:
    out = bytearray(b"\x00asm\x01\x00\x00\x00")
    mem = bytearray()
    mem.append(1)
    if with_max:
        mem += b"\x01\x01\x0a"  # flags=1 (has max), min=1, max=10
    else:
        mem += b"\x00\x01"      # flags=0 (no max), min=1
    out += bytes([5, len(mem)]) + mem
    exp = bytearray()
    exp.append(1)
    name = b"memory"
    exp.append(len(name))
    exp += name
    exp.append(0x02 if with_memory_export else 0x00)  # memory / function
    exp.append(0)
    out += bytes([7, len(exp)]) + exp
    return bytes(out).hex()


def _packfile(payload: bytes) -> str:
    obj = bytearray()
    obj.append((3 << 4) | (len(payload) & 0x0F))  # type 3 (blob)
    raw = bytes(obj) + zlib.compress(payload)
    return base64.b64encode(
        b"PACK" + struct.pack(">II", 2, 1) + raw).decode()


VULN = {
    "bgp_rpki_roa_hijack_anomaly_detector": {
        "route_data": [
            {"prefix": "203.0.113.0/24", "asn": "64500",
             "roa_status": "valid"},
            {"prefix": "203.0.113.0/24", "asn": "64501",
             "roa_status": "invalid"},
        ]},
    "quic_initial_packet_version_fingerprinter": {
        "quic_versions": ["0x00000001", "0xff00001d"]},
    "ja4_tls_client_hello_entropy_profiler": {
        "ja4_list": ["t13d1516h2_8daaf6152771_e5627efa2ab1_"]},
    "tcp_isn_clock_skew_uptime_estimator": {
        "tcp_observations": [
            {"timestamp": 1000, "isn": 1_000_000},
            {"timestamp": 1010, "isn": 3_000_000},
        ]},
    "dnssec_nsec3_zone_walker": {
        "nsec3_records": [
            {"owner": "aaa.example", "iterations": 0, "opt_out": True,
             "next_hashed": "aaa.example"},
        ]},
    "anycast_pop_bgp_latency_triangulator": {
        "latency_observations": [
            {"rtt_ms": 12.1, "pop": "fra"},
            {"rtt_ms": 12.4, "pop": "nrt"},
        ]},
    "http3_qpack_dynamic_table_fingerprinter": {
        "qpack_observations": [
            {"cross_connection_reuse": True,
             "dynamic_table_size": 4096, "encoder_max_table_size": 4096},
        ]},
    "ebpf_xdp_packet_drop_signature_prober": {
        "connection_outcomes": [
            {"port": 80, "outcome": "timeout"},
            {"port": 443, "outcome": "timeout"},
            {"port": 22, "outcome": "rst"},
        ]},
    "wasm_linear_memory_export_inspector": {
        "artifact_bytes": _wasm_module(True, False)},
    "v8_heap_snapshot_closure_secret_extractor": {
        "artifact_text": json.dumps({
            "snapshot": {"strings": ["api_key", "user", "token"],
                         "nodes": []}})},
    "electron_asar_integrity_bypass_checker": {
        "artifact_text": json.dumps({
            "files": {"main.js": {"size": 100}}})},
    "mobile_apk_native_jni_symbol_dumper": {
        "artifact_text": "Java_com_example_SignCrypto signData "
                         "Java_com_example_Native cryptoKey"},
    "ios_macho_entitlement_plist_extractor": {
        "artifact_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0"><dict>'
            '<key>get-task-allow</key><true/>'
            '</dict></plist>')},
    "graphql_federation_subgraph_entity_resolver": {
        "graphql_schema": (
            "type Query { _entities(representations: [_Any!]!): "
            "[_Entity]! _service: _Service! }")},
    "protobuf_wire_format_schema_inferrer": {
        "wire_samples": ["0801", "0a026162"]},
    "mqtt_wildcard_topic_acl_enumerator": {
        "mqtt_probe": {"anonymous_allowed": True,
                       "wildcard_allowed": True}},
    "etcd_raft_consensus_keyspace_dumper": {
        "etcd_probe": {"auth_required": False, "key_count": 3,
                       "key_names_sample": ["/config/api_key",
                                            "/config/port"]}},
    "consul_gossip_serf_member_enumerator": {
        "consul_probe": {"auth_required": False,
                         "members": ["node1", "node2"]}},
    "aws_sts_assume_role_trust_policy_grapher": {
        "artifact_text": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            }]})},
    "oidc_jwks_kid_cache_poison_surface_check": {
        "jwks": {"keys": [
            {"kty": "RSA", "kid": "key1", "n": "abc", "e": "AQAB"},
            {"kty": "RSA", "kid": "key1", "n": "xyz", "e": "AQAB"},
        ]}},
    "saml_xml_signature_wrapping_structural_linter": {
        "artifact_text": (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r1">'
            '<saml:Assertion ID="a1"><saml:Issuer>x</saml:Issuer></saml:Assertion>'
            '<saml:Assertion ID="a2"><saml:Issuer>y</saml:Issuer></saml:Assertion>'
            '<ds:Signature><ds:SignedInfo><ds:Reference URI="#a1"/>'
            '</ds:SignedInfo></ds:Signature>'
            '</samlp:Response>')},
    "kerberos_spn_asrep_roastability_auditor": {
        "artifact_text": "svc_web spn: HTTP/web.example.com "
                         "preauth: false\n"},
    "ldap_schema_acl_delegation_pathfinder": {
        "artifact_text": "alice -> Domain Admins: GenericWrite\n"},
    "git_packfile_dangling_blob_carver": {
        "artifact_bytes": _packfile(
            b"DB_PASSWORD=supersecretvalue123\n")},
    "container_overlayfs_whiteout_layer_differ": {
        "artifact_text": json.dumps({
            "layers": [
                {"id": "l1", "files": [
                    {"path": "config.yaml", "secret": True}]},
                {"id": "l2", "files": [
                    {"path": ".wh.config.yaml", "type": "whiteout"}]},
            ]})},
    "terraform_state_backend_drift_extractor": {
        "artifact_text": json.dumps({
            "backend": {"type": "s3", "config": {"encrypt": False}},
            "resources": []})},
    "sbom_cyclonedx_transitive_cve_linker": {
        "artifact_text": json.dumps({
            "metadata": {"component": {"bom-ref": "root"}},
            "components": [
                {"bom-ref": "direct-a", "name": "direct-a",
                 "version": "1.0"},
                {"bom-ref": "trans-b", "name": "trans-b",
                 "version": "2.0"},
            ],
            "dependencies": [
                {"ref": "root", "dependsOn": ["direct-a"]},
                {"ref": "direct-a", "dependsOn": ["trans-b"]},
            ],
            "vulnerabilities": [
                {"id": "CVE-2024-1234",
                 "affects": [{"ref": "trans-b"}]},
            ]})},
    "stylometry_commit_cadence_timezone_profiler": {
        "artifact_text": "\n".join(
            f"abc{i:04d} 2026-11-0{i % 9 + 1} 09:{10 + i:02d}:00 +05:30"
            for i in range(10))},
    "agent_sandbox_syscall_deterministic_guard": {
        "artifact_text": json.dumps({
            "allowed_syscalls": [], "blocked_syscalls": [],
            "allow_network": True, "allow_wall_clock": True,
            "fixed_seed": None, "cpu_seconds": 0, "memory_mb": 0,
            "max_open_files": 0, "max_file_bytes": 0,
            "timeout_s": 0})},
}

CLEAN = {
    "bgp_rpki_roa_hijack_anomaly_detector": {
        "route_data": [
            {"prefix": "203.0.113.0/24", "asn": "64500",
             "roa_status": "valid"},
        ]},
    "quic_initial_packet_version_fingerprinter": {
        "quic_versions": ["0x00000001"]},
    "ja4_tls_client_hello_entropy_profiler": {
        "ja4_list": ["t13d1516h2_8daaf6152771_e5627efa2ab1_9a1b2c3d4e5f"]},
    "tcp_isn_clock_skew_uptime_estimator": {
        "tcp_observations": [
            {"timestamp": 1000, "isn": 1_000_000},
            {"timestamp": 1010, "isn": 1_640_000},
        ]},
    "dnssec_nsec3_zone_walker": {
        "nsec3_records": [
            {"owner": "aaa.example", "iterations": 5, "opt_out": False,
             "next_hashed": "aaa.example"},
        ]},
    "anycast_pop_bgp_latency_triangulator": {
        "latency_observations": [
            {"rtt_ms": 12.1, "pop": "fra"},
            {"rtt_ms": 120.4, "pop": "nrt"},
        ]},
    "http3_qpack_dynamic_table_fingerprinter": {
        "qpack_observations": [
            {"cross_connection_reuse": False,
             "dynamic_table_size": 1024, "encoder_max_table_size": 4096},
        ]},
    "ebpf_xdp_packet_drop_signature_prober": {
        "connection_outcomes": [
            {"port": 80, "outcome": "rst"},
            {"port": 443, "outcome": "rst"},
            {"port": 22, "outcome": "rst"},
        ]},
    "wasm_linear_memory_export_inspector": {
        "artifact_bytes": _wasm_module(False, True)},
    "v8_heap_snapshot_closure_secret_extractor": {
        "artifact_text": json.dumps({
            "snapshot": {"strings": ["user", "count", "value"],
                         "nodes": []}})},
    "electron_asar_integrity_bypass_checker": {
        "artifact_text": json.dumps({
            "integrity": {"algorithm": "SHA256", "hash": "abc"},
            "files": {"main.js": {"size": 100}}})},
    "mobile_apk_native_jni_symbol_dumper": {
        "artifact_text": "Java_com_example_Main onCreate "
                         "Java_com_example_Main onResume"},
    "ios_macho_entitlement_plist_extractor": {
        "artifact_text": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<plist version="1.0"><dict>'
            '<key>application-identifier</key><string>TEAM.app</string>'
            '</dict></plist>')},
    "graphql_federation_subgraph_entity_resolver": {
        "graphql_schema": (
            "type Query @authenticated { _entities(representations: "
            "[_Any!]!): [_Entity]! }")},
    "protobuf_wire_format_schema_inferrer": {
        "wire_samples": ["0801", "1002"]},
    "mqtt_wildcard_topic_acl_enumerator": {
        "mqtt_probe": {"anonymous_allowed": False,
                       "wildcard_allowed": False}},
    "etcd_raft_consensus_keyspace_dumper": {
        "etcd_probe": {"auth_required": True}},
    "consul_gossip_serf_member_enumerator": {
        "consul_probe": {"auth_required": True}},
    "aws_sts_assume_role_trust_policy_grapher": {
        "artifact_text": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {
                    "sts:ExternalId": "secret-id"}},
            }]})},
    "oidc_jwks_kid_cache_poison_surface_check": {
        "jwks": {"keys": [
            {"kty": "RSA", "kid": "key1", "n": "abc", "e": "AQAB"},
            {"kty": "RSA", "kid": "key2", "n": "xyz", "e": "AQAB"},
        ]}},
    "saml_xml_signature_wrapping_structural_linter": {
        "artifact_text": (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="r1">'
            '<saml:Assertion ID="a1"><saml:Issuer>x</saml:Issuer></saml:Assertion>'
            '<ds:Signature><ds:SignedInfo><ds:Reference URI="#a1"/>'
            '</ds:SignedInfo></ds:Signature>'
            '</samlp:Response>')},
    "kerberos_spn_asrep_roastability_auditor": {
        "artifact_text": "svc_web spn: HTTP/web.example.com\n"
                         "svc_web preauth: true\n"},
    "ldap_schema_acl_delegation_pathfinder": {
        "artifact_text": "alice -> Workstations: GenericWrite\n"},
    "git_packfile_dangling_blob_carver": {
        "artifact_bytes": _packfile(b"hello world\n")},
    "container_overlayfs_whiteout_layer_differ": {
        "artifact_text": json.dumps({
            "layers": [
                {"id": "l1", "files": [
                    {"path": "config.yaml"}]},
                {"id": "l2", "files": [
                    {"path": "other.yaml"}]},
            ]})},
    "terraform_state_backend_drift_extractor": {
        "artifact_text": json.dumps({
            "backend": {"type": "s3", "config": {"encrypt": True}},
            "resources": []})},
    "sbom_cyclonedx_transitive_cve_linker": {
        "artifact_text": json.dumps({
            "metadata": {"component": {"bom-ref": "root"}},
            "components": [
                {"bom-ref": "direct-a", "name": "direct-a",
                 "version": "1.0"},
            ],
            "dependencies": [
                {"ref": "root", "dependsOn": ["direct-a"]},
            ],
            "vulnerabilities": []})},
    "stylometry_commit_cadence_timezone_profiler": {
        "artifact_text": "\n".join([
            "abc0001 2026-11-01 09:15:00 +05:30",
            "abc0002 2026-11-02 22:40:00 -08:00",
            "abc0003 2026-11-03 03:05:00 +00:00",
            "abc0004 2026-11-04 15:30:00 +09:00",
            "abc0005 2026-11-05 11:20:00 -05:00",
            "abc0006 2026-11-06 07:45:00 +01:00",
        ])},
    "agent_sandbox_syscall_deterministic_guard": {
        "artifact_text": json.dumps({
            "allowed_syscalls": ["read", "write", "openat", "close"],
            "blocked_syscalls": ["execve", "socket", "connect",
                                 "ptrace", "mount", "keyctl", "bpf",
                                 "perf_event_open"],
            "allow_network": False, "allow_wall_clock": False,
            "fixed_seed": 42, "cpu_seconds": 60, "memory_mb": 512,
            "max_open_files": 64, "max_file_bytes": 10485760,
            "timeout_s": 60})},
}
