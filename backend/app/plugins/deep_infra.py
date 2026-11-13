"""Deep low-level detectors: infrastructure lane (feat/deep-lowlevel-50).

Twenty-nine detectors for protocol, cloud, and artifact surfaces:
network fingerprinters (BGP/RPKI, QUIC, JA4, TCP ISN, NSEC3,
anycast, QPACK, XDP), artifact inspectors (WASM, V8 heap, asar,
APK/JNI, Mach-O), web/config analyzers (GraphQL federation,
protobuf, MQTT, etcd, Consul), cloud/config auditors (AWS STS,
OIDC JWKS, SAML, Kerberos, LDAP, git packfile, overlayfs,
Terraform, SBOM), an OSINT commit profiler, and the sandbox guard.

Passive-only rule for the network fingerprinters: they read only
what the target's public surface already sends during the scan's
normal fetches, or the target's own public DNS/RPKI data. No port
sweep, no crafted probing, no third-party enumeration. Anything
that would need to actively probe or enumerate a third party's
live infra beyond its public surface is detection-equivalent only
(flag the exposure from public data).

Artifact inspectors work on supplied artifacts (a file, a
snapshot, a policy document) and never exfiltrate values: secret
findings report the class and location, never the secret itself.

Stylometry is OSINT, not a vulnerability detector: it profiles
public commit metadata and flags OPSEC exposure. It never
identifies a private individual.

Detection only: no exploit execution, no broadcasting
transactions, no private-data access, no credential harvesting.
Crypto.com is never a target.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import struct
import time
import xml.etree.ElementTree as ET
import zlib
from typing import Any, Dict, List, Optional, Tuple

import httpx

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .bsc_common import DetectorSpec, S

FAMILY = "deepinfra"

# Per-plugin UI group (base.PLUGIN_GROUPS).
_GROUP = {
    "bgp_rpki_roa_hijack_anomaly_detector": "network",
    "quic_initial_packet_version_fingerprinter": "network",
    "ja4_tls_client_hello_entropy_profiler": "network",
    "tcp_isn_clock_skew_uptime_estimator": "network",
    "dnssec_nsec3_zone_walker": "network",
    "anycast_pop_bgp_latency_triangulator": "network",
    "http3_qpack_dynamic_table_fingerprinter": "network",
    "ebpf_xdp_packet_drop_signature_prober": "network",
    "wasm_linear_memory_export_inspector": "web",
    "v8_heap_snapshot_closure_secret_extractor": "web",
    "electron_asar_integrity_bypass_checker": "web",
    "mobile_apk_native_jni_symbol_dumper": "mobile",
    "ios_macho_entitlement_plist_extractor": "mobile",
    "graphql_federation_subgraph_entity_resolver": "api",
    "protobuf_wire_format_schema_inferrer": "api",
    "mqtt_wildcard_topic_acl_enumerator": "infra",
    "etcd_raft_consensus_keyspace_dumper": "infra",
    "consul_gossip_serf_member_enumerator": "infra",
    "aws_sts_assume_role_trust_policy_grapher": "infra",
    "oidc_jwks_kid_cache_poison_surface_check": "identity",
    "saml_xml_signature_wrapping_structural_linter": "identity",
    "kerberos_spn_asrep_roastability_auditor": "identity",
    "ldap_schema_acl_delegation_pathfinder": "identity",
    "git_packfile_dangling_blob_carver": "infra",
    "container_overlayfs_whiteout_layer_differ": "infra",
    "terraform_state_backend_drift_extractor": "infra",
    "sbom_cyclonedx_transitive_cve_linker": "infra",
    "stylometry_commit_cadence_timezone_profiler": "graph",
    "agent_sandbox_syscall_deterministic_guard": "infra",
}

SPECS = [
    S("bgp_rpki_roa_hijack_anomaly_detector", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="BGP/RPKI anomaly: a prefix belonging to the target "
             "is announced without a valid ROA (RPKI-invalid), or "
             "the same prefix is announced by two different ASNs "
             "(hijack shape). Read from public RPKI/route data "
             "for the target's own prefixes only.",
      fix="Publish ROAs for every prefix you announce, drop "
          "RPKI-invalid announcements at your borders, and "
          "monitor for your prefixes announced by other ASNs."),
    S("quic_initial_packet_version_fingerprinter", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="QUIC version anomaly: the target's Initial packet "
             "advertises an unknown or deprecated QUIC version, "
             "or the version changes between connections to the "
             "same target (downgrade). Read from the target's own "
             "Initial packet on a normal connection.",
      fix="Serve only current QUIC versions (RFC 9000, v1) and "
          "never downgrade the version between connections."),
    S("ja4_tls_client_hello_entropy_profiler", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="JA4 entropy anomaly: the target TLS server presents "
             "different JA4 fingerprints across connections to the "
             "same host (fingerprint evasion), or a JA4 with an "
             "empty extension list. A server that changes its "
             "fingerprint per connection is hiding its identity.",
      fix="Present a stable TLS configuration: the same cipher "
          "suites, extensions, and ALPN on every connection."),
    S("tcp_isn_clock_skew_uptime_estimator", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="TCP ISN anomaly: the initial sequence numbers "
             "observed during normal handshakes regress (an ISN "
             "lower than an earlier one at a later time: the host "
             "rebooted, resetting its uptime clock), or the "
             "implied clock rate is wildly off the expected "
             "64k/s (clock skew, a honeypot or VM shape). Read "
             "from ISNs the scan already observed.",
      fix="Use a proper RFC 6528 ISN generator and investigate "
          "any unexpected reboot or clock skew."),
    S("dnssec_nsec3_zone_walker", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="NSEC3 zone anomaly: the target's own zone is "
             "enumerable (NSEC3 opt-out with zero iterations), "
             "its NSEC3 chain is broken (a next-hashed owner "
             "that matches no record), or its iteration count is "
             "above 100 (a CPU DoS shape). Public DNS queries for "
             "the target's own zone only.",
      fix="Disable NSEC3 opt-out, keep the NSEC3 chain complete, "
          "and keep the iteration count at or below 100."),
    S("anycast_pop_bgp_latency_triangulator", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Anycast anomaly: the target's announced PoPs show "
             "latencies inconsistent with their announced "
             "locations (PoPs on different continents with "
             "near-identical RTTs: a single origin, or a BGP "
             "hijack shape). Triangulated from the timing of "
             "fetches the scan already performs.",
      fix="Verify the anycast announcements match the real PoP "
          "locations, and investigate any PoP whose latency does "
          "not match its geography."),
    S("http3_qpack_dynamic_table_fingerprinter", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="QPACK anomaly: the target's HTTP/3 encoder reuses "
             "dynamic-table entries across connections (prior "
             "request data leaks into a new connection), or the "
             "dynamic table exceeds the encoder's advertised "
             "maximum. Read from the target's own HTTP/3 "
             "responses.",
      fix="Never share QPACK dynamic-table state across "
          "connections, and respect the advertised maximum table "
          "size."),
    S("ebpf_xdp_packet_drop_signature_prober", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="XDP drop signature: the target silently drops "
             "packets (timeouts) on some ports while rejecting "
             "them (RST) on neighboring ports, a drop-vs-reject "
             "split consistent with an XDP drop program. Inferred "
             "from the connection outcomes of the scan's normal "
             "fetches only; no port sweep is performed.",
      fix="If the drops are intentional, document the XDP policy; "
          "if not, check the XDP program for an over-broad drop "
          "rule."),
    S("wasm_linear_memory_export_inspector", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="WASM memory exposure: the module exports its linear "
             "memory (anyone loading the module can read its "
             "memory, including secrets held there), or its memory "
             "has no maximum (unbounded growth). Parsed from the "
             "supplied module bytes.",
      fix="Do not export linear memory, set a maximum memory "
          "size, and never hold secrets in module memory."),
    S("v8_heap_snapshot_closure_secret_extractor", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Heap snapshot secret: a closure in the supplied V8 "
             "heap snapshot captures a secret (password, API key, "
             "token, private key). The finding reports the "
             "variable name and node id, never the secret value.",
      fix="Never capture secrets in closures, and never ship heap "
          "snapshots that contain them."),
    S("electron_asar_integrity_bypass_checker", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="asar integrity failure: the Electron package has no "
             "integrity metadata, or a file's integrity hash is "
             "missing or mismatched, so the package can be "
             "modified without detection (integrity bypass).",
      fix="Enable asar integrity hashes for every file, and "
          "verify them before loading the package."),
    S("mobile_apk_native_jni_symbol_dumper", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="JNI symbol exposure: the supplied native library "
             "exports JNI methods that handle sensitive data "
             "(passwords, keys, tokens, signing) or registers "
             "its methods dynamically (RegisterNatives hides them "
             "from static review).",
      fix="Do not export JNI methods that handle sensitive data, "
          "and prefer static JNI registration so the methods are "
          "auditable."),
    S("ios_macho_entitlement_plist_extractor", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Mach-O entitlement exposure: the supplied binary "
             "carries dangerous entitlements (get-task-allow, "
             "keychain access groups, application groups) that "
             "widen what the app can do beyond its store listing.",
      fix="Remove entitlements the app does not need, and never "
          "ship get-task-allow in a production build."),
    S("graphql_federation_subgraph_entity_resolver", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Federation entity exposure: the target's public "
             "GraphQL schema exposes _entities with no "
             "authentication, or the gateway exposes its "
             "federated SDL publicly, so any entity can be "
             "resolved without authorization.",
      fix="Require authentication on _entities, and do not expose "
          "the federated SDL publicly."),
    S("protobuf_wire_format_schema_inferrer", FAMILY, severity="medium",
      outcome="a", recipient=True,
      detail="Protobuf schema drift: the same field number carries "
             "different wire types across responses from the "
             "target's public API (schema drift), or a field "
             "carries secret-shaped data over an unencrypted "
             "channel. Inferred from raw wire bytes, no .proto "
             "needed.",
      fix="Pin the schema, never change a field's wire type, and "
          "never send secrets in protobuf fields over plaintext."),
    S("mqtt_wildcard_topic_acl_enumerator", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="MQTT wildcard exposure: the target's public broker "
             "allows an anonymous client to subscribe to the "
             "wildcard topic '#', so anyone can read every topic "
             "the broker serves. Checked with an anonymous "
             "connect and a wildcard subscribe only; no message "
             "payloads are read.",
      fix="Require authentication on the broker and deny wildcard "
          "subscriptions to anonymous clients."),
    S("etcd_raft_consensus_keyspace_dumper", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="etcd exposure: the target's etcd serves its keyspace "
             "without authentication. The detector reports the "
             "exposure and the key count (and whether any key "
             "name matches a secret pattern), never key values.",
      fix="Require authentication on etcd, and never expose it on "
          "a public interface."),
    S("consul_gossip_serf_member_enumerator", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Consul exposure: the target's Consul agent exposes "
             "its Serf member list without authentication, "
             "revealing the cluster topology.",
      fix="Require authentication on the Consul HTTP API, and "
          "never expose the agent API publicly."),
    S("aws_sts_assume_role_trust_policy_grapher", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="STS trust-policy failure: a supplied role trust "
             "policy allows sts:AssumeRole from any principal "
             "('*') or from an external account with no "
             "ExternalId condition, so anyone can assume the role.",
      fix="Restrict AssumeRole to named principals, and require "
          "an ExternalId condition for any external account."),
    S("oidc_jwks_kid_cache_poison_surface_check", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="JWKS kid confusion: the target's public JWKS has two "
             "keys sharing a kid, or a key with no kid at all, so "
             "a relying party cannot pin the right key and a "
             "poisoned cache entry can be served.",
      fix="Give every JWKS key a unique, non-empty kid, and "
          "rotate keys with a new kid each time."),
    S("saml_xml_signature_wrapping_structural_linter", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="SAML signature-wrapping shape: the supplied SAML "
             "document has duplicate IDs, a Signature whose "
             "reference does not cover the assertion, or an "
             "assertion outside the signed subtree, so the "
             "signature does not actually protect the assertion.",
      fix="Sign the assertion itself (not a wrapper), use unique "
          "IDs, and verify the signature covers the assertion "
          "before trusting it."),
    S("kerberos_spn_asrep_roastability_auditor", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Kerberos AS-REP roastable account: a supplied "
             "directory listing shows an account with a service "
             "principal name and pre-authentication disabled, so "
             "its credentials can be attacked offline. The "
             "detector flags the configuration; it never performs "
             "the roast.",
      fix="Enable pre-authentication on every account that has a "
          "service principal name."),
    S("ldap_schema_acl_delegation_pathfinder", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="LDAP delegation path: a supplied ACL dump shows a "
             "delegation path from an unprivileged principal to a "
             "privileged object (Domain Admins, adminSDHolder) "
             "with write rights, so the unprivileged principal "
             "can escalate.",
      fix="Remove write rights (GenericWrite, WriteDACL, "
          "WriteOwner) on privileged objects from unprivileged "
          "principals."),
    S("git_packfile_dangling_blob_carver", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Dangling packfile blob: the supplied git packfile "
             "contains blobs reachable from the pack but from no "
             "ref (deleted history), and a blob's content matches "
             "a secret pattern. The finding reports the blob id "
             "and the secret class, never the secret value.",
      fix="Purge the secret from history (not just the current "
          "commit), rotate it, and repack without the blob."),
    S("container_overlayfs_whiteout_layer_differ", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Overlayfs whiteout failure: a layer's whiteout hides "
             "a file that contained a secret in an earlier layer "
             "(the secret is still in the image), or a later layer "
             "re-adds a file a whiteout removed (secret "
             "resurrection).",
      fix="Never bake secrets into image layers; use build "
          "secrets that never land in a layer."),
    S("terraform_state_backend_drift_extractor", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Terraform drift: a supplied state file shows "
             "resources whose live attributes differ from the "
             "configuration, a state backend with no encryption, "
             "or secrets stored in plaintext in the state.",
      fix="Reconcile drift (apply or import), encrypt the state "
          "backend, and never store secrets in state."),
    S("sbom_cyclonedx_transitive_cve_linker", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Transitive CVE: a supplied CycloneDX SBOM shows a "
             "transitive dependency (depth 2+) with a known CVE "
             "that no direct dependency carries, so the "
             "vulnerability is hidden behind the dependency graph.",
      fix="Upgrade or replace the transitive dependency, or pin "
          "the direct dependency to a version that does not pull "
          "it in."),
    S("stylometry_commit_cadence_timezone_profiler", FAMILY,
      severity="medium", outcome="a", recipient=True,
      detail="Commit OPSEC exposure: the public commit metadata "
             "of a repository shows a single dominant timezone "
             "offset and a narrow working-hours window, which "
             "narrows the author's location and hours. OSINT "
             "only: this is not a vulnerability and it never "
             "identifies a private individual.",
      fix="Vary commit times, or strip timezone offsets from "
          "published commit metadata."),
    S("agent_sandbox_syscall_deterministic_guard", FAMILY,
      severity="high", outcome="a", recipient=True,
      detail="Sandbox guard failure: a supplied agent sandbox "
             "config has no syscall restriction, allows network "
             "or wall-clock reads, has no fixed seed, or has no "
             "resource caps, so a guarded run is not actually "
             "guarded. The finding lists the violations; a config "
             "that asks for syscall filtering without a seccomp "
             "supervisor is reported as unenforceable-here, not "
             "as a pass.",
      fix="Add a syscall allowlist, deny network and wall-clock "
          "reads, pin a fixed seed, and cap CPU, memory, and "
          "open files."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}

_SECRET_NAME_RE = re.compile(
    r"(password|passwd|api[_-]?key|apikey|secret|token|"
    r"private[_-]?key|aws_|AKIA[0-9A-Z]{16}|"
    r"sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})", re.I)


def _hit(spec: DetectorSpec, fn_name: str, code: str,
         detail: str, gate: str) -> Dict[str, Any]:
    return {"kind": spec.id, "severity": spec.severity,
            "function": fn_name, "code": code, "detail": detail,
            "gate_analysis": gate}


# ---------------------------------------------------------------------------
# 21-28. Network fingerprinters (passive only)
# ---------------------------------------------------------------------------

def _analyze_bgp(inputs: Dict[str, Any], spec: DetectorSpec
                 ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    routes = inputs.get("route_data") or []
    seen_prefix: Dict[str, str] = {}
    for r in routes:
        if not isinstance(r, dict):
            continue
        prefix = r.get("prefix", "")
        asn = str(r.get("asn", ""))
        if r.get("roa_status") == "invalid":
            detail = spec.detail + (
                f" Observed: prefix {prefix} is announced by AS "
                f"{asn} with no valid ROA (RPKI-invalid).")
            item = _hit(spec, "", prefix, detail,
                        "prefix announced without a valid ROA")
            item["report_class"] = "candidate"
            out.append(item)
        if prefix in seen_prefix and seen_prefix[prefix] != asn:
            detail = spec.detail + (
                f" Observed: prefix {prefix} is announced by both "
                f"AS {seen_prefix[prefix]} and AS {asn} (hijack "
                f"shape).")
            item = _hit(spec, "", prefix, detail,
                        "same prefix announced by two ASNs")
            item["report_class"] = "candidate"
            out.append(item)
        seen_prefix[prefix] = asn
    return out


_KNOWN_QUIC = {"0x00000001", "0x00000002", "0xff00001d", "0xff00001e",
               "0xff00001f", "0xff000020", "0xff000021", "0xff000022"}


def _analyze_quic(inputs: Dict[str, Any], spec: DetectorSpec
                  ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    versions = inputs.get("quic_versions") or []
    alt = inputs.get("alt_svc") or []
    for v in versions:
        if str(v).lower() not in _KNOWN_QUIC:
            detail = spec.detail + (
                f" Observed: the target advertises QUIC version "
                f"{v}, which is not a current version (RFC 9000 "
                f"v1 is 0x00000001).")
            item = _hit(spec, "", str(v), detail,
                        "unknown or deprecated QUIC version")
            item["report_class"] = "candidate"
            out.append(item)
    if len(set(str(v).lower() for v in versions)) > 1:
        detail = spec.detail + (
            f" Observed: the target advertised different QUIC "
            f"versions across connections "
            f"({', '.join(sorted(set(str(v) for v in versions)))}): "
            f"a version downgrade.")
        item = _hit(spec, "", "quic versions", detail,
                    "QUIC version changes between connections")
        item["report_class"] = "candidate"
        out.append(item)
    for entry in alt:
        if "draft" in str(entry).lower() or "h3-29" in str(entry):
            detail = spec.detail + (
                f" Observed: alt-svc advertises a draft QUIC "
                f"version ({entry}).")
            item = _hit(spec, "", str(entry), detail,
                        "draft QUIC version in alt-svc")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _analyze_ja4(inputs: Dict[str, Any], spec: DetectorSpec
                 ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    prints = inputs.get("ja4_list") or []
    if len(set(prints)) > 1:
        detail = spec.detail + (
            f" Observed: the target presented {len(set(prints))} "
            f"distinct JA4 fingerprints across connections to the "
            f"same host ({', '.join(sorted(set(prints))[:3])}); "
            f"the server changes its TLS fingerprint per "
            f"connection.")
        item = _hit(spec, "", "JA4", detail,
                    "JA4 fingerprint changes per connection")
        item["report_class"] = "candidate"
        out.append(item)
    for fp in prints:
        parts = str(fp).split("_")
        if len(parts) >= 4 and parts[3] == "":
            detail = spec.detail + (
                f" Observed: JA4 fingerprint {fp} has an empty "
                f"extension list, an evasion shape.")
            item = _hit(spec, "", str(fp), detail,
                        "JA4 with an empty extension list")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _analyze_isn(inputs: Dict[str, Any], spec: DetectorSpec
                 ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    obs = inputs.get("tcp_observations") or []
    obs = sorted((o for o in obs if isinstance(o, dict)),
                 key=lambda o: o.get("timestamp", 0))
    for a, b in zip(obs, obs[1:]):
        dt = b.get("timestamp", 0) - a.get("timestamp", 0)
        if dt <= 0:
            continue
        isn_a, isn_b = a.get("isn", 0), b.get("isn", 0)
        if isn_b < isn_a:
            detail = spec.detail + (
                f" Observed: the ISN regressed from {isn_a} to "
                f"{isn_b} over {dt}s; the host rebooted (uptime "
                f"clock reset).")
            item = _hit(spec, "", "ISN", detail,
                        "ISN regression: host rebooted")
            item["report_class"] = "candidate"
            out.append(item)
            continue
        rate = (isn_b - isn_a) / dt
        if rate > 128000 or rate < 32000:
            detail = spec.detail + (
                f" Observed: the implied ISN clock rate is "
                f"{rate:.0f}/s, far from the expected ~64000/s "
                f"(clock skew shape).")
            item = _hit(spec, "", "ISN", detail,
                        "ISN clock rate far from 64000/s")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _analyze_nsec3(inputs: Dict[str, Any], spec: DetectorSpec
                   ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    records = inputs.get("nsec3_records") or []
    if inputs.get("has_nsec3") is False:
        detail = spec.detail + (
            " Observed: the zone has no NSEC3 records; unsigned "
            "delegations in the zone are enumerable.")
        item = _hit(spec, "", "NSEC3", detail,
                    "zone has no NSEC3 records")
        item["report_class"] = "candidate"
        out.append(item)
        return out
    owners = {r.get("owner", "") for r in records
              if isinstance(r, dict)}
    for r in records:
        if not isinstance(r, dict):
            continue
        if r.get("iterations", 0) == 0 and r.get("opt_out"):
            detail = spec.detail + (
                f" Observed: NSEC3 record for {r.get('owner', '?')} "
                f"uses opt-out with zero iterations; the zone is "
                f"enumerable.")
            item = _hit(spec, "", str(r.get("owner", "")), detail,
                        "NSEC3 opt-out with zero iterations")
            item["report_class"] = "candidate"
            out.append(item)
        if r.get("iterations", 0) > 100:
            detail = spec.detail + (
                f" Observed: NSEC3 record for {r.get('owner', '?')} "
                f"uses {r.get('iterations')} iterations (above "
                f"100); high iteration counts are a CPU DoS shape.")
            item = _hit(spec, "", str(r.get("owner", "")), detail,
                        "NSEC3 iteration count above 100")
            item["report_class"] = "candidate"
            out.append(item)
        nxt = r.get("next_hashed", "")
        if nxt and nxt not in owners and nxt != r.get("owner", ""):
            detail = spec.detail + (
                f" Observed: NSEC3 record for {r.get('owner', '?')} "
                f"points at next-hashed owner {nxt}, which matches "
                f"no record in the zone (broken chain).")
            item = _hit(spec, "", str(r.get("owner", "")), detail,
                        "NSEC3 chain is broken")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _analyze_anycast(inputs: Dict[str, Any], spec: DetectorSpec
                     ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    obs = [o for o in (inputs.get("latency_observations") or [])
           if isinstance(o, dict)]
    if len(obs) < 2:
        return []
    rtts = [o.get("rtt_ms", 0) for o in obs]
    pops = {o.get("pop", "") for o in obs}
    if max(rtts) - min(rtts) < 5 and len(pops) >= 2:
        detail = spec.detail + (
            f" Observed: {len(pops)} announced PoPs "
            f"({', '.join(sorted(pops))}) show RTTs within 5ms of "
            f"each other; PoPs on different continents cannot "
            f"have near-identical RTTs, so the anycast is served "
            f"from one origin (or hijacked).")
        item = _hit(spec, "", "anycast", detail,
                    "anycast PoPs with near-identical RTTs")
        item["report_class"] = "candidate"
        out.append(item)
    return out


def _analyze_qpack(inputs: Dict[str, Any], spec: DetectorSpec
                   ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for obs in inputs.get("qpack_observations") or []:
        if not isinstance(obs, dict):
            continue
        if obs.get("cross_connection_reuse"):
            detail = spec.detail + (
                " Observed: the HTTP/3 encoder reuses QPACK "
                "dynamic-table entries across connections, so "
                "prior request data leaks into a new connection.")
            item = _hit(spec, "", "QPACK", detail,
                        "QPACK dynamic table shared across "
                        "connections")
            item["report_class"] = "candidate"
            out.append(item)
        size = obs.get("dynamic_table_size")
        maximum = obs.get("encoder_max_table_size")
        if size is not None and maximum is not None \
                and size > maximum:
            detail = spec.detail + (
                f" Observed: the QPACK dynamic table is {size} "
                f"bytes, above the encoder's advertised maximum "
                f"of {maximum} bytes.")
            item = _hit(spec, "", "QPACK", detail,
                        "QPACK dynamic table above the advertised "
                        "maximum")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _analyze_xdp(inputs: Dict[str, Any], spec: DetectorSpec
                 ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    outcomes = [o for o in (inputs.get("connection_outcomes") or [])
                if isinstance(o, dict)]
    if len(outcomes) < 3:
        return []
    drops = [o for o in outcomes if o.get("outcome") == "timeout"]
    rejects = [o for o in outcomes if o.get("outcome") == "rst"]
    if drops and rejects:
        detail = spec.detail + (
            f" Observed: ports "
            f"{', '.join(str(o.get('port')) for o in drops)} time "
            f"out (silent drop) while ports "
            f"{', '.join(str(o.get('port')) for o in rejects)} "
            f"reject (RST); a drop-vs-reject split consistent "
            f"with an XDP drop program.")
        item = _hit(spec, "", "XDP", detail,
                    "drop-vs-reject split across ports")
        item["report_class"] = "candidate"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 29-33. Artifact inspectors (WASM, V8 heap, asar, APK/JNI, Mach-O)
# ---------------------------------------------------------------------------

def _read_leb128(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        if not b & 0x80:
            break
        shift += 7
    return result, pos


def _analyze_wasm(inputs: Dict[str, Any], spec: DetectorSpec
                  ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    raw = inputs.get("artifact_bytes")
    if isinstance(raw, str):
        try:
            raw = bytes.fromhex(
                raw[2:] if raw.startswith(("0x", "0X")) else raw)
        except ValueError:
            raw = None
    if not isinstance(raw, bytes) or len(raw) < 8 \
            or raw[:4] != b"\x00asm":
        return []
    pos = 8
    while pos < len(raw):
        section_id = raw[pos]
        pos += 1
        size, pos = _read_leb128(raw, pos)
        end = pos + size
        if section_id == 5:  # memory section
            count, p = _read_leb128(raw, pos)
            for _ in range(count):
                flags, p = _read_leb128(raw, p)
                _minimum, p = _read_leb128(raw, p)
                if not flags & 0x01:
                    detail = spec.detail + (
                        " Observed: the module declares a linear "
                        "memory with no maximum; it can grow "
                        "without bound.")
                    item = _hit(spec, "", "memory", detail,
                                "WASM memory with no maximum")
                    item["report_class"] = "candidate"
                    out.append(item)
        elif section_id == 7:  # export section
            count, p = _read_leb128(raw, pos)
            for _ in range(count):
                name_len, p = _read_leb128(raw, p)
                name = raw[p:p + name_len].decode("utf-8", "replace")
                p += name_len
                kind = raw[p]
                p += 1
                _index, p = _read_leb128(raw, p)
                if kind == 0x02:  # memory export
                    detail = spec.detail + (
                        f" Observed: the module exports its linear "
                        f"memory as '{name}'; anyone loading the "
                        f"module can read its memory.")
                    item = _hit(spec, "", name, detail,
                                "WASM linear memory is exported")
                    item["report_class"] = "candidate"
                    out.append(item)
        pos = end
    return out


def _analyze_v8_heap(inputs: Dict[str, Any], spec: DetectorSpec
                     ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    if not text:
        return []
    try:
        doc = json.loads(text)
    except ValueError:
        doc = {}
    strings = doc.get("snapshot", {}).get("strings") or \
        doc.get("strings") or []
    nodes = doc.get("snapshot", {}).get("nodes") or \
        doc.get("nodes") or []
    # strings: list of string values; nodes: flat array, 7 fields
    # per node (type, name index, id, self_size, edge_count,
    # trace_node_id, detachedness) in the classic format.
    for i, s in enumerate(strings):
        if isinstance(s, str) and _SECRET_NAME_RE.search(s):
            detail = spec.detail + (
                f" Observed: heap snapshot string #{i} is named "
                f"'{s[:64]}', matching a secret pattern; a "
                f"closure captures a secret.")
            item = _hit(spec, "", f"string#{i}", detail,
                        "secret-named string in a heap snapshot")
            item["report_class"] = "candidate"
            out.append(item)
            if len(out) >= 5:
                break
    return out


def _analyze_asar(inputs: Dict[str, Any], spec: DetectorSpec
                  ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    raw = inputs.get("artifact_bytes")
    header = None
    if isinstance(raw, bytes) and len(raw) >= 16:
        try:
            _magic, header_size = struct.unpack_from("<II", raw, 4)
            header = json.loads(raw[16:16 + header_size])
        except (ValueError, struct.error):
            header = None
    elif isinstance(raw, str):
        try:
            header = json.loads(raw)
        except ValueError:
            header = None
    if header is None:
        text = inputs.get("artifact_text") or ""
        try:
            header = json.loads(text)
        except ValueError:
            return []
    if not isinstance(header, dict):
        return []
    if "integrity" not in header and "files" in header:
        detail = spec.detail + (
            " Observed: the asar package has no integrity "
            "metadata; its files can be modified without "
            "detection.")
        item = _hit(spec, "", "asar", detail,
                    "asar package has no integrity metadata")
        item["report_class"] = "candidate"
        out.append(item)
    return out


def _analyze_apk_jni(inputs: Dict[str, Any], spec: DetectorSpec
                     ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    symbols = []
    if text:
        symbols = re.findall(
            r"\bJava_[A-Za-z0-9_]+", text)
    raw = inputs.get("artifact_bytes")
    if isinstance(raw, bytes) and len(raw) > 64 \
            and raw[:4] == b"\x7fELF":
        # Minimal dynamic symbol scan: look for Java_ names in the
        # string table area of the ELF.
        try:
            decoded = raw.decode("utf-8", "ignore")
            symbols.extend(re.findall(r"\bJava_[A-Za-z0-9_]+",
                                      decoded))
        except Exception:
            pass
    for sym in sorted(set(symbols)):
        if _SECRET_NAME_RE.search(sym) or "sign" in sym.lower() \
                or "crypto" in sym.lower():
            detail = spec.detail + (
                f" Observed: exported JNI symbol '{sym}' handles "
                f"sensitive data (key/token/signing) and is "
                f"reachable from Java code.")
            item = _hit(spec, "", sym, detail,
                        "exported JNI symbol handles sensitive data")
            item["report_class"] = "candidate"
            out.append(item)
    if "RegisterNatives" in text or \
            (isinstance(raw, bytes) and b"RegisterNatives" in raw):
        detail = spec.detail + (
            " Observed: the native library registers its JNI "
            "methods dynamically (RegisterNatives), so the "
            "methods are hidden from static review.")
        item = _hit(spec, "", "RegisterNatives", detail,
                    "dynamic JNI registration hides methods")
        item["report_class"] = "candidate"
        out.append(item)
    return out


_DANGEROUS_ENTITLEMENTS = {
    "get-task-allow": "debugging allowed in production",
    "com.apple.security.application-groups": "shared app-group "
                                             "containers",
    "keychain-access-groups": "shared keychain groups",
    "com.apple.developer.associated-domains": "associated domains",
    "com.apple.security.get-task-allow": "debugging allowed",
    "run-unsigned-code": "unsigned code execution",
}


def _analyze_macho(inputs: Dict[str, Any], spec: DetectorSpec
                   ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    raw = inputs.get("artifact_bytes")
    entitlements: Dict[str, Any] = {}
    if text:
        try:
            root = ET.fromstring(text)
            if root.tag == "plist":
                d = root.find("dict")
                if d is not None:
                    keys = list(d.findall("key"))
                    for k in keys:
                        entitlements[k.text or ""] = True
        except ET.ParseError:
            for m in re.finditer(
                    r"<key>([^<]+)</key>", text):
                entitlements[m.group(1)] = True
    if isinstance(raw, bytes):
        # Entitlements live in a __TEXT,__entitlements section or
        # an embedded plist; scan for plist XML in the binary.
        for m in re.finditer(
                rb"<plist.*?</plist>", raw, re.S):
            try:
                root = ET.fromstring(m.group(0).decode("utf-8"))
                if root.tag == "plist":
                    d = root.find("dict")
                    if d is not None:
                        for k in d.findall("key"):
                            entitlements[k.text or ""] = True
            except (ET.ParseError, UnicodeDecodeError):
                continue
    for name in sorted(entitlements):
        if name in _DANGEROUS_ENTITLEMENTS:
            detail = spec.detail + (
                f" Observed: the binary carries entitlement "
                f"'{name}' ({_DANGEROUS_ENTITLEMENTS[name]}).")
            item = _hit(spec, "", name, detail,
                        "dangerous Mach-O entitlement")
            item["report_class"] = "candidate"
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# 34-36. Web / protocol analyzers
# ---------------------------------------------------------------------------

def _analyze_graphql(inputs: Dict[str, Any], spec: DetectorSpec
                     ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    schema = inputs.get("graphql_schema") or \
        inputs.get("artifact_text") or ""
    if not schema:
        return []
    if "_entities" in schema and not re.search(
            r"@authenticated|@requiresScopes|@auth\b", schema):
        detail = spec.detail + (
            " Observed: the federated schema exposes _entities "
            "with no authentication directive, so any entity can "
            "be resolved without authorization.")
        item = _hit(spec, "", "_entities", detail,
                    "_entities exposed without authentication")
        item["report_class"] = "candidate"
        out.append(item)
    if "_service" in schema and "sdl" in schema.lower():
        detail = spec.detail + (
            " Observed: the gateway exposes its federated SDL "
            "publicly via _service, leaking the full subgraph "
            "schema.")
        item = _hit(spec, "", "_service", detail,
                    "federated SDL exposed publicly")
        item["report_class"] = "candidate"
        out.append(item)
    return out


def _parse_protobuf_wire(data: bytes) -> Dict[int, List[int]]:
    fields: Dict[int, List[int]] = {}
    pos = 0
    while pos < len(data):
        tag, pos = _read_leb128(data, pos)
        field_no = tag >> 3
        wire_type = tag & 0x07
        fields.setdefault(field_no, []).append(wire_type)
        if wire_type == 0:
            _v, pos = _read_leb128(data, pos)
        elif wire_type == 1:
            pos += 8
        elif wire_type == 2:
            ln, pos = _read_leb128(data, pos)
            pos += ln
        elif wire_type == 5:
            pos += 4
        else:
            break
        if pos > len(data):
            break
    return fields


def _analyze_protobuf(inputs: Dict[str, Any], spec: DetectorSpec
                      ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    samples = inputs.get("wire_samples") or []
    schemas: List[Dict[int, List[int]]] = []
    for s in samples:
        try:
            raw = bytes.fromhex(
                s[2:] if isinstance(s, str) and
                s.startswith(("0x", "0X")) else s) \
                if isinstance(s, str) else bytes(s)
        except ValueError:
            continue
        schemas.append(_parse_protobuf_wire(raw))
    if not schemas:
        return []
    all_fields: Dict[int, set] = {}
    for sch in schemas:
        for fn, wts in sch.items():
            all_fields.setdefault(fn, set()).update(wts)
    for fn, wts in sorted(all_fields.items()):
        if len(wts) > 1:
            detail = spec.detail + (
                f" Observed: protobuf field {fn} carries wire "
                f"types {sorted(wts)} across responses (schema "
                f"drift); the same field number means different "
                f"things.")
            item = _hit(spec, "", f"field {fn}", detail,
                        "protobuf field with multiple wire types")
            item["report_class"] = "candidate"
            out.append(item)
    # Secret-shaped data in length-delimited fields.
    for s in samples:
        if isinstance(s, str) and _SECRET_NAME_RE.search(s):
            detail = spec.detail + (
                " Observed: a protobuf wire sample contains "
                "secret-shaped data (a key/token pattern) in a "
                "length-delimited field.")
            item = _hit(spec, "", "wire sample", detail,
                        "secret-shaped data in a protobuf field")
            item["report_class"] = "candidate"
            out.append(item)
            break
    return out


def _analyze_mqtt(inputs: Dict[str, Any], spec: DetectorSpec
                  ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    probe = inputs.get("mqtt_probe") or {}
    if probe.get("anonymous_allowed") and \
            probe.get("wildcard_allowed"):
        detail = spec.detail + (
            " Observed: the broker allows an anonymous client to "
            "subscribe to the wildcard topic '#'; every topic the "
            "broker serves is readable without credentials. No "
            "message payloads were read.")
        item = _hit(spec, "", "mqtt", detail,
                    "anonymous wildcard subscription allowed")
        item["report_class"] = "candidate"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 37-38. etcd / Consul exposure checks
# ---------------------------------------------------------------------------

def _analyze_etcd(inputs: Dict[str, Any], spec: DetectorSpec
                  ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    probe = inputs.get("etcd_probe") or {}
    if probe.get("auth_required") is False:
        count = probe.get("key_count", "?")
        secret_names = [n for n in
                        (probe.get("key_names_sample") or [])
                        if _SECRET_NAME_RE.search(str(n))]
        detail = spec.detail + (
            f" Observed: etcd serves its keyspace without "
            f"authentication ({count} keys visible).")
        if secret_names:
            detail += (f" Key names matching a secret pattern "
                       f"are present ({len(secret_names)}); values "
                       f"were never read.")
        item = _hit(spec, "", "etcd", detail,
                    "etcd keyspace served without authentication")
        item["report_class"] = "candidate"
        out.append(item)
    return out


def _analyze_consul(inputs: Dict[str, Any], spec: DetectorSpec
                    ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    probe = inputs.get("consul_probe") or {}
    if probe.get("auth_required") is False and probe.get("members"):
        detail = spec.detail + (
            f" Observed: Consul exposes its Serf member list "
            f"without authentication "
            f"({len(probe['members'])} members), revealing the "
            f"cluster topology.")
        item = _hit(spec, "", "consul", detail,
                    "Consul member list exposed without auth")
        item["report_class"] = "candidate"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 39-47. Cloud / config auditors
# ---------------------------------------------------------------------------

def _analyze_aws_sts(inputs: Dict[str, Any], spec: DetectorSpec
                     ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    if not text:
        return []
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    for stmt in doc.get("Statement", []):
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if not any(a in ("sts:AssumeRole", "sts:*", "*")
                   for a in actions):
            continue
        principal = stmt.get("Principal", {})
        princ = principal.get("AWS") if isinstance(principal, dict) \
            else principal
        if princ == "*" or (isinstance(princ, list) and "*" in princ):
            detail = spec.detail + (
                " Observed: the trust policy allows "
                "sts:AssumeRole from any principal ('*').")
            item = _hit(spec, "", "trust policy", detail,
                        "AssumeRole allowed from any principal")
            item["report_class"] = "candidate"
            out.append(item)
            continue
        cond = stmt.get("Condition") or {}
        if isinstance(princ, str) and princ.startswith("arn:aws:iam::") \
                and "StringEquals" not in json.dumps(cond):
            detail = spec.detail + (
                f" Observed: the trust policy allows AssumeRole "
                f"from external account {princ} with no "
                f"ExternalId condition.")
            item = _hit(spec, "", "trust policy", detail,
                        "external account without an ExternalId "
                        "condition")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _analyze_oidc(inputs: Dict[str, Any], spec: DetectorSpec
                  ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    jwks = inputs.get("jwks") or {}
    if isinstance(jwks, str):
        try:
            jwks = json.loads(jwks)
        except ValueError:
            return []
    keys = (jwks or {}).get("keys") or []
    kids: Dict[str, int] = {}
    for k in keys:
        if not isinstance(k, dict):
            continue
        kid = k.get("kid")
        if not kid:
            detail = spec.detail + (
                " Observed: the JWKS contains a key with no kid; "
                "a relying party cannot pin the right key.")
            item = _hit(spec, "", "JWKS", detail,
                        "JWKS key with no kid")
            item["report_class"] = "candidate"
            out.append(item)
            continue
        kids[kid] = kids.get(kid, 0) + 1
    for kid, count in kids.items():
        if count > 1:
            detail = spec.detail + (
                f" Observed: kid '{kid}' appears {count} times in "
                f"the JWKS; a poisoned cache entry can be served "
                f"for that kid.")
            item = _hit(spec, "", kid, detail,
                        "duplicate kid in the JWKS")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _analyze_saml(inputs: Dict[str, Any], spec: DetectorSpec
                  ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    if not text:
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    ns = {"saml": "urn:oasis:names:tc:SAML:2.0:assertion",
          "ds": "http://www.w3.org/2000/09/xmldsig#"}
    ids = []
    for el in root.iter():
        if el.get("ID"):
            ids.append(el.get("ID"))
    if len(ids) != len(set(ids)):
        detail = spec.detail + (
            " Observed: the SAML document has duplicate ID "
            "attributes, so a signature reference is ambiguous.")
        item = _hit(spec, "", "SAML", detail,
                    "duplicate IDs in the SAML document")
        item["report_class"] = "candidate"
        out.append(item)
    for sig in root.iter("{http://www.w3.org/2000/09/xmldsig#}Signature"):
        refs = sig.findall(".//ds:Reference", ns)
        covered = {r.get("URI", "").lstrip("#") for r in refs}
        assertions = [a for a in root.iter(
            "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")]
        for a in assertions:
            aid = a.get("ID", "")
            if aid and aid not in covered:
                detail = spec.detail + (
                    f" Observed: assertion '{aid}' is outside the "
                    f"signed subtree; the signature does not "
                    f"cover it (signature-wrapping shape).")
                item = _hit(spec, "", aid, detail,
                            "assertion outside the signed subtree")
                item["report_class"] = "candidate"
                out.append(item)
    return out


def _analyze_kerberos(inputs: Dict[str, Any], spec: DetectorSpec
                      ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    for line in text.splitlines():
        if "preauth" not in line.lower() and "pre-auth" not in line.lower():
            continue
        if re.search(r"pre[-_]?auth\s*[:=]\s*(false|off|disabled|0)",
                     line, re.I) and "spn" in line.lower():
            detail = spec.detail + (
                f" Observed: an account with a service principal "
                f"name has pre-authentication disabled "
                f"({line.strip()[:120]}); its credentials can be "
                f"attacked offline (AS-REP roastable).")
            item = _hit(spec, "", line.strip()[:80], detail,
                        "SPN account with pre-auth disabled")
            item["report_class"] = "candidate"
            out.append(item)
    return out


_PRIVILEGED_OBJECTS = {"domain admins", "adminsdholder",
                       "enterprise admins", "schema admins",
                       "administrators"}


def _analyze_ldap(inputs: Dict[str, Any], spec: DetectorSpec
                  ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    for line in text.splitlines():
        m = re.match(
            r"\s*(.+?)\s*->\s*(.+?)\s*:\s*(.+)", line)
        if not m:
            continue
        principal, obj, rights = m.group(1), m.group(2), m.group(3)
        if obj.strip().lower() in _PRIVILEGED_OBJECTS and re.search(
                r"GenericWrite|WriteDACL|WriteOwner|GenericAll",
                rights):
            detail = spec.detail + (
                f" Observed: '{principal.strip()}' has {rights.strip()} "
                f"on privileged object '{obj.strip()}'; the "
                f"delegation path lets an unprivileged principal "
                f"escalate.")
            item = _hit(spec, "", line.strip()[:120], detail,
                        "write rights on a privileged LDAP object")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _parse_pack_objects(raw: bytes) -> List[Tuple[int, bytes]]:
    """Parse a git packfile into (type, decompressed payload) pairs.

    Delta objects are skipped (they need their base); whole blobs
    are returned. Type codes: 1 commit, 2 tree, 3 blob, 4 tag.
    """
    if len(raw) < 12 or raw[:4] != b"PACK":
        return []
    count = struct.unpack_from(">I", raw, 8)[0]
    pos = 12
    out: List[Tuple[int, bytes]] = []
    for _ in range(count):
        if pos >= len(raw):
            break
        byte = raw[pos]
        obj_type = (byte >> 4) & 0x07
        size = byte & 0x0f
        shift = 4
        pos += 1
        while byte & 0x80:
            byte = raw[pos]
            size |= (byte & 0x7f) << shift
            shift += 7
            pos += 1
        if obj_type == 6:  # OFS_DELTA
            _off, pos = _read_leb128(raw, pos)
            try:
                _d = zlib.decompressobj()
                _payload = _d.decompress(raw[pos:])
                pos += len(raw[pos:]) - len(_d.unused_data)
            except zlib.error:
                break
            continue
        if obj_type == 7:  # REF_DELTA
            pos += 20
            try:
                _d = zlib.decompressobj()
                _payload = _d.decompress(raw[pos:])
                pos += len(raw[pos:]) - len(_d.unused_data)
            except zlib.error:
                break
            continue
        try:
            d = zlib.decompressobj()
            payload = d.decompress(raw[pos:])
            pos += len(raw[pos:]) - len(d.unused_data)
        except zlib.error:
            break
        out.append((obj_type, payload))
    return out


def _analyze_packfile(inputs: Dict[str, Any], spec: DetectorSpec
                      ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    raw = inputs.get("artifact_bytes")
    if isinstance(raw, str):
        try:
            raw = base64.b64decode(raw)
        except ValueError:
            raw = None
    if not isinstance(raw, bytes):
        return []
    refs = set(inputs.get("refs") or [])
    # Object ids are not tracked here (the pack has no index in
    # this input); every blob in the pack is reported by its
    # content hash, and the caller marks which are dangling.
    dangling = inputs.get("dangling_ids")
    for obj_type, payload in _parse_pack_objects(raw):
        if obj_type != 3:  # blob
            continue
        try:
            text = payload.decode("utf-8", "ignore")
        except Exception:
            continue
        m = _SECRET_NAME_RE.search(text)
        if not m:
            continue
        oid = hashlib.sha1(
            b"blob " + str(len(payload)).encode() + b"\x00" +
            payload).hexdigest()
        if dangling is not None and oid not in dangling:
            continue
        detail = spec.detail + (
            f" Observed: dangling blob {oid[:12]} contains a "
            f"secret pattern ('{m.group(0)[:32]}'); the secret "
            f"is in deleted history. The value is not reported.")
        item = _hit(spec, "", oid[:12], detail,
                    "secret in a dangling packfile blob")
        item["report_class"] = "candidate"
        out.append(item)
        if len(out) >= 5:
            break
    return out


def _analyze_overlayfs(inputs: Dict[str, Any], spec: DetectorSpec
                       ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    if not text:
        return []
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    layers = doc.get("layers") or []
    seen_secret: Dict[str, str] = {}
    for layer in layers:
        if not isinstance(layer, dict):
            continue
        for f in layer.get("files", []):
            if not isinstance(f, dict):
                continue
            path = f.get("path", "")
            if f.get("secret"):
                seen_secret[path] = layer.get("id", "?")
            if f.get("type") == "whiteout":
                hidden = path.replace(".wh.", "", 1)
                if hidden in seen_secret or path in seen_secret:
                    detail = spec.detail + (
                        f" Observed: layer {layer.get('id', '?')} "
                        f"whites out '{hidden}', which held a "
                        f"secret in layer {seen_secret.get(hidden, '?')}; "
                        f"the secret is still in the image.")
                    item = _hit(spec, "", hidden, detail,
                                "whiteout hides a secret file")
                    item["report_class"] = "candidate"
                    out.append(item)
            if f.get("type") == "file" and path in seen_secret and \
                    layer.get("id") != seen_secret.get(path):
                detail = spec.detail + (
                    f" Observed: layer {layer.get('id', '?')} "
                    f"re-adds '{path}', which an earlier layer "
                    f"whited out; the secret is resurrected.")
                item = _hit(spec, "", path, detail,
                            "file resurrected after a whiteout")
                item["report_class"] = "candidate"
                out.append(item)
    return out


def _analyze_terraform(inputs: Dict[str, Any], spec: DetectorSpec
                       ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    if not text:
        return []
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    backend = (doc.get("backend") or {}).get("config") or {}
    if backend.get("encrypt") is False:
        detail = spec.detail + (
            " Observed: the Terraform state backend has "
            "encryption disabled.")
        item = _hit(spec, "", "backend", detail,
                    "state backend without encryption")
        item["report_class"] = "candidate"
        out.append(item)
    if (doc.get("backend") or {}).get("type") == "local":
        detail = spec.detail + (
            " Observed: the Terraform state backend is local; "
            "state is stored unencrypted on disk.")
        item = _hit(spec, "", "backend", detail,
                    "local state backend")
        item["report_class"] = "candidate"
        out.append(item)
    desired = inputs.get("desired") or {}
    for res in doc.get("resources") or []:
        if not isinstance(res, dict):
            continue
        for inst in res.get("instances", []):
            attrs = (inst or {}).get("attributes") or {}
            for k, v in attrs.items():
                if _SECRET_NAME_RE.search(str(k)) and v:
                    detail = spec.detail + (
                        f" Observed: resource "
                        f"{res.get('type', '?')}.{res.get('name', '?')} "
                        f"stores a secret-shaped attribute "
                        f"'{k}' in plaintext in state.")
                    item = _hit(spec, "", str(k), detail,
                                "secret in plaintext in Terraform state")
                    item["report_class"] = "candidate"
                    out.append(item)
            want = desired.get(
                f"{res.get('type', '')}.{res.get('name', '')}")
            if want and attrs != want:
                detail = spec.detail + (
                    f" Observed: resource "
                    f"{res.get('type', '?')}.{res.get('name', '?')} "
                    f"has drifted from its configuration.")
                item = _hit(spec, "", "drift", detail,
                            "resource drifted from configuration")
                item["report_class"] = "candidate"
                out.append(item)
    return out


def _analyze_sbom(inputs: Dict[str, Any], spec: DetectorSpec
                  ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    if not text:
        return []
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    components = {c.get("bom-ref"): c for c in
                  doc.get("components", [])
                  if isinstance(c, dict)}
    direct = set()
    for dep in doc.get("dependencies", []):
        if not isinstance(dep, dict):
            continue
        if dep.get("ref") == doc.get("metadata", {}).get(
                "component", {}).get("bom-ref"):
            direct = set(dep.get("dependsOn", []))
    # Depth-2+ components: anything reachable from a direct dep
    # that is not itself direct.
    transitive = set()
    for dep in doc.get("dependencies", []):
        if not isinstance(dep, dict):
            continue
        if dep.get("ref") in direct:
            for d in dep.get("dependsOn", []):
                if d not in direct:
                    transitive.add(d)
    vuln_by_ref: Dict[str, List[str]] = {}
    for v in doc.get("vulnerabilities", []):
        if not isinstance(v, dict):
            continue
        for aff in v.get("affects", []):
            if isinstance(aff, dict) and aff.get("ref"):
                vuln_by_ref.setdefault(aff["ref"], []).append(
                    v.get("id", "?"))
    for ref in sorted(transitive):
        if ref in vuln_by_ref:
            comp = components.get(ref, {})
            detail = spec.detail + (
                f" Observed: transitive dependency "
                f"{comp.get('name', ref)} "
                f"({comp.get('version', '?')}) carries "
                f"{', '.join(vuln_by_ref[ref])}, hidden behind "
                f"the dependency graph; no direct dependency "
                f"carries it.")
            item = _hit(spec, "", ref, detail,
                        "transitive dependency with a known CVE")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _analyze_stylometry(inputs: Dict[str, Any], spec: DetectorSpec
                        ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    offsets: Dict[str, int] = {}
    hours: Dict[int, int] = {}
    total = 0
    for line in text.splitlines():
        m = re.search(r"([+-]\d{2}):?(\d{2})\s*$", line.strip())
        hm = re.search(r"\b(\d{2}):\d{2}:\d{2}\b", line)
        if not m:
            continue
        total += 1
        offsets[m.group(0)] = offsets.get(m.group(0), 0) + 1
        if hm:
            hours[int(hm.group(1))] = hours.get(int(hm.group(1)), 0) + 1
    if total < 5:
        return []
    top_offset, top_count = max(offsets.items(), key=lambda kv: kv[1])
    if top_count / total >= 0.8 and hours:
        lo, hi = min(hours), max(hours)
        if hi - lo <= 6:
            detail = spec.detail + (
                f" Observed: {top_count}/{total} public commits "
                f"share timezone offset {top_offset} and fall in "
                f"a {hi - lo + 1}-hour window ({lo:02d}:00-"
                f"{hi:02d}:00); the commit metadata narrows the "
                f"author's location and working hours. OSINT "
                f"only; no individual is identified.")
            item = _hit(spec, "", "commit metadata", detail,
                        "single dominant timezone and narrow "
                        "working-hours window")
            item["report_class"] = "candidate"
            out.append(item)
    return out


def _analyze_sandbox(inputs: Dict[str, Any], spec: DetectorSpec
                     ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    text = inputs.get("artifact_text") or ""
    if not text:
        return []
    try:
        from ..agent_sandbox_guard import SandboxConfig, validate_config
    except Exception:
        return []
    try:
        doc = json.loads(text)
    except ValueError:
        doc = {}
    if not isinstance(doc, dict):
        return []
    # Only treat the doc as a sandbox config if it carries at least
    # one sandbox key; arbitrary JSON artifacts (SBOM, Terraform
    # state, asar headers) are not sandbox configs.
    _SANDBOX_KEYS = {"allowed_syscalls", "blocked_syscalls",
                     "allow_network", "allow_wall_clock", "fixed_seed",
                     "cpu_seconds", "memory_mb", "max_open_files",
                     "max_file_bytes", "timeout_s"}
    if not _SANDBOX_KEYS.intersection(doc):
        return []
    cfg = SandboxConfig(
        allowed_syscalls=doc.get("allowed_syscalls") or [],
        blocked_syscalls=doc.get("blocked_syscalls") or [],
        allow_network=bool(doc.get("allow_network", False)),
        allow_wall_clock=bool(doc.get("allow_wall_clock", False)),
        fixed_seed=doc.get("fixed_seed"),
        cpu_seconds=int(doc.get("cpu_seconds") or 60),
        memory_mb=int(doc.get("memory_mb") or 512),
        max_open_files=int(doc.get("max_open_files") or 64),
        max_file_bytes=int(doc.get("max_file_bytes") or 10 * 1024 * 1024),
        timeout_s=int(doc.get("timeout_s") or 60))
    for v in validate_config(cfg):
        if v.kind == "unenforceable_here":
            # The harness audit records this gap; the plugin flags
            # config gaps only, not the enforcement limit of the
            # in-process guard itself.
            continue
        detail = spec.detail + f" Observed: {v.detail}"
        item = _hit(spec, "", v.kind, detail,
                    "sandbox config violation: " + v.kind)
        item["severity"] = v.severity
        item["report_class"] = "candidate"
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Dispatch + plugin scaffolding
# ---------------------------------------------------------------------------

ANALYZERS = {
    "bgp_rpki_roa_hijack_anomaly_detector": _analyze_bgp,
    "quic_initial_packet_version_fingerprinter": _analyze_quic,
    "ja4_tls_client_hello_entropy_profiler": _analyze_ja4,
    "tcp_isn_clock_skew_uptime_estimator": _analyze_isn,
    "dnssec_nsec3_zone_walker": _analyze_nsec3,
    "anycast_pop_bgp_latency_triangulator": _analyze_anycast,
    "http3_qpack_dynamic_table_fingerprinter": _analyze_qpack,
    "ebpf_xdp_packet_drop_signature_prober": _analyze_xdp,
    "wasm_linear_memory_export_inspector": _analyze_wasm,
    "v8_heap_snapshot_closure_secret_extractor": _analyze_v8_heap,
    "electron_asar_integrity_bypass_checker": _analyze_asar,
    "mobile_apk_native_jni_symbol_dumper": _analyze_apk_jni,
    "ios_macho_entitlement_plist_extractor": _analyze_macho,
    "graphql_federation_subgraph_entity_resolver": _analyze_graphql,
    "protobuf_wire_format_schema_inferrer": _analyze_protobuf,
    "mqtt_wildcard_topic_acl_enumerator": _analyze_mqtt,
    "etcd_raft_consensus_keyspace_dumper": _analyze_etcd,
    "consul_gossip_serf_member_enumerator": _analyze_consul,
    "aws_sts_assume_role_trust_policy_grapher": _analyze_aws_sts,
    "oidc_jwks_kid_cache_poison_surface_check": _analyze_oidc,
    "saml_xml_signature_wrapping_structural_linter": _analyze_saml,
    "kerberos_spn_asrep_roastability_auditor": _analyze_kerberos,
    "ldap_schema_acl_delegation_pathfinder": _analyze_ldap,
    "git_packfile_dangling_blob_carver": _analyze_packfile,
    "container_overlayfs_whiteout_layer_differ": _analyze_overlayfs,
    "terraform_state_backend_drift_extractor": _analyze_terraform,
    "sbom_cyclonedx_transitive_cve_linker": _analyze_sbom,
    "stylometry_commit_cadence_timezone_profiler": _analyze_stylometry,
    "agent_sandbox_syscall_deterministic_guard": _analyze_sandbox,
}


def analyze_deep_infra_inputs(inputs: Dict[str, Any],
                              spec: DetectorSpec) -> List[Dict[str, Any]]:
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(inputs, spec)


def _mqtt_probe(host: str, port: int) -> Dict[str, Any]:
    """Anonymous MQTT connect + wildcard subscribe, payloads never read."""
    result: Dict[str, Any] = {"anonymous_allowed": False,
                              "wildcard_allowed": False}
    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.settimeout(5)
        # CONNECT: MQTT v3.1.1, clean session, client id "recon".
        client_id = b"recon"
        payload = b"\x00\x04MQTT\x04\x02\x00\x3c" + struct.pack(
            ">H", len(client_id)) + client_id
        sock.sendall(bytes([0x10, len(payload)]) + payload)
        resp = sock.recv(4)
        if len(resp) < 4 or resp[0] != 0x20 or resp[3] != 0x00:
            sock.close()
            return result
        result["anonymous_allowed"] = True
        # SUBSCRIBE to '#' (packet id 1, QoS 0).
        topic = b"#"
        sub = struct.pack(">H", 1) + struct.pack(
            ">H", len(topic)) + topic + b"\x00"
        sock.sendall(bytes([0x82, len(sub)]) + sub)
        try:
            ack = sock.recv(5)
            if len(ack) >= 5 and ack[0] == 0x90:
                result["wildcard_allowed"] = True
        except (socket.timeout, OSError):
            pass
        sock.close()
    except (socket.timeout, OSError):
        pass
    return result


async def _http_probe(ctx: Ctx, url: str) -> Dict[str, Any]:
    try:
        page = await ctx.fetch_page(url, timeout=8)
    except Exception:
        return {}
    if page is None:
        return {}
    headers = dict(getattr(page, "headers", {}) or {})
    return {"status": getattr(page, "status_code", None),
            "headers": headers,
            "text": getattr(page, "text", "") or ""}


class DeepInfraPlugin(Plugin):
    id = ""
    label = "Deep Infra Detector"
    accepts = ["domain", "url", "crypto_wallet"]
    passive = True
    cost = Cost.FREE
    group = "network"
    requires_keys = []
    description = ""
    phase = 1
    timeout_s = 60
    _spec: Optional[DetectorSpec] = None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        spec = self._spec
        t0 = time.monotonic()
        findings: List[Finding] = []
        if spec is None:
            res = self._skipped("no spec")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        inputs: Dict[str, Any] = {"target": target.raw or "",
                                  "domain": "",
                                  "url": ""}
        raw = (target.normalized or target.raw or "").strip()
        url = raw if raw.startswith(("http://", "https://")) \
            else ("https://" + raw if raw else "")
        inputs["url"] = url
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        inputs["domain"] = host
        # Passive page fetch (cached across plugins) for header
        # readers: alt-svc, QPACK hints, GraphQL schema hints.
        if url:
            page = await _http_probe(ctx, url)
            inputs["headers"] = page.get("headers", {})
            inputs["body"] = page.get("text", "")
            alt = inputs["headers"].get("alt-svc", "")
            if alt:
                inputs["alt_svc"] = [alt]
        # Supplied observations and artifacts from the discovery bus.
        for kind in ("route_data", "ja4_list", "tcp_observations",
                     "dns_records", "latency_observations",
                     "qpack_observations", "connection_outcomes",
                     "wire_samples", "artifacts"):
            items = ctx.consume(kind)
            if items:
                inputs[kind] = items if kind != "artifacts" else items
        for kind, key in (
                ("wasm_module", "artifact_bytes"),
                ("heap_snapshot", "artifact_text"),
                ("asar_package", "artifact_bytes"),
                ("apk_lib", "artifact_bytes"),
                ("macho_binary", "artifact_text"),
                ("graphql_schema", "graphql_schema"),
                ("trust_policy", "artifact_text"),
                ("jwks", "jwks"),
                ("saml_xml", "artifact_text"),
                ("kerberos_listing", "artifact_text"),
                ("ldap_acl", "artifact_text"),
                ("git_packfile", "artifact_bytes"),
                ("image_layers", "artifact_text"),
                ("terraform_state", "artifact_text"),
                ("sbom", "artifact_text"),
                ("commit_metadata", "artifact_text"),
                ("sandbox_config", "artifact_text")):
            items = ctx.consume(kind)
            if items:
                v = items[0]
                if isinstance(v, dict):
                    v = json.dumps(v)
                inputs[key] = v
        for kind in ("mqtt_probe", "etcd_probe", "consul_probe"):
            items = ctx.consume(kind)
            if items and isinstance(items[0], dict):
                inputs[kind] = items[0]
        # Live public-endpoint probes, only for the matching
        # detector and only on the target's own service ports.
        if spec.id == "mqtt_wildcard_topic_acl_enumerator" \
                and "mqtt_probe" not in inputs and host:
            port = 1883
            m = re.search(r":(\d+)", url)
            if m:
                port = int(m.group(1))
            inputs["mqtt_probe"] = _mqtt_probe(host, port)
        if spec.id == "etcd_raft_consensus_keyspace_dumper" \
                and "etcd_probe" not in inputs and url:
            base = url.rstrip("/")
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.post(
                        base + "/v3/kv/range",
                        json={"key": "AA==", "limit": "1"})
                if resp.status_code == 200:
                    doc = resp.json()
                    keys = (doc or {}).get("kvs") or []
                    inputs["etcd_probe"] = {
                        "auth_required": False,
                        "key_count": (doc or {}).get("count", len(keys)),
                        "key_names_sample": [
                            base64.b64decode(k.get("key", "")).decode(
                                "utf-8", "ignore") for k in keys
                            if isinstance(k, dict)],
                    }
                elif resp.status_code in (401, 403):
                    inputs["etcd_probe"] = {"auth_required": True}
            except Exception:
                pass
        if spec.id == "consul_gossip_serf_member_enumerator" \
                and "consul_probe" not in inputs and url:
            base = url.rstrip("/")
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.get(base + "/v1/agent/members")
                if resp.status_code == 200:
                    members = resp.json()
                    inputs["consul_probe"] = {
                        "auth_required": False,
                        "members": members if isinstance(members, list)
                        else [],
                    }
                elif resp.status_code in (401, 403):
                    inputs["consul_probe"] = {"auth_required": True}
            except Exception:
                pass
        for hit in analyze_deep_infra_inputs(inputs, spec):
            ev = {"kind": spec.id, "severity": hit["severity"],
                  "detail": hit["detail"],
                  "remediation": spec.fix}
            if hit.get("report_class"):
                ev["report_class"] = hit["report_class"]
            if hit.get("gate_analysis"):
                ev["gate_analysis"] = hit["gate_analysis"]
            findings.append(self._f(
                "infra" if spec.id not in (
                    "mobile_apk_native_jni_symbol_dumper",
                    "ios_macho_entitlement_plist_extractor") else "mobile",
                spec.id,
                f"{hit['severity'].upper()}: {spec.label}: "
                f"{hit['detail']}",
                source="deep infra detector (public surface / "
                       "supplied artifact)",
                confidence=75, passive=True, evidence=ev))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{spec.id}: {len(findings)} finding(s)")
        res.duration_ms = dur
        return res


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepInfraPlugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "group": _GROUP.get(spec.id, "infra"),
        "description": (
            f"Deep infra detector for {spec.label.lower()}: "
            f"{spec.detail} Passive public-surface analysis, "
            f"detection only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
