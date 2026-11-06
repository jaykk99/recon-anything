"""SAML assertion replay tester (variant of fin_saml_metadata):
the covering plugin flags internal hostnames in SAML metadata.
This delta is replay-posture CONFIGURATION VALIDATION over
supplied IdP/SP metadata and assertion samples:

- WantAssertionsSigned absent/false, assertions not encrypted
- SHA-1 signature / digest algorithms
- assertion sample with no Conditions NotOnOrAfter window
- assertion sample with no AudienceRestriction
- no InResponseTo / replay-cache indicators in supplied config

BOUNDARY: configuration validation only - no forged assertions,
no replay against any IdP.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, text_of


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    text = text_of(data)
    if not text or ("saml" not in text.lower()
                    and "Assertion" not in text
                    and "EntityDescriptor" not in text):
        return hits
    is_metadata = "EntityDescriptor" in text or \
        "SPSSODescriptor" in text or "IDPSSODescriptor" in text
    is_assertion = "<Assertion" in text or "<saml:Assertion" in text \
        or "<Response" in text or "<samlp:Response" in text
    if is_metadata:
        if not re.search(r"WantAssertionsSigned\s*=\s*\"true\"", text):
            hits.append({
                "key": "saml_want_assertions_signed_absent",
                "severity": "medium",
                "value": "SAML metadata does not set "
                         "WantAssertionsSigned=\"true\" - the SP "
                         "does not declare that assertions must be "
                         "signed (replay/forgery posture)",
                "evidence": {"remediation": "Set "
                             "WantAssertionsSigned and require "
                             "signed assertions (and signed responses) "
                             "at the SP."}})
        if "WantAssertionsEncrypted" not in text and \
                "EncryptedAssertion" not in text:
            hits.append({
                "key": "saml_assertions_not_encrypted",
                "severity": "low",
                "value": "SAML metadata shows no assertion "
                         "encryption (WantAssertionsEncrypted / "
                         "EncryptedAssertion absent)",
                "evidence": {"remediation": "Enable assertion "
                             "encryption for attribute confidentiality "
                             "where attributes are sensitive."}})
    if re.search(r"(?i)(rsa-sha1|dsa-sha1|#sha1\b|xmlenc#sha1|"
                 r"xmldsig#sha1)", text):
        hits.append({
            "key": "saml_sha1_signature_algorithm",
            "severity": "medium",
            "value": "SAML metadata/assertion uses SHA-1 signature "
                     "or digest algorithms",
            "evidence": {"remediation": "Move to SHA-256+ signature "
                         "and digest algorithms; SHA-1 collision "
                         "resistance is broken."}})
    if is_assertion:
        if "NotOnOrAfter" not in text:
            hits.append({
                "key": "saml_missing_validity_window",
                "severity": "high",
                "value": "Supplied SAML assertion has NO "
                         "NotOnOrAfter validity bound - it never "
                         "expires, so a captured assertion is "
                         "replayable indefinitely",
                "evidence": {"remediation": "Require Conditions "
                             "NotBefore/NotOnOrAfter with a short "
                             "window (minutes) and enforce it at "
                             "the SP."}})
        if "AudienceRestriction" not in text:
            hits.append({
                "key": "saml_missing_audience_restriction",
                "severity": "medium",
                "value": "Supplied SAML assertion has no "
                         "AudienceRestriction - it can be presented "
                         "to a different SP than intended",
                "evidence": {"remediation": "Require and validate "
                             "AudienceRestriction matching the SP "
                             "entityID."}})
        if "InResponseTo" not in text:
            hits.append({
                "key": "saml_missing_in_response_to",
                "severity": "low",
                "value": "Supplied SAML response has no "
                         "InResponseTo binding to a request id - "
                         "unsolicited/replayed responses are harder "
                         "to reject",
                "evidence": {"remediation": "Track request ids and "
                             "require InResponseTo, with a replay "
                             "cache on assertion IDs."}})
    return hits[:10]


class SamlAssertionReplayTesterPlugin(Plugin):
    id = "saml_assertion_replay_tester"
    label = "SAML Assertion Replay Tester"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    phase = 2
    description = ("Replay-posture validation of supplied SAML "
                   "metadata/config/assertions: unsigned/unencrypted "
                   "assertions, SHA-1 algorithms, missing validity "
                   "window / audience restriction. Config validation "
                   "only - no forged assertions.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "identity",
                          ("saml_metadata", "saml_configs",
                           "saml_assertions"))
            if got is not None:
                return got
            return self._ok([], "no supplied SAML metadata/config/"
                            "assertion in ctx.shared")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
