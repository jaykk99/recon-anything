"""Finding-key -> standard taxonomy labels (MITRE CWE, plus MITRE ATT&CK
where a mapping is confident).

Sources: MITRE CWE (cwe.mitre.org), MITRE ATT&CK (attack.mitre.org).
Only mappings the author is confident about are listed; unknown keys
return None instead of a guessed label. ATT&CK is included only for the
handful of keys where the technique is unambiguous - most smart-contract
finding keys have no honest ATT&CK mapping and get CWE only.

Used by triage/reporting to label findings with standard taxonomies
(resource rows 6-8 of Jay's 100-resource sheet).
"""
from __future__ import annotations

from typing import Dict, Optional

# key -> {"cwe": "CWE-###", "name": "...", "attck": "T####(.###)" | None,
#         "attck_name": "..." | None}
CWE_MAP: Dict[str, Dict[str, Optional[str]]] = {
    # --- Wave 1: new r100 detectors (Track A) ---
    "div_before_mul_precision_loss": {
        "cwe": "CWE-682", "name": "Incorrect Calculation",
        "attck": None, "attck_name": None},
    "unbounded_loop_gas_dos": {
        "cwe": "CWE-400", "name": "Uncontrolled Resource Consumption",
        "attck": None, "attck_name": None},
    "erc721_transferfrom_no_receiver_check": {
        "cwe": "CWE-703",
        "name": "Improper Check or Handling of Exceptional Conditions",
        "attck": None, "attck_name": None},
    "payable_ignores_msg_value": {
        "cwe": "CWE-404",
        "name": "Improper Resource Shutdown or Release",
        "attck": None, "attck_name": None},
    "eth_no_withdrawal_path": {
        "cwe": "CWE-404",
        "name": "Improper Resource Shutdown or Release",
        "attck": None, "attck_name": None},
    "state_var_shadowed": {
        "cwe": "CWE-710",
        "name": "Improper Adherence to Coding Standards",
        "attck": None, "attck_name": None},
    # --- Existing major crypto detectors ---
    "reentrancy_path": {
        "cwe": "CWE-841",
        "name": "Improper Enforcement of Behavioral Workflow",
        "attck": None, "attck_name": None},
    "unchecked_erc20_return": {
        "cwe": "CWE-252", "name": "Unchecked Return Value",
        "attck": None, "attck_name": None},
    "permit_signature_replay": {
        "cwe": "CWE-347",
        "name": "Improper Verification of Cryptographic Signature",
        "attck": None, "attck_name": None},
    "flashloan_callback": {
        "cwe": "CWE-862", "name": "Missing Authorization",
        "attck": None, "attck_name": None},
    "chainlink_stale_feed": {
        "cwe": "CWE-20", "name": "Improper Input Validation",
        "attck": None, "attck_name": None},
    "oracle_spot_drift": {
        "cwe": "CWE-20", "name": "Improper Input Validation",
        "attck": None, "attck_name": None},
    "fee_on_transfer_overcredit": {
        "cwe": "CWE-682", "name": "Incorrect Calculation",
        "attck": None, "attck_name": None},
    "unprotected_initializer": {
        "cwe": "CWE-284", "name": "Improper Access Control",
        "attck": None, "attck_name": None},
    "arbitrary_delegatecall": {
        "cwe": "CWE-829",
        "name": "Inclusion of Functionality from Untrusted Control Sphere",
        "attck": None, "attck_name": None},
    "unbounded_slippage": {
        "cwe": "CWE-682", "name": "Incorrect Calculation",
        "attck": None, "attck_name": None},
    "ecdsa_signature_malleability": {
        "cwe": "CWE-347",
        "name": "Improper Verification of Cryptographic Signature",
        "attck": None, "attck_name": None},
    # --- Web / infra majors ---
    "sqli_error_based": {
        "cwe": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an "
                "SQL Command ('SQL Injection')",
        "attck": "T1190", "attck_name": "Exploit Public-Facing Application"},
    "xss_reflected": {
        "cwe": "CWE-79",
        "name": "Improper Neutralization of Input During Web Page "
                "Generation ('Cross-site Scripting')",
        "attck": "T1189", "attck_name": "Drive-by Compromise"},
    "ssrf_cloud_metadata": {
        "cwe": "CWE-918", "name": "Server-Side Request Forgery (SSRF)",
        "attck": "T1090", "attck_name": "Proxy"},
    "idor_candidate": {
        "cwe": "CWE-639",
        "name": "Authorization Bypass Through User-Controlled Key",
        "attck": None, "attck_name": None},
    "idor_confirmed": {
        "cwe": "CWE-639",
        "name": "Authorization Bypass Through User-Controlled Key",
        "attck": None, "attck_name": None},
    "open_redirect": {
        "cwe": "CWE-601",
        "name": "URL Redirection to Untrusted Site ('Open Redirect')",
        "attck": None, "attck_name": None},
    "jwt_alg_none": {
        "cwe": "CWE-347",
        "name": "Improper Verification of Cryptographic Signature",
        "attck": None, "attck_name": None},
    "exposed_aws_key": {
        "cwe": "CWE-798", "name": "Use of Hard-coded Credentials",
        "attck": "T1552.001",
        "attck_name": "Unsecured Credentials: Credentials In Files"},
    "exposed_github_token": {
        "cwe": "CWE-798", "name": "Use of Hard-coded Credentials",
        "attck": "T1552.001",
        "attck_name": "Unsecured Credentials: Credentials In Files"},
    "hardcoded_password": {
        "cwe": "CWE-798", "name": "Use of Hard-coded Credentials",
        "attck": "T1552.001",
        "attck_name": "Unsecured Credentials: Credentials In Files"},
    "s3_public_read": {
        "cwe": "CWE-200",
        "name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "attck": None, "attck_name": None},
    "cve_match": {
        "cwe": None, "name": "CVE-specific (see CVE record)",
        "attck": None, "attck_name": None},
}


def cwe_for(key: str) -> Optional[Dict[str, Optional[str]]]:
    """Taxonomy entry for a finding key, or None when unmapped."""
    if not key:
        return None
    return CWE_MAP.get(str(key).strip())


def label_for(key: str) -> str:
    """Short human label, e.g. 'CWE-682: Incorrect Calculation'."""
    entry = cwe_for(key)
    if not entry or not entry.get("cwe"):
        return ""
    return f"{entry['cwe']}: {entry['name']}"
