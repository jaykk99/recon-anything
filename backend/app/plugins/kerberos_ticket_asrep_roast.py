"""Kerberos AS-REP roast check - DETECTION-ONLY posture adaptation.

The boundary forbids ticket harvesting and offline cracking, and
neither is implemented. This plugin reads posture from directory /
config data the operator supplies (LDIF export, JSON account list,
smb_ldap_enum-style records): accounts whose userAccountControl
carries DONT_REQ_PREAUTH (0x400000) are AS-REP-roastable in
posture - Kerberos will issue them an AS-REP without pre-auth.
Each is reported as a configuration finding (account name + flag
only; no hashes exist in this data and none are requested).
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, text_of

DONT_REQ_PREAUTH = 0x400000


def _accounts_from_ldif(text: str):
    accounts = []
    current: Dict[str, str] = {}
    for line in (text or "").splitlines() + [""]:
        if not line.strip():
            if current:
                accounts.append(current)
                current = {}
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            current[k.strip().lower()] = v.strip().lstrip(":").strip()
    return accounts


def _accounts_from_json(text: str):
    try:
        obj = json.loads(text)
    except Exception:
        return []
    rows = obj if isinstance(obj, list) else obj.get("accounts", [])
    out = []
    for r in rows if isinstance(rows, list) else []:
        if isinstance(r, dict):
            out.append({str(k).lower(): v for k, v in r.items()})
    return out


def _flag_hits(name: str, uac_raw: Any, extra_flag: bool):
    try:
        uac = int(str(uac_raw), 0)
    except Exception:
        uac = 0
    if (uac & DONT_REQ_PREAUTH) or extra_flag:
        return {
            "key": "kerberos_asrep_roastable_account",
            "severity": "medium",
            "value": f"Account '{name}' has Kerberos pre-auth "
                     f"DISABLED (userAccountControl "
                     f"{uac_raw}, DONT_REQ_PREAUTH 0x400000 set) - "
                     "AS-REP-roastable posture: anyone can request "
                     "its AS-REP and attack the password offline",
            "evidence": {"account": name,
                         "user_account_control": str(uac_raw),
                         "remediation": "Enable 'Kerberos "
                         "pre-authentication' for this account "
                         "(clear DONT_REQ_PREAUTH) and set a long "
                         "random password. Detected from directory "
                         "data only - no ticket was requested and "
                         "nothing was cracked."}}
    return None


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    text = text_of(data)
    if not text:
        return hits
    accounts = _accounts_from_json(text) or _accounts_from_ldif(text)
    for acc in accounts:
        acct = str(acc.get("samaccountname") or acc.get("cn")
                   or acc.get("name") or acc.get("dn") or "?")
        uac = acc.get("useraccountcontrol",
                      acc.get("user_account_control", ""))
        flag_text = str(acc.get("flags", "")) + str(
            acc.get("kerberos", ""))
        extra = "DONT_REQ_PREAUTH" in text.upper() and \
            acct in text and bool(re.search(
                r"DONT_REQUIRE_PREAUTH|DONT_REQ_PREAUTH", flag_text,
                re.I))
        hit = _flag_hits(acct, uac, extra)
        if hit:
            hits.append(hit)
    if not accounts:
        # Flat text export: "user: X userAccountControl: N" lines.
        for m in re.finditer(
                r"(?im)([A-Za-z0-9_.\-]+)\D{0,30}userAccountControl"
                r"\s*[:=]\s*(\d+)", text):
            hit = _flag_hits(m.group(1), m.group(2), False)
            if hit:
                hits.append(hit)
    return hits[:16]


class KerberosTicketAsrepRoastPlugin(Plugin):
    id = "kerberos_ticket_asrep_roast"
    label = "Kerberos AS-REP Posture (Detection-Only)"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    phase = 2
    description = ("DETECTION ONLY - no ticket harvesting, no "
                   "cracking: flags accounts with Kerberos "
                   "pre-auth disabled (DONT_REQ_PREAUTH) in supplied "
                   "directory/LDIF/config data.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "identity",
                          ("directory_exports", "ldif_data",
                           "kerberos_configs"))
            if got is not None:
                return got
            return self._ok([], "no supplied directory/LDIF export "
                            "in ctx.shared; detection-only lane "
                            "requests no tickets")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
