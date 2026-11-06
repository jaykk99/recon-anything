"""Access Control Scraper (Cat-1 #21, VARIANT of contract_recon).

Delta: live role-membership AGGREGATION. contract_recon
inventories privileged functions; this plugin aggregates who
actually holds power - OpenZeppelin role holders (from
RoleGranted / RoleRevoked event records or getRoleMember results
supplied on the bus as role_data / role_members records) plus the
current owner per contract - into one roles/owners table, and
flags the dangerous shapes: DEFAULT_ADMIN_ROLE spread across
multiple holders, an admin role held by the zero address or by an
unexpected EOA set, and owner != admin divergence. A tight,
single-admin layout stays silent (the table is in evidence on any
finding, and the pure function always returns it).
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from . import _cat300_common as C

_ZERO = "0x0000000000000000000000000000000000000000"
_ADMIN_NAMES = ("default_admin_role", "admin", "owner")


def aggregate_roles(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """records: {contract, owner?, roles?: {role: [members]},
    events?: [{type: RoleGranted|RoleRevoked, role, account}]}"""
    table: Dict[str, Any] = {}
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        contract = str(rec.get("contract") or rec.get("address")
                       or "unknown")
        entry = table.setdefault(contract,
                                 {"owner": rec.get("owner"), "roles": {}})
        if rec.get("owner"):
            entry["owner"] = rec["owner"]
        for role, members in (rec.get("roles") or {}).items():
            cur = entry["roles"].setdefault(str(role), [])
            for m in members or []:
                if str(m) not in cur:
                    cur.append(str(m))
        for ev in rec.get("events") or []:
            if not isinstance(ev, dict):
                continue
            role = str(ev.get("role") or "")
            acct = str(ev.get("account") or ev.get("member") or "")
            if not role or not acct:
                continue
            cur = entry["roles"].setdefault(role, [])
            if ev.get("type") == "RoleRevoked":
                if acct in cur:
                    cur.remove(acct)
            elif acct not in cur:
                cur.append(acct)
    return table


def analyze_role_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    table = aggregate_roles(records)
    hits: List[Dict[str, Any]] = []
    for contract, entry in table.items():
        for role, members in entry["roles"].items():
            is_admin = any(a in role.lower() for a in _ADMIN_NAMES)
            if _ZERO in members:
                hits.append(C.hit(
                    "access_role_zero_address",
                    f"{contract}: role {role} lists the zero "
                    f"address as a holder - the role bookkeeping "
                    f"is broken or the role was burned without "
                    f"cleanup.",
                    "medium",
                    "Revoke the zero address and audit the role "
                    "grant history.",
                    contract=contract, role=role, table=table,
                    check="access_scraper"))
            if is_admin and len(members) > 1:
                hits.append(C.hit(
                    "access_admin_role_spread",
                    f"{contract}: admin role {role} is held by "
                    f"{len(members)} accounts "
                    f"({', '.join(members[:4])}): every holder "
                    f"can grant itself every other role.",
                    "medium",
                    "Reduce admin holders to the minimum (ideally "
                    "one multisig / timelock) and review each "
                    "holder.",
                    contract=contract, role=role, members=members,
                    table=table, check="access_scraper"))
        owner = entry.get("owner")
        admin_members: List[str] = []
        for role, members in entry["roles"].items():
            if "default_admin" in role.lower():
                admin_members = members
        if owner and admin_members and owner not in admin_members:
            hits.append(C.hit(
                "access_owner_admin_divergence",
                f"{contract}: owner {owner} is NOT among the "
                f"DEFAULT_ADMIN_ROLE holders "
                f"({', '.join(admin_members[:3])}) - two separate "
                f"power centres exist and either can act alone.",
                "medium",
                "Align ownership and admin role under one "
                "governed account (multisig/timelock).",
                contract=contract, owner=owner, table=table,
                check="access_scraper"))
    return hits


def analyze(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for kind in ("role_data", "role_members", "roles"):
        for item in data["extras"].get(kind, []):
            if isinstance(item, dict) and isinstance(
                    item.get("contracts"), list):
                records.extend(item["contracts"])
            elif isinstance(item, dict):
                records.append(item)
            elif isinstance(item, list):
                records.extend(x for x in item if isinstance(x, dict))
    return analyze_role_records(records)


class AccessControlScraperPlugin(Plugin):
    id = "access_control_scraper"
    label = "Access Control Scraper"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web3"
    description = ("Aggregates live OpenZeppelin role holders and "
                   "owners across contracts into one table and "
                   "flags admin-role spread, zero-address holders "
                   "and owner/admin divergence.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        return await C.finish(
            self, target, ctx, analyze,
            extras=("role_data", "role_members", "roles"),
            source=False, bytecode=False,
            no_input="no role/owner records supplied: aggregation "
                     "needs role_data records from log/eth_call lanes")
