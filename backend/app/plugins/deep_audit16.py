"""Deep-audit detectors, batch 12 continued as deep16.
The two batch-12/deep16 detectors (2026-11-07) not already on master;
the other three landed via PR #153 as deep_audit12, so this
module carries only approval_binds_id_not_version and
zero_amount_withdraw_all (with the 2026-11-07 sNUSD fix).

Five more chain-agnostic EVM detectors from the standing backlog
queue, built to the batch-11 / recipient-first standard: recipient
classification computed inside the detector and carried on the
finding (CALLER / CALLER-SUPPLIED = candidate; FIXED /
HOLDER-SELF = trigger-only, never a candidate), the exact code
plus a gate analysis on every finding, and a finding shape the
auto-validator can consume unchanged (kind, function, recipient,
report_class, gate).

- approval_binds_id_not_version: an approve / authorize function
  taking ONLY an id (incidentId / proposalId / assessmentId) that
  resolves the CURRENT round / version / schedule at execution
  time (reads currentAssessment[id] / the latest schedule),
  combined with a cancel + resubmit / replace path that can swap
  the payload under a pending approval. The Firelight Immunefi
  #88618 / #88366 Aug 2026 shape (High). An approve that takes a
  version / round / hash parameter and checks it against the
  current one stays silent. Distinct from built
  eip712_digest_unbound_to_payload (signature digest, not
  on-chain approval resolution).
- zero_amount_withdraw_all: a withdraw / unstake / undelegate
  function that takes a caller-supplied amount and forwards it
  into an external staking / withdrawal / delegation call (target
  call name contains withdraw / unstake / undelegate / redeem)
  with NO require(amount > 0) / zero-amount guard anywhere on
  the path; the downstream system treats 0 as "withdraw all".
  The b14g / Core Oct 2026 shape (~$1.47M). Any amount > 0 /
  amount != 0 check in the function stays silent, and calls into
  the contract's own inherited logic (super.redeem / this.redeem)
  stay silent - the downstream system must be an external
  staking / delegation contract.

Gate discipline: a caller-identity gate (only* modifier,
msg.sender identity comparison, role check) suppresses a
finding - a stranger cannot reach the path. The mechanism
under analysis itself does NOT count as such a gate.

Detection only: verified-source static analysis in the fast
lane, never sends a transaction, never calls the contract
for value. Fetch failure is reported honestly by the shared
scaffolding (analyzed 0 / no verified source - skipped),
never dressed up as a clean result.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from . import contract_chain as cc
from . import contract_logic as cl
from .bsc_common import DetectorSpec, S

MAX_ADDRESSES = 4
MAX_CHAIN_PAIRS = 4
FAMILY = "deep16"

SPECS = [
    S("approval_binds_id_not_version", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Approval binds an id, not a version: an approve / "
             "authorize function taking ONLY an id resolves the "
             "CURRENT round / version / schedule at execution "
             "time, and a cancel + resubmit / replace path can "
             "swap the payload under a pending approval, so the "
             "approval executes a payload nobody approved - the "
             "Firelight Immunefi shape. An approve that takes a "
             "version / round / hash parameter and checks it "
             "against the current one is the protected shape.",
      fix="Bind every approval to the exact version / round / "
          "payload hash it was granted for and require it to "
          "match the current one at execution, or invalidate "
          "pending approvals when a payload is replaced."),
    S("zero_amount_withdraw_all", FAMILY, severity="high",
      outcome="a", recipient=True,
      detail="Zero-amount withdraw withdraws all: a withdraw / "
             "unstake / undelegate function takes a "
             "caller-supplied amount and forwards it into an "
             "external staking / withdrawal / delegation call "
             "with NO require(amount > 0) / zero-amount guard "
             "anywhere on the path, and the downstream system "
             "treats 0 as 'withdraw all' - the b14g / Core "
             "shape. Any amount > 0 / amount != 0 check in the "
             "function is the protected shape.",
      fix="Require the amount to be greater than zero before "
          "forwarding it to the staking / delegation system, "
          "and treat 0 as an explicit withdraw-all only behind "
          "its own guarded path."),
]

SPECS_BY_ID = {s.id: s for s in SPECS}


# ---------------------------------------------------------------------------
# Shared helpers (mirrors batch 3)
# ---------------------------------------------------------------------------

def _scope_fns(src: str, contract_name: str):
    scope = cl._Scope(src, contract_name)
    fns = [fn for fn in scope.functions if "{" in fn["text"]]
    return scope, fns


def _hit(spec: DetectorSpec, fn_name: str, code: str,
         detail: str, gate: str) -> Dict[str, Any]:
    return {"kind": spec.id, "severity": spec.severity,
            "function": fn_name, "code": code, "detail": detail,
            "gate_analysis": gate}


def _classify(item: Dict[str, Any], recipient: str,
              rdetail: str) -> Dict[str, Any]:
    """The Nov 2 receive rule, carried on the finding."""
    item["recipient"] = recipient
    if recipient in ("FIXED", "HOLDER-SELF"):
        item["report_class"] = "trigger_only"
        item["severity"] = "low"
        item["detail"] += (
            f" Recipient analysis: the value / power lands at "
            f"a {recipient} destination ({rdetail}), so a "
            f"stranger can trigger this but receives nothing - "
            f"classified TRIGGER-ONLY under the receive rule.")
    else:
        item["report_class"] = "candidate"
        item["detail"] += (
            f" Recipient analysis: recipient classified "
            f"{recipient} ({rdetail}) - a stranger can receive "
            f"value or control here, classified CANDIDATE under "
            f"the receive rule.")
    return item


def _finish_recipient(spec: DetectorSpec, item: Dict[str, Any],
                      fn_text: str) -> Dict[str, Any]:
    recipient, rdetail = cl.classify_recipient(fn_text)
    return _classify(item, recipient, rdetail)


_IDENTITY_GATE_RE = re.compile(
    r"msg\.sender\s*(==|!=)|"
    r"(==|!=)\s*msg\.sender|"
    r"hasRole\s*\(|_checkOwner|_checkRole")
_ONLY_MOD_RE = re.compile(r"\bonly[A-Z][A-Za-z0-9_]*\b")


def _caller_gated(fn: Dict[str, Any], scope) -> bool:
    """Narrow caller-identity gate (see module docstring).

    Only an only* modifier, a msg.sender identity comparison,
    or a role check suppresses. The signature check and the
    _msgSender() gate under analysis are NOT gates here.
    """
    sig, text = fn["signature"], fn["text"]
    if _ONLY_MOD_RE.search(sig) or _IDENTITY_GATE_RE.search(text):
        return True
    stripped = re.sub(r"returns\s*\([^)]*\)", "", sig)
    i = stripped.find("(")
    if i >= 0:
        _, pend = _balanced(stripped, i)
        tail = stripped[pend + 1:]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", tail):
            body = scope.modifiers.get(tok)
            if body and ("msg.sender" in body and
                         ("==" in body or "!=" in body)):
                return True
    return False


def _balanced(text: str, open_pos: int) -> Tuple[str, int]:
    """(inner_text, end_pos) for the paren group at open_pos."""
    depth = 0
    for i in range(open_pos, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i
    return text[open_pos + 1:], len(text)


def _split_top(text: str) -> List[str]:
    depth = 0
    parts: List[str] = []
    cur: List[str] = []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur).strip())
    return [p for p in parts if p]



def _skip_fn(fn: Dict[str, Any], scope) -> bool:
    if re.search(r"\b(view|pure)\b", fn["signature"]):
        return True
    return _caller_gated(fn, scope)


def _fn_params(fn: Dict[str, Any]) -> List[str]:
    """Parameter names from a function signature."""
    sig = fn["signature"]
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:
                sig.rindex(")") if ")" in sig else len(sig)]
    out: List[str] = []
    for part in _split_top(inner):
        toks = [t for t in part.split()
                if t not in ("calldata", "memory", "storage",
                             "payable")]
        if len(toks) >= 2:
            out.append(toks[-1])
    return out



_APPROVE_FN_RE = re.compile(
    r"^(approve|authorize|approveAssessment|approveIncident|"
    r"confirmAssessment|executeApproval)$", re.I)
_CANCEL4_FN_RE = re.compile(r"^cancel", re.I)
_SUBMIT_FN_RE = re.compile(
    r"^(submit|propose|createAssessment|fileAssessment|"
    r"replaceAssessment)", re.I)
_CURRENT_READ_RE = re.compile(
    r"\b(current|latest)[A-Za-z_]*\s*\[[^\]]+\]|"
    r"\.\s*current\b", re.I)
_VERSION_PARAM_RE = re.compile(
    r"\b(version|round|scheduleVersion|assessmentVersion|"
    r"expectedHash|payloadHash|versionHash)\b")
_ID_PARAM_RE = re.compile(
    r"^(incidentId|proposalId|assessmentId|requestId|id)$",
    re.I)



def _analyze_approval_id_not_version(src, spec, compiler,
                                     contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _APPROVE_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        if not params or not _ID_PARAM_RE.match(params[0]):
            continue
        # A version / round / hash parameter is a binding only
        # when the function actually checks it against the
        # current one; a checked binding suppresses.
        version_param = None
        if len(params) == 2 and _VERSION_PARAM_RE.search(params[1]):
            version_param = params[1]
        elif len(params) != 1:
            continue
        if version_param and re.search(
                r"\b" + re.escape(version_param) + r"\s*(==|!=)",
                text):
            continue
        # Leg 1: approve resolves the CURRENT round / version /
        # schedule for the bare id at execution time.
        cur_m = _CURRENT_READ_RE.search(text)
        if not cur_m:
            continue
        cur_ref = cur_m.group(0).strip()
        if not cl._external_calls(text):
            continue
        # Leg 2: a cancel + resubmit / replace pair can swap the
        # payload under a pending approval for the same id.
        idp = params[0]
        has_cancel = False
        has_submit = False
        for ofn in fns:
            if ofn["name"] == fn["name"]:
                continue
            if _CANCEL4_FN_RE.match(ofn["name"]) and \
                    idp in _fn_params(ofn) and \
                    re.search(r"\bdelete\b|=\s*true\b|=\s*false\b",
                              ofn["text"]):
                has_cancel = True
            if _SUBMIT_FN_RE.match(ofn["name"]) and \
                    idp in _fn_params(ofn) and \
                    re.search(r"\b(current|latest)[A-Za-z_]*"
                              r"\s*\[[^\]]+\]\s*=",
                              ofn["text"]):
                has_submit = True
        if not (has_cancel and has_submit):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' takes only an id "
            f"('{idp}') and resolves the current version "
            f"('{cur_ref}') for it at execution time, while a "
            f"cancel + resubmit pair "
            f"can swap the payload stored under that same id, so "
            f"the approval executes a payload nobody approved. "
            f"Gate analysis: no caller-identity gate, no "
            f"version / round / hash binding on the approval.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated approve: binds only an id and "
                    "resolves the current version, cancel + "
                    "resubmit can swap the payload underneath")
        out.append(_finish_recipient(spec, item, text))
    return out


# ---------------------------------------------------------------------------
# 5. zero_amount_withdraw_all (b14g / Core shape)
# ---------------------------------------------------------------------------

_WITHDRAW5_FN_RE = re.compile(
    r"^(withdraw|unstake|undelegate|redeem|withdrawStake|"
    r"unstakeAll|redeemStake)$", re.I)
_STAKE_CALL_RE = re.compile(
    r"\.\s*(withdraw|unstake|undelegate|redeem)\s*\(")
_STAKE_RECV_RE = re.compile(
    r"stak|valid|deleg|pool|strategy|vault|operator|consensus",
    re.I)
_AMOUNT_PARAM_RE = re.compile(
    r"^(amount|shares|stakeAmount|value|assets)$", re.I)


def _zero_guard_present(text: str, amt: str) -> bool:
    pats = [
        r"require\s*\(\s*" + re.escape(amt) + r"\s*>\s*0",
        r"require\s*\(\s*" + re.escape(amt) + r"\s*!=\s*0",
        r"require\s*\(\s*" + re.escape(amt) + r"\s*>=\s*1",
        r"assert\s*\(\s*" + re.escape(amt) + r"\s*>\s*0",
        r"if\s*\(\s*" + re.escape(amt) + r"\s*==\s*0\s*\)\s*revert",
        r"if\s*\(\s*" + re.escape(amt) + r"\s*<=\s*0\s*\)\s*revert",
    ]
    return any(re.search(p, text) for p in pats)


def _analyze_zero_amount_withdraw(src, spec, compiler,
                                  contract_name):
    scope, fns = _scope_fns(src, contract_name)
    out: List[Dict[str, Any]] = []
    for fn in fns:
        if not _WITHDRAW5_FN_RE.match(fn["name"]):
            continue
        if _skip_fn(fn, scope):
            continue
        text = fn["text"]
        params = _fn_params(fn)
        amt = None
        for p in params:
            if _AMOUNT_PARAM_RE.match(p):
                amt = p
                break
        if amt is None:
            continue
        # Leg 1: the amount is forwarded into an external
        # staking / withdrawal / delegation call - an unstake /
        # undelegate / redeem call, or a withdraw call on a
        # staking / validator / delegation receiver.
        forwarded = None
        for m in _STAKE_CALL_RE.finditer(text):
            paren = text.index("(", m.start())
            inner, _ = _balanced(text, paren)
            args = _split_top(inner)
            if not any(a.strip() == amt for a in args):
                continue
            recv = text[max(0, m.start() - 60):m.start()]
            rm = re.search(r"([A-Za-z_]\w*)\s*$", recv)
            receiver = rm.group(1) if rm else ""
            # Live-corpus FP (2026-11-07): sNUSD / StakedlvlUSD
            # redeem() overrides call super.redeem() - inherited
            # ERC-4626 logic, not an external staking system with
            # 0-means-all semantics. super./this. calls are the
            # contract's own logic, never the downstream system.
            if receiver.lower() in ("super", "this"):
                continue
            method = m.group(1).lower()
            if method in ("unstake", "undelegate", "redeem") or \
                    _STAKE_RECV_RE.search(receiver):
                forwarded = text[m.start():m.start() + 80]
                break
        if forwarded is None:
            continue
        # Leg 2: no zero-amount guard anywhere on the path.
        if _zero_guard_present(text, amt):
            continue
        detail = spec.detail + (
            f" Observed: '{fn['name']}' forwards the "
            f"caller-supplied amount ('{amt}') into an external "
            f"staking / withdrawal call ('{forwarded.strip()}'"
            f") with no require({amt} > 0) / zero-amount guard, "
            f"so passing 0 makes the downstream system "
            f"withdraw everything. Gate analysis: no "
            f"caller-identity gate, no zero-amount guard on the "
            f"path.")
        item = _hit(spec, fn["name"], cc._snip(text), detail,
                    "ungated withdraw: caller amount forwarded to "
                    "a staking / delegation call with no "
                    "zero-amount guard")
        out.append(_finish_recipient(spec, item, text))
    return out


ANALYZERS = {
    "approval_binds_id_not_version": _analyze_approval_id_not_version,
    "zero_amount_withdraw_all": _analyze_zero_amount_withdraw,
}


def analyze_deep16_source(src: str, spec: DetectorSpec,
                          compiler: str = "",
                          contract_name: str = ""
                          ) -> List[Dict[str, Any]]:
    """Run ONE batch-12/deep16 detector over verified source. Returns
    finding dicts {kind(=spec.id), severity, function, code,
    detail, gate_analysis, recipient, report_class}."""
    fn = ANALYZERS.get(spec.id)
    if fn is None:
        return []
    return fn(src, spec, compiler, contract_name)


# ---------------------------------------------------------------------------
# Plugin scaffolding (mirrors the batch-3 collection / fetch /
# proxy resolution; analysis is analyze_deep16_source per spec)
# ---------------------------------------------------------------------------

class DeepAudit16Plugin(Plugin):
    id = ""
    label = "Deep Audit Detector (Batch 12 cont. / deep16)"
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []
    description = ""
    phase = 2
    timeout_s = 120
    _spec: Optional[DetectorSpec] = None

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        spec = self._spec
        t0 = time.monotonic()
        key = ctx.keys.get("etherscan") or \
            os.environ.get("ETHERSCAN_API_KEY") or None
        work = self._collect(target, ctx)
        if not work or spec is None:
            res = self._skipped(
                "no contract address to analyze: scan a contract "
                "address (optionally chain-prefixed, e.g. bsc:0x...) "
                "or a web target whose pages reference one")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        findings: List[Finding] = []
        analyzed = 0
        no_source = 0
        pairs_done = 0
        for chain_hint, addr in work:
            if pairs_done >= MAX_CHAIN_PAIRS:
                break
            try:
                pairs, got = await self._scan_address(
                    ctx, key, chain_hint, addr, findings)
            except Exception:
                pairs, got = 0, False
            pairs_done += pairs
            if pairs:
                analyzed += 1
                if not got:
                    no_source += 1
        dur = int((time.monotonic() - t0) * 1000)
        hits = sum(1 for f in findings if f.key == spec.id)
        res = self._ok(
            findings,
            f"{spec.id}: analyzed {analyzed} contract address(es) "
            f"({no_source} without verified source - skipped, no "
            f"guess made), {hits} finding(s)")
        res.duration_ms = dur
        return res

    def _collect(self, target: Target,
                 ctx: Ctx) -> List[Tuple[Optional[str], str]]:
        out: List[Tuple[Optional[str], str]] = []
        seen = set()

        def add(chain_hint: Optional[str], addr: str) -> None:
            addr = (addr or "").strip()
            if not cc.ADDRESS_RE.match(addr):
                return
            if addr.lower() == cc.ZERO_ADDRESS:
                return
            k = addr.lower()
            if k in seen:
                return
            seen.add(k)
            out.append((chain_hint, addr))

        for raw in (target.normalized, target.raw):
            chain_hint, addr = cc.parse_target_address(raw or "")
            if addr:
                add(chain_hint, addr)
                break
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else \
                    str(item.get("address", ""))
                add(None, a)
        for item in ctx.consume("chain_contracts"):
            if isinstance(item, dict):
                hint = item.get("chain")
                add(hint if isinstance(hint, str) and
                    hint in cc.CHAINS else None,
                    str(item.get("address", "")))
        return out[:MAX_ADDRESSES]

    async def _scan_address(self, ctx: Ctx, key: Optional[str],
                            chain_hint: Optional[str], addr: str,
                            findings: List[Finding]
                            ) -> Tuple[int, bool]:
        if chain_hint:
            chain_ids = [chain_hint]
        else:
            chain_ids = list(cc.DEFAULT_CHAIN_ORDER)
        pairs = 0
        got_source = False
        for cid in chain_ids:
            if pairs >= MAX_CHAIN_PAIRS:
                break
            chain = cc.CHAINS[cid]
            code = await cc.rpc_get_code(ctx, chain, addr)
            if code is None or code == "0x" or len(code) < 4:
                continue
            pairs += 1
            if await self._scan_on_chain(ctx, key, chain, addr,
                                         code, findings):
                got_source = True
            if chain_hint:
                break
        return pairs, got_source

    async def _scan_on_chain(self, ctx: Ctx, key: Optional[str],
                             chain: cc.ChainConfig, addr: str,
                             code_hex: str,
                             findings: List[Finding]) -> bool:
        src = await cc.fetch_verified_source(ctx, chain, addr, key)
        res = {"implementation": "", "via": "", "beacon": ""}
        try:
            res = await cc.resolve_implementation(
                ctx, chain, addr, code_hex,
                {"implementation": (src or {}).get(
                    "implementation", "")})
        except Exception:
            pass
        impl = res.get("implementation") or ""
        role = "proxy_shell" if impl else "standalone"
        got = self._analyze_contract(chain, addr, src, findings,
                                     role=role, impl_addr=impl)
        if not impl:
            return got
        impl_code = None
        impl_src = None
        try:
            impl_code = await cc.rpc_get_code(ctx, chain, impl)
            impl_src = await cc.fetch_verified_source(
                ctx, chain, impl, key)
        except Exception:
            impl_code, impl_src = None, None
        if not impl_code or impl_code == "0x" or len(impl_code) < 4:
            return got
        return self._analyze_contract(
            chain, impl, impl_src, findings,
            role="implementation", proxy_addr=addr) or got

    def _analyze_contract(self, chain: cc.ChainConfig, addr: str,
                          src: Optional[Dict[str, Any]],
                          findings: List[Finding], role: str,
                          proxy_addr: str = "",
                          impl_addr: str = "") -> bool:
        spec = self._spec
        if spec is None or not src:
            return False
        url = cc.explorer_url(chain, addr)
        base_ev = {"address": addr, "chain": chain.id,
                   "chain_id": chain.chain_id,
                   "contract_role": role}
        if role == "implementation":
            base_ev["proxy_address"] = proxy_addr
            base_ev["implementation_address"] = addr
            tag = f" [implementation behind proxy {proxy_addr}]"
        elif role == "proxy_shell":
            base_ev["proxy_address"] = addr
            base_ev["implementation_address"] = impl_addr
            tag = f" [proxy shell; implementation {impl_addr}]"
        else:
            tag = ""
        for item in analyze_deep16_source(
                src["source"], spec, src.get("compiler", ""),
                contract_name=src.get("contract_name", "")):
            ev = dict(base_ev)
            ev.update({
                "severity": item["severity"],
                "check": spec.id,
                "kind": spec.id,
                "detector_outcome": spec.outcome,
                "function": item["function"],
                "code": item["code"],
                "detail": item["detail"],
                "bytecode_only": False,
                "source_origin": src.get("origin", ""),
                "contract_name": src.get("contract_name", ""),
                "remediation": spec.fix,
            })
            if item.get("report_class"):
                ev["report_class"] = item["report_class"]
                ev["recipient"] = item.get("recipient", "")
            if item.get("gate_analysis"):
                ev["gate_analysis"] = item["gate_analysis"]
            fn_txt = f"function '{item['function']}' " \
                if item["function"] else ""
            findings.append(self._f(
                "web3", spec.id,
                f"{item['severity'].upper()}: {spec.label}: "
                f"{fn_txt}in contract {addr} on {chain.name}{tag}"
                f"\n\n{item['detail']}\n\nCode:\n{item['code']}",
                source="deep audit detector batch 12 "
                       "(verified source)",
                source_url=url,
                confidence=80 if item["severity"] == "high"
                else 65 if item["severity"] == "medium" else 55,
                passive=True, evidence=ev))
        return True


def _build_plugin_class(spec: DetectorSpec) -> type:
    return type(spec.class_name, (DeepAudit16Plugin,), {
        "id": spec.id,
        "label": spec.label,
        "_spec": spec,
        "description": (
            f"Deep-audit detector (batch 12) for "
            f"{spec.label.lower()}: {spec.detail} Static "
            f"verified-source analysis, fast lane, detection "
            f"only."),
        "__module__": __name__,
    })


for _spec in SPECS:
    globals()[_spec.class_name] = _build_plugin_class(_spec)
