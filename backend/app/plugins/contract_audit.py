"""Smart contract static analyzer (pure Python, no Slither).

Works with ZERO API keys:
- Keyless: Sourcify repo (no auth) for verified contract source.
- Enhanced: ETHERSCAN_API_KEY fetches Etherscan verified source first
  (broader coverage) when configured.

For contract addresses with VERIFIED source, pulls the public source and
runs static checks: reentrancy patterns (external call before state
update), missing access controls (public state-changing functions with no
guard), tx.origin usage, unchecked external calls, and integer overflow
risk on pre-0.8.0 Solidity. Static analysis only: it never sends
transactions, calls contracts, or touches the chain beyond reading
published source.
"""
from __future__ import annotations

import os
import re
import time
from typing import Dict, List, Optional, Tuple

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, safe_json_dict

ETH_API = "https://api.etherscan.io/api"
SOURCIFY_REPO = "https://repo.sourcify.dev/contracts"
MAX_ADDR = 5  # contracts to audit per run (free-tier friendly)

# Matches `function name(...) modifiers returns (...) {` up to the matching
# closing brace, using brace counting. Nested bodies handled.
FUNC_RE = re.compile(
    r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*"
    r"((?:public|external|internal|private|pure|view|payable|"
    r"virtual|override|[A-Za-z_][A-Za-z0-9_]*)\s*)*",
    re.S)


def _key(ctx: Ctx) -> Optional[str]:
    return ctx.keys.get("etherscan") or os.environ.get("ETHERSCAN_API_KEY") or None


def _strip_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def _split_functions(src: str) -> List[Tuple[str, str]]:
    """Return (name, body) pairs using brace matching after each signature."""
    out = []
    for m in FUNC_RE.finditer(src):
        name = m.group(1)
        i = m.end()
        # find the opening brace of the body
        while i < len(src) and src[i] != "{":
            i += 1
        if i >= len(src):
            continue
        depth = 0
        start = i
        j = i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((name, src[start:j + 1]))
    return out


def _modifiers(sig: str) -> List[str]:
    mods = []
    for w in ("onlyOwner", "onlyAdmin", "onlyRole", "nonReentrant",
              "whenNotPaused", "authorized", "onlyGuardian"):
        if w in sig:
            mods.append(w)
    return mods


def _state_writes(body: str) -> bool:
    # storage writes: plain assignments to identifiers (exclude ==, >=, <=,
    # !=, += handled separately, and function-local `uint x = ` decls are
    # roughly filtered by excluding lines starting with a type keyword)
    for line in body.splitlines():
        s = line.strip()
        if re.match(r"^(uint|int|bool|address|string|bytes|mapping|var)\b", s):
            continue
        if re.search(r"(?<![=!<>])=(?![=>])", s):
            return True
    return False


def audit_source(src: str) -> List[Dict[str, str]]:
    """Static checks over verified Solidity source.

    Returns list of {"check":..., "severity":..., "detail":..., "function":...}.
    """
    findings: List[Dict[str, str]] = []
    clean = _strip_comments(src)

    # --- 0. Solidity version (integer overflow risk pre-0.8.0) ---
    old_solidity = False
    m = re.search(r"pragma\s+solidity\s*([^;]+);", clean)
    pragma = m.group(1) if m else ""
    mv = re.search(r"0\.(\d+)", pragma)
    if mv and int(mv.group(1)) < 8:
        old_solidity = True
    uses_safemath = bool(re.search(r"SafeMath|using\s+.*\s+for\s+uint", clean))

    # tx.origin anywhere = global flag
    for tm in re.finditer(r"tx\.origin", clean):
        line = clean[max(0, tm.start() - 60):tm.end() + 60].replace("\n", " ").strip()
        findings.append({"check": "tx_origin", "severity": "high",
                         "function": "", "detail": f"tx.origin used: ...{line}..."})

    # unchecked external calls anywhere = global flag
    for pat, what in ((r"\.send\(", "send"), (r"\.delegatecall\(", "delegatecall")):
        for um in re.finditer(pat, clean):
            ctx_line = clean[max(0, um.start() - 80):um.end() + 40]
            # is the return value captured or checked nearby?
            before = clean[max(0, um.start() - 120):um.start()]
            after = clean[um.end():um.end() + 120]
            handled = bool(re.search(r"(bool|require|assert|if|success)", before[-60:] + after[:60]))
            if not handled:
                findings.append({"check": "unchecked_call", "severity": "medium",
                                 "function": "",
                                 "detail": f"Return value of .{what}(...) not checked near: {ctx_line.replace(chr(10), ' ').strip()[:140]}"})

    # --- 3. selfdestruct / suicide: can brick or drain the contract ---
    for sm in re.finditer(r"\bselfdestruct\s*\(|\bsuicide\s*\(", clean):
        ctx_line = clean[max(0, sm.start() - 80):sm.end() + 40].replace("\n", " ").strip()
        findings.append({"check": "selfdestruct", "severity": "medium",
                         "function": "",
                         "detail": f"selfdestruct/suicide present: ...{ctx_line[:140]}... "
                                   "Can brick the contract or force-drain ETH to an "
                                   "attacker-chosen address."})

    funcs = _split_functions(clean)
    fn_names = [n for n, _ in funcs]
    for name, body in funcs:
        # find the signature text (from 'function name' to the '{')
        sig_m = re.search(r"function\s+" + re.escape(name) + r"\s*\([^;{}]*\)[^{;]*", clean)
        sig_text = sig_m.group(0) if sig_m else ""
        is_public = ("public" in sig_text) or ("external" in sig_text)
        mods = _modifiers(sig_text)
        guarded = bool(mods) or bool(re.search(r"require\s*\(\s*msg\.sender", body))

        # --- 1. reentrancy: external value transfer before state write ---
        for call_re, call_kind in (
                (r"\.call\{value\s*:", "call{value}"),
                (r"\.call\.value\(", "call.value()"),
                (r"\.send\(", "send()"),
                (r"\.transfer\(", "transfer()")):
            for cm in re.finditer(call_re, body):
                after = body[cm.end():]
                if _state_writes(after):
                    no_guard_note = ("" if "nonReentrant" in mods else
                                     " Also missing a nonReentrant guard on this "
                                     "value-transfer function.")
                    findings.append({
                        "check": "reentrancy", "severity": "high",
                        "function": name,
                        "detail": (f"Function '{name}' makes an external value call "
                                   f"({call_kind}) and writes state AFTER it. Classic "
                                   "reentrancy shape: apply checks-effects-interactions "
                                   f"or ReentrancyGuard.{no_guard_note}")})
                    break

        # --- 3b. delegatecall to a non-hardcoded (untrusted) target ---
        # The TARGET of delegatecall is the receiver (X in X.delegatecall),
        # not the call arguments (which are just the forwarded calldata).
        # A receiver that is a 0x address literal or an immutable/constant
        # state var (set once at deploy time) is effectively hardcoded, so
        # it is trusted. Anything else (dynamic address, function arg,
        # mutable state var) is untrusted and gets flagged.
        for dm in re.finditer(
                r"((?:0x[0-9a-fA-F]{40})|(?:[A-Za-z_][A-Za-z0-9_]*"
                r"(?:\.[A-Za-z_][A-Za-z0-9_]*)*))"
                r"\.delegatecall\s*\(", body):
            receiver = dm.group(1).split(".")[-1]
            trusted = bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", receiver))
            if not trusted and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",
                                            receiver):
                # immutable/constant state vars are set once at deploy time:
                # effectively hardcoded, so trusted. Check the declaration
                # statement (keyword can come before or after the name).
                for decl in re.finditer(r"[^;{}]*\b" + re.escape(receiver) +
                                        r"\b[^;{}]*;", clean):
                    if re.search(r"\b(immutable|constant)\b", decl.group(0)):
                        trusted = True
                        break
            if not trusted:
                findings.append({
                    "check": "delegatecall_untrusted", "severity": "high",
                    "function": name,
                    "detail": (f"Function '{name}' delegatecalls to a non-hardcoded "
                               f"target ({receiver[:60] or 'dynamic'}). If the target "
                               "address is attacker-controllable the contract's "
                               "logic can be hijacked (storage lives in the "
                               "caller).")})
                break

        # --- 3c. flash-loan callback without caller check ---
        if name in ("onFlashLoan", "executeOperation") and not guarded:
            findings.append({
                "check": "flashloan_callback", "severity": "medium",
                "function": name,
                "detail": (f"Flash-loan callback '{name}' has no access control. "
                           "Anyone can invoke it directly, skipping the lending "
                           "pool's accounting (repay checks, fee enforcement).")})

        # --- 3d. unprotected initializer (proxy pattern) ---
        if name.lower() == "initialize" and is_public and not guarded:
            if not re.search(r"require\s*\(\s*!?_?initialized", body, re.I):
                findings.append({
                    "check": "unprotected_initializer", "severity": "high",
                    "function": name,
                    "detail": (f"Public initialize() in '{name}' has no guard. "
                               "On upgradeable proxies anyone can front-run the "
                               "initialization and seize ownership/admin rights.")})

        # --- 2. missing access control on public state-changing fns ---
        if is_public and name not in ("constructor",) and _state_writes(body) and not guarded:
            findings.append({
                "check": "missing_access_control", "severity": "medium",
                "function": name,
                "detail": (f"Public/external function '{name}' changes state with no "
                           "access control (no onlyOwner/onlyRole/require(msg.sender)). "
                           "Anyone can call it.")})

        # --- 5. integer overflow on pre-0.8.0 without SafeMath ---
        if old_solidity and not uses_safemath:
            arith = re.search(r"\+\+|--|\+=|-=|\*=|/=", body)
            if arith and name and not any(f["check"] == "overflow" for f in findings):
                findings.append({
                    "check": "overflow", "severity": "medium",
                    "function": name,
                    "detail": (f"Pragma {pragma.strip()} is pre-0.8.0 (no built-in "
                               "overflow checks) and no SafeMath detected. Arithmetic "
                               f"in '{name}' may overflow/underflow.")})

    # --- 6. front-running / tx-ordering shape: a public price/amount that is
    #     settable and immediately usable (setPrice + buy), or an oracle price
    #     consumed with no TWAP / commit-reveal protection ---
    setters = [n for n in fn_names
               if re.search(r"set(price|rate)|updateprice|setoracle", n, re.I)]
    buyers = [n for n in fn_names
              if re.search(r"buy|purchase|swap|deposit", n, re.I)]
    if setters and buyers:
        findings.append({
            "check": "frontrunning", "severity": "medium", "function": "",
            "detail": (f"MEV/front-running shape: public price setter(s) "
                       f"{', '.join(setters[:5])} and immediately-usable value "
                       f"function(s) {', '.join(buyers[:5])} in the same contract. "
                       "A searcher can observe the price update in the mempool "
                       "and buy/sell ahead of it.")})
    for om in re.finditer(r"latestRoundData\s*\(", clean):
        window = clean[max(0, om.start() - 500):om.end() + 500]
        if not re.search(r"updatedAt|answeredInRound", window):
            findings.append({
                "check": "frontrunning", "severity": "medium", "function": "",
                "detail": ("Oracle price from latestRoundData() used with no "
                           "staleness check (no updatedAt/answeredInRound "
                           "validation nearby). Stale prices enable oracle "
                           "manipulation and MEV extraction.")})
            break

    # dedup by (check, function)
    seen = set()
    deduped = []
    for f in findings:
        k = (f["check"], f["function"])
        if k in seen:
            continue
        seen.add(k)
        deduped.append(f)
    return deduped


REMEDIATION = {
    "reentrancy": "Use checks-effects-interactions ordering (state before calls), "
                  "add OpenZeppelin ReentrancyGuard, and prefer pull-over-push payments.",
    "missing_access_control": "Restrict the function with onlyOwner/AccessControl roles "
                              "or require(msg.sender == <authorized>). Never leave "
                              "state-changing functions public by default.",
    "tx_origin": "Never use tx.origin for authorization; use msg.sender. tx.origin "
                 "lets phishing contracts impersonate the user.",
    "unchecked_call": "Capture and check the return value of low-level calls: "
                       "require(success) / (bool ok,) = target.call{...}(...).",
    "overflow": "Upgrade to Solidity >=0.8.0 (built-in overflow checks) or use "
                "SafeMath for all arithmetic on older compilers.",
    "delegatecall_untrusted": "Only delegatecall to immutable, hardcoded "
                              "implementation addresses you control. Never let "
                              "the delegatecall target come from calldata, "
                              "storage set by an owner, or an untrusted registry.",
    "selfdestruct": "Remove selfdestruct if the contract holds funds. If an "
                    "escape hatch is required, gate it behind a timelock + "
                    "multisig and make it pause-first, never instant-destroy.",
    "frontrunning": "Don't let a public setter change prices that are "
                    "immediately tradable. Use commit-reveal, TWAP oracles, "
                    "or batch auctions; validate oracle staleness "
                    "(updatedAt, answeredInRound) before acting on a price.",
    "flashloan_callback": "Restrict the callback to the lending pool: "
                          "require(msg.sender == address(POOL)). Aave-style "
                          "callbacks must never be callable by arbitrary users.",
    "unprotected_initializer": "Call _disableInitializers() in the implementation "
                                "constructor, or guard initialize() so it runs "
                                "exactly once (OpenZeppelin Initializable).",
}

EXPL = {
    "reentrancy": "weaponized",
    "missing_access_control": "public_poc",
    "tx_origin": "public_poc",
    "unchecked_call": "theoretical",
    "overflow": "public_poc",
    "delegatecall_untrusted": "weaponized",
    "selfdestruct": "public_poc",
    "frontrunning": "theoretical",
    "flashloan_callback": "public_poc",
    "unprotected_initializer": "weaponized",
}


class ContractAuditPlugin(Plugin):
    id = "contract_audit"
    label = "Contract Static Auditor"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    requires_keys = []  # works keyless via Sourcify; etherscan key enhances
    description = ("Static analysis of verified contract source: reentrancy, "
                   "access control, tx.origin, unchecked calls, overflow. "
                   "Keyless Sourcify source always tried; ETHERSCAN_API_KEY "
                   "(optional) adds Etherscan coverage. "
                   "Never interacts with contracts.")
    phase = 2  # consumes addresses published by address miners
    timeout_s = 180

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        key = _key(ctx)

        addrs = self._collect(ctx)
        if not addrs:
            res = self._skipped("no contract addresses discovered on this "
                                "target; nothing to audit")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        audited = 0
        no_source = 0
        for addr in addrs[:MAX_ADDR]:
            try:
                src, src_origin = await self._source(ctx, key, addr)
                if not src:
                    no_source += 1
                    findings.append(self._f(
                        "web3", "contract_source_unavailable",
                        f"{addr}: no verified source on Etherscan; static audit "
                        "not possible (bytecode only).",
                        source="Etherscan/Sourcify",
                        source_url=f"https://etherscan.io/address/{addr}",
                        confidence=90, passive=True,
                        evidence={
                            "severity": "medium", "address": addr,
                            "exploitability": "unknown",
                            "remediation": ("Audit is impossible without verified "
                                            "source. Verify the source on the block "
                                            "explorer before trusting the contract.")}))
                    continue
                issues = audit_source(src)
                audited += 1
                if not issues:
                    findings.append(self._f(
                        "web3", "contract_audit_clean",
                        f"{addr}: verified source scanned; no flagged patterns "
                        "(reentrancy, delegatecall, selfdestruct, tx.origin, "
                        "access control, unchecked calls, overflow, "
                        "front-running, flash-loan callbacks, initializers). "
                        "Not a proof of safety.",
                        source="Etherscan/Sourcify static audit",
                        source_url=f"https://etherscan.io/address/{addr}",
                        confidence=60, passive=True,
                        evidence={
                            "severity": "low", "address": addr,
                            "exploitability": "unknown",
                            "remediation": ("Static scan is a first pass only. Get a "
                                            "professional audit before mainnet use.")}))
                for iss in issues:
                    findings.append(self._f(
                        "web3", f"contract_{iss['check']}",
                        f"{iss['severity'].upper()}: {iss['detail']}",
                        source="Etherscan/Sourcify static audit",
                        source_url=f"https://etherscan.io/address/{addr}",
                        confidence=70, passive=True,
                        evidence={
                            "severity": iss["severity"], "address": addr,
                            "check": iss["check"], "function": iss["function"],
                            "exploitability": EXPL.get(iss["check"], "unknown"),
                            "remediation": REMEDIATION.get(iss["check"], ""),
                            "scope_note": ("Static analysis of published source only. "
                                           "Never interacted with the contract.")}))
            except Exception:
                continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"audited {audited} contract(s), "
                                 f"{no_source} without verified source")
        res.duration_ms = dur
        return res

    def _collect(self, ctx: Ctx) -> List[str]:
        seen: List[str] = []
        for kind in ("contract_addresses", "crypto_addresses"):
            for item in ctx.consume(kind):
                a = item if isinstance(item, str) else str(item.get("address", ""))
                a = a.strip()
                if re.fullmatch(r"0x[0-9a-fA-F]{40}", a) and a not in seen:
                    seen.append(a)
        return seen

    async def _source(self, ctx: Ctx, key: Optional[str], addr: str):
        """Fetch verified contract source.

        Tries Etherscan (when a key is configured) first, then keyless
        Sourcify repo. Returns (source, origin_label); (None, "") when
        neither has verified source.
        """
        if key:
            src = await self._source_etherscan(ctx, key, addr)
            if src:
                return src, "Etherscan"
        src = await self._source_sourcify(ctx, addr)
        if src:
            return src, "Sourcify"
        return None, ""

    async def _source_etherscan(self, ctx: Ctx, key: str, addr: str) -> Optional[str]:
        from urllib.parse import urlencode
        url = f"{ETH_API}?{urlencode({'module': 'contract', 'action': 'getsourcecode', 'address': addr, 'apikey': key})}"
        r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=20,
                        max_retries=1)
        if r.status_code != 200:
            return None
        try:
            d = r.json()
        except Exception:
            return None
        res = d.get("result")
        if not res or not isinstance(res, list):
            return None
        src = (res[0] or {}).get("SourceCode") or ""
        # Etherscan wraps multi-file sources in {{...}} JSON; unwrap best-effort
        if src.startswith("{{"):
            src = src.strip("{}")
        return src if len(src) > 100 else None

    async def _source_sourcify(self, ctx: Ctx, addr: str) -> Optional[str]:
        """Keyless verified source via Sourcify repo (no auth).

        Tries full_match then partial_match metadata, downloads every
        .sol source file, concatenates. Returns None when not verified.
        """
        for match in ("full_match", "partial_match"):
            meta_url = f"{SOURCIFY_REPO}/{match}/1/{addr}/metadata.json"
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", meta_url,
                                timeout=20, max_retries=1)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            try:
                meta = r.json()
            except Exception:
                continue
            sources = (meta or {}).get("sources") or {}
            sol_paths = [p for p in sources.keys()
                         if isinstance(p, str) and p.endswith(".sol")]
            if not sol_paths:
                continue
            parts: List[str] = []
            for sp in sol_paths[:12]:  # cap files per contract
                furl = f"{SOURCIFY_REPO}/{match}/1/{addr}/sources/{sp}"
                try:
                    fr = await fetch(ctx.http, ctx.limiter, "GET", furl,
                                     timeout=20, max_retries=1)
                except Exception:
                    continue
                if fr.status_code == 200 and fr.text:
                    parts.append(f"\n// ==== {sp} ====\n{fr.text}")
            if parts:
                return "\n".join(parts)
        return None
