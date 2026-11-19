"""Live read-only verification for smart-contract candidates (eth_call).

WHY THIS EXISTS
---------------
The live-test path (app/safe_tester.py PROBE_MAP) is entirely HTTP: a
contract candidate has no probe there, so in "live mode" every
contract finding came back "No safe probe available" and had to be
adjudicated by hand with cast. Two whole scan rounds closed 36 + 18
candidates manually this way. This module is the missing automated
layer: it turns a static contract candidate into a verdict using only
read-only JSON-RPC. It NEVER builds or broadcasts a transaction.

Two checks close the candidate shapes that dominate real scans:

  access_control - eth_call the flagged function AS a stranger
    (from = 0x1111...1111). A revert ("only owner", "missing role",
    "FORBIDDEN", "Not owner") means the caller-identity gate holds, so
    the detector's "unguarded" claim is false -> FALSE_POSITIVE. This
    is exactly how the reports closed exitMaintenance, setOwner,
    setFeeToSetter, _acceptAdmin, etc. (The old eth_call omitted
    `from`, so this check was impossible before.)

  value_at_stake - read the balance the candidate says is drainable
    (native via eth_getBalance, ERC-20 via balanceOf). Zero balance
    means nothing to steal -> FALSE_POSITIVE. This is the report's own
    prescription for the sweep/rescue/multicall candidates: "a live
    balance read would close these at scan time."

VERDICTS
--------
  false_positive - auto-closed by a read (gate holds / nothing at stake)
  needs_review   - the gate the detector claimed is genuinely absent, or
                   value is present: keep for a human or a deeper fork
                   test. A read proves a gate's ABSENCE and value's
                   PRESENCE, never a completed exploit, so this layer
                   never stamps VERIFIED_REAL on its own.
  error          - could not verify (RPC down, no selector): leave as-is.

The decision core (classify_*) is pure and deterministic - it takes the
result of a read, not a network - so it is fully unit-tested with a fake
RPC. The RPC adapter is injected.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

STRANGER = "0x1111111111111111111111111111111111111111"

# ERC-20 balanceOf(address) selector.
_BALANCEOF_SELECTOR = "0x70a08231"

FALSE_POSITIVE = "false_positive"
NEEDS_REVIEW = "needs_review"
ERROR = "error"

# Candidate keys / families that are access-control claims: "a stranger
# can call this privileged function". Verified by a stranger eth_call.
_ACCESS_FAMILY_RE = re.compile(
    r"(?i)access_control|cross_function_guard|caller|unguarded|"
    r"gate_bypass|cfg|setowner|setfeetosetter|acceptadmin|"
    r"setpendingimpl|grant|onlyowner|privileged|admin|_exitmaintenance|"
    r"ungated")

# Candidate keys / families that are value-drain claims: "value can be
# moved out". Verified by a live balance read of what is at stake.
_VALUE_FAMILY_RE = re.compile(
    r"(?i)rescue|sweep|withdraw|overdraw|value_sink|drain|"
    r"residual|bridge_release|underwrite|multicall")

# Revert reasons that prove a caller-identity gate held against a
# stranger. (An empty revert / out-of-gas does NOT prove a gate.)
_GATE_REVERT_RE = re.compile(
    r"(?i)only|owner|unauthor|forbidden|missing role|access ?control|"
    r"not (?:the )?(?:owner|admin|authorized)|caller is not|"
    r"permission|denied|invalid caller|not allowed|"
    r"current validator|pendingadmin")


class RpcLike(Protocol):
    def eth_call(self, to: str, data: str,
                 from_: Optional[str] = None) -> Tuple[Optional[str], str]:
        ...

    def eth_get_balance(self, addr: str) -> Tuple[Optional[int], str]:
        ...


# --- pure decision core ------------------------------------------------

def classify_stranger_call(result: Optional[str], error: str
                           ) -> Tuple[str, str]:
    """Verdict from eth_call'ing the flagged function AS a stranger."""
    if error:
        if _GATE_REVERT_RE.search(error):
            return (FALSE_POSITIVE,
                    f"stranger call reverted on a caller gate: "
                    f"{error.strip()[:180]}")
        if re.search(r"(?i)execution reverted|revert", error):
            # Reverted, but not clearly on an identity gate (could be a
            # require on args). Still strong evidence a stranger cannot
            # drive it as-is; keep it, don't claim real.
            return (NEEDS_REVIEW,
                    f"stranger call reverted (reason not identity-"
                    f"specific): {error.strip()[:180]}")
        return (ERROR, f"could not verify (RPC error): {error.strip()[:180]}")
    # eth_call returned data -> no revert -> no caller-identity gate.
    return (NEEDS_REVIEW,
            "stranger call did NOT revert: no caller-identity gate on "
            "this function. eth_call cannot prove the state change; "
            "needs a fork/state check to confirm impact.")


def classify_value_at_stake(balance: Optional[int], unit: str = "wei"
                            ) -> Tuple[str, str]:
    """Verdict from reading the balance a drain candidate puts at stake."""
    if balance is None:
        return (ERROR, "could not read balance at stake")
    if balance == 0:
        return (FALSE_POSITIVE,
                f"zero balance at stake ({unit}): nothing to drain, "
                "the 'value sink' moves 0")
    return (NEEDS_REVIEW,
            f"{balance} {unit} at stake: value is present, needs an "
            "exploit confirmation (read alone cannot prove the drain)")


def candidate_family(candidate: Dict[str, Any]) -> Optional[str]:
    """Which check applies: 'value', 'access', or None (no live check)."""
    blob = " ".join(str(candidate.get(k, "")) for k in
                     ("key", "kind", "value", "function", "family"))
    # Value drains first: a sweep/rescue is checked by balance even when
    # its text also mentions "caller" (a caller-supplied recipient).
    if _VALUE_FAMILY_RE.search(blob):
        return "value"
    if _ACCESS_FAMILY_RE.search(blob):
        return "access"
    return None


# --- selector / calldata helpers --------------------------------------

def _function_selector(candidate: Dict[str, Any]) -> Optional[str]:
    """A 4-byte selector to call, if the candidate carries one or a
    zero-arg signature we can hash. Returns 0x-prefixed 10-char or None."""
    sel = str(candidate.get("selector") or "").strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{8}", sel):
        return sel.lower()
    # A bare function name with no signature cannot be hashed reliably
    # (we don't know the argument types), so we only hash a provided
    # full signature like "setOwner(address)".
    sig = str(candidate.get("signature") or "").strip()
    if re.fullmatch(r"[A-Za-z_]\w*\([^)]*\)", sig):
        try:
            from Crypto.Hash import keccak  # pycryptodome, if present
            k = keccak.new(digest_bits=256)
            k.update(sig.encode())
            return "0x" + k.hexdigest()[:8]
        except Exception:
            try:
                from eth_hash.auto import keccak as _k  # type: ignore
                return "0x" + _k(sig.encode()).hex()[:8]
            except Exception:
                return None
    return None


def _balanceof_calldata(holder: str) -> str:
    h = holder.lower().replace("0x", "")
    return _BALANCEOF_SELECTOR + h.rjust(64, "0")


def _hex_to_int(h: Optional[str]) -> Optional[int]:
    if not isinstance(h, str) or not h.startswith("0x"):
        return None
    try:
        return int(h, 16)
    except ValueError:
        return None


# --- orchestrator ------------------------------------------------------

def verify_candidate(candidate: Dict[str, Any], rpc: RpcLike
                     ) -> Dict[str, Any]:
    """Run the applicable read-only live check and return a verdict dict:
    {verdict, detail, check, candidate_key}. Never raises."""
    key = str(candidate.get("key") or candidate.get("kind") or "")
    out = {"verdict": ERROR, "detail": "", "check": None,
           "candidate_key": key}
    fam = candidate_family(candidate)
    contract = str(candidate.get("contract") or candidate.get("address")
                   or "").strip()
    try:
        if fam == "value":
            out["check"] = "value_at_stake"
            token = str(candidate.get("token") or "").strip()
            if token and contract:
                res, err = rpc.eth_call(
                    token, _balanceof_calldata(contract))
                bal = _hex_to_int(res)
                if bal is None and err:
                    out.update(verdict=ERROR, detail=f"balanceOf failed: {err[:160]}")
                    return out
                v, d = classify_value_at_stake(bal, unit="token units")
                out.update(verdict=v, detail=d)
                return out
            if contract:
                bal, err = rpc.eth_get_balance(contract)
                if bal is None and err:
                    out.update(verdict=ERROR, detail=f"getBalance failed: {err[:160]}")
                    return out
                v, d = classify_value_at_stake(bal, unit="wei")
                out.update(verdict=v, detail=d)
                return out
            out.update(verdict=ERROR, detail="no contract address to read balance")
            return out

        if fam == "access":
            out["check"] = "access_control"
            sel = _function_selector(candidate)
            if not (contract and sel):
                out.update(verdict=ERROR,
                           detail="no contract+selector to probe "
                                  "(candidate carries no selector/signature)")
                return out
            res, err = rpc.eth_call(contract, sel, from_=STRANGER)
            v, d = classify_stranger_call(res, err)
            out.update(verdict=v, detail=d)
            return out

        out.update(verdict=ERROR, detail="no live check applies to this candidate")
        return out
    except Exception as e:  # never let a verifier crash the pass
        out.update(verdict=ERROR, detail=f"verifier exception: {str(e)[:160]}")
        return out


class HttpRpc:
    """Read-only JSON-RPC adapter over a chain's public endpoints.

    Sends only eth_call / eth_getBalance - never a transaction. Tries
    endpoints in order, returns (result, "") or (None, error); never
    raises. Used by the live-mode contract verifier. The `from_` field
    is forwarded so access-control checks can call as a stranger.
    """

    def __init__(self, rpc_urls, timeout: float = 8.0):
        self.rpc_urls = list(rpc_urls or [])
        self.timeout = timeout

    def _post(self, method: str, params: list):
        import httpx
        last = "no endpoint"
        for url in self.rpc_urls:
            try:
                r = httpx.post(url, json={"jsonrpc": "2.0", "id": 1,
                                          "method": method,
                                          "params": params},
                               timeout=self.timeout)
            except Exception as e:
                last = f"{url}: {type(e).__name__}"
                continue
            if r.status_code != 200:
                last = f"{url}: HTTP {r.status_code}"
                continue
            try:
                data = r.json()
            except Exception:
                last = f"{url}: non-JSON"
                continue
            if isinstance(data, dict) and data.get("error"):
                # A revert comes back as an error; surface its message so
                # classify_stranger_call can read the reason.
                return None, str(data["error"].get("message")
                                 or data["error"])[:200]
            if isinstance(data, dict) and "result" in data:
                return data["result"], ""
            last = f"{url}: no result"
        return None, last

    def eth_call(self, to: str, data: str,
                 from_: Optional[str] = None) -> Tuple[Optional[str], str]:
        tx = {"to": to, "data": data}
        if from_:
            tx["from"] = from_
        return self._post("eth_call", [tx, "latest"])

    def eth_get_balance(self, addr: str) -> Tuple[Optional[int], str]:
        res, err = self._post("eth_getBalance", [addr, "latest"])
        return _hex_to_int(res), err


def verify_candidates(candidates: List[Dict[str, Any]], rpc: RpcLike
                      ) -> Dict[str, Any]:
    """Verify many candidates. Returns counts + per-candidate verdicts.
    Auto-closed false positives are separated from what still needs a
    human/fork test, so a live run reports a real number instead of a
    pile of unadjudicated candidates."""
    results = [dict(verify_candidate(c, rpc), index=i)
               for i, c in enumerate(candidates)]
    closed = [r for r in results if r["verdict"] == FALSE_POSITIVE]
    keep = [r for r in results if r["verdict"] == NEEDS_REVIEW]
    errs = [r for r in results if r["verdict"] == ERROR]
    return {
        "total": len(results),
        "auto_closed_false_positive": len(closed),
        "needs_review": len(keep),
        "unverifiable": len(errs),
        "results": results,
        "note": ("Read-only eth_call verification. false_positive = closed "
                 "by a live read (gate holds or nothing at stake); "
                 "needs_review = a real signal a read cannot finish "
                 "proving; a read never stamps VERIFIED_REAL."),
    }
