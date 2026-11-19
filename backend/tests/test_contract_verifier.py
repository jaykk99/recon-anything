"""contract_verifier: read-only eth_call verdicts over a fake RPC.

The decision core is pure, so these tests use a scripted RPC and need no
network. They cover the exact candidate shapes the two scan reports
closed by hand (stranger-call reverts, zero balance at stake) plus the
keep/error paths.
"""
from app.contract_verifier import (
    classify_stranger_call, classify_value_at_stake, candidate_family,
    verify_candidate, verify_candidates,
    FALSE_POSITIVE, NEEDS_REVIEW, ERROR, STRANGER)


class FakeRpc:
    def __init__(self, call=None, balance=None):
        self._call = call or (lambda to, data, from_=None: (None, ""))
        self._balance = balance or (lambda addr: (0, ""))
        self.calls = []

    def eth_call(self, to, data, from_=None):
        self.calls.append((to, data, from_))
        return self._call(to, data, from_)

    def eth_get_balance(self, addr):
        return self._balance(addr)


# --- pure core ---------------------------------------------------------

def test_stranger_revert_on_gate_is_false_positive():
    v, d = classify_stranger_call(None, "execution reverted: only current validators")
    assert v == FALSE_POSITIVE and "gate" in d.lower()


def test_stranger_revert_forbidden_is_false_positive():
    v, _ = classify_stranger_call(None, "execution reverted: Pancake: FORBIDDEN")
    assert v == FALSE_POSITIVE


def test_stranger_revert_not_owner_is_false_positive():
    v, _ = classify_stranger_call(None, "revert Not owner")
    assert v == FALSE_POSITIVE


def test_stranger_generic_revert_is_needs_review():
    v, _ = classify_stranger_call(None, "execution reverted: INSUFFICIENT_LIQUIDITY_BURNED")
    assert v == NEEDS_REVIEW


def test_stranger_success_is_needs_review():
    v, d = classify_stranger_call("0x0000000000000000000000000000000000000000000000000000000000000001", "")
    assert v == NEEDS_REVIEW and "did not revert" in d.lower()


def test_stranger_rpc_down_is_error():
    v, _ = classify_stranger_call(None, "bsc-dataseed: HTTP 503")
    assert v == ERROR


def test_zero_balance_is_false_positive():
    v, d = classify_value_at_stake(0, "wei")
    assert v == FALSE_POSITIVE and "nothing to drain" in d.lower()


def test_nonzero_balance_is_needs_review():
    v, _ = classify_value_at_stake(25966 * 10**18, "wei")
    assert v == NEEDS_REVIEW


def test_balance_none_is_error():
    v, _ = classify_value_at_stake(None)
    assert v == ERROR


# --- family routing -----------------------------------------------------

def test_family_value_beats_access_for_sweep():
    assert candidate_family({"key": "rescue", "value": "sweepToken caller-supplied recipient"}) == "value"


def test_family_access_for_setowner():
    assert candidate_family({"key": "z3_taint", "value": "setOwner unguarded"}) == "access"


def test_family_none_for_unrelated():
    assert candidate_family({"key": "eof_container", "value": "bad magic"}) is None


# --- orchestrator (the report's real candidates) ------------------------

def test_sweep_zero_balance_autocloses():
    # SmartRouter sweepToken: router holds 0 WBNB (report items 16-19,26,29)
    rpc = FakeRpc(call=lambda to, data, from_=None: ("0x" + "0"*64, ""))
    cand = {"key": "rescue", "value": "sweepToken WBNB",
            "contract": "0x13f4", "token": "0xbb4CdB"}
    r = verify_candidate(cand, rpc)
    assert r["verdict"] == FALSE_POSITIVE and r["check"] == "value_at_stake"


def test_sweep_native_zero_balance_autocloses():
    rpc = FakeRpc(balance=lambda addr: (0, ""))
    cand = {"key": "sweep", "value": "sweep native", "contract": "0x10ED"}
    r = verify_candidate(cand, rpc)
    assert r["verdict"] == FALSE_POSITIVE


def test_access_control_stranger_revert_autocloses():
    # ValidatorSet exitMaintenance: stranger -> "only current validators"
    rpc = FakeRpc(call=lambda to, data, from_=None: (None, "execution reverted: only current validators"))
    cand = {"key": "cross_function_guard", "value": "_exitMaintenance",
            "contract": "0x0000000000000000000000000000000000001000",
            "selector": "0xb7ab4db5"}
    r = verify_candidate(cand, rpc)
    assert r["verdict"] == FALSE_POSITIVE and r["check"] == "access_control"
    # proves the stranger `from` was actually used
    assert rpc.calls and rpc.calls[-1][2] == STRANGER


def test_access_control_no_selector_is_error():
    rpc = FakeRpc()
    cand = {"key": "access_control_flaw", "value": "setOwner",
            "contract": "0xabc"}  # no selector/signature
    r = verify_candidate(cand, rpc)
    assert r["verdict"] == ERROR and "selector" in r["detail"].lower()


def test_access_control_from_signature_hashes_selector():
    seen = {}
    def call(to, data, from_=None):
        seen["data"] = data
        return (None, "revert Not owner")
    rpc = FakeRpc(call=call)
    cand = {"key": "access_control_flaw", "value": "setOwner",
            "contract": "0xabc", "signature": "setOwner(address)"}
    r = verify_candidate(cand, rpc)
    # setOwner(address) selector is 0x13af4035
    assert r["verdict"] == FALSE_POSITIVE
    assert seen.get("data", "").startswith("0x13af4035")


def test_nonzero_value_needs_review_not_closed():
    rpc = FakeRpc(balance=lambda addr: (5 * 10**18, ""))
    cand = {"key": "overdraw_withdraw", "value": "withdraw", "contract": "0x1004"}
    r = verify_candidate(cand, rpc)
    assert r["verdict"] == NEEDS_REVIEW


def test_verify_candidates_counts():
    rpc = FakeRpc(call=lambda to, data, from_=None: ("0x" + "0"*64, ""),
                  balance=lambda addr: (0, ""))
    cands = [
        {"key": "sweep", "value": "sweepToken", "contract": "0xa", "token": "0xb"},
        {"key": "rescue", "value": "sweep native", "contract": "0xc"},
        {"key": "eof_container", "value": "bad magic"},  # no live check
    ]
    summary = verify_candidates(cands, rpc)
    assert summary["total"] == 3
    assert summary["auto_closed_false_positive"] == 2
    assert summary["unverifiable"] == 1


def test_verifier_never_raises_on_bad_rpc():
    class Boom:
        def eth_call(self, *a, **k): raise RuntimeError("boom")
        def eth_get_balance(self, *a, **k): raise RuntimeError("boom")
    r = verify_candidate({"key": "sweep", "contract": "0xa"}, Boom())
    assert r["verdict"] == ERROR


# --- HttpRpc plumbing (no network: httpx.post monkeypatched) ------------

def test_httprpc_eth_call_parses_result(monkeypatch):
    import httpx
    from app.contract_verifier import HttpRpc

    class Resp:
        status_code = 200
        def json(self): return {"jsonrpc": "2.0", "id": 1, "result": "0x2a"}

    sent = {}
    def fake_post(url, json=None, timeout=None):
        sent["url"] = url; sent["body"] = json
        return Resp()
    monkeypatch.setattr(httpx, "post", fake_post)

    rpc = HttpRpc(["https://rpc.example"])
    res, err = rpc.eth_call("0xto", "0xdata", from_=STRANGER)
    assert res == "0x2a" and err == ""
    assert sent["body"]["method"] == "eth_call"
    assert sent["body"]["params"][0]["from"] == STRANGER


def test_httprpc_revert_surfaces_message(monkeypatch):
    import httpx
    from app.contract_verifier import HttpRpc

    class Resp:
        status_code = 200
        def json(self):
            return {"error": {"code": 3, "message": "execution reverted: only owner"}}

    monkeypatch.setattr(httpx, "post", lambda url, json=None, timeout=None: Resp())
    rpc = HttpRpc(["https://rpc.example"])
    res, err = rpc.eth_call("0xto", "0xdata", from_=STRANGER)
    assert res is None and "only owner" in err
    # and the decision core closes it
    v, _ = classify_stranger_call(res, err)
    assert v == FALSE_POSITIVE


def test_httprpc_balance_to_int(monkeypatch):
    import httpx
    from app.contract_verifier import HttpRpc

    class Resp:
        status_code = 200
        def json(self): return {"result": "0x0"}

    monkeypatch.setattr(httpx, "post", lambda url, json=None, timeout=None: Resp())
    rpc = HttpRpc(["https://rpc.example"])
    bal, err = rpc.eth_get_balance("0xcontract")
    assert bal == 0 and err == ""


def test_httprpc_all_endpoints_fail_returns_error(monkeypatch):
    import httpx
    from app.contract_verifier import HttpRpc

    def boom(url, json=None, timeout=None): raise RuntimeError("conn refused")
    monkeypatch.setattr(httpx, "post", boom)
    rpc = HttpRpc(["https://a", "https://b"])
    res, err = rpc.eth_call("0xto", "0xdata")
    assert res is None and err
