"""Payout gate: a successful call is not value.

The MVK false positive was structural: ``eth_call`` (or a fork ``send``)
returned success, so the path "worked", but no value moved. The gate
requires the stranger to gain AND the contract to lose the same amount,
per asset, so that class fails at probe time instead of earning a stamp.

Also covers the fork harness wiring: a simulated payout reports
``VALUE_MOVED``; a successful call with unchanged balances reports
``NO_VALUE_MOVED``.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import fork_attack as fa  # noqa: E402

TOKEN = "0x" + "22" * 20
CONTRACT = "0x" + "11" * 20
ONE = 10 ** 18


# --------------------------------------------------------------------------
# the gate
# --------------------------------------------------------------------------

def test_mvk_shape_is_not_value():
    gate = fa.payout_gate(stranger_native=0, contract_native=0,
                          stranger_tokens={TOKEN: 0}, contract_tokens={TOKEN: 0})
    assert gate["value_moved"] is False
    assert gate["native"]["balanced"] is False
    assert "not a finding" in gate["reason"]


def test_balanced_native_payout_counts():
    gate = fa.payout_gate(stranger_native=ONE, contract_native=-ONE)
    assert gate["value_moved"] is True
    assert gate["native"]["balanced"] is True


def test_one_sided_gain_is_not_a_payout():
    gate = fa.payout_gate(stranger_native=ONE, contract_native=0)
    assert gate["value_moved"] is False
    assert "not a payout from this contract" in gate["reason"]


def test_tokens_are_checked_per_asset():
    gate = fa.payout_gate(
        stranger_native=0, contract_native=0,
        stranger_tokens={TOKEN: 500, "0x" + "33" * 20: 0},
        contract_tokens={TOKEN: -500, "0x" + "33" * 20: 0})
    assert gate["value_moved"] is True
    assert gate["tokens"][TOKEN]["balanced"] is True
    assert gate["tokens"]["0x" + "33" * 20]["balanced"] is False


def test_unknown_balances_never_claim_a_payout():
    gate = fa.payout_gate(stranger_native=None, contract_native=-ONE,
                          stranger_tokens={TOKEN: None},
                          contract_tokens={TOKEN: -500})
    assert gate["value_moved"] is False


# --------------------------------------------------------------------------
# harness wiring
# --------------------------------------------------------------------------

class _FakeProc:
    def kill(self):
        pass

    def wait(self, timeout=None):
        return 0


def _fake_harness(monkeypatch, payout_wei):
    """Run a mocked fork; ``payout_wei`` moves on the send, 0 moves nothing."""
    state = {
        "native": {fa.STRANGER: 10 ** 16, CONTRACT: 5 * ONE},
        "token": {(TOKEN, fa.STRANGER): 0, (TOKEN, CONTRACT): 10 * ONE},
        "sent": False,
    }

    def fake_cmd(args, timeout=25):
        if "block-number" in args:
            return "12345678\n", None
        if "anvil_setBalance" in args:
            return "{}\n", None
        if args[1:2] == ["balance"]:
            return f"{state['native'].get(args[-1], 0)}\n", None
        if args[1:2] == ["call"]:
            token, holder = args[-3], args[-1]
            return f"{state['token'].get((token, holder), 0)}\n", None
        if args[1:2] == ["send"]:
            state["sent"] = True
            if payout_wei:
                state["native"][fa.STRANGER] += payout_wei
                state["native"][CONTRACT] -= payout_wei
                state["token"][(TOKEN, fa.STRANGER)] += 5
                state["token"][(TOKEN, CONTRACT)] -= 5
            return (json.dumps({"status": 1, "gasUsed": 0,
                                "effectiveGasPrice": 0,
                                "transactionHash": "0xabc"}) + "\n"), None
        return "", None

    monkeypatch.setattr(fa, "_spawn_anvil", lambda args: _FakeProc())
    monkeypatch.setattr(fa, "_run_cmd", fake_cmd)
    return state


def test_harness_reports_value_moved(monkeypatch):
    _fake_harness(monkeypatch, payout_wei=ONE)
    r = fa.run_fork_attack(
        "bsc", CONTRACT,
        {"function": "mint(address,uint256)",
         "args": ["STRANGER", "MAX"], "tokens": [TOKEN]},
        anvil_bin="/usr/bin/anvil", cast_bin="/usr/bin/cast")
    assert r["status"] == "completed"
    assert r["candidate_status"] == "VALUE_MOVED"
    assert r["payout"]["value_moved"] is True
    assert r["verdict"] == "UNVERIFIED"  # still never proof


def test_harness_rejects_the_mvk_shape(monkeypatch):
    _fake_harness(monkeypatch, payout_wei=0)
    r = fa.run_fork_attack(
        "bsc", CONTRACT,
        {"function": "claimReward()", "args": []},
        anvil_bin="/usr/bin/anvil", cast_bin="/usr/bin/cast")
    assert r["status"] == "completed"
    assert r["candidate_status"] == "NO_VALUE_MOVED"
    assert r["payout"]["value_moved"] is False
    assert "not a finding" in r["payout_note"]
    assert r["verdict"] == "UNVERIFIED"


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    # monkeypatch-style tests need pytest; run them there.
    simple = [f for f in fns if f.__code__.co_argcount == 0]
    for fn in simple:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(simple)}/{len(fns)} payout tests runnable without pytest")


if __name__ == "__main__":
    _run_all()
