"""Validator V2 (lane L2): source recipient classifier extensions.

Each shape stalled in the backlog as recipient_unclassified
(validator missing=["recipient destination"]):

(a) struct / array-element destinations resolved through the
    BASE expression;
(b) ternary destinations combining both branches;
(c) nested casts (address(uint160(x)));
(d) value-out external calls: ERC4626 withdraw/redeem and a
    conservative named-recipient method set;
(e) ledger credits enabled by a mint-named HELPER (or a supply
    increase) anywhere on the bound call path, not only by the
    entry signature.

Every vuln shape resolves CALLER / CALLER-SUPPLIED; the clean
twin of the same shape resolves FIXED / HOLDER-SELF or stays
gated. The beneficiary-metered (FLY) protection must stay
ahead of the new CALLER-SUPPLIED shapes.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.plugins import contract_logic as cl  # noqa: E402
from app.plugins.auto_validator import validate_candidate  # noqa: E402

cr = cl.classify_recipient
PROBE_OK = {"status": "success", "via": "test", "detail": ""}
BAL = {"native_wei": 10 ** 18,
       "observed_at": "2026-11-06T00:00:00Z", "source": "test"}


def _path_recipient(src, contract, fn_name):
    scope = cl._Scope(src, contract)
    fn = [f for f in scope.functions if f["name"] == fn_name][0]
    return cl.classify_recipient_path(scope, fn)[0]


# ---------------------------------------------------------------------------
# (a) struct / array-element destinations
# ---------------------------------------------------------------------------

def test_array_element_of_param_array_is_caller_supplied():
    assert cr("function f(address[] memory payees, uint256 i, "
              "uint256 a) public { payable(payees[i]).transfer(a); }"
              )[0] == "CALLER-SUPPLIED"


def test_struct_member_of_param_is_caller_supplied():
    assert cr("function f(Info memory info, uint256 a) public { "
              "token.transfer(info.addr, a); }"
              )[0] == "CALLER-SUPPLIED"


def test_struct_member_of_state_mapping_is_fixed():
    # info[to].addr: the address is read out of storage.
    assert cr("function f(address to, uint256 a) public { "
              "token.transfer(info[to].addr, a); }"
              )[0] == "FIXED"


def test_stored_wallet_keyed_by_sender_is_fixed():
    assert cr("function f(uint256 a) public { "
              "payable(users[msg.sender].wallet).transfer(a); }"
              )[0] == "FIXED"


def test_local_recurses_into_member_definition():
    assert cr("function f(address[] memory payees, uint256 i, "
              "uint256 a) public { address dst = payees[i]; "
              "payable(dst).transfer(a); }")[0] == "CALLER-SUPPLIED"
    assert cr("function f(address to, uint256 a) public { "
              "address dst = wallets[to]; payable(dst).transfer(a); }"
              )[0] == "FIXED"


def test_sender_derived_local_is_caller():
    assert cr("function f(uint256 a) public { address me = msg.sender; "
              "payable(me).transfer(a); }")[0] == "CALLER"


# ---------------------------------------------------------------------------
# (b) ternary destinations
# ---------------------------------------------------------------------------

def test_ternary_with_param_branch_is_caller_supplied():
    assert cr("function f(address to, bool alt, uint256 a) public { "
              "token.transfer(alt ? to : treasury, a); }"
              )[0] == "CALLER-SUPPLIED"


def test_ternary_with_sender_branch_is_caller():
    assert cr("function f(bool alt, uint256 a) public { "
              "token.transfer(alt ? msg.sender : treasury, a); }"
              )[0] == "CALLER"


def test_ternary_both_fixed_is_fixed():
    assert cr("function f(bool alt, uint256 a) public { "
              "token.transfer(alt ? treasury : owner(), a); }"
              )[0] == "FIXED"


# ---------------------------------------------------------------------------
# (c) casts
# ---------------------------------------------------------------------------

def test_nested_cast_of_param_is_caller_supplied():
    assert cr("function f(address to, uint256 a) public { "
              "token.transfer(address(uint160(to)), a); }"
              )[0] == "CALLER-SUPPLIED"


def test_nested_cast_of_state_address_is_fixed():
    assert cr("function f(uint256 a) public { "
              "token.transfer(address(uint160(treasury)), a); }"
              )[0] == "FIXED"


# ---------------------------------------------------------------------------
# (d) value-out external calls
# ---------------------------------------------------------------------------

def test_erc4626_withdraw_receiver_is_args_1():
    assert cr("function f(uint256 assets, address receiver, "
              "address owner) public { "
              "vault.withdraw(assets, receiver, owner); }"
              )[0] == "CALLER-SUPPLIED"


def test_erc4626_redeem_to_sender_is_caller():
    assert cr("function f(uint256 shares, address owner) public { "
              "vault.redeem(shares, msg.sender, owner); }"
              )[0] == "CALLER"


def test_erc4626_short_arity_is_not_guessed():
    assert cr("function f(uint256 assets, address receiver) public { "
              "vault.withdraw(assets, receiver); }"
              )[0] == "UNRESOLVED"


def test_named_method_param_recipient():
    assert cr("function f(address to, uint256 a) public { "
              "pool.payoutTo(to, a); }")[0] == "CALLER-SUPPLIED"


def test_named_method_sender_recipient():
    assert cr("function f(uint256 a) public { "
              "staking.unstakeTo(a, msg.sender); }")[0] == "CALLER"


def test_named_method_stored_member_recipient_is_fixed():
    assert cr("function f(uint256 a) public { "
              "pool.payoutTo(config.treasury, a); }")[0] == "FIXED"


def test_named_method_ambiguous_two_address_params_not_guessed():
    assert cr("function f(address token, address user, uint256 a) "
              "public { pool.claimFor(token, user); }"
              )[0] == "UNRESOLVED"


def test_unknown_method_recipient_not_guessed():
    assert cr("function f(address to, uint256 a) public { "
              "pool.fooBar(to, a); }")[0] == "UNRESOLVED"


# ---------------------------------------------------------------------------
# (e) ledger credits on the bound path
# ---------------------------------------------------------------------------

MINT_HELPER = """
contract PathMint {
    mapping(address => uint256) public balanceOf;
    function claim(uint256 amt) public { _mintTo(msg.sender, amt); }
    function _mintTo(address to, uint256 amt) internal {
        balanceOf[to] += amt;
    }
}
"""

MINT_HELPER_FIXED = """
contract PathMintFixed {
    address public treasury;
    mapping(address => uint256) public balanceOf;
    function claim(uint256 amt) public { _mintTo(treasury, amt); }
    function _mintTo(address to, uint256 amt) internal {
        balanceOf[to] += amt;
    }
}
"""


def test_mint_named_helper_enables_ledger_credit():
    # No totalSupply increase anywhere: the OLD gate looked only
    # at the entry signature ("claim") and missed the credit.
    assert _path_recipient(MINT_HELPER, "PathMint", "claim") == "CALLER"


def test_mint_named_helper_fixed_destination():
    assert _path_recipient(MINT_HELPER_FIXED, "PathMintFixed",
                           "claim") == "FIXED"


# ---------------------------------------------------------------------------
# Validator level: stalled shapes now reach terminal verdicts
# ---------------------------------------------------------------------------

def test_validator_array_element_payout_verifies():
    src = """
contract Payees {
    function payout(address[] memory payees, uint256 i, uint256 a)
        public { payable(payees[i]).transfer(a); }
    receive() external payable {}
}
"""
    v = validate_candidate({
        "address": "0xabc", "chain": "ethereum",
        "function": "payout", "kind": "unprotected_drain",
        "source": src, "contract_name": "Payees",
        "probe": PROBE_OK, "balances": BAL})
    assert v["verdict"] == "VERIFIED_REAL"
    assert v["recipient"] == "CALLER-SUPPLIED"


def test_validator_stored_wallet_is_trigger_only():
    src = """
contract Stored {
    function withdraw(uint256 a) public {
        payable(users[msg.sender].wallet).transfer(a);
    }
    receive() external payable {}
}
"""
    v = validate_candidate({
        "address": "0xabc", "chain": "ethereum",
        "function": "withdraw", "kind": "unprotected_drain",
        "source": src, "contract_name": "Stored",
        "probe": PROBE_OK, "balances": BAL})
    assert v["verdict"] == "TRIGGER_ONLY"
    assert v["recipient"] == "FIXED"


def test_validator_ternary_fixed_is_trigger_only():
    src = """
contract Tern {
    address public treasury;
    function sweep(bool alt, uint256 a) public {
        token.transfer(alt ? treasury : owner(), a);
    }
    function owner() public view returns (address) {
        return treasury;
    }
}
"""
    v = validate_candidate({
        "address": "0xabc", "chain": "ethereum",
        "function": "sweep", "kind": "unprotected_drain",
        "source": src, "contract_name": "Tern",
        "probe": PROBE_OK, "balances": BAL})
    assert v["verdict"] == "TRIGGER_ONLY"
    assert v["recipient"] == "FIXED"


def test_validator_erc4626_exit_reaches_terminal():
    src = """
contract Exit {
    function exit(uint256 assets, address receiver, address owner)
        public { vault.withdraw(assets, receiver, owner); }
}
"""
    v = validate_candidate({
        "address": "0xabc", "chain": "ethereum",
        "function": "exit", "kind": "unprotected_drain",
        "source": src, "contract_name": "Exit",
        "probe": PROBE_OK, "balances": BAL})
    assert v["recipient"] == "CALLER-SUPPLIED"
    assert v["verdict"] == "VERIFIED_REAL"


def test_validator_mint_helper_path_verifies_with_pair_reserves():
    # Canonical _mint helper name: the validator's mint-value
    # gate keys on the _mint( shape in the bound path text.
    src = MINT_HELPER.replace("_mintTo", "_mint")
    v = validate_candidate({
        "address": "0xabc", "chain": "ethereum",
        "function": "claim", "kind": "unprotected_mint",
        "source": src, "contract_name": "PathMint",
        "probe": PROBE_OK,
        "balances": {"native_wei": 0,
                     "token_pair_reserves": {
                         "reserve0": 10 ** 20,
                         "reserve1": 10 ** 18}}})
    assert v["recipient"] == "CALLER"
    assert v["verdict"] == "VERIFIED_REAL"


def test_beneficiary_metered_stays_ahead_of_ternary_shape():
    # FLY discipline: a caller-supplied destination whose payout
    # is metered by the beneficiary's OWN consumed entitlement
    # is HOLDER-SELF, even through the new ternary classifier.
    src = """
contract Metered {
    mapping(address => uint256) public locked;
    function release(address to, bool alt) public {
        uint256 amt = locked[to];
        locked[to] = 0;
        payable(alt ? to : to).transfer(amt);
    }
    receive() external payable {}
}
"""
    v = validate_candidate({
        "address": "0xabc", "chain": "ethereum",
        "function": "release", "kind": "unprotected_drain",
        "source": src, "contract_name": "Metered",
        "probe": PROBE_OK, "balances": BAL})
    assert v["verdict"] == "TRIGGER_ONLY"
    assert v["recipient"] == "HOLDER-SELF"
    assert v["evidence"].get("beneficiary_metered") == "locked"
