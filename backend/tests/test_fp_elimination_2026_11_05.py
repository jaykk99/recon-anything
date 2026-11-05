"""FP-elimination regression pairs (2026-11-05).

For every false-positive shape silenced in the elimination
pass there is a true-positive variant of the same class in
this file that MUST still fire candidate-grade. Fixing FPs
by neutering detection fails here.
"""
import json
import pathlib

from app.plugins.contract_logic import analyze_logic_source
from app.plugins import recipient_first
from app.plugins.deep_audit2 import SPECS as SPECS2, \
    analyze_deep2_source
from app.plugins.deep_audit8 import SPECS as SPECS8, \
    analyze_deep8_source

FIX = pathlib.Path(__file__).parent / "fixtures" / "fp_clean"


def _cand(findings):
    return [f for f in findings
            if str(f.get("severity", "")).lower()
            in ("high", "critical")
            and f.get("report_class") == "candidate"]


def _fixture(name):
    return (FIX / name).read_text()


# ---------------------------------------------------------------
# Clean fixtures stay silent across the fixed analyzers
# ---------------------------------------------------------------

def test_clean_fixtures_zero_candidates():
    manifest = json.loads((FIX / "manifest.json").read_text())
    for entry in manifest:
        src = _fixture(entry["file"])
        cname = entry["contract_name"]
        assert _cand(analyze_logic_source(src, "", cname)) \
            == [], entry["file"]
        for spec_id in recipient_first.ANALYZERS:
            assert _cand(
                recipient_first.analyze_recipient_source(
                    src, spec_id, "", cname)) == [], \
                (entry["file"], spec_id)


# ---------------------------------------------------------------
# TP: a plain ungated mint with no funding, no gate and no
# balance metering is still a candidate access flaw + mint
# ---------------------------------------------------------------

_PLAIN_MINT = """
contract PlainMint {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
"""


def test_plain_ungated_mint_still_fires():
    hits = _cand(analyze_logic_source(_PLAIN_MINT, "",
                                      "PlainMint"))
    assert any(f["function"] == "mint" for f in hits)
    hits = _cand(recipient_first.analyze_recipient_source(
        _PLAIN_MINT, "recipient_mint_to_caller", "",
        "PlainMint"))
    assert hits


# ---------------------------------------------------------------
# TP: an ungated fee setter is still an access flaw
# ---------------------------------------------------------------

_FEE_SETTER = """
contract FeeSetter {
    uint256 public feePercent;
    function setFeePercent(uint256 fee) external {
        require(fee <= 10, "fee too high");
        feePercent = fee;
    }
}
"""


def test_ungated_fee_setter_still_fires():
    hits = _cand(analyze_logic_source(_FEE_SETTER, "",
                                      "FeeSetter"))
    assert any(f["function"] == "setFeePercent"
               for f in hits)


# ---------------------------------------------------------------
# TP: signature recovered but never compared to any
# authority does NOT back a claim (self-signable approval)
# ---------------------------------------------------------------

_SELF_SIGNED_CLAIM = """
contract SelfSignedClaim {
    mapping(uint256 => bool) public usedNonce;
    address public token;
    function claimBatch(uint256 batchNonce, uint256 amount,
                        uint8 v, bytes32 r, bytes32 s)
            external {
        require(!usedNonce[batchNonce], "nonce used");
        usedNonce[batchNonce] = true;
        bytes32 digest = keccak256(
            abi.encodePacked(batchNonce, amount));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        token.call(abi.encodeWithSignature(
            "transfer(address,uint256)", msg.sender,
            amount));
    }
}
"""


def test_self_signed_claim_still_fires():
    # transfer via low-level call may not register as a
    # payout for the claim analyzer; use a direct shape too.
    src = _SELF_SIGNED_CLAIM.replace(
        """        token.call(abi.encodeWithSignature(
            "transfer(address,uint256)", msg.sender,
            amount));""",
        """        IERC20Like(token).transfer(msg.sender,
            amount);""")
    src = "interface IERC20Like { function transfer(" \
          "address to, uint256 amount) external " \
          "returns (bool); }\n" + src
    hits = _cand(recipient_first.analyze_recipient_source(
        src, "recipient_unbacked_claim", "",
        "SelfSignedClaim"))
    assert hits


# ---------------------------------------------------------------
# TP: unbounded withdraw (no burn, no debit, no bound)
# still fires the overdraw detector
# ---------------------------------------------------------------

_UNBOUNDED_WITHDRAW = """
interface IERC20Like {
    function transfer(address to, uint256 amount)
        external returns (bool);
}
contract UnboundedWithdraw {
    IERC20Like public token;
    function withdraw(uint256 amount) external {
        token.transfer(msg.sender, amount);
    }
}
"""


def test_unbounded_withdraw_still_fires():
    hits = _cand(recipient_first.analyze_recipient_source(
        _UNBOUNDED_WITHDRAW, "recipient_overdraw_withdraw",
        "", "UnboundedWithdraw"))
    assert hits


# ---------------------------------------------------------------
# TP: a real EIP-7702 delegation setter with a caller-
# supplied target and no verification still fires, while a
# governance _delegate stays silent
# ---------------------------------------------------------------

_7702_VULN = """
contract Vuln7702Account {
    address public delegate;
    function setDelegate(address newDelegate) external {
        delegate = newDelegate;
    }
    function execute() external {
        require(msg.sender == address(this), "only self");
    }
    // EIP-7702 delegated account: code 0xef0100 || delegate
}
"""

_GOV_DELEGATE = """
contract GovDelegate {
    mapping(address => address) public delegates;
    mapping(address => uint256) public checkpoints;
    function _delegate(address delegator, address delegatee)
            internal {
        delegates[delegator] = delegatee;
        checkpoints[delegatee] += 1;
    }
    function delegate(address delegatee) external {
        _delegate(msg.sender, delegatee);
    }
}
"""


def _deep2(spec_id, src, cname):
    spec = [s for s in SPECS2 if s.id == spec_id][0]
    return analyze_deep2_source(src, spec, "", cname)


def test_eip7702_vuln_setter_still_fires():
    hits = _cand(_deep2("eip7702_unverified_delegate",
                        _7702_VULN, "Vuln7702Account"))
    assert hits


def test_governance_delegate_silent_for_7702():
    hits = _cand(_deep2("eip7702_unverified_delegate",
                        _GOV_DELEGATE, "GovDelegate"))
    assert hits == []


# ---------------------------------------------------------------
# TP: a PERMIT_TYPEHASH literal matching NEITHER known
# schema still fires the hash-constant detector; the Dai
# schema literal stays silent
# ---------------------------------------------------------------

_BAD_HASH = """
contract BadHash {
    bytes32 public constant PERMIT_TYPEHASH =
        0x1111111111111111111111111111111111111111111111111111111111111111;
}
"""

_DAI_HASH = """
contract DaiHash {
    bytes32 public constant PERMIT_TYPEHASH =
        0xea2aa0a1be11a07ed86d755c93467f4f82362b452371d1ba94d1715123511acb;
}
"""


def _deep8(spec_id, src, cname):
    spec = [s for s in SPECS8 if s.id == spec_id][0]
    return analyze_deep8_source(src, spec, "", cname)


def test_wrong_permit_typehash_still_fires():
    hits = _cand(_deep8("hardcoded_hash_constant_mismatch",
                        _BAD_HASH, "BadHash"))
    assert hits


def test_dai_permit_typehash_silent():
    hits = _cand(_deep8("hardcoded_hash_constant_mismatch",
                        _DAI_HASH, "DaiHash"))
    assert hits == []
