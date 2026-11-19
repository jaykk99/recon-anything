"""Detector live-gate precision, round 2 (2026-11-19).

The mint/claim plugins and the CFG detector fired on the static
path without modelling the live gate. Each test below pins one
newly modelled gate with a synthetic source in the real shape
taken from the 63 adjudicated false positives (all
FALSE_POSITIVE live, Nov 18 adjudication) and the 5 remaining
BNB CFG false positives:

- a gated shape must produce NO candidate on the fixed code
  (and must have produced one on the pre-fix code: run this
  file against the baseline backend to prove it fails there);
- the paired ungated control must STILL produce a candidate,
  proving the detector still catches the real shape.

Gated shapes that are silent ([]) vs downgraded to
trigger_only are both asserted as "no candidate"; the
downgrade cases additionally assert a trigger_only row exists.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.plugins.recipient_first import (  # noqa: E402
    analyze_recipient_source)
from app.plugins.deep_audit5 import (  # noqa: E402
    SPECS_BY_ID as D5_SPECS, analyze_deep5_source)
from app.plugins.deep_lowlevel import (  # noqa: E402
    SPECS_BY_ID as LL_SPECS, analyze_deep_lowlevel_source)


def _mint(src, contract="Token"):
    return analyze_recipient_source(
        src, "recipient_mint_to_caller", "", contract)


def _claim(src, contract="Token"):
    return analyze_recipient_source(
        src, "recipient_unbacked_claim", "", contract)


def _erc721(src, contract="Token"):
    return analyze_deep5_source(
        src, D5_SPECS["erc721_mint_without_receiver_check"],
        "", contract)


def _cfg(src, contract="Token"):
    return analyze_deep_lowlevel_source(
        src, LL_SPECS["evm_cfg_basic_block_reconstructor"],
        "", contract)


def _cands(findings):
    return [f for f in findings
            if f.get("report_class") == "candidate"]


def _triggers(findings):
    return [f for f in findings
            if f.get("report_class") == "trigger_only"]


# ---------------------------------------------------------------------------
# 1. Mint-call recognition: revert strings and declarations are not calls
# ---------------------------------------------------------------------------

DISABLED_MINT_SRC = """
contract AtvWrappedBoosterTL {
    function mint(uint256 amount, address to) external {
        revert("mint() is disabled");
    }
}
"""

UNGATED_MINT_SRC = """
contract Token {
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
"""


def test_disabled_mint_revert_string_is_not_a_mint_call():
    # No finding at all: the revert string and the function's
    # own declaration are not mint calls. (On the pre-fix
    # code this returned a trigger_only row.)
    assert _mint(DISABLED_MINT_SRC, "AtvWrappedBoosterTL") == []


def test_ungated_mint_still_fires():
    assert len(_cands(_mint(UNGATED_MINT_SRC))) >= 1


# ---------------------------------------------------------------------------
# 2. Super / parent-call delegation: the gate lives in the parent
# ---------------------------------------------------------------------------

SUPER_GATED_SRC = """
contract ERC20 {
    mapping(address => bool) minters;
    function mint(address to, uint256 amount) public {
        require(minters[msg.sender], "not minter");
        _mint(to, amount);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
contract Child is ERC20 {
    function mint(address to, uint256 amount) public override {
        super.mint(to, amount);
    }
}
"""

SUPER_UNGATED_SRC = """
contract ERC20 {
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
contract Child is ERC20 {
    function mint(address to, uint256 amount) public override {
        super.mint(to, amount);
    }
}
"""


def test_super_delegated_role_gate_silences():
    assert _cands(_mint(SUPER_GATED_SRC, "Child")) == []


def test_super_delegated_ungated_still_fires():
    assert len(_cands(_mint(SUPER_UNGATED_SRC, "Child"))) >= 1


# ---------------------------------------------------------------------------
# 3. Minter-limit / mapping gates on the bound path
# ---------------------------------------------------------------------------

MINTER_LIMIT_SRC = """
contract XERC20 {
    mapping(address => uint256) minterLimits;
    function mint(address to, uint256 amount) external {
        _mintWithCaller(msg.sender, to, amount);
    }
    function _mintWithCaller(address minter, address to,
                             uint256 amount) internal {
        uint256 limit = minterLimits[minter];
        if (limit < amount) revert("limit");
        minterLimits[minter] = limit - amount;
        _mint(to, amount);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
"""


def test_minter_limit_gate_silences():
    assert _cands(_mint(MINTER_LIMIT_SRC, "XERC20")) == []


# ---------------------------------------------------------------------------
# 4. Caller-alias fix: _msgSender() as the payment source
# ---------------------------------------------------------------------------

CALLER_FUNDED_SRC = """
contract DOG8004 {
    address usdt;
    address treasury;
    function mint(uint256 amount) external {
        address user = _msgSender();
        uint256 usdtAmount = amount * 2;
        IERC20(usdt).transferFrom(user, treasury, usdtAmount);
        _mint(user, amount);
    }
    function _msgSender() internal view returns (address) {
        return msg.sender;
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
"""


def test_caller_funded_mint_downgrades_to_trigger_only():
    findings = _mint(CALLER_FUNDED_SRC, "DOG8004")
    assert _cands(findings) == []
    assert len(_triggers(findings)) >= 1


# ---------------------------------------------------------------------------
# 5. Signature / proof gates apply to mint, not only to claim
# ---------------------------------------------------------------------------

SIGNED_MINT_SRC = """
contract FreeMint {
    mapping(address => bool) signers;
    mapping(address => uint256) nonces;
    function mint(bytes calldata signature) external {
        bytes32 h = keccak256(abi.encodePacked(
            msg.sender, nonces[msg.sender]));
        address recovered = ECDSA.recover(h, signature);
        if (!signers[recovered]) revert("bad signer");
        nonces[msg.sender] += 1;
        _mint(msg.sender, 100);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
"""


def test_signature_gate_in_mint_silences():
    assert _cands(_mint(SIGNED_MINT_SRC, "FreeMint")) == []


# ---------------------------------------------------------------------------
# 6. Entitlement-bounded payouts
# ---------------------------------------------------------------------------

XEN_ENTITLEMENT_SRC = """
contract XEN {
    struct MintInfo { uint256 rank; uint256 amount; }
    mapping(address => MintInfo) userMints;
    function claimMintReward() external {
        MintInfo memory mintInfo = userMints[_msgSender()];
        require(mintInfo.rank > 0, "CRank: No mint exists");
        _mint(_msgSender(), mintInfo.amount);
    }
    function _msgSender() internal view returns (address) {
        return msg.sender;
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
"""

HELIOS_HELPER_RETURN_SRC = """
contract HELIOS {
    struct MintRecord { uint256 hRank; uint256 gMintPower; }
    mapping(address => mapping(uint256 => MintRecord)) s_addressMIdToHRankInfo;
    function claimMint(uint256 id) external {
        _mintReward(_claimMint(_msgSender(), id));
    }
    function _mintReward(uint256 reward) private {
        _mint(_msgSender(), reward);
    }
    function _claimMint(address user, uint256 id)
        internal returns (uint256 reward) {
        uint256 hRank = s_addressMIdToHRankInfo[_msgSender()][id].hRank;
        if (hRank == 0) revert("NoMintExists");
        reward = hRank * 100;
    }
    function _msgSender() internal view returns (address) {
        return msg.sender;
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
"""

HEDRON_BOUND_KEY_SRC = """
contract Hedron {
    function mintInstanced(uint256 hsiIndex, address hsiAddress)
        external returns (uint256) {
        address _hsiAddress = _hsim.hsiLists(msg.sender, hsiIndex);
        require(hsiAddress == _hsiAddress, "mismatch");
        ShareCache memory share = _hsiLoad(hsiAddress);
        require(share._stake.lockedDay <= block.timestamp,
                "pending");
        require(share._isLoaned == false, "loaned");
        uint256 payout = share._stake.stakeShares * 10;
        _mint(msg.sender, payout);
        return payout;
    }
    function _hsiLoad(address a) internal view returns (ShareCache memory) {
        return shares[a];
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
    mapping(address => ShareCache) shares;
    address _hsim;
}
"""

HEDRON_HELPER_LOAD_SRC = """
contract Hedron {
    function mintNative(uint256 stakeIndex, uint40 stakeId)
        external returns (uint256) {
        HEXStake memory stake = _hexStakeLoad(stakeIndex);
        require(stake.stakeId == stakeId, "mismatch");
        uint256 payout = stake.stakeShares * 10;
        _mint(msg.sender, payout);
        return payout;
    }
    function _hexStakeLoad(uint256 stakeIndex)
        internal view returns (HEXStake memory) {
        (uint40 id, uint72 shares) =
            _hx.stakeLists(msg.sender, stakeIndex);
        return HEXStake(id, shares);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
    address _hx;
}
"""


def test_xen_record_existence_entitlement_silences():
    # The require(mintInfo.rank > 0) on a caller-keyed record
    # is itself the live gate (record-field guard), so the
    # finding is silent, not merely downgraded.
    assert _mint(XEN_ENTITLEMENT_SRC, "XEN") == []


def test_helios_helper_return_entitlement_silences():
    # The if (hRank == 0) revert on a caller-keyed record
    # inside _claimMint is itself the live gate
    # (record-field guard), so the finding is silent.
    assert _mint(HELIOS_HELPER_RETURN_SRC, "HELIOS") == []


def test_hedron_bound_key_entitlement_downgrades():
    findings = _mint(HEDRON_BOUND_KEY_SRC, "Hedron")
    assert _cands(findings) == []
    assert len(_triggers(findings)) >= 1


def test_hedron_helper_loads_caller_record_downgrades():
    findings = _mint(HEDRON_HELPER_LOAD_SRC, "Hedron")
    assert _cands(findings) == []
    assert len(_triggers(findings)) >= 1


# ---------------------------------------------------------------------------
# 7. Record-field gate (BridgedToken)
# ---------------------------------------------------------------------------

BRIDGED_TOKEN_SRC = """
contract BridgedToken {
    struct Supply { uint256 cap; uint256 total; }
    mapping(address => Supply) bridgeSupply;
    function mint(address _to, uint256 _amount) external {
        address bridge = msg.sender;
        Supply storage b = bridgeSupply[bridge];
        require(b.cap > 0, "invalid caller");
        b.total += _amount;
        require(b.total <= b.cap, "exceeds bridge supply cap");
        _mint(_to, _amount);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
"""


def test_record_field_gate_silences():
    assert _cands(_mint(BRIDGED_TOKEN_SRC, "BridgedToken")) == []


# ---------------------------------------------------------------------------
# 8. Priced mint and PoW gate
# ---------------------------------------------------------------------------

PRICED_MINT_SRC = """
contract Louder {
    uint256 price = 100;
    function mintPresale(uint256 amount) external payable {
        require(msg.value >= price * amount, "pay");
        _mint(msg.sender, amount);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
"""

POW_MINT_SRC = """
contract AutumnToken {
    uint256 _miningTarget = 1000;
    uint256 challengeNumber = 7;
    function mint(uint256 nonce) external {
        bytes32 digest = keccak256(abi.encodePacked(
            challengeNumber, msg.sender, nonce));
        if (uint256(digest) > _miningTarget) revert("pow");
        _mint(msg.sender, 1);
    }
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
    }
    mapping(address => uint256) balances;
}
"""


def test_priced_mint_downgrades_to_trigger_only():
    findings = _mint(PRICED_MINT_SRC, "Louder")
    assert _cands(findings) == []
    assert len(_triggers(findings)) >= 1


def test_pow_gate_silences():
    assert _cands(_mint(POW_MINT_SRC, "AutumnToken")) == []


# ---------------------------------------------------------------------------
# 9. Claim: storage-pointer record debit (Taopad)
# ---------------------------------------------------------------------------

TAOPAD_CLAIM_SRC = """
contract Taopad {
    struct Share { uint256 earned; }
    mapping(address => Share) shareholders;
    function claim() external {
        Share storage share = shareholders[msg.sender];
        uint256 amount = share.earned;
        share.earned = 0;
        token.transfer(msg.sender, amount);
    }
    address token;
}
"""

UNGATED_CLAIM_SRC = """
contract Token {
    function claim() external {
        token.transfer(msg.sender, 100);
    }
    address token;
}
"""


def test_claim_record_debit_silences():
    assert _cands(_claim(TAOPAD_CLAIM_SRC, "Taopad")) == []


def test_ungated_claim_still_fires():
    assert len(_cands(_claim(UNGATED_CLAIM_SRC))) >= 1


# ---------------------------------------------------------------------------
# 10. ERC721 mint: the gate check applies here too
# ---------------------------------------------------------------------------

ERC721_GATED_SRC = """
contract Louder is ERC721 {
    function mintTo(address to, uint256 amount)
        external onlyAdmin {
        _mint(to, amount);
    }
    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }
    address admin;
    function _mint(address to, uint256 amount) internal {
    }
}
"""

ERC721_UNGATED_SRC = """
contract Token is ERC721 {
    function mintTo(address to, uint256 amount) external {
        _mint(to, amount);
    }
    function _mint(address to, uint256 amount) internal {
    }
}
"""


def test_erc721_only_admin_silences():
    assert _erc721(ERC721_GATED_SRC, "Louder") == []


def test_erc721_ungated_still_fires():
    assert len(_erc721(ERC721_UNGATED_SRC)) >= 1


# ---------------------------------------------------------------------------
# 12. Tightening pins (2026-11-19 evening): these genuine shapes
# must STILL fire after the round-2 rules - the first full-suite
# run caught four over-silencings, fixed the same day.
# ---------------------------------------------------------------------------

DIRECT_WRITE_MINT_SRC = """
contract VulnMint {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

SELF_SIGNED_CLAIM_SRC = """
interface IERC20Like {
    function transfer(address to, uint256 amount)
        external returns (bool);
}
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
        IERC20Like(token).transfer(msg.sender, amount);
    }
}
"""

DOUBLE_CLAIM_SRC = """
contract DoubleClaim {
    mapping(address => uint256) public entitlement;
    function claim() public {
        uint256 amt = entitlement[msg.sender];
        require(amt > 0, "nothing");
        payable(msg.sender).transfer(amt);
    }
}
"""

CFG_DEBIT_TO_ARBITRARY_SRC = """
contract VaultVuln {
    address public owner;
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount, address to) external {
        balances[msg.sender] -= amount;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "call failed");
    }
}
"""

CFG_DEBIT_BACK_TO_CALLER_SRC = """
contract WBNB {
    mapping(address => uint256) public balances;
    function withdraw(uint256 wad) external {
        balances[msg.sender] -= wad;
        (bool success, ) = msg.sender.call{value: wad}("");
        require(success, "call failed");
    }
}
"""


def test_direct_write_mint_still_fires():
    assert len(_cands(_mint(DIRECT_WRITE_MINT_SRC,
                            "VulnMint"))) >= 1


def test_self_signed_claim_still_fires():
    # ecrecover + require(signer != address(0)) authorizes
    # nothing: anyone can sign their own claim.
    assert len(_cands(_claim(SELF_SIGNED_CLAIM_SRC,
                             "SelfSignedClaim"))) >= 1


def test_double_claim_still_fires():
    # Entitlement read with no debit: repeatable claim.
    assert len(_cands(_claim(DOUBLE_CLAIM_SRC,
                             "DoubleClaim"))) >= 1


def test_cfg_debit_to_arbitrary_address_still_fires():
    assert len(_cfg(CFG_DEBIT_TO_ARBITRARY_SRC,
                    "VaultVuln")) >= 1


def test_cfg_debit_back_to_caller_is_not_a_candidate():
    assert _cfg(CFG_DEBIT_BACK_TO_CALLER_SRC, "WBNB") == []


# ---------------------------------------------------------------------------
# 11. CFG: self-delegatecall, local declarations, caller-funded
#     value, and the TokenHub record guard
# ---------------------------------------------------------------------------

CFG_SELF_DELEGATECALL_SRC = """
contract SmartRouter {
    function multicall(bytes[] calldata data) external {
        for (uint i = 0; i < data.length; i++) {
            (bool ok,) = address(this).delegatecall(data[i]);
            require(ok);
        }
    }
}
"""

CFG_LOCAL_DECL_SRC = """
contract NFPM {
    function approve(address to, uint256 tokenId) external {
        address owner = ownerOf(tokenId);
        require(msg.sender == owner, "not owner");
        approvals[tokenId] = to;
    }
    function ownerOf(uint256 tokenId) internal view returns (address) {
        return owners[tokenId];
    }
    mapping(uint256 => address) owners;
    mapping(uint256 => address) approvals;
}
"""

CFG_CALLER_FUNDED_SRC = """
contract Router {
    address weth;
    function addLiquidityETH(address to) external payable {
        IWETH(weth).deposit{value: msg.value}();
        IWETH(weth).transfer(to, msg.value);
    }
}
"""

CFG_TOKENHUB_SRC = """
contract TokenHub {
    struct LockInfo { uint256 amount; uint256 unlockAt; }
    mapping(address => mapping(address => LockInfo)) public lockInfoMap;
    uint256 constant MAX_GAS_FOR_TRANSFER_BNB = 2300;
    function withdrawUnlockedToken(address tokenAddress,
                                   address recipient) external {
        LockInfo storage lockInfo = lockInfoMap[tokenAddress][recipient];
        require(lockInfo.amount > 0, "no locked amount");
        require(block.timestamp >= lockInfo.unlockAt, "still locked");
        uint256 _amount = lockInfo.amount;
        lockInfo.amount = 0;
        (bool _success,) = recipient.call{
            gas: MAX_GAS_FOR_TRANSFER_BNB, value: _amount }("");
        require(_success, "withdraw failed");
    }
}
"""

CFG_UNGATED_CALL_SRC = """
contract Vault {
    function drain(address to, uint256 amount) external {
        (bool ok,) = to.call{value: amount}("");
        require(ok, "fail");
    }
}
"""


def test_cfg_self_delegatecall_is_not_a_candidate():
    assert _cfg(CFG_SELF_DELEGATECALL_SRC, "SmartRouter") == []


def test_cfg_local_owner_declaration_is_not_a_state_write():
    assert _cfg(CFG_LOCAL_DECL_SRC, "NFPM") == []


def test_cfg_caller_funded_call_is_not_a_candidate():
    assert _cfg(CFG_CALLER_FUNDED_SRC, "Router") == []


def test_cfg_tokenhub_record_guard_is_not_a_candidate():
    assert _cfg(CFG_TOKENHUB_SRC, "TokenHub") == []


def test_cfg_ungated_call_still_fires():
    assert len(_cfg(CFG_UNGATED_CALL_SRC, "Vault")) >= 1
