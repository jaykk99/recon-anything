"""Fixtures for the recipient-first detector family.

Per detector: VULN (candidate-grade hit must fire), CLEAN (must
stay silent - no candidate AND no trigger-only item), and FIXED /
HOLDER variants (must come out trigger-only at most, never a
candidate).
"""

# ---------------------------------------------------------------------------
# 1. recipient_mint_to_caller
# ---------------------------------------------------------------------------

_MINT_VULN = """
contract VulnMint {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function mint(uint256 amount) public {
        totalSupply += amount;
        _mint(msg.sender, amount);
    }
    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }
}
"""

_MINT_CLEAN = """
contract CleanMint {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
    function mint(uint256 amount) public onlyOwner {
        totalSupply += amount;
        _mint(msg.sender, amount);
    }
    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }
}
"""

_MINT_FIXED = """
contract FixedMint {
    address public treasury;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function mint(uint256 amount) public {
        totalSupply += amount;
        _mint(treasury, amount);
    }
    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }
}
"""

# ---------------------------------------------------------------------------
# 2. recipient_unbacked_claim
# ---------------------------------------------------------------------------

_CLAIM_VULN = """
contract VulnFaucet {
    function claim() public {
        payable(msg.sender).transfer(1 ether);
    }
    function getReward() public {
        payable(msg.sender).transfer(0.1 ether);
    }
}
"""

_CLAIM_DOUBLE = """
contract DoubleClaim {
    mapping(address => uint256) public entitlement;
    function claim() public {
        uint256 amt = entitlement[msg.sender];
        require(amt > 0, "nothing");
        payable(msg.sender).transfer(amt);
    }
}
"""

_CLAIM_CLEAN = """
contract CleanClaim {
    mapping(address => uint256) public entitlement;
    function claim() public {
        uint256 amt = entitlement[msg.sender];
        require(amt > 0, "nothing");
        entitlement[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. recipient_overdraw_withdraw
# ---------------------------------------------------------------------------

_OVERDRAW_VULN = """
contract VulnVault {
    function withdraw(uint256 amount) public {
        require(address(this).balance >= amount, "insolvent");
        payable(msg.sender).transfer(amount);
    }
}
"""

_OVERDRAW_CLEAN = """
contract CleanVault {
    mapping(address => uint256) public deposits;
    function withdraw(uint256 amount) public {
        require(deposits[msg.sender] >= amount, "too much");
        deposits[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

# WETH9 shape: holder-self unwrap. Must stay silent (the caller's
# own balance is required AND debited by exactly the amount).
_OVERDRAW_HOLDER = """
contract WrappedNative {
    mapping(address => uint256) public balanceOf;
    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad, "insufficient");
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).transfer(wad);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. recipient_rescue_to_param
# ---------------------------------------------------------------------------

_RESCUE_VULN = """
contract VulnRescue {
    function rescueTokens(address token, address to) public {
        IERC20(token).transfer(to, IERC20(token).balanceOf(address(this)));
    }
    function rescueETH(address payable to) public {
        to.transfer(address(this).balance);
    }
}
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""

# The Nov 2 shape: ungated, probe-proven, but the destination is a
# hardcoded project wallet. Trigger-only, never a candidate.
_RESCUE_FIXED = """
contract FixedRescue {
    address public marketingAddress;
    function withdrawStuckBNB() public {
        payable(marketingAddress).transfer(address(this).balance);
    }
    function rescueBNB() public {
        payable(marketingAddress).transfer(address(this).balance);
    }
}
"""

_RESCUE_CLEAN = """
contract CleanRescue {
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
    function rescueTokens(address token, address to) public onlyOwner {
        IERC20(token).transfer(to, IERC20(token).balanceOf(address(this)));
    }
}
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}
"""

# ---------------------------------------------------------------------------
# 5. recipient_bridge_release_unproven
# ---------------------------------------------------------------------------

_BRIDGE_VULN = """
contract BridgeEscrow {
    address public bridge;
    mapping(bytes32 => bool) public processedMessages;
    function unlock(address payable to, uint256 amount) public {
        to.transfer(amount);
    }
}
"""

_BRIDGE_CLEAN = """
contract BridgeEscrowClean {
    mapping(bytes32 => bool) public processed;
    function unlock(bytes32 id, address payable to, uint256 amount, bytes memory proof) public {
        require(verifyProof(id, proof), "bad proof");
        processed[id] = true;
        to.transfer(amount);
    }
    function verifyProof(bytes32 id, bytes memory proof) internal pure returns (bool) {
        return proof.length > 0;
    }
}
"""

# ---------------------------------------------------------------------------
# 6. recipient_sig_value_to_self
# ---------------------------------------------------------------------------

_SIG_VULN_NOCMP = """
contract SigClaimNoCheck {
    function claimWithSignature(uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        address recovered = ecrecover(keccak256(abi.encodePacked(amount)), v, r, s);
        recovered;
        payable(msg.sender).transfer(amount);
    }
}
"""

_SIG_VULN_SUPPLIED = """
contract SigWithdrawSupplied {
    function withdrawSigned(address signer, uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        address recovered = ecrecover(keccak256(abi.encodePacked(amount)), v, r, s);
        require(recovered == signer, "bad sig");
        payable(msg.sender).transfer(amount);
    }
}
"""

_SIG_CLEAN = """
contract SigClaimClean {
    address public owner;
    function claimSigned(uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        address recovered = ECDSA.recover(keccak256(abi.encodePacked(amount)), v, r, s);
        require(recovered != address(0), "bad sig");
        require(recovered == owner, "not owner");
        payable(msg.sender).transfer(amount);
    }
}
library ECDSA {
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return address(0);
    }
}
"""

VULN = {
    "recipient_mint_to_caller": _MINT_VULN,
    "recipient_unbacked_claim": _CLAIM_VULN,
    "recipient_overdraw_withdraw": _OVERDRAW_VULN,
    "recipient_rescue_to_param": _RESCUE_VULN,
    "recipient_bridge_release_unproven": _BRIDGE_VULN,
    "recipient_sig_value_to_self": _SIG_VULN_NOCMP,
}

VULN_ALT = {
    "recipient_unbacked_claim": _CLAIM_DOUBLE,
    "recipient_sig_value_to_self": _SIG_VULN_SUPPLIED,
}

CLEAN = {
    "recipient_mint_to_caller": _MINT_CLEAN,
    "recipient_unbacked_claim": _CLAIM_CLEAN,
    "recipient_overdraw_withdraw": _OVERDRAW_CLEAN,
    "recipient_rescue_to_param": _RESCUE_CLEAN,
    "recipient_bridge_release_unproven": _BRIDGE_CLEAN,
    "recipient_sig_value_to_self": _SIG_CLEAN,
}

TRIGGER_ONLY = {
    "recipient_mint_to_caller": _MINT_FIXED,
    "recipient_overdraw_withdraw": _OVERDRAW_HOLDER,
    "recipient_rescue_to_param": _RESCUE_FIXED,
}
