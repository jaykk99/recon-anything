"""Fixtures for the deep-audit batch-4 detectors (scaffold port).

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; VARIANT[id]
carries the same vulnerable shape but the recipient is FIXED,
so it MUST fire with report_class "trigger_only" at low
severity - never a candidate; CLEAN[id] (the protected shape
of the same class) MUST stay silent under ALL three detectors;
every other plugin's vulnerable fixture MUST stay silent
under this one (no cross-talk).
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. bridge_proof_length_unvalidated
# ---------------------------------------------------------------------------

_PROOF_LEN_VULN = _TOKEN_IFACE + """
contract BridgeClaimVuln {
    IERC20Like public token;
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public processed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function verifyProof(bytes32[] memory proof, bytes32 leaf) internal view returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = keccak256(abi.encodePacked(computed, proof[i]));
        }
        return computed == merkleRoot;
    }

    function claim(bytes32[] memory proof, bytes32 leaf, uint256 amount) public {
        require(verifyProof(proof, leaf), "bad proof");
        require(!processed[leaf], "already claimed");
        processed[leaf] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

_PROOF_LEN_VARIANT = _TOKEN_IFACE + """
contract BridgeClaimFixedVariant {
    IERC20Like public token;
    bytes32 public merkleRoot;
    address public treasury;
    mapping(bytes32 => bool) public processed;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function verifyProof(bytes32[] memory proof, bytes32 leaf) internal view returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = keccak256(abi.encodePacked(computed, proof[i]));
        }
        return computed == merkleRoot;
    }

    function claim(bytes32[] memory proof, bytes32 leaf, uint256 amount) public {
        require(verifyProof(proof, leaf), "bad proof");
        require(!processed[leaf], "already claimed");
        processed[leaf] = true;
        token.transfer(treasury, amount);
    }
}
"""

_PROOF_LEN_CLEAN = _TOKEN_IFACE + """
contract BridgeClaimClean {
    IERC20Like public token;
    bytes32 public merkleRoot;
    uint256 public constant PROOF_DEPTH = 12;
    mapping(bytes32 => bool) public processed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function verifyProof(bytes32[] memory proof, bytes32 leaf) internal view returns (bool) {
        require(proof.length == PROOF_DEPTH, "bad proof depth");
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computed = keccak256(abi.encodePacked(computed, proof[i]));
        }
        return computed == merkleRoot;
    }

    function claim(bytes32[] memory proof, bytes32 leaf, uint256 amount) public {
        require(verifyProof(proof, leaf), "bad proof");
        require(!processed[leaf], "already claimed");
        processed[leaf] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. bridge_root_zero_assertion
# ---------------------------------------------------------------------------

_ROOT_ZERO_VULN = _TOKEN_IFACE + """
contract BridgeMuteRootVuln {
    IERC20Like public token;
    bytes32 public root;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claim(bytes32 leaf, uint256 amount) public {
        require(root == bytes32(0), "root check");
        token.transfer(msg.sender, amount);
    }
}
"""

_ROOT_ZERO_VARIANT = _TOKEN_IFACE + """
contract BridgeMuteRootFixedVariant {
    IERC20Like public token;
    bytes32 public root;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function claim(bytes32 leaf, uint256 amount) public {
        require(root == bytes32(0), "root check");
        token.transfer(treasury, amount);
    }
}
"""

_ROOT_ZERO_CLEAN = _TOKEN_IFACE + """
contract BridgeRootClean {
    IERC20Like public token;
    bytes32 public merkleRoot;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function setRootOnce(bytes32 newRoot) public {
        require(merkleRoot == bytes32(0), "already set");
        merkleRoot = newRoot;
    }

    function claim(bytes32 leaf, uint256 amount) public {
        require(merkleRoot != bytes32(0), "no root committed");
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. spot_price_own_balance
# ---------------------------------------------------------------------------

_OWN_BALANCE_VULN = _TOKEN_IFACE + """
contract OwnBalancePriceVuln {
    IERC20Like public token0;
    uint256 public totalShares;

    constructor(address _token) {
        token0 = IERC20Like(_token);
    }

    function spotPrice() public view returns (uint256) {
        uint256 reserve = token0.balanceOf(address(this));
        return reserve * 1e18 / totalShares;
    }
}
"""

_OWN_BALANCE_VARIANT = _TOKEN_IFACE + """
contract OwnBalanceSettleFixedVariant {
    IERC20Like public token;
    address public treasury;
    uint256 public totalShares;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function settle() public {
        uint256 price = token.balanceOf(address(this)) * 1e18 / totalShares;
        token.transfer(treasury, price);
    }
}
"""

_OWN_BALANCE_CLEAN = """
interface IPriceFeed {
    function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}
""" + _TOKEN_IFACE + """
contract OwnBalanceOracleClean {
    IERC20Like public token0;
    IPriceFeed public feed;

    constructor(address _token, address _feed) {
        token0 = IERC20Like(_token);
        feed = IPriceFeed(_feed);
    }

    function oraclePrice() public view returns (uint256) {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        require(updatedAt > 0, "stale price");
        return uint256(answer);
    }

    function reserveView() public view returns (uint256) {
        return token0.balanceOf(address(this));
    }
}
"""

_OWN_BALANCE_CLEAN_NO_ORACLE = _TOKEN_IFACE + """
contract OwnBalanceShapesClean {
    IERC20Like public token0;
    IERC20Like public token1;

    constructor(address _token0, address _token1) {
        token0 = IERC20Like(_token0);
        token1 = IERC20Like(_token1);
    }

    function reserveView() public view returns (uint256) {
        return token0.balanceOf(address(this));
    }

    function ratioPrice() public view returns (uint256) {
        uint256 r0 = token0.balanceOf(address(this));
        uint256 r1 = token1.balanceOf(address(this));
        return r1 * 1e18 / r0;
    }

    function flashLoan(uint256 amount) public {
        uint256 before = token0.balanceOf(address(this));
        require(token0.balanceOf(address(this)) >= before, "not repaid");
    }
}
"""

VULN = {
    "bridge_proof_length_unvalidated": _PROOF_LEN_VULN,
    "bridge_root_zero_assertion": _ROOT_ZERO_VULN,
    "spot_price_own_balance": _OWN_BALANCE_VULN,
}

VARIANT = {
    "bridge_proof_length_unvalidated": _PROOF_LEN_VARIANT,
    "bridge_root_zero_assertion": _ROOT_ZERO_VARIANT,
    "spot_price_own_balance": _OWN_BALANCE_VARIANT,
}

CLEAN = {
    "bridge_proof_length_unvalidated": _PROOF_LEN_CLEAN,
    "bridge_root_zero_assertion": _ROOT_ZERO_CLEAN,
    "spot_price_own_balance": _OWN_BALANCE_CLEAN,
    "spot_price_own_balance_no_oracle": _OWN_BALANCE_CLEAN_NO_ORACLE,
}
