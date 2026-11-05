"""Fixtures for the deep-audit batch-10 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the recipient / power is FIXED, so it MUST fire with
report_class "trigger_only" at low severity - never a
candidate.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. withdraw_rounding_drain
# ---------------------------------------------------------------------------

_WITHDRAW_VULN = _TOKEN_IFACE + """
contract BunniVaultVuln {
    IERC20Like public token;
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function _burn(address from, uint256 shares) internal {
        balanceOf[from] -= shares;
        totalSupply -= shares;
    }

    function withdraw(uint256 amount, address to) external {
        uint256 sharesToBurn = amount * totalSupply / totalAssets;
        _burn(msg.sender, sharesToBurn);
        totalAssets -= amount;
        token.transfer(to, amount);
    }
}
"""

_WITHDRAW_CLEAN = _TOKEN_IFACE + """
contract BunniVaultClean {
    IERC20Like public token;
    uint256 public totalSupply;
    uint256 public totalAssets;
    mapping(address => uint256) public balanceOf;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function _burn(address from, uint256 shares) internal {
        balanceOf[from] -= shares;
        totalSupply -= shares;
    }

    function withdraw(uint256 amount, address to) external {
        uint256 sharesToBurn = (amount * totalSupply + totalAssets - 1) / totalAssets;
        _burn(msg.sender, sharesToBurn);
        totalAssets -= amount;
        token.transfer(to, amount);
    }
}
"""

_WITHDRAW_MIN_GUARD = _TOKEN_IFACE + """
contract BunniVaultMinGuard {
    IERC20Like public token;
    uint256 public totalSupply;
    uint256 public totalAssets;
    uint256 public constant MIN_WITHDRAW = 1000;
    mapping(address => uint256) public balanceOf;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function _burn(address from, uint256 shares) internal {
        balanceOf[from] -= shares;
        totalSupply -= shares;
    }

    function withdraw(uint256 amount, address to) external {
        require(amount >= MIN_WITHDRAW, "dust");
        uint256 sharesToBurn = amount * totalSupply / totalAssets;
        _burn(msg.sender, sharesToBurn);
        totalAssets -= amount;
        token.transfer(to, amount);
    }
}
"""

_WITHDRAW_VARIANT = _TOKEN_IFACE + """
contract BunniVaultFixed {
    IERC20Like public token;
    uint256 public totalSupply;
    uint256 public totalAssets;
    address public treasury;
    mapping(address => uint256) public balanceOf;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function _burn(address from, uint256 shares) internal {
        balanceOf[from] -= shares;
        totalSupply -= shares;
    }

    function withdraw(uint256 amount) external {
        uint256 sharesToBurn = amount * totalSupply / totalAssets;
        _burn(msg.sender, sharesToBurn);
        totalAssets -= amount;
        token.transfer(treasury, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. forwarder_execute_spoof
# ---------------------------------------------------------------------------

_FORWARDER_VULN = _TOKEN_IFACE + """
contract KiloForwarderVuln {
    address public owner;
    address public priceFeed;

    constructor(address _priceFeed) {
        owner = msg.sender;
        priceFeed = _priceFeed;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setPrice(uint256 p) external onlyOwner {
        // privileged price setter, one hop up from the forwarder
        (bool ok, ) = priceFeed.call(abi.encodeWithSignature("setPrice(uint256)", p));
        require(ok, "set failed");
    }

    function execute(address from, address to, uint256 value, bytes calldata data, bytes calldata signature) external payable {
        bytes32 digest = keccak256(abi.encode(to, value, data, block.chainid));
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        address signer = ecrecover(digest, v, r, s);
        require(signer == from, "bad sig");
        (bool ok, ) = to.call{value: value}(data);
        require(ok, "call failed");
    }
}
"""

_FORWARDER_CLEAN = _TOKEN_IFACE + """
contract KiloForwarderClean {
    address public owner;
    address public priceFeed;

    constructor(address _priceFeed) {
        owner = msg.sender;
        priceFeed = _priceFeed;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setPrice(uint256 p) external onlyOwner {
        (bool ok, ) = priceFeed.call(abi.encodeWithSignature("setPrice(uint256)", p));
        require(ok, "set failed");
    }

    function execute(address from, address to, uint256 value, bytes calldata data, uint256 nonce, bytes calldata signature) external payable {
        bytes32 digest = keccak256(abi.encode(from, to, value, data, nonce));
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        address signer = ecrecover(digest, v, r, s);
        require(signer == from, "bad sig");
        (bool ok, ) = to.call{value: value}(data);
        require(ok, "call failed");
    }
}
"""

_FORWARDER_VARIANT = _TOKEN_IFACE + """
contract KiloForwarderFixed {
    address public owner;
    address public priceFeed;

    constructor(address _priceFeed) {
        owner = msg.sender;
        priceFeed = _priceFeed;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setPrice(uint256 p) external onlyOwner {
        (bool ok, ) = priceFeed.call(abi.encodeWithSignature("setPrice(uint256)", p));
        require(ok, "set failed");
    }

    function execute(address from, address to, uint256 value, bytes calldata data, bytes calldata signature) external payable {
        bytes32 digest = keccak256(abi.encode(to, value, data, block.chainid));
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        address signer = ecrecover(digest, v, r, s);
        require(signer == from, "bad sig");
        (bool ok, ) = priceFeed.call(data);
        require(ok, "call failed");
    }
}
"""

# ---------------------------------------------------------------------------
# 3. multicall_2771_sender_spoof
# ---------------------------------------------------------------------------

_MULTICALL_PREAMBLE = _TOKEN_IFACE + """
contract Multicall2771Base {
    IERC20Like public token;
    address public trustedForwarder;
    address public owner;

    constructor(address _token, address _forwarder) {
        token = IERC20Like(_token);
        trustedForwarder = _forwarder;
        owner = msg.sender;
    }

    function isTrustedForwarder(address f) public view returns (bool) {
        return f == trustedForwarder;
    }

    function _msgSender() internal view returns (address sender) {
        if (isTrustedForwarder(msg.sender)) {
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender = msg.sender;
        }
    }
"""

_MULTICALL_VULN = _MULTICALL_PREAMBLE + """
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory ret) = address(this).delegatecall(data[i]);
            require(ok, "subcall failed");
            results[i] = ret;
        }
    }

    function withdrawFunds(address to, uint256 amount) external {
        require(_msgSender() == owner, "not owner");
        token.transfer(to, amount);
    }
}
"""

_MULTICALL_CLEAN = _MULTICALL_PREAMBLE + """
    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory ret) = address(this).delegatecall(abi.encodePacked(data[i], msg.sender));
            require(ok, "subcall failed");
            results[i] = ret;
        }
    }

    function withdrawFunds(address to, uint256 amount) external {
        require(_msgSender() == owner, "not owner");
        token.transfer(to, amount);
    }
}
"""

_MULTICALL_VARIANT = _MULTICALL_PREAMBLE + """
    address public treasury;

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory ret) = address(this).delegatecall(data[i]);
            require(ok, "subcall failed");
            results[i] = ret;
        }
    }

    function withdrawFunds(uint256 amount) external {
        require(_msgSender() == owner, "not owner");
        token.transfer(treasury, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. liquidation_bonus_to_borrower
# ---------------------------------------------------------------------------

_LIQUIDATION_VULN = _TOKEN_IFACE + """
contract LiquidationBonusVuln {
    IERC20Like public debtToken;
    IERC20Like public collateralToken;
    uint256 public constant LIQUIDATION_BONUS = 110;

    constructor(address _debt, address _collateral) {
        debtToken = IERC20Like(_debt);
        collateralToken = IERC20Like(_collateral);
    }

    function liquidate(address borrower, uint256 debtToCover, address recipient) external {
        uint256 seized = debtToCover * LIQUIDATION_BONUS / 100;
        debtToken.transferFrom(msg.sender, address(this), debtToCover);
        collateralToken.transfer(recipient, seized);
    }
}
"""

_LIQUIDATION_CLEAN = _TOKEN_IFACE + """
contract LiquidationBonusClean {
    IERC20Like public debtToken;
    IERC20Like public collateralToken;
    uint256 public constant LIQUIDATION_BONUS = 110;

    constructor(address _debt, address _collateral) {
        debtToken = IERC20Like(_debt);
        collateralToken = IERC20Like(_collateral);
    }

    function liquidate(address borrower, uint256 debtToCover, address recipient) external {
        require(msg.sender != borrower, "no self-liquidation");
        uint256 seized = debtToCover * LIQUIDATION_BONUS / 100;
        debtToken.transferFrom(msg.sender, address(this), debtToCover);
        collateralToken.transfer(recipient, seized);
    }
}
"""

_LIQUIDATION_NO_BONUS = _TOKEN_IFACE + """
contract LiquidationNoBonus {
    IERC20Like public debtToken;
    IERC20Like public collateralToken;

    constructor(address _debt, address _collateral) {
        debtToken = IERC20Like(_debt);
        collateralToken = IERC20Like(_collateral);
    }

    function liquidate(address borrower, uint256 debtToCover, address recipient) external {
        uint256 seized = debtToCover * 100 / 100;
        debtToken.transferFrom(msg.sender, address(this), debtToCover);
        collateralToken.transfer(recipient, seized);
    }
}
"""

_LIQUIDATION_VARIANT = _TOKEN_IFACE + """
contract LiquidationBonusFixed {
    IERC20Like public debtToken;
    IERC20Like public collateralToken;
    address public treasury;
    uint256 public constant LIQUIDATION_BONUS = 110;

    constructor(address _debt, address _collateral, address _treasury) {
        debtToken = IERC20Like(_debt);
        collateralToken = IERC20Like(_collateral);
        treasury = _treasury;
    }

    function liquidate(address borrower, uint256 debtToCover) external {
        uint256 seized = debtToCover * LIQUIDATION_BONUS / 100;
        debtToken.transferFrom(msg.sender, address(this), debtToCover);
        collateralToken.transfer(treasury, seized);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. eip7702_low_slot_collision
# ---------------------------------------------------------------------------

_EIP7702_VULN = """
contract EIP7702DelegateVuln {
    address public owner;
    address public module;
    mapping(address => bool) public sessions;

    function initialize(address _owner) external {
        owner = _owner;
    }

    function execute(address to, uint256 value, bytes calldata data) external payable returns (bytes memory) {
        require(msg.sender == owner, "not owner");
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }

    function openSession(address user) external {
        require(msg.sender == module, "not module");
        sessions[user] = true;
    }
}
"""

_EIP7702_CLEAN = """
contract EIP7702DelegateClean {
    struct DelegateStorage {
        address owner;
        address module;
        mapping(address => bool) sessions;
    }

    bytes32 private constant DELEGATE_STORAGE_SLOT = keccak256("eip7702.delegate.storage") - 1;

    function _storage() internal pure returns (DelegateStorage storage s) {
        assembly {
            s.slot := DELEGATE_STORAGE_SLOT
        }
    }

    function initialize(address _owner) external {
        _storage().owner = _owner;
    }

    function execute(address to, uint256 value, bytes calldata data) external payable returns (bytes memory) {
        require(msg.sender == _storage().owner, "not owner");
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }
}
"""

_EIP7702_VARIANT = """
contract EIP7702DelegateFixed {
    address public owner;
    address public module;
    address public treasury;
    mapping(address => bool) public sessions;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function initialize(address _owner) external {
        owner = _owner;
    }

    function execute(address to, uint256 value, bytes calldata data) external payable returns (bytes memory) {
        require(msg.sender == owner, "not owner");
        (bool ok, bytes memory ret) = treasury.call{value: value}(data);
        require(ok, "call failed");
        return ret;
    }
}
"""

VULN = {
    "withdraw_rounding_drain": _WITHDRAW_VULN,
    "forwarder_execute_spoof": _FORWARDER_VULN,
    "multicall_2771_sender_spoof": _MULTICALL_VULN,
    "liquidation_bonus_to_borrower": _LIQUIDATION_VULN,
    "eip7702_low_slot_collision": _EIP7702_VULN,
}

CLEAN = {
    "withdraw_rounding_drain": _WITHDRAW_CLEAN,
    "forwarder_execute_spoof": _FORWARDER_CLEAN,
    "multicall_2771_sender_spoof": _MULTICALL_CLEAN,
    "liquidation_bonus_to_borrower": _LIQUIDATION_CLEAN,
    "eip7702_low_slot_collision": _EIP7702_CLEAN,
}

VARIANT = {
    "withdraw_rounding_drain": _WITHDRAW_VARIANT,
    "forwarder_execute_spoof": _FORWARDER_VARIANT,
    "multicall_2771_sender_spoof": _MULTICALL_VARIANT,
    "liquidation_bonus_to_borrower": _LIQUIDATION_VARIANT,
    "eip7702_low_slot_collision": _EIP7702_VARIANT,
}

# FP-regression shapes for eip7702_low_slot_collision: plain
# Ownable ERC-20 / governance tokens that the loose first-cut
# marker misfired on (15/15 false positives on the 2026-11-05
# corpus). A "Delegat" name, or initialize + delegatecall
# anywhere in the bundle, is NOT an EIP-7702 delegate.
_EIP7702_TOKEN_FP = _TOKEN_IFACE + """
library AddressLib {
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}

contract DSDelegateToken {
    IERC20Like public token;
    address public owner;
    mapping(address => uint256) public nonces;

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    function initialize(address _owner) external {
        owner = _owner;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        token.transfer(to, amount);
    }

    function delegateBySig(address delegatee, uint256 nonce, uint256 expiry, uint8 v, bytes32 r, bytes32 s) external {
        require(nonces[msg.sender] == nonce, "bad nonce");
        nonces[msg.sender] += 1;
    }
}
"""

_EIP7702_UPGRADEABLE_FP = _TOKEN_IFACE + """
contract OptimismMintableToken {
    IERC20Like public token;
    address public owner;

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    function initialize(address _owner) external {
        owner = _owner;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return token.transfer(to, amount);
    }

    function upgradeTo(address impl, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = impl.delegatecall(data);
        require(ok, "upgrade failed");
    }
}
"""

# Extra clean shapes (not the primary CLEAN control, asserted
# separately in the test file).
EXTRA_CLEAN = {
    "withdraw_rounding_drain_min_guard": _WITHDRAW_MIN_GUARD,
    "liquidation_bonus_to_borrower_no_bonus": _LIQUIDATION_NO_BONUS,
    "eip7702_low_slot_collision_token_fp": _EIP7702_TOKEN_FP,
    "eip7702_low_slot_collision_upgradeable_fp": _EIP7702_UPGRADEABLE_FP,
}
