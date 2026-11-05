"""Fixtures for the deep-audit batch-3 detectors.

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
# 1. transient_latch_unconsumed
# ---------------------------------------------------------------------------

_TRANSIENT_VULN = _TOKEN_IFACE + """
contract LatchDeliveryVuln {
    IERC20Like public token;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function markDelivered(bytes32 slot) external {
        assembly { tstore(slot, 1) }
    }

    function deliver(address to, uint256 amount) external {
        bytes32 slot = bytes32(uint256(1));
        uint256 latch;
        assembly { latch := tload(slot) }
        require(latch == 1, "not delivered");
        token.transfer(to, amount);
    }
}
"""

_TRANSIENT_CLEAN = _TOKEN_IFACE + """
contract LatchDeliveryClean {
    IERC20Like public token;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function markDelivered(bytes32 slot) external {
        assembly { tstore(slot, 1) }
    }

    function deliver(address to, uint256 amount) external {
        bytes32 slot = bytes32(uint256(1));
        uint256 latch;
        assembly { latch := tload(slot) }
        require(latch == 1, "not delivered");
        token.transfer(to, amount);
        assembly { tstore(slot, 0) }
    }
}
"""

_TRANSIENT_HASH_BOUND = _TOKEN_IFACE + """
contract LatchDeliveryHashBound {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deliver(address to, uint256 amount, bytes calldata payload) external {
        bytes32 slot = keccak256(abi.encode(to, payload));
        uint256 latch;
        assembly { latch := tload(slot) }
        require(latch == 1, "not delivered");
        token.transfer(to, amount);
    }
}
"""

_TRANSIENT_VARIANT = _TOKEN_IFACE + """
contract LatchDeliveryFixed {
    IERC20Like public token;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function markDelivered(bytes32 slot) external {
        assembly { tstore(slot, 1) }
    }

    function deliver(uint256 amount) external {
        bytes32 slot = bytes32(uint256(1));
        uint256 latch;
        assembly { latch := tload(slot) }
        require(latch == 1, "not delivered");
        token.transfer(treasury, amount);
    }
}
"""

# Method-style reset (OZ TransientSlot usage): the latch is
# read via slot.tload() and cleared via slot.tstore(0) - a
# real reset, so this shape must stay silent. Found 2026-11-04
# on a live contract (MultiDepositorVault _getCallbackApprovals
# clears via method-style tstore and was misread as unreset).
_TRANSIENT_METHOD_RESET = _TOKEN_IFACE + """
contract LatchDeliveryMethodReset {
    IERC20Like public token;
    bytes32 private constant CALLBACK_SLOT = bytes32(uint256(1));

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deliver(address to, uint256 amount) external {
        bytes32 slot = CALLBACK_SLOT;
        bytes32 latch = slot.tload();
        require(latch == bytes32(uint256(1)), "not delivered");
        token.transfer(to, amount);
        slot.tstore(0);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. v4_hook_shared_delta_take_pair
# ---------------------------------------------------------------------------

_V4_PREAMBLE = """
interface IPoolManager {
    function take(bytes32 currency, address to, uint256 amount) external;
    function unlock(bytes calldata data) external returns (bytes memory);
}

struct PoolKey {
    bytes32 currency0;
    bytes32 currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

struct SwapParams {
    bool zeroForOne;
    int256 amountSpecified;
    uint160 sqrtPriceLimitX96;
}

struct BalanceDelta {
    int128 amount0;
    int128 amount1;
}
"""

_V4_VULN = _V4_PREAMBLE + """
contract GpxHookVuln {
    IPoolManager public manager;
    address public treasury;

    constructor(address _manager, address _treasury) {
        manager = IPoolManager(_manager);
        treasury = _treasury;
    }

    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata hookData) external returns (bytes4, int128) {
        address recipient = abi.decode(hookData, (address));
        uint256 credit = uint256(int256(delta.amount0()));
        manager.take(key.currency0, recipient, credit);
        return (this.afterSwap.selector, 0);
    }
}
"""

_V4_CLEAN = _V4_PREAMBLE + """
contract GpxHookClean {
    IPoolManager public manager;
    address public treasury;

    constructor(address _manager, address _treasury) {
        manager = IPoolManager(_manager);
        treasury = _treasury;
    }

    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata hookData) external returns (bytes4, int128) {
        address recipient = abi.decode(hookData, (address));
        uint256 credit = uint256(int256(delta.amount0()));
        manager.unlock("");
        manager.take(key.currency0, recipient, credit);
        return (this.afterSwap.selector, 0);
    }
}
"""

_V4_DELTA_CLEAN = _V4_PREAMBLE + """
contract GpxHookDeltaClean {
    IPoolManager public manager;
    address public treasury;

    constructor(address _manager, address _treasury) {
        manager = IPoolManager(_manager);
        treasury = _treasury;
    }

    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata hookData) external returns (bytes4, int128) {
        address recipient = abi.decode(hookData, (address));
        require(delta.amount0() == 0, "delta not isolated");
        uint256 credit = uint256(int256(delta.amount0()));
        manager.take(key.currency0, recipient, credit);
        return (this.afterSwap.selector, 0);
    }
}
"""

_V4_VARIANT = _V4_PREAMBLE + """
contract GpxHookFixed {
    IPoolManager public manager;
    address public treasury;

    constructor(address _manager, address _treasury) {
        manager = IPoolManager(_manager);
        treasury = _treasury;
    }

    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata hookData) external returns (bytes4, int128) {
        uint256 credit = uint256(int256(delta.amount0()));
        manager.take(key.currency0, treasury, credit);
        return (this.afterSwap.selector, 0);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. inverted_division_zero_collapse
# ---------------------------------------------------------------------------

_INVERTED_VULN = _TOKEN_IFACE + """
contract BorrowVuln {
    IERC20Like public token;
    uint256 private constant PRICE_SCALE = 1e18;
    uint256 public oraclePrice;
    uint256 public collateralValue;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function borrow(uint256 amount) external {
        uint256 rate = PRICE_SCALE / oraclePrice;
        uint256 maxDebt = collateralValue;
        require(amount * rate <= maxDebt, "borrow exceeds limit");
        token.transfer(msg.sender, amount);
    }
}
"""

_INVERTED_CLEAN = _TOKEN_IFACE + """
contract BorrowClean {
    IERC20Like public token;
    uint256 private constant PRICE_SCALE = 1e18;
    uint256 public oraclePrice;
    uint256 public collateralValue;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function borrow(uint256 amount) external {
        uint256 rate = PRICE_SCALE / oraclePrice;
        require(rate > 0, "rate collapsed");
        uint256 maxDebt = collateralValue;
        require(amount * rate <= maxDebt, "borrow exceeds limit");
        token.transfer(msg.sender, amount);
    }
}
"""

_INVERTED_VARIANT = _TOKEN_IFACE + """
contract BorrowFixed {
    IERC20Like public token;
    uint256 private constant PRICE_SCALE = 1e18;
    uint256 public oraclePrice;
    uint256 public collateralValue;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function borrow(uint256 amount) external {
        uint256 rate = PRICE_SCALE / oraclePrice;
        uint256 maxDebt = collateralValue;
        require(amount * rate <= maxDebt, "borrow exceeds limit");
        token.transfer(treasury, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. share_transfer_cancel_desync
# ---------------------------------------------------------------------------

_SHARE_VULN = _TOKEN_IFACE + """
contract PrizeVaultVuln {
    IERC20Like public token;
    mapping(address => uint256) public entitlements;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        entitlements[msg.sender] += amount;
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function _burn(address user, uint256 amount) internal {
        balanceOf[user] -= amount;
    }

    function cancel() external {
        uint256 refund = entitlements[msg.sender];
        uint256 live = this.balanceOf(msg.sender);
        entitlements[msg.sender] = 0;
        _burn(msg.sender, live);
        token.transfer(msg.sender, refund);
    }
}
"""

_SHARE_CLEAN = _TOKEN_IFACE + """
contract PrizeVaultClean {
    IERC20Like public token;
    mapping(address => uint256) public entitlements;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        entitlements[msg.sender] += amount;
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }

    function _burn(address user, uint256 amount) internal {
        balanceOf[user] -= amount;
    }

    function cancel() external {
        uint256 refund = entitlements[msg.sender];
        uint256 live = this.balanceOf(msg.sender);
        entitlements[msg.sender] = 0;
        _burn(msg.sender, live);
        token.transfer(msg.sender, refund);
    }
}
"""

_SHARE_VARIANT = _TOKEN_IFACE + """
contract PrizeVaultFixed {
    IERC20Like public token;
    mapping(address => uint256) public entitlements;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        entitlements[msg.sender] += amount;
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function _burn(address user, uint256 amount) internal {
        balanceOf[user] -= amount;
    }

    function cancel() external {
        uint256 refund = entitlements[msg.sender];
        uint256 live = this.balanceOf(msg.sender);
        entitlements[msg.sender] = 0;
        _burn(msg.sender, live);
        token.transfer(treasury, refund);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. eip712_digest_unbound_to_payload
# ---------------------------------------------------------------------------

_EIP712_VULN = _TOKEN_IFACE + """
contract FeeClaimVuln {
    IERC20Like public token;
    bytes32 public constant FEE_APPROVAL_TYPEHASH = keccak256("FeeApproval(address token,uint256 feeRate,uint256 deadline)");
    address public treasury;

    struct FeeApproval {
        address token;
        uint256 feeRate;
        uint256 deadline;
    }

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function claimBatch(FeeApproval calldata approval, bytes calldata signature, address[] calldata recipients, uint256[] calldata amounts) external {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", keccak256(abi.encode(FEE_APPROVAL_TYPEHASH, approval.token, approval.feeRate, approval.deadline))));
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        for (uint256 i = 0; i < recipients.length; i++) {
            token.transfer(recipients[i], amounts[i]);
        }
    }
}
"""

_EIP712_CLEAN = _TOKEN_IFACE + """
contract FeeClaimClean {
    IERC20Like public token;
    bytes32 public constant FEE_APPROVAL_TYPEHASH = keccak256("FeeApproval(address token,uint256 feeRate,uint256 deadline,bytes32 payloadHash,uint256 batchNonce)");
    mapping(uint256 => bool) public usedNonce;
    address public treasury;

    struct FeeApproval {
        address token;
        uint256 feeRate;
        uint256 deadline;
        bytes32 payloadHash;
        uint256 batchNonce;
    }

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function claimBatch(FeeApproval calldata approval, bytes calldata signature, address[] calldata recipients, uint256[] calldata amounts) external {
        require(approval.payloadHash == keccak256(abi.encode(recipients, amounts)), "payload mismatch");
        require(!usedNonce[approval.batchNonce], "nonce used");
        usedNonce[approval.batchNonce] = true;
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", keccak256(abi.encode(FEE_APPROVAL_TYPEHASH, approval.token, approval.feeRate, approval.deadline, approval.payloadHash, approval.batchNonce))));
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        for (uint256 i = 0; i < recipients.length; i++) {
            token.transfer(recipients[i], amounts[i]);
        }
    }
}
"""

_EIP712_VARIANT = _TOKEN_IFACE + """
contract FeeClaimFixed {
    IERC20Like public token;
    bytes32 public constant FEE_APPROVAL_TYPEHASH = keccak256("FeeApproval(address token,uint256 feeRate,uint256 deadline)");
    address public treasury;

    struct FeeApproval {
        address token;
        uint256 feeRate;
        uint256 deadline;
    }

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function claimBatch(FeeApproval calldata approval, bytes calldata signature, address[] calldata recipients, uint256[] calldata amounts) external {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", keccak256(abi.encode(FEE_APPROVAL_TYPEHASH, approval.token, approval.feeRate, approval.deadline))));
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        for (uint256 i = 0; i < recipients.length; i++) {
            token.transfer(treasury, amounts[i]);
        }
    }
}
"""

VULN = {
    "transient_latch_unconsumed": _TRANSIENT_VULN,
    "v4_hook_shared_delta_take_pair": _V4_VULN,
    "inverted_division_zero_collapse": _INVERTED_VULN,
    "share_transfer_cancel_desync": _SHARE_VULN,
    "eip712_digest_unbound_to_payload": _EIP712_VULN,
}

CLEAN = {
    "transient_latch_unconsumed": _TRANSIENT_CLEAN,
    "v4_hook_shared_delta_take_pair": _V4_CLEAN,
    "inverted_division_zero_collapse": _INVERTED_CLEAN,
    "share_transfer_cancel_desync": _SHARE_CLEAN,
    "eip712_digest_unbound_to_payload": _EIP712_CLEAN,
}

VARIANT = {
    "transient_latch_unconsumed": _TRANSIENT_VARIANT,
    "v4_hook_shared_delta_take_pair": _V4_VARIANT,
    "inverted_division_zero_collapse": _INVERTED_VARIANT,
    "share_transfer_cancel_desync": _SHARE_VARIANT,
    "eip712_digest_unbound_to_payload": _EIP712_VARIANT,
}

# Extra clean shapes (not the primary CLEAN control, asserted
# separately in the test file).
EXTRA_CLEAN = {
    "transient_latch_unconsumed_hash_bound": _TRANSIENT_HASH_BOUND,
    "transient_latch_unconsumed_method_reset": _TRANSIENT_METHOD_RESET,
    "v4_hook_shared_delta_take_pair_delta": _V4_DELTA_CLEAN,
}
