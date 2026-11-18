"""Fixtures for the deep-audit batch-26 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" (the four recipient
detectors); the recorded-supply detector fires without a
candidate classification (batch-20 auction precedent: the
withdraw itself pays the caller's own balance - the
stranger-receivable value is the mispriced pool trade the
desync enables, not the withdrawal). CLEAN[id] (the protected
shape of the same class) MUST stay silent under ALL five
detectors; VARIANT[id] carries the same vulnerable shape but
the value lands at a FIXED destination, so it MUST fire with
report_class "trigger_only" at low severity - never a
candidate (no variant for the settlement detector: the caller
controls the call, so there is no fixed-destination form;
no variant for the recorded-supply detector: it carries no
recipient classification at all).

Cross-talk by construction: the order fixture validates a
signature and executes an order but names no swap / claim /
deposit / withdraw function and moves no value through a
router; the swap fixture credits a reported router output
but names no claim / order / execute function and takes no
fee-amount parameter; the fee-claim fixture claims fees
from a pool but names no swap / order / execute / withdraw
function and verifies no Merkle proof; the settlement
fixture executes a caller target but delegatecalls nothing,
names no mint / claim / deposit / bid function, and takes
no order hash; the recorded-supply fixture withdraws
against a capped reserve read but names no swap / claim /
order / execute function and verifies no signature.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function totalSupply() external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}
"""

_ECDSA_LIB = """
library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        return address(0);
    }
}
"""

_ROUTER_IFACE = """
interface IRouter {
    function swap(address tokenIn, uint256 amountIn, uint256 amountOut) external returns (uint256);
}
"""

_POOL_IFACE = """
interface IPool {
    function feesOwed(address account) external returns (uint256);
}
"""

_MATH_LIB = """
library Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
"""

# ---------------------------------------------------------------------------
# 1. order_signature_validates_description_not_hash
# ---------------------------------------------------------------------------

_ORDER_VULN = _TOKEN_IFACE + _ECDSA_LIB + """
contract OrderSigDescVuln {
    IERC20Like public token;
    address public owner;
    mapping(bytes32 => bool) public executedOrders;

    constructor(address _token, address _owner) {
        token = IERC20Like(_token);
        owner = _owner;
    }

    function isValidSignature(bytes32 orderHash, string calldata description, bytes calldata signature) external returns (bytes4) {
        bytes32 digest = keccak256(abi.encodePacked(description));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == owner, "bad signer");
        _executeOrder(orderHash);
        return 0x1626ba7e;
    }

    function _executeOrder(bytes32 orderHash) internal {
        require(!executedOrders[orderHash], "already executed");
        executedOrders[orderHash] = true;
        token.transfer(msg.sender, 1000);
    }
}
"""

_ORDER_VARIANT = _TOKEN_IFACE + _ECDSA_LIB + """
contract OrderSigDescFixed {
    IERC20Like public token;
    address public owner;
    address public treasury;
    mapping(bytes32 => bool) public executedOrders;

    constructor(address _token, address _owner, address _treasury) {
        token = IERC20Like(_token);
        owner = _owner;
        treasury = _treasury;
    }

    function isValidSignature(bytes32 orderHash, string calldata description, bytes calldata signature) external returns (bytes4) {
        bytes32 digest = keccak256(abi.encodePacked(description));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == owner, "bad signer");
        _executeOrder(orderHash);
        return 0x1626ba7e;
    }

    function _executeOrder(bytes32 orderHash) internal {
        require(!executedOrders[orderHash], "already executed");
        executedOrders[orderHash] = true;
        token.transfer(treasury, 1000);
    }
}
"""

# The order hash is hashed into the signed digest: protected shape.
_ORDER_CLEAN = _TOKEN_IFACE + _ECDSA_LIB + """
contract OrderSigDescClean {
    IERC20Like public token;
    address public owner;
    mapping(bytes32 => bool) public executedOrders;

    constructor(address _token, address _owner) {
        token = IERC20Like(_token);
        owner = _owner;
    }

    function isValidSignature(bytes32 orderHash, string calldata description, bytes calldata signature) external returns (bytes4) {
        bytes32 digest = keccak256(abi.encodePacked(orderHash, description));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == owner, "bad signer");
        _executeOrder(orderHash);
        return 0x1626ba7e;
    }

    function _executeOrder(bytes32 orderHash) internal {
        require(!executedOrders[orderHash], "already executed");
        executedOrders[orderHash] = true;
        token.transfer(msg.sender, 1000);
    }
}
"""

# Description validated, but no value movement downstream.
_ORDER_NO_VALUE = _TOKEN_IFACE + _ECDSA_LIB + """
contract OrderSigNoValue {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 orderHash, string calldata description, bytes calldata signature) external returns (bytes4) {
        bytes32 digest = keccak256(abi.encodePacked(description));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == owner, "bad signer");
        return 0x1626ba7e;
    }
}
"""

# The executed order hash is compared against the signed value.
_ORDER_HASH_COMPARED = _TOKEN_IFACE + _ECDSA_LIB + """
contract OrderSigHashCompared {
    IERC20Like public token;
    address public owner;
    mapping(bytes32 => bool) public executedOrders;

    constructor(address _token, address _owner) {
        token = IERC20Like(_token);
        owner = _owner;
    }

    function isValidSignature(bytes32 orderHash, bytes32 signedHash, string calldata description, bytes calldata signature) external returns (bytes4) {
        bytes32 digest = keccak256(abi.encodePacked(description));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == owner, "bad signer");
        require(orderHash == signedHash, "hash mismatch");
        _executeOrder(orderHash);
        return 0x1626ba7e;
    }

    function _executeOrder(bytes32 orderHash) internal {
        require(!executedOrders[orderHash], "already executed");
        executedOrders[orderHash] = true;
        token.transfer(msg.sender, 1000);
    }
}
"""

# Owner-gated validation: a stranger cannot reach the path.
_ORDER_GATED = _TOKEN_IFACE + _ECDSA_LIB + """
contract OrderSigGated {
    IERC20Like public token;
    address public owner;
    mapping(bytes32 => bool) public executedOrders;

    constructor(address _token, address _owner) {
        token = IERC20Like(_token);
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function isValidSignature(bytes32 orderHash, string calldata description, bytes calldata signature) external onlyOwner returns (bytes4) {
        bytes32 digest = keccak256(abi.encodePacked(description));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == owner, "bad signer");
        _executeOrder(orderHash);
        return 0x1626ba7e;
    }

    function _executeOrder(bytes32 orderHash) internal {
        require(!executedOrders[orderHash], "already executed");
        executedOrders[orderHash] = true;
        token.transfer(msg.sender, 1000);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. swap_output_trusted_report_no_receipt_check
# ---------------------------------------------------------------------------

_SWAP_VULN = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapOutputTrustVuln {
    IERC20Like public token;
    address public router;
    mapping(address => uint256) public reserves;
    mapping(address => uint256) public credits;

    constructor(address _router, address _token) {
        router = _router;
        token = IERC20Like(_token);
    }

    function swapAndCredit(address tokenIn, uint256 amountIn, uint256 amountOut) external {
        uint256 reported = IRouter(router).swap(tokenIn, amountIn, amountOut);
        reserves[tokenIn] += reported;
        credits[msg.sender] += reported;
    }

    function withdraw(uint256 amount) external {
        require(amount <= credits[msg.sender], "insufficient credit");
        credits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_SWAP_VARIANT = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapOutputTrustFixed {
    IERC20Like public token;
    address public router;
    address public treasury;
    mapping(address => uint256) public reserves;
    mapping(address => uint256) public credits;

    constructor(address _router, address _token, address _treasury) {
        router = _router;
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function swapAndCredit(address tokenIn, uint256 amountIn, uint256 amountOut) external {
        uint256 reported = IRouter(router).swap(tokenIn, amountIn, amountOut);
        reserves[tokenIn] += reported;
        credits[treasury] += reported;
    }

    function withdraw(uint256 amount) external {
        require(amount <= credits[treasury], "insufficient credit");
        credits[treasury] -= amount;
        token.transfer(treasury, amount);
    }
}
"""

# Before/after balanceOf receipt check: protected shape.
_SWAP_CLEAN = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapOutputTrustClean {
    IERC20Like public token;
    address public router;
    mapping(address => uint256) public reserves;
    mapping(address => uint256) public credits;

    constructor(address _router, address _token) {
        router = _router;
        token = IERC20Like(_token);
    }

    function swapAndCredit(address tokenIn, uint256 amountIn, uint256 amountOut) external {
        uint256 before = token.balanceOf(address(this));
        uint256 reported = IRouter(router).swap(tokenIn, amountIn, amountOut);
        uint256 afterBal = token.balanceOf(address(this));
        require(afterBal - before >= reported, "not received");
        reserves[tokenIn] += reported;
        credits[msg.sender] += reported;
    }

    function withdraw(uint256 amount) external {
        require(amount <= credits[msg.sender], "insufficient credit");
        credits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# The measured balance delta is credited, not the reported figure.
_SWAP_CREDIT_DELTA = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapCreditDelta {
    IERC20Like public token;
    address public router;
    mapping(address => uint256) public reserves;
    mapping(address => uint256) public credits;

    constructor(address _router, address _token) {
        router = _router;
        token = IERC20Like(_token);
    }

    function swapAndCredit(address tokenIn, uint256 amountIn, uint256 amountOut) external {
        uint256 before = token.balanceOf(address(this));
        uint256 reported = IRouter(router).swap(tokenIn, amountIn, amountOut);
        uint256 received = token.balanceOf(address(this)) - before;
        reserves[tokenIn] += received;
        credits[msg.sender] += received;
    }

    function withdraw(uint256 amount) external {
        require(amount <= credits[msg.sender], "insufficient credit");
        credits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# Credit with no downstream payout: out of scope.
_SWAP_NO_PAYOUT = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapNoPayout {
    address public router;
    mapping(address => uint256) public reserves;

    constructor(address _router) {
        router = _router;
    }

    function swapAndCredit(address tokenIn, uint256 amountIn, uint256 amountOut) external {
        uint256 reported = IRouter(router).swap(tokenIn, amountIn, amountOut);
        reserves[tokenIn] += reported;
    }
}
"""

# Swap with no ledger credit at all.
_SWAP_NO_CREDIT = _TOKEN_IFACE + _ROUTER_IFACE + """
contract SwapNoCredit {
    address public router;

    constructor(address _router) {
        router = _router;
    }

    function swapAndCredit(address tokenIn, uint256 amountIn, uint256 amountOut) external returns (uint256) {
        uint256 reported = IRouter(router).swap(tokenIn, amountIn, amountOut);
        return reported;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. fee_claim_exceeds_accrued_fees
# ---------------------------------------------------------------------------

_FEE_VULN = _TOKEN_IFACE + _POOL_IFACE + """
contract FeeClaimVuln {
    IERC20Like public token;
    mapping(address => uint256) public accruedFees;
    mapping(address => bool) public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claimFees(address pool, address to) external {
        uint256 fees = IPool(pool).feesOwed(msg.sender);
        require(!claimed[msg.sender], "already claimed");
        claimed[msg.sender] = true;
        token.transfer(to, fees);
    }
}
"""

_FEE_VARIANT = _TOKEN_IFACE + _POOL_IFACE + """
contract FeeClaimFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => uint256) public accruedFees;
    mapping(address => bool) public claimed;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function claimFees(address pool) external {
        uint256 fees = IPool(pool).feesOwed(msg.sender);
        require(!claimed[msg.sender], "already claimed");
        claimed[msg.sender] = true;
        token.transfer(treasury, fees);
    }
}
"""

# The claim is capped by the stored accrued-fees record.
_FEE_CLEAN = _TOKEN_IFACE + _POOL_IFACE + """
contract FeeClaimClean {
    IERC20Like public token;
    mapping(address => uint256) public accruedFees;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claimFees(address pool, address to) external {
        uint256 fees = IPool(pool).feesOwed(msg.sender);
        uint256 accrued = accruedFees[pool];
        require(fees <= accrued, "exceeds accrued fees");
        accruedFees[pool] -= fees;
        token.transfer(to, fees);
    }
}
"""

# The figure is computed from the contract's own stored state.
_FEE_FROM_STORED_STATE = _TOKEN_IFACE + _POOL_IFACE + """
contract FeeFromStoredState {
    IERC20Like public token;
    mapping(address => uint256) public accruedFees;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claimFees(address pool, address to) external {
        uint256 fees = accruedFees[pool];
        accruedFees[pool] = 0;
        token.transfer(to, fees);
    }
}
"""

# The claim is capped by a min() against the accrued record.
_FEE_MIN_CAPPED = _TOKEN_IFACE + _POOL_IFACE + _MATH_LIB + """
contract FeeMinCapped {
    IERC20Like public token;
    mapping(address => uint256) public accruedFees;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claimFees(address pool, address to) external {
        uint256 fees = IPool(pool).feesOwed(msg.sender);
        uint256 allowed = Math.min(fees, accruedFees[pool]);
        require(fees <= allowed, "exceeds accrued fees");
        accruedFees[pool] -= fees;
        token.transfer(to, fees);
    }
}
"""

# A caller-supplied amount capped by a claimable-fees record.
_FEE_CALLER_AMOUNT_CAPPED = _TOKEN_IFACE + _POOL_IFACE + """
contract FeeCallerAmountCapped {
    IERC20Like public token;
    mapping(address => uint256) public claimableFees;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claimFees(address pool, uint256 amount, address to) external {
        require(amount <= claimableFees[msg.sender], "exceeds claimable");
        claimableFees[msg.sender] -= amount;
        token.transfer(to, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. settlement_swap_executes_caller_target_spends_approvals
# ---------------------------------------------------------------------------

_SETTLE_VULN = _TOKEN_IFACE + """
contract SettlementSwapVuln {
    IERC20Like public token;
    mapping(address => bool) public allowedTargets;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function setupApproval(address spender) external {
        token.approve(spender, type(uint256).max);
    }

    function executeSwap(address target, bytes calldata data, address tokenAddr, uint256 amount) external {
        (bool ok, ) = target.call(data);
        require(ok, "swap failed");
        IERC20Like(tokenAddr).transferFrom(msg.sender, address(this), amount);
    }
}
"""

# The target is allowlisted per call: protected shape.
_SETTLE_CLEAN = _TOKEN_IFACE + """
contract SettlementSwapClean {
    IERC20Like public token;
    mapping(address => bool) public allowedTargets;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function setupApproval(address spender) external {
        token.approve(spender, type(uint256).max);
    }

    function executeSwap(address target, bytes calldata data, address tokenAddr, uint256 amount) external {
        require(allowedTargets[target], "target not allowed");
        (bool ok, ) = target.call(data);
        require(ok, "swap failed");
        IERC20Like(tokenAddr).transferFrom(msg.sender, address(this), amount);
    }
}
"""

# The target is bound to the stored router.
_SETTLE_ROUTER_BOUND = _TOKEN_IFACE + """
contract SettlementRouterBound {
    IERC20Like public token;
    address public router;

    constructor(address _token, address _router) {
        token = IERC20Like(_token);
        router = _router;
    }

    function setupApproval(address spender) external {
        token.approve(spender, type(uint256).max);
    }

    function executeSwap(address target, bytes calldata data, address tokenAddr, uint256 amount) external {
        require(target == router, "bad target");
        (bool ok, ) = target.call(data);
        require(ok, "swap failed");
        IERC20Like(tokenAddr).transferFrom(msg.sender, address(this), amount);
    }
}
"""

# Owner-gated settlement: a stranger cannot reach the path.
_SETTLE_OWNER_GATED = _TOKEN_IFACE + """
contract SettlementOwnerGated {
    IERC20Like public token;
    address public owner;

    constructor(address _token, address _owner) {
        token = IERC20Like(_token);
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function executeSwap(address target, bytes calldata data, address tokenAddr, uint256 amount) external onlyOwner {
        (bool ok, ) = target.call(data);
        require(ok, "swap failed");
        IERC20Like(tokenAddr).transferFrom(msg.sender, address(this), amount);
    }
}
"""

# Arbitrary call but no approval-spendable path anywhere.
_SETTLE_NO_APPROVAL = """
contract SettlementNoApproval {
    function executeSwap(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "swap failed");
    }
}
"""

# Delegatecall, not a plain call: the multicall detector owns it.
_SETTLE_DELEGATECALL = _TOKEN_IFACE + """
contract SettlementDelegatecall {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function setupApproval(address spender) external {
        token.approve(spender, type(uint256).max);
    }

    function executeSwap(address target, bytes calldata data, address tokenAddr, uint256 amount) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "swap failed");
        IERC20Like(tokenAddr).transferFrom(msg.sender, address(this), amount);
    }
}
"""

# Plain call to a stored target, not a caller-supplied one.
_SETTLE_STORED_TARGET = _TOKEN_IFACE + """
contract SettlementStoredTarget {
    IERC20Like public token;
    address public router;

    constructor(address _token, address _router) {
        token = IERC20Like(_token);
        router = _router;
    }

    function setupApproval(address spender) external {
        token.approve(spender, type(uint256).max);
    }

    function executeSwap(bytes calldata data, address tokenAddr, uint256 amount) external {
        (bool ok, ) = router.call(data);
        require(ok, "swap failed");
        IERC20Like(tokenAddr).transferFrom(msg.sender, address(this), amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. recorded_supply_caps_pool_reserves
# ---------------------------------------------------------------------------

_SUPPLY_VULN = _TOKEN_IFACE + """
contract RecordedSupplyPoolVuln {
    IERC20Like public token;
    uint256 public recordedSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function getAvailableReserves() public view returns (uint256) {
        uint256 actual = token.balanceOf(address(this));
        return actual < recordedSupply ? actual : recordedSupply;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        recordedSupply -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# The transfer is verified before the supply is decremented.
_SUPPLY_CLEAN = _TOKEN_IFACE + """
contract RecordedSupplyPoolClean {
    IERC20Like public token;
    uint256 public recordedSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function getAvailableReserves() public view returns (uint256) {
        uint256 actual = token.balanceOf(address(this));
        return actual < recordedSupply ? actual : recordedSupply;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        require(token.transfer(msg.sender, amount), "transfer failed");
        balances[msg.sender] -= amount;
        recordedSupply -= amount;
    }
}
"""

# Reserves read the raw balance only: no supply cap at all.
_SUPPLY_RAW_BALANCE = _TOKEN_IFACE + """
contract RecordedSupplyRawBalance {
    IERC20Like public token;
    uint256 public recordedSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function getAvailableReserves() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        recordedSupply -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# The cap exists but no withdrawal ever decrements the supply.
_SUPPLY_NO_DECREMENT = _TOKEN_IFACE + """
contract RecordedSupplyNoDecrement {
    IERC20Like public token;
    uint256 public recordedSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function getAvailableReserves() public view returns (uint256) {
        uint256 actual = token.balanceOf(address(this));
        return actual < recordedSupply ? actual : recordedSupply;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
"""

# A try/catch that swallows the transfer failure still decrements.
_SUPPLY_TRY_CATCH = _TOKEN_IFACE + _MATH_LIB + """
contract RecordedSupplyTryCatch {
    IERC20Like public token;
    uint256 public recordedSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function getAvailableReserves() public view returns (uint256) {
        return Math.min(token.balanceOf(address(this)), recordedSupply);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        recordedSupply -= amount;
        try token.transfer(msg.sender, amount) returns (bool ok) {
        } catch {
        }
    }
}
"""

VULN = {
    "order_signature_validates_description_not_hash": _ORDER_VULN,
    "swap_output_trusted_report_no_receipt_check": _SWAP_VULN,
    "fee_claim_exceeds_accrued_fees": _FEE_VULN,
    "settlement_swap_executes_caller_target_spends_approvals":
        _SETTLE_VULN,
    "recorded_supply_caps_pool_reserves": _SUPPLY_VULN,
}

VARIANT = {
    "order_signature_validates_description_not_hash": _ORDER_VARIANT,
    "swap_output_trusted_report_no_receipt_check": _SWAP_VARIANT,
    "fee_claim_exceeds_accrued_fees": _FEE_VARIANT,
}

CLEAN = {
    "order_signature_validates_description_not_hash": _ORDER_CLEAN,
    "swap_output_trusted_report_no_receipt_check": _SWAP_CLEAN,
    "fee_claim_exceeds_accrued_fees": _FEE_CLEAN,
    "settlement_swap_executes_caller_target_spends_approvals":
        _SETTLE_CLEAN,
    "recorded_supply_caps_pool_reserves": _SUPPLY_CLEAN,
}

EXTRA_CLEAN = {
    "order_no_value": _ORDER_NO_VALUE,
    "order_hash_compared": _ORDER_HASH_COMPARED,
    "order_gated": _ORDER_GATED,
    "swap_credit_delta": _SWAP_CREDIT_DELTA,
    "swap_no_payout": _SWAP_NO_PAYOUT,
    "swap_no_credit": _SWAP_NO_CREDIT,
    "fee_from_stored_state": _FEE_FROM_STORED_STATE,
    "fee_min_capped": _FEE_MIN_CAPPED,
    "fee_caller_amount_capped": _FEE_CALLER_AMOUNT_CAPPED,
    "settle_router_bound": _SETTLE_ROUTER_BOUND,
    "settle_owner_gated": _SETTLE_OWNER_GATED,
    "settle_no_approval": _SETTLE_NO_APPROVAL,
    "settle_delegatecall": _SETTLE_DELEGATECALL,
    "settle_stored_target": _SETTLE_STORED_TARGET,
    "supply_raw_balance": _SUPPLY_RAW_BALANCE,
    "supply_no_decrement": _SUPPLY_NO_DECREMENT,
}

# Extra vulnerable shape (not in VULN): a try/catch that swallows
# the transfer failure still decrements the recorded supply.
VULN_TRY_CATCH = _SUPPLY_TRY_CATCH
