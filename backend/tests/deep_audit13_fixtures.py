"""Fixtures for the deep-audit batch-13 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the value / power lands at a FIXED stored address, so it
MUST fire with report_class "trigger_only" at low severity -
never a candidate (same convention as batch 12: the variant
adds a transfer to a fixed treasury in the flagged function);
EXTRA_CLEAN[id] is a second protected shape that MUST stay
silent.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. residual_balance_sweep_ungated
# ---------------------------------------------------------------------------

_SWEEP_VULN = _TOKEN_IFACE + """
contract Dex223RouterVuln {
    IERC20Like public weth;

    constructor(address _weth) {
        weth = IERC20Like(_weth);
    }

    function refundETH() external payable {
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok, "refund failed");
    }

    function unwrapWETH9(uint256 amount, address recipient) public payable {
        weth.withdraw(weth.balanceOf(address(this)));
        (bool ok,) = recipient.call{value: address(this).balance}("");
        require(ok, "unwrap failed");
    }
}
"""

_SWEEP_CLEAN = _TOKEN_IFACE + """
contract Dex223RouterClean {
    IERC20Like public weth;
    address public owner;
    mapping(address => uint256) public deposits;

    constructor(address _weth) {
        weth = IERC20Like(_weth);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function sweepToTreasury(address treasury) external onlyOwner {
        (bool ok,) = treasury.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    function refund() external {
        uint256 amt = deposits[msg.sender];
        deposits[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""

_SWEEP_VARIANT = _TOKEN_IFACE + """
contract Dex223RouterFixed {
    IERC20Like public weth;
    address public treasury;

    constructor(address _weth, address _treasury) {
        weth = IERC20Like(_weth);
        treasury = _treasury;
    }

    function refundETH() external payable {
        (bool ok,) = treasury.call{value: address(this).balance}("");
        require(ok, "refund failed");
    }
}
"""

_SWEEP_EXTRA_CLEAN = _TOKEN_IFACE + """
contract Dex223RouterBounded {
    IERC20Like public token;
    mapping(address => uint256) public deposits;

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero amount");
        require(amount <= deposits[msg.sender], "exceeds deposit");
        deposits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. pyth_price_unsafe_unchecked
# ---------------------------------------------------------------------------

_PYTH_IFACE = """
interface IPythLike {
    struct Price {
        int64 price;
        uint64 conf;
        int32 expo;
        uint256 publishTime;
    }
    function getPriceUnsafe(bytes32 id) external view returns (Price memory price);
    function getPriceNoOlderThan(bytes32 id, uint256 age) external view returns (Price memory price);
}
"""

_PYTH_VULN = _PYTH_IFACE + """
contract PythConsumerVuln {
    IPythLike public pyth;
    bytes32 public priceId;
    uint256 public minValue;

    function getCollateralValue(uint256 collateralAmount) external view returns (uint256) {
        IPythLike.Price memory feed = pyth.getPriceUnsafe(priceId);
        uint256 value = collateralAmount * uint256(int256(feed.price)) / 1e8;
        require(value >= minValue, "undercollateralized");
        return value;
    }
}
"""

_PYTH_CLEAN = _PYTH_IFACE + """
contract PythConsumerClean {
    IPythLike public pyth;
    bytes32 public priceId;
    uint256 public minValue;
    uint64 public maxConf;

    function getCollateralValue(uint256 collateralAmount) external view returns (uint256) {
        IPythLike.Price memory feed = pyth.getPriceNoOlderThan(priceId, 60);
        require(feed.conf <= maxConf, "conf too wide");
        uint256 value = collateralAmount * uint256(int256(feed.price)) / 1e8;
        require(value >= minValue, "undercollateralized");
        return value;
    }
}
"""

_PYTH_VARIANT = _PYTH_IFACE + _TOKEN_IFACE + """
contract PythConsumerFixed {
    IPythLike public pyth;
    IERC20Like public token;
    bytes32 public priceId;
    uint256 public minValue;
    address public treasury;

    function getCollateralValue(uint256 collateralAmount) external returns (uint256) {
        IPythLike.Price memory feed = pyth.getPriceUnsafe(priceId);
        uint256 value = collateralAmount * uint256(int256(feed.price)) / 1e8;
        require(value >= minValue, "undercollateralized");
        token.transfer(treasury, 1);
        return value;
    }
}
"""

_PYTH_EXTRA_CLEAN = _PYTH_IFACE + """
contract PythConsumerStaleChecked {
    IPythLike public pyth;
    bytes32 public priceId;
    uint256 public minValue;
    uint256 public maxAge;

    function getCollateralValue(uint256 collateralAmount) external view returns (uint256) {
        IPythLike.Price memory feed = pyth.getPriceUnsafe(priceId);
        require(block.timestamp - feed.publishTime <= maxAge, "stale price");
        uint256 value = collateralAmount * uint256(int256(feed.price)) / 1e8;
        require(value >= minValue, "undercollateralized");
        return value;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. paymaster_sponsorship_unbounded
# ---------------------------------------------------------------------------

_PAYMASTER_IFACE = """
struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}
"""

_PAYMASTER_VULN = _PAYMASTER_IFACE + """
contract OpenPaymasterVuln {
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external returns (bytes memory context, uint256 validationData)
    {
        return ("", 0);
    }
}
"""

_PAYMASTER_CLEAN = _PAYMASTER_IFACE + """
contract SignedPaymasterClean {
    address public owner;

    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external returns (bytes memory context, uint256 validationData)
    {
        bytes32 hash = keccak256(abi.encode(userOp.sender, userOpHash, maxCost));
        address signer = ecrecover(hash, userOp.signature);
        require(signer == owner, "bad paymaster sig");
        return ("", 0);
    }
}
"""

_PAYMASTER_VARIANT = _PAYMASTER_IFACE + _TOKEN_IFACE + """
contract OpenPaymasterFixed {
    IERC20Like public token;
    address public treasury;

    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external returns (bytes memory context, uint256 validationData)
    {
        token.transfer(treasury, 1);
        return ("", 0);
    }
}
"""

_PAYMASTER_EXTRA_CLEAN = _PAYMASTER_IFACE + """
contract CappedPaymasterClean {
    mapping(address => uint256) public sponsored;
    uint256 public maxSpend;

    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        external returns (bytes memory context, uint256 validationData)
    {
        uint256 spent = sponsored[userOp.sender];
        require(spent + maxCost <= maxSpend, "sponsorship cap");
        sponsored[userOp.sender] = spent + maxCost;
        return ("", 0);
    }
}
"""

# ---------------------------------------------------------------------------
_STALE_VULN = """
contract TrovesVaultVuln {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR");
    address public rebalancer;
    mapping(bytes32 => mapping(address => bool)) public roles;

    constructor(address _rebalancer) {
        rebalancer = _rebalancer;
        grantRole(OPERATOR_ROLE, rebalancer);
    }

    function grantRole(bytes32 role, address account) public {
        roles[role][account] = true;
    }

    function setRebalancer(address _newRebalancer) external {
        rebalancer = _newRebalancer;
    }

    function drain(address token, uint256 amount) external {
        require(roles[OPERATOR_ROLE][msg.sender], "not operator");
    }
}
"""

_STALE_CLEAN = """
contract TrovesVaultClean {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR");
    address public rebalancer;
    mapping(bytes32 => mapping(address => bool)) public roles;

    constructor(address _rebalancer) {
        rebalancer = _rebalancer;
        grantRole(OPERATOR_ROLE, rebalancer);
    }

    function grantRole(bytes32 role, address account) public {
        roles[role][account] = true;
    }

    function revokeRole(bytes32 role, address account) public {
        roles[role][account] = false;
    }

    function setRebalancer(address _newRebalancer) external {
        revokeRole(OPERATOR_ROLE, rebalancer);
        rebalancer = _newRebalancer;
        grantRole(OPERATOR_ROLE, _newRebalancer);
    }

    function drain(address token, uint256 amount) external {
        require(roles[OPERATOR_ROLE][msg.sender], "not operator");
    }
}
"""

_STALE_VARIANT = _TOKEN_IFACE + """
contract TrovesVaultFixed {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR");
    address public rebalancer;
    IERC20Like public token;
    address public treasury;
    mapping(bytes32 => mapping(address => bool)) public roles;

    constructor(address _rebalancer) {
        rebalancer = _rebalancer;
        grantRole(OPERATOR_ROLE, rebalancer);
    }

    function grantRole(bytes32 role, address account) public {
        roles[role][account] = true;
    }

    function setRebalancer(address _newRebalancer) external {
        rebalancer = _newRebalancer;
        token.transfer(treasury, 1);
    }

    function drain(address tokenAddr, uint256 amount) external {
        require(roles[OPERATOR_ROLE][msg.sender], "not operator");
    }
}
"""

_STALE_EXTRA_CLEAN = """
contract TrovesVaultNeverGranted {
    address public rebalancer;

    function setRebalancer(address _newRebalancer) external {
        rebalancer = _newRebalancer;
    }
}
"""

VULN = {
    "residual_balance_sweep_ungated": _SWEEP_VULN,
    "pyth_price_unsafe_unchecked": _PYTH_VULN,
    "paymaster_sponsorship_unbounded": _PAYMASTER_VULN,
    "stale_permission_after_replacement": _STALE_VULN,
}

CLEAN = {
    "residual_balance_sweep_ungated": _SWEEP_CLEAN,
    "pyth_price_unsafe_unchecked": _PYTH_CLEAN,
    "paymaster_sponsorship_unbounded": _PAYMASTER_CLEAN,
    "stale_permission_after_replacement": _STALE_CLEAN,
}

VARIANT = {
    "residual_balance_sweep_ungated": _SWEEP_VARIANT,
    "pyth_price_unsafe_unchecked": _PYTH_VARIANT,
    "paymaster_sponsorship_unbounded": _PAYMASTER_VARIANT,
    "stale_permission_after_replacement": _STALE_VARIANT,
}

EXTRA_CLEAN = {
    "residual_balance_sweep_ungated": _SWEEP_EXTRA_CLEAN,
    "pyth_price_unsafe_unchecked": _PYTH_EXTRA_CLEAN,
    "paymaster_sponsorship_unbounded": _PAYMASTER_EXTRA_CLEAN,
    "stale_permission_after_replacement": _STALE_EXTRA_CLEAN,
}

# ---------------------------------------------------------------------------
# FP regression shapes (pinned 2026-11-09 from the live-run
# hand-read: every one of these fired on the first corpus pass
# and was hand-read as a false positive).
# ---------------------------------------------------------------------------

# _msgSender() identity gate (CANDY / kurbi / ZEUS / NIGHT):
# _msgSender() == _feeWallet is a caller-identity gate.
_FP_MSGSENDER = _TOKEN_IFACE + """
contract FeeWalletGated {
    IERC20Like public token;
    address public _feeWallet;

    function takeoutStuckETH() public {
        require(_msgSender() == _feeWallet);
        payable(msg.sender).transfer(address(this).balance);
    }

    function _msgSender() internal view returns (address) {
        return msg.sender;
    }
}
"""

# Mapping allowlist gate (Monke transfer()): a bare
# require(isTxLimitExempt[msg.sender]) is a gate.
_FP_ALLOWLIST = _TOKEN_IFACE + """
contract AllowlistGated {
    mapping(address => bool) public isTxLimitExempt;

    function transfer() external {
        require(isTxLimitExempt[msg.sender]);
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""

# Modifier override gate (Token / AlaskaGoldRush Withdrawable):
# the abstract modifier is virtual with no body, but the
# concrete override gates with _checkRole(DEFAULT_ADMIN_ROLE).
_FP_OVERRIDE = """
abstract contract WithdrawableFp {
    modifier protectedWithdrawal() virtual;
}

contract WithdrawableTokenFp is WithdrawableFp {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    mapping(bytes32 => mapping(address => bool)) public roles;

    modifier protectedWithdrawal() override {
        _checkRole(DEFAULT_ADMIN_ROLE);
        _;
    }

    function _checkRole(bytes32 role) internal view {
        require(roles[role][msg.sender], "no role");
    }

    function withdrawETH(address payable to) external protectedWithdrawal {
        to.transfer(address(this).balance);
    }
}
"""

# Role check via an external access-control contract
# (CudosToken withdrawStuckEther): hasAdminRole(_msgSender()).
_FP_HASADMINROLE = _TOKEN_IFACE + """
interface IAccessControlsLike {
    function hasAdminRole(address account) external view returns (bool);
}

contract AdminRoleGated {
    IAccessControlsLike public accessControls;

    function withdrawStuckEther(address payable _withdrawalAccount) external {
        require(accessControls.hasAdminRole(_msgSender()), "Only admin");
        _withdrawalAccount.transfer(address(this).balance);
    }

    function _msgSender() internal view returns (address) {
        return msg.sender;
    }
}
"""

# One-time setter (Locker setBoard): the setter reverts once
# the address is already set, so the stale-permission path is
# unreachable even though the old address holds a grant.
_FP_ONETIME_SETTER = _TOKEN_IFACE + """
contract BoardLockerFp {
    IERC20Like public token;
    address public board;

    function setBoard(address _board) external {
        if (board != address(0)) revert("already set");
        board = _board;
        token.approve(board, 1000000);
    }
}
"""

FP_REGRESSION = {
    "sweep_msgsender_gate": _FP_MSGSENDER,
    "sweep_allowlist_gate": _FP_ALLOWLIST,
    "sweep_modifier_override_gate": _FP_OVERRIDE,
    "sweep_has_admin_role_gate": _FP_HASADMINROLE,
    "stale_one_time_setter": _FP_ONETIME_SETTER,
}
