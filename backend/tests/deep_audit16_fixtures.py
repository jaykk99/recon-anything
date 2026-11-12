"""Fixtures for the deep-audit batch-12/deep16 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
two detectors; VARIANT[id] carries the same vulnerable shape
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
# 1. scheduled_settlement_books_unpaid
# ---------------------------------------------------------------------------

_APPROVAL_VULN = _TOKEN_IFACE + """
contract AssessmentVaultVuln {
    IERC20Like public token;

    struct Assessment {
        uint256 amount;
        bytes payload;
        uint256 version;
    }

    mapping(uint256 => Assessment) public currentAssessment;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function approve(uint256 incidentId) external {
        Assessment memory a = currentAssessment[incidentId];
        token.transfer(msg.sender, a.amount);
    }

    function cancelAssessment(uint256 incidentId) external {
        delete currentAssessment[incidentId];
    }

    function submitAssessment(uint256 incidentId, uint256 amount, bytes calldata payload) external {
        currentAssessment[incidentId] = Assessment({
            amount: amount,
            payload: payload,
            version: currentAssessment[incidentId].version + 1
        });
    }
}
"""

_APPROVAL_CLEAN = _TOKEN_IFACE + """
contract AssessmentVaultClean {
    IERC20Like public token;

    struct Assessment {
        uint256 amount;
        bytes payload;
        uint256 version;
    }

    mapping(uint256 => Assessment) public currentAssessment;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function approve(uint256 incidentId, uint256 version) external {
        Assessment memory a = currentAssessment[incidentId];
        require(a.version == version, "stale approval");
        token.transfer(msg.sender, a.amount);
    }

    function cancelAssessment(uint256 incidentId) external {
        delete currentAssessment[incidentId];
    }

    function submitAssessment(uint256 incidentId, uint256 amount, bytes calldata payload) external {
        currentAssessment[incidentId] = Assessment({
            amount: amount,
            payload: payload,
            version: currentAssessment[incidentId].version + 1
        });
    }
}
"""

_APPROVAL_VARIANT = _TOKEN_IFACE + """
contract AssessmentVaultFixed {
    IERC20Like public token;
    address public treasury;

    struct Assessment {
        uint256 amount;
        bytes payload;
        uint256 version;
    }

    mapping(uint256 => Assessment) public currentAssessment;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function approve(uint256 incidentId) external {
        Assessment memory a = currentAssessment[incidentId];
        token.transfer(treasury, a.amount);
    }

    function cancelAssessment(uint256 incidentId) external {
        delete currentAssessment[incidentId];
    }

    function submitAssessment(uint256 incidentId, uint256 amount, bytes calldata payload) external {
        currentAssessment[incidentId] = Assessment({
            amount: amount,
            payload: payload,
            version: currentAssessment[incidentId].version + 1
        });
    }
}
"""

# ---------------------------------------------------------------------------
# 5. zero_amount_withdraw_all
# ---------------------------------------------------------------------------

_STAKING_IFACE = """
interface IStaking {
    function unstake(uint256 amount) external;
}
"""

_ZERO_VULN = _TOKEN_IFACE + _STAKING_IFACE + """
contract StakingVaultVuln {
    IERC20Like public token;
    IStaking public staking;

    constructor(address _token, address _staking) {
        token = IERC20Like(_token);
        staking = IStaking(_staking);
    }

    function withdraw(uint256 amount) external {
        staking.unstake(amount);
        uint256 received = token.balanceOf(address(this));
        token.transfer(msg.sender, received);
    }
}
"""

_ZERO_CLEAN = _TOKEN_IFACE + _STAKING_IFACE + """
contract StakingVaultClean {
    IERC20Like public token;
    IStaking public staking;

    constructor(address _token, address _staking) {
        token = IERC20Like(_token);
        staking = IStaking(_staking);
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero amount");
        staking.unstake(amount);
        uint256 received = token.balanceOf(address(this));
        token.transfer(msg.sender, received);
    }
}
"""

_ZERO_REVERT = _TOKEN_IFACE + _STAKING_IFACE + """
contract StakingVaultRevert {
    IERC20Like public token;
    IStaking public staking;

    constructor(address _token, address _staking) {
        token = IERC20Like(_token);
        staking = IStaking(_staking);
    }

    function withdraw(uint256 amount) external {
        if (amount == 0) revert ZeroAmount();
        staking.unstake(amount);
        uint256 received = token.balanceOf(address(this));
        token.transfer(msg.sender, received);
    }
}
"""

_ZERO_VARIANT = _TOKEN_IFACE + _STAKING_IFACE + """
contract StakingVaultFixed {
    IERC20Like public token;
    IStaking public staking;
    address public treasury;

    constructor(address _token, address _staking, address _treasury) {
        token = IERC20Like(_token);
        staking = IStaking(_staking);
        treasury = _treasury;
    }

    function withdraw(uint256 amount) external {
        staking.unstake(amount);
        uint256 received = token.balanceOf(address(this));
        token.transfer(treasury, received);
    }
}
"""

_ZERO_SUPER_REDEEM = """
contract ERC4626Like {
    function redeem(uint256 shares, address receiver, address owner)
        public virtual returns (uint256) { return 0; }
}

contract StakedSuperRedeem is ERC4626Like {
    uint256 public cooldownDuration;

    function redeem(uint256 shares, address receiver, address _owner)
        public
        virtual
        override
        returns (uint256)
    {
        if (cooldownDuration != 0) revert CooldownOn();
        return super.redeem(shares, receiver, _owner);
    }
}
"""

VULN = {
    "approval_binds_id_not_version": _APPROVAL_VULN,
    "zero_amount_withdraw_all": _ZERO_VULN,
}

CLEAN = {
    "approval_binds_id_not_version": _APPROVAL_CLEAN,
    "zero_amount_withdraw_all": _ZERO_CLEAN,
}

VARIANT = {
    "approval_binds_id_not_version": _APPROVAL_VARIANT,
    "zero_amount_withdraw_all": _ZERO_VARIANT,
}

# Extra clean shapes (not the primary CLEAN control, asserted
# separately in the test file).
EXTRA_CLEAN = {
    "zero_amount_withdraw_all_revert_guard": _ZERO_REVERT,
    "zero_amount_withdraw_all_super_redeem": _ZERO_SUPER_REDEEM,
}
