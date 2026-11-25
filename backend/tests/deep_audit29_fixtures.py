"""Fixtures for the deep-audit batch-29 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" (all four are
recipient detectors - the liquidation and bridge findings pay
the caller / a caller-supplied recipient; the restake and
subaccount findings mint / pay value the desync creates beyond
the caller's own deposit, so the HOLDER-SELF shape the generic
classifier sees on the payout leg is overridden to candidate
under the vault_share_inflation / share-price precedent, pinned
explicitly in the test). CLEAN[id] (the protected shape of the
same class) MUST stay silent under ALL four detectors;
VARIANT[id] carries the same vulnerable shape but the value
lands at a FIXED destination, so it MUST fire with report_class
"trigger_only" at low severity - never a candidate.

Cross-talk by construction: the liquidation fixture liquidates
and borrows but names no bridge / voucher / restake / subaccount
function, verifies no signature, and moves no shares; the bridge
fixture verifies a signature over a receipt but names no
liquidate / restake / subaccount function, takes no account
parameter, and its digest binds the source chain id and the
message id while the recovered signer must equal a stored
authority (so the replay-digest detector stays silent); the
restake fixture stakes, transfers and restakes but names no
liquidate / bridge function, verifies no signature, its stake
measures the received balance delta (so the total-shares
mismatch detector stays silent) and runs the reward update
before crediting shares (so the reward-distribution detector
stays silent); the subaccount fixture transfers between
subaccounts and withdraws but names no liquidate / bridge /
restake function, verifies no signature, and its debit IS
present (so the credit-without-debit detector stays silent)
while its withdraw carries a sufficiency require (so the
overdraw detector stays silent). Any co-fire found by the
neighbour sweep is asserted explicitly in the test, not
pretended silent.
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

# ---------------------------------------------------------------------------
# 1. liquidation_clears_collateral_keeps_debt (MORE Markets, Nov 16 2026)
# ---------------------------------------------------------------------------

_LIQ_VULN = _TOKEN_IFACE + """
contract MoreStyleMarket {
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalBorrows;

    function depositCollateral(uint256 amount) external {
        uint256 balanceBefore = collateralToken.balanceOf(address(this));
        collateralToken.transferFrom(msg.sender, address(this), amount);
        uint256 received = collateralToken.balanceOf(address(this)) - balanceBefore;
        collateral[msg.sender] += received;
    }

    function borrow(uint256 amount) external {
        require(collateral[msg.sender] >= amount * 2, "undercollateralized");
        require(debt[msg.sender] + amount <= 1000000 ether, "cap");
        debt[msg.sender] += amount;
        totalBorrows += amount;
        debtToken.transfer(msg.sender, amount);
    }

    function liquidate(address borrower) external {
        uint256 seized = collateral[borrower];
        collateral[borrower] = 0;
        collateralToken.transfer(msg.sender, seized);
        // BUG: debt[borrower] and totalBorrows are never reduced -
        // the collateral is gone but the debt stays on the books.
    }

    function withdraw(uint256 amount) external {
        require(debt[msg.sender] == 0, "debt outstanding");
        collateral[msg.sender] -= amount;
        collateralToken.transfer(msg.sender, amount);
    }
}
"""

_LIQ_CLEAN = _TOKEN_IFACE + """
contract MoreStyleMarket {
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalBorrows;

    function depositCollateral(uint256 amount) external {
        uint256 balanceBefore = collateralToken.balanceOf(address(this));
        collateralToken.transferFrom(msg.sender, address(this), amount);
        uint256 received = collateralToken.balanceOf(address(this)) - balanceBefore;
        collateral[msg.sender] += received;
    }

    function borrow(uint256 amount) external {
        require(collateral[msg.sender] >= amount * 2, "undercollateralized");
        require(debt[msg.sender] + amount <= 1000000 ether, "cap");
        debt[msg.sender] += amount;
        totalBorrows += amount;
        debtToken.transfer(msg.sender, amount);
    }

    function liquidate(address borrower, uint256 repayAmount) external {
        uint256 seized = collateral[borrower];
        collateral[borrower] = 0;
        debt[borrower] -= repayAmount;
        totalBorrows -= repayAmount;
        collateralToken.transfer(msg.sender, seized);
    }

    function withdraw(uint256 amount) external {
        require(debt[msg.sender] == 0, "debt outstanding");
        collateral[msg.sender] -= amount;
        collateralToken.transfer(msg.sender, amount);
    }
}
"""

_LIQ_VARIANT = _TOKEN_IFACE + """
contract MoreStyleMarket {
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    address public feeCollector;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalBorrows;

    function borrow(uint256 amount) external {
        require(collateral[msg.sender] >= amount * 2, "undercollateralized");
        debt[msg.sender] += amount;
        totalBorrows += amount;
        debtToken.transfer(msg.sender, amount);
    }

    function liquidate(address borrower) external {
        uint256 seized = collateral[borrower];
        collateral[borrower] = 0;
        collateralToken.transfer(feeCollector, seized);
        // BUG: debt never reduced - but the seized collateral
        // lands at the FIXED fee collector, never the caller.
    }
}
"""

_LIQ_GATED = _TOKEN_IFACE + """
contract MoreStyleMarket {
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    address public owner;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalBorrows;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
        totalBorrows += amount;
        debtToken.transfer(msg.sender, amount);
    }

    function liquidate(address borrower) external onlyOwner {
        uint256 seized = collateral[borrower];
        collateral[borrower] = 0;
        collateralToken.transfer(msg.sender, seized);
    }
}
"""

_LIQ_DEBT_REDUCED_INTERNAL = _TOKEN_IFACE + """
contract MoreStyleMarket {
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalBorrows;

    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
        totalBorrows += amount;
        debtToken.transfer(msg.sender, amount);
    }

    function _clearDebt(address borrower, uint256 repayAmount) internal {
        debt[borrower] -= repayAmount;
        totalBorrows -= repayAmount;
    }

    function liquidate(address borrower, uint256 repayAmount) external {
        uint256 seized = collateral[borrower];
        collateral[borrower] = 0;
        _clearDebt(borrower, repayAmount);
        collateralToken.transfer(msg.sender, seized);
    }
}
"""

_LIQ_COLLATERAL_KEPT = _TOKEN_IFACE + """
contract AbracadabraStyleMarket {
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalBorrows;

    function borrow(uint256 amount) external {
        debt[msg.sender] += amount;
        totalBorrows += amount;
        debtToken.transfer(msg.sender, amount);
    }

    function liquidate(address borrower, uint256 repayAmount) external {
        // The mirror image: the debt is zeroed but the
        // collateral record is left standing (the residual
        // collateral shape, owned by another detector).
        debt[borrower] -= repayAmount;
        totalBorrows -= repayAmount;
        debtToken.transferFrom(msg.sender, address(this), repayAmount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. bridge_withdraw_no_consumed_receipt_check (Ankr, Nov 9 2026)
# ---------------------------------------------------------------------------

_BRIDGE_VULN = _TOKEN_IFACE + _ECDSA_LIB + """
contract AnkrStyleBridge {
    address public bridgeSigner;

    function withdraw(bytes32 messageId, address token, uint256 amount, address recipient, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(block.chainid, messageId, token, amount, recipient));
        address recovered = ECDSA.recover(digest, signature);
        require(recovered == bridgeSigner, "bad signature");
        // BUG: no usedReceipts[messageId] check - the same signed
        // receipt pays again and again with changed fields.
        IERC20Like(token).transfer(recipient, amount);
    }
}
"""

_BRIDGE_CLEAN = _TOKEN_IFACE + _ECDSA_LIB + """
contract AnkrStyleBridge {
    address public bridgeSigner;
    mapping(bytes32 => bool) public usedReceipts;

    function withdraw(bytes32 messageId, address token, uint256 amount, address recipient, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(block.chainid, messageId, token, amount, recipient));
        address recovered = ECDSA.recover(digest, signature);
        require(recovered == bridgeSigner, "bad signature");
        require(!usedReceipts[messageId], "already used");
        usedReceipts[messageId] = true;
        IERC20Like(token).transfer(recipient, amount);
    }
}
"""

_BRIDGE_VARIANT = _TOKEN_IFACE + _ECDSA_LIB + """
contract AnkrStyleBridge {
    address public bridgeSigner;
    address public treasury;

    function withdraw(bytes32 messageId, address token, uint256 amount, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(block.chainid, messageId, token, amount, treasury));
        address recovered = ECDSA.recover(digest, signature);
        require(recovered == bridgeSigner, "bad signature");
        // BUG: no consumed-receipt check - but the payout lands
        // at the FIXED treasury, never the caller.
        IERC20Like(token).transfer(treasury, amount);
    }
}
"""

_BRIDGE_NO_SIG = _TOKEN_IFACE + """
contract AnkrStyleBridge {
    function withdraw(bytes32 messageId, address token, uint256 amount, address recipient) external {
        IERC20Like(token).transfer(recipient, amount);
    }
}
"""

_BRIDGE_GATED = _TOKEN_IFACE + _ECDSA_LIB + """
contract AnkrStyleBridge {
    address public bridgeSigner;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function withdraw(bytes32 messageId, address token, uint256 amount, address recipient, bytes calldata signature) external onlyOwner {
        bytes32 digest = keccak256(abi.encode(block.chainid, messageId, token, amount, recipient));
        address recovered = ECDSA.recover(digest, signature);
        require(recovered == bridgeSigner, "bad signature");
        IERC20Like(token).transfer(recipient, amount);
    }
}
"""

_BRIDGE_NO_VALUE = _TOKEN_IFACE + _ECDSA_LIB + """
contract AnkrStyleBridge {
    address public bridgeSigner;

    function withdraw(bytes32 messageId, address token, uint256 amount, address recipient, bytes calldata signature) external returns (bool) {
        bytes32 digest = keccak256(abi.encode(block.chainid, messageId, token, amount, recipient));
        address recovered = ECDSA.recover(digest, signature);
        require(recovered == bridgeSigner, "bad signature");
        return true;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. restake_reward_baseline_desync_on_transfer (Chain Games, Nov 15 2026)
# ---------------------------------------------------------------------------

_RESTAKE_VULN = _TOKEN_IFACE + """
contract ValidatorShare {
    IERC20Like public stakeToken;
    uint256 public rewardPerShare;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public initialRewardPerShare;

    function _updateReward(address account) internal {
        initialRewardPerShare[account] = rewardPerShare;
    }

    function stake(uint256 amount) external {
        uint256 balanceBefore = stakeToken.balanceOf(address(this));
        stakeToken.transferFrom(msg.sender, address(this), amount);
        uint256 received = stakeToken.balanceOf(address(this)) - balanceBefore;
        _updateReward(msg.sender);
        shares[msg.sender] += received;
        totalShares += received;
    }

    function transfer(address to, uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        shares[msg.sender] -= amount;
        shares[to] += amount;
        // BUG: initialRewardPerShare[to] is never set - a fresh
        // recipient keeps baseline 0 and claims rewards accrued
        // before it held shares.
    }

    function restake() external {
        uint256 reward = (rewardPerShare - initialRewardPerShare[msg.sender]) * shares[msg.sender];
        shares[msg.sender] += reward;
        totalShares += reward;
        initialRewardPerShare[msg.sender] = rewardPerShare;
    }

    function distribute(uint256 reward) external {
        rewardPerShare += reward / totalShares;
    }
}
"""

_RESTAKE_CLEAN = _TOKEN_IFACE + """
contract ValidatorShare {
    IERC20Like public stakeToken;
    uint256 public rewardPerShare;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public initialRewardPerShare;

    function _updateReward(address account) internal {
        initialRewardPerShare[account] = rewardPerShare;
    }

    function stake(uint256 amount) external {
        uint256 balanceBefore = stakeToken.balanceOf(address(this));
        stakeToken.transferFrom(msg.sender, address(this), amount);
        uint256 received = stakeToken.balanceOf(address(this)) - balanceBefore;
        _updateReward(msg.sender);
        shares[msg.sender] += received;
        totalShares += received;
    }

    function transfer(address to, uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        _updateReward(msg.sender);
        _updateReward(to);
        shares[msg.sender] -= amount;
        shares[to] += amount;
        initialRewardPerShare[to] = rewardPerShare;
    }

    function restake() external {
        uint256 reward = (rewardPerShare - initialRewardPerShare[msg.sender]) * shares[msg.sender];
        shares[msg.sender] += reward;
        totalShares += reward;
        initialRewardPerShare[msg.sender] = rewardPerShare;
    }

    function distribute(uint256 reward) external {
        rewardPerShare += reward / totalShares;
    }
}
"""

_RESTAKE_VARIANT = _TOKEN_IFACE + """
contract ValidatorShare {
    IERC20Like public stakeToken;
    address public treasury;
    uint256 public rewardPerShare;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public initialRewardPerShare;

    function transfer(address to, uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        shares[msg.sender] -= amount;
        shares[to] += amount;
        // BUG: recipient baseline never set - but the restake
        // mints the reward to the FIXED treasury, never the caller.
    }

    function restake() external {
        uint256 reward = (rewardPerShare - initialRewardPerShare[msg.sender]) * shares[msg.sender];
        shares[treasury] += reward;
        totalShares += reward;
        initialRewardPerShare[msg.sender] = rewardPerShare;
    }

    function distribute(uint256 reward) external {
        rewardPerShare += reward / totalShares;
    }
}
"""

_RESTAKE_TRANSFER_SETTLES = _TOKEN_IFACE + """
contract ValidatorShare {
    IERC20Like public stakeToken;
    uint256 public rewardPerShare;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public initialRewardPerShare;

    function _updateReward(address account) internal {
        initialRewardPerShare[account] = rewardPerShare;
    }

    function transfer(address to, uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        _updateReward(msg.sender);
        _updateReward(to);
        shares[msg.sender] -= amount;
        shares[to] += amount;
    }

    function restake() external {
        uint256 reward = (rewardPerShare - initialRewardPerShare[msg.sender]) * shares[msg.sender];
        shares[msg.sender] += reward;
        totalShares += reward;
        initialRewardPerShare[msg.sender] = rewardPerShare;
    }

    function distribute(uint256 reward) external {
        rewardPerShare += reward / totalShares;
    }
}
"""

_RESTAKE_NO_RESTAKE = _TOKEN_IFACE + """
contract ValidatorShare {
    IERC20Like public stakeToken;
    uint256 public rewardPerShare;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public initialRewardPerShare;

    function transfer(address to, uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        shares[msg.sender] -= amount;
        shares[to] += amount;
    }

    function distribute(uint256 reward) external {
        rewardPerShare += reward / totalShares;
    }
}
"""

_RESTAKE_GATED = _TOKEN_IFACE + """
contract ValidatorShare {
    IERC20Like public stakeToken;
    address public owner;
    uint256 public rewardPerShare;
    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public initialRewardPerShare;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function transfer(address to, uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        shares[msg.sender] -= amount;
        shares[to] += amount;
    }

    function restake() external onlyOwner {
        uint256 reward = (rewardPerShare - initialRewardPerShare[msg.sender]) * shares[msg.sender];
        shares[msg.sender] += reward;
        totalShares += reward;
        initialRewardPerShare[msg.sender] = rewardPerShare;
    }
}
"""

# ---------------------------------------------------------------------------
# 4. subaccount_transfer_unchecked_underflow (Arcus Perps, Nov 9-10 2026)
# ---------------------------------------------------------------------------

_SUB_VULN = """
contract SubaccountLedger {
    mapping(address => mapping(uint256 => uint256)) public subBalances;

    function transferBetween(uint256 fromSub, uint256 toSub, uint256 amount) external {
        unchecked {
            subBalances[msg.sender][fromSub] -= amount;
            subBalances[msg.sender][toSub] += amount;
        }
    }

    function withdraw(uint256 sub, uint256 amount) external {
        require(subBalances[msg.sender][sub] >= amount, "insufficient");
        subBalances[msg.sender][sub] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

_SUB_CLEAN = """
contract SubaccountLedger {
    mapping(address => mapping(uint256 => uint256)) public subBalances;

    function transferBetween(uint256 fromSub, uint256 toSub, uint256 amount) external {
        require(subBalances[msg.sender][fromSub] >= amount, "insufficient");
        unchecked {
            subBalances[msg.sender][fromSub] -= amount;
            subBalances[msg.sender][toSub] += amount;
        }
    }

    function withdraw(uint256 sub, uint256 amount) external {
        require(subBalances[msg.sender][sub] >= amount, "insufficient");
        subBalances[msg.sender][sub] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

_SUB_VARIANT = """
contract SubaccountLedger {
    mapping(address => mapping(uint256 => uint256)) public subBalances;
    address public treasury;

    function transferBetween(uint256 fromSub, uint256 toSub, uint256 amount) external {
        unchecked {
            subBalances[msg.sender][fromSub] -= amount;
            subBalances[msg.sender][toSub] += amount;
        }
    }

    function withdraw(uint256 sub, uint256 amount) external {
        require(subBalances[msg.sender][sub] >= amount, "insufficient");
        subBalances[msg.sender][sub] -= amount;
        // BUG: the wrapped balance is real - but the payout lands
        // at the FIXED treasury, never the caller.
        payable(treasury).transfer(amount);
    }
}
"""

_SUB_CHECKED = """
contract SubaccountLedger {
    mapping(address => mapping(uint256 => uint256)) public subBalances;

    function transferBetween(uint256 fromSub, uint256 toSub, uint256 amount) external {
        subBalances[msg.sender][fromSub] -= amount;
        subBalances[msg.sender][toSub] += amount;
    }

    function withdraw(uint256 sub, uint256 amount) external {
        require(subBalances[msg.sender][sub] >= amount, "insufficient");
        subBalances[msg.sender][sub] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

_SUB_GUARD_IN_MODIFIER = """
contract SubaccountLedger {
    mapping(address => mapping(uint256 => uint256)) public subBalances;

    modifier onlySufficient(uint256 fromSub, uint256 amount) {
        require(subBalances[msg.sender][fromSub] >= amount, "insufficient");
        _;
    }

    function transferBetween(uint256 fromSub, uint256 toSub, uint256 amount) external onlySufficient(fromSub, amount) {
        unchecked {
            subBalances[msg.sender][fromSub] -= amount;
            subBalances[msg.sender][toSub] += amount;
        }
    }

    function withdraw(uint256 sub, uint256 amount) external {
        require(subBalances[msg.sender][sub] >= amount, "insufficient");
        subBalances[msg.sender][sub] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

_SUB_NO_WITHDRAW = """
contract SubaccountLedger {
    mapping(address => mapping(uint256 => uint256)) public subBalances;

    function transferBetween(uint256 fromSub, uint256 toSub, uint256 amount) external {
        unchecked {
            subBalances[msg.sender][fromSub] -= amount;
            subBalances[msg.sender][toSub] += amount;
        }
    }
}
"""

VULN = {
    "liquidation_clears_collateral_keeps_debt": _LIQ_VULN,
    "bridge_withdraw_no_consumed_receipt_check": _BRIDGE_VULN,
    "restake_reward_baseline_desync_on_transfer": _RESTAKE_VULN,
    "subaccount_transfer_unchecked_underflow": _SUB_VULN,
}

VARIANT = {
    "liquidation_clears_collateral_keeps_debt": _LIQ_VARIANT,
    "bridge_withdraw_no_consumed_receipt_check": _BRIDGE_VARIANT,
    "restake_reward_baseline_desync_on_transfer": _RESTAKE_VARIANT,
    "subaccount_transfer_unchecked_underflow": _SUB_VARIANT,
}

CLEAN = {
    "liquidation_clears_collateral_keeps_debt": _LIQ_CLEAN,
    "bridge_withdraw_no_consumed_receipt_check": _BRIDGE_CLEAN,
    "restake_reward_baseline_desync_on_transfer": _RESTAKE_CLEAN,
    "subaccount_transfer_unchecked_underflow": _SUB_CLEAN,
}

EXTRA_CLEAN = {
    "liquidation_gated": _LIQ_GATED,
    "liquidation_debt_reduced_internal": _LIQ_DEBT_REDUCED_INTERNAL,
    "liquidation_collateral_kept": _LIQ_COLLATERAL_KEPT,
    "bridge_no_sig": _BRIDGE_NO_SIG,
    "bridge_gated": _BRIDGE_GATED,
    "bridge_no_value": _BRIDGE_NO_VALUE,
    "restake_transfer_settles": _RESTAKE_TRANSFER_SETTLES,
    "restake_no_restake": _RESTAKE_NO_RESTAKE,
    "restake_gated": _RESTAKE_GATED,
    "subaccount_checked": _SUB_CHECKED,
    "subaccount_guard_in_modifier": _SUB_GUARD_IN_MODIFIER,
    "subaccount_no_withdraw": _SUB_NO_WITHDRAW,
}
