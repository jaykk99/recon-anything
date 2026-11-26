"""Fixtures for the deep-audit batch-34 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the value lands at a FIXED destination, so it MUST fire
with report_class "trigger_only" at low severity - never a
candidate.

Cross-talk by construction: the burn fixture burns a position
but names no mint / claim / buy function, no liquidation, no
_credit and no constructor loop; the burn-debit fixture mints
to the caller but its function is a buy (not a burn) and it
burns a caller-supplied address, not a position; the
liquidation fixture burns the debt token in a
finalizeLiquidation (not a mint / buy) and seizes collateral;
the OFT fixture credits in an internal _credit override (not
a mint / buy) with an unclamped accumulator; the rewards
fixture overwrites in its constructor loop and pays out in a
separate claimReward that burns nothing. DOCUMENTED CO-FIRES:
pancake_lp_token_burn_logic fires on the
burn_debits_caller_supplied_address and the
liquidation_burns_wrong_units_debt fixtures by design - both
expose a `.burn(` through an ungated function mentioning
msg.sender, which is the pancake detector's whole (broad)
pattern. The new detectors add the dimensions it cannot
express: the burn debits a caller-supplied address while
minting to the caller (#2), and the burn amount is in the
wrong units while collateral is seized (#3). Those co-fires
are pinned explicitly in the test, not pretended silent.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function totalSupply() external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function burn(address from, uint256 amount) external;
    function burnFrom(address from, uint256 amount) external;
}
"""

# ---------------------------------------------------------------------------
# 1. burn_zero_amount_skips_liquidity_decrement
# ---------------------------------------------------------------------------

_BURN_VULN = _TOKEN_IFACE + """
contract BiswapBurnVuln {
    IERC20Like public token0;
    IERC20Like public token1;

    struct Position {
        uint128 liquidity;
    }

    mapping(uint256 => Position) public positions;

    constructor(address _token0, address _token1) {
        token0 = IERC20Like(_token0);
        token1 = IERC20Like(_token1);
    }

    function _amountsForLiquidity(uint128 liquidity) internal pure returns (uint256, uint256) {
        return (0, 0);
    }

    function _burn(uint256 tokenId) internal {
        delete positions[tokenId];
    }

    function burn(uint256 tokenId) external returns (uint256 amount0, uint256 amount1) {
        Position storage position = positions[tokenId];
        (amount0, amount1) = _amountsForLiquidity(position.liquidity);
        if (amount0 > 0 || amount1 > 0) {
            position.liquidity -= position.liquidity;
        }
        _burn(tokenId);
        token0.transfer(msg.sender, amount0);
        token1.transfer(msg.sender, amount1);
    }
}
"""

_BURN_VARIANT = _TOKEN_IFACE + """
contract BiswapBurnFixed {
    IERC20Like public token0;
    IERC20Like public token1;
    address public treasury;

    struct Position {
        uint128 liquidity;
    }

    mapping(uint256 => Position) public positions;

    constructor(address _token0, address _token1, address _treasury) {
        token0 = IERC20Like(_token0);
        token1 = IERC20Like(_token1);
        treasury = _treasury;
    }

    function _amountsForLiquidity(uint128 liquidity) internal pure returns (uint256, uint256) {
        return (0, 0);
    }

    function _burn(uint256 tokenId) internal {
        delete positions[tokenId];
    }

    function burn(uint256 tokenId) external returns (uint256 amount0, uint256 amount1) {
        Position storage position = positions[tokenId];
        (amount0, amount1) = _amountsForLiquidity(position.liquidity);
        if (amount0 > 0 || amount1 > 0) {
            position.liquidity -= position.liquidity;
        }
        _burn(tokenId);
        token0.transfer(treasury, amount0);
        token1.transfer(treasury, amount1);
    }
}
"""

# The liquidity is decremented unconditionally on every burn:
# a zero-amount burn still clears the recorded liquidity.
_BURN_CLEAN = _TOKEN_IFACE + """
contract BiswapBurnClean {
    IERC20Like public token0;
    IERC20Like public token1;

    struct Position {
        uint128 liquidity;
    }

    mapping(uint256 => Position) public positions;

    constructor(address _token0, address _token1) {
        token0 = IERC20Like(_token0);
        token1 = IERC20Like(_token1);
    }

    function _amountsForLiquidity(uint128 liquidity) internal pure returns (uint256, uint256) {
        return (0, 0);
    }

    function _burn(uint256 tokenId) internal {
        delete positions[tokenId];
    }

    function burn(uint256 tokenId) external returns (uint256 amount0, uint256 amount1) {
        Position storage position = positions[tokenId];
        (amount0, amount1) = _amountsForLiquidity(position.liquidity);
        position.liquidity -= position.liquidity;
        if (amount0 > 0 || amount1 > 0) {
            token0.transfer(msg.sender, amount0);
            token1.transfer(msg.sender, amount1);
        }
        _burn(tokenId);
    }
}
"""

_BURN_EXTRA_CLEAN = {
    # Only one withdrawal amount exists: the two-amount
    # zero guard cannot be formed.
    "burn_single_amount": _TOKEN_IFACE + """
contract BurnSingleAmount {
    IERC20Like public token0;

    struct Position {
        uint128 liquidity;
    }

    mapping(uint256 => Position) public positions;

    constructor(address _token0) {
        token0 = IERC20Like(_token0);
    }

    function _burn(uint256 tokenId) internal {
        delete positions[tokenId];
    }

    function burn(uint256 tokenId) external returns (uint256 amount0) {
        Position storage position = positions[tokenId];
        amount0 = uint256(position.liquidity);
        if (amount0 > 0) {
            position.liquidity -= position.liquidity;
        }
        _burn(tokenId);
        token0.transfer(msg.sender, amount0);
    }
}
""",
    # The both-zero early return happens BEFORE the position
    # is burned and before the decrement: nothing is removed
    # on the zero path, so no phantom liquidity is created.
    "burn_early_return_before_burn": _TOKEN_IFACE + """
contract BurnEarlyReturnBeforeBurn {
    IERC20Like public token0;
    IERC20Like public token1;

    struct Position {
        uint128 liquidity;
    }

    mapping(uint256 => Position) public positions;

    constructor(address _token0, address _token1) {
        token0 = IERC20Like(_token0);
        token1 = IERC20Like(_token1);
    }

    function _amountsForLiquidity(uint128 liquidity) internal pure returns (uint256, uint256) {
        return (0, 0);
    }

    function _burn(uint256 tokenId) internal {
        delete positions[tokenId];
    }

    function burn(uint256 tokenId) external returns (uint256 amount0, uint256 amount1) {
        Position storage position = positions[tokenId];
        (amount0, amount1) = _amountsForLiquidity(position.liquidity);
        if (amount0 == 0 && amount1 == 0) {
            return (amount0, amount1);
        }
        position.liquidity -= position.liquidity;
        _burn(tokenId);
        token0.transfer(msg.sender, amount0);
        token1.transfer(msg.sender, amount1);
    }
}
""",
}

# Second vulnerable shape for the same detector: the position
# is burned first, then an early return on both-zero skips the
# decrement that sits after the guard.
VULN_BURN_EARLY_RETURN = _TOKEN_IFACE + """
contract BiswapBurnEarlyReturn {
    IERC20Like public token0;
    IERC20Like public token1;

    struct Position {
        uint128 liquidity;
    }

    mapping(uint256 => Position) public positions;

    constructor(address _token0, address _token1) {
        token0 = IERC20Like(_token0);
        token1 = IERC20Like(_token1);
    }

    function _amountsForLiquidity(uint128 liquidity) internal pure returns (uint256, uint256) {
        return (0, 0);
    }

    function _burn(uint256 tokenId) internal {
        delete positions[tokenId];
    }

    function burn(uint256 tokenId) external returns (uint256 amount0, uint256 amount1) {
        Position storage position = positions[tokenId];
        (amount0, amount1) = _amountsForLiquidity(position.liquidity);
        _burn(tokenId);
        if (amount0 == 0 && amount1 == 0) {
            return (amount0, amount1);
        }
        position.liquidity -= position.liquidity;
        token0.transfer(msg.sender, amount0);
        token1.transfer(msg.sender, amount1);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. burn_debits_caller_supplied_address
# ---------------------------------------------------------------------------

_BURN_DEBIT_VULN = _TOKEN_IFACE + """
contract SantasListVuln {
    IERC20Like public santaToken;
    uint256 public constant PRICE = 100;

    constructor(address _santaToken) {
        santaToken = IERC20Like(_santaToken);
    }

    function _mint(address to, uint256 presentId) internal {
    }

    function buyPresent(address presentReceiver, uint256 presentId) external {
        santaToken.burn(presentReceiver, PRICE);
        _mint(msg.sender, presentId);
    }
}
"""

_BURN_DEBIT_VARIANT = _TOKEN_IFACE + """
contract SantasListFixed {
    IERC20Like public santaToken;
    address public treasury;
    uint256 public constant PRICE = 100;

    constructor(address _santaToken, address _treasury) {
        santaToken = IERC20Like(_santaToken);
        treasury = _treasury;
    }

    function _mint(address to, uint256 presentId) internal {
    }

    function buyPresent(address presentReceiver, uint256 presentId) external {
        santaToken.burn(presentReceiver, PRICE);
        _mint(treasury, presentId);
    }
}
"""

# The burn debits msg.sender itself: nobody else's tokens can
# be taken.
_BURN_DEBIT_CLEAN = _TOKEN_IFACE + """
contract SantasListClean {
    IERC20Like public santaToken;
    uint256 public constant PRICE = 100;

    constructor(address _santaToken) {
        santaToken = IERC20Like(_santaToken);
    }

    function _mint(address to, uint256 presentId) internal {
    }

    function buyPresent(address presentReceiver, uint256 presentId) external {
        santaToken.burn(msg.sender, PRICE);
        _mint(msg.sender, presentId);
    }
}
"""

_BURN_DEBIT_EXTRA_CLEAN = {
    # burnFrom with an allowance check: the caller may only
    # burn what the victim approved.
    "buy_allowance": _TOKEN_IFACE + """
contract SantasListAllowance {
    IERC20Like public santaToken;
    uint256 public constant PRICE = 100;

    constructor(address _santaToken) {
        santaToken = IERC20Like(_santaToken);
    }

    function _mint(address to, uint256 presentId) internal {
    }

    function buyPresent(address presentReceiver, uint256 presentId) external {
        require(santaToken.allowance(presentReceiver, address(this)) >= PRICE, "no allowance");
        santaToken.burnFrom(presentReceiver, PRICE);
        _mint(msg.sender, presentId);
    }
}
""",
    # The debited address must be the caller.
    "buy_param_is_sender": _TOKEN_IFACE + """
contract SantasListParamIsSender {
    IERC20Like public santaToken;
    uint256 public constant PRICE = 100;

    constructor(address _santaToken) {
        santaToken = IERC20Like(_santaToken);
    }

    function _mint(address to, uint256 presentId) internal {
    }

    function buyPresent(address presentReceiver, uint256 presentId) external {
        require(presentReceiver == msg.sender, "not yours");
        santaToken.burn(presentReceiver, PRICE);
        _mint(msg.sender, presentId);
    }
}
""",
    # The burn debits a caller-supplied address, but nothing
    # is minted or credited to the caller: no value lands with
    # the stranger.
    "buy_no_mint": _TOKEN_IFACE + """
contract SantasListNoMint {
    IERC20Like public santaToken;
    uint256 public constant PRICE = 100;

    constructor(address _santaToken) {
        santaToken = IERC20Like(_santaToken);
    }

    function buyPresent(address presentReceiver, uint256 presentId) external {
        santaToken.burn(presentReceiver, PRICE);
    }
}
""",
}

# ---------------------------------------------------------------------------
# 3. liquidation_burns_wrong_units_debt
# ---------------------------------------------------------------------------

_LIQ_VULN = _TOKEN_IFACE + """
contract RaacLendingVuln {
    IERC20Like public debtToken;
    IERC20Like public collateralToken;
    uint256 public liquidityIndex;
    mapping(address => uint256) public collateralBalance;

    constructor(address _debtToken, address _collateralToken) {
        debtToken = IERC20Like(_debtToken);
        collateralToken = IERC20Like(_collateralToken);
        liquidityIndex = 1e27;
    }

    function finalizeLiquidation(address borrower) external {
        uint256 userDebt = debtToken.balanceOf(borrower) / liquidityIndex;
        debtToken.burn(borrower, userDebt);
        collateralToken.transfer(msg.sender, collateralBalance[borrower]);
    }
}
"""

_LIQ_VARIANT = _TOKEN_IFACE + """
contract RaacLendingFixed {
    IERC20Like public debtToken;
    IERC20Like public collateralToken;
    address public treasury;
    uint256 public liquidityIndex;
    mapping(address => uint256) public collateralBalance;

    constructor(address _debtToken, address _collateralToken, address _treasury) {
        debtToken = IERC20Like(_debtToken);
        collateralToken = IERC20Like(_collateralToken);
        treasury = _treasury;
        liquidityIndex = 1e27;
    }

    function finalizeLiquidation(address borrower) external {
        uint256 userDebt = debtToken.balanceOf(borrower) / liquidityIndex;
        debtToken.burn(borrower, userDebt);
        collateralToken.transfer(treasury, collateralBalance[borrower]);
    }
}
"""

# The burn uses the raw scaled balance: the debt is cleared in
# the token's own units.
_LIQ_CLEAN = _TOKEN_IFACE + """
contract RaacLendingClean {
    IERC20Like public debtToken;
    IERC20Like public collateralToken;
    uint256 public liquidityIndex;
    mapping(address => uint256) public collateralBalance;

    constructor(address _debtToken, address _collateralToken) {
        debtToken = IERC20Like(_debtToken);
        collateralToken = IERC20Like(_collateralToken);
        liquidityIndex = 1e27;
    }

    function finalizeLiquidation(address borrower) external {
        uint256 scaledDebt = debtToken.balanceOf(borrower);
        debtToken.burn(borrower, scaledDebt);
        collateralToken.transfer(msg.sender, collateralBalance[borrower]);
    }
}
"""

_LIQ_EXTRA_CLEAN = {
    # The normalized amount is multiplied back by the index
    # before the burn: the burn is in the token's own units.
    "liq_rescaled": _TOKEN_IFACE + """
contract RaacLendingRescaled {
    IERC20Like public debtToken;
    IERC20Like public collateralToken;
    uint256 public liquidityIndex;
    mapping(address => uint256) public collateralBalance;

    constructor(address _debtToken, address _collateralToken) {
        debtToken = IERC20Like(_debtToken);
        collateralToken = IERC20Like(_collateralToken);
        liquidityIndex = 1e27;
    }

    function finalizeLiquidation(address borrower) external {
        uint256 userDebt = debtToken.balanceOf(borrower) / liquidityIndex;
        uint256 scaledDebt = userDebt * liquidityIndex;
        debtToken.burn(borrower, scaledDebt);
        collateralToken.transfer(msg.sender, collateralBalance[borrower]);
    }
}
""",
    # The debt is burned in the wrong units, but no collateral
    # is seized in this path: not a liquidation that takes
    # everything while clearing only part of the debt.
    "liq_no_seizure": _TOKEN_IFACE + """
contract RaacLendingNoSeizure {
    IERC20Like public debtToken;
    uint256 public liquidityIndex;

    constructor(address _debtToken) {
        debtToken = IERC20Like(_debtToken);
        liquidityIndex = 1e27;
    }

    function finalizeLiquidation(address borrower) external {
        uint256 userDebt = debtToken.balanceOf(borrower) / liquidityIndex;
        debtToken.burn(borrower, userDebt);
    }
}
""",
    # rayDiv with a rayMul back: the burn is re-scaled.
    "liq_raydiv_rescaled": _TOKEN_IFACE + """
contract RaacLendingRayDivRescaled {
    IERC20Like public debtToken;
    IERC20Like public collateralToken;
    uint256 public liquidityIndex;
    mapping(address => uint256) public collateralBalance;

    constructor(address _debtToken, address _collateralToken) {
        debtToken = IERC20Like(_debtToken);
        collateralToken = IERC20Like(_collateralToken);
        liquidityIndex = 1e27;
    }

    function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }

    function rayMul(uint256 a, uint256 b) internal pure returns (uint256) {
        return a * b;
    }

    function finalizeLiquidation(address borrower) external {
        uint256 userDebt = rayDiv(debtToken.balanceOf(borrower), liquidityIndex);
        uint256 scaledDebt = rayMul(userDebt, liquidityIndex);
        debtToken.burn(borrower, scaledDebt);
        collateralToken.transfer(msg.sender, collateralBalance[borrower]);
    }
}
""",
}

# Second vulnerable shape for the same detector: the
# normalized amount comes from rayDiv instead of a `/`
# division, still with no multiply-back.
VULN_LIQ_RAYDIV = _TOKEN_IFACE + """
contract RaacLendingRayDiv {
    IERC20Like public debtToken;
    IERC20Like public collateralToken;
    uint256 public liquidityIndex;
    mapping(address => uint256) public collateralBalance;

    constructor(address _debtToken, address _collateralToken) {
        debtToken = IERC20Like(_debtToken);
        collateralToken = IERC20Like(_collateralToken);
        liquidityIndex = 1e27;
    }

    function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }

    function finalizeLiquidation(address borrower) external {
        uint256 userDebt = rayDiv(debtToken.balanceOf(borrower), liquidityIndex);
        debtToken.burn(borrower, userDebt);
        collateralToken.transfer(msg.sender, collateralBalance[borrower]);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. oft_credit_unclamped_accumulator_underflow
# ---------------------------------------------------------------------------

_OFT_IFACE = """
interface IOFTLike {
    function lzReceive(uint32 srcEid, bytes32 sender, uint64 nonce, bytes calldata payload) external;
}
"""

_OFT_VULN = _TOKEN_IFACE + _OFT_IFACE + """
contract OverlayerOFTVuln is IOFTLike {
    uint256 public totalBridgedOut;

    function _mint(address to, uint256 amount) internal {
    }

    function _credit(address to, uint256 amount, uint32 srcEid) internal {
        totalBridgedOut -= amount;
        _mint(to, amount);
    }

    function lzReceive(uint32 srcEid, bytes32 sender, uint64 nonce, bytes calldata payload) external {
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        _credit(to, amount, srcEid);
    }
}
"""

_OFT_VARIANT = _TOKEN_IFACE + _OFT_IFACE + """
contract OverlayerOFTFixed {
    uint256 public totalBridgedOut;
    address public treasury;

    function _mint(address to, uint256 amount) internal {
    }

    function _credit(address to, uint256 amount, uint32 srcEid) internal {
        totalBridgedOut -= amount;
        _mint(treasury, amount);
    }

    function lzReceive(uint32 srcEid, bytes32 sender, uint64 nonce, bytes calldata payload) external {
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        _credit(to, amount, srcEid);
    }
}
"""

# A >= guard on the accumulator: the credit reverts instead of
# underflowing.
_OFT_CLEAN = _TOKEN_IFACE + _OFT_IFACE + """
contract OverlayerOFTClean is IOFTLike {
    uint256 public totalBridgedOut;

    function _mint(address to, uint256 amount) internal {
    }

    function _credit(address to, uint256 amount, uint32 srcEid) internal {
        require(totalBridgedOut >= amount, "underflow");
        totalBridgedOut -= amount;
        _mint(to, amount);
    }

    function lzReceive(uint32 srcEid, bytes32 sender, uint64 nonce, bytes calldata payload) external {
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        _credit(to, amount, srcEid);
    }
}
"""

_OFT_EXTRA_CLEAN = {
    # The accumulator is clamped with a ternary: it floors at
    # zero instead of underflowing.
    "oft_clamp": _TOKEN_IFACE + _OFT_IFACE + """
contract OverlayerOFTClamp is IOFTLike {
    uint256 public totalBridgedOut;

    function _mint(address to, uint256 amount) internal {
    }

    function _credit(address to, uint256 amount, uint32 srcEid) internal {
        totalBridgedOut = totalBridgedOut >= amount ? totalBridgedOut - amount : 0;
        _mint(to, amount);
    }

    function lzReceive(uint32 srcEid, bytes32 sender, uint64 nonce, bytes calldata payload) external {
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        _credit(to, amount, srcEid);
    }
}
""",
    # The accumulator is initialized on first use: the first
    # credit for a peer sets it instead of subtracting from
    # zero.
    "oft_init": _TOKEN_IFACE + _OFT_IFACE + """
contract OverlayerOFTInit is IOFTLike {
    uint256 public totalBridgedOut;

    function _mint(address to, uint256 amount) internal {
    }

    function _credit(address to, uint256 amount, uint32 srcEid) internal {
        if (totalBridgedOut == 0) {
            totalBridgedOut = amount;
        } else {
            totalBridgedOut -= amount;
        }
        _mint(to, amount);
    }

    function lzReceive(uint32 srcEid, bytes32 sender, uint64 nonce, bytes calldata payload) external {
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        _credit(to, amount, srcEid);
    }
}
""",
    # The same unclamped _credit shape, but the contract
    # carries no OFT / LayerZero marker: not an OFT credit
    # path, so this detector stays silent.
    "oft_no_marker": _TOKEN_IFACE + """
contract BridgeVaultPlain {
    uint256 public totalBridgedOut;

    function _mint(address to, uint256 amount) internal {
    }

    function _credit(address to, uint256 amount, uint32 srcEid) internal {
        totalBridgedOut -= amount;
        _mint(to, amount);
    }
}
""",
}

# ---------------------------------------------------------------------------
# 5. duplicate_array_entries_overwrite_rewards
# ---------------------------------------------------------------------------

_POT_VULN = _TOKEN_IFACE + """
contract PotVuln {
    IERC20Like public rewardToken;
    mapping(address => uint256) public playersToRewards;

    constructor(address[] memory players, uint256[] memory rewards, address _rewardToken) {
        rewardToken = IERC20Like(_rewardToken);
        for (uint256 i = 0; i < players.length; i++) {
            playersToRewards[players[i]] = rewards[i];
        }
    }

    function claimReward() external {
        uint256 reward = playersToRewards[msg.sender];
        playersToRewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, reward);
    }
}
"""

_POT_VARIANT = _TOKEN_IFACE + """
contract PotFixed {
    IERC20Like public rewardToken;
    address public treasury;
    mapping(address => uint256) public playersToRewards;

    constructor(address[] memory players, uint256[] memory rewards, address _rewardToken, address _treasury) {
        rewardToken = IERC20Like(_rewardToken);
        treasury = _treasury;
        for (uint256 i = 0; i < players.length; i++) {
            playersToRewards[players[i]] = rewards[i];
        }
    }

    function claimReward() external {
        uint256 reward = playersToRewards[msg.sender];
        playersToRewards[msg.sender] = 0;
        rewardToken.transfer(treasury, reward);
    }
}
"""

# Accumulation with `+=`: a duplicate address sums its
# rewards instead of overwriting them.
_POT_CLEAN = _TOKEN_IFACE + """
contract PotClean {
    IERC20Like public rewardToken;
    mapping(address => uint256) public playersToRewards;

    constructor(address[] memory players, uint256[] memory rewards, address _rewardToken) {
        rewardToken = IERC20Like(_rewardToken);
        for (uint256 i = 0; i < players.length; i++) {
            playersToRewards[players[i]] += rewards[i];
        }
    }

    function claimReward() external {
        uint256 reward = playersToRewards[msg.sender];
        playersToRewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, reward);
    }
}
"""

_POT_EXTRA_CLEAN = {
    # A seen-set rejects duplicate entries in the loop.
    "pot_seen_check": _TOKEN_IFACE + """
contract PotSeenCheck {
    IERC20Like public rewardToken;
    mapping(address => uint256) public playersToRewards;
    mapping(address => bool) public seen;

    constructor(address[] memory players, uint256[] memory rewards, address _rewardToken) {
        rewardToken = IERC20Like(_rewardToken);
        for (uint256 i = 0; i < players.length; i++) {
            require(!seen[players[i]], "duplicate");
            seen[players[i]] = true;
            playersToRewards[players[i]] = rewards[i];
        }
    }

    function claimReward() external {
        uint256 reward = playersToRewards[msg.sender];
        playersToRewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, reward);
    }
}
""",
    # No loop at all: a single assignment, no parallel arrays.
    "pot_no_loop": _TOKEN_IFACE + """
contract PotNoLoop {
    IERC20Like public rewardToken;
    mapping(address => uint256) public playersToRewards;

    constructor(address player, uint256 reward, address _rewardToken) {
        rewardToken = IERC20Like(_rewardToken);
        playersToRewards[player] = reward;
    }

    function claimReward() external {
        uint256 reward = playersToRewards[msg.sender];
        playersToRewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, reward);
    }
}
""",
    # Parallel-array overwrite, but on a plain scores mapping
    # with no reward / claim context and no payout function:
    # not a reward distribution.
    "pot_non_reward_mapping": _TOKEN_IFACE + """
contract RegistryScores {
    mapping(address => uint256) public scores;

    constructor(address[] memory users, uint256[] memory points) {
        for (uint256 i = 0; i < users.length; i++) {
            scores[users[i]] = points[i];
        }
    }
}
""",
}

VULN = {
    "burn_zero_amount_skips_liquidity_decrement": _BURN_VULN,
    "burn_debits_caller_supplied_address": _BURN_DEBIT_VULN,
    "liquidation_burns_wrong_units_debt": _LIQ_VULN,
    "oft_credit_unclamped_accumulator_underflow": _OFT_VULN,
    "duplicate_array_entries_overwrite_rewards": _POT_VULN,
}

CLEAN = {
    "burn_zero_amount_skips_liquidity_decrement": _BURN_CLEAN,
    "burn_debits_caller_supplied_address": _BURN_DEBIT_CLEAN,
    "liquidation_burns_wrong_units_debt": _LIQ_CLEAN,
    "oft_credit_unclamped_accumulator_underflow": _OFT_CLEAN,
    "duplicate_array_entries_overwrite_rewards": _POT_CLEAN,
}

VARIANT = {
    "burn_zero_amount_skips_liquidity_decrement": _BURN_VARIANT,
    "burn_debits_caller_supplied_address": _BURN_DEBIT_VARIANT,
    "liquidation_burns_wrong_units_debt": _LIQ_VARIANT,
    "oft_credit_unclamped_accumulator_underflow": _OFT_VARIANT,
    "duplicate_array_entries_overwrite_rewards": _POT_VARIANT,
}

EXTRA_CLEAN = {}
EXTRA_CLEAN.update(_BURN_EXTRA_CLEAN)
EXTRA_CLEAN.update(_BURN_DEBIT_EXTRA_CLEAN)
EXTRA_CLEAN.update(_LIQ_EXTRA_CLEAN)
EXTRA_CLEAN.update(_OFT_EXTRA_CLEAN)
EXTRA_CLEAN.update(_POT_EXTRA_CLEAN)
