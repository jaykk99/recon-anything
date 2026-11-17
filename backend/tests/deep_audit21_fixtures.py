"""Fixtures for the deep-audit batch-21 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and gate analysis; CLEAN[id] (the protected shape
of the same class) MUST stay silent under ALL five detectors;
VARIANT[id] carries the same vulnerable shape but the value
lands at a FIXED destination, so it MUST fire with
report_class "trigger_only" at low severity - never a
candidate. redeem_burns_shares_for_zero_assets has no VARIANT:
the caller themself is the victim, so its VULN fixture fires
HOLDER-SELF / trigger-only at low severity by construction.

Cross-talk by construction: the oracle fixture has no lockbook,
no rescue, no checkpoint and no redeem() function; the
lockbook fixture has no oracle, no rescue, no checkpoint and
no redeem() function; the rescue fixture has no oracle, no
lockbook, no checkpoint and no redeem() function; the
checkpoint fixture has no oracle, no lockbook, no rescue and
no redeem() function; the redeem fixture has no oracle, no
lockbook, no rescue and no checkpoint.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. oracle_twap_fallback_to_spot (CoreVault, 2026-11-03)
# ---------------------------------------------------------------------------

_ORACLE_VULN = _TOKEN_IFACE + """
contract CoreVaultVuln {
    IERC20Like public token;
    address public pair;
    mapping(address => uint256) public principalBalance;

    constructor(address _token, address _pair) {
        token = IERC20Like(_token);
        pair = _pair;
    }

    function _getTwapPrice() internal view returns (uint256) {
        uint32[] memory secondsAgo = new uint32[](2);
        secondsAgo[0] = 3600;
        secondsAgo[1] = 0;
        (int56[] memory tickCumulatives,) = IUniswapV3Pool(pair).observe(secondsAgo);
        return uint256(int256(tickCumulatives[1] - tickCumulatives[0]));
    }

    function getPrice() public view returns (uint256) {
        uint256 twapPrice = _getTwapPrice();
        if (twapPrice == 0) {
            // TWAP window not populated yet: fallback to spot price.
            (uint256 r0, uint256 r1,) = IPancakePair(pair).getReserves();
            return r0 * 1e18 / r1;
        }
        return twapPrice;
    }

    function redeemPrincipal(uint256 shares) external {
        uint256 price = getPrice();
        uint256 amount = shares * price / 1e18;
        principalBalance[msg.sender] -= shares;
        token.transfer(msg.sender, amount);
    }
}

interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
}

interface IPancakePair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}
"""

_ORACLE_VARIANT = _TOKEN_IFACE + """
contract CoreVaultFixed {
    IERC20Like public token;
    address public pair;
    address public treasury;
    mapping(address => uint256) public principalBalance;

    constructor(address _token, address _pair, address _treasury) {
        token = IERC20Like(_token);
        pair = _pair;
        treasury = _treasury;
    }

    function _getTwapPrice() internal view returns (uint256) {
        uint32[] memory secondsAgo = new uint32[](2);
        secondsAgo[0] = 3600;
        secondsAgo[1] = 0;
        (int56[] memory tickCumulatives,) = IUniswapV3Pool(pair).observe(secondsAgo);
        return uint256(int256(tickCumulatives[1] - tickCumulatives[0]));
    }

    function getPrice() public view returns (uint256) {
        uint256 twapPrice = _getTwapPrice();
        if (twapPrice == 0) {
            // TWAP window not populated yet: fallback to spot price.
            (uint256 r0, uint256 r1,) = IPancakePair(pair).getReserves();
            return r0 * 1e18 / r1;
        }
        return twapPrice;
    }

    function redeemPrincipal(uint256 shares) external {
        uint256 price = getPrice();
        uint256 amount = shares * price / 1e18;
        principalBalance[msg.sender] -= shares;
        token.transfer(treasury, amount);
    }
}

interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
}

interface IPancakePair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}
"""

_ORACLE_CLEAN = _TOKEN_IFACE + """
contract CoreVaultClean {
    IERC20Like public token;
    address public pair;
    mapping(address => uint256) public principalBalance;

    constructor(address _token, address _pair) {
        token = IERC20Like(_token);
        pair = _pair;
    }

    function _getTwapPrice() internal view returns (uint256) {
        uint32[] memory secondsAgo = new uint32[](2);
        secondsAgo[0] = 3600;
        secondsAgo[1] = 0;
        (int56[] memory tickCumulatives,) = IUniswapV3Pool(pair).observe(secondsAgo);
        return uint256(int256(tickCumulatives[1] - tickCumulatives[0]));
    }

    function getPrice() public view returns (uint256) {
        return _getTwapPrice();
    }

    function redeemPrincipal(uint256 shares) external {
        uint256 price = getPrice();
        uint256 amount = shares * price / 1e18;
        principalBalance[msg.sender] -= shares;
        token.transfer(msg.sender, amount);
    }
}

interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
}
"""

_ORACLE_EXTRA_CLEAN = _TOKEN_IFACE + """
contract CoreVaultGuarded {
    IERC20Like public token;
    address public pair;
    mapping(address => uint256) public principalBalance;

    constructor(address _token, address _pair) {
        token = IERC20Like(_token);
        pair = _pair;
    }

    function _getTwapPrice() internal view returns (uint256) {
        uint32[] memory secondsAgo = new uint32[](2);
        secondsAgo[0] = 3600;
        secondsAgo[1] = 0;
        (int56[] memory tickCumulatives,) = IUniswapV3Pool(pair).observe(secondsAgo);
        return uint256(int256(tickCumulatives[1] - tickCumulatives[0]));
    }

    function getPrice() public view returns (uint256) {
        uint256 twapPrice = _getTwapPrice();
        require(twapPrice > 0, "TWAP not ready");
        return twapPrice;
    }

    function quoteSpot() public view returns (uint256) {
        (uint256 r0, uint256 r1,) = IPancakePair(pair).getReserves();
        return r0 * 1e18 / r1;
    }

    function redeemPrincipal(uint256 shares) external {
        uint256 price = getPrice();
        uint256 amount = shares * price / 1e18;
        principalBalance[msg.sender] -= shares;
        token.transfer(msg.sender, amount);
    }
}

interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128s);
}

interface IPancakePair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
}
"""

# ---------------------------------------------------------------------------
# 2. erc4626_lockbook_share_transfer_desync (Belong #57399/#57685)
# ---------------------------------------------------------------------------

_LOCKBOOK_VULN = _TOKEN_IFACE + """
contract LockVaultVuln {
    IERC20Like public token;
    uint256 public constant LOCK = 30 days;

    struct Stake {
        uint256 amount;
        uint256 unlockTime;
    }

    mapping(address => Stake[]) public stakes;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function deposit(uint256 assets) external {
        token.transferFrom(msg.sender, address(this), assets);
        stakes[msg.sender].push(Stake({amount: assets, unlockTime: block.timestamp + LOCK}));
        balances[msg.sender] += assets;
        totalSupply += assets;
    }

    function withdraw(uint256 amount) external {
        uint256 unlocked = 0;
        Stake[] storage mine = stakes[msg.sender];
        for (uint256 i = 0; i < mine.length; i++) {
            if (mine[i].unlockTime <= block.timestamp) {
                unlocked += mine[i].amount;
            }
        }
        require(unlocked >= amount, "locked");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        token.transfer(msg.sender, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
}
"""

_LOCKBOOK_VARIANT = _TOKEN_IFACE + """
contract LockVaultFixed {
    IERC20Like public token;
    address public rewardPool;
    uint256 public constant LOCK = 30 days;

    struct Stake {
        uint256 amount;
        uint256 unlockTime;
    }

    mapping(address => Stake[]) public stakes;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor(address _pool) {
        rewardPool = _pool;
    }

    function deposit(uint256 assets) external {
        token.transferFrom(msg.sender, address(this), assets);
        stakes[msg.sender].push(Stake({amount: assets, unlockTime: block.timestamp + LOCK}));
        balances[msg.sender] += assets;
        totalSupply += assets;
    }

    function withdraw(uint256 amount) external {
        uint256 unlocked = 0;
        Stake[] storage mine = stakes[msg.sender];
        for (uint256 i = 0; i < mine.length; i++) {
            if (mine[i].unlockTime <= block.timestamp) {
                unlocked += mine[i].amount;
            }
        }
        require(unlocked >= amount, "locked");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        token.transfer(msg.sender, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(to == rewardPool, "only pool");
        balances[msg.sender] -= amount;
        balances[rewardPool] += amount;
        return true;
    }
}
"""

_LOCKBOOK_CLEAN = _TOKEN_IFACE + """
contract LockVaultClean {
    IERC20Like public token;
    uint256 public constant LOCK = 30 days;

    struct Stake {
        uint256 amount;
        uint256 unlockTime;
    }

    mapping(address => Stake[]) public stakes;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function deposit(uint256 assets) external {
        token.transferFrom(msg.sender, address(this), assets);
        stakes[msg.sender].push(Stake({amount: assets, unlockTime: block.timestamp + LOCK}));
        balances[msg.sender] += assets;
        totalSupply += assets;
    }

    function withdraw(uint256 amount) external {
        uint256 unlocked = 0;
        Stake[] storage mine = stakes[msg.sender];
        for (uint256 i = 0; i < mine.length; i++) {
            if (mine[i].unlockTime <= block.timestamp) {
                unlocked += mine[i].amount;
            }
        }
        require(unlocked >= amount, "locked");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        token.transfer(msg.sender, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        Stake[] storage mine = stakes[msg.sender];
        for (uint256 i = 0; i < mine.length; i++) {
            stakes[to].push(mine[i]);
        }
        delete stakes[msg.sender];
        return true;
    }
}
"""

_LOCKBOOK_EXTRA_CLEAN_NONTRANSFERABLE = _TOKEN_IFACE + """
contract LockVaultNonTransferable {
    IERC20Like public token;
    uint256 public constant LOCK = 30 days;

    struct Stake {
        uint256 amount;
        uint256 unlockTime;
    }

    mapping(address => Stake[]) public stakes;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function deposit(uint256 assets) external {
        token.transferFrom(msg.sender, address(this), assets);
        stakes[msg.sender].push(Stake({amount: assets, unlockTime: block.timestamp + LOCK}));
        balances[msg.sender] += assets;
        totalSupply += assets;
    }

    function withdraw(uint256 amount) external {
        uint256 unlocked = 0;
        Stake[] storage mine = stakes[msg.sender];
        for (uint256 i = 0; i < mine.length; i++) {
            if (mine[i].unlockTime <= block.timestamp) {
                unlocked += mine[i].amount;
            }
        }
        require(unlocked >= amount, "locked");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        token.transfer(msg.sender, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        revert("shares non-transferable");
    }
}
"""

_LOCKBOOK_EXTRA_CLEAN_PLAIN = _TOKEN_IFACE + """
contract PlainVault {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    function deposit(uint256 assets) external {
        token.transferFrom(msg.sender, address(this), assets);
        balances[msg.sender] += assets;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. rescue_marks_future_bucket_claimed (Firelight #88231)
# ---------------------------------------------------------------------------

_RESCUE_VULN = _TOKEN_IFACE + """
contract BucketVaultVuln {
    IERC20Like public token;
    mapping(uint256 => mapping(address => bool)) public isWithdrawClaimed;
    mapping(uint256 => mapping(address => uint256)) public withdrawAssets;
    mapping(address => uint256) public shares;
    address public rescuer;

    constructor(address _token, address _rescuer) {
        token = IERC20Like(_token);
        rescuer = _rescuer;
    }

    modifier onlyRescuer() {
        require(msg.sender == rescuer, "not rescuer");
        _;
    }

    function currentPeriod() public view returns (uint256) {
        return block.timestamp / 1 days;
    }

    function requestWithdraw(uint256 _shares) external {
        shares[msg.sender] -= _shares;
        withdrawAssets[currentPeriod() + 1][msg.sender] += _shares;
    }

    function claimWithdraw(uint256 period) external {
        require(period < currentPeriod(), "not elapsed");
        require(!isWithdrawClaimed[period][msg.sender], "AlreadyClaimedPeriod");
        isWithdrawClaimed[period][msg.sender] = true;
        uint256 amount = withdrawAssets[period][msg.sender];
        withdrawAssets[period][msg.sender] = 0;
        token.transfer(msg.sender, amount);
    }

    function rescueWithdrawFromBlocklisted(address account, address safeAddress, uint256[] calldata periods) external onlyRescuer {
        for (uint256 i = 0; i < periods.length; i++) {
            uint256 amount = withdrawAssets[periods[i]][account];
            withdrawAssets[periods[i]][account] = 0;
            isWithdrawClaimed[periods[i]][account] = true;
            token.transfer(safeAddress, amount);
        }
    }
}
"""

_RESCUE_VARIANT = _TOKEN_IFACE + """
contract BucketVaultFixed {
    IERC20Like public token;
    mapping(uint256 => mapping(address => bool)) public isWithdrawClaimed;
    mapping(uint256 => mapping(address => uint256)) public withdrawAssets;
    mapping(address => uint256) public shares;
    address public rescuer;
    address public recoveryVault;

    constructor(address _token, address _rescuer, address _vault) {
        token = IERC20Like(_token);
        rescuer = _rescuer;
        recoveryVault = _vault;
    }

    modifier onlyRescuer() {
        require(msg.sender == rescuer, "not rescuer");
        _;
    }

    function currentPeriod() public view returns (uint256) {
        return block.timestamp / 1 days;
    }

    function requestWithdraw(uint256 _shares) external {
        shares[msg.sender] -= _shares;
        withdrawAssets[currentPeriod() + 1][msg.sender] += _shares;
    }

    function claimWithdraw(uint256 period) external {
        require(period < currentPeriod(), "not elapsed");
        require(!isWithdrawClaimed[period][msg.sender], "AlreadyClaimedPeriod");
        isWithdrawClaimed[period][msg.sender] = true;
        uint256 amount = withdrawAssets[period][msg.sender];
        withdrawAssets[period][msg.sender] = 0;
        token.transfer(msg.sender, amount);
    }

    function rescueWithdrawFromBlocklisted(address account, address safeAddress, uint256[] calldata periods) external onlyRescuer {
        for (uint256 i = 0; i < periods.length; i++) {
            uint256 amount = withdrawAssets[periods[i]][account];
            withdrawAssets[periods[i]][account] = 0;
            isWithdrawClaimed[periods[i]][account] = true;
            token.transfer(recoveryVault, amount);
        }
    }
}
"""

_RESCUE_CLEAN = _TOKEN_IFACE + """
contract BucketVaultClean {
    IERC20Like public token;
    mapping(uint256 => mapping(address => bool)) public isWithdrawClaimed;
    mapping(uint256 => mapping(address => uint256)) public withdrawAssets;
    mapping(address => uint256) public shares;
    address public rescuer;

    constructor(address _token, address _rescuer) {
        token = IERC20Like(_token);
        rescuer = _rescuer;
    }

    modifier onlyRescuer() {
        require(msg.sender == rescuer, "not rescuer");
        _;
    }

    function currentPeriod() public view returns (uint256) {
        return block.timestamp / 1 days;
    }

    function requestWithdraw(uint256 _shares) external {
        shares[msg.sender] -= _shares;
        withdrawAssets[currentPeriod() + 1][msg.sender] += _shares;
    }

    function claimWithdraw(uint256 period) external {
        require(period < currentPeriod(), "not elapsed");
        require(!isWithdrawClaimed[period][msg.sender], "AlreadyClaimedPeriod");
        isWithdrawClaimed[period][msg.sender] = true;
        uint256 amount = withdrawAssets[period][msg.sender];
        withdrawAssets[period][msg.sender] = 0;
        token.transfer(msg.sender, amount);
    }

    function rescueWithdrawFromBlocklisted(address account, address safeAddress, uint256[] calldata periods) external onlyRescuer {
        for (uint256 i = 0; i < periods.length; i++) {
            require(periods[i] < currentPeriod(), "not elapsed");
            uint256 amount = withdrawAssets[periods[i]][account];
            withdrawAssets[periods[i]][account] = 0;
            isWithdrawClaimed[periods[i]][account] = true;
            token.transfer(safeAddress, amount);
        }
    }
}
"""

_RESCUE_EXTRA_CLEAN_NO_FLAG = _TOKEN_IFACE + """
contract BucketVaultNoFlag {
    IERC20Like public token;
    mapping(uint256 => mapping(address => bool)) public isWithdrawClaimed;
    mapping(uint256 => mapping(address => uint256)) public withdrawAssets;
    mapping(address => uint256) public shares;
    address public rescuer;

    constructor(address _token, address _rescuer) {
        token = IERC20Like(_token);
        rescuer = _rescuer;
    }

    modifier onlyRescuer() {
        require(msg.sender == rescuer, "not rescuer");
        _;
    }

    function currentPeriod() public view returns (uint256) {
        return block.timestamp / 1 days;
    }

    function requestWithdraw(uint256 _shares) external {
        shares[msg.sender] -= _shares;
        withdrawAssets[currentPeriod() + 1][msg.sender] += _shares;
    }

    function claimWithdraw(uint256 period) external {
        require(period < currentPeriod(), "not elapsed");
        require(!isWithdrawClaimed[period][msg.sender], "AlreadyClaimedPeriod");
        isWithdrawClaimed[period][msg.sender] = true;
        uint256 amount = withdrawAssets[period][msg.sender];
        withdrawAssets[period][msg.sender] = 0;
        token.transfer(msg.sender, amount);
    }

    function rescueWithdrawFromBlocklisted(address account, address safeAddress, uint256[] calldata periods) external onlyRescuer {
        for (uint256 i = 0; i < periods.length; i++) {
            uint256 amount = withdrawAssets[periods[i]][account];
            withdrawAssets[periods[i]][account] = 0;
            token.transfer(safeAddress, amount);
        }
    }
}
"""

# ---------------------------------------------------------------------------
# 4. period_start_checkpoint_zeroes_payout_cap (Firelight #88287)
# ---------------------------------------------------------------------------

_CHECKPOINT_VULN = _TOKEN_IFACE + """
contract PeriodVaultVuln {
    IERC20Like public token;
    mapping(address => uint256) public shares;
    uint256 public totalAssets;
    uint256 public totalSupply;

    struct Trace {
        uint256 key;
        uint256 value;
    }

    Trace[] public traces;

    function currentPeriodStart() public view returns (uint256) {
        return block.timestamp - (block.timestamp % 1 days);
    }

    function _burn(address from, uint256 amount) internal {
        shares[from] -= amount;
        totalSupply -= amount;
    }

    function _logTrace(uint256 key, uint256 value) internal {
        traces.push(Trace(key, value));
    }

    function totalAssetsAt(uint256 key) public view returns (uint256) {
        return upperLookupRecent(traces, key);
    }

    function upperLookupRecent(Trace[] storage _traces, uint256 key) internal view returns (uint256) {
        uint256 result = 0;
        for (uint256 i = 0; i < _traces.length; i++) {
            if (_traces[i].key <= key) {
                result = _traces[i].value;
            }
        }
        return result;
    }

    function withdraw(uint256 sharesAmount) external {
        _burn(msg.sender, sharesAmount);
        _logTrace(block.timestamp, totalAssets);
    }

    function payout(address claimant, uint256 amount) external {
        uint256 cap = totalAssetsAt(currentPeriodStart());
        uint256 payable = min(amount, cap);
        token.transfer(claimant, payable);
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
"""

_CHECKPOINT_VARIANT = _TOKEN_IFACE + """
contract PeriodVaultFixed {
    IERC20Like public token;
    mapping(address => uint256) public shares;
    address public beneficiary;
    uint256 public totalAssets;
    uint256 public totalSupply;

    struct Trace {
        uint256 key;
        uint256 value;
    }

    Trace[] public traces;

    constructor(address _beneficiary) {
        beneficiary = _beneficiary;
    }

    function currentPeriodStart() public view returns (uint256) {
        return block.timestamp - (block.timestamp % 1 days);
    }

    function _burn(address from, uint256 amount) internal {
        shares[from] -= amount;
        totalSupply -= amount;
    }

    function _logTrace(uint256 key, uint256 value) internal {
        traces.push(Trace(key, value));
    }

    function totalAssetsAt(uint256 key) public view returns (uint256) {
        return upperLookupRecent(traces, key);
    }

    function upperLookupRecent(Trace[] storage _traces, uint256 key) internal view returns (uint256) {
        uint256 result = 0;
        for (uint256 i = 0; i < _traces.length; i++) {
            if (_traces[i].key <= key) {
                result = _traces[i].value;
            }
        }
        return result;
    }

    function withdraw(uint256 sharesAmount) external {
        _burn(msg.sender, sharesAmount);
        _logTrace(block.timestamp, totalAssets);
    }

    function payout(address claimant, uint256 amount) external {
        uint256 cap = totalAssetsAt(currentPeriodStart());
        uint256 payable = min(amount, cap);
        token.transfer(beneficiary, payable);
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
"""

_CHECKPOINT_CLEAN = _TOKEN_IFACE + """
contract PeriodVaultClean {
    IERC20Like public token;
    mapping(address => uint256) public shares;
    uint256 public totalAssets;
    uint256 public totalSupply;

    struct Trace {
        uint256 key;
        uint256 value;
    }

    Trace[] public traces;

    function currentPeriodStart() public view returns (uint256) {
        return block.timestamp - (block.timestamp % 1 days);
    }

    function _burn(address from, uint256 amount) internal {
        shares[from] -= amount;
        totalSupply -= amount;
    }

    function _logTrace(uint256 key, uint256 value) internal {
        traces.push(Trace(key, value));
    }

    function totalAssetsAt(uint256 key) public view returns (uint256) {
        return upperLookupRecent(traces, key);
    }

    function upperLookupRecent(Trace[] storage _traces, uint256 key) internal view returns (uint256) {
        uint256 result = 0;
        for (uint256 i = 0; i < _traces.length; i++) {
            if (_traces[i].key <= key) {
                result = _traces[i].value;
            }
        }
        return result;
    }

    function withdraw(uint256 sharesAmount) external {
        _logTrace(block.timestamp, totalAssets);
        _burn(msg.sender, sharesAmount);
    }

    function payout(address claimant, uint256 amount) external {
        uint256 cap = totalAssetsAt(currentPeriodStart());
        uint256 payable = min(amount, cap);
        token.transfer(claimant, payable);
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
"""

_CHECKPOINT_EXTRA_CLEAN_EXCLUSIVE = _TOKEN_IFACE + """
contract PeriodVaultExclusive {
    IERC20Like public token;
    mapping(address => uint256) public shares;
    uint256 public totalAssets;
    uint256 public totalSupply;

    struct Trace {
        uint256 key;
        uint256 value;
    }

    Trace[] public traces;

    function currentPeriodStart() public view returns (uint256) {
        return block.timestamp - (block.timestamp % 1 days);
    }

    function _burn(address from, uint256 amount) internal {
        shares[from] -= amount;
        totalSupply -= amount;
    }

    function _logTrace(uint256 key, uint256 value) internal {
        traces.push(Trace(key, value));
    }

    function lowerLookup(Trace[] storage _traces, uint256 key) internal view returns (uint256) {
        uint256 result = 0;
        for (uint256 i = 0; i < _traces.length; i++) {
            if (_traces[i].key < key) {
                result = _traces[i].value;
            }
        }
        return result;
    }

    function withdraw(uint256 sharesAmount) external {
        _burn(msg.sender, sharesAmount);
        _logTrace(block.timestamp, totalAssets);
    }

    function payout(address claimant, uint256 amount) external {
        uint256 cap = lowerLookup(traces, currentPeriodStart());
        uint256 payable = min(amount, cap);
        token.transfer(claimant, payable);
    }

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}
"""

# ---------------------------------------------------------------------------
# 5. redeem_burns_shares_for_zero_assets (Firelight #88269)
# ---------------------------------------------------------------------------

_REDEEM_VULN = _TOKEN_IFACE + """
contract RedeemVaultVuln {
    IERC20Like public token;
    mapping(address => uint256) public shares;
    mapping(uint256 => mapping(address => uint256)) public withdrawAssets;
    mapping(uint256 => mapping(address => uint256)) public withdrawShares;
    uint256 public totalAssets;
    uint256 public totalSupply;

    function currentPeriod() public view returns (uint256) {
        return block.timestamp / 1 days;
    }

    function deposit(uint256 assets) external returns (uint256) {
        uint256 sharesMinted = assets * totalSupply / totalAssets;
        require(sharesMinted > 0, "zero shares");
        shares[msg.sender] += sharesMinted;
        totalSupply += sharesMinted;
        return sharesMinted;
    }

    function _burn(address from, uint256 amount) internal {
        shares[from] -= amount;
        totalSupply -= amount;
    }

    function redeem(uint256 shares) external {
        require(shares > 0, "zero shares");
        uint256 assets = shares * totalAssets / totalSupply;
        _burn(msg.sender, shares);
        withdrawAssets[currentPeriod()][msg.sender] += assets;
        withdrawShares[currentPeriod()][msg.sender] += shares;
    }
}
"""

_REDEEM_CLEAN = _TOKEN_IFACE + """
contract RedeemVaultClean {
    IERC20Like public token;
    mapping(address => uint256) public shares;
    mapping(uint256 => mapping(address => uint256)) public withdrawAssets;
    mapping(uint256 => mapping(address => uint256)) public withdrawShares;
    uint256 public totalAssets;
    uint256 public totalSupply;

    function currentPeriod() public view returns (uint256) {
        return block.timestamp / 1 days;
    }

    function deposit(uint256 assets) external returns (uint256) {
        uint256 sharesMinted = assets * totalSupply / totalAssets;
        require(sharesMinted > 0, "zero shares");
        shares[msg.sender] += sharesMinted;
        totalSupply += sharesMinted;
        return sharesMinted;
    }

    function _burn(address from, uint256 amount) internal {
        shares[from] -= amount;
        totalSupply -= amount;
    }

    function redeem(uint256 shares) external {
        require(shares > 0, "zero shares");
        uint256 assets = shares * totalAssets / totalSupply;
        if (assets == 0) revert InvalidAmount();
        _burn(msg.sender, shares);
        withdrawAssets[currentPeriod()][msg.sender] += assets;
        withdrawShares[currentPeriod()][msg.sender] += shares;
    }
}
"""

_REDEEM_EXTRA_CLEAN_NO_ASYMMETRY = _TOKEN_IFACE + """
contract RedeemVaultNoGuard {
    IERC20Like public token;
    mapping(address => uint256) public shares;
    mapping(uint256 => mapping(address => uint256)) public withdrawAssets;
    mapping(uint256 => mapping(address => uint256)) public withdrawShares;
    uint256 public totalAssets;
    uint256 public totalSupply;

    function currentPeriod() public view returns (uint256) {
        return block.timestamp / 1 days;
    }

    function deposit(uint256 assets) external returns (uint256) {
        uint256 sharesMinted = assets * totalSupply / totalAssets;
        shares[msg.sender] += sharesMinted;
        totalSupply += sharesMinted;
        return sharesMinted;
    }

    function _burn(address from, uint256 amount) internal {
        shares[from] -= amount;
        totalSupply -= amount;
    }

    function redeem(uint256 shares) external {
        require(shares > 0, "zero shares");
        uint256 assets = shares * totalAssets / totalSupply;
        _burn(msg.sender, shares);
        withdrawAssets[currentPeriod()][msg.sender] += assets;
        withdrawShares[currentPeriod()][msg.sender] += shares;
    }
}
"""

VULN = {
    "oracle_twap_fallback_to_spot": _ORACLE_VULN,
    "erc4626_lockbook_share_transfer_desync": _LOCKBOOK_VULN,
    "rescue_marks_future_bucket_claimed": _RESCUE_VULN,
    "period_start_checkpoint_zeroes_payout_cap": _CHECKPOINT_VULN,
    "redeem_burns_shares_for_zero_assets": _REDEEM_VULN,
}

VARIANT = {
    "oracle_twap_fallback_to_spot": _ORACLE_VARIANT,
    "erc4626_lockbook_share_transfer_desync": _LOCKBOOK_VARIANT,
    "rescue_marks_future_bucket_claimed": _RESCUE_VARIANT,
    "period_start_checkpoint_zeroes_payout_cap": _CHECKPOINT_VARIANT,
}

CLEAN = {
    "oracle_twap_fallback_to_spot": _ORACLE_CLEAN,
    "erc4626_lockbook_share_transfer_desync": _LOCKBOOK_CLEAN,
    "rescue_marks_future_bucket_claimed": _RESCUE_CLEAN,
    "period_start_checkpoint_zeroes_payout_cap": _CHECKPOINT_CLEAN,
    "redeem_burns_shares_for_zero_assets": _REDEEM_CLEAN,
}

EXTRA_CLEAN = {
    "oracle_twap_fallback_guarded": _ORACLE_EXTRA_CLEAN,
    "lockbook_non_transferable": _LOCKBOOK_EXTRA_CLEAN_NONTRANSFERABLE,
    "lockbook_plain_vault": _LOCKBOOK_EXTRA_CLEAN_PLAIN,
    "rescue_no_flag_write": _RESCUE_EXTRA_CLEAN_NO_FLAG,
    "checkpoint_exclusive_lookup": _CHECKPOINT_EXTRA_CLEAN_EXCLUSIVE,
    "redeem_no_asymmetry": _REDEEM_EXTRA_CLEAN_NO_ASYMMETRY,
}
