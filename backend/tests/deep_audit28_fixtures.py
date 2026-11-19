"""Fixtures for the deep-audit batch-28 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" (the four recipient
detectors); the period-exit detector fires without a candidate
classification (batch-20 auction precedent: the exit pays the
caller's own balance - the stranger-receivable value is the
short-paid claim the desync enables, not the exit). CLEAN[id]
(the protected shape of the same class) MUST stay silent under
ALL five detectors; VARIANT[id] carries the same vulnerable
shape but the value lands at a FIXED destination, so it MUST
fire with report_class "trigger_only" at low severity - never a
candidate (no variant for the period-exit detector: it carries
no recipient classification at all).

Cross-talk by construction: the snapshot fixture syncs a
position and withdraws it but names no swap / claim / voucher /
valuation / period function and verifies no signature; the
share-price fixture values a vault and redeems it but names no
sync / voucher / period function, verifies no signature, and
its deposit measures the received balance delta (so the
fee-on-transfer detector stays silent) and carries a dead-share
bootstrap (so vault_share_inflation stays silent); the voucher
fixture redeems a signed voucher but names no sync / swap /
valuation / period function, takes no account parameter, and
compares the recovered signer against a stored authorized
signer (so the recipient-unbacked-claim detector stays silent);
the period-exit fixture exits and claims cover but names no
sync / voucher / valuation function, burns no shares, and its
claim uses no checkpoint lookup; the withdraw-other fixture
withdraws another account's balance but names no sync /
voucher / valuation / period function and verifies no
signature. DOCUMENTED CO-FIRE: recipient_overdraw_withdraw
fires on the withdraw-other VULN fixture by design - the
payout is not bounded by the CALLER's balance (it is bounded
by the VICTIM's), which is the hole from the boundedness
angle; the new detector adds the authorization dimension the
overdraw detector cannot express. That co-fire is pinned
explicitly in the test, not pretended silent.
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
# 1. snapshot_position_sync_caller_writable
# ---------------------------------------------------------------------------

_SYNC_VULN = _TOKEN_IFACE + """
contract SnapshotSyncVuln {
    IERC20Like public token;
    mapping(address => uint256) public positions;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function syncInvestor(address investor, uint256 newPosition) external {
        positions[investor] = newPosition;
    }

    function withdraw(uint256 amount) external {
        require(amount <= positions[msg.sender], "insufficient position");
        positions[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_SYNC_VARIANT = _TOKEN_IFACE + """
contract SnapshotSyncFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => uint256) public positions;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function syncInvestor(address investor, uint256 newPosition) external {
        positions[investor] = newPosition;
    }

    function withdraw(uint256 amount) external {
        require(amount <= positions[msg.sender], "insufficient position");
        positions[msg.sender] -= amount;
        token.transfer(treasury, amount);
    }
}
"""

# The sync recomputes the position from the pool's own state.
_SYNC_CLEAN = _TOKEN_IFACE + """
contract SnapshotSyncClean {
    IERC20Like public token;
    IERC20Like public pool;
    mapping(address => uint256) public positions;

    constructor(address _token, address _pool) {
        token = IERC20Like(_token);
        pool = IERC20Like(_pool);
    }

    function syncInvestor(address investor) external {
        positions[investor] = pool.balanceOf(investor);
    }

    function withdraw(uint256 amount) external {
        require(amount <= positions[msg.sender], "insufficient position");
        positions[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# Owner-gated sync: a stranger cannot reach the path.
_SYNC_GATED = _TOKEN_IFACE + """
contract SnapshotSyncGated {
    IERC20Like public token;
    address public owner;
    mapping(address => uint256) public positions;

    constructor(address _token, address _owner) {
        token = IERC20Like(_token);
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function syncInvestor(address investor, uint256 newPosition) external onlyOwner {
        positions[investor] = newPosition;
    }

    function withdraw(uint256 amount) external {
        require(amount <= positions[msg.sender], "insufficient position");
        positions[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# The sync recomputes through an internal helper, not a caller value.
_SYNC_RECOMPUTE_INTERNAL = _TOKEN_IFACE + """
contract SnapshotSyncRecompute {
    IERC20Like public token;
    IERC20Like public pool;
    mapping(address => uint256) public positions;

    constructor(address _token, address _pool) {
        token = IERC20Like(_token);
        pool = IERC20Like(_pool);
    }

    function _positionOf(address investor) internal view returns (uint256) {
        return pool.balanceOf(investor);
    }

    function syncInvestor(address investor) external {
        positions[investor] = _positionOf(investor);
    }

    function withdraw(uint256 amount) external {
        require(amount <= positions[msg.sender], "insufficient position");
        positions[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# A caller-writable sync with no downstream payout: out of scope.
_SYNC_NO_PAYOUT = """
contract SnapshotSyncNoPayout {
    mapping(address => uint256) public positions;

    function syncInvestor(address investor, uint256 newPosition) external {
        positions[investor] = newPosition;
    }
}
"""

# ---------------------------------------------------------------------------
# 2. share_price_excludes_subthreshold_collateral
# ---------------------------------------------------------------------------

_SHARE_VULN = _TOKEN_IFACE + """
contract SubthresholdVaultVuln {
    IERC20Like public bold;
    IERC20Like public weth;
    uint256 public constant MIN_WETH = 1e15;
    uint256 public wethPrice = 3000 * 1e18;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;

    constructor(address _bold, address _weth) {
        bold = IERC20Like(_bold);
        weth = IERC20Like(_weth);
        _mint(address(0), 1000);
        totalSupply = 1000;
    }

    function _mint(address to, uint256 amount) internal {
        shares[to] += amount;
        totalSupply += amount;
    }

    function totalAssets() public view returns (uint256) {
        uint256 boldBal = bold.balanceOf(address(this));
        uint256 wethBal = weth.balanceOf(address(this));
        uint256 total = boldBal;
        if (wethBal > MIN_WETH) {
            total += wethBal * wethPrice / 1e18;
        }
        return total;
    }

    function deposit(uint256 amount) external {
        uint256 before = bold.balanceOf(address(this));
        bold.transferFrom(msg.sender, address(this), amount);
        uint256 received = bold.balanceOf(address(this)) - before;
        uint256 shareAmount = received * totalSupply / totalAssets();
        _mint(msg.sender, shareAmount);
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(msg.sender, assets);
    }
}
"""

_SHARE_VARIANT = _TOKEN_IFACE + """
contract SubthresholdVaultFixed {
    IERC20Like public bold;
    IERC20Like public weth;
    address public treasury;
    uint256 public constant MIN_WETH = 1e15;
    uint256 public wethPrice = 3000 * 1e18;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;

    constructor(address _bold, address _weth, address _treasury) {
        bold = IERC20Like(_bold);
        weth = IERC20Like(_weth);
        treasury = _treasury;
        _mint(address(0), 1000);
        totalSupply = 1000;
    }

    function _mint(address to, uint256 amount) internal {
        shares[to] += amount;
        totalSupply += amount;
    }

    function totalAssets() public view returns (uint256) {
        uint256 boldBal = bold.balanceOf(address(this));
        uint256 wethBal = weth.balanceOf(address(this));
        uint256 total = boldBal;
        if (wethBal > MIN_WETH) {
            total += wethBal * wethPrice / 1e18;
        }
        return total;
    }

    function deposit(uint256 amount) external {
        uint256 before = bold.balanceOf(address(this));
        bold.transferFrom(msg.sender, address(this), amount);
        uint256 received = bold.balanceOf(address(this)) - before;
        uint256 shareAmount = received * totalSupply / totalAssets();
        _mint(msg.sender, shareAmount);
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(treasury, assets);
    }
}
"""

# Every held leg is summed unconditionally: protected shape.
_SHARE_CLEAN = _TOKEN_IFACE + """
contract SubthresholdVaultClean {
    IERC20Like public bold;
    IERC20Like public weth;
    uint256 public wethPrice = 3000 * 1e18;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;

    constructor(address _bold, address _weth) {
        bold = IERC20Like(_bold);
        weth = IERC20Like(_weth);
        _mint(address(0), 1000);
        totalSupply = 1000;
    }

    function _mint(address to, uint256 amount) internal {
        shares[to] += amount;
        totalSupply += amount;
    }

    function totalAssets() public view returns (uint256) {
        uint256 boldBal = bold.balanceOf(address(this));
        uint256 wethBal = weth.balanceOf(address(this));
        return boldBal + wethBal * wethPrice / 1e18;
    }

    function deposit(uint256 amount) external {
        uint256 before = bold.balanceOf(address(this));
        bold.transferFrom(msg.sender, address(this), amount);
        uint256 received = bold.balanceOf(address(this)) - before;
        uint256 shareAmount = received * totalSupply / totalAssets();
        _mint(msg.sender, shareAmount);
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(msg.sender, assets);
    }
}
"""

# A `> 0` zero-guard is not a threshold exclusion.
_SHARE_ZERO_GUARD = _TOKEN_IFACE + """
contract SubthresholdZeroGuard {
    IERC20Like public bold;
    IERC20Like public weth;
    uint256 public wethPrice = 3000 * 1e18;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;

    constructor(address _bold, address _weth) {
        bold = IERC20Like(_bold);
        weth = IERC20Like(_weth);
        _mint(address(0), 1000);
        totalSupply = 1000;
    }

    function _mint(address to, uint256 amount) internal {
        shares[to] += amount;
        totalSupply += amount;
    }

    function totalAssets() public view returns (uint256) {
        uint256 boldBal = bold.balanceOf(address(this));
        uint256 wethBal = weth.balanceOf(address(this));
        uint256 total = boldBal;
        if (wethBal > 0) {
            total += wethBal * wethPrice / 1e18;
        }
        return total;
    }

    function deposit(uint256 amount) external {
        uint256 before = bold.balanceOf(address(this));
        bold.transferFrom(msg.sender, address(this), amount);
        uint256 received = bold.balanceOf(address(this)) - before;
        uint256 shareAmount = received * totalSupply / totalAssets();
        _mint(msg.sender, shareAmount);
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(msg.sender, assets);
    }
}
"""

# Owner-gated entry / exit legs: a stranger cannot reach the path.
_SHARE_GATED_LEGS = _TOKEN_IFACE + """
contract SubthresholdGatedLegs {
    IERC20Like public bold;
    IERC20Like public weth;
    address public owner;
    uint256 public constant MIN_WETH = 1e15;
    uint256 public wethPrice = 3000 * 1e18;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;

    constructor(address _bold, address _weth, address _owner) {
        bold = IERC20Like(_bold);
        weth = IERC20Like(_weth);
        owner = _owner;
        _mint(address(0), 1000);
        totalSupply = 1000;
    }

    function _mint(address to, uint256 amount) internal {
        shares[to] += amount;
        totalSupply += amount;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function totalAssets() public view returns (uint256) {
        uint256 boldBal = bold.balanceOf(address(this));
        uint256 wethBal = weth.balanceOf(address(this));
        uint256 total = boldBal;
        if (wethBal > MIN_WETH) {
            total += wethBal * wethPrice / 1e18;
        }
        return total;
    }

    function deposit(uint256 amount) external onlyOwner {
        uint256 before = bold.balanceOf(address(this));
        bold.transferFrom(msg.sender, address(this), amount);
        uint256 received = bold.balanceOf(address(this)) - before;
        uint256 shareAmount = received * totalSupply / totalAssets();
        _mint(msg.sender, shareAmount);
    }

    function redeem(uint256 shareAmount) external onlyOwner {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(msg.sender, assets);
    }
}
"""

# The ternary form of the threshold exclusion: still fires.
_SHARE_TERNARY = _TOKEN_IFACE + """
contract SubthresholdVaultTernary {
    IERC20Like public bold;
    IERC20Like public weth;
    uint256 public constant MIN_WETH = 1e15;
    uint256 public wethPrice = 3000 * 1e18;
    mapping(address => uint256) public shares;
    uint256 public totalSupply;

    constructor(address _bold, address _weth) {
        bold = IERC20Like(_bold);
        weth = IERC20Like(_weth);
        _mint(address(0), 1000);
        totalSupply = 1000;
    }

    function _mint(address to, uint256 amount) internal {
        shares[to] += amount;
        totalSupply += amount;
    }

    function totalAssets() public view returns (uint256) {
        uint256 boldBal = bold.balanceOf(address(this));
        uint256 wethBal = weth.balanceOf(address(this));
        uint256 wethValue = wethBal > MIN_WETH ? wethBal * wethPrice / 1e18 : 0;
        return boldBal + wethValue;
    }

    function deposit(uint256 amount) external {
        uint256 before = bold.balanceOf(address(this));
        bold.transferFrom(msg.sender, address(this), amount);
        uint256 received = bold.balanceOf(address(this)) - before;
        uint256 shareAmount = received * totalSupply / totalAssets();
        _mint(msg.sender, shareAmount);
    }

    function redeem(uint256 shareAmount) external {
        require(shareAmount <= shares[msg.sender], "insufficient shares");
        uint256 assets = shareAmount * totalAssets() / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        bold.transfer(msg.sender, assets);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. voucher_redeem_recipient_unbound
# ---------------------------------------------------------------------------

_VOUCHER_VULN = _TOKEN_IFACE + _ECDSA_LIB + """
contract VoucherRedeemVuln {
    IERC20Like public token;
    address public authorizedSigner;
    mapping(uint256 => bool) public usedNonces;

    constructor(address _token, address _signer) {
        token = IERC20Like(_token);
        authorizedSigner = _signer;
    }

    function withdrawLevelReward(uint256 amount, uint256 nonce, bytes calldata signature) external {
        require(!usedNonces[nonce], "voucher already used");
        bytes32 digest = keccak256(abi.encodePacked(amount, nonce));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == authorizedSigner, "bad signer");
        usedNonces[nonce] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

_VOUCHER_VARIANT = _TOKEN_IFACE + _ECDSA_LIB + """
contract VoucherRedeemFixed {
    IERC20Like public token;
    address public authorizedSigner;
    address public treasury;
    mapping(uint256 => bool) public usedNonces;

    constructor(address _token, address _signer, address _treasury) {
        token = IERC20Like(_token);
        authorizedSigner = _signer;
        treasury = _treasury;
    }

    function withdrawLevelReward(uint256 amount, uint256 nonce, bytes calldata signature) external {
        require(!usedNonces[nonce], "voucher already used");
        bytes32 digest = keccak256(abi.encodePacked(amount, nonce));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == authorizedSigner, "bad signer");
        usedNonces[nonce] = true;
        token.transfer(treasury, amount);
    }
}
"""

# The digest binds the redeemer: protected shape.
_VOUCHER_CLEAN = _TOKEN_IFACE + _ECDSA_LIB + """
contract VoucherRedeemClean {
    IERC20Like public token;
    address public authorizedSigner;
    mapping(uint256 => bool) public usedNonces;

    constructor(address _token, address _signer) {
        token = IERC20Like(_token);
        authorizedSigner = _signer;
    }

    function withdrawLevelReward(uint256 amount, uint256 nonce, bytes calldata signature) external {
        require(!usedNonces[nonce], "voucher already used");
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, amount, nonce));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == authorizedSigner, "bad signer");
        usedNonces[nonce] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

# No nonce / consumed marker: the replay class, not this one.
_VOUCHER_NO_NONCE = _TOKEN_IFACE + _ECDSA_LIB + """
contract VoucherNoNonce {
    IERC20Like public token;
    address public authorizedSigner;

    constructor(address _token, address _signer) {
        token = IERC20Like(_token);
        authorizedSigner = _signer;
    }

    function withdrawLevelReward(uint256 amount, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encodePacked(amount));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == authorizedSigner, "bad signer");
        token.transfer(msg.sender, amount);
    }
}
"""

# Owner-gated redeem: a stranger cannot reach the path.
_VOUCHER_GATED = _TOKEN_IFACE + _ECDSA_LIB + """
contract VoucherGated {
    IERC20Like public token;
    address public authorizedSigner;
    address public owner;
    mapping(uint256 => bool) public usedNonces;

    constructor(address _token, address _signer, address _owner) {
        token = IERC20Like(_token);
        authorizedSigner = _signer;
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function withdrawLevelReward(uint256 amount, uint256 nonce, bytes calldata signature) external onlyOwner {
        require(!usedNonces[nonce], "voucher already used");
        bytes32 digest = keccak256(abi.encodePacked(amount, nonce));
        address signer = ECDSA.recover(digest, signature);
        require(signer != address(0), "zero signer");
        require(signer == authorizedSigner, "bad signer");
        usedNonces[nonce] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

# No signature verification at all: not this detector's shape.
_VOUCHER_NO_SIG = _TOKEN_IFACE + """
contract VoucherNoSig {
    IERC20Like public token;
    mapping(uint256 => bool) public usedNonces;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function withdrawLevelReward(uint256 amount, uint256 nonce) external {
        require(!usedNonces[nonce], "voucher already used");
        usedNonces[nonce] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. period_exit_writes_new_period_exposure_snapshot
# ---------------------------------------------------------------------------

_PERIOD_VULN = _TOKEN_IFACE + """
contract PeriodExitVuln {
    IERC20Like public token;
    uint256 public constant PERIOD = 1 days;
    uint256 public totalExposure;
    mapping(address => uint256) public userExposure;
    mapping(uint256 => uint256) public periodExposure;
    mapping(address => uint256) public approvedClaims;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        userExposure[msg.sender] += received;
        totalExposure += received;
    }

    function exit(uint256 amount) external {
        uint256 period = block.timestamp / PERIOD;
        if (block.timestamp % PERIOD == 0) {
            periodExposure[period] = totalExposure;
        }
        require(amount <= userExposure[msg.sender], "insufficient exposure");
        userExposure[msg.sender] -= amount;
        totalExposure -= amount;
        token.transfer(msg.sender, amount);
    }

    function claimCover(uint256 period, uint256 amount) external {
        require(amount <= approvedClaims[msg.sender], "exceeds approved claim");
        approvedClaims[msg.sender] -= amount;
        uint256 payout = periodExposure[period] * amount / 1e18;
        require(payout <= token.balanceOf(address(this)), "insufficient reserves");
        token.transfer(msg.sender, payout);
    }
}
"""

# The snapshot is written only on deposit, never on exit.
_PERIOD_CLEAN = _TOKEN_IFACE + """
contract PeriodExitClean {
    IERC20Like public token;
    uint256 public constant PERIOD = 1 days;
    uint256 public totalExposure;
    mapping(address => uint256) public userExposure;
    mapping(uint256 => uint256) public periodExposure;
    mapping(address => uint256) public approvedClaims;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        userExposure[msg.sender] += received;
        totalExposure += received;
        uint256 period = block.timestamp / PERIOD;
        periodExposure[period] = totalExposure;
    }

    function exit(uint256 amount) external {
        require(amount <= userExposure[msg.sender], "insufficient exposure");
        userExposure[msg.sender] -= amount;
        totalExposure -= amount;
        token.transfer(msg.sender, amount);
    }

    function claimCover(uint256 period, uint256 amount) external {
        require(amount <= approvedClaims[msg.sender], "exceeds approved claim");
        approvedClaims[msg.sender] -= amount;
        uint256 payout = periodExposure[period] * amount / 1e18;
        require(payout <= token.balanceOf(address(this)), "insufficient reserves");
        token.transfer(msg.sender, payout);
    }
}
"""

# The exit reads the snapshot but never writes it.
_PERIOD_READS_ONLY = _TOKEN_IFACE + """
contract PeriodExitReadsOnly {
    IERC20Like public token;
    uint256 public constant PERIOD = 1 days;
    uint256 public totalExposure;
    mapping(address => uint256) public userExposure;
    mapping(uint256 => uint256) public periodExposure;
    mapping(address => uint256) public approvedClaims;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function snapshotPeriod() external {
        uint256 period = block.timestamp / PERIOD;
        periodExposure[period] = totalExposure;
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        userExposure[msg.sender] += received;
        totalExposure += received;
    }

    function exit(uint256 amount) external {
        uint256 period = block.timestamp / PERIOD;
        uint256 available = periodExposure[period];
        require(amount <= userExposure[msg.sender], "insufficient exposure");
        require(amount <= available, "exceeds period exposure");
        userExposure[msg.sender] -= amount;
        totalExposure -= amount;
        token.transfer(msg.sender, amount);
    }

    function claimCover(uint256 period, uint256 amount) external {
        require(amount <= approvedClaims[msg.sender], "exceeds approved claim");
        approvedClaims[msg.sender] -= amount;
        uint256 payout = periodExposure[period] * amount / 1e18;
        require(payout <= token.balanceOf(address(this)), "insufficient reserves");
        token.transfer(msg.sender, payout);
    }
}
"""

# The exit writes the snapshot but no claim reads it: no victim.
_PERIOD_NO_CLAIM = _TOKEN_IFACE + """
contract PeriodExitNoClaim {
    IERC20Like public token;
    uint256 public constant PERIOD = 1 days;
    uint256 public totalExposure;
    mapping(address => uint256) public userExposure;
    mapping(uint256 => uint256) public periodExposure;
    mapping(address => uint256) public approvedClaims;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        userExposure[msg.sender] += received;
        totalExposure += received;
    }

    function exit(uint256 amount) external {
        uint256 period = block.timestamp / PERIOD;
        if (block.timestamp % PERIOD == 0) {
            periodExposure[period] = totalExposure;
        }
        require(amount <= userExposure[msg.sender], "insufficient exposure");
        userExposure[msg.sender] -= amount;
        totalExposure -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# Owner-gated exit: a stranger cannot reach the path.
_PERIOD_GATED = _TOKEN_IFACE + """
contract PeriodExitGated {
    IERC20Like public token;
    address public owner;
    uint256 public constant PERIOD = 1 days;
    uint256 public totalExposure;
    mapping(address => uint256) public userExposure;
    mapping(uint256 => uint256) public periodExposure;
    mapping(address => uint256) public approvedClaims;

    constructor(address _token, address _owner) {
        token = IERC20Like(_token);
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        userExposure[msg.sender] += received;
        totalExposure += received;
    }

    function exit(uint256 amount) external onlyOwner {
        uint256 period = block.timestamp / PERIOD;
        if (block.timestamp % PERIOD == 0) {
            periodExposure[period] = totalExposure;
        }
        require(amount <= userExposure[msg.sender], "insufficient exposure");
        userExposure[msg.sender] -= amount;
        totalExposure -= amount;
        token.transfer(msg.sender, amount);
    }

    function claimCover(uint256 period, uint256 amount) external {
        require(amount <= approvedClaims[msg.sender], "exceeds approved claim");
        approvedClaims[msg.sender] -= amount;
        uint256 payout = periodExposure[period] * amount / 1e18;
        require(payout <= token.balanceOf(address(this)), "insufficient reserves");
        token.transfer(msg.sender, payout);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. withdraw_pays_other_account_balance
# ---------------------------------------------------------------------------

_WITHDRAW_OTHER_VULN = _TOKEN_IFACE + """
contract WithdrawOtherVuln {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        balances[msg.sender] += received;
    }

    function withdraw(address account, uint256 amount) external {
        require(amount <= balances[account], "insufficient balance");
        balances[account] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_WITHDRAW_OTHER_VARIANT = _TOKEN_IFACE + """
contract WithdrawOtherFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => uint256) public balances;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        balances[msg.sender] += received;
    }

    function withdraw(address account, uint256 amount) external {
        require(amount <= balances[account], "insufficient balance");
        balances[account] -= amount;
        token.transfer(treasury, amount);
    }
}
"""

# The caller must be the account: protected shape.
_WITHDRAW_OTHER_CLEAN = _TOKEN_IFACE + """
contract WithdrawOtherClean {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        balances[msg.sender] += received;
    }

    function withdraw(address account, uint256 amount) external {
        require(msg.sender == account, "not your account");
        require(amount <= balances[account], "insufficient balance");
        balances[account] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# An allowance from the account authorizes the withdraw.
_WITHDRAW_OTHER_ALLOWANCE = _TOKEN_IFACE + """
contract WithdrawOtherAllowance {
    IERC20Like public token;
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function approve(address spender, uint256 amount) external {
        allowance[msg.sender][spender] = amount;
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        balances[msg.sender] += received;
    }

    function withdraw(address account, uint256 amount) external {
        require(allowance[account][msg.sender] >= amount, "no allowance");
        allowance[account][msg.sender] -= amount;
        require(amount <= balances[account], "insufficient balance");
        balances[account] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# No account parameter at all: the caller can only spend their own.
_WITHDRAW_OTHER_OWN_ONLY = _TOKEN_IFACE + """
contract WithdrawOwnOnly {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        balances[msg.sender] += received;
    }

    function withdraw(uint256 amount) external {
        require(amount <= balances[msg.sender], "insufficient balance");
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# Owner-gated withdraw: a stranger cannot reach the path.
_WITHDRAW_OTHER_GATED = _TOKEN_IFACE + """
contract WithdrawOtherGated {
    IERC20Like public token;
    address public owner;
    mapping(address => uint256) public balances;

    constructor(address _token, address _owner) {
        token = IERC20Like(_token);
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deposit(uint256 amount) external {
        uint256 before = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        uint256 received = token.balanceOf(address(this)) - before;
        balances[msg.sender] += received;
    }

    function withdraw(address account, uint256 amount) external onlyOwner {
        require(amount <= balances[account], "insufficient balance");
        balances[account] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

VULN = {
    "snapshot_position_sync_caller_writable": _SYNC_VULN,
    "share_price_excludes_subthreshold_collateral": _SHARE_VULN,
    "voucher_redeem_recipient_unbound": _VOUCHER_VULN,
    "period_exit_writes_new_period_exposure_snapshot": _PERIOD_VULN,
    "withdraw_pays_other_account_balance": _WITHDRAW_OTHER_VULN,
}

VARIANT = {
    "snapshot_position_sync_caller_writable": _SYNC_VARIANT,
    "share_price_excludes_subthreshold_collateral": _SHARE_VARIANT,
    "voucher_redeem_recipient_unbound": _VOUCHER_VARIANT,
    "withdraw_pays_other_account_balance": _WITHDRAW_OTHER_VARIANT,
}

CLEAN = {
    "snapshot_position_sync_caller_writable": _SYNC_CLEAN,
    "share_price_excludes_subthreshold_collateral": _SHARE_CLEAN,
    "voucher_redeem_recipient_unbound": _VOUCHER_CLEAN,
    "period_exit_writes_new_period_exposure_snapshot": _PERIOD_CLEAN,
    "withdraw_pays_other_account_balance": _WITHDRAW_OTHER_CLEAN,
}

EXTRA_CLEAN = {
    "sync_gated": _SYNC_GATED,
    "sync_recompute_internal": _SYNC_RECOMPUTE_INTERNAL,
    "sync_no_payout": _SYNC_NO_PAYOUT,
    "share_zero_guard": _SHARE_ZERO_GUARD,
    "share_gated_legs": _SHARE_GATED_LEGS,
    "voucher_no_nonce": _VOUCHER_NO_NONCE,
    "voucher_gated": _VOUCHER_GATED,
    "voucher_no_sig": _VOUCHER_NO_SIG,
    "period_reads_only": _PERIOD_READS_ONLY,
    "period_no_claim": _PERIOD_NO_CLAIM,
    "period_gated": _PERIOD_GATED,
    "withdraw_allowance": _WITHDRAW_OTHER_ALLOWANCE,
    "withdraw_own_only": _WITHDRAW_OTHER_OWN_ONLY,
    "withdraw_gated": _WITHDRAW_OTHER_GATED,
}

# Extra vulnerable shape (not in VULN): the ternary form of the
# threshold exclusion still fires.
VULN_TERNARY = _SHARE_TERNARY
