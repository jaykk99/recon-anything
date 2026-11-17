"""Fixtures for the deep-audit batch-22 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the value lands at a FIXED destination, so it MUST fire
with report_class "trigger_only" at low severity - never a
candidate.

Cross-talk by construction:
- The claim fixture has no checkpoint push, no buy function,
  no price feed, no listing function.
- The checkpoint VULN fixture's push OVERWRITES on equal key;
  the CLEAN fixture is the #88287 shape (withdraw pushes a
  boundary checkpoint through an append-only push that
  reverts on equal key, payout reads it as a cap) and MUST
  stay silent under the checkpoint detector - that is the
  deep_audit21 adjudication pin.
- The presale fixture uses a 1e6 literal only (never 1e18),
  so the generic hardcoded_decimals_scaling slice stays
  silent on it; it has no price feed and no listing.
- The collateral-value fixture uses a 1e10 literal only in
  the valuation function (the 1e18 divisor is a named
  constant, so no function text contains a 1e18 literal and
  the generic slice stays silent); it has no buy function
  and no listing function.
- The listing fixture's borrow reads the price via getPrice
  with a 1e8 divisor (never 1e10/1e18), so the
  collateral-value detector stays silent on it.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

_AGGREGATOR_IFACE = """
interface AggregatorV3Like {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}
"""

# ---------------------------------------------------------------------------
# 1. claim_guard_wrong_key_replay (CodeHawks Snarkeling)
# ---------------------------------------------------------------------------

_CLAIM_VULN = _TOKEN_IFACE + """
contract TreasureHuntVuln {
    IERC20Like public token;
    bytes32 private immutable _treasureHash;
    mapping(bytes32 => bool) public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claim(bytes32 treasureHash, bytes calldata proof, address recipient) external {
        require(!claimed[_treasureHash], "already claimed");
        require(_verifyProof(proof, treasureHash), "bad proof");
        _markClaimed(treasureHash);
        token.transfer(recipient, 10 ether);
    }

    function _markClaimed(bytes32 treasureHash) internal {
        claimed[treasureHash] = true;
    }

    function _verifyProof(bytes calldata, bytes32) internal pure returns (bool) {
        return true;
    }
}
"""

_CLAIM_VARIANT = _TOKEN_IFACE + """
contract TreasureHuntFixed {
    IERC20Like public token;
    address public owner;
    bytes32 private immutable _treasureHash;
    mapping(bytes32 => bool) public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    function claim(bytes32 treasureHash, bytes calldata proof) external {
        require(!claimed[_treasureHash], "already claimed");
        require(_verifyProof(proof, treasureHash), "bad proof");
        _markClaimed(treasureHash);
        token.transfer(owner, 10 ether);
    }

    function _markClaimed(bytes32 treasureHash) internal {
        claimed[treasureHash] = true;
    }

    function _verifyProof(bytes calldata, bytes32) internal pure returns (bool) {
        return true;
    }
}
"""

# Guard and mark use the SAME key (the parameter): the guard works.
_CLAIM_CLEAN = _TOKEN_IFACE + """
contract TreasureHuntClean {
    IERC20Like public token;
    mapping(bytes32 => bool) public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claim(bytes32 treasureHash, bytes calldata proof, address recipient) external {
        require(!claimed[treasureHash], "already claimed");
        require(_verifyProof(proof, treasureHash), "bad proof");
        _markClaimed(treasureHash);
        token.transfer(recipient, 10 ether);
    }

    function _markClaimed(bytes32 treasureHash) internal {
        claimed[treasureHash] = true;
    }

    function _verifyProof(bytes calldata, bytes32) internal pure returns (bool) {
        return true;
    }
}
"""

# The guard variable IS assigned in the constructor: the guard works.
_CLAIM_CLEAN_ASSIGNED = _TOKEN_IFACE + """
contract TreasureHuntAssigned {
    IERC20Like public token;
    bytes32 private immutable _treasureHash;
    mapping(bytes32 => bool) public claimed;

    constructor(address _token, bytes32 _hash) {
        token = IERC20Like(_token);
        _treasureHash = _hash;
    }

    function claim(bytes32 treasureHash, bytes calldata proof, address recipient) external {
        require(!claimed[_treasureHash], "already claimed");
        require(_verifyProof(proof, treasureHash), "bad proof");
        _markClaimed(treasureHash);
        token.transfer(recipient, 10 ether);
    }

    function _markClaimed(bytes32 treasureHash) internal {
        claimed[treasureHash] = true;
    }

    function _verifyProof(bytes calldata, bytes32) internal pure returns (bool) {
        return true;
    }
}
"""

# ---------------------------------------------------------------------------
# 2. checkpoint_overwrite_equal_key_rewrites_snapshot (Firelight #89588)
# ---------------------------------------------------------------------------

_CHECKPOINT_LIB_VULN = """
library Checkpoints {
    struct Checkpoint {
        uint256 key;
        uint256 value;
    }
    struct Trace256 {
        Checkpoint[] _checkpoints;
    }

    function push(Trace256 storage self, uint256 key, uint256 value) internal returns (uint256, uint256) {
        uint256 len = self._checkpoints.length;
        if (len > 0) {
            Checkpoint storage last = self._checkpoints[len - 1];
            if (last.key == key) {
                last.value = value;
                return (last.value, value);
            }
        }
        self._checkpoints.push(Checkpoint(key, value));
        return (0, value);
    }

    function upperLookup(Trace256 storage self, uint256 key) internal view returns (uint256) {
        uint256 len = self._checkpoints.length;
        if (len == 0) {
            return 0;
        }
        return self._checkpoints[len - 1].value;
    }
}
"""

_CHECKPOINT_VULN = _TOKEN_IFACE + _CHECKPOINT_LIB_VULN + """
contract FirelightVaultVuln {
    using Checkpoints for Checkpoints.Trace256;
    Checkpoints.Trace256 internal _exposure;
    IERC20Like public token;
    uint256 public periodStart;
    mapping(address => uint256) public deposits;

    constructor(address _token, uint256 _periodStart) {
        token = IERC20Like(_token);
        periodStart = _periodStart;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        _exposure.push(periodStart, deposits[msg.sender]);
        token.transfer(msg.sender, amount);
    }

    function payout(address claimant, uint256 claimAmount) external {
        uint256 cap = _exposure.upperLookup(periodStart);
        uint256 pay = claimAmount < cap ? claimAmount : cap;
        token.transfer(claimant, pay);
    }
}
"""

# Same shape, but the withdrawn value lands at a FIXED treasury.
_CHECKPOINT_VARIANT = _TOKEN_IFACE + _CHECKPOINT_LIB_VULN + """
contract FirelightVaultFixed {
    using Checkpoints for Checkpoints.Trace256;
    Checkpoints.Trace256 internal _exposure;
    IERC20Like public token;
    address public treasury;
    uint256 public periodStart;
    mapping(address => uint256) public deposits;

    constructor(address _token, uint256 _periodStart) {
        token = IERC20Like(_token);
        periodStart = _periodStart;
        treasury = msg.sender;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        _exposure.push(periodStart, deposits[msg.sender]);
        token.transfer(treasury, amount);
    }

    function payout(address claimant, uint256 claimAmount) external {
        uint256 cap = _exposure.upperLookup(periodStart);
        uint256 pay = claimAmount < cap ? claimAmount : cap;
        token.transfer(claimant, pay);
    }
}
"""

# The #88287 shape (deep_audit21): withdraw pushes a boundary
# checkpoint through an APPEND-ONLY push (revert on equal key)
# and payout reads it as a cap. Must stay silent here: the
# distinguishing element is the library overwrite, which this
# push does not have.
_CHECKPOINT_LIB_CLEAN = """
library CheckpointsClean {
    struct Checkpoint {
        uint256 key;
        uint256 value;
    }
    struct Trace256 {
        Checkpoint[] _checkpoints;
    }

    function push(Trace256 storage self, uint256 key, uint256 value) internal returns (uint256, uint256) {
        uint256 len = self._checkpoints.length;
        if (len > 0) {
            Checkpoint storage last = self._checkpoints[len - 1];
            if (last.key == key) {
                revert("duplicate key");
            }
        }
        self._checkpoints.push(Checkpoint(key, value));
        return (0, value);
    }

    function upperLookup(Trace256 storage self, uint256 key) internal view returns (uint256) {
        uint256 len = self._checkpoints.length;
        if (len == 0) {
            return 0;
        }
        return self._checkpoints[len - 1].value;
    }
}
"""

_CHECKPOINT_CLEAN = _TOKEN_IFACE + _CHECKPOINT_LIB_CLEAN + """
contract FirelightVaultClean {
    using CheckpointsClean for CheckpointsClean.Trace256;
    CheckpointsClean.Trace256 internal _exposure;
    IERC20Like public token;
    uint256 public periodStart;
    mapping(address => uint256) public deposits;

    constructor(address _token, uint256 _periodStart) {
        token = IERC20Like(_token);
        periodStart = _periodStart;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        _exposure.push(periodStart, deposits[msg.sender]);
        token.transfer(msg.sender, amount);
    }

    function payout(address claimant, uint256 claimAmount) external {
        uint256 cap = _exposure.upperLookup(periodStart);
        uint256 pay = claimAmount < cap ? claimAmount : cap;
        token.transfer(claimant, pay);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. presale_hardcoded_decimals_dust_purchase (Hacken TCG-Vault)
# ---------------------------------------------------------------------------

_PRESALE_VULN = _TOKEN_IFACE + """
contract PresaleVuln {
    IERC20Like public paymentToken;
    IERC20Like public saleToken;
    uint256 public price = 100;

    constructor(address _payment, address _sale) {
        paymentToken = IERC20Like(_payment);
        saleToken = IERC20Like(_sale);
    }

    function buy(uint256 paymentAmount) external {
        uint256 allocation = paymentAmount * 1e6 / price;
        paymentToken.transferFrom(msg.sender, address(this), paymentAmount);
        saleToken.transfer(msg.sender, allocation);
    }
}
"""

_PRESALE_VARIANT = _TOKEN_IFACE + """
contract PresaleFixed {
    IERC20Like public paymentToken;
    IERC20Like public saleToken;
    address public owner;
    uint256 public price = 100;

    constructor(address _payment, address _sale) {
        paymentToken = IERC20Like(_payment);
        saleToken = IERC20Like(_sale);
        owner = msg.sender;
    }

    function buy(uint256 paymentAmount) external {
        uint256 allocation = paymentAmount * 1e6 / price;
        paymentToken.transferFrom(msg.sender, address(this), paymentAmount);
        saleToken.transfer(owner, allocation);
    }
}
"""

# decimals() is read: the sale is decimals-aware.
_PRESALE_CLEAN = _TOKEN_IFACE + """
contract PresaleClean {
    IERC20Like public paymentToken;
    IERC20Like public saleToken;
    uint256 public price = 100;

    constructor(address _payment, address _sale) {
        paymentToken = IERC20Like(_payment);
        saleToken = IERC20Like(_sale);
    }

    function buy(uint256 paymentAmount) external {
        uint256 decimals = paymentToken.decimals();
        uint256 allocation = paymentAmount * 10 ** decimals / price;
        paymentToken.transferFrom(msg.sender, address(this), paymentAmount);
        saleToken.transfer(msg.sender, allocation);
    }
}
"""

# The payment token is pinned to an allowlisted stablecoin.
_PRESALE_CLEAN_ALLOWLIST = _TOKEN_IFACE + """
contract PresaleAllowlisted {
    IERC20Like public paymentToken;
    IERC20Like public saleToken;
    mapping(address => bool) public acceptedStablecoins;
    uint256 public price = 100;

    constructor(address _payment, address _sale, address _usdt) {
        paymentToken = IERC20Like(_payment);
        saleToken = IERC20Like(_sale);
        acceptedStablecoins[_usdt] = true;
    }

    function buy(address paymentTokenAddr, uint256 paymentAmount) external {
        require(acceptedStablecoins[paymentTokenAddr], "not accepted");
        uint256 allocation = paymentAmount * 1e6 / price;
        paymentToken.transferFrom(msg.sender, address(this), paymentAmount);
        saleToken.transfer(msg.sender, allocation);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. collateral_value_assumes_18_decimals (DSCEngine / Inverse FiRM)
# ---------------------------------------------------------------------------

_COLLATERAL_VULN = _TOKEN_IFACE + _AGGREGATOR_IFACE + """
contract DSCEngineVuln {
    AggregatorV3Like public priceFeed;
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    mapping(address => uint256) public collateralBalances;
    mapping(address => uint256) public debtBalances;
    uint256 public constant PRECISION = 1e18;

    constructor(address _feed, address _collateral, address _debt) {
        priceFeed = AggregatorV3Like(_feed);
        collateralToken = IERC20Like(_collateral);
        debtToken = IERC20Like(_debt);
    }

    function getUsdValue(address token, uint256 amount) public view returns (uint256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        return (uint256(price) * 1e10 * amount) / PRECISION;
    }

    function getAccountCollateralValue(address user) public view returns (uint256) {
        return getUsdValue(address(collateralToken), collateralBalances[user]);
    }

    function getHealthFactor(address user) public view returns (uint256) {
        uint256 collateralValue = getAccountCollateralValue(user);
        uint256 debt = debtBalances[user];
        if (debt == 0) {
            return type(uint256).max;
        }
        return collateralValue * 100 / debt;
    }

    function borrow(uint256 amount) external {
        require(getHealthFactor(msg.sender) > 100, "unhealthy");
        debtBalances[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }
}
"""

# Same shape, but the borrowed value lands at a FIXED owner.
_COLLATERAL_VARIANT = _TOKEN_IFACE + _AGGREGATOR_IFACE + """
contract DSCEngineFixed {
    AggregatorV3Like public priceFeed;
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    address public owner;
    mapping(address => uint256) public collateralBalances;
    mapping(address => uint256) public debtBalances;
    uint256 public constant PRECISION = 1e18;

    constructor(address _feed, address _collateral, address _debt) {
        priceFeed = AggregatorV3Like(_feed);
        collateralToken = IERC20Like(_collateral);
        debtToken = IERC20Like(_debt);
        owner = msg.sender;
    }

    function getUsdValue(address token, uint256 amount) public view returns (uint256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        return (uint256(price) * 1e10 * amount) / PRECISION;
    }

    function getAccountCollateralValue(address user) public view returns (uint256) {
        return getUsdValue(address(collateralToken), collateralBalances[user]);
    }

    function getHealthFactor(address user) public view returns (uint256) {
        uint256 collateralValue = getAccountCollateralValue(user);
        uint256 debt = debtBalances[user];
        if (debt == 0) {
            return type(uint256).max;
        }
        return collateralValue * 100 / debt;
    }

    function borrow(uint256 amount) external {
        require(getHealthFactor(msg.sender) > 100, "unhealthy");
        debtBalances[msg.sender] += amount;
        debtToken.transfer(owner, amount);
    }
}
"""

# decimals() is read: the valuation is decimals-aware.
_COLLATERAL_CLEAN = _TOKEN_IFACE + _AGGREGATOR_IFACE + """
contract DSCEngineClean {
    AggregatorV3Like public priceFeed;
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    mapping(address => uint256) public collateralBalances;
    mapping(address => uint256) public debtBalances;
    uint256 public constant PRECISION = 1e18;

    constructor(address _feed, address _collateral, address _debt) {
        priceFeed = AggregatorV3Like(_feed);
        collateralToken = IERC20Like(_collateral);
        debtToken = IERC20Like(_debt);
    }

    function getUsdValue(address token, uint256 amount) public view returns (uint256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        uint256 decimals = IERC20Like(token).decimals();
        return (uint256(price) * 1e10 * amount) / (10 ** decimals) / PRECISION * PRECISION;
    }

    function getAccountCollateralValue(address user) public view returns (uint256) {
        return getUsdValue(address(collateralToken), collateralBalances[user]);
    }

    function getHealthFactor(address user) public view returns (uint256) {
        uint256 collateralValue = getAccountCollateralValue(user);
        uint256 debt = debtBalances[user];
        if (debt == 0) {
            return type(uint256).max;
        }
        return collateralValue * 100 / debt;
    }

    function borrow(uint256 amount) external {
        require(getHealthFactor(msg.sender) > 100, "unhealthy");
        debtBalances[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }
}
"""

# Per-token decimals config is consulted instead of decimals().
_COLLATERAL_CLEAN_CONFIG = _TOKEN_IFACE + _AGGREGATOR_IFACE + """
contract DSCEngineConfigured {
    AggregatorV3Like public priceFeed;
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    mapping(address => uint256) public tokenDecimals;
    mapping(address => uint256) public collateralBalances;
    mapping(address => uint256) public debtBalances;
    uint256 public constant PRECISION = 1e18;

    constructor(address _feed, address _collateral, address _debt) {
        priceFeed = AggregatorV3Like(_feed);
        collateralToken = IERC20Like(_collateral);
        debtToken = IERC20Like(_debt);
        tokenDecimals[_collateral] = 8;
    }

    function getUsdValue(address token, uint256 amount) public view returns (uint256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        uint256 decimals = tokenDecimals[token];
        return (uint256(price) * 1e10 * amount) / (10 ** decimals);
    }

    function getAccountCollateralValue(address user) public view returns (uint256) {
        return getUsdValue(address(collateralToken), collateralBalances[user]);
    }

    function getHealthFactor(address user) public view returns (uint256) {
        uint256 collateralValue = getAccountCollateralValue(user);
        uint256 debt = debtBalances[user];
        if (debt == 0) {
            return type(uint256).max;
        }
        return collateralValue * 100 / debt;
    }

    function borrow(uint256 amount) external {
        require(getHealthFactor(msg.sender) > 100, "unhealthy");
        debtBalances[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. permissionless_collateral_listing_fake_token (Rhea Finance)
# ---------------------------------------------------------------------------

_LISTING_VULN = _TOKEN_IFACE + _AGGREGATOR_IFACE + """
contract LendingMarketVuln {
    IERC20Like public usdc;
    mapping(address => bool) public supportedCollateral;
    mapping(address => address) public priceFeeds;
    mapping(address => uint256) public borrowed;

    constructor(address _usdc) {
        usdc = IERC20Like(_usdc);
    }

    function addCollateral(address token, address priceFeed) external {
        supportedCollateral[token] = true;
        priceFeeds[token] = priceFeed;
    }

    function getPrice(address token) public view returns (uint256) {
        (, int256 price, , , ) = AggregatorV3Like(priceFeeds[token]).latestRoundData();
        return uint256(price);
    }

    function borrow(address collateral, uint256 amount) external {
        require(supportedCollateral[collateral], "unsupported");
        uint256 price = getPrice(collateral);
        uint256 maxBorrow = amount * price / 1e8;
        borrowed[msg.sender] += amount;
        usdc.transfer(msg.sender, maxBorrow);
    }
}
"""

_LISTING_VARIANT = _TOKEN_IFACE + _AGGREGATOR_IFACE + """
contract LendingMarketFixed {
    IERC20Like public usdc;
    address public owner;
    mapping(address => bool) public supportedCollateral;
    mapping(address => address) public priceFeeds;
    mapping(address => uint256) public borrowed;

    constructor(address _usdc) {
        usdc = IERC20Like(_usdc);
        owner = msg.sender;
    }

    function addCollateral(address token, address priceFeed) external {
        supportedCollateral[token] = true;
        priceFeeds[token] = priceFeed;
    }

    function getPrice(address token) public view returns (uint256) {
        (, int256 price, , , ) = AggregatorV3Like(priceFeeds[token]).latestRoundData();
        return uint256(price);
    }

    function borrow(address collateral, uint256 amount) external {
        require(supportedCollateral[collateral], "unsupported");
        uint256 price = getPrice(collateral);
        uint256 maxBorrow = amount * price / 1e8;
        borrowed[msg.sender] += amount;
        usdc.transfer(owner, maxBorrow);
    }
}
"""

# Gated listing + allowlisted oracle: the protected shape.
_LISTING_CLEAN = _TOKEN_IFACE + _AGGREGATOR_IFACE + """
contract LendingMarketClean {
    IERC20Like public usdc;
    address public owner;
    mapping(address => bool) public supportedCollateral;
    mapping(address => address) public priceFeeds;
    mapping(address => bool) public approvedOracles;
    mapping(address => uint256) public borrowed;

    constructor(address _usdc, address _oracle) {
        usdc = IERC20Like(_usdc);
        owner = msg.sender;
        approvedOracles[_oracle] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function addCollateral(address token, address priceFeed) external onlyOwner {
        require(approvedOracles[priceFeed], "oracle not approved");
        supportedCollateral[token] = true;
        priceFeeds[token] = priceFeed;
    }

    function getPrice(address token) public view returns (uint256) {
        (, int256 price, , , ) = AggregatorV3Like(priceFeeds[token]).latestRoundData();
        return uint256(price);
    }

    function borrow(address collateral, uint256 amount) external {
        require(supportedCollateral[collateral], "unsupported");
        uint256 price = getPrice(collateral);
        uint256 maxBorrow = amount * price / 1e8;
        borrowed[msg.sender] += amount;
        usdc.transfer(msg.sender, maxBorrow);
    }
}
"""

# Gated listing, no oracle parameter at all: also protected.
_LISTING_CLEAN_GATED = _TOKEN_IFACE + _AGGREGATOR_IFACE + """
contract LendingMarketGated {
    IERC20Like public usdc;
    address public owner;
    mapping(address => bool) public supportedCollateral;
    mapping(address => address) public priceFeeds;
    mapping(address => uint256) public borrowed;

    constructor(address _usdc) {
        usdc = IERC20Like(_usdc);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function addCollateral(address token) external onlyOwner {
        supportedCollateral[token] = true;
    }

    function getPrice(address token) public view returns (uint256) {
        (, int256 price, , , ) = AggregatorV3Like(priceFeeds[token]).latestRoundData();
        return uint256(price);
    }

    function borrow(address collateral, uint256 amount) external {
        require(supportedCollateral[collateral], "unsupported");
        uint256 price = getPrice(collateral);
        uint256 maxBorrow = amount * price / 1e8;
        borrowed[msg.sender] += amount;
        usdc.transfer(msg.sender, maxBorrow);
    }
}
"""

# The same misvaluation spelled with a 1e18 literal instead of
# 1e10 (DSCEngine's getTokenAmountFromUsd direction). This one
# also trips the generic hardcoded_decimals_scaling slice (a
# true positive of that slice), so it lives in EXTRA_VULN,
# not in VULN.
_COLLATERAL_VULN_1E18 = _TOKEN_IFACE + _AGGREGATOR_IFACE + """
contract DSCEngineVuln18 {
    AggregatorV3Like public priceFeed;
    IERC20Like public collateralToken;
    IERC20Like public debtToken;
    mapping(address => uint256) public collateralBalances;
    mapping(address => uint256) public debtBalances;

    constructor(address _feed, address _collateral, address _debt) {
        priceFeed = AggregatorV3Like(_feed);
        collateralToken = IERC20Like(_collateral);
        debtToken = IERC20Like(_debt);
    }

    function getUsdValue(address token, uint256 amount) public view returns (uint256) {
        (, int256 price, , , ) = priceFeed.latestRoundData();
        return (uint256(price) * 1e18 * amount) / 1e26;
    }

    function getAccountCollateralValue(address user) public view returns (uint256) {
        return getUsdValue(address(collateralToken), collateralBalances[user]);
    }

    function getHealthFactor(address user) public view returns (uint256) {
        uint256 collateralValue = getAccountCollateralValue(user);
        uint256 debt = debtBalances[user];
        if (debt == 0) {
            return type(uint256).max;
        }
        return collateralValue * 100 / debt;
    }

    function borrow(uint256 amount) external {
        require(getHealthFactor(msg.sender) > 100, "unhealthy");
        debtBalances[msg.sender] += amount;
        debtToken.transfer(msg.sender, amount);
    }
}
"""

VULN = {
    "claim_guard_wrong_key_replay": _CLAIM_VULN,
    "checkpoint_overwrite_equal_key_rewrites_snapshot": _CHECKPOINT_VULN,
    "presale_hardcoded_decimals_dust_purchase": _PRESALE_VULN,
    "collateral_value_assumes_18_decimals": _COLLATERAL_VULN,
    "permissionless_collateral_listing_fake_token": _LISTING_VULN,
}

VARIANT = {
    "claim_guard_wrong_key_replay": _CLAIM_VARIANT,
    "checkpoint_overwrite_equal_key_rewrites_snapshot": _CHECKPOINT_VARIANT,
    "presale_hardcoded_decimals_dust_purchase": _PRESALE_VARIANT,
    "collateral_value_assumes_18_decimals": _COLLATERAL_VARIANT,
    "permissionless_collateral_listing_fake_token": _LISTING_VARIANT,
}

CLEAN = {
    "claim_guard_wrong_key_replay": _CLAIM_CLEAN,
    "checkpoint_overwrite_equal_key_rewrites_snapshot": _CHECKPOINT_CLEAN,
    "presale_hardcoded_decimals_dust_purchase": _PRESALE_CLEAN,
    "collateral_value_assumes_18_decimals": _COLLATERAL_CLEAN,
    "permissionless_collateral_listing_fake_token": _LISTING_CLEAN,
}

EXTRA_VULN = {
    "collateral_value_assumes_18_decimals_1e18": _COLLATERAL_VULN_1E18,
}

EXTRA_CLEAN = {
    "claim_guard_assigned_in_constructor": _CLAIM_CLEAN_ASSIGNED,
    "presale_allowlisted_payment_token": _PRESALE_CLEAN_ALLOWLIST,
    "collateral_per_token_decimals_config": _COLLATERAL_CLEAN_CONFIG,
    "listing_gated_no_oracle_param": _LISTING_CLEAN_GATED,
}
