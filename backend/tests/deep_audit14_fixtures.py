"""Fixtures for the deep-audit batch-14 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the value / power lands at a FIXED stored address, so it
MUST fire with report_class "trigger_only" at low severity -
never a candidate (same convention as batch 13: the variant
adds a transfer to a fixed treasury in the flagged function,
or the flagged function pays a fixed address); EXTRA_CLEAN[id]
is a second protected shape that MUST stay silent.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. lending_collateral_price_provider_unvalidated
# ---------------------------------------------------------------------------

_PRICE_FEED_IFACE = """
interface IPriceFeedLike {
    function latestAnswer() external view returns (int256);
}
"""

_PROVIDER_VULN = _TOKEN_IFACE + _PRICE_FEED_IFACE + """
contract LoopscaleMarketVuln {
    IERC20Like public token;
    IPriceFeedLike public fallbackFeed;
    mapping(address => address) public priceProviders;
    uint256 public minValue;

    function setPriceProvider(address market, address provider) external {
        priceProviders[market] = provider;
    }

    function borrow(address market, uint256 amount) external {
        address provider = priceProviders[market];
        uint256 price = uint256(IPriceFeedLike(provider).latestAnswer());
        uint256 value = amount * price;
        require(value >= minValue, "undercollateralized");
        token.transfer(msg.sender, amount);
    }
}
"""

_PROVIDER_CLEAN = _TOKEN_IFACE + _PRICE_FEED_IFACE + """
contract LoopscaleMarketClean {
    IERC20Like public token;
    address public owner;
    mapping(address => address) public priceProviders;
    uint256 public minValue;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setPriceProvider(address market, address provider) external onlyOwner {
        priceProviders[market] = provider;
    }

    function borrow(address market, uint256 amount) external {
        address provider = priceProviders[market];
        uint256 price = uint256(IPriceFeedLike(provider).latestAnswer());
        uint256 value = amount * price;
        require(value >= minValue, "undercollateralized");
        token.transfer(msg.sender, amount);
    }
}
"""

_PROVIDER_VARIANT = _TOKEN_IFACE + _PRICE_FEED_IFACE + """
contract LoopscaleMarketFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => address) public priceProviders;
    uint256 public minValue;

    function setPriceProvider(address market, address provider) external {
        priceProviders[market] = provider;
    }

    function borrow(address market, uint256 amount) external {
        address provider = priceProviders[market];
        uint256 price = uint256(IPriceFeedLike(provider).latestAnswer());
        uint256 value = amount * price;
        require(value >= minValue, "undercollateralized");
        token.transfer(treasury, amount);
    }
}
"""

_PROVIDER_EXTRA_CLEAN = _TOKEN_IFACE + _PRICE_FEED_IFACE + """
contract LoopscaleMarketAllowlisted {
    IERC20Like public token;
    mapping(address => address) public priceProviders;
    mapping(address => bool) public approvedProviders;
    uint256 public minValue;

    function setPriceProvider(address market, address provider) external {
        priceProviders[market] = provider;
    }

    function borrow(address market, uint256 amount) external {
        address provider = priceProviders[market];
        require(approvedProviders[provider], "provider not approved");
        uint256 price = uint256(IPriceFeedLike(provider).latestAnswer());
        uint256 value = amount * price;
        require(value >= minValue, "undercollateralized");
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. callback_token_cei_violation
# ---------------------------------------------------------------------------

_CEI_VULN = _TOKEN_IFACE + """
contract CreamVaultVuln {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount, address recipient) external {
        require(balances[msg.sender] >= amount, "insufficient");
        token.transfer(recipient, amount);
        balances[msg.sender] -= amount;
    }

    function mintShares(uint256 amount, address recipient) external {
        token.transferFrom(msg.sender, address(this), amount);
        balances[recipient] += amount;
    }
}
"""

_CEI_CLEAN = _TOKEN_IFACE + """
contract CreamVaultClean {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount, address recipient) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        token.transfer(recipient, amount);
    }

    function mintShares(uint256 amount, address recipient) external {
        balances[recipient] += amount;
        token.transferFrom(msg.sender, address(this), amount);
    }
}
"""

_CEI_VARIANT = _TOKEN_IFACE + """
contract CreamVaultFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount, address recipient) external {
        require(balances[msg.sender] >= amount, "insufficient");
        token.transfer(treasury, amount);
        balances[msg.sender] -= amount;
    }
}
"""

_CEI_EXTRA_CLEAN = _TOKEN_IFACE + """
contract CreamVaultGuarded {
    IERC20Like public token;
    mapping(address => uint256) public balances;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    function withdraw(uint256 amount, address recipient) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        token.transfer(recipient, amount);
        balances[msg.sender] -= amount;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. forwarder_library_msgdata_tail_confusion
# ---------------------------------------------------------------------------

_FORWARDER_VULN = _TOKEN_IFACE + """
contract MezoVaultVuln {
    IERC20Like public token;
    address public trustedForwarder;
    address public library;
    mapping(address => uint256) public balances;

    function _msgSender() internal view returns (address) {
        if (msg.sender == trustedForwarder) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
        }
        return msg.sender;
    }

    function executeViaLibrary(bytes calldata data, uint256 amount) external {
        (bool ok,) = library.call(data);
        require(ok, "lib call failed");
        require(balances[_msgSender()] >= amount, "insufficient");
        token.transfer(_msgSender(), amount);
    }
}
"""

_FORWARDER_CLEAN = _TOKEN_IFACE + """
contract MezoVaultClean {
    IERC20Like public token;
    address public library;
    mapping(address => uint256) public balances;

    function executeViaLibrary(bytes calldata data, uint256 amount) external {
        (bool ok,) = library.call(data);
        require(ok, "lib call failed");
        require(balances[msg.sender] >= amount, "insufficient");
        token.transfer(msg.sender, amount);
    }
}
"""

_FORWARDER_VARIANT = _TOKEN_IFACE + """
contract MezoVaultFixed {
    IERC20Like public token;
    address public trustedForwarder;
    address public library;
    address public treasury;
    mapping(address => uint256) public balances;

    function _msgSender() internal view returns (address) {
        if (msg.sender == trustedForwarder) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
        }
        return msg.sender;
    }

    function executeViaLibrary(bytes calldata data, uint256 amount) external {
        (bool ok,) = library.call(data);
        require(ok, "lib call failed");
        require(balances[_msgSender()] >= amount, "insufficient");
        token.transfer(treasury, amount);
    }
}
"""

_FORWARDER_EXTRA_CLEAN = _TOKEN_IFACE + """
contract MezoVaultFixedCalldata {
    IERC20Like public token;
    address public trustedForwarder;
    address public library;
    mapping(address => uint256) public balances;

    function _msgSender() internal view returns (address) {
        if (msg.sender == trustedForwarder) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
        }
        return msg.sender;
    }

    function executeViaLibrary(uint256 amount) external {
        bytes memory data = abi.encodeWithSelector(0x12345678, amount);
        (bool ok,) = library.call(data);
        require(ok, "lib call failed");
        require(balances[_msgSender()] >= amount, "insufficient");
        token.transfer(_msgSender(), amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. governance_no_snapshot_immediate_seat
# ---------------------------------------------------------------------------

_GOV_VULN = _TOKEN_IFACE + """
contract ElectionVuln {
    IERC20Like public token;
    mapping(address => uint256) public votes;
    address public leader;
    mapping(address => bool) public isCouncil;

    function vote(address candidate) external {
        uint256 weight = token.balanceOf(msg.sender);
        votes[candidate] += weight;
    }

    function electLeader(address candidate) external {
        require(votes[candidate] > 0, "no votes");
        leader = candidate;
        isCouncil[candidate] = true;
    }

    function privilegedAction() external {
        require(isCouncil[msg.sender], "not council");
    }
}
"""

_GOV_CLEAN = _TOKEN_IFACE + """
contract ElectionClean {
    IERC20Like public token;
    mapping(address => uint256) public votes;
    address public leader;
    mapping(address => bool) public isCouncil;

    function vote(address candidate, uint256 snapshotBlock) external {
        uint256 weight = token.getPastVotes(msg.sender, snapshotBlock);
        votes[candidate] += weight;
    }

    function electLeader(address candidate) external {
        require(votes[candidate] > 0, "no votes");
        leader = candidate;
        isCouncil[candidate] = true;
    }

    function privilegedAction() external {
        require(isCouncil[msg.sender], "not council");
    }
}
"""

_GOV_VARIANT = _TOKEN_IFACE + """
contract ElectionFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => uint256) public votes;
    address public leader;
    mapping(address => bool) public isCouncil;

    function vote(address candidate) external {
        uint256 weight = token.balanceOf(msg.sender);
        votes[candidate] += weight;
        token.transfer(treasury, 1);
    }

    function electLeader(address candidate) external {
        require(votes[candidate] > 0, "no votes");
        leader = candidate;
        isCouncil[candidate] = true;
    }

    function privilegedAction() external {
        require(isCouncil[msg.sender], "not council");
    }
}
"""

_GOV_EXTRA_CLEAN = _TOKEN_IFACE + """
contract ElectionTimelocked {
    IERC20Like public token;
    mapping(address => uint256) public votes;
    address public leader;
    mapping(address => bool) public isCouncil;
    uint256 public activationTime;

    function vote(address candidate) external {
        uint256 weight = token.balanceOf(msg.sender);
        votes[candidate] += weight;
    }

    function electLeader(address candidate) external {
        require(votes[candidate] > 0, "no votes");
        require(block.timestamp >= activationTime, "seat not active yet");
        leader = candidate;
        isCouncil[candidate] = true;
    }

    function privilegedAction() external {
        require(isCouncil[msg.sender], "not council");
    }
}
"""

# ---------------------------------------------------------------------------
# 5. vault_underwrites_attacker_created_pool
# ---------------------------------------------------------------------------

_POOL_FACTORY_IFACE = """
interface IPoolFactoryLike {
    function createPool(address tokenA, address tokenB) external returns (address);
}

interface IPoolLike {
    function totalLiquidity() external view returns (uint256);
}
"""

_POOL_VULN = _TOKEN_IFACE + _POOL_FACTORY_IFACE + """
contract PremiaVaultVuln {
    IERC20Like public token;
    address public factory;

    function invest(address pool, uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        token.transfer(pool, amount);
    }
}
"""

_POOL_CLEAN = _TOKEN_IFACE + _POOL_FACTORY_IFACE + """
contract PremiaVaultClean {
    IERC20Like public token;
    mapping(address => bool) public allowedPools;

    function invest(address pool, uint256 amount) external {
        require(allowedPools[pool], "pool not allowed");
        token.transferFrom(msg.sender, address(this), amount);
        token.transfer(pool, amount);
    }
}
"""

_POOL_VARIANT = _TOKEN_IFACE + _POOL_FACTORY_IFACE + """
contract PremiaVaultFixed {
    IERC20Like public token;
    address public factory;

    function invest(uint256 amount) external {
        address pool = IPoolFactoryLike(factory).createPool(address(token), address(token));
        token.transferFrom(msg.sender, address(this), amount);
        token.transfer(pool, amount);
    }
}
"""

_POOL_EXTRA_CLEAN = _TOKEN_IFACE + _POOL_FACTORY_IFACE + """
contract PremiaVaultLiquid {
    IERC20Like public token;
    uint256 public minLiquidity;

    function invest(address pool, uint256 amount) external {
        require(IPoolLike(pool).totalLiquidity() >= minLiquidity, "pool too small");
        token.transferFrom(msg.sender, address(this), amount);
        token.transfer(pool, amount);
    }
}
"""

VULN = {
    "lending_collateral_price_provider_unvalidated": _PROVIDER_VULN,
    "callback_token_cei_violation": _CEI_VULN,
    "forwarder_library_msgdata_tail_confusion": _FORWARDER_VULN,
    "governance_no_snapshot_immediate_seat": _GOV_VULN,
    "vault_underwrites_attacker_created_pool": _POOL_VULN,
}

CLEAN = {
    "lending_collateral_price_provider_unvalidated": _PROVIDER_CLEAN,
    "callback_token_cei_violation": _CEI_CLEAN,
    "forwarder_library_msgdata_tail_confusion": _FORWARDER_CLEAN,
    "governance_no_snapshot_immediate_seat": _GOV_CLEAN,
    "vault_underwrites_attacker_created_pool": _POOL_CLEAN,
}

VARIANT = {
    "lending_collateral_price_provider_unvalidated": _PROVIDER_VARIANT,
    "callback_token_cei_violation": _CEI_VARIANT,
    "forwarder_library_msgdata_tail_confusion": _FORWARDER_VARIANT,
    "governance_no_snapshot_immediate_seat": _GOV_VARIANT,
    "vault_underwrites_attacker_created_pool": _POOL_VARIANT,
}

EXTRA_CLEAN = {
    "lending_collateral_price_provider_unvalidated": _PROVIDER_EXTRA_CLEAN,
    "callback_token_cei_violation": _CEI_EXTRA_CLEAN,
    "forwarder_library_msgdata_tail_confusion": _FORWARDER_EXTRA_CLEAN,
    "governance_no_snapshot_immediate_seat": _GOV_EXTRA_CLEAN,
    "vault_underwrites_attacker_created_pool": _POOL_EXTRA_CLEAN,
}

# ---------------------------------------------------------------------------
# FP regression shapes (pinned 2026-11-10 from the live-run
# hand-read: every one of these fired on the first corpus pass
# and was hand-read as a false positive - the pool-method
# receiver was a fixed protocol / parent contract, not a
# caller-derived pool).
# ---------------------------------------------------------------------------

# super.mint() passthrough (ERC20 share-token mint): the
# receiver is `super`, not a pool the caller picked.
_FP_SUPER_MINT = _TOKEN_IFACE + """
contract ShareTokenFp {
    IERC20Like public token;

    function mint(address to, uint256 value) public override {
        super.mint(to, value);
        require(totalSupply() <= type(uint128).max, "cap");
    }

    function totalSupply() public view returns (uint256) {
        return 0;
    }
}
"""

# MORPHO.supply() on the fixed Morpho protocol: the market is
# selected by a stored id, the protocol address is immutable -
# not a caller-supplied or freshly created pool.
_FP_MORPHO_SUPPLY = """
interface IMorphoLike {
    struct MarketParams {
        address loanToken;
        address collateralToken;
    }
    function supply(MarketParams memory marketParams, uint256 assets, uint256 shares, address onBehalf, bytes calldata data) external returns (uint256, uint256);
    function market(bytes32 id) external view returns (uint256 totalSupplyAssets, uint256 totalSupplyShares);
}

contract MorphoVaultFp {
    IMorphoLike public constant MORPHO = IMorphoLike(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF42C476);
    bytes32 public id;

    function _marketParams(bytes32 marketId) internal view returns (IMorphoLike.MarketParams memory) {
        return IMorphoLike.MarketParams(address(0), address(0));
    }

    function _supplyMorpho(uint256 assets) internal {
        IMorphoLike.MarketParams memory marketParams = _marketParams(id);
        (uint256 totalSupplyAssets, uint256 totalSupplyShares) = MORPHO.market(id);
        MORPHO.supply(marketParams, assets, 0, address(this), hex"");
    }
}
"""

# router.addLiquidity() on a fixed DEX router: the router is a
# stored address and the currency is allowlisted - the vault
# does not send collateral into a caller-picked pool.
_FP_ROUTER_LIQUIDITY = _TOKEN_IFACE + """
interface IRouterLike {
    function addLiquidity(address tokenA, address tokenB, uint256 amountADesired, uint256 amountBDesired, uint256 amountAMin, uint256 amountBMin, address to, uint256 deadline) external returns (uint256 amountA, uint256 amountB, uint256 liquidity);
}

contract RouterVaultFp {
    IRouterLike public router;
    mapping(address => bool) public currencyList;

    function mintWhitelist(uint256 _amount, address _currency) public {
        require(currencyList[_currency], "currency not supported");
        IERC20Like(_currency).transferFrom(msg.sender, address(this), _amount);
        router.addLiquidity(_currency, address(this), _amount, _amount, 0, 0, msg.sender, block.timestamp);
    }
}
"""

FP_REGRESSION = {
    "pool_super_mint_passthrough": _FP_SUPER_MINT,
    "pool_morpho_fixed_protocol": _FP_MORPHO_SUPPLY,
    "pool_router_fixed_add_liquidity": _FP_ROUTER_LIQUIDITY,
}
