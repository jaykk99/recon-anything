"""Fixtures for the deep-audit batch-31 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind
and code evidence. The oracle detector fires with report_class
"candidate" (the borrower is the caller, CALLER); the honeypot,
upgrade, and mint detectors fire WITHOUT a recipient
classification (batch-20 auction precedent): a honeypot is a
scam warning to buyers, an upgrade held by one key and an
owner mint are trust warnings about the privileged actor -
neither is value a stranger can receive by calling the
function. CLEAN[id] (the protected shape of the same class)
MUST stay silent under ALL four detectors; VARIANT[oracle_
spot_collateral_borrow] carries the same vulnerable shape
but the loan is paid to a FIXED treasury, so it MUST fire
with report_class "trigger_only" at low severity - never a
candidate.

Cross-talk by construction: the honeypot fixtures name no
borrow / upgrade / mint function; the oracle fixture names
no transfer-gate / upgrade / mint function; the upgrade
fixture names no transfer / borrow / mint function; the
mint fixture names no transfer / borrow / upgrade function.
DOCUMENTED CO-FIRE: single_source_oracle fires on the
oracle VULN fixture by design - the spot read is the same
signal; the new detector adds the borrow leg the generic
oracle detector cannot express. That co-fire is pinned
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

_PAIR_IFACE = """
interface IPairLike {
    function getReserves() external view returns (uint112, uint112, uint32);
}
"""

# ---------------------------------------------------------------------------
# 1. honeypot_sell_gate_static - leg (a): sell-side blacklist gate
# ---------------------------------------------------------------------------

_HONEYPOT_GATE_VULN = _TOKEN_IFACE + """
contract HoneypotSellGate {
    IERC20Like public token;
    mapping(address => bool) public isBlacklisted;
    address public uniswapV2Pair;
    mapping(address => uint256) public balanceOf;

    function _transfer(address from, address to, uint256 amount) internal {
        if (to == uniswapV2Pair) {
            require(!isBlacklisted[from], "blacklisted");
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }
}
"""

# ---------------------------------------------------------------------------
# 1b. honeypot_sell_gate_static - leg (b): 99% sell fee
# ---------------------------------------------------------------------------

_HONEYPOT_FEE_VULN = _TOKEN_IFACE + """
contract HoneypotSellFee {
    IERC20Like public token;
    uint256 public sellFee = 99;
    address public uniswapV2Pair;
    mapping(address => uint256) public balanceOf;

    function _transfer(address from, address to, uint256 amount) internal {
        uint256 fee = 0;
        if (to == uniswapV2Pair) {
            fee = amount * sellFee / 100;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }
}
"""

_HONEYPOT_CLEAN = _TOKEN_IFACE + """
contract CleanFeeToken {
    IERC20Like public token;
    mapping(address => bool) public isBlacklisted;
    uint256 public sellFee = 3;
    mapping(address => uint256) public balanceOf;

    function _transfer(address from, address to, uint256 amount) internal {
        require(!isBlacklisted[from], "blacklisted");
        require(!isBlacklisted[to], "blacklisted");
        uint256 fee = amount * sellFee / 100;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }
}
"""

# ---------------------------------------------------------------------------
# 2. oracle_spot_collateral_borrow
# ---------------------------------------------------------------------------

_ORACLE_BORROW_VULN = _TOKEN_IFACE + _PAIR_IFACE + """
contract SpotBorrowVuln {
    IERC20Like public token;
    IPairLike public pair;
    mapping(address => uint256) public borrows;

    function borrow(uint256 collateralAmount, uint256 borrowAmount) external {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 price = uint256(r0) * 1e18 / uint256(r1);
        uint256 collateralValue = collateralAmount * price / 1e18;
        require(borrowAmount <= collateralValue, "insufficient collateral");
        borrows[msg.sender] += borrowAmount;
        token.transfer(msg.sender, borrowAmount);
    }
}
"""

_ORACLE_BORROW_VARIANT = _TOKEN_IFACE + _PAIR_IFACE + """
contract SpotBorrowFixedTreasury {
    IERC20Like public token;
    IPairLike public pair;
    address public treasury;
    mapping(address => uint256) public borrows;

    function borrow(uint256 collateralAmount, uint256 borrowAmount) external {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 price = uint256(r0) * 1e18 / uint256(r1);
        uint256 collateralValue = collateralAmount * price / 1e18;
        require(borrowAmount <= collateralValue, "insufficient collateral");
        borrows[msg.sender] += borrowAmount;
        token.transfer(treasury, borrowAmount);
    }
}
"""

_ORACLE_BORROW_CLEAN = _TOKEN_IFACE + _PAIR_IFACE + """
contract TwapBorrowClean {
    IERC20Like public token;
    IPairLike public pair;
    mapping(address => uint256) public borrows;

    function borrow(uint256 collateralAmount, uint256 borrowAmount) external {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 price = uint256(r0) * 1e18 / uint256(r1);
        uint256 twap = _twapPrice();
        require(price <= twap * 105 / 100 && price >= twap * 95 / 100, "price moved");
        uint256 collateralValue = collateralAmount * twap / 1e18;
        require(borrowAmount <= collateralValue, "insufficient collateral");
        borrows[msg.sender] += borrowAmount;
        token.transfer(msg.sender, borrowAmount);
    }

    function _twapPrice() internal view returns (uint256) {
        return 1e18;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. upgrade_single_key_admin
# ---------------------------------------------------------------------------

_UPGRADE_VULN = """
contract UpgradeSingleKey {
    address public implementation;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _authorizeUpgrade(address newImplementation) internal onlyOwner {
    }

    function upgradeTo(address newImplementation) external onlyOwner {
        _authorizeUpgrade(newImplementation);
        implementation = newImplementation;
    }
}
"""

_UPGRADE_CLEAN = """
contract UpgradeTimelockClean {
    address public implementation;
    address public timelock;

    modifier onlyTimelock() {
        require(msg.sender == timelock, "not timelock");
        _;
    }

    function _authorizeUpgrade(address newImplementation) internal onlyTimelock {
    }

    function upgradeTo(address newImplementation) external onlyTimelock {
        _authorizeUpgrade(newImplementation);
        implementation = newImplementation;
    }
}
"""

# ---------------------------------------------------------------------------
# 4. owner_mint_uncapped
# ---------------------------------------------------------------------------

_MINT_VULN = """
contract OwnerMintVuln {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

_MINT_CLEAN = """
contract CappedRoleMintClean {
    uint256 public constant MAX_SUPPLY = 1000000 ether;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    mapping(bytes32 => mapping(address => bool)) public roles;

    modifier onlyRole(bytes32 role) {
        require(roles[role][msg.sender], "no role");
        _;
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        require(totalSupply + amount <= MAX_SUPPLY, "cap");
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

# A plain token with no borrow / upgrade / mint / transfer-gate
# surface at all - must stay silent under every detector.
_PLAIN_CLEAN = _TOKEN_IFACE + """
contract PlainTokenClean {
    IERC20Like public token;
    mapping(address => uint256) public balanceOf;

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"""

VULN = {
    "honeypot_sell_gate_static": _HONEYPOT_GATE_VULN,
    "oracle_spot_collateral_borrow": _ORACLE_BORROW_VULN,
    "upgrade_single_key_admin": _UPGRADE_VULN,
    "owner_mint_uncapped": _MINT_VULN,
}

# Second honeypot leg (99% sell fee) - same detector, separate fixture.
VULN_FEE = _HONEYPOT_FEE_VULN

VARIANT = {
    "oracle_spot_collateral_borrow": _ORACLE_BORROW_VARIANT,
}

CLEAN = {
    "honeypot_sell_gate_static": _HONEYPOT_CLEAN,
    "oracle_spot_collateral_borrow": _ORACLE_BORROW_CLEAN,
    "upgrade_single_key_admin": _UPGRADE_CLEAN,
    "owner_mint_uncapped": _MINT_CLEAN,
}

EXTRA_CLEAN = {
    "plain_token": _PLAIN_CLEAN,
}
