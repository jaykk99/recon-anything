"""Fixtures for the deep-audit batch-18 detector.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent; VARIANT[id]
carries the same vulnerable shape but the shares land at a FIXED
destination, so it MUST fire with report_class "trigger_only" at
low severity - never a candidate.

EXTRA_VULN holds two more firing shapes: a caller-supplied
recipient (CALLER-SUPPLIED candidate) and the amount0/amount1
split-input shape (no array, so no length check can exist -
the valuation leg alone carries it).

EXTRA_CLEAN isolates each silencing leg: a full valuation with
no length check (leg c), a token0-only withdraw (leg d), and a
literal-2 length guard (leg b).
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

_HELPERS = """
    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function _burn(address from, uint256 amount) internal {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }
"""

# ---------------------------------------------------------------------------
# multitoken_deposit_length_mismatch
# ---------------------------------------------------------------------------

_VULN = _TOKEN_IFACE + """
contract MultiVaultVuln {
    IERC20Like[] public tokens;
    uint256 public price0;
    uint256 public totalValue0;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address tokenA, address tokenB, uint256 _price0) {
        tokens.push(IERC20Like(tokenA));
        tokens.push(IERC20Like(tokenB));
        price0 = _price0;
    }

    function depositMulti(uint256[] calldata amounts) external {
        uint256 value0 = amounts[0] * price0;
        uint256 shares = totalSupply == 0 ? value0 : value0 * totalSupply / totalValue0;
        tokens[0].transferFrom(msg.sender, address(this), amounts[0]);
        _mint(msg.sender, shares);
    }

    function withdrawMulti(uint256 shares) external {
        uint256 amount0 = shares * tokens[0].balanceOf(address(this)) / totalSupply;
        uint256 amount1 = shares * tokens[1].balanceOf(address(this)) / totalSupply;
        tokens[0].transfer(msg.sender, amount0);
        tokens[1].transfer(msg.sender, amount1);
        _burn(msg.sender, shares);
    }
""" + _HELPERS + """
}
"""

_VARIANT_FIXED = _TOKEN_IFACE + """
contract MultiVaultFixed {
    IERC20Like[] public tokens;
    uint256 public price0;
    uint256 public totalValue0;
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address tokenA, address tokenB, uint256 _price0) {
        tokens.push(IERC20Like(tokenA));
        tokens.push(IERC20Like(tokenB));
        price0 = _price0;
        owner = msg.sender;
    }

    function depositMulti(uint256[] calldata amounts) external {
        uint256 value0 = amounts[0] * price0;
        uint256 shares = totalSupply == 0 ? value0 : value0 * totalSupply / totalValue0;
        tokens[0].transferFrom(msg.sender, address(this), amounts[0]);
        _mint(owner, shares);
    }

    function withdrawMulti(uint256 shares) external {
        uint256 amount0 = shares * tokens[0].balanceOf(address(this)) / totalSupply;
        uint256 amount1 = shares * tokens[1].balanceOf(address(this)) / totalSupply;
        tokens[0].transfer(msg.sender, amount0);
        tokens[1].transfer(msg.sender, amount1);
        _burn(msg.sender, shares);
    }
""" + _HELPERS + """
}
"""

_CLEAN = _TOKEN_IFACE + """
contract MultiVaultClean {
    IERC20Like[] public tokens;
    uint256 public price0;
    uint256 public price1;
    uint256 public totalValue;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address tokenA, address tokenB, uint256 _price0, uint256 _price1) {
        tokens.push(IERC20Like(tokenA));
        tokens.push(IERC20Like(tokenB));
        price0 = _price0;
        price1 = _price1;
    }

    function depositMulti(uint256[] calldata amounts) external {
        require(amounts.length == tokens.length, "bad length");
        uint256 value = amounts[0] * price0 + amounts[1] * price1;
        uint256 shares = totalSupply == 0 ? value : value * totalSupply / totalValue;
        tokens[0].transferFrom(msg.sender, address(this), amounts[0]);
        tokens[1].transferFrom(msg.sender, address(this), amounts[1]);
        _mint(msg.sender, shares);
    }

    function withdrawMulti(uint256 shares) external {
        uint256 amount0 = shares * tokens[0].balanceOf(address(this)) / totalSupply;
        uint256 amount1 = shares * tokens[1].balanceOf(address(this)) / totalSupply;
        tokens[0].transfer(msg.sender, amount0);
        tokens[1].transfer(msg.sender, amount1);
        _burn(msg.sender, shares);
    }
""" + _HELPERS + """
}
"""

_CLEAN_SINGLE_TOKEN = _TOKEN_IFACE + """
contract SingleTokenVaultClean {
    IERC20Like public token;
    uint256 public price;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address _token, uint256 _price) {
        token = IERC20Like(_token);
        price = _price;
    }

    function deposit(uint256[] calldata amounts) external {
        uint256 value = amounts[0] * price;
        uint256 shares = totalSupply == 0 ? value : value * totalSupply / token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amounts[0]);
        _mint(msg.sender, shares);
    }

    function withdraw(uint256 shares) external {
        uint256 amount = shares * token.balanceOf(address(this)) / totalSupply;
        token.transfer(msg.sender, amount);
        _burn(msg.sender, shares);
    }
""" + _HELPERS + """
}
"""

_EXTRA_VULN_CALLER_SUPPLIED = _TOKEN_IFACE + """
contract MultiVaultCallerSupplied {
    IERC20Like[] public tokens;
    uint256 public price0;
    uint256 public totalValue0;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address tokenA, address tokenB, uint256 _price0) {
        tokens.push(IERC20Like(tokenA));
        tokens.push(IERC20Like(tokenB));
        price0 = _price0;
    }

    function depositMulti(uint256[] calldata amounts, address to) external {
        uint256 value0 = amounts[0] * price0;
        uint256 shares = totalSupply == 0 ? value0 : value0 * totalSupply / totalValue0;
        tokens[0].transferFrom(msg.sender, address(this), amounts[0]);
        _mint(to, shares);
    }

    function withdrawMulti(uint256 shares) external {
        uint256 amount0 = shares * tokens[0].balanceOf(address(this)) / totalSupply;
        uint256 amount1 = shares * tokens[1].balanceOf(address(this)) / totalSupply;
        tokens[0].transfer(msg.sender, amount0);
        tokens[1].transfer(msg.sender, amount1);
        _burn(msg.sender, shares);
    }
""" + _HELPERS + """
}
"""

_EXTRA_VULN_SPLIT_INPUTS = _TOKEN_IFACE + """
contract MultiVaultSplitInputs {
    IERC20Like[] public tokens;
    uint256 public price0;
    uint256 public totalValue0;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address tokenA, address tokenB, uint256 _price0) {
        tokens.push(IERC20Like(tokenA));
        tokens.push(IERC20Like(tokenB));
        price0 = _price0;
    }

    function deposit(uint256 amount0, uint256 amount1) external {
        uint256 value0 = amount0 * price0;
        uint256 shares = totalSupply == 0 ? value0 : value0 * totalSupply / totalValue0;
        tokens[0].transferFrom(msg.sender, address(this), amount0);
        _mint(msg.sender, shares);
    }

    function withdrawMulti(uint256 shares) external {
        uint256 amount0 = shares * tokens[0].balanceOf(address(this)) / totalSupply;
        uint256 amount1 = shares * tokens[1].balanceOf(address(this)) / totalSupply;
        tokens[0].transfer(msg.sender, amount0);
        tokens[1].transfer(msg.sender, amount1);
        _burn(msg.sender, shares);
    }
""" + _HELPERS + """
}
"""

_EXTRA_CLEAN_FULL_VALUATION = _TOKEN_IFACE + """
contract MultiVaultFullValuation {
    IERC20Like[] public tokens;
    uint256 public price0;
    uint256 public price1;
    uint256 public totalValue;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address tokenA, address tokenB, uint256 _price0, uint256 _price1) {
        tokens.push(IERC20Like(tokenA));
        tokens.push(IERC20Like(tokenB));
        price0 = _price0;
        price1 = _price1;
    }

    function depositMulti(uint256[] calldata amounts) external {
        uint256 value = amounts[0] * price0 + amounts[1] * price1;
        uint256 shares = totalSupply == 0 ? value : value * totalSupply / totalValue;
        tokens[0].transferFrom(msg.sender, address(this), amounts[0]);
        tokens[1].transferFrom(msg.sender, address(this), amounts[1]);
        _mint(msg.sender, shares);
    }

    function withdrawMulti(uint256 shares) external {
        uint256 amount0 = shares * tokens[0].balanceOf(address(this)) / totalSupply;
        uint256 amount1 = shares * tokens[1].balanceOf(address(this)) / totalSupply;
        tokens[0].transfer(msg.sender, amount0);
        tokens[1].transfer(msg.sender, amount1);
        _burn(msg.sender, shares);
    }
""" + _HELPERS + """
}
"""

_EXTRA_CLEAN_TOKEN0_WITHDRAW = _TOKEN_IFACE + """
contract MultiVaultToken0Withdraw {
    IERC20Like[] public tokens;
    uint256 public price0;
    uint256 public price1;
    uint256 public totalValue0;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address tokenA, address tokenB, uint256 _price0, uint256 _price1) {
        tokens.push(IERC20Like(tokenA));
        tokens.push(IERC20Like(tokenB));
        price0 = _price0;
        price1 = _price1;
    }

    function totalValue() external view returns (uint256) {
        return tokens[0].balanceOf(address(this)) * price0 + tokens[1].balanceOf(address(this)) * price1;
    }

    function depositMulti(uint256[] calldata amounts) external {
        uint256 value0 = amounts[0] * price0;
        uint256 shares = totalSupply == 0 ? value0 : value0 * totalSupply / totalValue0;
        tokens[0].transferFrom(msg.sender, address(this), amounts[0]);
        _mint(msg.sender, shares);
    }

    function withdrawMulti(uint256 shares) external {
        uint256 amount0 = shares * tokens[0].balanceOf(address(this)) / totalSupply;
        tokens[0].transfer(msg.sender, amount0);
        _burn(msg.sender, shares);
    }
""" + _HELPERS + """
}
"""

_EXTRA_CLEAN_LENGTH_LITERAL = _TOKEN_IFACE + """
contract MultiVaultLengthLiteral {
    IERC20Like[] public tokens;
    uint256 public price0;
    uint256 public totalValue0;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address tokenA, address tokenB, uint256 _price0) {
        tokens.push(IERC20Like(tokenA));
        tokens.push(IERC20Like(tokenB));
        price0 = _price0;
    }

    function depositMulti(uint256[] calldata amounts) external {
        require(amounts.length == 2, "bad length");
        uint256 value0 = amounts[0] * price0;
        uint256 shares = totalSupply == 0 ? value0 : value0 * totalSupply / totalValue0;
        tokens[0].transferFrom(msg.sender, address(this), amounts[0]);
        _mint(msg.sender, shares);
    }

    function withdrawMulti(uint256 shares) external {
        uint256 amount0 = shares * tokens[0].balanceOf(address(this)) / totalSupply;
        uint256 amount1 = shares * tokens[1].balanceOf(address(this)) / totalSupply;
        tokens[0].transfer(msg.sender, amount0);
        tokens[1].transfer(msg.sender, amount1);
        _burn(msg.sender, shares);
    }
""" + _HELPERS + """
}
"""

PID = "multitoken_deposit_length_mismatch"

VULN = {
    PID: _VULN,
}

CLEAN = {
    PID: _CLEAN,
    "single_token_vault": _CLEAN_SINGLE_TOKEN,
}

VARIANT = {
    PID: _VARIANT_FIXED,
}

EXTRA_VULN = {
    "caller_supplied_recipient": _EXTRA_VULN_CALLER_SUPPLIED,
    "amounts0_amounts1_style": _EXTRA_VULN_SPLIT_INPUTS,
}

EXTRA_CLEAN = {
    # No length check, but the valuation reads BOTH tokens:
    # leg (c) alone silences it.
    "full_valuation_no_length_check": _EXTRA_CLEAN_FULL_VALUATION,
    # Vuln-shaped deposit, but withdraw pays token0 only:
    # no asymmetry, leg (d) alone silences it. totalValue()
    # keeps the second token visible to the contract so the
    # silence is the withdraw leg's doing, not the
    # multi-token leg's.
    "token0_only_withdraw": _EXTRA_CLEAN_TOKEN0_WITHDRAW,
    # Token0-only valuation, but the length IS guarded with
    # the literal-2 form: leg (b) alone silences it.
    "length_check_literal_2": _EXTRA_CLEAN_LENGTH_LITERAL,
}
