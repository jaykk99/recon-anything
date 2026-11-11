"""Fixtures for the deep-audit batch-15 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
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
# 1. unsafe_narrowing_cast_collateral_zero
# ---------------------------------------------------------------------------

_NARROW_VULN = _TOKEN_IFACE + """
contract NotionalEscrowVuln {
    IERC20Like public token;
    mapping(address => int256) public liabilities;
    mapping(address => uint256) public balances;

    function _abs(int256 x) internal pure returns (uint256) {
        return x >= 0 ? uint256(x) : uint256(-x);
    }

    function borrow(uint256 amount, address to) external {
        int256 liability = liabilities[msg.sender] + int256(amount);
        uint128 narrowed = uint128(_abs(liability));
        liabilities[msg.sender] = liability;
        uint256 collateral = balances[msg.sender];
        int256 freeCollateral = int256(collateral) - int256(uint256(narrowed));
        require(freeCollateral >= 0, "insolvent");
        token.transfer(to, amount);
    }
}
"""

_NARROW_CLEAN = _TOKEN_IFACE + """
contract NotionalEscrowClean {
    IERC20Like public token;
    mapping(address => int256) public liabilities;
    mapping(address => uint256) public balances;

    function _abs(int256 x) internal pure returns (uint256) {
        return x >= 0 ? uint256(x) : uint256(-x);
    }

    function borrow(uint256 amount, address to) external {
        int256 liability = liabilities[msg.sender] + int256(amount);
        uint128 narrowed = SafeCast.toUint128(_abs(liability));
        liabilities[msg.sender] = liability;
        uint256 collateral = balances[msg.sender];
        int256 freeCollateral = int256(collateral) - int256(uint256(narrowed));
        require(freeCollateral >= 0, "insolvent");
        token.transfer(to, amount);
    }
}
"""

_NARROW_MAX_CHECK = _TOKEN_IFACE + """
contract NotionalEscrowMaxCheck {
    IERC20Like public token;
    mapping(address => int256) public liabilities;
    mapping(address => uint256) public balances;

    function _abs(int256 x) internal pure returns (uint256) {
        return x >= 0 ? uint256(x) : uint256(-x);
    }

    function borrow(uint256 amount, address to) external {
        int256 liability = liabilities[msg.sender] + int256(amount);
        require(_abs(liability) <= type(uint128).max, "overflow");
        uint128 narrowed = uint128(_abs(liability));
        liabilities[msg.sender] = liability;
        uint256 collateral = balances[msg.sender];
        int256 freeCollateral = int256(collateral) - int256(uint256(narrowed));
        require(freeCollateral >= 0, "insolvent");
        token.transfer(to, amount);
    }
}
"""

_NARROW_DISPLAY_ONLY = _TOKEN_IFACE + """
contract NotionalEscrowDisplay {
    IERC20Like public token;
    mapping(address => int256) public liabilities;
    event CollateralQuoted(address indexed account, uint128 shown);

    function _abs(int256 x) internal pure returns (uint256) {
        return x >= 0 ? uint256(x) : uint256(-x);
    }

    function quoteCollateral(address account) external {
        int256 liability = liabilities[account];
        uint128 shown = uint128(_abs(liability));
        emit CollateralQuoted(account, shown);
    }
}
"""

_NARROW_VARIANT = _TOKEN_IFACE + """
contract NotionalEscrowFixed {
    IERC20Like public token;
    mapping(address => int256) public liabilities;
    mapping(address => uint256) public balances;
    address public treasury;

    function _abs(int256 x) internal pure returns (uint256) {
        return x >= 0 ? uint256(x) : uint256(-x);
    }

    function borrow(uint256 amount) external {
        int256 liability = liabilities[msg.sender] + int256(amount);
        uint128 narrowed = uint128(_abs(liability));
        liabilities[msg.sender] = liability;
        uint256 collateral = balances[msg.sender];
        int256 freeCollateral = int256(collateral) - int256(uint256(narrowed));
        require(freeCollateral >= 0, "insolvent");
        token.transfer(treasury, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. negative_fee_mint_inflation
# ---------------------------------------------------------------------------

_FEE_VULN = _TOKEN_IFACE + """
contract SymbiosisBridgeVuln {
    IERC20Like public syBTC;
    int256 public fee;
    address public relayer;

    function setFee(int256 _fee) external {
        require(msg.sender == relayer, "not relayer");
        fee = _fee;
    }

    function deposit(uint256 amount) external {
        int256 credited = int256(amount) - fee;
        _mint(msg.sender, uint256(credited));
    }

    function _mint(address to, uint256 amount) internal {
        syBTC.transfer(to, amount);
    }
}
"""

_FEE_CLEAN = _TOKEN_IFACE + """
contract SymbiosisBridgeClean {
    IERC20Like public syBTC;
    uint256 public fee;
    address public relayer;

    function setFee(uint256 _fee) external {
        require(msg.sender == relayer, "not relayer");
        fee = _fee;
    }

    function deposit(uint256 amount) external {
        uint256 credited = amount - fee;
        _mint(msg.sender, credited);
    }

    function _mint(address to, uint256 amount) internal {
        syBTC.transfer(to, amount);
    }
}
"""

_FEE_SETTER_GUARD = _TOKEN_IFACE + """
contract SymbiosisBridgeSetterGuard {
    IERC20Like public syBTC;
    int256 public fee;
    address public relayer;

    function setFee(int256 _fee) external {
        require(msg.sender == relayer, "not relayer");
        require(_fee >= 0, "fee");
        fee = _fee;
    }

    function deposit(uint256 amount) external {
        int256 credited = int256(amount) - fee;
        _mint(msg.sender, uint256(credited));
    }

    function _mint(address to, uint256 amount) internal {
        syBTC.transfer(to, amount);
    }
}
"""

_FEE_CLAMPED = _TOKEN_IFACE + """
contract SymbiosisBridgeClamped {
    IERC20Like public syBTC;
    int256 public fee;
    address public relayer;

    function setFee(int256 _fee) external {
        require(msg.sender == relayer, "not relayer");
        fee = _fee;
    }

    function deposit(uint256 amount) external {
        int256 credited = int256(amount) - fee;
        require(credited <= int256(amount), "overcredit");
        _mint(msg.sender, uint256(credited));
    }

    function _mint(address to, uint256 amount) internal {
        syBTC.transfer(to, amount);
    }
}
"""

_FEE_VARIANT = _TOKEN_IFACE + """
contract SymbiosisBridgeFixed {
    IERC20Like public syBTC;
    int256 public fee;
    address public relayer;
    address public treasury;

    function setFee(int256 _fee) external {
        require(msg.sender == relayer, "not relayer");
        fee = _fee;
    }

    function deposit(uint256 amount) external {
        int256 credited = int256(amount) - fee;
        syBTC.transfer(treasury, uint256(credited));
    }
}
"""

# ---------------------------------------------------------------------------
# 3. scaled_allowance_overapproval
# ---------------------------------------------------------------------------

_ALLOW_VULN = _TOKEN_IFACE + """
contract RAACVaultVuln {
    IERC20Like public token;
    uint256 public liquidityIndex;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public balanceOf;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function _spendAllowance(address owner, address spender, uint256 amount) internal {
        uint256 current = allowance[owner][spender];
        require(current >= amount, "allowance");
        allowance[owner][spender] = current - amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 scaledAmount = amount.rayDiv(liquidityIndex);
        _spendAllowance(from, msg.sender, scaledAmount);
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        token.transfer(to, amount);
        return true;
    }
}
"""

_ALLOW_CLEAN = _TOKEN_IFACE + """
contract RAACVaultClean {
    IERC20Like public token;
    uint256 public liquidityIndex;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public balanceOf;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount.rayDiv(liquidityIndex);
        return true;
    }

    function _spendAllowance(address owner, address spender, uint256 amount) internal {
        uint256 current = allowance[owner][spender];
        require(current >= amount, "allowance");
        allowance[owner][spender] = current - amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 scaledAmount = amount.rayDiv(liquidityIndex);
        _spendAllowance(from, msg.sender, scaledAmount);
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        token.transfer(to, amount);
        return true;
    }
}
"""

_ALLOW_RAW_CHECK = _TOKEN_IFACE + """
contract RAACVaultRawCheck {
    IERC20Like public token;
    uint256 public liquidityIndex;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public balanceOf;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function _spendAllowance(address owner, address spender, uint256 amount) internal {
        uint256 current = allowance[owner][spender];
        require(current >= amount, "allowance");
        allowance[owner][spender] = current - amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 scaledAmount = amount.rayDiv(liquidityIndex);
        _spendAllowance(from, msg.sender, amount);
        balanceOf[from] -= scaledAmount;
        balanceOf[to] += scaledAmount;
        token.transfer(to, scaledAmount);
        return true;
    }
}
"""

_ALLOW_FIXED_INDEX = _TOKEN_IFACE + """
contract RAACVaultFixedIndex {
    IERC20Like public token;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public balanceOf;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function _spendAllowance(address owner, address spender, uint256 amount) internal {
        uint256 current = allowance[owner][spender];
        require(current >= amount, "allowance");
        allowance[owner][spender] = current - amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 scaledAmount = amount.rayDiv(1e27);
        _spendAllowance(from, msg.sender, scaledAmount);
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        token.transfer(to, amount);
        return true;
    }
}
"""

_ALLOW_VARIANT = _TOKEN_IFACE + """
contract RAACVaultFixed {
    IERC20Like public token;
    uint256 public liquidityIndex;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public balanceOf;
    address public treasury;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function _spendAllowance(address owner, address spender, uint256 amount) internal {
        uint256 current = allowance[owner][spender];
        require(current >= amount, "allowance");
        allowance[owner][spender] = current - amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 scaledAmount = amount.rayDiv(liquidityIndex);
        _spendAllowance(from, msg.sender, scaledAmount);
        balanceOf[from] -= amount;
        balanceOf[treasury] += amount;
        token.transfer(treasury, amount);
        return true;
    }
}
"""

# ---------------------------------------------------------------------------
# 4. claim_callback_before_claimed_flag
# ---------------------------------------------------------------------------

_CLAIM_VULN = _TOKEN_IFACE + """
interface ILockup {
    function createLockedPosition(address user, uint256 amount) external;
}

contract HemiMerkleBoxVuln {
    IERC20Like public token;
    mapping(uint256 => address) public groupLockup;
    mapping(address => mapping(uint256 => bool)) public claimed;
    mapping(uint256 => uint256) public groupAmounts;

    function createGroup(uint256 groupId, address lockup) external {
        groupLockup[groupId] = lockup;
    }

    function _verifyProof(bytes32[] calldata proof, uint256 groupId, address user, uint256 amount) internal pure returns (bool) {
        return proof.length > 0 && amount > 0;
    }

    function claim(uint256 groupId, uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender][groupId], "claimed");
        require(_verifyProof(proof, groupId, msg.sender, amount), "proof");
        address lockup = groupLockup[groupId];
        ILockup(lockup).createLockedPosition(msg.sender, amount);
        claimed[msg.sender][groupId] = true;
        groupAmounts[groupId] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_CLAIM_CLEAN = _TOKEN_IFACE + """
interface ILockup {
    function createLockedPosition(address user, uint256 amount) external;
}

contract HemiMerkleBoxClean {
    IERC20Like public token;
    mapping(uint256 => address) public groupLockup;
    mapping(address => mapping(uint256 => bool)) public claimed;
    mapping(uint256 => uint256) public groupAmounts;

    function createGroup(uint256 groupId, address lockup) external {
        groupLockup[groupId] = lockup;
    }

    function _verifyProof(bytes32[] calldata proof, uint256 groupId, address user, uint256 amount) internal pure returns (bool) {
        return proof.length > 0 && amount > 0;
    }

    function claim(uint256 groupId, uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender][groupId], "claimed");
        require(_verifyProof(proof, groupId, msg.sender, amount), "proof");
        claimed[msg.sender][groupId] = true;
        groupAmounts[groupId] -= amount;
        address lockup = groupLockup[groupId];
        ILockup(lockup).createLockedPosition(msg.sender, amount);
        token.transfer(msg.sender, amount);
    }
}
"""

_CLAIM_NONREENTRANT = _TOKEN_IFACE + """
interface ILockup {
    function createLockedPosition(address user, uint256 amount) external;
}

contract HemiMerkleBoxGuarded {
    IERC20Like public token;
    mapping(uint256 => address) public groupLockup;
    mapping(address => mapping(uint256 => bool)) public claimed;
    mapping(uint256 => uint256) public groupAmounts;

    function createGroup(uint256 groupId, address lockup) external {
        groupLockup[groupId] = lockup;
    }

    function _verifyProof(bytes32[] calldata proof, uint256 groupId, address user, uint256 amount) internal pure returns (bool) {
        return proof.length > 0 && amount > 0;
    }

    function claim(uint256 groupId, uint256 amount, bytes32[] calldata proof) external nonReentrant {
        require(!claimed[msg.sender][groupId], "claimed");
        require(_verifyProof(proof, groupId, msg.sender, amount), "proof");
        address lockup = groupLockup[groupId];
        ILockup(lockup).createLockedPosition(msg.sender, amount);
        claimed[msg.sender][groupId] = true;
        groupAmounts[groupId] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_CLAIM_ALLOWLIST = _TOKEN_IFACE + """
interface ILockup {
    function createLockedPosition(address user, uint256 amount) external;
}

contract HemiMerkleBoxAllowlist {
    IERC20Like public token;
    mapping(uint256 => address) public groupLockup;
    mapping(address => mapping(uint256 => bool)) public claimed;
    mapping(uint256 => uint256) public groupAmounts;
    mapping(address => bool) public allowlistedLockups;

    function createGroup(uint256 groupId, address lockup) external {
        groupLockup[groupId] = lockup;
    }

    function _verifyProof(bytes32[] calldata proof, uint256 groupId, address user, uint256 amount) internal pure returns (bool) {
        return proof.length > 0 && amount > 0;
    }

    function claim(uint256 groupId, uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender][groupId], "claimed");
        require(_verifyProof(proof, groupId, msg.sender, amount), "proof");
        address lockup = groupLockup[groupId];
        require(allowlistedLockups[lockup], "not allowlisted");
        ILockup(lockup).createLockedPosition(msg.sender, amount);
        claimed[msg.sender][groupId] = true;
        groupAmounts[groupId] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_CLAIM_VARIANT = _TOKEN_IFACE + """
interface ILockup {
    function createLockedPosition(address user, uint256 amount) external;
}

contract HemiMerkleBoxFixed {
    IERC20Like public token;
    mapping(uint256 => address) public groupLockup;
    mapping(address => mapping(uint256 => bool)) public claimed;
    mapping(uint256 => uint256) public groupAmounts;
    address public treasury;

    function createGroup(uint256 groupId, address lockup) external {
        groupLockup[groupId] = lockup;
    }

    function _verifyProof(bytes32[] calldata proof, uint256 groupId, address user, uint256 amount) internal pure returns (bool) {
        return proof.length > 0 && amount > 0;
    }

    function claim(uint256 groupId, uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender][groupId], "claimed");
        require(_verifyProof(proof, groupId, msg.sender, amount), "proof");
        address lockup = groupLockup[groupId];
        ILockup(lockup).createLockedPosition(msg.sender, amount);
        claimed[msg.sender][groupId] = true;
        groupAmounts[groupId] -= amount;
        token.transfer(treasury, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. post_slash_erc4626_offset_inversion
# ---------------------------------------------------------------------------

_SLASH_VULN = _TOKEN_IFACE + """
contract FirelightVaultVuln {
    IERC20Like public token;
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    address public manager;

    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * (totalSupply + 1) / (totalAssets + 1);
    }

    function deposit(uint256 assets, address to) external {
        uint256 shares = convertToShares(assets);
        _mint(to, shares);
        totalSupply += shares;
        totalAssets += assets;
        token.transferFrom(msg.sender, address(this), assets);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }

    function slash(uint256 amount, address to) external {
        require(msg.sender == manager, "not manager");
        totalAssets -= amount;
        token.transfer(to, amount);
    }
}
"""

_SLASH_CLEAN = _TOKEN_IFACE + """
contract FirelightVaultClean {
    IERC20Like public token;
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    address public manager;

    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * (totalSupply + 1) / (totalAssets + 1);
    }

    function deposit(uint256 assets, address to) external {
        uint256 shares = convertToShares(assets);
        _mint(to, shares);
        totalSupply += shares;
        totalAssets += assets;
        token.transferFrom(msg.sender, address(this), assets);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }

    function _burn(address from, uint256 amount) internal {
        balanceOf[from] -= amount;
        totalSupply -= amount;
    }

    function slash(uint256 amount, address to) external {
        require(msg.sender == manager, "not manager");
        uint256 sharesToBurn = convertToShares(amount);
        _burn(msg.sender, sharesToBurn);
        totalAssets -= amount;
        token.transfer(to, amount);
    }
}
"""

_SLASH_DEPOSIT_GUARD = _TOKEN_IFACE + """
contract FirelightVaultDepositGuard {
    IERC20Like public token;
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    address public manager;

    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * (totalSupply + 1) / (totalAssets + 1);
    }

    function deposit(uint256 assets, address to) external {
        require(totalAssets > 0 || totalSupply == 0, "slashed empty");
        uint256 shares = convertToShares(assets);
        _mint(to, shares);
        totalSupply += shares;
        totalAssets += assets;
        token.transferFrom(msg.sender, address(this), assets);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }

    function slash(uint256 amount, address to) external {
        require(msg.sender == manager, "not manager");
        totalAssets -= amount;
        token.transfer(to, amount);
    }
}
"""

_SLASH_NO_OFFSET = _TOKEN_IFACE + """
contract FirelightVaultNoOffset {
    IERC20Like public token;
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    address public manager;

    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0) return assets;
        return assets * totalSupply / totalAssets;
    }

    function deposit(uint256 assets, address to) external {
        uint256 shares = convertToShares(assets);
        _mint(to, shares);
        totalSupply += shares;
        totalAssets += assets;
        token.transferFrom(msg.sender, address(this), assets);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }

    function slash(uint256 amount, address to) external {
        require(msg.sender == manager, "not manager");
        totalAssets -= amount;
        token.transfer(to, amount);
    }
}
"""

_SLASH_VARIANT = _TOKEN_IFACE + """
contract FirelightVaultFixed {
    IERC20Like public token;
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    address public manager;
    address public treasury;

    function convertToShares(uint256 assets) public view returns (uint256) {
        return assets * (totalSupply + 1) / (totalAssets + 1);
    }

    function deposit(uint256 assets, address to) external {
        uint256 shares = convertToShares(assets);
        _mint(treasury, shares);
        totalSupply += shares;
        totalAssets += assets;
        token.transferFrom(msg.sender, address(this), assets);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
    }

    function slash(uint256 amount, address to) external {
        require(msg.sender == manager, "not manager");
        totalAssets -= amount;
        token.transfer(to, amount);
    }
}
"""

VULN = {
    "unsafe_narrowing_cast_collateral_zero": _NARROW_VULN,
    "negative_fee_mint_inflation": _FEE_VULN,
    "scaled_allowance_overapproval": _ALLOW_VULN,
    "claim_callback_before_claimed_flag": _CLAIM_VULN,
    "post_slash_erc4626_offset_inversion": _SLASH_VULN,
}

CLEAN = {
    "unsafe_narrowing_cast_collateral_zero": _NARROW_CLEAN,
    "negative_fee_mint_inflation": _FEE_CLEAN,
    "scaled_allowance_overapproval": _ALLOW_CLEAN,
    "claim_callback_before_claimed_flag": _CLAIM_CLEAN,
    "post_slash_erc4626_offset_inversion": _SLASH_CLEAN,
}

VARIANT = {
    "unsafe_narrowing_cast_collateral_zero": _NARROW_VARIANT,
    "negative_fee_mint_inflation": _FEE_VARIANT,
    "scaled_allowance_overapproval": _ALLOW_VARIANT,
    "claim_callback_before_claimed_flag": _CLAIM_VARIANT,
    "post_slash_erc4626_offset_inversion": _SLASH_VARIANT,
}

EXTRA_CLEAN = {
    "unsafe_narrowing_cast_collateral_zero_max_check": _NARROW_MAX_CHECK,
    "unsafe_narrowing_cast_collateral_zero_display_only": _NARROW_DISPLAY_ONLY,
    "negative_fee_mint_inflation_setter_guard": _FEE_SETTER_GUARD,
    "negative_fee_mint_inflation_clamped": _FEE_CLAMPED,
    "scaled_allowance_overapproval_raw_check": _ALLOW_RAW_CHECK,
    "scaled_allowance_overapproval_fixed_index": _ALLOW_FIXED_INDEX,
    "claim_callback_before_claimed_flag_nonreentrant": _CLAIM_NONREENTRANT,
    "claim_callback_before_claimed_flag_allowlist": _CLAIM_ALLOWLIST,
    "post_slash_erc4626_offset_inversion_deposit_guard": _SLASH_DEPOSIT_GUARD,
    "post_slash_erc4626_offset_inversion_no_offset": _SLASH_NO_OFFSET,
}
