"""Fixtures for the deep-audit batch-33 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the value lands at a FIXED destination, so it MUST fire
with report_class "trigger_only" at low severity - never a
candidate.

Cross-talk by construction: the flash-loan fixture lends and
swaps but names no cap counter, gauge, proof, or deposit /
rounding shape; the cap fixture mints against a never-written
counter but names no flash / swap / gauge / proof function and
pulls no tokens; the gauge fixture claims by weight but names
no accumulator (no rewardPerToken / accRewardPerShare), no
deposit / stake function, and pulls no tokens; the proof
fixture verifies a storage proof but names no flash / swap /
gauge / deposit function, verifies no signature, and its
digest binds no context; the LP fixture deposits with a
self-rounding collection but pulls the ROUNDED amount (not a
parameter amount) and mints the REQUESTED amount through a
local (never the pulled amount at face value), so the
fee-on-transfer detector stays silent. DOCUMENTED CO-FIRE:
spot_price_own_balance fires on the pool-flashloan VULN
fixture by design - the swap does price from its own balance;
the new detector adds the flash-loan dimension (the pool
lends the very balance it prices from). That co-fire is pinned
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

_MERKLE_LIB = """
library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return true;
    }
}
"""

# ---------------------------------------------------------------------------
# 1. pool_flashloan_lends_pricing_balance
# ---------------------------------------------------------------------------

_FLASH_VULN = _TOKEN_IFACE + """
contract FlexPoolVuln {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function flashBorrow(address borrower, uint256 amount) external {
        require(amount <= token.balanceOf(address(this)), "insufficient vault");
        token.transfer(borrower, amount);
    }

    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 reserve = token.balanceOf(address(this));
        amountOut = amountIn * reserve / (reserve + amountIn);
        token.transferFrom(msg.sender, address(this), amountIn);
        token.transfer(msg.sender, amountOut);
    }
}
"""

_FLASH_VARIANT = _TOKEN_IFACE + """
contract FlexPoolFixed {
    IERC20Like public token;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function flashBorrow(address borrower, uint256 amount) external {
        require(amount <= token.balanceOf(address(this)), "insufficient vault");
        token.transfer(borrower, amount);
    }

    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 reserve = token.balanceOf(address(this));
        amountOut = amountIn * reserve / (reserve + amountIn);
        token.transferFrom(msg.sender, address(this), amountIn);
        token.transfer(treasury, amountOut);
    }
}
"""

# The swap prices from a stored reserve updated only by swaps,
# never from the live balance - the flash loan cannot move the
# price.
_FLASH_CLEAN = _TOKEN_IFACE + """
contract FlexPoolClean {
    IERC20Like public token;
    uint256 public reserve0;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function flashBorrow(address borrower, uint256 amount) external {
        require(amount <= token.balanceOf(address(this)), "insufficient vault");
        token.transfer(borrower, amount);
    }

    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        amountOut = amountIn * reserve0 / (reserve0 + amountIn);
        token.transferFrom(msg.sender, address(this), amountIn);
        token.transfer(msg.sender, amountOut);
        reserve0 += amountIn;
        reserve0 -= amountOut;
    }
}
"""

_FLASH_EXTRA_CLEAN = {
    # The flash loan is drawn from a separate lending vault,
    # not from the pool's own reserve balance.
    "flash_separate_vault": _TOKEN_IFACE + """
contract FlexPoolSeparateVault {
    IERC20Like public token;
    address public lendingVault;

    constructor(address _token, address _vault) {
        token = IERC20Like(_token);
        lendingVault = _vault;
    }

    function flashBorrow(address borrower, uint256 amount) external {
        require(amount <= token.balanceOf(lendingVault), "insufficient vault");
        token.transferFrom(lendingVault, borrower, amount);
    }

    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 reserve = token.balanceOf(address(this));
        amountOut = amountIn * reserve / (reserve + amountIn);
        token.transferFrom(msg.sender, address(this), amountIn);
        token.transfer(msg.sender, amountOut);
    }
}
""",
    # The flash loan leg is owner-gated: a stranger cannot
    # borrow the vault.
    "flash_gated": _TOKEN_IFACE + """
contract FlexPoolGated {
    IERC20Like public token;
    address public owner;

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function flashBorrow(address borrower, uint256 amount) external onlyOwner {
        require(amount <= token.balanceOf(address(this)), "insufficient vault");
        token.transfer(borrower, amount);
    }

    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 reserve = token.balanceOf(address(this));
        amountOut = amountIn * reserve / (reserve + amountIn);
        token.transferFrom(msg.sender, address(this), amountIn);
        token.transfer(msg.sender, amountOut);
    }
}
""",
    # No swap at all: a flash loan with no pricing leg to move.
    "flash_no_swap": _TOKEN_IFACE + """
contract FlashNoSwap {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function flashBorrow(address borrower, uint256 amount) external {
        require(amount <= token.balanceOf(address(this)), "insufficient vault");
        token.transfer(borrower, amount);
    }
}
""",
}

# ---------------------------------------------------------------------------
# 2. cap_counter_never_incremented
# ---------------------------------------------------------------------------

_CAP_VULN = _TOKEN_IFACE + """
contract CapNeverVuln {
    IERC20Like public token;
    mapping(address => uint256) public mintCount;
    uint256 public constant MAX_MINTS_PER_USER = 3;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function mint(uint256 amount) external {
        require(mintCount[msg.sender] < MAX_MINTS_PER_USER, "cap reached");
        totalSupply += amount;
        balances[msg.sender] += amount;
    }
}
"""

_CAP_VARIANT = _TOKEN_IFACE + """
contract CapNeverFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => uint256) public mintCount;
    uint256 public constant MAX_MINTS_PER_USER = 3;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function mint(uint256 amount) external {
        require(mintCount[msg.sender] < MAX_MINTS_PER_USER, "cap reached");
        totalSupply += amount;
        balances[treasury] += amount;
    }
}
"""

# The counter IS incremented on every mint: the cap binds.
_CAP_CLEAN = _TOKEN_IFACE + """
contract CapClean {
    IERC20Like public token;
    mapping(address => uint256) public mintCount;
    uint256 public constant MAX_MINTS_PER_USER = 3;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function mint(uint256 amount) external {
        require(mintCount[msg.sender] < MAX_MINTS_PER_USER, "cap reached");
        mintCount[msg.sender] += 1;
        totalSupply += amount;
        balances[msg.sender] += amount;
    }
}
"""

_CAP_EXTRA_CLEAN = {
    # A time check, not a counter check: no counter is compared
    # against a cap at all.
    "cap_time_only": _TOKEN_IFACE + """
contract CapTimeOnly {
    IERC20Like public token;
    uint256 public deadline;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token, uint256 _deadline) {
        token = IERC20Like(_token);
        deadline = _deadline;
    }

    function mint(uint256 amount) external {
        require(block.timestamp < deadline, "sale over");
        totalSupply += amount;
        balances[msg.sender] += amount;
    }
}
""",
    # The cap_counter_reset_by_setter shape: a setter re-arms
    # the counter, so it IS written - silent here (and the
    # reset detector fires on it, pinned in the test).
    "cap_setter_reset": _TOKEN_IFACE + """
contract CapSetterReset {
    IERC20Like public token;
    uint256 public minted;
    uint256 public constant MAX_SUPPLY = 1000;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function setMinted(uint256 value) external {
        minted = value;
    }

    function mint(uint256 amount) external {
        require(minted + amount <= MAX_SUPPLY, "cap reached");
        minted += amount;
        totalSupply += amount;
        balances[msg.sender] += amount;
    }
}
""",
    # The mint leg is owner-gated: a stranger cannot reach the
    # uncapped mint.
    "cap_gated": _TOKEN_IFACE + """
contract CapGated {
    IERC20Like public token;
    address public owner;
    mapping(address => uint256) public mintCount;
    uint256 public constant MAX_MINTS_PER_USER = 3;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(uint256 amount) external onlyOwner {
        require(mintCount[msg.sender] < MAX_MINTS_PER_USER, "cap reached");
        totalSupply += amount;
        balances[msg.sender] += amount;
    }
}
""",
}

# ---------------------------------------------------------------------------
# 3. reward_weight_ignores_account_param
# ---------------------------------------------------------------------------

_GAUGE_IFACE = """
interface IGaugeController {
    function getGaugeWeight(address gauge) external view returns (uint256);
}
"""

_WEIGHT_VULN = _TOKEN_IFACE + _GAUGE_IFACE + """
contract GaugeWeightVuln {
    IGaugeController public gaugeController;
    IERC20Like public rewardToken;
    uint256 public rewardRate;
    mapping(address => uint256) public totalClaimed;

    constructor(address _controller, address _rewardToken) {
        gaugeController = IGaugeController(_controller);
        rewardToken = IERC20Like(_rewardToken);
    }

    function _gaugeWeight(address account) internal view returns (uint256) {
        return gaugeController.getGaugeWeight(address(this));
    }

    function claimRewards() external {
        uint256 weight = _gaugeWeight(msg.sender);
        uint256 reward = weight * rewardRate / 1e18;
        totalClaimed[msg.sender] += reward;
        rewardToken.transfer(msg.sender, reward);
    }
}
"""

_WEIGHT_VARIANT = _TOKEN_IFACE + _GAUGE_IFACE + """
contract GaugeWeightFixed {
    IGaugeController public gaugeController;
    IERC20Like public rewardToken;
    address public treasury;
    uint256 public rewardRate;
    mapping(address => uint256) public totalClaimed;

    constructor(address _controller, address _rewardToken, address _treasury) {
        gaugeController = IGaugeController(_controller);
        rewardToken = IERC20Like(_rewardToken);
        treasury = _treasury;
    }

    function _gaugeWeight(address account) internal view returns (uint256) {
        return gaugeController.getGaugeWeight(address(this));
    }

    function claimRewards() external {
        uint256 weight = _gaugeWeight(msg.sender);
        uint256 reward = weight * rewardRate / 1e18;
        totalClaimed[msg.sender] += reward;
        rewardToken.transfer(treasury, reward);
    }
}
"""

# The helper uses its account parameter: the weight is that
# account's gauge weight.
_WEIGHT_CLEAN = _TOKEN_IFACE + _GAUGE_IFACE + """
contract GaugeWeightClean {
    IGaugeController public gaugeController;
    IERC20Like public rewardToken;
    uint256 public rewardRate;
    mapping(address => uint256) public totalClaimed;

    constructor(address _controller, address _rewardToken) {
        gaugeController = IGaugeController(_controller);
        rewardToken = IERC20Like(_rewardToken);
    }

    function _gaugeWeight(address account) internal view returns (uint256) {
        return gaugeController.getGaugeWeight(account);
    }

    function claimRewards() external {
        uint256 weight = _gaugeWeight(msg.sender);
        uint256 reward = weight * rewardRate / 1e18;
        totalClaimed[msg.sender] += reward;
        rewardToken.transfer(msg.sender, reward);
    }
}
"""

_WEIGHT_EXTRA_CLEAN = {
    # The helper ignores its parameter, but no claim function
    # consumes the helper's return: the weight feeds no payout.
    "weight_no_claim": _TOKEN_IFACE + _GAUGE_IFACE + """
contract GaugeWeightNoClaim {
    IGaugeController public gaugeController;
    IERC20Like public rewardToken;
    uint256 public rewardRate;

    constructor(address _controller, address _rewardToken) {
        gaugeController = IGaugeController(_controller);
        rewardToken = IERC20Like(_rewardToken);
    }

    function _gaugeWeight(address account) internal view returns (uint256) {
        return gaugeController.getGaugeWeight(address(this));
    }

    function gaugeWeightOf() external view returns (uint256) {
        return _gaugeWeight(msg.sender);
    }
}
""",
    # The claim is owner-gated: a stranger cannot reach it.
    "weight_gated": _TOKEN_IFACE + _GAUGE_IFACE + """
contract GaugeWeightGated {
    IGaugeController public gaugeController;
    IERC20Like public rewardToken;
    address public owner;
    uint256 public rewardRate;
    mapping(address => uint256) public totalClaimed;

    constructor(address _controller, address _rewardToken) {
        gaugeController = IGaugeController(_controller);
        rewardToken = IERC20Like(_rewardToken);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _gaugeWeight(address account) internal view returns (uint256) {
        return gaugeController.getGaugeWeight(address(this));
    }

    function claimRewards() external onlyOwner {
        uint256 weight = _gaugeWeight(msg.sender);
        uint256 reward = weight * rewardRate / 1e18;
        totalClaimed[msg.sender] += reward;
        rewardToken.transfer(msg.sender, reward);
    }
}
""",
}

# ---------------------------------------------------------------------------
# 4. proof_verification_no_context_binding
# ---------------------------------------------------------------------------

_PROOF_VULN = _TOKEN_IFACE + _MERKLE_LIB + """
contract ProofReplayVuln {
    IERC20Like public token;
    mapping(address => bool) public verified;
    uint256 public payout;

    constructor(address _token, uint256 _payout) {
        token = IERC20Like(_token);
        payout = _payout;
    }

    function verifyStorageProof(bytes32 stateRoot, bytes32 leaf, bytes32[] calldata proof) external {
        bytes32 computed = keccak256(abi.encodePacked(stateRoot, leaf));
        require(MerkleProof.verify(proof, stateRoot, computed), "bad proof");
        verified[msg.sender] = true;
        token.transfer(msg.sender, payout);
    }
}
"""

_PROOF_VARIANT = _TOKEN_IFACE + _MERKLE_LIB + """
contract ProofReplayFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => bool) public verified;
    uint256 public payout;

    constructor(address _token, address _treasury, uint256 _payout) {
        token = IERC20Like(_token);
        treasury = _treasury;
        payout = _payout;
    }

    function verifyStorageProof(bytes32 stateRoot, bytes32 leaf, bytes32[] calldata proof) external {
        bytes32 computed = keccak256(abi.encodePacked(stateRoot, leaf));
        require(MerkleProof.verify(proof, stateRoot, computed), "bad proof");
        verified[msg.sender] = true;
        token.transfer(treasury, payout);
    }
}
"""

# The digest binds the verifying contract and the chain: a
# proof generated for another contract or chain fails here.
_PROOF_CLEAN = _TOKEN_IFACE + _MERKLE_LIB + """
contract ProofBoundClean {
    IERC20Like public token;
    mapping(address => bool) public verified;
    uint256 public payout;

    constructor(address _token, uint256 _payout) {
        token = IERC20Like(_token);
        payout = _payout;
    }

    function verifyStorageProof(bytes32 stateRoot, bytes32 leaf, bytes32[] calldata proof) external {
        bytes32 computed = keccak256(abi.encodePacked(address(this), block.chainid, stateRoot, leaf));
        require(MerkleProof.verify(proof, stateRoot, computed), "bad proof");
        verified[msg.sender] = true;
        token.transfer(msg.sender, payout);
    }
}
"""

_PROOF_EXTRA_CLEAN = {
    # The digest binds a domain separator instead of the
    # contract address: still a context binding.
    "proof_domain_separator": _TOKEN_IFACE + _MERKLE_LIB + """
contract ProofDomainClean {
    IERC20Like public token;
    bytes32 public domainSeparator;
    mapping(address => bool) public verified;
    uint256 public payout;

    constructor(address _token, bytes32 _separator, uint256 _payout) {
        token = IERC20Like(_token);
        domainSeparator = _separator;
        payout = _payout;
    }

    function verifyStorageProof(bytes32 stateRoot, bytes32 leaf, bytes32[] calldata proof) external {
        bytes32 computed = keccak256(abi.encodePacked(domainSeparator, stateRoot, leaf));
        require(MerkleProof.verify(proof, stateRoot, computed), "bad proof");
        verified[msg.sender] = true;
        token.transfer(msg.sender, payout);
    }
}
""",
    # Verification gates no state change: a pure view that only
    # returns whether the proof is valid.
    "proof_no_effect": _TOKEN_IFACE + _MERKLE_LIB + """
contract ProofNoEffect {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function verifyStorageProof(bytes32 stateRoot, bytes32 leaf, bytes32[] calldata proof) external view returns (bool) {
        bytes32 computed = keccak256(abi.encodePacked(stateRoot, leaf));
        return MerkleProof.verify(proof, stateRoot, computed);
    }
}
""",
    # The verification leg is owner-gated: a stranger cannot
    # present a replayed proof.
    "proof_gated": _TOKEN_IFACE + _MERKLE_LIB + """
contract ProofGated {
    IERC20Like public token;
    address public owner;
    mapping(address => bool) public verified;
    uint256 public payout;

    constructor(address _token, uint256 _payout) {
        token = IERC20Like(_token);
        owner = msg.sender;
        payout = _payout;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function verifyStorageProof(bytes32 stateRoot, bytes32 leaf, bytes32[] calldata proof) external onlyOwner {
        bytes32 computed = keccak256(abi.encodePacked(stateRoot, leaf));
        require(MerkleProof.verify(proof, stateRoot, computed), "bad proof");
        verified[msg.sender] = true;
        token.transfer(msg.sender, payout);
    }
}
""",
}

# ---------------------------------------------------------------------------
# 5. lp_mint_unrounded_shares_rounded_collection
# ---------------------------------------------------------------------------

_LP_VULN = _TOKEN_IFACE + """
contract RoundingPoolVuln {
    IERC20Like public token;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balances[to] += amount;
    }

    function addLiquidity(uint256 amount) external {
        uint256 shares = amount;
        uint256 unit = 10 ** 6;
        uint256 collected = amount - (amount % unit);
        token.transferFrom(msg.sender, address(this), collected);
        _mint(msg.sender, shares);
    }
}
"""

_LP_VARIANT = _TOKEN_IFACE + """
contract RoundingPoolFixed {
    IERC20Like public token;
    address public treasury;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balances[to] += amount;
    }

    function addLiquidity(uint256 amount) external {
        uint256 shares = amount;
        uint256 unit = 10 ** 6;
        uint256 collected = amount - (amount % unit);
        token.transferFrom(msg.sender, address(this), collected);
        _mint(treasury, shares);
    }
}
"""

# Shares are minted from the MEASURED received balance: the
# collection rounding cannot over-credit.
_LP_CLEAN = _TOKEN_IFACE + """
contract RoundingPoolClean {
    IERC20Like public token;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balances[to] += amount;
    }

    function addLiquidity(uint256 amount) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        uint256 unit = 10 ** 6;
        uint256 collected = amount - (amount % unit);
        token.transferFrom(msg.sender, address(this), collected);
        uint256 received = token.balanceOf(address(this)) - balanceBefore;
        _mint(msg.sender, received);
    }
}
"""

_LP_EXTRA_CLEAN = {
    # The collected amount equals the requested amount with no
    # rounding at all: nothing is rounded down.
    "lp_no_rounding": _TOKEN_IFACE + """
contract RoundingPoolNoRounding {
    IERC20Like public token;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balances[to] += amount;
    }

    function addLiquidity(uint256 amount) external {
        uint256 shares = amount;
        token.transferFrom(msg.sender, address(this), amount);
        _mint(msg.sender, shares);
    }
}
""",
    # The deposit leg is owner-gated: a stranger cannot mint
    # the over-credit.
    "lp_gated": _TOKEN_IFACE + """
contract RoundingPoolGated {
    IERC20Like public token;
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balances[to] += amount;
    }

    function addLiquidity(uint256 amount) external onlyOwner {
        uint256 shares = amount;
        uint256 unit = 10 ** 6;
        uint256 collected = amount - (amount % unit);
        token.transferFrom(msg.sender, address(this), collected);
        _mint(msg.sender, shares);
    }
}
""",
}

# Second vulnerable shape for the same detector: the collection
# rounds down via amount / unit * unit instead of a modulo.
VULN_DIVMUL = _TOKEN_IFACE + """
contract RoundingPoolDivMul {
    IERC20Like public token;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balances[to] += amount;
    }

    function addLiquidity(uint256 amount) external {
        uint256 shares = amount;
        uint256 unit = 10 ** 6;
        uint256 collected = amount / unit * unit;
        token.transferFrom(msg.sender, address(this), collected);
        _mint(msg.sender, shares);
    }
}
"""

VULN = {
    "pool_flashloan_lends_pricing_balance": _FLASH_VULN,
    "cap_counter_never_incremented": _CAP_VULN,
    "reward_weight_ignores_account_param": _WEIGHT_VULN,
    "proof_verification_no_context_binding": _PROOF_VULN,
    "lp_mint_unrounded_shares_rounded_collection": _LP_VULN,
}

CLEAN = {
    "pool_flashloan_lends_pricing_balance": _FLASH_CLEAN,
    "cap_counter_never_incremented": _CAP_CLEAN,
    "reward_weight_ignores_account_param": _WEIGHT_CLEAN,
    "proof_verification_no_context_binding": _PROOF_CLEAN,
    "lp_mint_unrounded_shares_rounded_collection": _LP_CLEAN,
}

VARIANT = {
    "pool_flashloan_lends_pricing_balance": _FLASH_VARIANT,
    "cap_counter_never_incremented": _CAP_VARIANT,
    "reward_weight_ignores_account_param": _WEIGHT_VARIANT,
    "proof_verification_no_context_binding": _PROOF_VARIANT,
    "lp_mint_unrounded_shares_rounded_collection": _LP_VARIANT,
}

EXTRA_CLEAN = {}
EXTRA_CLEAN.update(_FLASH_EXTRA_CLEAN)
EXTRA_CLEAN.update(_CAP_EXTRA_CLEAN)
EXTRA_CLEAN.update(_WEIGHT_EXTRA_CLEAN)
EXTRA_CLEAN.update(_PROOF_EXTRA_CLEAN)
EXTRA_CLEAN.update(_LP_EXTRA_CLEAN)
