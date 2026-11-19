"""Fixtures for the deep-audit batch-27 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the value lands at a FIXED destination, so it MUST fire
with report_class "trigger_only" at low severity - never a
candidate.

Cross-talk by construction: the LP-mint fixture computes
liquidity from sqrt with no rate / accumulator variable and
no balanceOf(this) read; the merkle fixture carries a claimed
marker (so merkle_claim_no_claimed_marker stays silent) and
binds the amount in the leaf (so merkle_proof_amount_unbound
stays silent); the vesting fixture has no signature, no
merkle proof and no random-named variable; the permit
fixture carries a domain separator, a consumed nonce and a
chainid-bound digest (so permit_no_domain_separator,
signature_replay_no_nonce and
ecdsa_signature_replay_cross_chain stay silent) and uses
ECDSA.recover, not raw ecrecover; the bonding-curve fixture
prices from address(this).balance with no rate variable and
no balanceOf(this) read.
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
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return address(0);
    }
}
"""

_MERKLE_LIB = """
library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return true;
    }
}
"""

_MATH_LIB = """
library Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
    function sqrt(uint256 x) internal pure returns (uint256) {
        return x;
    }
}
"""

# ---------------------------------------------------------------------------
# 1. lp_mint_no_minimum_liquidity_lock
# ---------------------------------------------------------------------------

_LP_VULN = _TOKEN_IFACE + _MATH_LIB + """
contract LPMintNoMinVuln {
    IERC20Like public token0;
    IERC20Like public token1;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function mint(uint256 amount0, uint256 amount1) external returns (uint256 liquidity) {
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        if (totalSupply == 0) {
            liquidity = Math.sqrt(amount0 * amount1);
        } else {
            liquidity = Math.min(amount0 * totalSupply / 1000, amount1 * totalSupply / 1000);
        }
        require(liquidity > 0, "no liquidity");
        _mint(msg.sender, liquidity);
        return liquidity;
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

_LP_VARIANT = _TOKEN_IFACE + _MATH_LIB + """
contract LPMintNoMinFixed {
    IERC20Like public token0;
    IERC20Like public token1;
    address public treasury;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function mint(uint256 amount0, uint256 amount1) external returns (uint256 liquidity) {
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        if (totalSupply == 0) {
            liquidity = Math.sqrt(amount0 * amount1);
        } else {
            liquidity = Math.min(amount0 * totalSupply / 1000, amount1 * totalSupply / 1000);
        }
        require(liquidity > 0, "no liquidity");
        _mint(treasury, liquidity);
        return liquidity;
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

# First mint burns MINIMUM_LIQUIDITY to address(0): protected shape.
_LP_CLEAN = _TOKEN_IFACE + _MATH_LIB + """
contract LPMintNoMinClean {
    IERC20Like public token0;
    IERC20Like public token1;
    uint256 public constant MINIMUM_LIQUIDITY = 1000;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function mint(uint256 amount0, uint256 amount1) external returns (uint256 liquidity) {
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        if (totalSupply == 0) {
            liquidity = Math.sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
            _mint(address(0), MINIMUM_LIQUIDITY);
        } else {
            liquidity = Math.min(amount0 * totalSupply / 1000, amount1 * totalSupply / 1000);
        }
        require(liquidity > 0, "no liquidity");
        _mint(msg.sender, liquidity);
        return liquidity;
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

# ---------------------------------------------------------------------------
# 2. merkle_claim_replayable_across_chains
# ---------------------------------------------------------------------------

_MERKLE_VULN = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleClaimCrossChainVuln {
    IERC20Like public token;
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;

    function claim(address account, uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(account, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        require(!claimed[account], "claimed");
        claimed[account] = true;
        token.transfer(account, amount);
    }
}
"""

_MERKLE_VARIANT = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleClaimCrossChainFixed {
    IERC20Like public token;
    bytes32 public merkleRoot;
    address public treasury;
    mapping(address => bool) public claimed;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function claim(address account, uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(account, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        require(!claimed[account], "claimed");
        claimed[account] = true;
        token.transfer(treasury, amount);
    }
}
"""

# The leaf binds the chain: protected shape.
_MERKLE_CLEAN = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleClaimCrossChainClean {
    IERC20Like public token;
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;

    function claim(address account, uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(block.chainid, account, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        require(!claimed[account], "claimed");
        claimed[account] = true;
        token.transfer(account, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. vesting_claim_overrelease_past_duration
# ---------------------------------------------------------------------------

# Per-beneficiary vesting: the per-call payout is bounded by the
# caller's own allocation (so recipient_overdraw_withdraw stays
# silent - each single payout is entitled), but the releasable
# formula itself is never capped at the vesting end, so the
# CUMULATIVE payout still grows past 100% of the allocation:
# the over-release is real, it just takes more than one call.
_VEST_VULN = _TOKEN_IFACE + """
contract VestingOverreleaseVuln {
    IERC20Like public token;
    uint256 public start;
    uint256 public duration;
    mapping(address => uint256) public allocation;
    mapping(address => uint256) public released;

    function release() external {
        uint256 releasable = (block.timestamp - start) * allocation[msg.sender] / duration;
        uint256 payout = releasable - released[msg.sender];
        require(payout <= allocation[msg.sender], "over allocation");
        released[msg.sender] += payout;
        token.transfer(msg.sender, payout);
    }
}
"""

_VEST_VARIANT = _TOKEN_IFACE + """
contract VestingOverreleaseFixed {
    IERC20Like public token;
    address public beneficiary;
    uint256 public start;
    uint256 public duration;
    mapping(address => uint256) public allocation;
    mapping(address => uint256) public released;

    constructor(address _beneficiary) {
        beneficiary = _beneficiary;
    }

    function release() external {
        uint256 releasable = (block.timestamp - start) * allocation[msg.sender] / duration;
        uint256 payout = releasable - released[msg.sender];
        require(payout <= allocation[msg.sender], "over allocation");
        released[msg.sender] += payout;
        token.transfer(beneficiary, payout);
    }
}
"""

# The elapsed time is capped at the vesting end: protected shape.
_VEST_CLEAN = _TOKEN_IFACE + _MATH_LIB + """
contract VestingOverreleaseClean {
    IERC20Like public token;
    uint256 public start;
    uint256 public duration;
    mapping(address => uint256) public allocation;
    mapping(address => uint256) public released;

    function release() external {
        uint256 end = start + duration;
        uint256 elapsed = Math.min(block.timestamp, end) - start;
        uint256 releasable = elapsed * allocation[msg.sender] / duration;
        uint256 payout = releasable - released[msg.sender];
        require(payout <= allocation[msg.sender], "over allocation");
        released[msg.sender] += payout;
        token.transfer(msg.sender, payout);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. permit_deadline_param_never_enforced
# ---------------------------------------------------------------------------

_PERMIT_VULN = _TOKEN_IFACE + _ECDSA_LIB + """
contract PermitDeadlineVuln {
    IERC20Like public token;
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, DOMAIN_SEPARATOR, owner, spender, value, nonces[owner], deadline));
        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == owner, "bad signer");
        nonces[owner]++;
        _approve(owner, spender, value);
    }

    function _approve(address owner, address spender, uint256 value) internal {
        allowance[owner][spender] = value;
    }
}
"""

_PERMIT_VARIANT = _TOKEN_IFACE + _ECDSA_LIB + """
contract PermitDeadlineFixed {
    IERC20Like public token;
    bytes32 public DOMAIN_SEPARATOR;
    address public treasury;
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function permit(address owner, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, DOMAIN_SEPARATOR, owner, treasury, value, nonces[owner], deadline));
        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == owner, "bad signer");
        nonces[owner]++;
        _approve(owner, treasury, value);
    }

    function _approve(address owner, address spender, uint256 value) internal {
        allowance[owner][spender] = value;
    }
}
"""

# The deadline is enforced: protected shape.
_PERMIT_CLEAN = _TOKEN_IFACE + _ECDSA_LIB + """
contract PermitDeadlineClean {
    IERC20Like public token;
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, DOMAIN_SEPARATOR, owner, spender, value, nonces[owner], deadline));
        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == owner, "bad signer");
        nonces[owner]++;
        _approve(owner, spender, value);
    }

    function _approve(address owner, address spender, uint256 value) internal {
        allowance[owner][spender] = value;
    }
}
"""

# ---------------------------------------------------------------------------
# 5. bonding_curve_price_from_raw_balance_no_virtual_reserve
# ---------------------------------------------------------------------------

_BOND_VULN = _TOKEN_IFACE + """
contract BondingCurveRawBalanceVuln {
    IERC20Like public token;
    uint256 public circulating;

    function buyTokens() external payable {
        uint256 price = address(this).balance * 1e18 / circulating;
        uint256 tokensOut = msg.value * 1e18 / price;
        circulating += tokensOut;
        token.transfer(msg.sender, tokensOut);
    }
}
"""

_BOND_VARIANT = _TOKEN_IFACE + """
contract BondingCurveRawBalanceFixed {
    IERC20Like public token;
    address public treasury;
    uint256 public circulating;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function buyTokens() external payable {
        uint256 price = address(this).balance * 1e18 / circulating;
        uint256 tokensOut = msg.value * 1e18 / price;
        circulating += tokensOut;
        token.transfer(treasury, tokensOut);
    }
}
"""

# The price comes from a virtual reserve the contract controls: protected shape.
_BOND_CLEAN = _TOKEN_IFACE + """
contract BondingCurveRawBalanceClean {
    IERC20Like public token;
    uint256 public circulating;
    uint256 public virtualReserve = 1000 ether;

    function buyTokens() external payable {
        uint256 price = (address(this).balance + virtualReserve) * 1e18 / circulating;
        uint256 tokensOut = msg.value * 1e18 / price;
        circulating += tokensOut;
        token.transfer(msg.sender, tokensOut);
    }
}
"""

# ---------------------------------------------------------------------------
# Extra clean controls (one guard each, for the per-detector tests)
# ---------------------------------------------------------------------------

# Gated mint: onlyOwner suppresses the LP-mint detector.
_LP_GATED = _TOKEN_IFACE + _MATH_LIB + """
contract LPMintGated {
    IERC20Like public token0;
    IERC20Like public token1;
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(uint256 amount0, uint256 amount1) external onlyOwner returns (uint256 liquidity) {
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        liquidity = Math.sqrt(amount0 * amount1);
        require(liquidity > 0, "no liquidity");
        _mint(msg.sender, liquidity);
        return liquidity;
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

# Proportional-only mint (no sqrt, no first-mint branch): the
# later-mint formula is anchored by a nonzero totalSupply.
_LP_NO_SQRT = _TOKEN_IFACE + _MATH_LIB + """
contract LPMintNoSqrt {
    IERC20Like public token0;
    IERC20Like public token1;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function mint(uint256 amount0, uint256 amount1) external returns (uint256 liquidity) {
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        require(totalSupply > 0, "empty pool");
        liquidity = Math.min(amount0 * totalSupply / 1000, amount1 * totalSupply / 1000);
        require(liquidity > 0, "no liquidity");
        _mint(msg.sender, liquidity);
        return liquidity;
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

# Merkle claim that pays nothing: no spendable value, out of scope.
_MERKLE_NO_PAYOUT = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleClaimNoPayout {
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;

    function claim(address account, uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(account, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        require(!claimed[account], "claimed");
        claimed[account] = true;
    }
}
"""

# Vesting release capped by a releasable-vs-total require.
_VEST_CAPPED_TOTAL = _TOKEN_IFACE + """
contract VestingCappedTotal {
    IERC20Like public token;
    uint256 public start;
    uint256 public duration;
    mapping(address => uint256) public allocation;
    mapping(address => uint256) public released;

    function release() external {
        uint256 releasable = (block.timestamp - start) * allocation[msg.sender] / duration;
        require(releasable <= allocation[msg.sender], "over release");
        uint256 payout = releasable - released[msg.sender];
        released[msg.sender] += payout;
        token.transfer(msg.sender, payout);
    }
}
"""

# Gated vesting release: onlyOwner suppresses the detector.
_VEST_GATED = _TOKEN_IFACE + """
contract VestingGated {
    IERC20Like public token;
    address public owner;
    uint256 public start;
    uint256 public duration;
    mapping(address => uint256) public allocation;
    mapping(address => uint256) public released;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function release() external onlyOwner {
        uint256 releasable = (block.timestamp - start) * allocation[msg.sender] / duration;
        uint256 payout = releasable - released[msg.sender];
        require(payout <= allocation[msg.sender], "over allocation");
        released[msg.sender] += payout;
        token.transfer(msg.sender, payout);
    }
}
"""

# Permit with no signature recovery at all: not a permit shape.
_PERMIT_NO_SIG = _TOKEN_IFACE + _ECDSA_LIB + """
contract PermitNoSig {
    IERC20Like public token;
    mapping(address => mapping(address => uint256)) public allowance;

    function permit(address owner, address spender, uint256 value, uint256 deadline) external {
        _approve(owner, spender, value);
    }

    function _approve(address owner, address spender, uint256 value) internal {
        allowance[owner][spender] = value;
    }
}
"""

# Bonding-curve buy bounded by a min-out check.
_BOND_MIN_OUT = _TOKEN_IFACE + """
contract BondingCurveMinOut {
    IERC20Like public token;
    uint256 public circulating;

    function buyTokens(uint256 minTokensOut) external payable {
        uint256 price = address(this).balance * 1e18 / circulating;
        uint256 tokensOut = msg.value * 1e18 / price;
        require(tokensOut >= minTokensOut, "slippage");
        circulating += tokensOut;
        token.transfer(msg.sender, tokensOut);
    }
}
"""

# Gated bonding-curve buy: onlyOwner suppresses the detector.
_BOND_GATED = _TOKEN_IFACE + """
contract BondingCurveGated {
    IERC20Like public token;
    address public owner;
    uint256 public circulating;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function buyTokens() external payable onlyOwner {
        uint256 price = address(this).balance * 1e18 / circulating;
        uint256 tokensOut = msg.value * 1e18 / price;
        circulating += tokensOut;
        token.transfer(msg.sender, tokensOut);
    }
}
"""

EXTRA_CLEAN = {
    "lp_gated": _LP_GATED,
    "lp_no_sqrt": _LP_NO_SQRT,
    "merkle_no_payout": _MERKLE_NO_PAYOUT,
    "vest_capped_total": _VEST_CAPPED_TOTAL,
    "vest_gated": _VEST_GATED,
    "permit_no_sig": _PERMIT_NO_SIG,
    "bond_min_out": _BOND_MIN_OUT,
    "bond_gated": _BOND_GATED,
}

VULN = {
    "lp_mint_no_minimum_liquidity_lock": _LP_VULN,
    "merkle_claim_replayable_across_chains": _MERKLE_VULN,
    "vesting_claim_overrelease_past_duration": _VEST_VULN,
    "permit_deadline_param_never_enforced": _PERMIT_VULN,
    "bonding_curve_price_from_raw_balance_no_virtual_reserve":
        _BOND_VULN,
}

VARIANT = {
    "lp_mint_no_minimum_liquidity_lock": _LP_VARIANT,
    "merkle_claim_replayable_across_chains": _MERKLE_VARIANT,
    "vesting_claim_overrelease_past_duration": _VEST_VARIANT,
    "permit_deadline_param_never_enforced": _PERMIT_VARIANT,
    "bonding_curve_price_from_raw_balance_no_virtual_reserve":
        _BOND_VARIANT,
}

CLEAN = {
    "lp_mint_no_minimum_liquidity_lock": _LP_CLEAN,
    "merkle_claim_replayable_across_chains": _MERKLE_CLEAN,
    "vesting_claim_overrelease_past_duration": _VEST_CLEAN,
    "permit_deadline_param_never_enforced": _PERMIT_CLEAN,
    "bonding_curve_price_from_raw_balance_no_virtual_reserve":
        _BOND_CLEAN,
}
