"""Fixtures for the deep-audit batch-24 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" (all five are
recipient-classified detectors); CLEAN[id] (the protected shape
of the same class) MUST stay silent under ALL five detectors;
VARIANT[id] carries the same vulnerable shape but the value
lands at a FIXED destination, so it MUST fire with
report_class "trigger_only" at low severity - never a
candidate.

Cross-talk by construction: the sell-hook fixture burns pair
tokens in a _transfer hook but names no escape / removeLiquidity
/ release / verify function; the escape-hatch fixture pays out
on public inputs but verifies no proof and names no transfer
hook / release / verify function; the LP-mint fixture sizes a
payout from a caller-supplied mint but names no transfer hook /
escape / release / verify function; the bridge fixture verifies
a signature and pays a caller amount but names no transfer hook
/ escape / LP function and verifies no Merkle proof; the leaf
fixture verifies a Merkle proof for an index but names no claim
/ transfer hook / escape / release function.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function totalSupply() external view returns (uint256);
}
"""

_MERKLE_LIB = """
library MerkleProof {
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return true;
    }
}
"""

_PAIR_IFACE = """
interface IUniswapV2Pair {
    function sync() external;
}
"""

# ---------------------------------------------------------------------------
# 1. token_sell_hook_burns_pair_reserves_sync
# ---------------------------------------------------------------------------

_SELL_VULN = _TOKEN_IFACE + _PAIR_IFACE + """
contract TokenSellHookVuln {
    mapping(address => uint256) public balances;
    address public pair;

    constructor(address _pair) {
        pair = _pair;
    }

    function _burn(address account, uint256 amount) internal {
        balances[account] -= amount;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        _burn(pair, amount / 2);
        IUniswapV2Pair(pair).sync();
        balances[from] -= amount;
        balances[to] += amount;
        emit Transfer(from, to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    event Transfer(address indexed from, address indexed to, uint256 amount);
}
"""

_SELL_VARIANT = _TOKEN_IFACE + _PAIR_IFACE + """
contract TokenSellHookFixed {
    mapping(address => uint256) public balances;
    address public pair;
    address public treasury;

    constructor(address _pair, address _treasury) {
        pair = _pair;
        treasury = _treasury;
    }

    function _burn(address account, uint256 amount) internal {
        balances[account] -= amount;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        _burn(pair, amount / 2);
        IUniswapV2Pair(pair).sync();
        balances[from] -= amount;
        balances[treasury] += amount;
        emit Transfer(from, treasury, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    event Transfer(address indexed from, address indexed to, uint256 amount);
}
"""

# Burn / sync only AFTER the transfer settles: protected shape.
_SELL_CLEAN = _TOKEN_IFACE + _PAIR_IFACE + """
contract TokenSellHookClean {
    mapping(address => uint256) public balances;
    address public pair;

    constructor(address _pair) {
        pair = _pair;
    }

    function _burn(address account, uint256 amount) internal {
        balances[account] -= amount;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        balances[from] -= amount;
        balances[to] += amount;
        emit Transfer(from, to, amount);
        _burn(pair, amount / 2);
        IUniswapV2Pair(pair).sync();
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    event Transfer(address indexed from, address indexed to, uint256 amount);
}
"""

# Plain ERC20 transfer with no pair interaction at all.
_SELL_PLAIN_TRANSFER = _TOKEN_IFACE + """
contract TokenPlainTransfer {
    mapping(address => uint256) public balances;

    function _transfer(address from, address to, uint256 amount) internal {
        balances[from] -= amount;
        balances[to] += amount;
        emit Transfer(from, to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    event Transfer(address indexed from, address indexed to, uint256 amount);
}
"""

# Pair sync delegated to a helper called only AFTER the transfer settles.
_SELL_HELPER_AFTER_SETTLE = _TOKEN_IFACE + _PAIR_IFACE + """
contract TokenSellHelperAfterSettle {
    mapping(address => uint256) public balances;
    address public pair;

    constructor(address _pair) {
        pair = _pair;
    }

    function _syncPair() internal {
        IUniswapV2Pair(pair).sync();
    }

    function _transfer(address from, address to, uint256 amount) internal {
        balances[from] -= amount;
        balances[to] += amount;
        emit Transfer(from, to, amount);
        _syncPair();
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    event Transfer(address indexed from, address indexed to, uint256 amount);
}
"""

# ---------------------------------------------------------------------------
# 2. escape_hatch_unbound_public_inputs
# ---------------------------------------------------------------------------

_ESCAPE_VULN = _TOKEN_IFACE + """
contract RollupEscapeVuln {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function escapeHatch(uint256 proofId, bytes calldata publicOutput) external {
        uint256 amount = abi.decode(publicOutput, (uint256));
        token.transfer(msg.sender, amount);
    }
}
"""

_ESCAPE_VARIANT = _TOKEN_IFACE + """
contract RollupEscapeFixed {
    IERC20Like public token;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function escapeHatch(uint256 proofId, bytes calldata publicOutput) external {
        uint256 amount = abi.decode(publicOutput, (uint256));
        token.transfer(treasury, amount);
    }
}
"""

_ESCAPE_CLEAN = _TOKEN_IFACE + """
contract RollupEscapeClean {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function verifyProof(uint256 proofId, bytes calldata publicOutput) internal pure returns (bool) {
        return true;
    }

    function escapeHatch(uint256 proofId, bytes calldata publicOutput) external {
        require(verifyProof(proofId, publicOutput), "bad proof");
        uint256 amount = abi.decode(publicOutput, (uint256));
        token.transfer(msg.sender, amount);
    }
}
"""

# Escape hatch pays a fixed escrow amount: the proof / output
# parameters never size the payout.
_ESCAPE_FIXED_AMOUNT = _TOKEN_IFACE + """
contract RollupEscapeFixedAmount {
    IERC20Like public token;
    uint256 public escrowBalance;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function escapeHatch(uint256 proofId, bytes calldata publicOutput) external {
        token.transfer(msg.sender, escrowBalance);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. lp_mint_unverified_caller_supplied
# ---------------------------------------------------------------------------

_LP_VULN = _TOKEN_IFACE + """
contract PoolRemoveVuln {
    IERC20Like public token;
    uint256 public reserve;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function removeLiquidity(address lpToken, uint256 lpAmount) external {
        uint256 total = IERC20(lpToken).totalSupply();
        uint256 amountOut = lpAmount * reserve / total;
        token.transfer(msg.sender, amountOut);
    }
}
"""

_LP_VARIANT = _TOKEN_IFACE + """
contract PoolRemoveFixed {
    IERC20Like public token;
    uint256 public reserve;
    address public treasury;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function removeLiquidity(address lpToken, uint256 lpAmount) external {
        uint256 total = IERC20(lpToken).totalSupply();
        uint256 amountOut = lpAmount * reserve / total;
        token.transfer(treasury, amountOut);
    }
}
"""

_LP_CLEAN = _TOKEN_IFACE + """
contract PoolRemoveClean {
    IERC20Like public token;
    uint256 public reserve;
    address public storedLpToken;

    constructor(address _token, address _lpToken) {
        token = IERC20Like(_token);
        storedLpToken = _lpToken;
    }

    function removeLiquidity(address lpToken, uint256 lpAmount) external {
        require(lpToken == storedLpToken, "wrong lp");
        uint256 total = IERC20(lpToken).totalSupply();
        uint256 amountOut = lpAmount * reserve / total;
        token.transfer(msg.sender, amountOut);
    }
}
"""

# LP token read from pool storage; the caller parameter is ignored.
_LP_STORAGE_READ = _TOKEN_IFACE + """
contract PoolRemoveStorageRead {
    IERC20Like public token;
    uint256 public reserve;
    address public storedLpToken;

    constructor(address _token, address _lpToken) {
        token = IERC20Like(_token);
        storedLpToken = _lpToken;
    }

    function removeLiquidity(address lpToken, uint256 lpAmount) external {
        address lp = storedLpToken;
        uint256 total = IERC20(lp).totalSupply();
        uint256 amountOut = lpAmount * reserve / total;
        token.transfer(msg.sender, amountOut);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. bridge_release_value_unbound_to_proof
# ---------------------------------------------------------------------------

_BRIDGE_VULN = _TOKEN_IFACE + """
contract BridgeReleaseVuln {
    IERC20Like public token;
    address public authority;

    constructor(address _token, address _authority) {
        token = IERC20Like(_token);
        authority = _authority;
    }

    function release(bytes32 txId, uint256 amount, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(messageHash, v, r, s);
        require(signer == authority, "bad sig");
        token.transfer(msg.sender, amount);
    }
}
"""

_BRIDGE_VARIANT = _TOKEN_IFACE + """
contract BridgeReleaseFixed {
    IERC20Like public token;
    address public authority;
    address public treasury;

    constructor(address _token, address _authority, address _treasury) {
        token = IERC20Like(_token);
        authority = _authority;
        treasury = _treasury;
    }

    function release(bytes32 txId, uint256 amount, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(messageHash, v, r, s);
        require(signer == authority, "bad sig");
        token.transfer(treasury, amount);
    }
}
"""

_BRIDGE_CLEAN = _TOKEN_IFACE + """
contract BridgeReleaseClean {
    IERC20Like public token;
    address public authority;

    struct Deposit {
        uint256 amount;
        address recipient;
    }

    mapping(bytes32 => Deposit) public deposits;

    constructor(address _token, address _authority) {
        token = IERC20Like(_token);
        authority = _authority;
    }

    function release(bytes32 txId, uint256 amount, bytes32 messageHash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(messageHash, v, r, s);
        require(signer == authority, "bad sig");
        require(amount == deposits[txId].amount, "amount mismatch");
        token.transfer(msg.sender, amount);
    }
}
"""

# Release with NO verification at all: the payload-injection
# shape, not the value-binding shape.
_BRIDGE_NO_VERIFICATION = _TOKEN_IFACE + """
contract BridgeReleaseNoVerification {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function release(bytes32 txId, uint256 amount) external {
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. merkle_proof_unbounded_leaf_index
# ---------------------------------------------------------------------------

_LEAF_VULN = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleLeafVuln {
    IERC20Like public token;
    bytes32 public merkleRoot;

    constructor(address _token, bytes32 _root) {
        token = IERC20Like(_token);
        merkleRoot = _root;
    }

    function verifyLeaf(uint256 index, bytes32[] calldata proof, bytes32 leaf, uint256 reward) external {
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        token.transfer(msg.sender, reward);
    }
}
"""

_LEAF_VARIANT = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleLeafFixed {
    IERC20Like public token;
    bytes32 public merkleRoot;
    address public treasury;

    constructor(address _token, bytes32 _root, address _treasury) {
        token = IERC20Like(_token);
        merkleRoot = _root;
        treasury = _treasury;
    }

    function verifyLeaf(uint256 index, bytes32[] calldata proof, bytes32 leaf, uint256 reward) external {
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        token.transfer(treasury, reward);
    }
}
"""

_LEAF_CLEAN = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleLeafClean {
    IERC20Like public token;
    bytes32 public merkleRoot;
    uint256 public leafCount;

    constructor(address _token, bytes32 _root) {
        token = IERC20Like(_token);
        merkleRoot = _root;
    }

    function verifyLeaf(uint256 index, bytes32[] calldata proof, bytes32 leaf, uint256 reward) external {
        require(index < leafCount, "out of bounds");
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        token.transfer(msg.sender, reward);
    }
}
"""

# Proof verification with no leaf index parameter at all:
# nothing to bound-check.
_LEAF_NO_INDEX = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleLeafNoIndex {
    IERC20Like public token;
    bytes32 public merkleRoot;
    uint256 public reward;

    constructor(address _token, bytes32 _root) {
        token = IERC20Like(_token);
        merkleRoot = _root;
    }

    function verifyProof(bytes32[] calldata proof, bytes32 leaf) external {
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        token.transfer(msg.sender, reward);
    }
}
"""

VULN = {
    "token_sell_hook_burns_pair_reserves_sync": _SELL_VULN,
    "escape_hatch_unbound_public_inputs": _ESCAPE_VULN,
    "lp_mint_unverified_caller_supplied": _LP_VULN,
    "bridge_release_value_unbound_to_proof": _BRIDGE_VULN,
    "merkle_proof_unbounded_leaf_index": _LEAF_VULN,
}

VARIANT = {
    "token_sell_hook_burns_pair_reserves_sync": _SELL_VARIANT,
    "escape_hatch_unbound_public_inputs": _ESCAPE_VARIANT,
    "lp_mint_unverified_caller_supplied": _LP_VARIANT,
    "bridge_release_value_unbound_to_proof": _BRIDGE_VARIANT,
    "merkle_proof_unbounded_leaf_index": _LEAF_VARIANT,
}

CLEAN = {
    "token_sell_hook_burns_pair_reserves_sync": _SELL_CLEAN,
    "escape_hatch_unbound_public_inputs": _ESCAPE_CLEAN,
    "lp_mint_unverified_caller_supplied": _LP_CLEAN,
    "bridge_release_value_unbound_to_proof": _BRIDGE_CLEAN,
    "merkle_proof_unbounded_leaf_index": _LEAF_CLEAN,
}

# Paid allowlist mint (ERC20Plus mintManyERC20AL shape, found
# 2026-11-17 live run): verifies an allowlist Merkle proof and
# mints a caller-chosen amount, but the caller PAYS per token
# (transferFrom) under per-account and total caps - a paid mint,
# not a bridge release. Must stay silent under
# bridge_release_value_unbound_to_proof.
_BRIDGE_MINT_ALLOWLIST_PAID = _TOKEN_IFACE + _MERKLE_LIB + """
contract AllowlistPaidMint {
    IERC20Like public token;
    IERC20Like public paymentToken;
    bytes32 public merkleRoot;
    uint256 public maxSupply;
    uint256 public totalMinted;
    mapping(address => uint256) public mintedByAccount;

    constructor(address _token, address _payment, bytes32 _root) {
        token = IERC20Like(_token);
        paymentToken = IERC20Like(_payment);
        merkleRoot = _root;
    }

    function isAllowlisted(address _to, bytes32[] calldata _merkleProof) internal view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(_to));
        return MerkleProof.verify(_merkleProof, merkleRoot, leaf);
    }

    function mintManyERC20AL(address _to, uint256 _amount, bytes32[] calldata _merkleProof, address _erc20TokenContract) external payable {
        require(isAllowlisted(_to, _merkleProof), "not allowlisted");
        require(totalMinted + _amount <= maxSupply, "cap exceeded");
        require(mintedByAccount[_to] + _amount <= 10 ether, "account cap");
        uint256 charge = 1 ether * _amount;
        require(paymentToken.transferFrom(_to, address(this), charge), "payment failed");
        mintedByAccount[_to] += _amount;
        totalMinted += _amount;
        token.transfer(_to, _amount);
    }
}
"""

EXTRA_CLEAN = {
    "sell_plain_transfer": _SELL_PLAIN_TRANSFER,
    "sell_helper_after_settle": _SELL_HELPER_AFTER_SETTLE,
    "escape_fixed_amount": _ESCAPE_FIXED_AMOUNT,
    "lp_storage_read": _LP_STORAGE_READ,
    "bridge_no_verification": _BRIDGE_NO_VERIFICATION,
    "bridge_mint_allowlist_paid": _BRIDGE_MINT_ALLOWLIST_PAID,
    "leaf_no_index": _LEAF_NO_INDEX,
}
