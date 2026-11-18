"""Fixtures for the deep-audit batch-25 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" (the four recipient
detectors); the auction detector fires without a candidate
classification (batch-20 auction precedent: stale-price /
locked funds are not a stranger drain). CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the value lands at a FIXED destination, so it MUST fire
with report_class "trigger_only" at low severity - never a
candidate (no variant for the auction or the multicall
detector: neither has a fixed-destination form).

Cross-talk by construction: the NFT fixture mints in a buy()
but names no claim / deposit / bid / multicall function; the
multicall fixture delegatecalls but is non-payable and names
no mint / claim / deposit / bid function; the auction fixture
bids but refunds the previous bidder via the pull pattern and
names no mint / claim / deposit / multicall function; the
bridge fixture credits a ledger in a deposit() with no token
movement and names no mint / claim / bid / multicall
function; the merkle fixture claims with a double-hashed leaf
and a claimed marker set before the payout, and names no mint
/ deposit / bid / multicall function.
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

# ---------------------------------------------------------------------------
# 1. nft_batch_mint_underpayment
# ---------------------------------------------------------------------------

_NFT_VULN = """
contract NftBatchMintVuln {
    uint256 public mintPrice = 0.01 ether;
    uint256 public maxSupply = 10000;
    uint256 public nextTokenId;
    address public treasury;
    mapping(uint256 => address) public ownerOf;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function _safeMint(address to, uint256 tokenId) internal {
        ownerOf[tokenId] = to;
    }

    function buy(address to, uint256 quantity) external payable {
        require(msg.value >= mintPrice, "insufficient payment");
        require(nextTokenId + quantity <= maxSupply, "sold out");
        for (uint256 i = 0; i < quantity; i++) {
            _safeMint(to, nextTokenId);
            nextTokenId++;
        }
    }
}
"""

_NFT_VARIANT = """
contract NftBatchMintFixed {
    uint256 public mintPrice = 0.01 ether;
    uint256 public maxSupply = 10000;
    uint256 public nextTokenId;
    address public treasury;
    mapping(uint256 => address) public ownerOf;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function _safeMint(address to, uint256 tokenId) internal {
        ownerOf[tokenId] = to;
    }

    function buy(address to, uint256 quantity) external payable {
        require(msg.value >= mintPrice, "insufficient payment");
        require(nextTokenId + quantity <= maxSupply, "sold out");
        for (uint256 i = 0; i < quantity; i++) {
            _safeMint(treasury, nextTokenId);
            nextTokenId++;
        }
    }
}
"""

# Payment prices every unit: protected shape.
_NFT_CLEAN = """
contract NftBatchMintClean {
    uint256 public mintPrice = 0.01 ether;
    uint256 public maxSupply = 10000;
    uint256 public nextTokenId;
    address public treasury;
    mapping(uint256 => address) public ownerOf;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function _safeMint(address to, uint256 tokenId) internal {
        ownerOf[tokenId] = to;
    }

    function buy(address to, uint256 quantity) external payable {
        require(msg.value >= mintPrice * quantity, "insufficient payment");
        require(nextTokenId + quantity <= maxSupply, "sold out");
        for (uint256 i = 0; i < quantity; i++) {
            _safeMint(to, nextTokenId);
            nextTokenId++;
        }
    }
}
"""

# Single-unit mint: no quantity parameter at all.
_NFT_SINGLE = """
contract NftSingleMint {
    uint256 public mintPrice = 0.01 ether;
    uint256 public nextTokenId;
    mapping(uint256 => address) public ownerOf;

    function _safeMint(address to, uint256 tokenId) internal {
        ownerOf[tokenId] = to;
    }

    function buy(address to) external payable {
        require(msg.value >= mintPrice, "insufficient payment");
        _safeMint(to, nextTokenId);
        nextTokenId++;
    }
}
"""

# Reversed comparison still prices per unit.
_NFT_REVERSED = """
contract NftBatchMintReversed {
    uint256 public mintPrice = 0.01 ether;
    uint256 public maxSupply = 10000;
    uint256 public nextTokenId;
    mapping(uint256 => address) public ownerOf;

    function _safeMint(address to, uint256 tokenId) internal {
        ownerOf[tokenId] = to;
    }

    function buy(address to, uint256 quantity) external payable {
        require(quantity * mintPrice <= msg.value, "insufficient payment");
        require(nextTokenId + quantity <= maxSupply, "sold out");
        for (uint256 i = 0; i < quantity; i++) {
            _safeMint(to, nextTokenId);
            nextTokenId++;
        }
    }
}
"""

# ---------------------------------------------------------------------------
# 2. multicall_arbitrary_delegatecall
# ---------------------------------------------------------------------------

_MULTICALL_VULN = """
contract MulticallVuln {
    function multicall(address[] calldata targets, bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](targets.length);
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, bytes memory ret) = targets[i].delegatecall(data[i]);
            require(ok, "subcall failed");
            results[i] = ret;
        }
    }
}
"""

# Delegatecall to a stored implementation only: protected shape.
_MULTICALL_CLEAN = """
contract MulticallClean {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
    }

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool ok, bytes memory ret) = implementation.delegatecall(data[i]);
            require(ok, "subcall failed");
            results[i] = ret;
        }
    }
}
"""

# Target allowlist enforced per sub-call.
_MULTICALL_ALLOWLIST = """
contract MulticallAllowlist {
    mapping(address => bool) public allowedTargets;

    function multicall(address[] calldata targets, bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](targets.length);
        for (uint256 i = 0; i < targets.length; i++) {
            require(allowedTargets[targets[i]], "target not allowed");
            (bool ok, bytes memory ret) = targets[i].delegatecall(data[i]);
            require(ok, "subcall failed");
            results[i] = ret;
        }
    }
}
"""

# Plain call batch: no delegatecall at all.
_MULTICALL_PLAIN_CALL = """
contract MulticallPlainCall {
    function multicall(address[] calldata targets, bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](targets.length);
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, bytes memory ret) = targets[i].call(data[i]);
            require(ok, "subcall failed");
            results[i] = ret;
        }
    }
}
"""

# ---------------------------------------------------------------------------
# 3. auction_bid_after_deadline
# ---------------------------------------------------------------------------

_AUCTION_VULN = """
contract AuctionDeadlineVuln {
    uint256 public auctionEnd;
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    constructor(uint256 _auctionEnd) {
        auctionEnd = _auctionEnd;
    }

    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        pendingReturns[highestBidder] += highestBid;
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function withdraw() external {
        uint256 amount = pendingReturns[msg.sender];
        pendingReturns[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "payout failed");
    }
}
"""

# Deadline enforced on every bid: protected shape.
_AUCTION_CLEAN = """
contract AuctionDeadlineClean {
    uint256 public auctionEnd;
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    constructor(uint256 _auctionEnd) {
        auctionEnd = _auctionEnd;
    }

    function bid() external payable {
        require(block.timestamp < auctionEnd, "auction ended");
        require(msg.value > highestBid, "bid too low");
        pendingReturns[highestBidder] += highestBid;
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function withdraw() external {
        uint256 amount = pendingReturns[msg.sender];
        pendingReturns[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "payout failed");
    }
}
"""

# Deadline enforced in a modifier the bid carries.
_AUCTION_MODIFIER = """
contract AuctionModifierDeadline {
    uint256 public auctionEnd;
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    constructor(uint256 _auctionEnd) {
        auctionEnd = _auctionEnd;
    }

    modifier onlyBeforeEnd() {
        require(block.timestamp < auctionEnd, "auction ended");
        _;
    }

    function bid() external payable onlyBeforeEnd {
        require(msg.value > highestBid, "bid too low");
        pendingReturns[highestBidder] += highestBid;
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
"""

# Deadline enforced in an internal helper the bid calls.
_AUCTION_HELPER = """
contract AuctionHelperDeadline {
    uint256 public auctionEnd;
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    constructor(uint256 _auctionEnd) {
        auctionEnd = _auctionEnd;
    }

    function _checkOpen() internal view {
        require(block.timestamp < auctionEnd, "auction ended");
    }

    function bid() external payable {
        _checkOpen();
        require(msg.value > highestBid, "bid too low");
        pendingReturns[highestBidder] += highestBid;
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
"""

# No deadline declared anywhere: nothing to enforce.
_AUCTION_NO_DEADLINE = """
contract AuctionNoDeadline {
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        pendingReturns[highestBidder] += highestBid;
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
"""

# ---------------------------------------------------------------------------
# 4. bridge_deposit_value_unbound_to_msgvalue
# ---------------------------------------------------------------------------

_BRIDGE_VULN = """
contract BridgeDepositVuln {
    mapping(address => uint256) public deposits;

    function deposit(address to, uint256 amount) external payable {
        deposits[to] += amount;
        emit Deposit(to, amount);
    }

    event Deposit(address indexed to, uint256 amount);
}
"""

_BRIDGE_VARIANT = """
contract BridgeDepositFixed {
    mapping(address => uint256) public deposits;
    address public treasury;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function deposit(address to, uint256 amount) external payable {
        deposits[treasury] += amount;
        emit Deposit(treasury, amount);
    }

    event Deposit(address indexed to, uint256 amount);
}
"""

# Native value bound to the credited amount: protected shape.
_BRIDGE_CLEAN = """
contract BridgeDepositClean {
    mapping(address => uint256) public deposits;

    function deposit(address to, uint256 amount) external payable {
        require(msg.value == amount, "value mismatch");
        deposits[to] += amount;
        emit Deposit(to, amount);
    }

    event Deposit(address indexed to, uint256 amount);
}
"""

# Credits msg.value itself, not the amount parameter.
_BRIDGE_CREDITS_MSGVALUE = """
contract BridgeDepositMsgValue {
    mapping(address => uint256) public deposits;

    function deposit(address to, uint256 amount) external payable {
        deposits[to] += msg.value;
        emit Deposit(to, msg.value);
    }

    event Deposit(address indexed to, uint256 amount);
}
"""

# Non-payable ERC20 deposit: out of scope for a native-value check.
_BRIDGE_ERC20 = _TOKEN_IFACE + """
contract BridgeDepositErc20 {
    mapping(address => uint256) public deposits;
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deposit(address to, uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "pull failed");
        deposits[to] += amount;
        emit Deposit(to, amount);
    }

    event Deposit(address indexed to, uint256 amount);
}
"""

# ---------------------------------------------------------------------------
# 5. merkle_proof_amount_unbound
# ---------------------------------------------------------------------------

_MERKLE_VULN = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleAmountVuln {
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;
    IERC20Like public token;

    constructor(bytes32 _root, address _token) {
        merkleRoot = _root;
        token = IERC20Like(_token);
    }

    function claim(address account, uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked(account))));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        require(!claimed[account], "already claimed");
        claimed[account] = true;
        token.transfer(account, amount);
    }
}
"""

_MERKLE_VARIANT = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleAmountFixed {
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;
    IERC20Like public token;
    address public treasury;

    constructor(bytes32 _root, address _token, address _treasury) {
        merkleRoot = _root;
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function claim(address account, uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked(account))));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        require(!claimed[account], "already claimed");
        claimed[account] = true;
        token.transfer(treasury, amount);
    }
}
"""

# Leaf binds the amount: protected shape.
_MERKLE_CLEAN = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleAmountClean {
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;
    IERC20Like public token;

    constructor(bytes32 _root, address _token) {
        merkleRoot = _root;
        token = IERC20Like(_token);
    }

    function claim(address account, uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked(account, amount))));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        require(!claimed[account], "already claimed");
        claimed[account] = true;
        token.transfer(account, amount);
    }
}
"""

# Leaf supplied by the caller: no inline leaf construction.
_MERKLE_LEAF_PARAM = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleLeafParam {
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;
    IERC20Like public token;

    constructor(bytes32 _root, address _token) {
        merkleRoot = _root;
        token = IERC20Like(_token);
    }

    function claim(address account, uint256 amount, bytes32 leaf, bytes32[] calldata proof) external {
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        require(!claimed[account], "already claimed");
        claimed[account] = true;
        token.transfer(account, amount);
    }
}
"""

# Payout is a stored entitlement: no amount parameter at all.
_MERKLE_STORED_ENTITLEMENT = _TOKEN_IFACE + _MERKLE_LIB + """
contract MerkleStoredEntitlement {
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;
    mapping(address => uint256) public entitlements;
    IERC20Like public token;

    constructor(bytes32 _root, address _token) {
        merkleRoot = _root;
        token = IERC20Like(_token);
    }

    function claim(address account, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encodePacked(account))));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        require(!claimed[account], "already claimed");
        claimed[account] = true;
        uint256 amount = entitlements[account];
        token.transfer(account, amount);
    }
}
"""

VULN = {
    "nft_batch_mint_underpayment": _NFT_VULN,
    "multicall_arbitrary_delegatecall": _MULTICALL_VULN,
    "auction_bid_after_deadline": _AUCTION_VULN,
    "bridge_deposit_value_unbound_to_msgvalue": _BRIDGE_VULN,
    "merkle_proof_amount_unbound": _MERKLE_VULN,
}

VARIANT = {
    "nft_batch_mint_underpayment": _NFT_VARIANT,
    "bridge_deposit_value_unbound_to_msgvalue": _BRIDGE_VARIANT,
    "merkle_proof_amount_unbound": _MERKLE_VARIANT,
}

CLEAN = {
    "nft_batch_mint_underpayment": _NFT_CLEAN,
    "multicall_arbitrary_delegatecall": _MULTICALL_CLEAN,
    "auction_bid_after_deadline": _AUCTION_CLEAN,
    "bridge_deposit_value_unbound_to_msgvalue": _BRIDGE_CLEAN,
    "merkle_proof_amount_unbound": _MERKLE_CLEAN,
}

EXTRA_CLEAN = {
    "nft_single_mint": _NFT_SINGLE,
    "nft_reversed_pricing": _NFT_REVERSED,
    "multicall_allowlist": _MULTICALL_ALLOWLIST,
    "multicall_plain_call": _MULTICALL_PLAIN_CALL,
    "auction_modifier_deadline": _AUCTION_MODIFIER,
    "auction_helper_deadline": _AUCTION_HELPER,
    "auction_no_deadline": _AUCTION_NO_DEADLINE,
    "bridge_credits_msgvalue": _BRIDGE_CREDITS_MSGVALUE,
    "bridge_erc20_deposit": _BRIDGE_ERC20,
    "merkle_leaf_param": _MERKLE_LEAF_PARAM,
    "merkle_stored_entitlement": _MERKLE_STORED_ENTITLEMENT,
}
