"""Fixtures for the deep-audit batch-20 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" (the four
recipient-classified detectors); CLEAN[id] (the protected shape
of the same class) MUST stay silent under ALL five detectors;
VARIANT[id] carries the same vulnerable shape but the value
lands at a FIXED destination, so it MUST fire with
report_class "trigger_only" at low severity - never a
candidate. auction_bid_no_prior_refund has no recipient (no
value moves to a stranger - the loss is locked funds), so it
fires with no report_class.

Cross-talk by construction: the merkle fixture verifies a proof
but names no borrow / liquidate / bid / lzReceive function;
the lzReceive fixture executes a payload but no claim / borrow
/ liquidate / bid function; the auction fixture overwrites the
highest bid but moves no value out; the borrow fixture pays the
caller but checks no price and verifies no proof; the
liquidation fixture takes a price parameter but verifies no
proof and names no borrow function.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
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
# 1. merkle_claim_no_claimed_marker
# ---------------------------------------------------------------------------

_MERKLE_VULN = _TOKEN_IFACE + _MERKLE_LIB + """
contract AirdropVuln {
    IERC20Like public token;
    bytes32 public merkleRoot;

    constructor(address _token, bytes32 _root) {
        token = IERC20Like(_token);
        merkleRoot = _root;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        token.transfer(msg.sender, amount);
    }
}
"""

_MERKLE_VARIANT = _TOKEN_IFACE + _MERKLE_LIB + """
contract AirdropFixed {
    IERC20Like public token;
    bytes32 public merkleRoot;
    address public treasury;

    constructor(address _token, bytes32 _root, address _treasury) {
        token = IERC20Like(_token);
        merkleRoot = _root;
        treasury = _treasury;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        token.transfer(treasury, amount);
    }
}
"""

_MERKLE_CLEAN = _TOKEN_IFACE + _MERKLE_LIB + """
contract AirdropClean {
    IERC20Like public token;
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;

    constructor(address _token, bytes32 _root) {
        token = IERC20Like(_token);
        merkleRoot = _root;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender], "already claimed");
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        claimed[msg.sender] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

# Marker written in an internal helper the entry point calls.
_MERKLE_HELPER_MARK = _TOKEN_IFACE + _MERKLE_LIB + """
contract AirdropHelperMark {
    IERC20Like public token;
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;

    constructor(address _token, bytes32 _root) {
        token = IERC20Like(_token);
        merkleRoot = _root;
    }

    function _markClaimed(address who) internal {
        claimed[who] = true;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        require(!claimed[msg.sender], "already claimed");
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        _markClaimed(msg.sender);
        token.transfer(msg.sender, amount);
    }
}
"""

# Proof verified, no value moved at all: not a drain.
_MERKLE_NO_PAYOUT = _TOKEN_IFACE + _MERKLE_LIB + """
contract AirdropNoPayout {
    IERC20Like public token;
    bytes32 public merkleRoot;

    constructor(address _token, bytes32 _root) {
        token = IERC20Like(_token);
        merkleRoot = _root;
    }

    function claim(uint256 amount, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "bad proof");
        emit Claimed(msg.sender, amount);
    }

    event Claimed(address indexed who, uint256 amount);
}
"""

# ---------------------------------------------------------------------------
# 2. lzreceive_no_origin_validation
# ---------------------------------------------------------------------------

_LZ_VULN = _TOKEN_IFACE + """
contract BridgeReceiverVuln {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function lzReceive(uint32 srcEid, bytes32 sender, bytes calldata payload) external payable {
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        token.transfer(to, amount);
    }
}
"""

_LZ_VARIANT = _TOKEN_IFACE + """
contract BridgeReceiverFixed {
    IERC20Like public token;
    address public vault;

    constructor(address _token, address _vault) {
        token = IERC20Like(_token);
        vault = _vault;
    }

    function lzReceive(uint32 srcEid, bytes32 sender, bytes calldata payload) external payable {
        (uint256 amount) = abi.decode(payload, (uint256));
        token.transfer(vault, amount);
    }
}
"""

_LZ_CLEAN = _TOKEN_IFACE + """
contract BridgeReceiverClean {
    IERC20Like public token;
    address public endpoint;

    constructor(address _token, address _endpoint) {
        token = IERC20Like(_token);
        endpoint = _endpoint;
    }

    function lzReceive(uint32 srcEid, bytes32 sender, bytes calldata payload) external payable onlyEndpoint {
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        token.transfer(to, amount);
    }

    modifier onlyEndpoint() {
        require(msg.sender == endpoint, "not endpoint");
        _;
    }
}
"""

# Inline origin check instead of a modifier: trusted remote for the srcEid.
_LZ_INLINE_CHECK = _TOKEN_IFACE + """
contract BridgeReceiverInlineCheck {
    IERC20Like public token;
    mapping(uint32 => bytes32) public trustedRemote;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    struct Origin {
        uint32 srcEid;
        bytes32 sender;
        uint64 nonce;
    }

    function lzReceive(Origin calldata _origin, bytes32 guid, bytes calldata payload, address executor, bytes calldata extraData) external payable {
        require(_origin.sender == trustedRemote[_origin.srcEid], "untrusted origin");
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        token.transfer(to, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. auction_bid_no_prior_refund
# ---------------------------------------------------------------------------

_AUCTION_VULN = """
contract AuctionVuln {
    address public highestBidder;
    uint256 public highestBid;

    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        highestBid = msg.value;
        highestBidder = msg.sender;
    }
}
"""

_AUCTION_CLEAN = """
contract AuctionClean {
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public pendingReturns;

    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        pendingReturns[highestBidder] += highestBid;
        highestBid = msg.value;
        highestBidder = msg.sender;
    }

    function withdraw() external {
        uint256 amount = pendingReturns[msg.sender];
        pendingReturns[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
"""

# Direct refund via an internal helper the entry point calls.
_AUCTION_HELPER_REFUND = """
contract AuctionHelperRefund {
    address public highestBidder;
    uint256 public highestBid;

    function _refundPreviousBidder() internal {
        payable(highestBidder).transfer(highestBid);
    }

    function placeBid() external payable {
        require(msg.value > highestBid, "bid too low");
        if (highestBidder != address(0)) {
            _refundPreviousBidder();
        }
        highestBid = msg.value;
        highestBidder = msg.sender;
    }
}
"""

# placeBid name, direct refund inline.
_AUCTION_DIRECT_REFUND = """
contract AuctionDirectRefund {
    address public highestBidder;
    uint256 public highestBid;

    function placeBid() external payable {
        require(msg.value > highestBid, "bid too low");
        if (highestBidder != address(0)) {
            payable(highestBidder).transfer(highestBid);
        }
        highestBid = msg.value;
        highestBidder = msg.sender;
    }
}
"""

# ---------------------------------------------------------------------------
# 4. borrow_no_collateral_check
# ---------------------------------------------------------------------------

_BORROW_VULN = _TOKEN_IFACE + """
contract LendingVuln {
    IERC20Like public token;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function borrow(uint256 amount) external {
        token.transfer(msg.sender, amount);
    }
}
"""

_BORROW_VARIANT = _TOKEN_IFACE + """
contract LendingFixed {
    IERC20Like public token;
    address public vault;

    constructor(address _token, address _vault) {
        token = IERC20Like(_token);
        vault = _vault;
    }

    function borrow(uint256 amount) external {
        token.transfer(vault, amount);
    }
}
"""

_BORROW_CLEAN = _TOKEN_IFACE + """
contract LendingClean {
    IERC20Like public token;
    mapping(address => uint256) public collateralBalances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function getCollateralValue(address who) public view returns (uint256) {
        return collateralBalances[who];
    }

    function borrow(uint256 amount) external {
        uint256 collateralValue = getCollateralValue(msg.sender);
        require(collateralValue >= amount * 2, "undercollateralized");
        token.transfer(msg.sender, amount);
    }
}
"""

# Comptroller hook instead of an inline collateral require.
_BORROW_COMPTROLLER = _TOKEN_IFACE + """
interface IComptroller {
    function borrowAllowed(address market, address borrower, uint256 amount) external returns (uint256);
}

contract LendingComptroller {
    IERC20Like public token;
    IComptroller public comptroller;

    constructor(address _token, address _comptroller) {
        token = IERC20Like(_token);
        comptroller = IComptroller(_comptroller);
    }

    function borrow(uint256 amount) external {
        require(comptroller.borrowAllowed(address(this), msg.sender, amount) == 0, "not allowed");
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. liquidation_caller_supplied_price
# ---------------------------------------------------------------------------

_LIQUIDATION_VULN = _TOKEN_IFACE + """
contract LiquidationVuln {
    IERC20Like public collateralToken;
    mapping(address => uint256) public debts;
    mapping(address => uint256) public collaterals;

    constructor(address _token) {
        collateralToken = IERC20Like(_token);
    }

    function liquidate(address borrower, uint256 price) external {
        uint256 seizeAmount = debts[borrower] * 1e18 / price;
        collaterals[borrower] -= seizeAmount;
        collateralToken.transfer(msg.sender, seizeAmount);
    }
}
"""

_LIQUIDATION_VARIANT = _TOKEN_IFACE + """
contract LiquidationFixed {
    IERC20Like public collateralToken;
    mapping(address => uint256) public debts;
    mapping(address => uint256) public collaterals;
    address public treasury;

    constructor(address _token, address _treasury) {
        collateralToken = IERC20Like(_token);
        treasury = _treasury;
    }

    function liquidate(address borrower, uint256 price) external {
        uint256 seizeAmount = debts[borrower] * 1e18 / price;
        collaterals[borrower] -= seizeAmount;
        collateralToken.transfer(treasury, seizeAmount);
    }
}
"""

_LIQUIDATION_CLEAN = _TOKEN_IFACE + """
interface IPriceFeed {
    function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

contract LiquidationClean {
    IERC20Like public collateralToken;
    IPriceFeed public priceFeed;
    mapping(address => uint256) public debts;
    mapping(address => uint256) public collaterals;

    constructor(address _token, address _feed) {
        collateralToken = IERC20Like(_token);
        priceFeed = IPriceFeed(_feed);
    }

    function liquidate(address borrower) external {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        uint256 price = uint256(answer);
        uint256 seizeAmount = debts[borrower] * 1e18 / price;
        collaterals[borrower] -= seizeAmount;
        collateralToken.transfer(msg.sender, seizeAmount);
    }
}
"""

# Price parameter present, but the oracle price is read and enforced too.
_LIQUIDATION_ORACLE_ENFORCED = _TOKEN_IFACE + """
interface IPriceFeed {
    function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

contract LiquidationOracleEnforced {
    IERC20Like public collateralToken;
    IPriceFeed public priceFeed;
    mapping(address => uint256) public debts;
    mapping(address => uint256) public collaterals;

    constructor(address _token, address _feed) {
        collateralToken = IERC20Like(_token);
        priceFeed = IPriceFeed(_feed);
    }

    function liquidate(address borrower, uint256 price) external {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        require(price == uint256(answer), "price mismatch");
        uint256 seizeAmount = debts[borrower] * 1e18 / price;
        collaterals[borrower] -= seizeAmount;
        collateralToken.transfer(msg.sender, seizeAmount);
    }
}
"""

VULN = {
    "merkle_claim_no_claimed_marker": _MERKLE_VULN,
    "lzreceive_no_origin_validation": _LZ_VULN,
    "auction_bid_no_prior_refund": _AUCTION_VULN,
    "borrow_no_collateral_check": _BORROW_VULN,
    "liquidation_caller_supplied_price": _LIQUIDATION_VULN,
}

VARIANT = {
    "merkle_claim_no_claimed_marker": _MERKLE_VARIANT,
    "lzreceive_no_origin_validation": _LZ_VARIANT,
    "borrow_no_collateral_check": _BORROW_VARIANT,
    "liquidation_caller_supplied_price": _LIQUIDATION_VARIANT,
}

CLEAN = {
    "merkle_claim_no_claimed_marker": _MERKLE_CLEAN,
    "lzreceive_no_origin_validation": _LZ_CLEAN,
    "auction_bid_no_prior_refund": _AUCTION_CLEAN,
    "borrow_no_collateral_check": _BORROW_CLEAN,
    "liquidation_caller_supplied_price": _LIQUIDATION_CLEAN,
}

EXTRA_CLEAN = {
    "merkle_helper_mark": _MERKLE_HELPER_MARK,
    "merkle_no_payout": _MERKLE_NO_PAYOUT,
    "lz_inline_check": _LZ_INLINE_CHECK,
    "auction_helper_refund": _AUCTION_HELPER_REFUND,
    "auction_direct_refund": _AUCTION_DIRECT_REFUND,
    "borrow_comptroller": _BORROW_COMPTROLLER,
    "liquidation_oracle_enforced": _LIQUIDATION_ORACLE_ENFORCED,
}
