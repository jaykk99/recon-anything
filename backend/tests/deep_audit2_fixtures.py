"""Fixtures for the deep-audit batch-2 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
six detectors; VARIANT[id] carries the same vulnerable shape
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
# 1. hook_cei_reentrancy
# ---------------------------------------------------------------------------

_HOOK_VULN = _TOKEN_IFACE + """
interface IERC777Recipient {
    function tokensReceived(address operator, address from, address to, uint256 amount, bytes calldata userData, bytes calldata operatorData) external;
}

contract HookTokenVuln {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function send(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        IERC777Recipient(to).tokensReceived(msg.sender, msg.sender, to, amount, "", "");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
"""

_HOOK_CLEAN = _TOKEN_IFACE + """
interface IERC777Recipient {
    function tokensReceived(address operator, address from, address to, uint256 amount, bytes calldata userData, bytes calldata operatorData) external;
}

contract HookTokenClean {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    function send(address to, uint256 amount) external nonReentrant {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        if (to.code.length > 0) {
            IERC777Recipient(to).tokensReceived(msg.sender, msg.sender, to, amount, "", "");
        }
    }
}
"""

_HOOK_VARIANT = _TOKEN_IFACE + """
interface IERC1363Receiver {
    function onTransferReceived(address operator, address from, uint256 amount, bytes calldata data) external returns (bytes4);
}

contract HookSettleFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => uint256) public settled;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function settle(uint256 amount) external {
        IERC1363Receiver(treasury).onTransferReceived(msg.sender, msg.sender, amount, "");
        settled[treasury] += amount;
        token.transfer(treasury, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. bridge_replay_unbound_digest
# ---------------------------------------------------------------------------

_BRIDGE_VULN = _TOKEN_IFACE + """
contract BridgeExecutorVuln {
    IERC20Like public token;
    address public validator;
    mapping(bytes32 => bool) public executed;

    constructor(address _token, address _validator) {
        token = IERC20Like(_token);
        validator = _validator;
    }

    function executeMessage(address recipient, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(recipient, amount));
        address signer = ecrecover(digest, v, r, s);
        require(signer == validator, "bad signer");
        require(!executed[digest], "already executed");
        executed[digest] = true;
        token.transfer(recipient, amount);
    }
}
"""

_BRIDGE_CLEAN = _TOKEN_IFACE + """
contract BridgeExecutorClean {
    IERC20Like public token;
    address public validator;
    mapping(bytes32 => bool) public executed;

    constructor(address _token, address _validator) {
        token = IERC20Like(_token);
        validator = _validator;
    }

    function executeMessage(uint256 srcChainId, address srcSender, uint256 nonce, address recipient, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        require(srcChainId == 56, "wrong source chain");
        bytes32 digest = keccak256(abi.encode(srcChainId, srcSender, nonce, recipient, amount));
        address signer = ecrecover(digest, v, r, s);
        require(signer == validator, "bad signer");
        require(!executed[digest], "replay");
        executed[digest] = true;
        token.transfer(recipient, amount);
    }
}
"""

_BRIDGE_VARIANT = _TOKEN_IFACE + """
contract BridgeClaimFixed {
    IERC20Like public token;
    address public validator;
    address public vault;
    mapping(bytes32 => bool) public claimed;

    constructor(address _token, address _validator, address _vault) {
        token = IERC20Like(_token);
        validator = _validator;
        vault = _vault;
    }

    function claim(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(amount));
        require(ecrecover(digest, v, r, s) == validator, "bad signer");
        require(!claimed[digest], "replay");
        claimed[digest] = true;
        token.transfer(vault, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. eip7702_unverified_delegate
# ---------------------------------------------------------------------------

_7702_VULN = """
contract DelegatedAccountVuln {
    address public delegate;
    bytes public designator;

    function setDelegate(address newDelegate) external {
        delegate = newDelegate;
        designator = abi.encodePacked(bytes3(0xef0100), newDelegate);
    }
}
"""

_7702_CLEAN = """
contract DelegatedAccountClean {
    address public delegate;
    address public owner;
    mapping(address => bool) public allowedDelegate;

    function setDelegate(address newDelegate) external {
        require(msg.sender == owner, "not owner");
        require(allowedDelegate[newDelegate], "delegate not allowlisted");
        require(newDelegate.code.length > 0, "delegate has no code");
        delegate = newDelegate;
    }
}
"""

_7702_VARIANT = """
contract DelegatedAccountFixed {
    address public delegate;
    address public defaultDelegate;
    bytes public designator;

    constructor(address _defaultDelegate) {
        defaultDelegate = _defaultDelegate;
    }

    function resetDelegate() external {
        delegate = defaultDelegate;
        designator = abi.encodePacked(bytes3(0xef0100), defaultDelegate);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. l2_sequencer_uptime_missing
# ---------------------------------------------------------------------------

_FEED_IFACE = """
interface IChainlinkFeed {
    function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}
"""

_L2_VULN = _TOKEN_IFACE + _FEED_IFACE + """
contract ArbitrumLendingVuln {
    IChainlinkFeed public feed;
    IERC20Like public token;
    mapping(address => uint256) public borrowed;

    constructor(address _feed, address _token) {
        feed = IChainlinkFeed(_feed);
        token = IERC20Like(_token);
    }

    function liquidate(address borrower, uint256 amount) external {
        (, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();
        require(price > 0, "bad price");
        require(block.timestamp - updatedAt <= 3600, "stale price");
        borrowed[borrower] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_L2_CLEAN = _TOKEN_IFACE + _FEED_IFACE + """
contract ArbitrumLendingClean {
    IChainlinkFeed public feed;
    IChainlinkFeed public sequencerUptimeFeed;
    IERC20Like public token;
    uint256 public constant GRACE_PERIOD_TIME = 3600;
    mapping(address => uint256) public borrowed;

    constructor(address _feed, address _sequencer, address _token) {
        feed = IChainlinkFeed(_feed);
        sequencerUptimeFeed = IChainlinkFeed(_sequencer);
        token = IERC20Like(_token);
    }

    function liquidate(address borrower, uint256 amount) external {
        (, int256 upAnswer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();
        require(upAnswer == 0, "sequencer is down");
        require(block.timestamp - startedAt > GRACE_PERIOD_TIME, "grace period not over");
        (, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();
        require(price > 0, "bad price");
        require(block.timestamp - updatedAt <= 3600, "stale price");
        borrowed[borrower] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_L2_VARIANT = _TOKEN_IFACE + _FEED_IFACE + """
contract ArbitrumFeesFixed {
    IChainlinkFeed public feed;
    IERC20Like public token;
    address public treasury;

    constructor(address _feed, address _token, address _treasury) {
        feed = IChainlinkFeed(_feed);
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function collect(uint256 amount) external {
        (, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();
        require(price > 0, "bad price");
        require(block.timestamp - updatedAt <= 3600, "stale price");
        token.transfer(treasury, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. fee_on_transfer_overcredit
# ---------------------------------------------------------------------------

_FOT_VULN = _TOKEN_IFACE + """
contract FotVaultVuln {
    IERC20Like public token;
    mapping(address => uint256) public sharesOf;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        sharesOf[msg.sender] += amount;
    }
}
"""

_FOT_CLEAN = _TOKEN_IFACE + """
contract FotVaultClean {
    IERC20Like public token;
    mapping(address => uint256) public sharesOf;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function deposit(uint256 amount) external returns (uint256 received) {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.transferFrom(msg.sender, address(this), amount);
        received = token.balanceOf(address(this)) - balanceBefore;
        sharesOf[msg.sender] += received;
    }
}
"""

_FOT_VARIANT = _TOKEN_IFACE + """
contract FotTreasuryFixed {
    IERC20Like public token;
    address public treasury;
    mapping(address => uint256) public sharesOf;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function depositToTreasury(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        sharesOf[treasury] += amount;
    }
}
"""

# ---------------------------------------------------------------------------
# 6. create2_metamorphic_redeploy
# ---------------------------------------------------------------------------

_CREATE2_VULN = """
contract MetamorphicChild {
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}

contract MetamorphicFactoryVuln {
    function deploy(bytes32 salt) external returns (address addr) {
        bytes32 finalSalt = keccak256(abi.encode(msg.sender, salt));
        MetamorphicChild child = new MetamorphicChild{ salt: finalSalt }();
        addr = address(child);
    }
}
"""

_CREATE2_CLEAN = """
contract ImmutableChild {
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }
}

contract ImmutableFactoryClean {
    function deploy(bytes32 salt) external returns (address addr) {
        bytes32 finalSalt = keccak256(abi.encode(msg.sender, salt));
        ImmutableChild child = new ImmutableChild{ salt: finalSalt }();
        addr = address(child);
    }
}
"""

_CREATE2_VARIANT = """
contract GatedChild {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function kill() external onlyOwner {
        selfdestruct(payable(owner));
    }
}

contract GatedFactory {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function deploy(bytes32 salt) external onlyOwner returns (address addr) {
        bytes32 finalSalt = keccak256(abi.encode(msg.sender, salt));
        GatedChild child = new GatedChild{ salt: finalSalt }();
        addr = address(child);
    }
}
"""

VULN = {
    "hook_cei_reentrancy": _HOOK_VULN,
    "bridge_replay_unbound_digest": _BRIDGE_VULN,
    "eip7702_unverified_delegate": _7702_VULN,
    "l2_sequencer_uptime_missing": _L2_VULN,
    "fee_on_transfer_overcredit": _FOT_VULN,
    "create2_metamorphic_redeploy": _CREATE2_VULN,
}

CLEAN = {
    "hook_cei_reentrancy": _HOOK_CLEAN,
    "bridge_replay_unbound_digest": _BRIDGE_CLEAN,
    "eip7702_unverified_delegate": _7702_CLEAN,
    "l2_sequencer_uptime_missing": _L2_CLEAN,
    "fee_on_transfer_overcredit": _FOT_CLEAN,
    "create2_metamorphic_redeploy": _CREATE2_CLEAN,
}

VARIANT = {
    "hook_cei_reentrancy": _HOOK_VARIANT,
    "bridge_replay_unbound_digest": _BRIDGE_VARIANT,
    "eip7702_unverified_delegate": _7702_VARIANT,
    "l2_sequencer_uptime_missing": _L2_VARIANT,
    "fee_on_transfer_overcredit": _FOT_VARIANT,
    "create2_metamorphic_redeploy": _CREATE2_VARIANT,
}
