"""Fixtures for the deep-audit batch-17 detector.

VULN MUST fire with kind zeroday_exploit_chain, code evidence,
and report_class "candidate"; CLEAN (the protected shape of the
same class) MUST stay silent; VARIANT carries the same dangerous
shape but the value lands at a FIXED recipient, so it MUST fire
with report_class "trigger_only" at low severity - never a
candidate; every EXTRA_CLEAN shape MUST stay silent.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# VULN: ungated execute() delegatecalls a caller-supplied target and
# the same function pays the contract's token balance to the caller.
# ---------------------------------------------------------------------------

_VULN = _TOKEN_IFACE + """
contract ZeroDayVaultVuln {
    IERC20Like public token;

    constructor(address _t) {
        token = IERC20Like(_t);
    }

    function execute(address target, bytes calldata data) external payable {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }
}
"""

# ---------------------------------------------------------------------------
# CLEAN: the same shape, gated by onlyOwner.
# ---------------------------------------------------------------------------

_CLEAN = _TOKEN_IFACE + """
contract ZeroDayVaultClean {
    IERC20Like public token;
    address public owner;

    constructor(address _t) {
        token = IERC20Like(_t);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function execute(address target, bytes calldata data) external payable onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }
}
"""

# ---------------------------------------------------------------------------
# VARIANT: mint to a FIXED recipient with a caller-controlled
# amount - the caller controls how much is minted but not who
# receives it, so it fires trigger-only, never a candidate.
# ---------------------------------------------------------------------------

_VARIANT = """
contract ZeroDayMintFixed {
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    function mint(uint256 amount) external {
        _mint(owner, amount);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

# ---------------------------------------------------------------------------
# EXTRA_CLEAN shapes (asserted separately in the test file).
# ---------------------------------------------------------------------------

_FIXED_TARGET = _TOKEN_IFACE + """
contract ZeroDayFixedTarget {
    IERC20Like public token;
    address public immutable implementation;

    constructor(address _t, address _impl) {
        token = IERC20Like(_t);
        implementation = _impl;
    }

    function execute(bytes calldata data) external payable {
        (bool ok, ) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
        token.transfer(msg.sender, token.balanceOf(address(this)));
    }
}
"""

_CALL_NO_VALUE = """
contract ZeroDayCallNoValue {
    function execute(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}
"""

_MINT_GATED = """
contract ZeroDayMintGated {
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

_MINT_FIXED_AMOUNT = """
contract ZeroDayMintFixedAmount {
    address public owner;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    function mint() external {
        _mint(owner, 100);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

_SELFDESTRUCT_FIXED = """
contract ZeroDaySelfdestructFixed {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function kill() external {
        selfdestruct(payable(owner));
    }
}
"""

_UPGRADE_GATED = """
contract ZeroDayUpgradeGated {
    address public owner;
    address public implementation;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function upgradeTo(address newImplementation) external onlyOwner {
        implementation = newImplementation;
    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""

_UPGRADE_FIXED = """
contract ZeroDayUpgradeFixed {
    address public implementation;
    address public fixedImpl;

    constructor(address _impl) {
        fixedImpl = _impl;
    }

    function upgradeTo() external {
        implementation = fixedImpl;
    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""

_CALL_FIXED_TARGET = """
contract ZeroDayCallFixedTarget {
    address public target;

    constructor(address _t) {
        target = _t;
    }

    function execute(bytes calldata data) external payable {
        (bool ok, ) = target.call{value: address(this).balance}(data);
        require(ok, "call failed");
    }
}
"""

# A second vulnerable shape: ungated selfdestruct to a
# caller-supplied recipient (the balance goes where the caller
# says). Used by the plugin-run test's balance gate, not by the
# fixture test's VULN slot.
_VULN_SELFDESTRUCT = """
contract ZeroDaySelfdestructVuln {
    function kill(address payable to) external {
        selfdestruct(to);
    }
}
"""

# A third vulnerable shape: unguided upgradeTo on a contract that
# holds value (withdraw exists), implementation caller-supplied.
_VULN_UPGRADE = """
contract ZeroDayUpgradeVuln {
    address public implementation;

    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""

# A fourth vulnerable shape: ungated mint to the caller.
_VULN_MINT = """
contract ZeroDayMintVuln {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

# A fifth vulnerable shape: ungated mint of a DOUBLED amount
# (amount * 2) - the amount is an expression built from the
# caller's parameter, so it is still caller-controlled and must
# fire. Only an amount of exactly msg.value is self-funded.
_VULN_MINT_DOUBLED = """
contract ZeroDayMintDoubled {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        _mint(to, amount * 2);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

# ---------------------------------------------------------------------------
# EXTRA_CLEAN shapes from the smoke triage (2026-11-11): real gates
# the first build missed. Each MUST stay silent.
# ---------------------------------------------------------------------------

# A canMint modifier whose body is a minter allowlist
# (minters[msg.sender]) - the ZenToken shape.
_MINT_MAPPING_GATE = """
contract ZeroDayMintMappingGate {
    mapping(address => bool) public minters;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    modifier canMint() {
        if (!minters[msg.sender]) {
            revert("not minter");
        }
        _;
    }

    function mint(address to, uint256 amount) external canMint {
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

# A guard helper one hop down: mint requires _canMint(), whose
# body compares msg.sender to the allowed contracts.
_MINT_GUARD_HELPER = """
contract ZeroDayMintGuardHelper {
    address public mndContract;
    address public ndContract;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    constructor(address _mnd, address _nd) {
        mndContract = _mnd;
        ndContract = _nd;
    }

    function _canMint() private view returns (bool) {
        return msg.sender == mndContract || msg.sender == ndContract;
    }

    function mint(address to, uint256 amount) external {
        require(_canMint(), "not minter");
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

# A child mint that only delegates to a gated parent mint
# (super.mint); the parent requires a sender role.
_MINT_PARENT_GATED = """
contract ZeroDayMintBase {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) public virtual {
        require(isSenderInRole(1), "denied");
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal virtual {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}

contract ZeroDayMintChild is ZeroDayMintBase {
    function mint(address to, uint256 amount) public override {
        super.mint(to, amount);
    }
}
"""

# A self-funded mint: the caller pays msg.value and mints exactly
# msg.value worth (depositTo). Nothing to steal.
_MINT_SELF_FUNDED = """
contract ZeroDayMintSelfFunded {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function depositTo(address account) public payable {
        _mint(account, msg.value);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

# A sender-role predicate call in the function itself
# (isSenderInRole checks the caller's role internally).
_MINT_SENDER_ROLE = """
contract ZeroDayMintSenderRole {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        require(isSenderInRole(1), "denied");
        _mint(to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

# A per-caller bridge limit (the xERC20 shape): only a registered
# bridge has a minting limit above zero, so a stranger's mint
# reverts when the limit is below the amount.
_MINT_BRIDGE_LIMIT = """
contract ZeroDayMintBridgeLimit {
    mapping(address => uint256) public limits;
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mintingCurrentLimitOf(address bridge)
        public view returns (uint256)
    {
        return limits[bridge];
    }

    function mint(address user, uint256 amount) external {
        address bridge = msg.sender;
        uint256 currentLimit = mintingCurrentLimitOf(bridge);
        if (currentLimit < amount) revert("limit");
        _mint(user, amount);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
"""

# A UUPS upgrade whose _authorizeUpgrade override is gated
# (onlyOwner): the upgrade path is authorized, so no upgrade leg.
_UPGRADE_AUTHORIZE_GATED = """
contract ZeroDayUpgradeAuthorizeGated {
    address public implementation;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function upgradeTo(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
        implementation = newImplementation;
    }

    function _authorizeUpgrade(address newImplementation)
        internal onlyOwner
    {
    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""

VULN = {
    "zeroday_exploit_chain": _VULN,
}

CLEAN = {
    "zeroday_exploit_chain": _CLEAN,
}

VARIANT = {
    "zeroday_exploit_chain": _VARIANT,
}

# Extra clean shapes (not the primary CLEAN control, asserted
# separately in the test file).
EXTRA_CLEAN = {
    "zeroday_exploit_chain_fixed_target": _FIXED_TARGET,
    "zeroday_exploit_chain_call_no_value": _CALL_NO_VALUE,
    "zeroday_exploit_chain_mint_gated": _MINT_GATED,
    "zeroday_exploit_chain_mint_fixed_amount": _MINT_FIXED_AMOUNT,
    "zeroday_exploit_chain_selfdestruct_fixed": _SELFDESTRUCT_FIXED,
    "zeroday_exploit_chain_upgrade_gated": _UPGRADE_GATED,
    "zeroday_exploit_chain_upgrade_fixed": _UPGRADE_FIXED,
    "zeroday_exploit_chain_call_fixed_target": _CALL_FIXED_TARGET,
    "zeroday_exploit_chain_mint_mapping_gate": _MINT_MAPPING_GATE,
    "zeroday_exploit_chain_mint_guard_helper": _MINT_GUARD_HELPER,
    "zeroday_exploit_chain_mint_parent_gated": _MINT_PARENT_GATED,
    "zeroday_exploit_chain_mint_self_funded": _MINT_SELF_FUNDED,
    "zeroday_exploit_chain_mint_sender_role": _MINT_SENDER_ROLE,
    "zeroday_exploit_chain_mint_bridge_limit": _MINT_BRIDGE_LIMIT,
    "zeroday_exploit_chain_upgrade_authorize_gated":
        _UPGRADE_AUTHORIZE_GATED,
}

# Extra vulnerable shapes (one per remaining primitive leg).
EXTRA_VULN = {
    "zeroday_exploit_chain_selfdestruct": _VULN_SELFDESTRUCT,
    "zeroday_exploit_chain_upgrade": _VULN_UPGRADE,
    "zeroday_exploit_chain_mint": _VULN_MINT,
    "zeroday_exploit_chain_mint_doubled": _VULN_MINT_DOUBLED,
}
