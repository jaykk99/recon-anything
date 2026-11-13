"""Fixtures for the deep-audit batch-20 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate"; CLEAN[id] (the
protected shape of the same class) MUST stay silent under ALL
five detectors; VARIANT[id] carries the same vulnerable shape
but the value lands at a FIXED destination, so it MUST fire
with report_class "trigger_only" at low severity - never a
candidate. All five detectors are recipient-classified.

Cross-talk by construction: the cover fixture has no sweep /
selector / wrapper / cap shape; the selector fixture has no
capacity / sweep / wrapper / cap shape; the sweep fixture has
no capacity / selector / wrapper / cap shape; the wrapper
fixture has no capacity / selector / sweep / cap shape; the
cap fixture has no capacity / selector / sweep / wrapper shape.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. cover_capacity_counts_unpaid_prior_period
# ---------------------------------------------------------------------------

_COVER_VULN = _TOKEN_IFACE + """
contract CoverPoolVuln {
    IERC20Like public token;
    uint256 public totalCollateral;
    uint256 public unpaidPriorPeriod;
    uint256 public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function availableCover() public view returns (uint256) {
        return totalCollateral - claimed;
    }

    function claim(uint256 amount) external {
        uint256 cover = availableCover();
        require(amount <= cover, "exceeds cover");
        claimed += amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_COVER_VARIANT = _TOKEN_IFACE + """
contract CoverPoolFixed {
    IERC20Like public token;
    address public treasury;
    uint256 public totalCollateral;
    uint256 public unpaidPriorPeriod;
    uint256 public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
        treasury = msg.sender;
    }

    function availableCover() public view returns (uint256) {
        return totalCollateral - claimed;
    }

    function claim(uint256 amount) external {
        uint256 cover = availableCover();
        require(amount <= cover, "exceeds cover");
        claimed += amount;
        token.transfer(treasury, amount);
    }
}
"""

_COVER_CLEAN = _TOKEN_IFACE + """
contract CoverPoolClean {
    IERC20Like public token;
    uint256 public totalCollateral;
    uint256 public unpaidPriorPeriod;
    uint256 public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function availableCover() public view returns (uint256) {
        return totalCollateral - claimed - unpaidPriorPeriod;
    }

    function claim(uint256 amount) external {
        uint256 cover = availableCover();
        require(amount <= cover, "exceeds cover");
        claimed += amount;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. user_bytes_as_call_selector
# ---------------------------------------------------------------------------

_SELECTOR_VULN = _TOKEN_IFACE + """
contract ZkVerifierVuln {
    IERC20Like public token;
    address public verifier;
    bytes32 public stateRoot;

    constructor(address _token, address _verifier) {
        token = IERC20Like(_token);
        verifier = _verifier;
    }

    function verifyProof(bytes calldata proof, uint256 amount) external {
        (bool ok, bytes memory ret) = verifier.call(abi.encodePacked(bytes4(proof), proof));
        require(ok, "verify failed");
        stateRoot = bytes32(ret);
        token.transfer(msg.sender, amount);
    }
}
"""

_SELECTOR_VARIANT = _TOKEN_IFACE + """
contract ZkVerifierFixed {
    IERC20Like public token;
    address public verifier;
    address public treasury;
    bytes32 public stateRoot;

    constructor(address _token, address _verifier) {
        token = IERC20Like(_token);
        verifier = _verifier;
        treasury = msg.sender;
    }

    function verifyProof(bytes calldata proof, uint256 amount) external {
        (bool ok, bytes memory ret) = verifier.call(abi.encodePacked(bytes4(proof), proof));
        require(ok, "verify failed");
        stateRoot = bytes32(ret);
        token.transfer(treasury, amount);
    }
}
"""

_SELECTOR_CLEAN = _TOKEN_IFACE + """
contract ZkVerifierClean {
    IERC20Like public token;
    address public verifier;
    bytes32 public stateRoot;

    constructor(address _token, address _verifier) {
        token = IERC20Like(_token);
        verifier = _verifier;
    }

    function verifyProof(bytes calldata proof, uint256 amount) external {
        (bool ok, bytes memory ret) = verifier.call(abi.encodePacked(bytes4(0x24270d54), proof));
        require(ok, "verify failed");
        stateRoot = bytes32(ret);
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. permissionless_sweep_breaks_settlement_finality
# ---------------------------------------------------------------------------

_SWEEP_VULN = _TOKEN_IFACE + """
contract BattlePoolVuln {
    IERC20Like public token;
    bool public claimsStarted;
    uint256 public totalStaked;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claim(uint256 amount) external {
        claimsStarted = true;
        token.transfer(msg.sender, amount);
    }

    function sweepUnclaimedBonus() external {
        uint256 bonus = token.balanceOf(address(this)) / 10;
        token.transfer(msg.sender, bonus);
    }

    function reflagSettlement() external {
        uint256 remaining = token.balanceOf(address(this));
        totalStaked = remaining;
    }
}
"""

_SWEEP_VARIANT = _TOKEN_IFACE + """
contract BattlePoolFixed {
    IERC20Like public token;
    address public treasury;
    bool public claimsStarted;
    uint256 public totalStaked;

    constructor(address _token) {
        token = IERC20Like(_token);
        treasury = msg.sender;
    }

    function claim(uint256 amount) external {
        claimsStarted = true;
        token.transfer(msg.sender, amount);
    }

    function sweepUnclaimedBonus() external {
        uint256 bonus = token.balanceOf(address(this)) / 10;
        token.transfer(treasury, bonus);
    }

    function reflagSettlement() external {
        uint256 remaining = token.balanceOf(address(this));
        totalStaked = remaining;
    }
}
"""

_SWEEP_CLEAN = _TOKEN_IFACE + """
contract BattlePoolClean {
    IERC20Like public token;
    bool public claimsStarted;
    uint256 public totalStaked;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claim(uint256 amount) external {
        claimsStarted = true;
        token.transfer(msg.sender, amount);
    }

    function sweepUnclaimedBonus() external {
        require(claimsStarted, "settlement not started");
        uint256 bonus = token.balanceOf(address(this)) / 10;
        token.transfer(msg.sender, bonus);
    }

    function reflagSettlement() external {
        uint256 remaining = token.balanceOf(address(this));
        totalStaked = remaining;
    }
}
"""

# ---------------------------------------------------------------------------
# 4. wrapper_create_no_code_check
# ---------------------------------------------------------------------------

_WRAPPER_VULN = _TOKEN_IFACE + """
contract ERC223Wrapper {
    address public token;

    constructor(address _token) {
        token = _token;
    }
}

contract WrapperFactoryVuln {
    IERC20Like public token;
    address public deployer;
    mapping(address => address) public wrappers;

    constructor() {
        deployer = msg.sender;
    }

    function createERC223Wrapper(address token) external payable returns (address wrapper) {
        uint256 fee = 0.01 ether;
        require(msg.value >= fee, "fee");
        wrapper = address(new ERC223Wrapper(token));
        wrappers[token] = wrapper;
        payable(msg.sender).transfer(msg.value - fee);
        return wrapper;
    }
}
"""

_WRAPPER_VARIANT = _TOKEN_IFACE + """
contract ERC223Wrapper {
    address public token;

    constructor(address _token) {
        token = _token;
    }
}

contract WrapperFactoryFixed {
    IERC20Like public token;
    address public deployer;
    mapping(address => address) public wrappers;

    constructor() {
        deployer = msg.sender;
    }

    function createERC223Wrapper(address token) external payable returns (address wrapper) {
        uint256 fee = 0.01 ether;
        require(msg.value >= fee, "fee");
        wrapper = address(new ERC223Wrapper(token));
        wrappers[token] = wrapper;
        payable(deployer).transfer(msg.value - fee);
        return wrapper;
    }
}
"""

_WRAPPER_CLEAN = _TOKEN_IFACE + """
import "@openzeppelin/contracts/utils/Address.sol";

contract ERC223Wrapper {
    address public token;

    constructor(address _token) {
        token = _token;
    }
}

contract WrapperFactoryClean {
    IERC20Like public token;
    address public deployer;
    mapping(address => address) public wrappers;

    constructor() {
        deployer = msg.sender;
    }

    function createERC223Wrapper(address token) external payable returns (address wrapper) {
        require(Address.isContract(token), "not a contract");
        uint256 fee = 0.01 ether;
        require(msg.value >= fee, "fee");
        wrapper = address(new ERC223Wrapper(token));
        wrappers[token] = wrapper;
        payable(msg.sender).transfer(msg.value - fee);
        return wrapper;
    }
}
"""

# ---------------------------------------------------------------------------
# 5. supply_cap_bypass_direct_transfer
# ---------------------------------------------------------------------------

_CAP_VULN = _TOKEN_IFACE + """
contract CTokenMarketVuln {
    IERC20Like public token;
    uint256 public supplyCap;
    uint256 public totalSupply;
    mapping(address => uint256) public supplied;
    mapping(address => uint256) public borrows;

    constructor(address _token, uint256 _cap) {
        token = IERC20Like(_token);
        supplyCap = _cap;
    }

    function mintAllowed(uint256 amount) internal view returns (bool) {
        require(totalSupply + amount <= supplyCap, "cap");
        return true;
    }

    function mint(uint256 amount) external {
        require(mintAllowed(amount), "not allowed");
        token.transferFrom(msg.sender, address(this), amount);
        supplied[msg.sender] += amount;
        totalSupply += amount;
    }

    function getCash() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function exchangeRate() public view returns (uint256) {
        uint256 cash = getCash();
        if (totalSupply == 0) return 1e18;
        return cash * 1e18 / totalSupply;
    }

    function borrow(uint256 amount) external {
        uint256 rate = exchangeRate();
        uint256 maxBorrow = supplied[msg.sender] * rate / 1e18;
        require(amount <= maxBorrow, "insufficient");
        borrows[msg.sender] += amount;
        token.transfer(msg.sender, amount);
    }
}
"""

_CAP_VARIANT = _TOKEN_IFACE + """
contract CTokenMarketFixed {
    IERC20Like public token;
    address public treasury;
    uint256 public supplyCap;
    uint256 public totalSupply;
    mapping(address => uint256) public supplied;
    mapping(address => uint256) public borrows;

    constructor(address _token, uint256 _cap) {
        token = IERC20Like(_token);
        supplyCap = _cap;
        treasury = msg.sender;
    }

    function mintAllowed(uint256 amount) internal view returns (bool) {
        require(totalSupply + amount <= supplyCap, "cap");
        return true;
    }

    function mint(uint256 amount) external {
        require(mintAllowed(amount), "not allowed");
        token.transferFrom(msg.sender, address(this), amount);
        supplied[msg.sender] += amount;
        totalSupply += amount;
    }

    function getCash() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function exchangeRate() public view returns (uint256) {
        uint256 cash = getCash();
        if (totalSupply == 0) return 1e18;
        return cash * 1e18 / totalSupply;
    }

    function borrow(uint256 amount) external {
        uint256 rate = exchangeRate();
        uint256 maxBorrow = supplied[msg.sender] * rate / 1e18;
        require(amount <= maxBorrow, "insufficient");
        borrows[msg.sender] += amount;
        token.transfer(treasury, amount);
    }
}
"""

_CAP_CLEAN = _TOKEN_IFACE + """
contract CTokenMarketClean {
    IERC20Like public token;
    uint256 public supplyCap;
    uint256 public totalSupply;
    uint256 public cash;
    mapping(address => uint256) public supplied;
    mapping(address => uint256) public borrows;

    constructor(address _token, uint256 _cap) {
        token = IERC20Like(_token);
        supplyCap = _cap;
    }

    function mintAllowed(uint256 amount) internal view returns (bool) {
        require(totalSupply + amount <= supplyCap, "cap");
        return true;
    }

    function mint(uint256 amount) external {
        require(mintAllowed(amount), "not allowed");
        token.transferFrom(msg.sender, address(this), amount);
        supplied[msg.sender] += amount;
        totalSupply += amount;
        cash += amount;
    }

    function redeem(uint256 amount) external {
        require(supplied[msg.sender] >= amount, "insufficient");
        supplied[msg.sender] -= amount;
        totalSupply -= amount;
        cash -= amount;
        token.transfer(msg.sender, amount);
    }

    function getCash() public view returns (uint256) {
        return cash;
    }

    function exchangeRate() public view returns (uint256) {
        uint256 cashValue = getCash();
        if (totalSupply == 0) return 1e18;
        return cashValue * 1e18 / totalSupply;
    }

    function borrow(uint256 amount) external {
        uint256 rate = exchangeRate();
        uint256 maxBorrow = supplied[msg.sender] * rate / 1e18;
        require(amount <= maxBorrow, "insufficient");
        borrows[msg.sender] += amount;
        token.transfer(msg.sender, amount);
    }
}
"""

VULN = {
    "cover_capacity_counts_unpaid_prior_period": _COVER_VULN,
    "user_bytes_as_call_selector": _SELECTOR_VULN,
    "permissionless_sweep_breaks_settlement_finality": _SWEEP_VULN,
    "wrapper_create_no_code_check": _WRAPPER_VULN,
    "supply_cap_bypass_direct_transfer": _CAP_VULN,
}

CLEAN = {
    "cover_capacity_counts_unpaid_prior_period": _COVER_CLEAN,
    "user_bytes_as_call_selector": _SELECTOR_CLEAN,
    "permissionless_sweep_breaks_settlement_finality": _SWEEP_CLEAN,
    "wrapper_create_no_code_check": _WRAPPER_CLEAN,
    "supply_cap_bypass_direct_transfer": _CAP_CLEAN,
}

VARIANT = {
    "cover_capacity_counts_unpaid_prior_period": _COVER_VARIANT,
    "user_bytes_as_call_selector": _SELECTOR_VARIANT,
    "permissionless_sweep_breaks_settlement_finality": _SWEEP_VARIANT,
    "wrapper_create_no_code_check": _WRAPPER_VARIANT,
    "supply_cap_bypass_direct_transfer": _CAP_VARIANT,
}

# Extra clean shapes (not the primary CLEAN control, asserted
# silent under ALL five detectors as well).
EXTRA_CLEAN = {
    # Cover capacity via SafeMath .sub(): the unpaid liability
    # IS subtracted, just spelled `.sub(unpaidPriorPeriod)`.
    "cover_capacity_sub_spelling": _TOKEN_IFACE + """
contract CoverPoolSubClean {
    IERC20Like public token;
    uint256 public totalCollateral;
    uint256 public unpaidPriorPeriod;
    uint256 public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function availableCover() public view returns (uint256) {
        return totalCollateral.sub(claimed).sub(unpaidPriorPeriod);
    }

    function claim(uint256 amount) external {
        uint256 cover = availableCover();
        require(amount <= cover, "exceeds cover");
        claimed += amount;
        token.transfer(msg.sender, amount);
    }
}
""",
    # Selector from an interface .selector: a fixed, known
    # function - not caller-controlled.
    "selector_interface_selector": _TOKEN_IFACE + """
interface IVerifier {
    function verify(bytes calldata proof) external returns (bytes32);
}

contract ZkVerifierSelectorClean {
    IERC20Like public token;
    address public verifier;
    bytes32 public stateRoot;

    constructor(address _token, address _verifier) {
        token = IERC20Like(_token);
        verifier = _verifier;
    }

    function verifyProof(bytes calldata proof, uint256 amount) external {
        (bool ok, bytes memory ret) = verifier.call(abi.encodeWithSelector(IVerifier.verify.selector, proof));
        require(ok, "verify failed");
        stateRoot = bytes32(ret);
        token.transfer(msg.sender, amount);
    }
}
""",
    # Selector from keccak256 of a constant string: still a
    # constant selector, not caller-controlled.
    "selector_keccak_constant": _TOKEN_IFACE + """
contract ZkVerifierKeccakClean {
    IERC20Like public token;
    address public verifier;
    bytes32 public stateRoot;

    constructor(address _token, address _verifier) {
        token = IERC20Like(_token);
        verifier = _verifier;
    }

    function verifyProof(bytes calldata proof, uint256 amount) external {
        (bool ok, bytes memory ret) = verifier.call(abi.encodePacked(bytes4(keccak256("verifyProof(bytes)")), proof));
        require(ok, "verify failed");
        stateRoot = bytes32(ret);
        token.transfer(msg.sender, amount);
    }
}
""",
    # Sweep gated to the owner: a stranger cannot reach it.
    "sweep_only_owner": _TOKEN_IFACE + """
contract BattlePoolOwnerClean {
    IERC20Like public token;
    bool public claimsStarted;
    uint256 public totalStaked;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claim(uint256 amount) external {
        claimsStarted = true;
        token.transfer(msg.sender, amount);
    }

    function sweepUnclaimedBonus() external onlyOwner {
        uint256 bonus = token.balanceOf(address(this)) / 10;
        token.transfer(msg.sender, bonus);
    }

    function reflagSettlement() external {
        uint256 remaining = token.balanceOf(address(this));
        totalStaked = remaining;
    }
}
""",
    # Wrapper creation with a token.code.length check.
    "wrapper_code_length_check": _TOKEN_IFACE + """
contract ERC223Wrapper {
    address public token;

    constructor(address _token) {
        token = _token;
    }
}

contract WrapperFactoryCodeLengthClean {
    IERC20Like public token;
    address public deployer;
    mapping(address => address) public wrappers;

    constructor() {
        deployer = msg.sender;
    }

    function createERC223Wrapper(address token) external payable returns (address wrapper) {
        require(token.code.length > 0, "not a contract");
        uint256 fee = 0.01 ether;
        require(msg.value >= fee, "fee");
        wrapper = address(new ERC223Wrapper(token));
        wrappers[token] = wrapper;
        payable(msg.sender).transfer(msg.value - fee);
        return wrapper;
    }
}
""",
    # Borrow path enforces the cap too: the cap is compared in
    # borrow, so a direct transfer cannot inflate past it.
    "cap_checked_in_borrow": _TOKEN_IFACE + """
contract CTokenMarketBorrowCapClean {
    IERC20Like public token;
    uint256 public supplyCap;
    uint256 public totalSupply;
    mapping(address => uint256) public supplied;
    mapping(address => uint256) public borrows;

    constructor(address _token, uint256 _cap) {
        token = IERC20Like(_token);
        supplyCap = _cap;
    }

    function mintAllowed(uint256 amount) internal view returns (bool) {
        require(totalSupply + amount <= supplyCap, "cap");
        return true;
    }

    function mint(uint256 amount) external {
        require(mintAllowed(amount), "not allowed");
        token.transferFrom(msg.sender, address(this), amount);
        supplied[msg.sender] += amount;
        totalSupply += amount;
    }

    function getCash() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function exchangeRate() public view returns (uint256) {
        uint256 cash = getCash();
        if (totalSupply == 0) return 1e18;
        return cash * 1e18 / totalSupply;
    }

    function borrow(uint256 amount) external {
        require(totalSupply + amount <= supplyCap, "cap");
        uint256 rate = exchangeRate();
        uint256 maxBorrow = supplied[msg.sender] * rate / 1e18;
        require(amount <= maxBorrow, "insufficient");
        borrows[msg.sender] += amount;
        token.transfer(msg.sender, amount);
    }
}
""",
}
