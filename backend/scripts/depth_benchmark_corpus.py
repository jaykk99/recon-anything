"""Benchmark corpus for the ReconAnything plugin-depth upgrade.

Ground truth, labeled by hand. Every source case states:
  - source: Solidity source (bundled cases use the flattened
    `// ==== path ====` file markers the analyzers understand),
  - contract_name: the deployed target's verified name,
  - function: the flagged function a detector would report,
  - expect_detector_candidate: True when SOME money-path analyzer
    must produce a candidate-grade finding on that function
    (severity high/critical, not trigger-only); False when none
    may (trigger-only at most),
  - expect_validator: the auto-validator verdict given the live
    evidence in `evidence` (probe outcome + balances a gathering
    lane would honestly read for this ground truth), or None when
    the validator layer is not scored for the case,
  - expect_recipient: CALLER / CALLER-SUPPLIED / FIXED /
    HOLDER-SELF where the case turns on classification,
  - gap: which Step-2 gap the case discriminates (1 attribution,
    2 guard path tracing, 3 bytecode), or None for controls.

Bytecode cases are assembled with the tiny assembler below so the
dispatcher / selector layout is exact, and state per-selector
capability expectations.
"""

# ---------------------------------------------------------------------------
# Vulnerable fixtures
# ---------------------------------------------------------------------------

VULN_WITHDRAW_CALLER = """
contract VulnVault {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdrawAll() public {
        uint256 amt = address(this).balance;
        payable(msg.sender).transfer(amt);
    }
}
"""

VULN_WITHDRAW_PARAM = """
contract VulnWithdrawParam {
    function withdrawTo(address to, uint256 amount) public {
        payable(to).transfer(amount);
    }
    receive() external payable {}
}
"""

VULN_MINT_SUPPLIED = """
contract VulnMint {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

VULN_RESCUE_PARAM = """
interface IERC20 { function transfer(address to, uint256 amt) external returns (bool); function balanceOf(address a) external view returns (uint256); }
contract VulnRescue {
    function rescueTokens(address token, address to) public {
        uint256 bal = IERC20(token).balanceOf(address(this));
        IERC20(token).transfer(to, bal);
    }
}
"""

VULN_CLAIM_REPEAT = """
contract VulnClaim {
    mapping(address => uint256) public entitlement;
    function claim() public {
        uint256 amt = entitlement[msg.sender];
        require(amt > 0, "nothing to claim");
        payable(msg.sender).transfer(amt);
    }
    receive() external payable {}
}
"""

VULN_REENTRANCY_CEI = """
contract VulnReentrant {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdrawBalance() public {
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}
"""

VULN_REENTRANCY_HELPER_SPLIT = """
contract VulnReentrantSplit {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        _sendOut(amt);
        balances[msg.sender] = 0;
    }
    function _sendOut(uint256 amt) internal {
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
    }
}
"""

VULN_INITIALIZE = """
contract VulnInit {
    address public owner;
    bool public initialized;
    function initialize() public {
        owner = msg.sender;
        initialized = true;
    }
    function sweep() public {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }
    receive() external payable {}
}
"""

VULN_VAULT_INFLATION = """
interface IERC20 { function transfer(address to, uint256 amt) external returns (bool); function transferFrom(address f, address t, uint256 amt) external returns (bool); function balanceOf(address a) external view returns (uint256); }
contract VulnVault4626 {
    IERC20 public asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    constructor(address _asset) { asset = IERC20(_asset); }
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? assets : (assets * supply) / totalAssets();
    }
    function deposit(uint256 assets) public returns (uint256 shares) {
        shares = convertToShares(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }
    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? shares : (shares * totalAssets()) / supply;
    }
    function redeem(uint256 shares) public returns (uint256 assets) {
        assets = convertToAssets(shares);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        asset.transfer(msg.sender, assets);
    }
}
"""

VULN_SPOT_ORACLE = """
interface IPair { function getReserves() external view returns (uint112 r0, uint112 r1, uint32 ts); }
contract VulnOracleBorrow {
    IPair public pair;
    mapping(address => uint256) public borrowed;
    constructor(address _pair) { pair = IPair(_pair); }
    function borrow(uint256 collateralTokens) public {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 price = (uint256(r1) * 1e18) / uint256(r0);
        uint256 amount = (collateralTokens * price) / 1e18;
        borrowed[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

VULN_SPOT_ORACLE_MINT = """
interface IPair { function getReserves() external view returns (uint112 r0, uint112 r1, uint32 ts); }
contract VulnSpotMint {
    IPair public pair;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    constructor(address _pair) { pair = IPair(_pair); }
    function mint(uint256 collateralTokens) public {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 price = (uint256(r1) * 1e18) / uint256(r0);
        uint256 amount = (collateralTokens * price) / 1e18;
        totalSupply += amount;
        balanceOf[msg.sender] += amount;
    }
}
"""

VULN_SPOT_ORACLE_REDEEM = """
interface IPair { function getReserves() external view returns (uint112 r0, uint112 r1, uint32 ts); }
contract VulnSpotRedeem {
    IPair public pair;
    mapping(address => uint256) public shares;
    constructor(address _pair) { pair = IPair(_pair); }
    function redeem(uint256 shareAmount, address to) public {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        uint256 price = (uint256(r1) * 1e18) / uint256(r0);
        uint256 amount = (shareAmount * price) / 1e18;
        shares[msg.sender] -= shareAmount;
        payable(to).transfer(amount);
    }
    receive() external payable {}
}
"""

VULN_HELPER_RECIPIENT = """
contract VulnHelperPay {
    function withdraw(uint256 amount) public {
        _payout(amount);
    }
    function _payout(uint256 amount) internal {
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

# Bundled compilation: the deployed target is the Proxy; the flagged
# function lives in the implementation contract bundled alongside it.
VULN_BUNDLED_IMPL = """
// ==== contracts/Proxy.sol ====
contract Proxy {
    address public implementation;
    address public admin;
    constructor(address _impl) { implementation = _impl; admin = msg.sender; }
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
    receive() external payable {}
}
// ==== contracts/Impl.sol ====
contract Impl {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function withdrawTo(address to, uint256 amount) public {
        payable(to).transfer(amount);
    }
    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
    receive() external payable {}
}
"""

VULN_DELEGATECALL_PARAM = """
contract VulnExec {
    function execute(address target, bytes memory data) public returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}
"""

VULN_BRIDGE_RELEASE = """
interface IERC20 { function transfer(address to, uint256 amt) external returns (bool); }
contract VulnBridge {
    IERC20 public token;
    uint256 public nonce;
    mapping(uint256 => bool) public processed;
    constructor(address _token) { token = IERC20(_token); }
    function release(address to, uint256 amount) public {
        token.transfer(to, amount);
    }
}
"""

VULN_SIG_SELF = """
contract VulnSigClaim {
    function claimWithSig(uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, amount));
        address signer = ecrecover(h, v, r, s);
        require(signer != address(0), "bad sig");
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

# ---------------------------------------------------------------------------
# Clean fixtures (no candidate-grade finding may fire)
# ---------------------------------------------------------------------------

CLEAN_WITHDRAW_OWNER = """
contract CleanOwnerVault {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    function withdrawAll() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
    receive() external payable {}
}
"""

CLEAN_ENTITLED_WITHDRAW = """
contract CleanEntitled {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
"""

CLEAN_CEI_CORRECT = """
contract CleanCei {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdrawBalance() public {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
    }
}
"""

CLEAN_REENTRANCY_NONREENTRANT = """
contract CleanGuarded {
    mapping(address => uint256) public balances;
    bool internal _locked;
    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdrawBalance() public nonReentrant {
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}
"""

CLEAN_REENTRANCY_CUSTOM_LOCK = """
contract CleanCustomLock {
    mapping(address => uint256) public balances;
    uint256 private _status;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdrawBalance() public {
        require(_status == 0, "locked");
        _status = 1;
        uint256 amt = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
        _status = 0;
    }
}
"""

CLEAN_VAULT_OFFSET = """
interface IERC20 { function transfer(address to, uint256 amt) external returns (bool); function transferFrom(address f, address t, uint256 amt) external returns (bool); function balanceOf(address a) external view returns (uint256); }
contract CleanVault4626 {
    IERC20 public asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    constructor(address _asset) { asset = IERC20(_asset); }
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }
    function convertToShares(uint256 assets) public view returns (uint256) {
        return (assets * (totalSupply + 1000)) / (totalAssets() + 1);
    }
    function deposit(uint256 assets) public returns (uint256 shares) {
        shares = convertToShares(assets);
        require(shares > 0, "zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return (shares * (totalAssets() + 1)) / (totalSupply + 1000);
    }
    function redeem(uint256 shares) public returns (uint256 assets) {
        assets = convertToAssets(shares);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        asset.transfer(msg.sender, assets);
    }
}
"""

CLEAN_ORACLE_TWAP = """
interface IOracle { function observe(uint32 secondsAgo) external view returns (int56[] memory tickCumulatives); }
contract CleanTwapBorrow {
    IOracle public oracle;
    mapping(address => uint256) public borrowed;
    constructor(address _oracle) { oracle = IOracle(_oracle); }
    function borrow(uint256 collateralTokens) public {
        int56[] memory ticks = oracle.observe(3600);
        uint256 price = uint256(int256(ticks[1] - ticks[0]) / 3600) + 1e18;
        uint256 amount = (collateralTokens * price) / 1e18;
        borrowed[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

CLEAN_ORACLE_CHAINLINK = """
interface AggregatorV3Interface { function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound); }
contract CleanChainlinkBorrow {
    AggregatorV3Interface public feed;
    mapping(address => uint256) public borrowed;
    constructor(address _feed) { feed = AggregatorV3Interface(_feed); }
    function borrow(uint256 collateralTokens) public {
        (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
        require(answer > 0, "bad price");
        require(block.timestamp - updatedAt < 3600, "stale price");
        uint256 price = uint256(answer);
        uint256 amount = (collateralTokens * price) / 1e8;
        borrowed[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }
    receive() external payable {}
}
"""

CLEAN_SPOT_DISPLAY = """
interface IPair { function getReserves() external view returns (uint112 r0, uint112 r1, uint32 ts); }
contract CleanSpotDisplay {
    IPair public pair;
    constructor(address _pair) { pair = IPair(_pair); }
    function spotPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return (uint256(r1) * 1e18) / uint256(r0);
    }
    function quote(uint256 collateralTokens) public view returns (uint256) {
        return (collateralTokens * spotPrice()) / 1e18;
    }
}
"""

CLEAN_MINT_ROLE = """
contract CleanRoleMint {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public minters;
    constructor() { owner = msg.sender; }
    modifier onlyMinter() { require(minters[msg.sender], "not minter"); _; }
    function mint(address to, uint256 amount) public onlyMinter {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

CLEAN_CLAIM_CONSUMED = """
contract CleanClaim {
    mapping(address => uint256) public entitlement;
    function claim() public {
        uint256 amt = entitlement[msg.sender];
        require(amt > 0, "nothing to claim");
        entitlement[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
    receive() external payable {}
}
"""

CLEAN_GUARD_HELPER_AUTH = """
contract CleanHelperAuth {
    address public owner;
    constructor() { owner = msg.sender; }
    function _authorize() internal view {
        require(msg.sender == owner, "not owner");
    }
    function withdrawTo(address to, uint256 amount) public {
        _authorize();
        payable(to).transfer(amount);
    }
    receive() external payable {}
}
"""

CLEAN_GUARD_MODIFIER_ANCESTOR = """
// ==== contracts/Base.sol ====
contract Base {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
}
// ==== contracts/Vault.sol ====
contract Vault is Base {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) public onlyOwner {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
}
"""

# The DepositHandler mirror (hunt, Nov 5): the deployed target is the
# token; the alarming functions live in a bundled SIBLING contract.
CLEAN_SIBLING = """
// ==== contracts/Token.sol ====
contract Token {
    address public owner;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    function mint(address to, uint256 amount) public onlyOwner {
        totalSupply += amount;
        balanceOf[to] += amount;
    }
    function depositAddress(bytes32 salt) public pure returns (address) {
        return address(uint160(uint256(salt)));
    }
}
// ==== contracts/DepositHandler.sol ====
contract DepositHandler {
    bool private locked;
    modifier noReenter() { require(!locked, "reentrant"); locked = true; _; locked = false; }
    function execute(address callee, bytes memory data) public noReenter {
        (bool ok, ) = callee.call(data);
        require(ok, "call failed");
    }
    function destroy(address etherDestination) public noReenter {
        selfdestruct(payable(etherDestination));
    }
}
"""

CLEAN_PROXY_ADMIN = """
contract CleanProxy {
    address private _implementation;
    address private _admin;
    constructor(address impl) { _implementation = impl; _admin = msg.sender; }
    function upgradeTo(address newImpl) public {
        if (msg.sender != _admin) { revert("not admin"); }
        _implementation = newImpl;
    }
    fallback() external payable {
        address impl = _implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
    receive() external payable {}
}
"""

CLEAN_RESCUE_FIXED = """
contract CleanRescueFixed {
    address public constant TREASURY = 0x1111111111111111111111111111111111111111;
    function rescue() public {
        payable(TREASURY).transfer(address(this).balance);
    }
    receive() external payable {}
}
"""

# ---------------------------------------------------------------------------
# Case manifest
# ---------------------------------------------------------------------------

def V(id, source, contract_name, function, recipient=None,
      validator=None, probe="success", balances=None, gap=None,
      note="", function_match="exact"):
    return {"id": id, "source": source,
            "contract_name": contract_name, "function": function,
            "expect_detector_candidate": True,
            "expect_recipient": recipient,
            "expect_validator": validator,
            "evidence": {"probe": probe, "balances": balances or {}},
            "gap": gap, "note": note,
            "function_match": function_match}


def C(id, source, contract_name, function, recipient=None,
      validator=None, probe="success", balances=None, gap=None,
      note="", function_match="exact"):
    d = V(id, source, contract_name, function, recipient,
          validator, probe, balances, gap, note, function_match)
    d["expect_detector_candidate"] = False
    return d


_NATIVE = {"native_wei": 10 ** 18}
_TOKEN = {"token_self_wei": 10 ** 21}
_MINTVAL = {"token_pair_reserves": {"reserve0": 10 ** 20,
                                   "reserve1": 10 ** 18}}

SOURCE_CASES = [
    V("vuln_withdraw_caller", VULN_WITHDRAW_CALLER, "VulnVault",
      "withdrawAll", recipient="CALLER", validator="VERIFIED_REAL",
      balances=_NATIVE),
    V("vuln_withdraw_param", VULN_WITHDRAW_PARAM,
      "VulnWithdrawParam", "withdrawTo",
      recipient="CALLER-SUPPLIED", validator="VERIFIED_REAL",
      balances=_NATIVE),
    V("vuln_mint_supplied", VULN_MINT_SUPPLIED, "VulnMint", "mint",
      recipient="CALLER-SUPPLIED", validator="VERIFIED_REAL",
      balances=_MINTVAL),
    V("vuln_rescue_param", VULN_RESCUE_PARAM, "VulnRescue",
      "rescueTokens", recipient="CALLER-SUPPLIED",
      validator="VERIFIED_REAL", balances=_TOKEN),
    V("vuln_claim_repeat", VULN_CLAIM_REPEAT, "VulnClaim", "claim",
      recipient="CALLER", validator="VERIFIED_REAL",
      balances=_NATIVE),
    V("vuln_reentrancy_cei", VULN_REENTRANCY_CEI, "VulnReentrant",
      "withdrawBalance"),
    V("vuln_reentrancy_helper_split", VULN_REENTRANCY_HELPER_SPLIT,
      "VulnReentrantSplit", "withdraw", gap=2,
      note="external call lives in the internal helper; the state "
           "write sits in the entry after the helper call"),
    V("vuln_initialize", VULN_INITIALIZE, "VulnInit", "initialize"),
    V("vuln_vault_inflation", VULN_VAULT_INFLATION,
      "VulnVault4626", "deposit", function_match="any"),
    V("vuln_spot_oracle", VULN_SPOT_ORACLE, "VulnOracleBorrow",
      "borrow", function_match="any",
      note="payout priced off pair.getReserves() spot"),
    V("vuln_spot_oracle_mint", VULN_SPOT_ORACLE_MINT,
      "VulnSpotMint", "mint", recipient="CALLER",
      note="mint amount priced off pair.getReserves() spot"),
    V("vuln_spot_oracle_redeem", VULN_SPOT_ORACLE_REDEEM,
      "VulnSpotRedeem", "redeem", recipient="CALLER-SUPPLIED",
      note="redeem payout to a caller-supplied address, priced "
           "off pair.getReserves() spot"),
    V("vuln_helper_recipient", VULN_HELPER_RECIPIENT,
      "VulnHelperPay", "withdraw", recipient="CALLER",
      validator="VERIFIED_REAL", balances=_NATIVE, gap=1,
      note="entry body has no destination at all; the transfer "
           "to msg.sender lives in the internal helper"),
    V("vuln_bundled_impl", VULN_BUNDLED_IMPL, "Proxy",
      "withdrawTo", recipient="CALLER-SUPPLIED",
      validator="VERIFIED_REAL", balances=_NATIVE, gap=1,
      note="flagged function exists only in the bundled "
           "implementation contract; target scope is the proxy"),
    V("vuln_delegatecall_param", VULN_DELEGATECALL_PARAM,
      "VulnExec", "execute"),
    V("vuln_bridge_release", VULN_BRIDGE_RELEASE, "VulnBridge",
      "release", recipient="CALLER-SUPPLIED",
      validator="VERIFIED_REAL", balances=_TOKEN),
    V("vuln_sig_self", VULN_SIG_SELF, "VulnSigClaim",
      "claimWithSig", recipient="CALLER",
      validator="VERIFIED_REAL", balances=_NATIVE, gap=2,
      note="ecrecover present but the recovered signer is never "
           "compared to a stored authority; the generic gate read "
           "counts bare ecrecover as a gate"),
    C("clean_withdraw_owner", CLEAN_WITHDRAW_OWNER,
      "CleanOwnerVault", "withdrawAll", recipient="FIXED"),
    C("clean_entitled_withdraw", CLEAN_ENTITLED_WITHDRAW,
      "CleanEntitled", "withdraw", recipient="HOLDER-SELF",
      validator="TRIGGER_ONLY", balances=_NATIVE),
    C("clean_cei_correct", CLEAN_CEI_CORRECT, "CleanCei",
      "withdrawBalance"),
    C("clean_reentrancy_nonreentrant", CLEAN_REENTRANCY_NONREENTRANT,
      "CleanGuarded", "withdrawBalance"),
    C("clean_reentrancy_custom_lock", CLEAN_REENTRANCY_CUSTOM_LOCK,
      "CleanCustomLock", "withdrawBalance", gap=2,
      note="reentrancy guard is a hand-rolled storage lock, not "
           "the nonReentrant keyword"),
    C("clean_vault_offset", CLEAN_VAULT_OFFSET, "CleanVault4626",
      "deposit", function_match="any"),
    C("clean_oracle_twap", CLEAN_ORACLE_TWAP, "CleanTwapBorrow",
      "borrow", function_match="any"),
    C("clean_oracle_chainlink", CLEAN_ORACLE_CHAINLINK,
      "CleanChainlinkBorrow", "borrow", function_match="any",
      note="payout priced off a Chainlink latestRoundData feed "
           "with a staleness check, not off spot reserves"),
    C("clean_spot_display", CLEAN_SPOT_DISPLAY, "CleanSpotDisplay",
      "spotPrice", function_match="any",
      note="spot reserves read only for a display/quote getter; "
           "no value-out is sized from the price"),
    C("clean_mint_role", CLEAN_MINT_ROLE, "CleanRoleMint", "mint"),
    C("clean_claim_consumed", CLEAN_CLAIM_CONSUMED, "CleanClaim",
      "claim", recipient="HOLDER-SELF"),
    C("clean_guard_helper_auth", CLEAN_GUARD_HELPER_AUTH,
      "CleanHelperAuth", "withdrawTo"),
    C("clean_guard_modifier_ancestor", CLEAN_GUARD_MODIFIER_ANCESTOR,
      "Vault", "mint"),
    C("clean_sibling_deposithandler", CLEAN_SIBLING, "Token",
      "execute", validator="FALSE_POSITIVE", probe="revert",
      gap=1,
      note="the hunt's DepositHandler case: flagged function "
           "exists only in a bundled sibling; the deployed "
           "contract does not expose it and the probe reverts. "
           "Fed to the validator WITHOUT function_out_of_scope, "
           "exactly as the backlog lane fed it"),
    C("clean_proxy_admin", CLEAN_PROXY_ADMIN, "CleanProxy",
      "upgradeTo"),
    C("clean_rescue_fixed", CLEAN_RESCUE_FIXED, "CleanRescueFixed",
      "rescue", recipient="FIXED", validator="TRIGGER_ONLY",
      balances=_NATIVE),
]

# ---------------------------------------------------------------------------
# Tiny EVM assembler (runtime code only) for bytecode fixtures
# ---------------------------------------------------------------------------

_OPS = {"STOP": 0x00, "BALANCE": 0x31, "ADDRESS": 0x30,
        "CALLER": 0x33, "CALLVALUE": 0x34, "CALLDATALOAD": 0x35,
        "CALLDATASIZE": 0x36, "POP": 0x50, "SLOAD": 0x54,
        "SSTORE": 0x55, "JUMP": 0x56, "JUMPI": 0x57,
        "JUMPDEST": 0x5B, "SHR": 0x1C, "EQ": 0x14, "DUP1": 0x80,
        "SWAP1": 0x90, "RETURN": 0xF3, "CALL": 0xF1,
        "DELEGATECALL": 0xF4, "REVERT": 0xFD,
        "SELFDESTRUCT": 0xFF}


def _push(value):
    if isinstance(value, (bytes, bytearray)):
        data = bytes(value)
    else:
        n = max(1, (int(value).bit_length() + 7) // 8)
        data = int(value).to_bytes(n, "big")
    return bytes([0x5F + len(data)]) + data


def assemble(items):
    """items: ('label', name) | ('op', NAME) | ('push', value) |
    ('pushlabel', name). Labels resolve to PUSH2 offsets."""
    sizes = []
    for kind, val in items:
        if kind == "label":
            sizes.append(1)          # the JUMPDEST byte itself
        elif kind == "op":
            sizes.append(1)
        elif kind == "push":
            sizes.append(len(_push(val)))
        elif kind == "pushlabel":
            sizes.append(3)
        else:
            raise ValueError(kind)
    labels, off = {}, 0
    for (kind, val), size in zip(items, sizes):
        if kind == "label":
            labels[val] = off
        off += size
    out = bytearray()
    for (kind, val), size in zip(items, sizes):
        if kind == "label":
            out.append(_OPS["JUMPDEST"])
        elif kind == "op":
            out.append(_OPS[val])
        elif kind == "push":
            out += _push(val)
        elif kind == "pushlabel":
            out += bytes([0x61]) + labels[val].to_bytes(2, "big")
    return "0x" + bytes(out).hex()


def _dispatcher(routes):
    """routes: [(selector_bytes4, label)] — standard selector
    dispatcher falling through to REVERT."""
    items = [("push", 0), ("op", "CALLDATALOAD"),
             ("push", 0xE0), ("op", "SHR")]
    for sel, label in routes:
        items += [("op", "DUP1"), ("push", sel), ("op", "EQ"),
                  ("pushlabel", label), ("op", "JUMPI")]
    items += [("push", 0), ("push", 0), ("op", "REVERT")]
    return items


# kill() -> SELFDESTRUCT(caller); store() -> benign SSTORE routine.
def _bc_selfdestruct(keccak256):
    sel_kill = keccak256(b"kill()")[:4]
    sel_store = keccak256(b"store()")[:4]
    items = _dispatcher([(sel_kill, "kill"), (sel_store, "store")])
    items += [("label", "kill"), ("op", "CALLER"),
              ("op", "SELFDESTRUCT")]
    items += [("label", "store"), ("push", 0x2A), ("push", 0),
              ("op", "SSTORE"), ("op", "STOP")]
    return assemble(items), {"0x" + sel_kill.hex(): ["SELFDESTRUCT"],
                             "0x" + sel_store.hex(): []}


# execute(address,bytes) -> DELEGATECALL to the calldata address;
# withdraw(uint256) -> CALL paying the caller the contract balance.
def _bc_delegatecall(keccak256):
    sel_exec = keccak256(b"execute(address,bytes)")[:4]
    sel_wd = keccak256(b"withdraw(uint256)")[:4]
    items = _dispatcher([(sel_exec, "exec"), (sel_wd, "wd")])
    # DELEGATECALL(gas, to, in_off, in_size, out_off, out_size);
    # to = calldata word at offset 4.
    items += [("label", "exec"),
              ("push", 0), ("push", 0), ("push", 0x40),
              ("push", 0x24), ("push", 4), ("op", "CALLDATALOAD"),
              ("push", 0xFFFF), ("op", "DELEGATECALL"),
              ("op", "POP"), ("op", "STOP")]
    # CALL(gas, to, value, in_off, in_size, out_off, out_size)
    items += [("label", "wd"),
              ("push", 0), ("push", 0), ("push", 0), ("push", 0),
              ("op", "ADDRESS"), ("op", "BALANCE"),
              ("op", "CALLER"), ("push", 0xFFFF), ("op", "CALL"),
              ("op", "POP"), ("op", "STOP")]
    return assemble(items), {
        "0x" + sel_exec.hex(): ["DELEGATECALL"],
        "0x" + sel_wd.hex(): ["CALL"]}


def _bc_benign(keccak256):
    sel_get = keccak256(b"get()")[:4]
    sel_set = keccak256(b"set(uint256)")[:4]
    items = _dispatcher([(sel_get, "get"), (sel_set, "set")])
    items += [("label", "get"), ("push", 0), ("op", "SLOAD"),
              ("push", 0), ("push", 0), ("op", "RETURN")]
    items += [("label", "set"), ("push", 4),
              ("op", "CALLDATALOAD"), ("push", 0), ("op", "SSTORE"),
              ("op", "STOP")]
    return assemble(items), {}


_IMPL = "0x1111111111111111111111111111111111111111"
_MINIMAL_PROXY_HEX = (
    "0x363d3d373d3d3d363d73" +
    _IMPL[2:] +
    "5af43d82803e903d91602b57fd5bf3")


def build_bytecode_cases(keccak256):
    sd_hex, sd_map = _bc_selfdestruct(keccak256)
    dc_hex, dc_map = _bc_delegatecall(keccak256)
    bn_hex, _ = _bc_benign(keccak256)
    return [
        {"id": "bc_selfdestruct", "hex": sd_hex,
         "expect_capability": True, "expect_attribution": True,
         "selector_capabilities": sd_map, "expect_proxy": None,
         "note": "one selector reaches SELFDESTRUCT, the other "
                 "is a benign store routine"},
        {"id": "bc_delegatecall_call", "hex": dc_hex,
         "expect_capability": True, "expect_attribution": True,
         "selector_capabilities": dc_map, "expect_proxy": None,
         "note": "execute() reaches DELEGATECALL on a "
                 "caller-supplied target; withdraw() reaches CALL "
                 "paying the caller"},
        {"id": "bc_minimal_proxy", "hex": _MINIMAL_PROXY_HEX,
         "expect_capability": True, "expect_attribution": True,
         "selector_capabilities": {}, "expect_proxy": _IMPL,
         "note": "EIP-1167 minimal proxy: every call delegates "
                 "to the implementation"},
        {"id": "bc_benign", "hex": bn_hex,
         "expect_capability": False, "expect_attribution": False,
         "selector_capabilities": {}, "expect_proxy": None,
         "note": "storage-only contract: no risky opcode may "
                 "be reported"},
    ]


# Populated by score.py, which imports keccak256 from the backend
# under test (app.plugins.cryptopack_util).
BYTECODE_CASES = []
