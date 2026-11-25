"""Fixtures for the deep-audit batch-29 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" (the four
recipient detectors: relay, hook, swap helper, governance);
the duplicate-reward detector fires trigger-only at medium
severity with recipient HOLDER-SELF (user-harm / insolvency
class, NOT stranger-receivable - the duplicated player loses
their earlier reward). CLEAN[id] (the protected shape of the
same class) MUST stay silent under ALL five detectors;
VARIANT[id] carries the same vulnerable shape but behind an
owner gate, so it MUST fire with report_class "trigger_only"
at low severity - never a candidate (no variant for the
duplicate-reward detector: it carries no caller gate at all,
its VULN already fires trigger-only).

Cross-talk by construction: the relay fixture relays a call
and trusts the arbitrator but names no swap / settle /
execute / hook / PoolKey / quorum function, verifies no
signature, and carries no digest at all; the hook fixture
pays a rebate from afterSwap but names no relay / swap /
quorum function, burns nothing from a pair, never syncs a
pair, and never takes from a shared delta; the swap-helper
fixture routes through a caller-supplied PoolKey but makes
no raw .call( to a caller target anywhere and carries no
standing approvals; the governance fixture executes a
proposal call but names no relay / hook / swap function,
carries no totalSupply() call, and HAS a state check
(Succeeded) and an eta check - the ONLY missing piece is
quorum; the pot fixture assigns rewards in its constructor
and claims them but names no relay / hook / swap / quorum
function, carries no pending / earned balance, zeroes the
recorded reward before paying, defines no transfer function
and has no cancel path. The relay and pot fixtures never
use the word "bridge" in their source (the deposit-event
spoofing detector keys on it); the hook and swap-helper
fixtures never use the word "reserve"; the governance
fixture never uses "threshold" / "owners" / "expiry" /
"totalSupply" / "allowance" in its source.

DOCUMENTED CO-FIRE: recipient_unbacked_claim fires on the
relay VULN fixture by design - claimMessage moves value
through a generic call with no entitlement backing it, which
is the same hole from the claim angle; the new detector adds
the trusted-identity dimension the claim detector cannot
express (the call executes as the relayer). The old detector
also fires on the relay CLEAN / digest-verified / fixed-target
fixtures, which is its own over-breadth on claim-named
generic-call functions (it does not model allowlists or
digest checks); the new detector correctly stays silent
there. That co-fire is pinned explicitly in the test, not
pretended silent.
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

# ---------------------------------------------------------------------------
# 1. relay_arbitrary_call_trusted_identity
# ---------------------------------------------------------------------------

_RELAY_VULN = """
contract Arbitrator {
    address public gateway;

    constructor(address _gateway) {
        gateway = _gateway;
    }

    function claimMessage(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}

contract Gateway {
    address public arbitrator;
    bytes32 public batchRoot;

    constructor(address _arbitrator) {
        arbitrator = _arbitrator;
    }

    function syncBatchRoot(bytes32 root) external {
        require(msg.sender == arbitrator, "not arbitrator");
        batchRoot = root;
    }
}
"""

# The relay target is allowlisted: the protected shape.
_RELAY_CLEAN = """
contract Arbitrator {
    address public gateway;
    mapping(address => bool) public allowedTargets;

    constructor(address _gateway) {
        gateway = _gateway;
    }

    function setAllowedTarget(address target, bool allowed) external {
        allowedTargets[target] = allowed;
    }

    function claimMessage(address target, bytes calldata data) external {
        require(allowedTargets[target], "target not allowed");
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}

contract Gateway {
    address public arbitrator;
    bytes32 public batchRoot;

    constructor(address _arbitrator) {
        arbitrator = _arbitrator;
    }

    function syncBatchRoot(bytes32 root) external {
        require(msg.sender == arbitrator, "not arbitrator");
        batchRoot = root;
    }
}
"""

# Owner-gated relay: same shape, trigger-only.
_RELAY_VARIANT = """
contract Arbitrator {
    address public gateway;
    address public owner;

    constructor(address _gateway, address _owner) {
        gateway = _gateway;
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function claimMessage(address target, bytes calldata data) external onlyOwner {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}

contract Gateway {
    address public arbitrator;
    bytes32 public batchRoot;

    constructor(address _arbitrator) {
        arbitrator = _arbitrator;
    }

    function syncBatchRoot(bytes32 root) external {
        require(msg.sender == arbitrator, "not arbitrator");
        batchRoot = root;
    }
}
"""

# The message content is verified against a verified digest.
_RELAY_DIGEST = """
contract Arbitrator {
    address public gateway;
    mapping(bytes32 => bool) public verifiedDigests;

    constructor(address _gateway) {
        gateway = _gateway;
    }

    function claimMessage(address target, bytes calldata data) external {
        bytes32 digest = keccak256(abi.encodePacked(target, data));
        require(verifiedDigests[digest], "digest not verified");
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
    }
}

contract Gateway {
    address public arbitrator;
    bytes32 public batchRoot;

    constructor(address _arbitrator) {
        arbitrator = _arbitrator;
    }

    function syncBatchRoot(bytes32 root) external {
        require(msg.sender == arbitrator, "not arbitrator");
        batchRoot = root;
    }
}
"""

# The relay only ever calls a stored router: no caller target.
_RELAY_FIXED_TARGET = """
contract Arbitrator {
    address public gateway;
    address public router;

    constructor(address _gateway, address _router) {
        gateway = _gateway;
        router = _router;
    }

    function claimMessage(bytes calldata data) external {
        (bool ok, ) = router.call(data);
        require(ok, "call failed");
    }
}

contract Gateway {
    address public arbitrator;
    bytes32 public batchRoot;

    constructor(address _arbitrator) {
        arbitrator = _arbitrator;
    }

    function syncBatchRoot(bytes32 root) external {
        require(msg.sender == arbitrator, "not arbitrator");
        batchRoot = root;
    }
}
"""

# ---------------------------------------------------------------------------
# 2. v4_hook_callback_no_poolmanager_check
# ---------------------------------------------------------------------------

_HOOK_TYPES = """
struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

struct SwapParams {
    bool zeroForOne;
    int256 amountSpecified;
    uint160 sqrtPriceLimitX96;
}

struct BalanceDelta {
    int256 amount0;
    int256 amount1;
}
"""

_HOOK_VULN = _TOKEN_IFACE + _HOOK_TYPES + """
contract RebateHookVuln {
    IERC20Like public token;
    address public poolManager;
    mapping(address => uint256) public rebates;

    constructor(address _token, address _poolManager) {
        token = IERC20Like(_token);
        poolManager = _poolManager;
    }

    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external returns (bytes4, int128) {
        uint256 amount = abi.decode(hookData, (uint256));
        rebates[sender] = 0;
        token.transfer(sender, amount);
        return (this.afterSwap.selector, 0);
    }
}
"""

# The callback checks the caller is the pool manager.
_HOOK_CLEAN = _TOKEN_IFACE + _HOOK_TYPES + """
contract RebateHookClean {
    IERC20Like public token;
    address public poolManager;
    mapping(address => uint256) public rebates;

    constructor(address _token, address _poolManager) {
        token = IERC20Like(_token);
        poolManager = _poolManager;
    }

    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external returns (bytes4, int128) {
        require(msg.sender == address(poolManager), "not manager");
        uint256 amount = abi.decode(hookData, (uint256));
        rebates[sender] = 0;
        token.transfer(sender, amount);
        return (this.afterSwap.selector, 0);
    }
}
"""

# Owner-gated callback: same shape, trigger-only.
_HOOK_VARIANT = _TOKEN_IFACE + _HOOK_TYPES + """
contract RebateHookGated {
    IERC20Like public token;
    address public poolManager;
    address public owner;
    mapping(address => uint256) public rebates;

    constructor(address _token, address _poolManager, address _owner) {
        token = IERC20Like(_token);
        poolManager = _poolManager;
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyOwner returns (bytes4, int128) {
        uint256 amount = abi.decode(hookData, (uint256));
        rebates[sender] = 0;
        token.transfer(sender, amount);
        return (this.afterSwap.selector, 0);
    }
}
"""

# OpenZeppelin-style hook with an onlyPoolManager modifier.
_HOOK_ONLY_MANAGER = _TOKEN_IFACE + _HOOK_TYPES + """
contract RebateHookOnlyManager {
    IERC20Like public token;
    address public poolManager;
    mapping(address => uint256) public rebates;

    constructor(address _token, address _poolManager) {
        token = IERC20Like(_token);
        poolManager = _poolManager;
    }

    modifier onlyPoolManager() {
        require(msg.sender == address(poolManager), "not manager");
        _;
    }

    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata params, BalanceDelta calldata delta, bytes calldata hookData) external onlyPoolManager returns (bytes4, int128) {
        uint256 amount = abi.decode(hookData, (uint256));
        rebates[sender] = 0;
        token.transfer(sender, amount);
        return (this.afterSwap.selector, 0);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. swap_helper_caller_supplied_pool_hook_no_allowlist
# ---------------------------------------------------------------------------

_SWAP_TYPES = """
struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

interface IPoolManager {
    function swap(PoolKey calldata key, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96, bytes calldata hookData) external returns (int256);
}
"""

_SWAP_VULN = _TOKEN_IFACE + _SWAP_TYPES + """
contract SwapHelperVuln {
    IERC20Like public token;
    IPoolManager public poolManager;

    constructor(address _token, address _manager) {
        token = IERC20Like(_token);
        poolManager = IPoolManager(_manager);
    }

    function executeSwap(PoolKey calldata key, uint256 amountIn) external {
        int256 delta = poolManager.swap(key, true, int256(amountIn), 0, "");
        uint256 amountOut = uint256(delta > 0 ? delta : -delta);
        token.transfer(msg.sender, amountOut);
    }
}
"""

# The hook in the caller-supplied key is allowlisted.
_SWAP_CLEAN = _TOKEN_IFACE + _SWAP_TYPES + """
contract SwapHelperClean {
    IERC20Like public token;
    IPoolManager public poolManager;
    mapping(address => bool) public allowedHooks;

    constructor(address _token, address _manager) {
        token = IERC20Like(_token);
        poolManager = IPoolManager(_manager);
    }

    function executeSwap(PoolKey calldata key, uint256 amountIn) external {
        require(allowedHooks[key.hooks], "hook not allowed");
        int256 delta = poolManager.swap(key, true, int256(amountIn), 0, "");
        uint256 amountOut = uint256(delta > 0 ? delta : -delta);
        token.transfer(msg.sender, amountOut);
    }
}
"""

# Owner-gated helper: same shape, trigger-only.
_SWAP_VARIANT = _TOKEN_IFACE + _SWAP_TYPES + """
contract SwapHelperGated {
    IERC20Like public token;
    IPoolManager public poolManager;
    address public owner;

    constructor(address _token, address _manager, address _owner) {
        token = IERC20Like(_token);
        poolManager = IPoolManager(_manager);
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function executeSwap(PoolKey calldata key, uint256 amountIn) external onlyOwner {
        int256 delta = poolManager.swap(key, true, int256(amountIn), 0, "");
        uint256 amountOut = uint256(delta > 0 ? delta : -delta);
        token.transfer(msg.sender, amountOut);
    }
}
"""

# The pool key is read from contract storage, not the caller.
_SWAP_STORED_KEY = _TOKEN_IFACE + _SWAP_TYPES + """
contract SwapHelperStoredKey {
    IERC20Like public token;
    IPoolManager public poolManager;
    PoolKey public storedKey;

    constructor(address _token, address _manager) {
        token = IERC20Like(_token);
        poolManager = IPoolManager(_manager);
    }

    function executeSwap(uint256 amountIn) external {
        int256 delta = poolManager.swap(storedKey, true, int256(amountIn), 0, "");
        uint256 amountOut = uint256(delta > 0 ? delta : -delta);
        token.transfer(msg.sender, amountOut);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. governance_zero_quorum_executes
# ---------------------------------------------------------------------------

_GOV_VULN = """
contract WorkersUnionVuln {
    enum ProposalState { Pending, Active, Succeeded, Defeated, Executed }

    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public proposalCount;
    uint256 public votingPeriod = 3 days;

    function quorum() public view returns (uint256) {
        return 0;
    }

    function state(uint256 id) public view returns (ProposalState) {
        Proposal storage p = proposals[id];
        if (p.executed) {
            return ProposalState.Executed;
        }
        if (block.timestamp <= p.eta) {
            return ProposalState.Active;
        }
        if (p.forVotes > p.againstVotes) {
            return ProposalState.Succeeded;
        }
        return ProposalState.Defeated;
    }

    function propose(address target, uint256 value, bytes calldata data) external returns (uint256) {
        uint256 id = proposalCount;
        proposalCount += 1;
        proposals[id].target = target;
        proposals[id].value = value;
        proposals[id].data = data;
        proposals[id].eta = block.timestamp + votingPeriod;
        return id;
    }

    function vote(uint256 id, bool support) external {
        require(!hasVoted[id][msg.sender], "already voted");
        hasVoted[id][msg.sender] = true;
        if (support) {
            proposals[id].forVotes += 1;
        } else {
            proposals[id].againstVotes += 1;
        }
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(state(id) == ProposalState.Succeeded, "not succeeded");
        uint256 eta = p.eta;
        require(block.timestamp >= eta, "too early");
        p.executed = true;
        (bool ok, ) = p.target.call{value: p.value}(p.data);
        require(ok, "call failed");
    }
}
"""

# Quorum enforced: votes for must reach a nonzero quorum.
_GOV_CLEAN = """
contract WorkersUnionClean {
    enum ProposalState { Pending, Active, Succeeded, Defeated, Executed }

    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public proposalCount;
    uint256 public votingPeriod = 3 days;

    function quorum() public view returns (uint256) {
        return 100;
    }

    function state(uint256 id) public view returns (ProposalState) {
        Proposal storage p = proposals[id];
        if (p.executed) {
            return ProposalState.Executed;
        }
        if (block.timestamp <= p.eta) {
            return ProposalState.Active;
        }
        if (p.forVotes > p.againstVotes) {
            return ProposalState.Succeeded;
        }
        return ProposalState.Defeated;
    }

    function propose(address target, uint256 value, bytes calldata data) external returns (uint256) {
        uint256 id = proposalCount;
        proposalCount += 1;
        proposals[id].target = target;
        proposals[id].value = value;
        proposals[id].data = data;
        proposals[id].eta = block.timestamp + votingPeriod;
        return id;
    }

    function vote(uint256 id, bool support) external {
        require(!hasVoted[id][msg.sender], "already voted");
        hasVoted[id][msg.sender] = true;
        if (support) {
            proposals[id].forVotes += 1;
        } else {
            proposals[id].againstVotes += 1;
        }
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(state(id) == ProposalState.Succeeded, "not succeeded");
        uint256 eta = p.eta;
        require(block.timestamp >= eta, "too early");
        require(p.forVotes >= quorum(), "quorum not reached");
        p.executed = true;
        (bool ok, ) = p.target.call{value: p.value}(p.data);
        require(ok, "call failed");
    }
}
"""

# Owner-gated execute: same zero-quorum shape, trigger-only.
_GOV_VARIANT = """
contract WorkersUnionGated {
    enum ProposalState { Pending, Active, Succeeded, Defeated, Executed }

    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public proposalCount;
    uint256 public votingPeriod = 3 days;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function quorum() public view returns (uint256) {
        return 0;
    }

    function state(uint256 id) public view returns (ProposalState) {
        Proposal storage p = proposals[id];
        if (p.executed) {
            return ProposalState.Executed;
        }
        if (block.timestamp <= p.eta) {
            return ProposalState.Active;
        }
        if (p.forVotes > p.againstVotes) {
            return ProposalState.Succeeded;
        }
        return ProposalState.Defeated;
    }

    function propose(address target, uint256 value, bytes calldata data) external returns (uint256) {
        uint256 id = proposalCount;
        proposalCount += 1;
        proposals[id].target = target;
        proposals[id].value = value;
        proposals[id].data = data;
        proposals[id].eta = block.timestamp + votingPeriod;
        return id;
    }

    function vote(uint256 id, bool support) external {
        require(!hasVoted[id][msg.sender], "already voted");
        hasVoted[id][msg.sender] = true;
        if (support) {
            proposals[id].forVotes += 1;
        } else {
            proposals[id].againstVotes += 1;
        }
    }

    function execute(uint256 id) external onlyOwner {
        Proposal storage p = proposals[id];
        require(state(id) == ProposalState.Succeeded, "not succeeded");
        uint256 eta = p.eta;
        require(block.timestamp >= eta, "too early");
        p.executed = true;
        (bool ok, ) = p.target.call{value: p.value}(p.data);
        require(ok, "call failed");
    }
}
"""

# Quorum enforced in an internal helper the execute calls.
_GOV_QUORUM_HELPER = """
contract WorkersUnionQuorumHelper {
    enum ProposalState { Pending, Active, Succeeded, Defeated, Executed }

    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public proposalCount;
    uint256 public votingPeriod = 3 days;

    function quorum() public view returns (uint256) {
        return 100;
    }

    function state(uint256 id) public view returns (ProposalState) {
        Proposal storage p = proposals[id];
        if (p.executed) {
            return ProposalState.Executed;
        }
        if (block.timestamp <= p.eta) {
            return ProposalState.Active;
        }
        if (p.forVotes > p.againstVotes) {
            return ProposalState.Succeeded;
        }
        return ProposalState.Defeated;
    }

    function propose(address target, uint256 value, bytes calldata data) external returns (uint256) {
        uint256 id = proposalCount;
        proposalCount += 1;
        proposals[id].target = target;
        proposals[id].value = value;
        proposals[id].data = data;
        proposals[id].eta = block.timestamp + votingPeriod;
        return id;
    }

    function vote(uint256 id, bool support) external {
        require(!hasVoted[id][msg.sender], "already voted");
        hasVoted[id][msg.sender] = true;
        if (support) {
            proposals[id].forVotes += 1;
        } else {
            proposals[id].againstVotes += 1;
        }
    }

    function _checkQuorum(uint256 id) internal view {
        require(proposals[id].forVotes >= quorum(), "quorum not reached");
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(state(id) == ProposalState.Succeeded, "not succeeded");
        uint256 eta = p.eta;
        require(block.timestamp >= eta, "too early");
        _checkQuorum(id);
        p.executed = true;
        (bool ok, ) = p.target.call{value: p.value}(p.data);
        require(ok, "call failed");
    }
}
"""

# Execute performs no generic call at all.
_GOV_NO_CALL = """
contract WorkersUnionNoCall {
    enum ProposalState { Pending, Active, Succeeded, Defeated, Executed }

    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        uint256 eta;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    uint256 public proposalCount;
    uint256 public votingPeriod = 3 days;

    function quorum() public view returns (uint256) {
        return 0;
    }

    function state(uint256 id) public view returns (ProposalState) {
        Proposal storage p = proposals[id];
        if (p.executed) {
            return ProposalState.Executed;
        }
        if (block.timestamp <= p.eta) {
            return ProposalState.Active;
        }
        if (p.forVotes > p.againstVotes) {
            return ProposalState.Succeeded;
        }
        return ProposalState.Defeated;
    }

    function propose(address target, uint256 value, bytes calldata data) external returns (uint256) {
        uint256 id = proposalCount;
        proposalCount += 1;
        proposals[id].target = target;
        proposals[id].value = value;
        proposals[id].data = data;
        proposals[id].eta = block.timestamp + votingPeriod;
        return id;
    }

    function vote(uint256 id, bool support) external {
        require(!hasVoted[id][msg.sender], "already voted");
        hasVoted[id][msg.sender] = true;
        if (support) {
            proposals[id].forVotes += 1;
        } else {
            proposals[id].againstVotes += 1;
        }
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(state(id) == ProposalState.Succeeded, "not succeeded");
        uint256 eta = p.eta;
        require(block.timestamp >= eta, "too early");
        p.executed = true;
    }
}
"""

# ---------------------------------------------------------------------------
# 5. duplicate_reward_overwrite_desync
# ---------------------------------------------------------------------------

_POT_VULN = _TOKEN_IFACE + """
contract PotVuln {
    IERC20Like public token;
    mapping(address => uint256) public playersToRewards;
    uint256 public remainingRewards;
    address[] public players;

    constructor(address _token, address[] memory _players, uint256[] memory _rewards) {
        token = IERC20Like(_token);
        players = _players;
        for (uint256 i = 0; i < _players.length; i++) {
            playersToRewards[_players[i]] = _rewards[i];
            remainingRewards += _rewards[i];
        }
    }

    function claim() external {
        uint256 amount = playersToRewards[msg.sender];
        require(amount > 0, "nothing to claim");
        playersToRewards[msg.sender] = 0;
        token.transfer(msg.sender, amount);
    }
}
"""

# The batch loop accumulates with += : duplicates add up.
_POT_CLEAN = _TOKEN_IFACE + """
contract PotClean {
    IERC20Like public token;
    mapping(address => uint256) public playersToRewards;
    uint256 public remainingRewards;
    address[] public players;

    constructor(address _token, address[] memory _players, uint256[] memory _rewards) {
        token = IERC20Like(_token);
        players = _players;
        for (uint256 i = 0; i < _players.length; i++) {
            playersToRewards[_players[i]] += _rewards[i];
            remainingRewards += _rewards[i];
        }
    }

    function claim() external {
        uint256 amount = playersToRewards[msg.sender];
        require(amount > 0, "nothing to claim");
        playersToRewards[msg.sender] = 0;
        token.transfer(msg.sender, amount);
    }
}
"""

# The batch loop rejects a duplicate player outright.
_POT_DUP_REQUIRE = _TOKEN_IFACE + """
contract PotDupRequire {
    IERC20Like public token;
    mapping(address => uint256) public playersToRewards;
    uint256 public remainingRewards;
    address[] public players;

    constructor(address _token, address[] memory _players, uint256[] memory _rewards) {
        token = IERC20Like(_token);
        players = _players;
        for (uint256 i = 0; i < _players.length; i++) {
            require(playersToRewards[_players[i]] == 0, "duplicate player");
            playersToRewards[_players[i]] = _rewards[i];
            remainingRewards += _rewards[i];
        }
    }

    function claim() external {
        uint256 amount = playersToRewards[msg.sender];
        require(amount > 0, "nothing to claim");
        playersToRewards[msg.sender] = 0;
        token.transfer(msg.sender, amount);
    }
}
"""

VULN = {
    "relay_arbitrary_call_trusted_identity": _RELAY_VULN,
    "v4_hook_callback_no_poolmanager_check": _HOOK_VULN,
    "swap_helper_caller_supplied_pool_hook_no_allowlist": _SWAP_VULN,
    "governance_zero_quorum_executes": _GOV_VULN,
    "duplicate_reward_overwrite_desync": _POT_VULN,
}

CLEAN = {
    "relay_arbitrary_call_trusted_identity": _RELAY_CLEAN,
    "v4_hook_callback_no_poolmanager_check": _HOOK_CLEAN,
    "swap_helper_caller_supplied_pool_hook_no_allowlist": _SWAP_CLEAN,
    "governance_zero_quorum_executes": _GOV_CLEAN,
    "duplicate_reward_overwrite_desync": _POT_CLEAN,
}

VARIANT = {
    "relay_arbitrary_call_trusted_identity": _RELAY_VARIANT,
    "v4_hook_callback_no_poolmanager_check": _HOOK_VARIANT,
    "swap_helper_caller_supplied_pool_hook_no_allowlist": _SWAP_VARIANT,
    "governance_zero_quorum_executes": _GOV_VARIANT,
}

EXTRA_CLEAN = {
    "relay_digest_verified": _RELAY_DIGEST,
    "relay_fixed_target": _RELAY_FIXED_TARGET,
    "hook_only_pool_manager": _HOOK_ONLY_MANAGER,
    "swap_stored_key": _SWAP_STORED_KEY,
    "gov_quorum_helper": _GOV_QUORUM_HELPER,
    "gov_execute_no_call": _GOV_NO_CALL,
    "pot_duplicate_require": _POT_DUP_REQUIRE,
}
