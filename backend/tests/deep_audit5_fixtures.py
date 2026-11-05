"""Fixtures for the deep-audit batch-5 detectors (ERC + access).

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" at the spec
severity; CLEAN[id] (the protected shape of the same class)
MUST stay silent under ALL twelve detectors; every other
plugin's vulnerable fixture MUST stay silent under this one
(no cross-talk). VARIANT[id], where present, carries the same
vulnerable shape but the value lands at a FIXED destination,
so it MUST fire with report_class "trigger_only" at low
severity - never a candidate.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. erc20_missing_return_guard
# ---------------------------------------------------------------------------

_MISSING_RETURN_VULN = _TOKEN_IFACE + """
contract BoolWrapperVuln {
    IERC20Like public token;

    function payout(uint256 amount) public {
        require(token.transfer(msg.sender, amount), "transfer failed");
    }
}
"""

_MISSING_RETURN_VARIANT = _TOKEN_IFACE + """
contract BoolWrapperFixedVariant {
    IERC20Like public token;
    address public treasury;

    function payout(uint256 amount) public {
        require(token.transfer(treasury, amount), "transfer failed");
    }
}
"""

_MISSING_RETURN_TOKEN_VULN = """
contract NoReturnTokenVuln {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) public {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
"""

_MISSING_RETURN_CLEAN = """
library SafeERC20 {
    function safeTransfer(IERC20Like token, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(token.transfer.selector, to, amount));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "safe fail");
    }
}
""" + _TOKEN_IFACE + """
contract SafeWrapperClean {
    using SafeERC20 for IERC20Like;
    IERC20Like public token;

    function payout(uint256 amount) public {
        token.safeTransfer(msg.sender, amount);
    }
}
"""

_MISSING_RETURN_CLEAN_TOKEN = """
contract BoolTokenClean {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function transfer(address to, uint256 amount) public returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"""

# ---------------------------------------------------------------------------
# 2. erc721_mint_without_receiver_check
# ---------------------------------------------------------------------------

_721_VULN = """
contract GameItemVuln is ERC721 {
    uint256 public nextId;

    function mintTo(address recipient) public {
        _mint(recipient, nextId);
        nextId += 1;
    }
}
"""

_721_CLEAN = """
contract GameItemClean is ERC721 {
    uint256 public nextId;

    function mintTo(address recipient) public {
        _safeMint(recipient, nextId);
        nextId += 1;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. erc1155_batch_receiver_missing
# ---------------------------------------------------------------------------

_1155_VULN = """
contract Game1155ReceiverVuln {
    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data) external returns (bytes4) {
        return bytes4(0xf23a6e61);
    }
}
"""

_1155_CLEAN = """
contract Game1155ReceiverClean {
    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data) external returns (bytes4) {
        return bytes4(0xf23a6e61);
    }

    function onERC1155BatchReceived(address operator, address from, uint256[] calldata ids, uint256[] calldata values, bytes calldata data) external returns (bytes4) {
        return bytes4(0xbc197c81);
    }
}
"""

_1155_CLEAN_NEITHER = _TOKEN_IFACE + """
contract PlainVaultClean {
    IERC20Like public token;

    function deposit(uint256 amount) public {
        token.transferFrom(msg.sender, address(this), amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 4. eip712_separator_unbound
# ---------------------------------------------------------------------------

_SEPARATOR_VULN = """
contract PermitVaultVuln {
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,uint256 amount)");

    constructor(string memory name) {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,address verifyingContract)"),
            keccak256(bytes(name)),
            address(this)
        ));
    }

    function permit(address owner, uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 digest = keccak256(abi.encodePacked(
            "\\x19\\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, amount))));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad signature");
    }
}
"""

_SEPARATOR_DEPLOY_BOUND = """
contract PermitVaultDeployBound {
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,uint256 amount)");

    constructor(string memory name) {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            block.chainid,
            address(this)
        ));
    }

    function permit(address owner, uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 digest = keccak256(abi.encodePacked(
            "\\x19\\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, amount))));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad signature");
    }
}
"""

_SEPARATOR_CLEAN = """
contract PermitVaultClean {
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,uint256 amount)");
    string public name;

    constructor(string memory _name) {
        name = _name;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            block.chainid,
            address(this)
        ));
    }

    function permit(address owner, uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 digest = keccak256(abi.encodePacked(
            "\\x19\\x01", domainSeparator(),
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, amount))));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad signature");
    }
}
"""

# ---------------------------------------------------------------------------
# 5. erc2771_msg_sender_unbound
# ---------------------------------------------------------------------------

_2771_VULN = _TOKEN_IFACE + """
contract RelayedVaultVuln {
    IERC20Like public token;
    address public trustedForwarder;
    address public admin;

    function isTrustedForwarder(address forwarder) public view returns (bool) {
        return forwarder == trustedForwarder;
    }

    function execute(uint256 amount) public {
        require(msg.sender == admin, "not admin");
        token.transfer(admin, amount);
    }
}
"""

_2771_CLEAN = _TOKEN_IFACE + """
contract RelayedVaultClean {
    IERC20Like public token;
    address public trustedForwarder;
    address public admin;

    function isTrustedForwarder(address forwarder) public view returns (bool) {
        return forwarder == trustedForwarder;
    }

    function _msgSender() internal view returns (address) {
        if (isTrustedForwarder(msg.sender) && msg.data.length >= 20) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
        }
        return msg.sender;
    }

    function execute(uint256 amount) public {
        require(_msgSender() == admin, "not admin");
        token.transfer(admin, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 6. eip1271_magic_value_unchecked
# ---------------------------------------------------------------------------

_1271_VULN = _TOKEN_IFACE + """
interface ISigner1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}
""" + """
contract SigGateVuln {
    IERC20Like public token;
    ISigner1271 public signerWallet;

    function release(bytes32 hash, bytes calldata signature, uint256 amount) public {
        require(signerWallet.isValidSignature(hash, signature) != bytes4(0), "invalid");
        token.transfer(msg.sender, amount);
    }
}
"""

_1271_CLEAN = _TOKEN_IFACE + """
interface ISigner1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}
""" + """
contract SigGateClean {
    IERC20Like public token;
    ISigner1271 public signerWallet;

    function release(bytes32 hash, bytes calldata signature, uint256 amount) public {
        require(signerWallet.isValidSignature(hash, signature) == bytes4(0x1626ba7e), "invalid");
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 7. two_step_ownership_missing
# ---------------------------------------------------------------------------

_TWO_STEP_VULN = """
contract OwnedVaultVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, "not owner");
        owner = newOwner;
    }
}
"""

_TWO_STEP_CLEAN = """
contract OwnedVaultClean {
    address public owner;
    address public pendingOwner;

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, "not owner");
        pendingOwner = newOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == pendingOwner, "not pending");
        owner = msg.sender;
        pendingOwner = address(0);
    }
}
"""

# ---------------------------------------------------------------------------
# 8. default_admin_grant_exposed
# ---------------------------------------------------------------------------

_ADMIN_VULN = """
contract RoleSystemVuln {
    bytes32 public constant DEFAULT_ADMIN_ROLE = bytes32(0);
    mapping(bytes32 => mapping(address => bool)) public roles;

    function _grantRole(bytes32 role, address account) internal {
        roles[role][account] = true;
    }

    function initialize() public {
        _grantRole(DEFAULT_ADMIN_ROLE, 0x1111111111111111111111111111111111111111);
    }
}
"""

_ADMIN_CLEAN = """
contract RoleSystemClean {
    bytes32 public constant DEFAULT_ADMIN_ROLE = bytes32(0);
    mapping(bytes32 => mapping(address => bool)) public roles;

    function _grantRole(bytes32 role, address account) internal {
        roles[role][account] = true;
    }

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
}
"""

# ---------------------------------------------------------------------------
# 9. renounce_role_last_admin
# ---------------------------------------------------------------------------

_RENOUNCE_VULN = """
contract RoleRenounceVuln {
    mapping(bytes32 => mapping(address => bool)) public roles;

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return roles[role][account];
    }

    function renounceRole(bytes32 role, address account) public {
        require(account == msg.sender, "can only renounce self");
        roles[role][account] = false;
    }
}
"""

_RENOUNCE_CLEAN = """
contract RoleRenounceClean {
    mapping(bytes32 => mapping(address => bool)) public roles;
    mapping(bytes32 => uint256) public memberCounts;

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return roles[role][account];
    }

    function getRoleMemberCount(bytes32 role) public view returns (uint256) {
        return memberCounts[role];
    }

    function renounceRole(bytes32 role, address account) public {
        require(account == msg.sender, "can only renounce self");
        require(getRoleMemberCount(role) > 1, "last holder cannot renounce");
        roles[role][account] = false;
        memberCounts[role] -= 1;
    }
}
"""

# ---------------------------------------------------------------------------
# 10. pause_coverage_missing
# ---------------------------------------------------------------------------

_PAUSE_VULN = _TOKEN_IFACE + """
contract PausableVaultVuln {
    IERC20Like public token;
    bool public paused;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function pause() public onlyOwner {
        paused = true;
    }

    function withdraw(uint256 amount) public {
        token.transfer(msg.sender, amount);
    }
}
"""

_PAUSE_VARIANT = _TOKEN_IFACE + """
contract PausableVaultFixedVariant {
    IERC20Like public token;
    bool public paused;
    address public treasury;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function pause() public onlyOwner {
        paused = true;
    }

    function withdraw(uint256 amount) public {
        token.transfer(treasury, amount);
    }
}
"""

_PAUSE_CLEAN = _TOKEN_IFACE + """
contract PausableVaultClean {
    IERC20Like public token;
    bool public paused;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function pause() public onlyOwner {
        paused = true;
    }

    function withdraw(uint256 amount) public whenNotPaused {
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 11. signature_nonce_unconsumed
# ---------------------------------------------------------------------------

_NONCE_VULN = _TOKEN_IFACE + """
contract SigAdminVuln {
    IERC20Like public token;
    mapping(address => uint256) public nonces;
    address public signer;

    function executeBySig(uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 digest = keccak256(abi.encodePacked(signer, amount, nonces[signer]));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == signer, "bad signature");
        token.transfer(msg.sender, amount);
    }
}
"""

_NONCE_VARIANT = _TOKEN_IFACE + """
contract SigAdminFixedVariant {
    IERC20Like public token;
    mapping(address => uint256) public nonces;
    address public signer;
    address public treasury;

    function executeBySig(uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 digest = keccak256(abi.encodePacked(signer, amount, nonces[signer]));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == signer, "bad signature");
        token.transfer(treasury, amount);
    }
}
"""

_NONCE_CLEAN = _TOKEN_IFACE + """
contract SigAdminClean {
    IERC20Like public token;
    mapping(address => uint256) public nonces;
    address public signer;

    function executeBySig(uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        bytes32 digest = keccak256(abi.encodePacked(signer, amount, nonces[signer]));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == signer, "bad signature");
        nonces[signer] += 1;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 12. multisig_threshold_setter_unsafe
# ---------------------------------------------------------------------------

_THRESHOLD_VULN = """
contract MultiSigVuln {
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public threshold;

    function setThreshold(uint256 newThreshold) public {
        threshold = newThreshold;
    }
}
"""

_THRESHOLD_CLEAN = """
contract MultiSigClean {
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public threshold;
    address public admin;

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    function setThreshold(uint256 newThreshold) public onlyAdmin {
        require(newThreshold > 0, "zero threshold");
        require(newThreshold <= owners.length, "above owner count");
        threshold = newThreshold;
    }
}
"""

VULN = {
    "erc20_missing_return_guard": _MISSING_RETURN_VULN,
    "erc721_mint_without_receiver_check": _721_VULN,
    "erc1155_batch_receiver_missing": _1155_VULN,
    "eip712_separator_unbound": _SEPARATOR_VULN,
    "erc2771_msg_sender_unbound": _2771_VULN,
    "eip1271_magic_value_unchecked": _1271_VULN,
    "two_step_ownership_missing": _TWO_STEP_VULN,
    "default_admin_grant_exposed": _ADMIN_VULN,
    "renounce_role_last_admin": _RENOUNCE_VULN,
    "pause_coverage_missing": _PAUSE_VULN,
    "signature_nonce_unconsumed": _NONCE_VULN,
    "multisig_threshold_setter_unsafe": _THRESHOLD_VULN,
}

# Extra vulnerable shape for detector 1 (token implementation
# slice); MUST also fire candidate under its own detector.
VULN_EXTRA = {
    "erc20_missing_return_guard": _MISSING_RETURN_TOKEN_VULN,
}

# Deployment-chain-bound separator (FP elimination, 2026-11-05):
# fires, but only as trigger-only at low severity - the shape
# Dai / Uni / UniswapV2Pair ship in production.
DEPLOY_BOUND = {
    "eip712_separator_unbound": _SEPARATOR_DEPLOY_BOUND,
}

VARIANT = {
    "erc20_missing_return_guard": _MISSING_RETURN_VARIANT,
    "pause_coverage_missing": _PAUSE_VARIANT,
    "signature_nonce_unconsumed": _NONCE_VARIANT,
}

CLEAN = {
    "erc20_missing_return_guard": _MISSING_RETURN_CLEAN,
    "erc20_missing_return_guard_token": _MISSING_RETURN_CLEAN_TOKEN,
    "erc721_mint_without_receiver_check": _721_CLEAN,
    "erc1155_batch_receiver_missing": _1155_CLEAN,
    "erc1155_batch_receiver_missing_neither": _1155_CLEAN_NEITHER,
    "eip712_separator_unbound": _SEPARATOR_CLEAN,
    "erc2771_msg_sender_unbound": _2771_CLEAN,
    "eip1271_magic_value_unchecked": _1271_CLEAN,
    "two_step_ownership_missing": _TWO_STEP_CLEAN,
    "default_admin_grant_exposed": _ADMIN_CLEAN,
    "renounce_role_last_admin": _RENOUNCE_CLEAN,
    "pause_coverage_missing": _PAUSE_CLEAN,
    "signature_nonce_unconsumed": _NONCE_CLEAN,
    "multisig_threshold_setter_unsafe": _THRESHOLD_CLEAN,
}
