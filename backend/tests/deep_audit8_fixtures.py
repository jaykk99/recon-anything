"""Fixtures for the deep-audit batch-8 detectors (REE + CRY).

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, gate analysis and report_class "candidate";
VARIANT[id] (where present) carries the same vulnerable
shape but the recipient is FIXED, so it MUST fire with
report_class "trigger_only" at low severity - never a
candidate; CLEAN[id] (the protected shape of the same class)
MUST stay silent under ALL fourteen detectors; every other
plugin's vulnerable fixture MUST stay silent under this one
(no cross-talk).
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}
"""

_S_BOUND = ("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501"
            "DDFE92F46681B20A0")

# ---------------------------------------------------------------------------
# 1. cross_function_guard_sibling
# ---------------------------------------------------------------------------

_GUARD_SIBLING_VULN = _TOKEN_IFACE + """
contract GuardSiblingVuln {
    IERC20Like public token;
    mapping(address => uint256) public balances;
    uint256 public totalSwept;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function withdraw(uint256 amount) public nonReentrant {
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    function sweep(uint256 amount) public {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        totalSwept += amount;
    }

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    bool private locked;
}
"""

_GUARD_SIBLING_VARIANT = _TOKEN_IFACE + """
contract GuardSiblingFixedVariant {
    IERC20Like public token;
    address public treasury;
    mapping(address => uint256) public balances;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function withdraw(uint256 amount) public nonReentrant {
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    uint256 public totalSwept;

    function sweep(uint256 amount) public {
        (bool ok, ) = payable(treasury).call{value: amount}("");
        require(ok, "call failed");
        totalSwept += amount;
    }

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    bool private locked;
}
"""

_GUARD_SIBLING_CLEAN = _TOKEN_IFACE + """
contract GuardSiblingClean {
    IERC20Like public token;
    mapping(address => uint256) public balances;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function withdraw(uint256 amount) public nonReentrant {
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }

    function claim(uint256 amount) public {
        balances[msg.sender] = 0;
        token.transfer(msg.sender, amount);
    }

    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    bool private locked;
}
"""

# ---------------------------------------------------------------------------
# 2. reentrancy_guard_uninitialized
# ---------------------------------------------------------------------------

_GUARD_UNINIT_VULN = """
contract GuardUninitVuln {
    uint256 private _status;
    mapping(address => uint256) public balances;

    modifier nonReentrant() {
        require(_status != 2, "reentrant call");
        _status = 2;
        _;
        _status = 1;
    }

    function withdraw() public nonReentrant {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""

_GUARD_UNINIT_CLEAN = """
contract GuardInitClean {
    uint256 private _status = 1;
    mapping(address => uint256) public balances;

    modifier nonReentrant() {
        require(_status != 2, "reentrant call");
        _status = 2;
        _;
        _status = 1;
    }

    function withdraw() public nonReentrant {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""

_GUARD_UNINIT_CLEAN_CTOR = """
contract GuardInitCtorClean {
    uint256 private _status;
    mapping(address => uint256) public balances;

    constructor() {
        _status = 1;
    }

    modifier nonReentrant() {
        require(_status != 2, "reentrant call");
        _status = 2;
        _;
        _status = 1;
    }

    function withdraw() public nonReentrant {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. eth_send_stipend_brick
# ---------------------------------------------------------------------------

_SEND_VULN = """
contract SendBrickVuln {
    mapping(address => bool) public claimed;

    function claimReward(address account, uint256 amount) public {
        require(!claimed[account], "already claimed");
        claimed[account] = true;
        bool ok = payable(account).send(amount);
        require(ok, "send failed");
    }
}
"""

_SEND_VARIANT = """
contract SendBrickFixedVariant {
    address public treasury;
    mapping(address => uint256) public balances;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function settle() public {
        uint256 amt = balances[treasury];
        balances[treasury] = 0;
        bool ok = payable(treasury).send(amt);
        require(ok, "send failed");
    }
}
"""

_SEND_CLEAN = """
contract SendClean {
    mapping(address => uint256) public balances;

    function withdraw() public {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "call failed");
    }
}
"""

# ---------------------------------------------------------------------------
# 4. fallback_state_write_extended
# ---------------------------------------------------------------------------

_FALLBACK_VULN = """
contract FallbackWriteVuln {
    uint256 public receiveCount;
    uint256 public lastValue;
    address[] public callers;

    fallback() external {
        receiveCount++;
        callers.push(msg.sender);
        lastValue = 1;
    }
}
"""

_FALLBACK_CLEAN = """
contract FallbackClean {
    event Received(address from, uint256 value);

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    fallback() external payable {
        emit Received(msg.sender, msg.value);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. token_callback_caller_unverified
# ---------------------------------------------------------------------------

_CALLBACK_VULN = """
contract CallbackVuln {
    mapping(address => uint256) public credited;
    uint256 public totalReceived;

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4) {
        credited[from] += 1;
        totalReceived += 1;
        return this.onERC721Received.selector;
    }
}
"""

_CALLBACK_CLEAN = """
contract CallbackClean {
    address public collection;
    mapping(address => uint256) public credited;

    constructor(address _collection) {
        collection = _collection;
    }

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4) {
        require(msg.sender == collection, "not the collection");
        credited[from] += 1;
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data) external returns (bytes4) {
        require(msg.sender == collection, "not the collection");
        credited[from] += value;
        return this.onERC1155Received.selector;
    }
}
"""

# ---------------------------------------------------------------------------
# 6. multicall_value_reuse
# ---------------------------------------------------------------------------

_MULTICALL_VULN = """
contract MulticallVuln {
    function multicall(bytes[] calldata data) external payable returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            require(msg.value > 0, "no value sent");
            (bool ok, bytes memory res) = address(this).delegatecall(data[i]);
            require(ok, "subcall failed");
            results[i] = res;
        }
    }
}
"""

_MULTICALL_CLEAN = """
contract MulticallClean {
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    function multicall(Call[] calldata calls) external payable {
        uint256 total = 0;
        for (uint256 i = 0; i < calls.length; i++) {
            total += calls[i].value;
        }
        require(total == msg.value, "value mismatch");
        for (uint256 i = 0; i < calls.length; i++) {
            (bool ok, ) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(ok, "subcall failed");
        }
    }
}
"""

# ---------------------------------------------------------------------------
# 7. push_payment_revert_dos
# ---------------------------------------------------------------------------

_PUSH_VULN = """
contract PushPaymentVuln {
    address payable[] public payees;
    mapping(address => uint256) public shares;

    function distribute() public {
        for (uint256 i = 0; i < payees.length; i++) {
            payees[i].transfer(shares[payees[i]]);
        }
    }
}
"""

_PUSH_VARIANT = """
contract PushPaymentFixedVariant {
    address payable[] public payees;
    address public treasury;
    uint256 public feeAmount;

    constructor(address _treasury) {
        treasury = _treasury;
    }

    function distributeFees() public {
        for (uint256 i = 0; i < payees.length; i++) {
            payable(treasury).transfer(feeAmount);
        }
    }
}
"""

_PUSH_CLEAN = """
contract PushPaymentClean {
    address payable[] public payees;
    mapping(address => uint256) public shares;
    mapping(address => uint256) public failedPayouts;

    function distribute() public {
        for (uint256 i = 0; i < payees.length; i++) {
            uint256 amt = shares[payees[i]];
            shares[payees[i]] = 0;
            (bool ok, ) = payees[i].call{value: amt}("");
            if (!ok) {
                failedPayouts[payees[i]] += amt;
            }
        }
    }
}
"""

# ---------------------------------------------------------------------------
# 8. ecdsa_recover_zero_unchecked
# ---------------------------------------------------------------------------

_ECDSA_VULN = _TOKEN_IFACE + """
contract EcdsaRecoverVuln {
    IERC20Like public token;
    address public owner;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claimWithSig(bytes32 hash, bytes memory sig, uint256 amount) public {
        address signer = ECDSA.recover(hash, sig);
        require(signer == owner, "bad signer");
        token.transfer(msg.sender, amount);
    }
}
"""

_ECDSA_TRY_VULN = _TOKEN_IFACE + """
contract EcdsaTryRecoverVuln {
    IERC20Like public token;
    address public owner;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claimWithSig(bytes32 hash, bytes memory sig, uint256 amount) public {
        (address signer) = ECDSA.tryRecover(hash, sig);
        require(signer == owner, "bad signer");
        require(signer != address(0), "zero signer");
        token.transfer(msg.sender, amount);
    }
}
"""

_ECDSA_CLEAN = _TOKEN_IFACE + """
contract EcdsaRecoverClean {
    IERC20Like public token;
    address public owner;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claimWithSig(bytes32 hash, bytes memory sig, uint256 amount) public {
        address signer = ECDSA.recover(hash, sig);
        require(signer != address(0), "zero signer");
        require(signer == owner, "bad signer");
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 9. raw_ecrecover_s_unbounded
# ---------------------------------------------------------------------------

_S_UNBOUNDED_VULN = """
contract RawEcrecoverVuln {
    address public owner;

    function recoverSigner(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return ecrecover(hash, v, r, s);
    }

    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        return recoverSigner(hash, v, r, s) == owner;
    }
}
"""

_S_UNBOUNDED_CLEAN = """
contract RawEcrecoverClean {
    address public owner;

    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public view returns (bool) {
        require(uint256(s) <= SBOUND, "s too high");
        address rec = ecrecover(hash, v, r, s);
        require(rec != address(0), "zero signer");
        return rec == owner;
    }

    uint256 internal constant SBOUND = """ + _S_BOUND + """;
}
"""

# ---------------------------------------------------------------------------
# 10. merkle_leaf_single_hash
# ---------------------------------------------------------------------------

_MERKLE_VULN = _TOKEN_IFACE + """
contract MerkleLeafVuln {
    IERC20Like public token;
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claim(string memory name, uint256 amount) public {
        bytes32 leaf = keccak256(abi.encodePacked(name));
        require(leaf == merkleRoot, "not in tree");
        claimed[msg.sender] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

_MERKLE_CLEAN = _TOKEN_IFACE + """
contract MerkleLeafClean {
    IERC20Like public token;
    bytes32 public merkleRoot;
    mapping(address => bool) public claimed;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function claim(string memory name, uint256 amount) public {
        bytes32 leaf = keccak256(abi.encodePacked(name));
        bytes32 hashedLeaf = keccak256(abi.encode(leaf));
        require(hashedLeaf == merkleRoot, "not in tree");
        claimed[msg.sender] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 11. hardcoded_hash_constant_mismatch
# ---------------------------------------------------------------------------

_HASH_CONST_VULN = """
contract HashConstantVuln {
    bytes32 public constant MINTER_ROLE = 0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a;
    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c8;

    mapping(address => bool) public minters;

    function grantMinter(address account) public {
        minters[account] = true;
    }
}
"""

_HASH_CONST_CLEAN = """
contract HashConstantClean {
    bytes32 public constant MINTER_ROLE = 0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6;
    bytes32 public constant PAUSER_ROLE = 0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a;
    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    bytes32 public constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
    bytes32 public constant SALT = 0x1111111111111111111111111111111111111111111111111111111111111111;
}
"""

# ---------------------------------------------------------------------------
# 12. weak_randomness_value_outcome
# ---------------------------------------------------------------------------

_RANDOM_VULN = _TOKEN_IFACE + """
contract WeakRandomVuln {
    IERC20Like public token;
    address[] public participants;

    constructor(address _token) {
        token = IERC20Like(_token);
    }

    function drawWinner() public {
        uint256 rand = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender)));
        address winner = participants[rand % participants.length];
        token.transfer(winner, 100);
    }
}
"""

_RANDOM_VARIANT = _TOKEN_IFACE + """
contract WeakRandomFixedVariant {
    IERC20Like public token;
    address public treasury;
    address[] public participants;

    constructor(address _token, address _treasury) {
        token = IERC20Like(_token);
        treasury = _treasury;
    }

    function settleRound() public {
        uint256 rand = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao)));
        address picked = participants[rand % participants.length];
        token.transfer(treasury, 100);
    }
}
"""

_RANDOM_CLEAN = """
contract RandomClean {
    mapping(address => uint256) public balances;
    uint256 public unlockTime;

    function withdrawAfterLock() public {
        require(block.timestamp >= unlockTime, "still locked");
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
}
"""

# ---------------------------------------------------------------------------
# 13. empty_signature_accepted
# ---------------------------------------------------------------------------

_EMPTY_SIG_VULN = """
contract EmptySigVuln {
    address public owner;

    function isValidSignature(bytes32 hash, bytes memory signature) public view returns (bool) {
        if (signature.length == 0) return true;
        return true;
    }

    function verifySplit(bytes32 hash, bytes memory sig) public view returns (bool) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        require(uint256(s) <= """ + _S_BOUND + """, "s too high");
        return ecrecover(hash, v, r, s) == owner;
    }
}
"""

_EMPTY_SIG_CLEAN = """
contract EmptySigClean {
    address public owner;

    function verify(bytes32 hash, bytes memory sig) public view returns (bool) {
        require(sig.length == 65, "bad signature length");
        if (sig.length == 0) return false;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        require(uint256(s) <= """ + _S_BOUND + """, "s too high");
        address rec = ecrecover(hash, v, r, s);
        require(rec != address(0), "zero signer");
        return rec == owner;
    }
}
"""

# ---------------------------------------------------------------------------
# 14. packed_encoding_collision
# ---------------------------------------------------------------------------

_PACKED_VULN = """
contract PackedCollisionVuln {
    mapping(bytes32 => bool) public usedIds;

    function registerId(string memory name, string memory category) public returns (bytes32) {
        bytes32 id = keccak256(abi.encodePacked(name, category));
        require(!usedIds[id], "id taken");
        usedIds[id] = true;
        return id;
    }
}
"""

_PACKED_CLEAN = """
contract PackedCollisionClean {
    function keyFor(address user, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, nonce));
    }

    function digestFor(string memory a, string memory b) public pure returns (bytes32) {
        return keccak256(abi.encode(a, b));
    }
}
"""

VULN = {
    "cross_function_guard_sibling": _GUARD_SIBLING_VULN,
    "reentrancy_guard_uninitialized": _GUARD_UNINIT_VULN,
    "eth_send_stipend_brick": _SEND_VULN,
    "fallback_state_write_extended": _FALLBACK_VULN,
    "token_callback_caller_unverified": _CALLBACK_VULN,
    "multicall_value_reuse": _MULTICALL_VULN,
    "push_payment_revert_dos": _PUSH_VULN,
    "ecdsa_recover_zero_unchecked": _ECDSA_VULN,
    "raw_ecrecover_s_unbounded": _S_UNBOUNDED_VULN,
    "merkle_leaf_single_hash": _MERKLE_VULN,
    "hardcoded_hash_constant_mismatch": _HASH_CONST_VULN,
    "weak_randomness_value_outcome": _RANDOM_VULN,
    "empty_signature_accepted": _EMPTY_SIG_VULN,
    "packed_encoding_collision": _PACKED_VULN,
}

EXTRA_VULN = {
    "ecdsa_recover_zero_unchecked": _ECDSA_TRY_VULN,
}

VARIANT = {
    "cross_function_guard_sibling": _GUARD_SIBLING_VARIANT,
    "eth_send_stipend_brick": _SEND_VARIANT,
    "push_payment_revert_dos": _PUSH_VARIANT,
    "weak_randomness_value_outcome": _RANDOM_VARIANT,
}

CLEAN = {
    "cross_function_guard_sibling": _GUARD_SIBLING_CLEAN,
    "reentrancy_guard_uninitialized": _GUARD_UNINIT_CLEAN,
    "reentrancy_guard_uninitialized_ctor": _GUARD_UNINIT_CLEAN_CTOR,
    "eth_send_stipend_brick": _SEND_CLEAN,
    "fallback_state_write_extended": _FALLBACK_CLEAN,
    "token_callback_caller_unverified": _CALLBACK_CLEAN,
    "multicall_value_reuse": _MULTICALL_CLEAN,
    "push_payment_revert_dos": _PUSH_CLEAN,
    "ecdsa_recover_zero_unchecked": _ECDSA_CLEAN,
    "raw_ecrecover_s_unbounded": _S_UNBOUNDED_CLEAN,
    "merkle_leaf_single_hash": _MERKLE_CLEAN,
    "hardcoded_hash_constant_mismatch": _HASH_CONST_CLEAN,
    "weak_randomness_value_outcome": _RANDOM_CLEAN,
    "empty_signature_accepted": _EMPTY_SIG_CLEAN,
    "packed_encoding_collision": _PACKED_CLEAN,
}
