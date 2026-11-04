"""Fixtures for the deep-audit batch-7 detectors (bridge +
proxy slices).

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" at the spec
severity; VARIANT[id] (only for the value-moving detectors)
carries the same vulnerable shape but the recipient is FIXED,
so it MUST fire trigger-only at low severity; CLEAN[id] (the
protected shape of the same class) MUST stay silent under
ALL twelve detectors; every other plugin's vulnerable /
variant fixture MUST stay silent under this one (no
cross-talk).
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}
"""

# ---------------------------------------------------------------------------
# 1. bridge_digest_no_destination_chain
# ---------------------------------------------------------------------------

_DIGEST_VULN = _TOKEN_IFACE + """
contract DigestClaimVuln {
    IERC20Like public token;
    bytes32 public committedDigest;

    function claimWithDigest(uint32 srcChain, address originSender, uint64 nonce, uint256 amount) public {
        bytes32 digest = keccak256(abi.encode(srcChain, originSender, nonce, amount));
        require(digest == committedDigest, "bad digest");
        token.transfer(msg.sender, amount);
    }
}
"""

_DIGEST_VARIANT = _TOKEN_IFACE + """
contract DigestClaimFixedVariant {
    IERC20Like public token;
    bytes32 public committedDigest;
    address public treasury;

    function claimWithDigest(uint32 srcChain, address originSender, uint64 nonce, uint256 amount) public {
        bytes32 digest = keccak256(abi.encode(srcChain, originSender, nonce, amount));
        require(digest == committedDigest, "bad digest");
        token.transfer(treasury, amount);
    }
}
"""

_DIGEST_CLEAN = _TOKEN_IFACE + """
contract DigestClaimClean {
    IERC20Like public token;
    bytes32 public committedDigest;

    function claimWithDigest(uint32 srcChain, address originSender, uint64 nonce, uint32 destinationChain, uint256 amount) public {
        bytes32 digest = keccak256(abi.encode(srcChain, originSender, nonce, destinationChain, amount));
        require(digest == committedDigest, "bad digest");
        token.transfer(msg.sender, amount);
    }
}
"""

_DIGEST_NO_BINDING_CLEAN = _TOKEN_IFACE + """
contract DigestNoBindingClean {
    IERC20Like public token;
    bytes32 public committedDigest;

    function claimAmountOnly(uint256 amount) public {
        bytes32 digest = keccak256(abi.encode(amount));
        require(digest == committedDigest, "bad digest");
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 2. bridge_bytes_proof_length_unvalidated
# ---------------------------------------------------------------------------

_PROOF_IFACE = """
interface IProofVerifier {
    function verify(bytes calldata proof, bytes32 leaf) external view returns (bool);
}
"""

_BYTES_PROOF_VULN = _TOKEN_IFACE + _PROOF_IFACE + """
contract BytesProofClaimVuln {
    IERC20Like public token;
    IProofVerifier public verifier;
    mapping(bytes32 => bool) public usedProofs;

    function claimWithProof(bytes calldata proof, bytes32 leaf, uint256 amount) public {
        require(verifier.verify(proof, leaf), "bad proof");
        usedProofs[leaf] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

_BYTES_PROOF_VARIANT = _TOKEN_IFACE + _PROOF_IFACE + """
contract BytesProofClaimFixedVariant {
    IERC20Like public token;
    IProofVerifier public verifier;
    address public treasury;
    mapping(bytes32 => bool) public usedProofs;

    function claimWithProof(bytes calldata proof, bytes32 leaf, uint256 amount) public {
        require(verifier.verify(proof, leaf), "bad proof");
        usedProofs[leaf] = true;
        token.transfer(treasury, amount);
    }
}
"""

_BYTES_PROOF_CLEAN = _TOKEN_IFACE + _PROOF_IFACE + """
contract BytesProofClaimClean {
    IERC20Like public token;
    IProofVerifier public verifier;
    mapping(bytes32 => bool) public usedProofs;

    function claimWithProof(bytes calldata proof, bytes32 leaf, uint256 amount) public {
        require(proof.length == 64, "bad proof length");
        require(verifier.verify(proof, leaf), "bad proof");
        usedProofs[leaf] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 3. bridge_static_gas_limit
# ---------------------------------------------------------------------------

_MESSENGER_IFACE = """
struct Options { uint256 gasLimit; }
interface IMessengerLike {
    function dispatch(uint32 destinationChain, bytes memory payload, Options memory options) external payable;
}
"""

_GAS_VULN = _MESSENGER_IFACE + """
contract GasDispatchVuln {
    uint256 public constant GAS_LIMIT = 200000;
    IMessengerLike public messenger;

    function sendMessage(uint32 destinationChain, bytes memory payload) public payable {
        messenger.dispatch(destinationChain, payload, Options({gasLimit: GAS_LIMIT}));
    }
}
"""

_GAS_CLEAN = _MESSENGER_IFACE + """
contract GasDispatchClean {
    IMessengerLike public messenger;

    function sendMessage(uint32 destinationChain, bytes memory payload, uint256 gasLimit) public payable {
        messenger.dispatch(destinationChain, payload, Options({gasLimit: gasLimit}));
    }
}
"""

_GAS_COMPUTED_CLEAN = _MESSENGER_IFACE + """
contract GasDispatchComputedClean {
    uint256 public constant BASE_GAS = 50000;
    IMessengerLike public messenger;

    function sendMessage(uint32 destinationChain, bytes memory payload) public payable {
        messenger.dispatch(destinationChain, payload, Options({gasLimit: BASE_GAS + payload.length * 32}));
    }
}
"""

_GAS_STRUCT_VULN = _MESSENGER_IFACE + """
contract GasStructDispatchVuln {
    IMessengerLike public messenger;

    function sendMessage(uint32 destinationChain, bytes memory payload) public payable {
        messenger.dispatch(destinationChain, payload, Options({gasLimit: 250000}));
    }
}
"""

# ---------------------------------------------------------------------------
# 4. bridge_receiver_sender_unchecked
# ---------------------------------------------------------------------------

_PROOF_LIB = """
interface IProofLib {
    function verify(bytes calldata payload, bytes32 root) external view returns (bool);
}
"""

_RECEIVER_VULN = _TOKEN_IFACE + _PROOF_LIB + """
contract ReceiverUncheckedVuln {
    IERC20Like public token;
    IProofLib public proofLib;
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public processedMessages;

    function lzReceive(bytes calldata payload, bytes32 messageId, uint256 amount) public {
        require(proofLib.verify(payload, merkleRoot), "bad proof");
        processedMessages[messageId] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

_RECEIVER_VARIANT = _TOKEN_IFACE + _PROOF_LIB + """
contract ReceiverUncheckedFixedVariant {
    IERC20Like public token;
    IProofLib public proofLib;
    bytes32 public merkleRoot;
    address public treasury;
    mapping(bytes32 => bool) public processedMessages;

    function lzReceive(bytes calldata payload, bytes32 messageId, uint256 amount) public {
        require(proofLib.verify(payload, merkleRoot), "bad proof");
        processedMessages[messageId] = true;
        token.transfer(treasury, amount);
    }
}
"""

_RECEIVER_CLEAN = _TOKEN_IFACE + _PROOF_LIB + """
contract ReceiverCheckedClean {
    IERC20Like public token;
    IProofLib public proofLib;
    bytes32 public merkleRoot;
    address public endpoint;
    mapping(bytes32 => bool) public processedMessages;

    function lzReceive(bytes calldata payload, bytes32 messageId, uint256 amount) public {
        require(msg.sender == endpoint, "only endpoint");
        require(proofLib.verify(payload, merkleRoot), "bad proof");
        processedMessages[messageId] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 5. bridge_mint_burn_gate_asymmetry
# ---------------------------------------------------------------------------

_MINTBURN_VULN = """
contract MintBurnAsymVuln {
    function bridgeMint(address to, uint256 amount) public onlyBridge {
        _mint(to, amount);
    }

    function burn(uint256 amount) public {
        _burn(msg.sender, amount);
    }

    function _mint(address to, uint256 amount) internal {}
    function _burn(address from, uint256 amount) internal {}
}
"""

_MINTBURN_VARIANT = """
contract MintBurnAsymFixedVariant {
    address public treasury;

    function bridgeMint(uint256 amount) public {
        _mint(treasury, amount);
    }

    function burn(uint256 amount) public onlyBridge {
        _burn(msg.sender, amount);
    }

    function _mint(address to, uint256 amount) internal {}
    function _burn(address from, uint256 amount) internal {}
}
"""

_MINTBURN_CLEAN = """
contract MintBurnSymmetricClean {
    function bridgeMint(address to, uint256 amount) public onlyBridge {
        _mint(to, amount);
    }

    function burn(uint256 amount) public onlyBridge {
        _burn(msg.sender, amount);
    }

    function _mint(address to, uint256 amount) internal {}
    function _burn(address from, uint256 amount) internal {}
}
"""

# ---------------------------------------------------------------------------
# 6. bridge_nonce_order_unenforced
# ---------------------------------------------------------------------------

_NONCE_VULN = _TOKEN_IFACE + """
contract NonceOrderVuln {
    IERC20Like public token;
    address public endpoint;
    uint256 public nextNonce;
    mapping(address => uint256) public receivedNonces;

    function receiveMessage(uint64 nonce, uint256 amount) public {
        require(msg.sender == endpoint, "only endpoint");
        receivedNonces[msg.sender] = nonce;
        token.transfer(msg.sender, amount);
    }
}
"""

_NONCE_VARIANT = _TOKEN_IFACE + """
contract NonceOrderFixedVariant {
    IERC20Like public token;
    address public endpoint;
    address public treasury;
    uint256 public nextNonce;
    mapping(address => uint256) public receivedNonces;

    function receiveMessage(uint64 nonce, uint256 amount) public {
        require(msg.sender == endpoint, "only endpoint");
        receivedNonces[msg.sender] = nonce;
        token.transfer(treasury, amount);
    }
}
"""

_NONCE_CLEAN = _TOKEN_IFACE + """
contract NonceOrderClean {
    IERC20Like public token;
    address public endpoint;
    uint256 public nextNonce;
    mapping(address => uint256) public receivedNonces;

    function receiveMessage(uint64 nonce, uint256 amount) public {
        require(msg.sender == endpoint, "only endpoint");
        require(nonce == nextNonce, "out of order");
        receivedNonces[msg.sender] = nonce;
        nextNonce += 1;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 7. bridge_proof_nullifier_missing
# ---------------------------------------------------------------------------

_ZK_IFACE = """
interface IZKVerifier {
    function verifyProof(uint256[2] calldata proof, uint256[] calldata publicInputs) external view returns (bool);
}
"""

_NULLIFIER_VULN = _TOKEN_IFACE + _ZK_IFACE + """
contract NullifierClaimVuln {
    IERC20Like public token;
    IZKVerifier public verifier;

    function claimWithZKProof(uint256[2] calldata proof, uint256[] calldata publicInputs, uint256 amount) public {
        require(verifier.verifyProof(proof, publicInputs), "bad proof");
        token.transfer(msg.sender, amount);
    }
}
"""

_NULLIFIER_VARIANT = _TOKEN_IFACE + _ZK_IFACE + """
contract NullifierClaimFixedVariant {
    IERC20Like public token;
    IZKVerifier public verifier;
    address public treasury;

    function claimWithZKProof(uint256[2] calldata proof, uint256[] calldata publicInputs, uint256 amount) public {
        require(verifier.verifyProof(proof, publicInputs), "bad proof");
        token.transfer(treasury, amount);
    }
}
"""

_NULLIFIER_CLEAN = _TOKEN_IFACE + _ZK_IFACE + """
contract NullifierClaimClean {
    IERC20Like public token;
    IZKVerifier public verifier;
    mapping(uint256 => bool) public nullifiers;

    function claimWithZKProof(uint256[2] calldata proof, uint256[] calldata publicInputs, uint256 amount) public {
        require(verifier.verifyProof(proof, publicInputs), "bad proof");
        require(!nullifiers[publicInputs[0]], "proof already used");
        nullifiers[publicInputs[0]] = true;
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 8. bridge_payload_slice_unbounded
# ---------------------------------------------------------------------------

_PAYLOAD_VULN = _TOKEN_IFACE + """
contract PayloadSliceVuln {
    IERC20Like public token;
    address public endpoint;

    function executeMessage(bytes calldata payload, uint256 amount) public {
        require(msg.sender == endpoint, "only endpoint");
        bytes1 marker = payload[0];
        require(marker == bytes1(0x01), "bad marker");
        token.transfer(msg.sender, amount);
    }
}
"""

_PAYLOAD_VARIANT = _TOKEN_IFACE + """
contract PayloadSliceFixedVariant {
    IERC20Like public token;
    address public endpoint;
    address public treasury;

    function executeMessage(bytes calldata payload, uint256 amount) public {
        require(msg.sender == endpoint, "only endpoint");
        bytes1 marker = payload[0];
        require(marker == bytes1(0x01), "bad marker");
        token.transfer(treasury, amount);
    }
}
"""

_PAYLOAD_CLEAN = _TOKEN_IFACE + """
contract PayloadSliceClean {
    IERC20Like public token;
    address public endpoint;

    function executeMessage(bytes calldata payload, uint256 amount) public {
        require(msg.sender == endpoint, "only endpoint");
        require(payload.length >= 1, "payload too short");
        bytes1 marker = payload[0];
        require(marker == bytes1(0x01), "bad marker");
        token.transfer(msg.sender, amount);
    }
}
"""

# ---------------------------------------------------------------------------
# 9. uups_authorize_upgrade_missing
# ---------------------------------------------------------------------------

_UUPS_VULN = """
contract UUPSVuln is UUPSUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal override {}

    function version() public pure returns (uint256) {
        return 1;
    }
}
"""

_UUPS_MISSING_VULN = """
contract UUPSMissingAuthVuln is UUPSUpgradeable {
    function version() public pure returns (uint256) {
        return 1;
    }
}
"""

_UUPS_CLEAN = """
contract UUPSClean is UUPSUpgradeable {
    address public owner;

    function _authorizeUpgrade(address newImplementation) internal override {
        require(msg.sender == owner, "only owner");
    }

    function version() public pure returns (uint256) {
        return 1;
    }
}
"""

# ---------------------------------------------------------------------------
# 10. initializer_flag_after_call
# ---------------------------------------------------------------------------

_REGISTRY_IFACE = """
interface IRegistryLike {
    function register(address who) external;
}
"""

_INITFLAG_VULN = _REGISTRY_IFACE + """
contract InitFlagVuln {
    bool public initialized;
    IRegistryLike public registry;

    function initialize(address registryAddress) public {
        registry = IRegistryLike(registryAddress);
        registry.register(address(this));
        initialized = true;
    }
}
"""

_INITFLAG_CLEAN = _REGISTRY_IFACE + """
contract InitFlagClean {
    bool public initialized;
    IRegistryLike public registry;

    function initialize(address registryAddress) public {
        initialized = true;
        registry = IRegistryLike(registryAddress);
        registry.register(address(this));
    }
}
"""

_INITFLAG_MODIFIER_CLEAN = _REGISTRY_IFACE + """
contract InitFlagModifierClean {
    bool public initialized;
    IRegistryLike public registry;

    function initialize(address registryAddress) public initializer {
        registry = IRegistryLike(registryAddress);
        registry.register(address(this));
        initialized = true;
    }
}
"""

# ---------------------------------------------------------------------------
# 11. diamond_selector_collision
# ---------------------------------------------------------------------------

_DIAMOND_VULN = """
contract Diamond {
    function diamondCut(address facet, bytes4 selector) public {}
    function facets() public view returns (address[] memory) {}
}

contract FacetAlpha {
    function transfer(address to, uint256 amount) public returns (bool) {
        return true;
    }

    function redeem(uint256 shares) public returns (uint256) {
        return shares;
    }
}

contract FacetBeta {
    function transfer(address to, uint256 amount) public returns (bool) {
        return true;
    }
}
"""

_DIAMOND_CLEAN = """
contract Diamond {
    function diamondCut(address facet, bytes4 selector) public {}
    function facets() public view returns (address[] memory) {}
}

contract FacetAlpha {
    function transfer(address to, uint256 amount) public returns (bool) {
        return true;
    }
}

contract FacetBeta {
    function redeem(uint256 shares) public returns (uint256) {
        return shares;
    }
}
"""

_DIAMOND_NO_MARKER_CLEAN = """
contract FacetAlpha {
    function transfer(address to, uint256 amount) public returns (bool) {
        return true;
    }
}

contract FacetBeta {
    function transfer(address to, uint256 amount) public returns (bool) {
        return true;
    }
}
"""

# ---------------------------------------------------------------------------
# 12. beacon_implementation_zero_accepted
# ---------------------------------------------------------------------------

_BEACON_VULN = """
contract BeaconSetterVuln {
    address public implementation;
    address public owner;

    function upgradeBeacon(address newImplementation) public onlyOwner {
        implementation = newImplementation;
    }
}
"""

_BEACON_CLEAN = """
contract BeaconSetterClean {
    address public implementation;
    address public owner;

    function upgradeBeacon(address newImplementation) public onlyOwner {
        require(newImplementation != address(0), "zero implementation");
        implementation = newImplementation;
    }
}
"""

VULN = {
    "bridge_digest_no_destination_chain": _DIGEST_VULN,
    "bridge_bytes_proof_length_unvalidated": _BYTES_PROOF_VULN,
    "bridge_static_gas_limit": _GAS_VULN,
    "bridge_receiver_sender_unchecked": _RECEIVER_VULN,
    "bridge_mint_burn_gate_asymmetry": _MINTBURN_VULN,
    "bridge_nonce_order_unenforced": _NONCE_VULN,
    "bridge_proof_nullifier_missing": _NULLIFIER_VULN,
    "bridge_payload_slice_unbounded": _PAYLOAD_VULN,
    "uups_authorize_upgrade_missing": _UUPS_VULN,
    "initializer_flag_after_call": _INITFLAG_VULN,
    "diamond_selector_collision": _DIAMOND_VULN,
    "beacon_implementation_zero_accepted": _BEACON_VULN,
}

EXTRA_VULN = {
    "bridge_static_gas_limit_struct": _GAS_STRUCT_VULN,
    "uups_authorize_upgrade_missing_absent": _UUPS_MISSING_VULN,
}

VARIANT = {
    "bridge_digest_no_destination_chain": _DIGEST_VARIANT,
    "bridge_bytes_proof_length_unvalidated": _BYTES_PROOF_VARIANT,
    "bridge_receiver_sender_unchecked": _RECEIVER_VARIANT,
    "bridge_mint_burn_gate_asymmetry": _MINTBURN_VARIANT,
    "bridge_nonce_order_unenforced": _NONCE_VARIANT,
    "bridge_proof_nullifier_missing": _NULLIFIER_VARIANT,
    "bridge_payload_slice_unbounded": _PAYLOAD_VARIANT,
}

CLEAN = {
    "bridge_digest_no_destination_chain": _DIGEST_CLEAN,
    "bridge_bytes_proof_length_unvalidated": _BYTES_PROOF_CLEAN,
    "bridge_static_gas_limit": _GAS_CLEAN,
    "bridge_receiver_sender_unchecked": _RECEIVER_CLEAN,
    "bridge_mint_burn_gate_asymmetry": _MINTBURN_CLEAN,
    "bridge_nonce_order_unenforced": _NONCE_CLEAN,
    "bridge_proof_nullifier_missing": _NULLIFIER_CLEAN,
    "bridge_payload_slice_unbounded": _PAYLOAD_CLEAN,
    "uups_authorize_upgrade_missing": _UUPS_CLEAN,
    "initializer_flag_after_call": _INITFLAG_CLEAN,
    "diamond_selector_collision": _DIAMOND_CLEAN,
    "beacon_implementation_zero_accepted": _BEACON_CLEAN,
}

EXTRA_CLEAN = {
    "digest_no_binding": _DIGEST_NO_BINDING_CLEAN,
    "static_gas_computed": _GAS_COMPUTED_CLEAN,
    "initializer_modifier": _INITFLAG_MODIFIER_CLEAN,
    "diamond_no_marker": _DIAMOND_NO_MARKER_CLEAN,
}
