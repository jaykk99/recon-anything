"""Fixtures for the deep low-level EVM detectors (feat/deep-lowlevel-50).

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" (except the paymaster
simulator, which is simulation-only and MUST fire with
report_class "unverified" and proof "simulation_only");
CLEAN[id] (the protected shape of the same class) MUST stay
silent under ALL twelve detectors.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from app.plugins.deep_lowlevel import _rlp_encode, _keccak256  # noqa: E402

# ---------------------------------------------------------------------------
# 1. evm_cfg_basic_block_reconstructor
# ---------------------------------------------------------------------------

_CFG_VULN = """
contract VaultVuln {
    address public owner;
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount, address to) external {
        balances[msg.sender] -= amount;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "call failed");
    }
}
"""

_CFG_CLEAN = """
contract VaultClean {
    address public owner;
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount, address to) external {
        require(msg.sender == owner, "not owner");
        balances[msg.sender] -= amount;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "call failed");
    }
}
"""

_CFG_VARIANT_ELSE = """
contract VaultElse {
    address public owner;
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount, address to) external {
        if (msg.sender == owner) {
            balances[msg.sender] -= amount;
        } else {
            (bool ok, ) = to.call{value: amount}("");
            require(ok, "call failed");
        }
    }
}
"""

# ---------------------------------------------------------------------------
# 2. symbolic_z3_storage_taint_tracer
# ---------------------------------------------------------------------------

_Z3_VULN = """
contract OwnerVuln {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"""

_Z3_CLEAN = """
contract OwnerClean {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
"""

# ---------------------------------------------------------------------------
# 3. diamond_erc2535_facet_selector_tree
# ---------------------------------------------------------------------------

_DIAMOND_VULN = """
contract DiamondVuln {
    function upgrade() external {
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](2);
        cuts[0] = IDiamondCut.FacetCut({
            facetAddress: 0x1111111111111111111111111111111111111111,
            action: FacetCutAction.Add,
            functionSelectors: [bytes4(0x12345678), bytes4(0x87654321)]
        });
        cuts[1] = IDiamondCut.FacetCut({
            facetAddress: 0x2222222222222222222222222222222222222222,
            action: FacetCutAction.Add,
            functionSelectors: [bytes4(0x12345678)]
        });
        diamondCut(cuts, address(0), "");
    }
}
"""

_DIAMOND_CLEAN = """
contract DiamondClean {
    function upgrade() external {
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](2);
        cuts[0] = IDiamondCut.FacetCut({
            facetAddress: 0x1111111111111111111111111111111111111111,
            action: FacetCutAction.Add,
            functionSelectors: [bytes4(0x12345678), bytes4(0x87654321)]
        });
        cuts[1] = IDiamondCut.FacetCut({
            facetAddress: 0x2222222222222222222222222222222222222222,
            action: FacetCutAction.Add,
            functionSelectors: [bytes4(0xabcdef01)]
        });
        diamondCut(cuts, address(0), "");
    }
}
"""

# ---------------------------------------------------------------------------
# 4. transient_storage_tstore_lifecycle_auditor
# ---------------------------------------------------------------------------

_TSTORE_VULN = """
contract TransientVuln {
    function readPool() external view returns (address) {
        address pool;
        assembly {
            pool := tload(0)
        }
        return pool;
    }
}
"""

_TSTORE_CLEAN = """
contract TransientClean {
    function swap(address pool, uint256 amount) external {
        assembly {
            tstore(0, pool)
            tstore(1, amount)
        }
        address stored;
        uint256 storedAmount;
        assembly {
            stored := tload(0)
            storedAmount := tload(1)
        }
        require(stored != address(0), "no pool");
        require(storedAmount > 0, "no amount");
    }
}
"""

# ---------------------------------------------------------------------------
# 5. eof_container_code_section_verifier
# ---------------------------------------------------------------------------

# Valid EOF container: types(4) + code STOP(1).
_EOF_CLEAN = (
    "ef0001" + "010004" + "020001" + "030000" + "040000" + "00"
    + "00000000" + "00"
)
# RJUMP +16 from a 3-byte code section: target 19 is out of bounds.
_EOF_VULN = (
    "ef0001" + "010004" + "020003" + "030000" + "040000" + "00"
    + "00000000" + "5c0010"
)

# ---------------------------------------------------------------------------
# 6. erc4337_entrypoint_paymaster_simulator
# ---------------------------------------------------------------------------

_PAYMASTER_VULN = """
contract PaymasterVuln {
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        return ("", 0);
    }
}
"""

_PAYMASTER_CLEAN = """
contract PaymasterClean {
    uint256 public constant MAX_SPEND = 1 ether;
    mapping(address => uint256) public spent;

    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        require(maxCost <= MAX_SPEND, "over cap");
        require(spent[userOp.sender] + maxCost <= MAX_SPEND, "over user cap");
        require(getDeposit() >= maxCost, "deposit short");
        spent[userOp.sender] += maxCost;
        return ("", 0);
    }

    function getDeposit() public view returns (uint256) {
        return address(this).balance;
    }
}
"""

# ---------------------------------------------------------------------------
# 7. erc7579_modular_account_hook_inspector
# ---------------------------------------------------------------------------

_HOOK_VULN = """
contract AccountVuln {
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external {
        IModule(module).onInstall(initData);
    }

    function preCheck(address account, uint256 value) external returns (bytes memory) {
        return "";
    }
}
"""

_HOOK_CLEAN = """
contract AccountClean {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external onlyOwner {
        require(module != address(0), "zero module");
        IModule(module).onInstall(initData);
    }

    function preCheck(address account, uint256 value) external returns (bytes memory) {
        require(account != address(0), "zero account");
        require(value > 0, "zero value");
        return "";
    }
}
"""

# ---------------------------------------------------------------------------
# 8. zk_snark_verifier_vk_parameter_auditor
# ---------------------------------------------------------------------------

_VK_VULN = """
contract VerifierVuln {
    uint256 constant alpha = 0;
    uint256 constant beta = 123456789;
    uint256 constant gamma = 987654321;
    uint256 constant delta = 555555555;

    function verifyProof(uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[1] memory input) public view returns (bool) {
        return true;
    }
}
"""

_VK_CLEAN = """
contract VerifierClean {
    uint256 constant alpha = 12345678901234567890;
    uint256 constant beta = 98765432109876543210;
    uint256 constant gamma = 55555555555555555555;
    uint256 constant delta = 11111111111111111111;

    function verifyProof(uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[1] memory input) public view returns (bool) {
        require(alpha != 0, "bad vk");
        require(beta != 0, "bad vk");
        return _verify(a, b, c, input, alpha, beta, gamma, delta);
    }

    function _verify(uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[1] memory input, uint256 alpha, uint256 beta, uint256 gamma, uint256 delta) internal view returns (bool) {
        return true;
    }
}
"""

# ---------------------------------------------------------------------------
# 9. circom_r1cs_underconstrained_wire_checker
# ---------------------------------------------------------------------------

_R1CS_VULN = """
pragma circom 2.0.0;

template MulVuln() {
    signal input a;
    signal input b;
    signal output out;
    signal tmp;

    tmp <-- a * b;
    out <== tmp;
}

component main = MulVuln();
"""

_R1CS_CLEAN = """
pragma circom 2.0.0;

template MulClean() {
    signal input a;
    signal input b;
    signal output out;

    out <== a * b;
}

component main = MulClean();
"""

# ---------------------------------------------------------------------------
# 10. halo2_lookup_table_range_profiler
# ---------------------------------------------------------------------------

_HALO2_VULN = """
fn lookup_u16(config: &Config, value: u16) {
    let range = 0..255;
    let table = config.assign_fixed(range);
    let queried: u16 = value;
    config.lookup_any(queried, table);
}
"""

_HALO2_CLEAN = """
fn lookup_u16(config: &Config, value: u16) {
    let range = 0..65535;
    let table = config.assign_fixed(range);
    let queried: u16 = value;
    config.lookup_any(queried, table);
}
"""

# ---------------------------------------------------------------------------
# 11. gnosis_safe_fallback_handler_mutator_check
# ---------------------------------------------------------------------------

_SAFE_VULN = """
contract SafeVuln {
    address public fallbackHandler;

    function setFallbackHandler(address handler) external {
        fallbackHandler = handler;
    }
}
"""

_SAFE_CLEAN = """
contract SafeClean {
    address public fallbackHandler;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setFallbackHandler(address handler) external onlyOwner {
        require(handler != address(0), "zero handler");
        fallbackHandler = handler;
    }
}
"""

# ---------------------------------------------------------------------------
# 12. merkle_patricia_trie_state_proof_verifier
# ---------------------------------------------------------------------------

_MPT_KEY = bytes([0x12])
_MPT_VALUE = b"hello"
_MPT_LEAF = _rlp_encode([bytes([0x20, 0x12]), _MPT_VALUE])
_MPT_ROOT = _keccak256(_MPT_LEAF) if len(_MPT_LEAF) >= 32 else _MPT_LEAF

_MPT_CLEAN = {
    "root": _MPT_ROOT.hex(),
    "key": _MPT_KEY.hex(),
    "proof": [_MPT_LEAF.hex()],
    "expected_value": _MPT_VALUE.hex(),
}
_MPT_VULN = dict(_MPT_CLEAN)
_MPT_VULN["expected_value"] = b"hellx".hex()

VULN = {
    "evm_cfg_basic_block_reconstructor": _CFG_VULN,
    "symbolic_z3_storage_taint_tracer": _Z3_VULN,
    "diamond_erc2535_facet_selector_tree": _DIAMOND_VULN,
    "transient_storage_tstore_lifecycle_auditor": _TSTORE_VULN,
    "eof_container_code_section_verifier": _EOF_VULN,
    "erc4337_entrypoint_paymaster_simulator": _PAYMASTER_VULN,
    "erc7579_modular_account_hook_inspector": _HOOK_VULN,
    "zk_snark_verifier_vk_parameter_auditor": _VK_VULN,
    "circom_r1cs_underconstrained_wire_checker": _R1CS_VULN,
    "halo2_lookup_table_range_profiler": _HALO2_VULN,
    "gnosis_safe_fallback_handler_mutator_check": _SAFE_VULN,
    "merkle_patricia_trie_state_proof_verifier": __import__("json").dumps(_MPT_VULN),
}

CLEAN = {
    "evm_cfg_basic_block_reconstructor": _CFG_CLEAN,
    "symbolic_z3_storage_taint_tracer": _Z3_CLEAN,
    "diamond_erc2535_facet_selector_tree": _DIAMOND_CLEAN,
    "transient_storage_tstore_lifecycle_auditor": _TSTORE_CLEAN,
    "eof_container_code_section_verifier": _EOF_CLEAN,
    "erc4337_entrypoint_paymaster_simulator": _PAYMASTER_CLEAN,
    "erc7579_modular_account_hook_inspector": _HOOK_CLEAN,
    "zk_snark_verifier_vk_parameter_auditor": _VK_CLEAN,
    "circom_r1cs_underconstrained_wire_checker": _R1CS_CLEAN,
    "halo2_lookup_table_range_profiler": _HALO2_CLEAN,
    "gnosis_safe_fallback_handler_mutator_check": _SAFE_CLEAN,
    "merkle_patricia_trie_state_proof_verifier": __import__("json").dumps(_MPT_CLEAN),
}

# The else-branch CFG shape: a guard in the if branch, the
# value-moving op in the else branch. Must fire as a candidate.
VARIANT = {
    "evm_cfg_basic_block_reconstructor": _CFG_VARIANT_ELSE,
}
