"""Fixtures for the deep-audit batch-19 detectors.

Per plugin id: VULN[id] MUST fire with its own finding kind,
code evidence, and report_class "candidate" (the three
recipient-classified detectors); CLEAN[id] (the protected shape
of the same class) MUST stay silent under ALL four detectors;
VARIANT[id] carries the same vulnerable shape but the value
lands at a FIXED destination, so it MUST fire with
report_class "trigger_only" at low severity - never a
candidate. weak_onchain_randomness has no recipient (no value
moves in the function), so it fires with no report_class.

Cross-talk by construction: the malleability fixture consumes
a nonce (silent under the replay detector) but has no s bound;
the replay fixture bounds s (silent under the malleability
detector) but consumes no nonce; the permit fixture bounds s
AND consumes a nonce (silent under both) but builds its digest
with no domain separator; the randomness fixture touches no
signatures at all.
"""

_TOKEN_IFACE = """
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
"""

_HALF_N = ("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
           "5D576E7357A4501DDFE92F46681B20A0")

# ---------------------------------------------------------------------------
# 1. ecrecover_no_malleability_guard
# ---------------------------------------------------------------------------

_MALLEABILITY_VULN = _TOKEN_IFACE + f"""
contract ClaimVaultVuln {{
    IERC20Like public token;
    address public authorized;
    mapping(address => uint256) public nonces;

    constructor(address _token, address _auth) {{
        token = IERC20Like(_token);
        authorized = _auth;
    }}

    function claim(uint256 amount, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {{
        address signer = ecrecover(hash, v, r, s);
        require(signer == authorized, "bad sig");
        nonces[msg.sender]++;
        token.transfer(msg.sender, amount);
    }}
}}
"""

_MALLEABILITY_VARIANT = _TOKEN_IFACE + """
contract ClaimVaultFixed {
    IERC20Like public token;
    address public authorized;
    address public owner;
    mapping(address => uint256) public nonces;

    constructor(address _token, address _auth) {
        token = IERC20Like(_token);
        authorized = _auth;
        owner = msg.sender;
    }

    function claim(uint256 amount, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(hash, v, r, s);
        require(signer == authorized, "bad sig");
        nonces[msg.sender]++;
        token.transfer(owner, amount);
    }
}
"""

_MALLEABILITY_CLEAN = _TOKEN_IFACE + f"""
contract ClaimVaultClean {{
    IERC20Like public token;
    address public authorized;
    mapping(address => uint256) public nonces;

    constructor(address _token, address _auth) {{
        token = IERC20Like(_token);
        authorized = _auth;
    }}

    function claim(uint256 amount, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {{
        require(s <= {_HALF_N}, "bad s");
        address signer = ecrecover(hash, v, r, s);
        require(signer == authorized, "bad sig");
        nonces[msg.sender]++;
        token.transfer(msg.sender, amount);
    }}
}}
"""

# ---------------------------------------------------------------------------
# 2. signature_replay_no_nonce
# ---------------------------------------------------------------------------

_REPLAY_VULN = _TOKEN_IFACE + f"""
contract ReplayVaultVuln {{
    IERC20Like public token;
    address public authorized;

    constructor(address _token, address _auth) {{
        token = IERC20Like(_token);
        authorized = _auth;
    }}

    function claim(uint256 amount, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {{
        require(s <= {_HALF_N}, "bad s");
        address signer = ecrecover(hash, v, r, s);
        require(signer == authorized, "bad sig");
        token.transfer(msg.sender, amount);
    }}
}}
"""

_REPLAY_VARIANT = _TOKEN_IFACE + f"""
contract ReplayVaultFixed {{
    IERC20Like public token;
    address public authorized;
    address public owner;

    constructor(address _token, address _auth) {{
        token = IERC20Like(_token);
        authorized = _auth;
        owner = msg.sender;
    }}

    function claim(uint256 amount, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {{
        require(s <= {_HALF_N}, "bad s");
        address signer = ecrecover(hash, v, r, s);
        require(signer == authorized, "bad sig");
        token.transfer(owner, amount);
    }}
}}
"""

_REPLAY_CLEAN = _TOKEN_IFACE + f"""
contract ReplayVaultClean {{
    IERC20Like public token;
    address public authorized;
    mapping(address => uint256) public nonces;

    constructor(address _token, address _auth) {{
        token = IERC20Like(_token);
        authorized = _auth;
    }}

    function claim(uint256 amount, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {{
        require(s <= {_HALF_N}, "bad s");
        address signer = ecrecover(hash, v, r, s);
        require(signer == authorized, "bad sig");
        nonces[msg.sender]++;
        token.transfer(msg.sender, amount);
    }}
}}
"""

# ---------------------------------------------------------------------------
# 3. permit_no_domain_separator
# ---------------------------------------------------------------------------

_PERMIT_VULN = _TOKEN_IFACE + f"""
contract PermitTokenVuln {{
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {{
        require(s <= {_HALF_N}, "bad s");
        bytes32 digest = keccak256(abi.encodePacked(owner, spender, value, deadline));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "bad sig");
        nonces[owner]++;
        allowance[owner][spender] = value;
    }}
}}
"""

_PERMIT_CLEAN = _TOKEN_IFACE + f"""
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract PermitTokenClean is EIP712 {{
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    constructor() EIP712("PermitToken", "1") {{}}

    function DOMAIN_SEPARATOR() external view returns (bytes32) {{
        return _domainSeparatorV4();
    }}

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {{
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)));
        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == owner, "bad sig");
        require(block.chainid == 1, "wrong chain");
        allowance[owner][spender] = value;
    }}
}}
"""

# ---------------------------------------------------------------------------
# 4. weak_onchain_randomness
# ---------------------------------------------------------------------------

_RANDOMNESS_VULN = """
contract LotteryVuln {
    address[] public entries;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function enter() external payable {
        entries.push(msg.sender);
    }

    function drawWinner() external {
        uint256 random = uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty, msg.sender))) % entries.length;
        address winner = entries[random];
        payable(winner).transfer(address(this).balance);
    }
}
"""

_RANDOMNESS_CLEAN = """
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";

contract LotteryClean is VRFConsumerBaseV2 {
    address[] public entries;
    uint256 public lastRequestId;

    constructor(address vrfCoordinator) VRFConsumerBaseV2(vrfCoordinator) {}

    function enter() external payable {
        entries.push(msg.sender);
    }

    function requestWinner() external {
        lastRequestId = 1;
    }

    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {
        uint256 random = randomWords[0] % entries.length;
        address winner = entries[random];
        payable(winner).transfer(address(this).balance);
    }
}
"""

VULN = {
    "ecrecover_no_malleability_guard": _MALLEABILITY_VULN,
    "signature_replay_no_nonce": _REPLAY_VULN,
    "permit_no_domain_separator": _PERMIT_VULN,
    "weak_onchain_randomness": _RANDOMNESS_VULN,
}

CLEAN = {
    "ecrecover_no_malleability_guard": _MALLEABILITY_CLEAN,
    "signature_replay_no_nonce": _REPLAY_CLEAN,
    "permit_no_domain_separator": _PERMIT_CLEAN,
    "weak_onchain_randomness": _RANDOMNESS_CLEAN,
}

VARIANT = {
    "ecrecover_no_malleability_guard": _MALLEABILITY_VARIANT,
    "signature_replay_no_nonce": _REPLAY_VARIANT,
}

# Extra clean shapes (not the primary CLEAN control, asserted
# silent under ALL four detectors as well).
EXTRA_CLEAN = {
    # OZ ECDSA + EIP-712 + VRF together: every protected shape
    # at once. Nothing here may fire any batch-19 detector.
    "oz_ecdsa_eip712_vrf_kitchen_sink": _TOKEN_IFACE + f"""
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";

contract KitchenSinkClean is EIP712, VRFConsumerBaseV2 {{
    IERC20Like public token;
    mapping(address => uint256) public nonces;
    address[] public entries;

    constructor(address _token, address vrfCoordinator) EIP712("Sink", "1") VRFConsumerBaseV2(vrfCoordinator) {{
        token = IERC20Like(_token);
    }}

    function claim(uint256 amount, bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {{
        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == msg.sender, "bad sig");
        nonces[msg.sender]++;
        token.transfer(msg.sender, amount);
    }}

    function fulfillRandomWords(uint256 requestId, uint256[] memory randomWords) internal override {{
        uint256 random = randomWords[0] % entries.length;
        address winner = entries[random];
        payable(winner).transfer(address(this).balance);
    }}
}}
""",
    # block.timestamp used only for deadline / lock checks: not
    # randomness, must stay silent under the randomness detector.
    "timestamp_deadline_only": """
contract TimelockClean {
    uint256 public unlockTime;
    address public owner;

    constructor(uint256 _unlockTime) {
        unlockTime = _unlockTime;
        owner = msg.sender;
    }

    function withdraw() external {
        require(block.timestamp >= unlockTime, "locked");
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }

    function extend(uint256 extra) external {
        require(block.timestamp < unlockTime, "already unlocked");
        unlockTime += extra;
    }
}
""",
    # Live-run FP pins (2026-11-12 corpus): each of these fired
    # under a batch-19 detector on a real contract and was
    # hand-read as a false positive. All five must stay silent
    # under ALL four detectors.
    # Axelar BurnableMintableCappedERC20 permit: the s bound is
    # spelled `if (uint256(s) > HALF) revert InvalidS();` — a
    # cast-wrapped comparison the plain `s <= 0x7f` spellings miss.
    "cast_wrapped_s_guard": _TOKEN_IFACE + f"""
contract AxelarStylePermit {{
    IERC20Like public token;
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;

    function permit(address issuer, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {{
        if (block.timestamp > deadline) revert PermitExpired();
        if (uint256(s) > {_HALF_N}) revert InvalidS();
        if (v != 27 && v != 28) revert InvalidV();
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), DOMAIN_SEPARATOR, keccak256(abi.encode(keccak256("Permit(address issuer,address spender,uint256 value,uint256 nonce,uint256 deadline)"), issuer, spender, value, nonces[issuer]++, deadline))));
        address recoveredAddress = ecrecover(digest, v, r, s);
        if (recoveredAddress != issuer) revert InvalidSignature();
        token.transferFrom(issuer, spender, value);
    }}
}}
""",
    # BoldToken (Liquity v2) permit: the recovery is
    # `ECDSA.recover(...)` with no import line in the flattened
    # source and no s bound in the function — the OZ call itself
    # enforces the bound, so the raw-ecrecover shape must not fire.
    "ecdsa_recover_no_import": _TOKEN_IFACE + f"""
contract BoldStylePermit {{
    IERC20Like public token;
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {{
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), DOMAIN_SEPARATOR, keccak256(abi.encode(keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"), owner, spender, value, nonces[owner]++, deadline))));
        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == owner, "bad sig");
        token.transferFrom(owner, spender, value);
    }}
}}
""",
    # dYdX permit: the nonce is consumed by a read-into-local +
    # write-back (`_nonces[owner] = currentValidNonce.add(1)`),
    # not a `nonces[owner]++` — and the mapping name has a
    # leading underscore, which `\\bnonces` never matches.
    "nonce_writeback_add": _TOKEN_IFACE + f"""
contract DydxStylePermit {{
    IERC20Like public token;
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public _nonces;

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {{
        require(owner != address(0), "INVALID_OWNER");
        require(block.timestamp <= deadline, "INVALID_EXPIRATION");
        require(s <= {_HALF_N}, "bad s");
        uint256 currentValidNonce = _nonces[owner];
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), DOMAIN_SEPARATOR, keccak256(abi.encode(keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"), owner, spender, value, currentValidNonce, deadline))));
        require(owner == ecrecover(digest, v, r, s), "INVALID_SIGNATURE");
        _nonces[owner] = currentValidNonce.add(1);
        token.transferFrom(owner, spender, value);
    }}
}}
""",
    # WrappedLYX bridge mint: the nonce is a boolean `_nonces`
    # mapping (`require(_nonces[bridgeNonce] == false)` then
    # `_nonces[bridgeNonce] = true`), recovered via ECDSA.recover.
    "underscore_nonces_mark": _TOKEN_IFACE + """
contract LyxStyleMint {
    IERC20Like public token;
    address public _operator;
    mapping(uint256 => bool) public _nonces;

    function mint(uint256 value, uint256 bridgeNonce, address recipient, uint8 v, bytes32 r, bytes32 s) external {
        require(_nonces[bridgeNonce] == false, "Nonce already used");
        require(ECDSA.recover(keccak256(abi.encodePacked(value, recipient, bridgeNonce)), v, r, s) == _operator, "Signature verification failure");
        _nonces[bridgeNonce] = true;
        token.transfer(recipient, value);
    }
}
""",
    # Dollar permit: the domain binding is
    # `LibEIP712.hashEIP712Message(EIP712_DOMAIN_SEPARATOR, ...)`
    # — `\\bDOMAIN_SEPARATOR\\b` never matches inside the
    # `EIP712_`-prefixed identifier.
    "eip712_domain_separator_const": _TOKEN_IFACE + f"""
contract DollarStylePermit {{
    IERC20Like public token;
    bytes32 public EIP712_DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {{
        require(s <= {_HALF_N}, "bad s");
        bytes32 digest = LibEIP712.hashEIP712Message(EIP712_DOMAIN_SEPARATOR, keccak256(abi.encode(keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"), owner, spender, value, nonces[owner]++, deadline)));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered == owner, "bad sig");
        token.transferFrom(owner, spender, value);
    }}
}}
""",
    # Cast-wrapped s guard, `s` spelled `_s` (VerseToken permit:
    # `if (uint256(_s) > HALF) ...` — the plain `s` spelling misses it).
    "cast_wrapped_s_guard_underscore": _TOKEN_IFACE + f"""
contract VerseStylePermit {{
    IERC20Like public token;
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public nonces;

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 _s) external {{
        if (block.timestamp > deadline) revert PermitExpired();
        if (uint256(_s) > {_HALF_N}) revert InvalidS();
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), DOMAIN_SEPARATOR, keccak256(abi.encode(keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"), owner, spender, value, nonces[owner]++, deadline))));
        address recoveredAddress = ecrecover(digest, v, r, _s);
        if (recoveredAddress != owner) revert InvalidSignature();
        token.transferFrom(owner, spender, value);
    }}
}}
""",
}
