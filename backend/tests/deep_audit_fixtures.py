"""Fixtures for the deep-audit detectors (AI dev day 1).

Per plugin id: VULN[id] MUST fire with its own finding kind and
code evidence; CLEAN[id] (the protected shape of the same class)
MUST stay silent under ALL five detectors.
"""

_VAULT_VULN = """
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableVault {
    IERC20 public asset;
    uint256 public totalShares;
    mapping(address => uint256) public balanceOf;

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) {
            return assets;
        }
        return (assets * supply) / totalAssets();
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = convertToShares(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        totalShares += shares;
        balanceOf[msg.sender] += shares;
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        assets = (shares * totalAssets()) / totalShares;
        balanceOf[msg.sender] -= shares;
        totalShares -= shares;
        asset.transfer(msg.sender, assets);
    }
}
"""

_VAULT_CLEAN = """
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract ProtectedVault {
    IERC20 public asset;
    uint256 public totalShares;
    mapping(address => uint256) public balanceOf;

    constructor(address _asset) {
        asset = IERC20(_asset);
    }

    function _decimalsOffset() internal pure returns (uint8) {
        return 6;
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    function _convertToShares(uint256 assets) internal view returns (uint256) {
        return (assets * (totalShares + 10 ** _decimalsOffset())) / (totalAssets() + 1);
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = _convertToShares(assets);
        require(shares > 0, "zero shares");
        asset.transferFrom(msg.sender, address(this), assets);
        totalShares += shares;
        balanceOf[msg.sender] += shares;
    }

    function redeem(uint256 shares) external returns (uint256 assets) {
        assets = (shares * (totalAssets() + 1)) / (totalShares + 10 ** _decimalsOffset());
        balanceOf[msg.sender] -= shares;
        totalShares -= shares;
        asset.transfer(msg.sender, assets);
    }
}
"""

_POOL_VULN = """
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract VulnerablePool {
    bool private _locked;
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalShares;
    IERC20 public token;
    address public owner;

    modifier nonReentrant() {
        require(!_locked, "locked");
        _locked = true;
        _;
        _locked = false;
    }

    function withdraw(uint256 amount) external nonReentrant {
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function collectFees(uint256 fee) external {
        token.transfer(owner, fee);
    }

    function getVirtualPrice() external view returns (uint256) {
        return ((reserve0 + reserve1) * 1e18) / totalShares;
    }
}
"""

_POOL_CLEAN = """
contract ProtectedPool {
    bool private _locked;
    uint256 public reserve0;
    uint256 public reserve1;
    uint256 public totalShares;

    modifier nonReentrant() {
        require(!_locked, "locked");
        _locked = true;
        _;
        _locked = false;
    }

    function withdraw(uint256 amount) external nonReentrant {
        payable(msg.sender).transfer(amount);
    }

    function getVirtualPrice() external view nonReentrant returns (uint256) {
        return ((reserve0 + reserve1) * 1e18) / totalShares;
    }

    function quoteFee(uint256 amount) external pure returns (uint256) {
        return (amount * 3) / 100;
    }
}
"""

_DIAMOND_VULN = """
contract VulnerableDiamond {
    mapping(bytes4 => address) public selectorToFacet;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function diamondCut(bytes4[] calldata selectors, address facet) external {
        for (uint256 i = 0; i < selectors.length; i++) {
            selectorToFacet[selectors[i]] = facet;
        }
    }

    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
        require(facet != address(0), "no facet");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
"""

_DIAMOND_CLEAN = """
library LibDiamond {
    struct DiamondStorage {
        address contractOwner;
        mapping(bytes4 => address) selectorToFacet;
    }

    function diamondStorage() internal pure returns (DiamondStorage storage ds) {
        bytes32 position = keccak256("diamond.standard.diamond.storage");
        assembly { ds.slot := position }
    }

    function enforceIsContractOwner() internal view {
        require(msg.sender == diamondStorage().contractOwner, "LibDiamond: Must be contract owner");
    }

    function diamondCut(address facet, bytes4[] memory selectors) internal {
        enforceIsContractOwner();
        DiamondStorage storage ds = diamondStorage();
        for (uint256 i = 0; i < selectors.length; i++) {
            ds.selectorToFacet[selectors[i]] = facet;
        }
    }
}

contract ProtectedDiamondCutFacet {
    function diamondCut(address facet, bytes4[] calldata selectors) external {
        LibDiamond.diamondCut(facet, selectors);
    }
}
"""

_AA_COMMON = """
struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        return address(0);
    }
}
"""

_AA_VULN = _AA_COMMON + """
contract VulnerableAccount {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) external returns (uint256) {
        return 0;
    }

    function execute(address dest, uint256 value, bytes calldata func) external {
        (bool ok, ) = dest.call{value: value}(func);
        require(ok, "execution failed");
    }
}

contract VulnerablePaymaster {
    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost) external returns (bytes memory context, uint256 validationData) {
        return ("", 0);
    }
}
"""

_AA_CLEAN = _AA_COMMON + """
interface IEntryPoint {
}

contract ProtectedAccount {
    address public owner;
    IEntryPoint public entryPoint;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    constructor(address _owner, address _entryPoint) {
        owner = _owner;
        entryPoint = IEntryPoint(_entryPoint);
    }

    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) external returns (uint256) {
        _requireFromEntryPoint();
        return _validateSignature(userOp, userOpHash);
    }

    function _requireFromEntryPoint() internal view {
        require(msg.sender == address(entryPoint), "not from EntryPoint");
    }

    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash) internal view returns (uint256) {
        address recovered = ECDSA.recover(userOpHash, userOp.signature);
        if (recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }
}

contract ProtectedPaymaster {
    IEntryPoint public entryPoint;
    address public verifyingSigner;

    constructor(address _entryPoint, address _signer) {
        entryPoint = IEntryPoint(_entryPoint);
        verifyingSigner = _signer;
    }

    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost) external returns (bytes memory context, uint256 validationData) {
        require(msg.sender == address(entryPoint), "not from EntryPoint");
        address recovered = ECDSA.recover(userOpHash, userOp.signature);
        require(recovered == verifyingSigner, "invalid signature");
        return ("", 0);
    }
}
"""

_ECRECOVER_VULN = """
contract VulnerableClaim {
    address public signer;
    mapping(address => bool) public claimed;

    function setSigner(address _signer) external {
        signer = _signer;
    }

    function claim(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        address recovered = ecrecover(hash, v, r, s);
        require(recovered == signer, "bad signature");
        claimed[msg.sender] = true;
        payable(msg.sender).transfer(1 ether);
    }
}
"""

_ECRECOVER_CLEAN = """
library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        return address(0);
    }
}

contract ProtectedClaim {
    address public signer;
    mapping(address => bool) public claimed;

    function claim(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
        address recovered = ecrecover(hash, v, r, s);
        require(recovered != address(0), "invalid signature");
        require(recovered == signer, "bad signature");
        claimed[msg.sender] = true;
        payable(msg.sender).transfer(1 ether);
    }
}

contract ProtectedClaimECDSA {
    address public signer;

    function claim(bytes32 hash, bytes memory signature) external {
        address recovered = ECDSA.recover(hash, signature);
        require(recovered == signer, "bad signature");
    }
}

contract OZStyleRecover {
    // OpenZeppelin ECDSA shape: raw ecrecover with the
    // zero-address rejection written as an == comparison in
    // an if with an early return. Must stay silent (this is
    // the exact shape that false-fired on real OZ library
    // code during the day-1 corpus run).
    function tryRecover(bytes32 hash, uint8 v, bytes32 r,
                        bytes32 s) internal pure
        returns (address) {
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return address(0);
        }
        return signer;
    }
}
"""

VULN = {
    "vault_share_inflation": _VAULT_VULN,
    "readonly_reentrancy_gap": _POOL_VULN,
    "diamond_cut_ungated": _DIAMOND_VULN,
    "aa_validation_ungated": _AA_VULN,
    "ecrecover_zero_signer": _ECRECOVER_VULN,
}

CLEAN = {
    "vault_share_inflation": _VAULT_CLEAN,
    "readonly_reentrancy_gap": _POOL_CLEAN,
    "diamond_cut_ungated": _DIAMOND_CLEAN,
    "aa_validation_ungated": _AA_CLEAN,
    "ecrecover_zero_signer": _ECRECOVER_CLEAN,
}
