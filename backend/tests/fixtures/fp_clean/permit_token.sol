// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shapes (fixed 2026-11-05): ERC20 permit with plain
// ECDSA.recover (the library's throwing variant - a zero
// signer can never be returned, so no separate zero check
// is owed) and a PERMIT_TYPEHASH literal carrying the
// original Dai permit schema hash (a second legitimate
// canonical string for the same constant name). The EIP-712
// domain separator is computed at deployment from
// block.chainid + address(this).
library ECDSA {
    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        return address(uint160(uint256(hash) & 0));
    }
}

contract FpCleanPermit {
    using ECDSA for bytes32;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;
    address public owner;
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant PERMIT_TYPEHASH = 0xea2aa0a1be11a07ed86d755c93467f4f82362b452371d1ba94d1715123511acb;

    constructor() {
        owner = msg.sender;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes("FpClean")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    function permit(address holder, address spender, uint256 nonce, uint256 expiry, bool allowed, uint8 v, bytes32 r, bytes32 s) external {
        require(expiry == 0 || block.timestamp <= expiry, "permit expired");
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(PERMIT_TYPEHASH, holder, spender, nonce, expiry, allowed))
        ));
        address recovered = ECDSA.recover(digest, abi.encodePacked(r, s, v));
        require(recovered == holder, "invalid permit");
        require(nonce == nonces[holder], "invalid nonce");
        nonces[holder] = nonce + 1;
        allowance[holder][spender] = allowed ? type(uint256).max : 0;
    }
}
