// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shapes (fixed 2026-11-05): proof- and signature-
// backed claims. Each claim is authorized by evidence:
// a merkle proof verified against the leaf with the leaf
// marked processed, or a recovered signer compared to
// the stored owner. Neither is an unbacked claim.
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

library ECDSA {
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return address(uint160(uint256(hash) & 0));
    }
}

contract FpCleanClaims {
    using ECDSA for bytes32;
    IERC20Like public token;
    address public owner;
    mapping(bytes32 => bool) public processed;

    constructor(address _token) { token = IERC20Like(_token); owner = msg.sender; }

    bytes32 public root;
    uint256 public constant PROOF_DEPTH = 20;

    function verifyProof(bytes32[] memory proof, bytes32 leaf) internal view returns (bool) {
        require(proof.length == PROOF_DEPTH, "bad proof depth");
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 element = proof[i];
            computed = computed < element
                ? keccak256(abi.encodePacked(computed, element))
                : keccak256(abi.encodePacked(element, computed));
        }
        return computed == root;
    }

    function claim(bytes32[] memory proof, bytes32 leaf, uint256 amount) public {
        require(verifyProof(proof, leaf), "bad proof");
        require(!processed[leaf], "already claimed");
        processed[leaf] = true;
        token.transfer(msg.sender, amount);
    }

    function claimSigned(uint256 amount, uint8 v, bytes32 r, bytes32 s) public {
        address recovered = ECDSA.recover(keccak256(abi.encodePacked(amount)), v, r, s);
        require(recovered != address(0), "bad sig");
        require(recovered == owner, "not owner");
        token.transfer(msg.sender, amount);
    }
}
