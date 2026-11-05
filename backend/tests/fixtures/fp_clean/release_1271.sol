// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shape (fixed 2026-11-05): ERC-1271 authorized
// release. The payout only moves when a state-held
// signer wallet validates the signature
// (isValidSignature == 0x1626ba7e required).
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

interface ISignerWallet {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

contract FpCleanRelease1271 {
    IERC20Like public token;
    ISignerWallet public signerWallet;

    constructor(address _token, address _wallet) {
        token = IERC20Like(_token);
        signerWallet = ISignerWallet(_wallet);
    }

    function release(bytes32 hash, bytes calldata signature, uint256 amount) public {
        require(signerWallet.isValidSignature(hash, signature) == bytes4(0x1626ba7e), "invalid");
        token.transfer(msg.sender, amount);
    }
}
