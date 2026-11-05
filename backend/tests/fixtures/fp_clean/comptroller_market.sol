// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shape (fixed 2026-11-05): Compound-style market
// mint. Execution is authorized by an external call on a
// state-held contract whose return must equal 0
// (comptroller.mintAllowed(...) == 0 required before any
// value moves).
interface IComptroller {
    function mintAllowed(address cToken, address minter, uint256 mintAmount) external returns (uint256);
}

contract FpCleanMarket {
    IComptroller public comptroller;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(address _comptroller) { comptroller = IComptroller(_comptroller); }

    function mint(address minter, uint256 mintAmount) external returns (uint256) {
        require(comptroller.mintAllowed(address(this), minter, mintAmount) == 0, "mint not allowed");
        uint256 mintTokens = mintAmount;
        totalSupply += mintTokens;
        balanceOf[minter] += mintTokens;
        return mintTokens;
    }
}
