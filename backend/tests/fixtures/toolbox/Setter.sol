// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SetterVault {
    address public owner;
    uint256 public fee;

    constructor() { owner = msg.sender; }

    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function setFee(uint256 newFee) public {
        fee = newFee;
    }
}
