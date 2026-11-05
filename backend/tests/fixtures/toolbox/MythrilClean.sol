// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Clean control for the Mythril adapter live test: the same
// selfdestruct, properly owner-gated. Mythril must NOT report
// SWC-106 (unprotected selfdestruct) for it.
contract MythrilClean {
    address public owner;

    constructor() { owner = msg.sender; }

    function kill() public {
        require(msg.sender == owner, "not owner");
        selfdestruct(payable(owner));
    }
}
