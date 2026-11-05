// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Tiny live-run canary for the Mythril adapter: an unguarded
// selfdestruct is the smallest search space that still exercises
// real symbolic execution (Mythril must reach kill() and report
// SWC-106). The full Vulnerable.sol fixture takes minutes under
// Mythril; this one completes in seconds-to-a-minute.
contract MythrilCanary {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
