// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Vulnerable.sol";

contract Reenterer {
    VulnerableVault public vault;
    uint256 public amount;
    bool private entered;

    constructor(VulnerableVault v) payable { vault = v; }

    function fund() public payable {
        amount = msg.value;
        vault.contribute{value: msg.value}();
    }

    function attack() public { vault.withdrawCredit(); }

    receive() external payable {
        if (!entered && amount > 0 && address(vault).balance >= amount) {
            entered = true;
            vault.withdrawCredit();
        }
    }
}

contract EchidnaHarness {
    VulnerableVault public vault;
    Reenterer public reenterer;

    constructor() payable {
        vault = new VulnerableVault();
        reenterer = new Reenterer(vault);
    }

    function seedVault() public payable {
        vault.contribute{value: msg.value}();
    }

    function fundReenterer() public payable {
        reenterer.fund{value: msg.value}();
    }

    function attack() public {
        uint256 amt = reenterer.amount();
        if (amt == 0) return;
        if (address(vault).balance < amt) return;
        uint256 beforeBal = address(vault).balance;
        reenterer.attack();
        // A safe vault pays the reenterer its credit exactly once.
        assert(address(vault).balance >= beforeBal - amt);
    }
}
