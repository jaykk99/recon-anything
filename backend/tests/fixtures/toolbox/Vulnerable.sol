// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public contributions;

    constructor() { owner = msg.sender; }

    function contribute() public payable {
        contributions[msg.sender] += msg.value;
        if (contributions[msg.sender] > contributions[owner]) {
            owner = msg.sender;
        }
    }

    receive() external payable {
        require(msg.value > 0);
        owner = msg.sender;
    }

    function withdraw() public {
        require(tx.origin == owner);
        payable(msg.sender).transfer(address(this).balance);
    }

    function withdrawCredit() public {
        uint256 amount = contributions[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        contributions[msg.sender] = 0;
    }

    function mint(address to, uint256 amount) public {
        contributions[to] += amount;
    }

    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
