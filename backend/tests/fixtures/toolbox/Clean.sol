// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CleanVault {
    address public owner;
    mapping(address => uint256) public balances;
    bool private locked;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier nonReentrant() {
        require(!locked, "reentrant");
        locked = true;
        _;
        locked = false;
    }

    constructor() { owner = msg.sender; }

    function deposit() public payable { balances[msg.sender] += msg.value; }

    function withdrawCredit() public nonReentrant {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
    }

    function sweep() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
