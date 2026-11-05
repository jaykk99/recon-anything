// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BaseVault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() { owner = msg.sender; }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}

contract RiskyVault is BaseVault {
    address public implementation;

    function setImplementation(address impl) public {
        implementation = impl;
    }

    function forward(bytes calldata data) public returns (bytes memory) {
        (bool ok, bytes memory ret) = implementation.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }

    function ping(address target) public {
        target.call(abi.encodeWithSignature("ping()"));
    }

    function auth() public view returns (bool) {
        return tx.origin == owner;
    }

    function kill() public {
        selfdestruct(payable(owner));
    }

    function raw() public pure returns (uint256 out) {
        assembly { out := 42 }
    }
}
