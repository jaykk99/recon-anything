// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// Canary fixture adapted from DeFiVulnLabs (SunWeb3Sec), MIT License,
// https://github.com/SunWeb3Sec/DeFiVulnLabs pinned at commit
// e762f04b3856d2e649f58335a6586d, src/test/Reentrancy.sol.
// The EtherStore (vulnerable) and EtherStoreRemediated contracts are
// reproduced verbatim; the forge-std test harness around them is
// dropped so the file compiles standalone. Used as an extra
// reentrancy canary for the toolbox lanes (Slither must flag
// EtherStore.withdrawFunds and stay quiet on the remediated twin).

contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public {
        require(balances[msg.sender] >= _weiToWithdraw);
        (bool send, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(send, "send failed");

        // check if after send still enough to avoid underflow
        if (balances[msg.sender] >= _weiToWithdraw) {
            balances[msg.sender] -= _weiToWithdraw;
        }
    }
}

contract EtherStoreRemediated {
    mapping(address => uint256) public balances;
    bool internal locked;

    modifier nonReentrant() {
        require(!locked, "No re-entrancy");
        locked = true;
        _;
        locked = false;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawFunds(uint256 _weiToWithdraw) public nonReentrant {
        require(balances[msg.sender] >= _weiToWithdraw);
        balances[msg.sender] -= _weiToWithdraw;
        (bool send, ) = msg.sender.call{value: _weiToWithdraw}("");
        require(send, "send failed");
    }
}
