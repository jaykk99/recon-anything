// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shapes (fixed 2026-11-05): governance vote
// delegation (_delegate writes checkpoints - NOT EIP-7702
// account delegation) and a schedule-gated governance
// mint (block.timestamp stored as the next-mint window;
// the minted amount is a caller parameter, never derived
// from the block value).
contract FpCleanVotes {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => address) public delegates;
    mapping(address => uint256) public numCheckpoints;
    address public minter;
    uint256 public mintingAllowedAfter;

    constructor() { minter = msg.sender; }

    function _mint(address account, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[account] += amount;
    }

    function _delegate(address delegator, address delegatee) internal {
        delegates[delegator] = delegatee;
        numCheckpoints[delegatee] += 1;
    }

    function delegate(address delegatee) external {
        _delegate(msg.sender, delegatee);
    }

    function mint(address dst, uint256 rawAmount) external {
        require(msg.sender == minter, "only minter");
        require(block.timestamp >= mintingAllowedAfter, "minting not allowed yet");
        mintingAllowedAfter = block.timestamp + 2592000;
        _mint(dst, rawAmount);
    }
}
