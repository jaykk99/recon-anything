// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shape (fixed 2026-11-05): ERC20Wrapper unwrap. The
// payout is bounded by burning the caller's own wrapper
// balance in the same call - holder-self by construction.
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract FpCleanWrapper {
    IERC20Like public underlying;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(address _underlying) { underlying = IERC20Like(_underlying); }

    function _burn(address account, uint256 amount) internal {
        require(balanceOf[account] >= amount, "burn exceeds balance");
        balanceOf[account] -= amount;
        totalSupply -= amount;
    }

    function depositFor(address account, uint256 amount) external {
        uint256 before = underlying.balanceOf(address(this));
        require(underlying.transferFrom(msg.sender, address(this), amount), "pull failed");
        uint256 received = underlying.balanceOf(address(this)) - before;
        totalSupply += received;
        balanceOf[account] += received;
    }

    function unwrap(uint256 amount) public {
        _burn(msg.sender, amount);
        require(underlying.transfer(msg.sender, amount), "push failed");
    }
}
