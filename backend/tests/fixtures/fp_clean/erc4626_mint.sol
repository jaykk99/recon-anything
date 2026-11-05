// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shape (fixed 2026-11-05): ERC4626 mint/deposit. The
// public mint pulls the caller's own assets through the
// _deposit helper before issuing shares - caller-funded
// public surface, not an ungated mint flaw.
interface IERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract FpCleanVault4626 {
    IERC20Like public asset;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(address _asset) { asset = IERC20Like(_asset); }

    function _msgSender() internal view returns (address) { return msg.sender; }

    function mint(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = shares + 1;
        _deposit(_msgSender(), receiver, assets, shares);
    }

    function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal {
        require(asset.transferFrom(caller, address(this), assets), "pull failed");
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        require(owner == msg.sender, "not owner");
        shares = assets;
        require(balanceOf[owner] >= shares, "insufficient shares");
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        require(asset.transfer(receiver, assets), "push failed");
    }
}
