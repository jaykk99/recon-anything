"""Loop fixtures: one planted-vuln vault, one clean canonical token.

VAULT_VULN_SOURCE - share inflation + missing gate. deposit() mints
shares against the vault balance, donate() lets anyone inflate that
balance (so the next depositor's shares round to ~0), and
withdrawAll() sends the vault's full balance to the caller with no
access control at all. The loop must take this from flag to verdict
with a pack.

WETH9_SOURCE - canonical WETH9 shape (deposit / withdraw against the
caller's own recorded balance, ERC20 transfer/approve). Every payout
is metered by the caller's own balance, so the loop must close it
with zero validator candidates.
"""
from __future__ import annotations

VAULT_VULN_SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// InflatableVault: planted-vuln fixture for the investigator loop.
/// - deposit() mints shares priced off address(this).balance.
/// - donate() inflates that balance with no shares issued (share
///   inflation: the next depositor's shares round down to ~0).
/// - withdrawAll() pays the vault's FULL balance to the caller with
///   no access control (missing gate).
contract InflatableVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        uint256 s;
        if (totalShares == 0) {
            s = msg.value;
        } else {
            s = msg.value * totalShares / address(this).balance;
        }
        shares[msg.sender] += s;
        totalShares += s;
    }

    function donate() external payable {
    }

    function withdrawAll() external {
        uint256 amount = address(this).balance;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
"""

WETH9_SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// Canonical WETH9 shape: every payout is metered by the caller's own
/// recorded balance. No ungated drain exists.
contract WETH9 {
    string public name = "Wrapped Ether";
    string public symbol = "WETH";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);
    event Approval(address indexed src, address indexed guy, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);

    receive() external payable {
        deposit();
    }

    function deposit() public payable {
        balanceOf[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad, "insufficient balance");
        balanceOf[msg.sender] -= wad;
        (bool ok, ) = msg.sender.call{value: wad}("");
        require(ok, "transfer failed");
        emit Withdrawal(msg.sender, wad);
    }

    function totalSupply() public view returns (uint256) {
        return address(this).balance;
    }

    function approve(address guy, uint256 wad) public returns (bool) {
        allowance[msg.sender][guy] = wad;
        emit Approval(msg.sender, guy, wad);
        return true;
    }

    function transfer(address dst, uint256 wad) public returns (bool) {
        return transferFrom(msg.sender, dst, wad);
    }

    function transferFrom(address src, address dst, uint256 wad)
        public
        returns (bool)
    {
        require(balanceOf[src] >= wad, "insufficient balance");
        if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
            require(allowance[src][msg.sender] >= wad, "insufficient allowance");
            allowance[src][msg.sender] -= wad;
        }
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
        return true;
    }
}
"""

# Deterministic addresses for the fixtures (test fixtures, no value).
VAULT_ADDRESS = "0x00000000000000000000000000000000F1A60017"
WETH_ADDRESS = "0x00000000000000000000000000000000C0FFEE01"
