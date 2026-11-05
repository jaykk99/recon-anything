// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shape (fixed 2026-11-05): MasterChef withdraw /
// emergencyWithdraw. The payout is metered by the
// caller's own recorded position through a storage
// pointer (userInfo[pid][msg.sender]) that is debited /
// zeroed in the same call.
interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract FpCleanChef {
    struct PoolInfo { address lpToken; uint256 accRewardPerShare; }
    struct UserInfo { uint256 amount; uint256 rewardDebt; }
    PoolInfo[] public poolInfo;
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    IERC20Like public rewardToken;

    function withdraw(uint256 _pid, uint256 _amount) external {
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 pending = user.amount * pool.accRewardPerShare / 1e12 - user.rewardDebt;
        user.amount -= _amount;
        user.rewardDebt = user.amount * pool.accRewardPerShare / 1e12;
        if (pending > 0) { rewardToken.transfer(msg.sender, pending); }
        IERC20Like(pool.lpToken).transfer(msg.sender, _amount);
    }

    function emergencyWithdraw(uint256 _pid) external {
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;
        IERC20Like(poolInfo[_pid].lpToken).transfer(msg.sender, amount);
    }
}
