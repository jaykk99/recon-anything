// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shape (fixed 2026-11-05): AMM pair mint. Liquidity is
// metered by the pair's own token balance deltas against
// recorded reserves - the caller can only mint against
// what they already transferred in.
interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract FpCleanPair {
    address public token0;
    address public token1;
    uint112 private reserve0;
    uint112 private reserve1;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function _mint(address to, uint256 value) internal {
        totalSupply += value;
        balanceOf[to] += value;
    }

    function mint(address to) external returns (uint256 liquidity) {
        uint256 balance0 = IERC20Like(token0).balanceOf(address(this));
        uint256 balance1 = IERC20Like(token1).balanceOf(address(this));
        uint256 amount0 = balance0 - reserve0;
        uint256 amount1 = balance1 - reserve1;
        liquidity = amount0 + amount1;
        require(liquidity > 0, "insufficient liquidity minted");
        _mint(to, liquidity);
        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
    }
}
