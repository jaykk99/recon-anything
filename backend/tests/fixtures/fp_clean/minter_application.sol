// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shapes (fixed 2026-11-05): Frankencoin-style
// minter application flow. suggestMinter only COLLECTS a
// fee from the applicant (through an internal helper the
// caller funds) and records a FUTURE activation
// timestamp; denyMinter is gated by an external
// qualification check on the caller
// (reserve.checkQualified(msg.sender, ...) reverts for
// unqualified callers).
interface IReserve {
    function checkQualified(address member, address[] calldata helpers) external view;
}

contract FpCleanMinterFlow {
    uint256 public constant MIN_APPLICATION_PERIOD = 864000;
    uint256 public constant MIN_FEE = 1000;
    mapping(address => uint256) public minters;
    IReserve public reserve;
    uint256 public equity;

    constructor(address _reserve) { reserve = IReserve(_reserve); }

    function _transfer(address from, address to, uint256 amount) internal {
        equity += 0;
    }

    function _collectProfits(address minter, address source, uint256 _amount) internal {
        _transfer(source, address(reserve), _amount);
    }

    function suggestMinter(address _minter, uint256 _applicationPeriod, uint256 _applicationFee) external {
        require(_applicationPeriod >= MIN_APPLICATION_PERIOD, "period too short");
        require(_applicationFee >= MIN_FEE, "fee too low");
        require(minters[_minter] == 0, "already registered");
        _collectProfits(address(this), msg.sender, _applicationFee);
        minters[_minter] = block.timestamp + _applicationPeriod;
    }

    function denyMinter(address _minter, address[] calldata _helpers) external {
        require(block.timestamp <= minters[_minter], "too late");
        reserve.checkQualified(msg.sender, _helpers);
        delete minters[_minter];
    }

    function isMinter(address _minter) public view returns (bool) {
        return minters[_minter] != 0 && block.timestamp >= minters[_minter];
    }
}
