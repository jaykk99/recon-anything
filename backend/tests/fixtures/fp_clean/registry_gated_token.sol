// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// FP shape (fixed 2026-11-05): mint gated by a require
// helper over OR-ed boolean registry mappings
// (borrowerOperations[msg.sender] || activePool[msg.sender])
// - the Liquity BoldToken gate shape.
contract FpCleanRegistryToken {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public borrowerOperationsAddresses;
    mapping(address => bool) public activePoolAddresses;

    function _mint(address account, uint256 amount) internal {
        totalSupply += amount;
        balanceOf[account] += amount;
    }

    function _requireCallerIsBOorAP() internal view {
        require(
            borrowerOperationsAddresses[msg.sender] || activePoolAddresses[msg.sender],
            "Caller is not BO or AP"
        );
    }

    function mint(address _account, uint256 _amount) external {
        _requireCallerIsBOorAP();
        _mint(_account, _amount);
    }
}
