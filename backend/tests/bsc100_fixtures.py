"""Fixtures for the 100 BSC detectors.

VULN[id]    = a compact source that MUST produce a finding of
              exactly that detector's type (and, per the dedupe
              gate in test_bsc100_dedupe.py, no other new
              detector may fire on the same function).
CLEAN[family] = a properly-built contract of that family that
              MUST produce zero findings from all 100 detectors.

Fixtures are pattern snippets in the house style of
test_contract_logic.py - small, readable, one flaw each.
"""
from __future__ import annotations

VULN = {}
CLEAN = {}

# ===========================================================================
# BEP-20
# ===========================================================================

VULN["bep20_transfer_fee_miscalculation"] = r"""
pragma solidity ^0.8.20;
contract FeeToken {
    mapping(address => uint256) public balances;
    address public feeWallet;
    uint256 public taxFee = 5;
    event Transfer(address indexed from, address indexed to, uint256 amount);
    function transfer(address to, uint256 amount) public returns (bool) {
        uint256 fee = amount * taxFee / 100;
        balances[msg.sender] -= amount;
        balances[to] += amount;
        balances[feeWallet] += fee;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
"""

VULN["bep20_blacklist_authority_check"] = r"""
pragma solidity ^0.8.20;
contract BlacklistToken {
    mapping(address => bool) public blacklist;
    function addToBlacklist(address account) public {
        blacklist[account] = true;
    }
}
"""

VULN["bep20_mint_cap_bypass"] = r"""
pragma solidity ^0.8.20;
contract CappedToken {
    uint256 public maxSupply = 1000000;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    function mint(address to, uint256 amount) public {
        totalSupply += amount;
        balances[to] += amount;
    }
}
"""

VULN["bep20_allowance_double_spend"] = r"""
pragma solidity ^0.8.20;
contract RaceToken {
    mapping(address => mapping(address => uint256)) public allowance;
    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }
}
"""

VULN["bep20_balance_of_side_effects"] = r"""
pragma solidity ^0.8.20;
contract SideEffectToken {
    mapping(address => uint256) public balances;
    uint256 public totalReflected;
    function balanceOf(address account) public returns (uint256) {
        totalReflected += 1;
        balances[account] = balances[account] + 0;
        return balances[account];
    }
}
"""

VULN["bep20_owner_privilege_abuse"] = r"""
pragma solidity ^0.8.20;
contract SeizeToken {
    mapping(address => uint256) public balances;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function ownerTransfer(address from, address to, uint256 amount) public onlyOwner {
        balances[from] -= amount;
        balances[to] += amount;
    }
}
"""

VULN["bep20_burn_from_overflow"] = r"""
pragma solidity ^0.7.6;
contract BurnToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    function burnFrom(address account, uint256 value) public {
        balances[account] -= value;
        totalSupply -= value;
    }
}
"""

VULN["bep20_fake_transfer_events"] = r"""
pragma solidity ^0.8.20;
contract SilentToken {
    mapping(address => uint256) public balances;
    function transfer(address to, uint256 amount) public returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
}
"""

VULN["bep20_arbitrary_minting_endpoints"] = r"""
pragma solidity ^0.8.20;
contract SideMint {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        balances[to] += amount;
    }
    function issueTokens(address to, uint256 amount) public {
        _mint(to, amount);
    }
}
"""

VULN["bep20_decimal_mismatch"] = r"""
pragma solidity ^0.8.20;
contract DecimalToken {
    uint256 public totalSupply;
    function decimals() public pure returns (uint8) { return 6; }
    function mint(address to) public {
        totalSupply += 1000 * 10 ** 18;
    }
}
"""

CLEAN["bep20"] = r"""
pragma solidity ^0.8.20;
contract CleanToken {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    uint256 public cap = 1000000 * 10 ** 18;
    address public owner;
    event Transfer(address indexed from, address indexed to, uint256 amount);
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function decimals() public pure returns (uint8) { return 18; }
    function balanceOf(address account) public view returns (uint256) {
        return balances[account];
    }
    function transfer(address to, uint256 amount) public returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    function approve(address spender, uint256 value) public returns (bool) {
        require(value == 0 || allowance[msg.sender][spender] == 0, "zero first");
        allowance[msg.sender][spender] = value;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(allowance[from][msg.sender] >= amount);
        allowance[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
    function mint(address to, uint256 amount) public onlyOwner {
        require(totalSupply + amount <= cap, "cap");
        totalSupply += amount;
        balances[to] += amount;
    }
    function burn(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        totalSupply -= amount;
    }
}
"""

# ===========================================================================
# PancakeSwap
# ===========================================================================

VULN["pancake_v2_v3_router_misdirection"] = r"""
pragma solidity ^0.8.20;
interface IPancakeRouter02 {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory amounts);
}
contract MisdirectedSwap {
    address public router = 0x1111111111111111111111111111111111111111;
    function doSwap(uint256 amountIn, uint256 minOut, address[] calldata path) external {
        IPancakeRouter02(router).swapExactTokensForTokens(amountIn, minOut, path, msg.sender, block.timestamp);
    }
}
"""

VULN["pancake_pool_skimming_vulnerability"] = r"""
pragma solidity ^0.8.20;
interface IPancakePair {
    function skim(address to) external;
}
contract Skimmer {
    function harvest(address pair) public {
        IPancakePair(pair).skim(msg.sender);
    }
}
"""

VULN["pancake_price_oracle_manipulation"] = r"""
pragma solidity ^0.8.20;
interface IPancakePair2 {
    function getReserves() external view returns (uint112, uint112, uint32);
}
contract SpotOracleMint {
    address public pair;
    uint256 public totalSupply;
    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
    }
    function mintWithSpotPrice(uint256 collateral) public {
        (uint112 r0, uint112 r1, ) = IPancakePair2(pair).getReserves();
        uint256 price = uint256(r1) * 1e18 / uint256(r0);
        _mint(msg.sender, collateral * price / 1e18);
    }
}
"""

VULN["pancake_add_liquidity_dust_leak"] = r"""
pragma solidity ^0.8.20;
interface IPancakeRouter03 {
    function addLiquidity(address tokenA, address tokenB, uint256 amountADesired, uint256 amountBDesired, uint256 amountAMin, uint256 amountBMin, address to, uint256 deadline) external returns (uint256, uint256, uint256);
}
contract DustAdd {
    address public router;
    function add(address a, address b, uint256 x, uint256 y) external {
        IPancakeRouter03(router).addLiquidity(a, b, x, y, 0, 0, msg.sender, block.timestamp);
    }
}
"""

VULN["pancake_remove_liquidity_frontrun"] = r"""
pragma solidity ^0.8.20;
interface IPancakeRouter04 {
    function removeLiquidity(address tokenA, address tokenB, uint256 liquidity, uint256 amountAMin, uint256 amountBMin, address to, uint256 deadline) external returns (uint256, uint256);
}
contract RugRemove {
    address public router;
    function remove(address a, address b, uint256 liq) external {
        IPancakeRouter04(router).removeLiquidity(a, b, liq, 0, 0, msg.sender, block.timestamp);
    }
}
"""

VULN["pancake_swap_exact_tokens_underflow"] = r"""
pragma solidity ^0.7.6;
interface IPancakeRouter05 {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory);
}
interface IERC20B {
    function balanceOf(address account) external view returns (uint256);
}
contract UnderflowSwap {
    address public router;
    IERC20B public token;
    uint256 public reserved;
    function swapAll(address[] calldata path, uint256 minOut) external {
        uint256 amountIn = token.balanceOf(address(this)) - reserved;
        IPancakeRouter05(router).swapExactTokensForTokens(amountIn, minOut, path, msg.sender, block.timestamp);
    }
}
"""

VULN["pancake_lp_token_burn_logic"] = r"""
pragma solidity ^0.8.20;
interface IPancakePair3 {
    function burn(address to) external returns (uint256, uint256);
}
contract LpBurner {
    function burnLP(address pair, address to) public {
        IPancakePair3(pair).burn(to);
    }
}
"""

VULN["pancake_flash_swap_reentrancy"] = r"""
pragma solidity ^0.8.20;
interface IERC20C {
    function transfer(address to, uint256 amount) external returns (bool);
}
contract FlashCallback {
    address public token;
    uint256 public received;
    function pancakeCall(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external {
        received = amount0 + amount1;
        IERC20C(token).transfer(sender, amount0);
    }
}
"""

VULN["pancake_insufficient_slippage_protection"] = r"""
pragma solidity ^0.8.20;
interface IPancakeRouter06 {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory);
}
contract NoSlippage {
    address public router;
    function swap(uint256 amountIn, address[] calldata path) external {
        IPancakeRouter06(router).swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);
    }
}
"""

VULN["pancake_k_value_invariant_violation"] = r"""
pragma solidity ^0.8.20;
contract MiniPair {
    uint256 public reserve0;
    uint256 public reserve1;
    function swap(uint256 amount0Out, uint256 amount1Out) external {
        reserve0 = reserve0 - amount0Out + 1;
        reserve1 = reserve1 - amount1Out + 1;
    }
}
"""

CLEAN["pancake"] = r"""
pragma solidity ^0.8.20;
interface IPancakeRouterClean {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory);
    function addLiquidity(address tokenA, address tokenB, uint256 amountADesired, uint256 amountBDesired, uint256 amountAMin, uint256 amountBMin, address to, uint256 deadline) external returns (uint256, uint256, uint256);
}
contract CleanSwapHelper {
    address public constant ROUTER = 0x10ED43C718714eb63d5aA57B78B54704E256024E;
    function swap(uint256 amountIn, uint256 minOut, address[] calldata path) external {
        require(minOut > 0, "minOut");
        IPancakeRouterClean(ROUTER).swapExactTokensForTokens(amountIn, minOut, path, msg.sender, block.timestamp + 600);
    }
    function addLiq(address a, address b, uint256 x, uint256 y, address to) external {
        IPancakeRouterClean(ROUTER).addLiquidity(a, b, x, y, x * 95 / 100, y * 95 / 100, to, block.timestamp + 600);
    }
}
"""

# ===========================================================================
# Flash loans / lending
# ===========================================================================

VULN["flash_loan_spot_balance_check"] = r"""
pragma solidity ^0.8.20;
interface IERC20L {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
interface IReceiverL {
    function onFlashLoan(uint256 amount) external;
}
contract SpotLender {
    IERC20L public token;
    function flashLoan(uint256 amount, address receiver) external {
        uint256 before = token.balanceOf(address(this));
        token.transfer(receiver, amount);
        IReceiverL(receiver).onFlashLoan(amount);
        require(token.balanceOf(address(this)) >= before + amount);
    }
}
"""

VULN["flash_loan_callback_auth_bypass"] = r"""
pragma solidity ^0.8.20;
interface IERC20M {
    function approve(address spender, uint256 amount) external returns (bool);
}
contract FlashReceiverVuln {
    address public token;
    address public treasury;
    uint256 public approved;
    function onFlashLoan(address initiator, uint256 amount, bytes calldata data) external returns (bytes32) {
        approved = amount;
        IERC20M(token).approve(treasury, amount);
        return keccak256("onFlashLoan");
    }
}
"""

VULN["flash_loan_repayment_underflow"] = r"""
pragma solidity ^0.7.6;
interface IERC20L2 {
    function balanceOf(address account) external view returns (uint256);
}
contract RepayUnderflow {
    IERC20L2 public token;
    uint256 public balanceBefore;
    uint256 public lastFee;
    function flashRepay() external {
        uint256 fee = token.balanceOf(address(this)) - balanceBefore;
        lastFee = fee;
    }
}
"""

VULN["flash_loan_governance_takeover"] = r"""
pragma solidity ^0.8.20;
interface IERC20L3 {
    function balanceOf(address account) external view returns (uint256);
}
contract SpotGovernor {
    IERC20L3 public token;
    mapping(uint256 => uint256) public forVotes;
    function castVote(uint256 proposalId, bool support) external {
        uint256 weight = token.balanceOf(msg.sender);
        if (support) { forVotes[proposalId] += weight; }
    }
}
"""

VULN["flash_loan_reward_dilution"] = r"""
pragma solidity ^0.8.20;
contract DilutionRewards {
    mapping(address => uint256) public shares;
    uint256 public rewardRate = 10;
    function claim() external {
        uint256 reward = shares[msg.sender] * rewardRate;
        (bool ok, ) = msg.sender.call{value: reward}("");
        require(ok);
    }
}
"""

VULN["venus_comptroller_state_sync"] = r"""
pragma solidity ^0.8.20;
interface IERC20L4 {
    function transfer(address to, uint256 amount) external returns (bool);
}
contract DesyncMarket {
    uint256 public totalBorrows;
    mapping(address => uint256) public accountBorrows;
    address public underlying;
    function borrowFresh(address borrower, uint256 borrowAmount) external {
        accountBorrows[borrower] += borrowAmount;
        totalBorrows += borrowAmount;
        IERC20L4(underlying).transfer(borrower, borrowAmount);
    }
}
"""

VULN["venus_accrue_interest_omission"] = r"""
pragma solidity ^0.8.20;
contract StaleMarket {
    function exchangeRateStored() public view returns (uint256) { return 1e18; }
    function accrueInterest() public returns (uint256) { return 0; }
    function redeemFresh(address redeemer, uint256 vTokenAmount) external returns (uint256) {
        uint256 rate = exchangeRateStored();
        uint256 underlyingAmount = vTokenAmount * rate / 1e18;
        return underlyingAmount;
    }
}
"""

VULN["venus_mint_rate_assumption"] = r"""
pragma solidity ^0.8.20;
contract OneToOneMarket {
    address public comptroller;
    uint256 public totalBorrows;
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    function mint(uint256 mintAmount) external {
        balances[msg.sender] += mintAmount;
        totalSupply += mintAmount;
    }
}
"""

VULN["lending_pool_liquidation_incentive_overflow"] = r"""
pragma solidity ^0.6.12;
contract OverflowLiquidator {
    uint256 public incentiveMantissa = 110;
    uint256 public lastSeize;
    function liquidate(uint256 debtToCover) external {
        uint256 seizeAmount = debtToCover * incentiveMantissa / 100;
        lastSeize = seizeAmount;
    }
}
"""

VULN["lending_pool_collateral_seizure_gap"] = r"""
pragma solidity ^0.8.20;
contract GapLiquidator {
    mapping(address => uint256) public collateralOf;
    function liquidate(address borrower, uint256 amount) external {
        uint256 seized = seizeCollateral(borrower, amount);
        collateralOf[msg.sender] += seized;
    }
    function seizeCollateral(address borrower, uint256 amount) internal returns (uint256) {
        collateralOf[borrower] -= amount;
        return amount;
    }
}
"""

CLEAN["lending"] = r"""
pragma solidity ^0.8.20;
interface IComptrollerC {
    function mintAllowed(address vToken, address minter, uint256 amount) external returns (uint256);
    function borrowAllowed(address vToken, address borrower, uint256 amount) external returns (uint256);
    function liquidateBorrowAllowed(address vBorrowed, address vCollateral, address liquidator, address borrower, uint256 repayAmount) external returns (uint256);
}
interface IERC20LC {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
interface IFlashReceiverC {
    function onFlashLoan(address initiator, uint256 amount, bytes calldata data) external;
}
contract CleanMarket {
    IComptrollerC public comptroller;
    IERC20LC public token;
    uint256 public totalBorrows;
    uint256 public totalSupply;
    mapping(address => uint256) public accountBorrows;
    function accrueInterest() public returns (uint256) { return 0; }
    function exchangeRateStored() public view returns (uint256) { return 1e18; }
    function exchangeRateCurrent() public returns (uint256) {
        accrueInterest();
        return exchangeRateStored();
    }
    function mint(address minter, uint256 mintAmount) external returns (uint256) {
        require(comptroller.mintAllowed(address(this), minter, mintAmount) == 0, "mint not allowed");
        accrueInterest();
        uint256 rate = exchangeRateStored();
        uint256 mintTokens = mintAmount * 1e18 / rate;
        totalSupply += mintTokens;
        return mintTokens;
    }
    function borrow(address borrower, uint256 borrowAmount) external {
        require(comptroller.borrowAllowed(address(this), borrower, borrowAmount) == 0, "borrow not allowed");
        accrueInterest();
        accountBorrows[borrower] += borrowAmount;
        totalBorrows += borrowAmount;
    }
    function liquidateBorrow(address borrower, uint256 repayAmount, address collateralMarket) external returns (uint256) {
        require(comptroller.liquidateBorrowAllowed(address(this), collateralMarket, msg.sender, borrower, repayAmount) == 0, "liquidate not allowed");
        accrueInterest();
        uint256 seizeTokens = repayAmount * 108 / 100;
        accountBorrows[borrower] -= repayAmount;
        return seizeTokens;
    }
    function flashLoan(address receiver, uint256 amount, bytes calldata data) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.transfer(receiver, amount);
        IFlashReceiverC(receiver).onFlashLoan(msg.sender, amount, data);
        uint256 fee = amount * 9 / 10000;
        require(token.balanceOf(address(this)) >= balanceBefore + fee, "not repaid");
        token.transferFrom(receiver, address(this), amount + fee);
    }
}
"""

# ===========================================================================
# Staking / MasterChef
# ===========================================================================

VULN["masterchef_pool_length_oob"] = r"""
pragma solidity ^0.8.20;
contract OobChef {
    struct PoolInfo { address lpToken; uint256 allocPoint; }
    PoolInfo[] public poolInfo;
    uint256 public lastAmount;
    function deposit(uint256 _pid, uint256 _amount) external {
        lastAmount = _amount + poolInfo[_pid].allocPoint;
    }
}
"""

VULN["masterchef_pending_reward_overflow"] = r"""
pragma solidity ^0.6.12;
contract OverflowChef {
    struct PoolInfo { uint256 accRewardPerShare; }
    struct UserInfo { uint256 amount; uint256 rewardDebt; }
    PoolInfo[] public poolInfo;
    mapping(address => UserInfo) public userInfo;
    function pendingReward(address _user) external view returns (uint256) {
        UserInfo storage user = userInfo[_user];
        PoolInfo storage pool = poolInfo[0];
        return user.amount * pool.accRewardPerShare / 1e12 - user.rewardDebt;
    }
}
"""

VULN["masterchef_emergency_withdraw_lock"] = r"""
pragma solidity ^0.8.20;
interface IERC20S {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}
contract LockChef {
    struct UserInfo { uint256 amount; uint256 rewardDebt; }
    mapping(address => UserInfo) public userInfo;
    IERC20S public lpToken;
    function emergencyWithdraw() external {
        UserInfo storage user = userInfo[msg.sender];
        lpToken.transfer(msg.sender, user.amount);
    }
}
"""

VULN["masterchef_reward_token_depletion"] = r"""
pragma solidity ^0.8.20;
contract StaleChef {
    struct PoolInfo { address lpToken; uint256 accRewardPerShare; }
    struct UserInfo { uint256 amount; uint256 rewardDebt; }
    PoolInfo[] public poolInfo;
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    IERC20S public rewardToken;
    function withdraw(uint256 _pid, uint256 _amount) external {
        require(_pid < poolInfo.length, "pid");
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 pending = user.amount * pool.accRewardPerShare / 1e12 - user.rewardDebt;
        user.rewardDebt = user.amount * pool.accRewardPerShare / 1e12;
        rewardToken.transfer(msg.sender, pending);
    }
}
"""

VULN["masterchef_duplicate_pool_registration"] = r"""
pragma solidity ^0.8.20;
contract DupChef {
    struct PoolInfo { address lpToken; uint256 allocPoint; }
    PoolInfo[] public poolInfo;
    function add(address _lpToken) external {
        poolInfo.push(PoolInfo(_lpToken, 100));
    }
}
"""

VULN["masterchef_deposit_fee_skimming"] = r"""
pragma solidity ^0.8.20;
contract SkimChef {
    struct PoolInfo { address lpToken; }
    struct UserInfo { uint256 amount; uint256 rewardDebt; }
    PoolInfo[] public poolInfo;
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    address public feeAddress;
    function deposit(uint256 _pid, uint256 _amount) external {
        require(_pid < poolInfo.length, "pid");
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        IERC20S(pool.lpToken).transferFrom(msg.sender, address(this), _amount);
        uint256 fee = _amount * 400 / 10000;
        IERC20S(pool.lpToken).transfer(feeAddress, fee);
        user.amount += _amount;
    }
}
"""

VULN["staking_lockup_duration_bypass"] = r"""
pragma solidity ^0.8.20;
contract FakeLockStaking {
    uint256 public lockPeriod = 30 days;
    mapping(address => uint256) public staked;
    IERC20S public token;
    function withdraw(uint256 amount) external {
        staked[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
"""

VULN["staking_reward_compounding_reentrancy"] = r"""
pragma solidity ^0.8.20;
contract CompoundVuln {
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public lastCompound;
    IERC20S public rewardToken;
    function compound() external {
        uint256 reward = rewards[msg.sender];
        rewardToken.transfer(msg.sender, reward);
        lastCompound[msg.sender] = block.timestamp;
        rewards[msg.sender] = 0;
    }
}
"""

VULN["staking_total_shares_mismatch"] = r"""
pragma solidity ^0.8.20;
contract ShareVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    IERC20S public token;
    function stake(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
        totalShares += amount;
    }
}
"""

VULN["staking_zero_deposit_harvest"] = r"""
pragma solidity ^0.8.20;
contract LoopChef {
    struct PoolInfo { address lpToken; uint256 accRewardPerShare; }
    struct UserInfo { uint256 amount; uint256 rewardDebt; }
    PoolInfo[] public poolInfo;
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    IERC20S public rewardToken;
    function deposit(uint256 _pid, uint256 _amount) external {
        require(_pid < poolInfo.length, "pid");
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 pending = user.amount * pool.accRewardPerShare / 1e12 - user.rewardDebt;
        if (pending > 0) {
            rewardToken.transfer(msg.sender, pending);
        }
        user.amount += _amount;
    }
}
"""

CLEAN["staking"] = r"""
pragma solidity ^0.8.20;
contract CleanChef {
    struct PoolInfo { address lpToken; uint256 accRewardPerShare; }
    struct UserInfo { uint256 amount; uint256 rewardDebt; }
    PoolInfo[] public poolInfo;
    mapping(uint256 => mapping(address => UserInfo)) public userInfo;
    IERC20S public rewardToken;
    address public feeAddress;
    function add(address _lpToken) external {
        for (uint256 i = 0; i < poolInfo.length; i++) {
            require(poolInfo[i].lpToken != _lpToken, "dup");
        }
        poolInfo.push(PoolInfo(_lpToken, 0));
    }
    function updatePool(uint256 _pid) public {
        require(_pid < poolInfo.length, "pid");
        PoolInfo storage pool = poolInfo[_pid];
        pool.accRewardPerShare += 1;
    }
    function deposit(uint256 _pid, uint256 _amount) external {
        require(_pid < poolInfo.length, "pid");
        updatePool(_pid);
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        IERC20S(pool.lpToken).transferFrom(msg.sender, address(this), _amount);
        uint256 fee = _amount * 10 / 10000;
        if (fee > 0) { IERC20S(pool.lpToken).transfer(feeAddress, fee); }
        user.amount += _amount - fee;
        user.rewardDebt = user.amount * pool.accRewardPerShare / 1e12;
    }
    function withdraw(uint256 _pid, uint256 _amount) external {
        require(_pid < poolInfo.length, "pid");
        updatePool(_pid);
        PoolInfo storage pool = poolInfo[_pid];
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 pending = user.amount * pool.accRewardPerShare / 1e12 - user.rewardDebt;
        user.amount -= _amount;
        user.rewardDebt = user.amount * pool.accRewardPerShare / 1e12;
        if (pending > 0) { rewardToken.transfer(msg.sender, pending); }
        IERC20S(pool.lpToken).transfer(msg.sender, _amount);
    }
    function emergencyWithdraw(uint256 _pid) external {
        require(_pid < poolInfo.length, "pid");
        UserInfo storage user = userInfo[_pid][msg.sender];
        uint256 amount = user.amount;
        user.amount = 0;
        user.rewardDebt = 0;
        IERC20S(poolInfo[_pid].lpToken).transfer(msg.sender, amount);
    }
}
"""

# ===========================================================================
# Governance / timelocks
# ===========================================================================

VULN["timelock_delay_bypass"] = r"""
pragma solidity ^0.8.20;
contract WeakTimelock {
    mapping(bytes32 => bool) public queuedTransactions;
    function queueTransaction(address target, uint256 value, bytes memory data, uint256 eta) external returns (bytes32) {
        bytes32 txHash = keccak256(abi.encode(target, value, data, eta));
        queuedTransactions[txHash] = true;
        return txHash;
    }
}
"""

VULN["timelock_queue_transaction_collision"] = r"""
pragma solidity ^0.8.20;
contract CollidingTimelock {
    mapping(bytes32 => bool) public queuedTransactions;
    uint256 public constant minDelay = 2 days;
    function queueTransaction(address target, uint256 value, bytes memory data, uint256 eta) external returns (bytes32) {
        require(eta >= block.timestamp + minDelay, "eta too soon");
        bytes32 txHash = keccak256(abi.encode(target, value));
        queuedTransactions[txHash] = true;
        return txHash;
    }
}
"""

VULN["governance_proposal_threshold_gaming"] = r"""
pragma solidity ^0.8.20;
interface IERC20G {
    function balanceOf(address account) external view returns (uint256);
    function getPastVotes(address account, uint256 blockNumber) external view returns (uint256);
    function getPastTotalSupply(uint256 blockNumber) external view returns (uint256);
}
contract GameableGovernor {
    IERC20G public token;
    uint256 public proposalThreshold = 1000;
    function propose() external returns (uint256) {
        require(token.balanceOf(msg.sender) > proposalThreshold, "below");
        return 7;
    }
}
"""

VULN["governance_quorum_calculation_flaw"] = r"""
pragma solidity ^0.8.20;
interface IERC20Q {
    function totalSupply() external view returns (uint256);
}
contract LiveQuorum {
    IERC20Q public token;
    uint256 public quorumPercent = 4;
    function quorumReached(uint256 forVotes) external view returns (bool) {
        return forVotes >= token.totalSupply() * quorumPercent / 100;
    }
}
"""

VULN["governance_early_execution_race"] = r"""
pragma solidity ^0.8.20;
contract RaceGovernor {
    struct Proposal { bool executed; address target; }
    mapping(uint256 => Proposal) public proposals;
    function executeProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        p.executed = true;
        p.target.call{value: 0}("");
    }
}
"""

VULN["governance_vote_double_delegation"] = r"""
pragma solidity ^0.8.20;
contract DoubleDelegate {
    mapping(address => address) public delegates;
    mapping(address => uint256) public votes;
    IERC20G public token;
    function delegate(address to) external {
        delegates[msg.sender] = to;
        votes[to] += token.balanceOf(msg.sender);
    }
}
"""

VULN["governance_cancel_privilege_abuse"] = r"""
pragma solidity ^0.8.20;
contract CancelAnyone {
    struct Proposal { bool canceled; }
    mapping(uint256 => Proposal) public proposals;
    function cancelProposal(uint256 proposalId) external {
        proposals[proposalId].canceled = true;
    }
}
"""

VULN["timelock_execution_gas_exhaustion"] = r"""
pragma solidity ^0.8.20;
contract BatchTimelock {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function executeBatch(address[] memory targets, bytes[] memory datas) external onlyOwner {
        for (uint256 i = 0; i < targets.length; i++) {
            targets[i].call{value: 0}(datas[i]);
        }
    }
}
"""

VULN["governance_state_staleness"] = r"""
pragma solidity ^0.8.20;
contract MutableRules {
    uint256 public votingPeriod = 100;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setVotingPeriod(uint256 newPeriod) external onlyOwner {
        votingPeriod = newPeriod;
    }
}
"""

VULN["governance_signature_replay"] = r"""
pragma solidity ^0.8.20;
contract ReplayGovernor {
    mapping(uint256 => uint256) public forVotes;
    function castVoteBySig(uint256 proposalId, bool support, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(proposalId, support));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0));
        forVotes[proposalId] += 1;
    }
}
"""

CLEAN["governance"] = r"""
pragma solidity ^0.8.20;
contract CleanGovernor {
    struct Proposal { address proposer; uint256 eta; bool executed; bool canceled; uint256 forVotes; }
    mapping(uint256 => Proposal) public proposals;
    mapping(address => address) public delegates;
    mapping(address => uint256) public nonces;
    uint256 public votingDelay = 1;
    uint256 public votingPeriod = 100;
    uint256 public quorumPercent = 4;
    IERC20G public token;
    uint256 public constant minDelay = 2 days;
    mapping(bytes32 => bool) public queuedTransactions;
    function propose() external returns (uint256) {
        require(token.getPastVotes(msg.sender, block.number - 1) > 1000, "below threshold");
        return 1;
    }
    function castVote(uint256 proposalId, bool support) external {
        uint256 weight = token.getPastVotes(msg.sender, block.number - votingDelay);
        proposals[proposalId].forVotes += weight;
    }
    function castVoteBySig(uint256 proposalId, bool support, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(address(this), block.chainid, proposalId, support, nonces[msg.sender]));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0));
        nonces[signer] += 1;
        proposals[proposalId].forVotes += 1;
    }
    function quorum() public view returns (uint256) {
        return token.getPastTotalSupply(block.number - 1) * quorumPercent / 100;
    }
    function cancel(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(msg.sender == p.proposer, "not proposer");
        p.canceled = true;
    }
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.eta > 0 && block.timestamp >= p.eta, "not ready");
        require(!p.executed, "done");
        p.executed = true;
    }
    function queueTransaction(address target, uint256 value, string memory signature, bytes memory data, uint256 eta) external returns (bytes32) {
        require(eta >= block.timestamp + minDelay, "delay");
        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));
        queuedTransactions[txHash] = true;
        return txHash;
    }
    function delegate(address to) external {
        address old = delegates[msg.sender];
        _moveDelegates(old, to, token.balanceOf(msg.sender));
        delegates[msg.sender] = to;
    }
    function _moveDelegates(address from, address to, uint256 amount) internal { }
}
"""

# ===========================================================================
# Proxy / upgradeability
# ===========================================================================

VULN["proxy_implementation_uninitialized"] = r"""
pragma solidity ^0.8.20;
contract VulnerableImpl {
    address public owner;
    function initialize(address _owner) external {
        owner = _owner;
    }
}
contract MiniProxy {
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    fallback() external payable {
        address impl;
        assembly {
            impl := sload(IMPL_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
        }
    }
}
"""

VULN["proxy_storage_collision_detector"] = r"""
pragma solidity ^0.8.20;
contract SlotProxy {
    address public implementation;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setImplementation(address impl) external onlyOwner {
        implementation = impl;
    }
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
        }
    }
}
"""

VULN["proxy_upgrade_authorization_gap"] = r"""
pragma solidity ^0.8.20;
contract UpgradeProxy {
    address public implementation;
    function upgradeTo(address newImplementation) external {
        implementation = newImplementation;
    }
}
"""

VULN["proxy_delegatecall_selfdestruct"] = r"""
pragma solidity ^0.8.20;
contract DestructImpl {
    address public owner;
    function kill() external {
        selfdestruct(payable(owner));
    }
}
contract DestructProxy {
    bytes32 internal constant SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    fallback() external payable {
        assembly {
            let impl := sload(SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
        }
    }
}
"""

VULN["proxy_beacon_address_manipulation"] = r"""
pragma solidity ^0.8.20;
contract Beacon {
    address public implementation;
    address public owner;
    function setImplementation(address newImpl) external {
        implementation = newImpl;
    }
}
"""

VULN["proxy_cloning_initial_state_leak"] = r"""
pragma solidity ^0.8.20;
library Clones {
    function clone(address impl) internal returns (address) { return impl; }
}
contract CloneFactory {
    address public implementation;
    function createClone() external returns (address) {
        address instance = Clones.clone(implementation);
        return instance;
    }
}
"""

VULN["proxy_shadow_variable_override"] = r"""
pragma solidity ^0.8.20;
contract ShadowProxy {
    address public owner;
    bytes32 internal constant SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    fallback() external payable {
        assembly {
            let impl := sload(SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
        }
    }
}
contract ShadowImpl {
    address public owner;
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"""

VULN["proxy_function_clashing"] = r"""
pragma solidity ^0.8.20;
contract ClashProxy {
    uint256 public value;
    function setValue(uint256 newValue) external {
        value = newValue;
    }
    fallback() external payable {
        assembly {
            let impl := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
        }
    }
}
contract ClashImpl {
    uint256 public value;
    function setValue(uint256 newValue) external {
        value = newValue;
    }
}
"""

VULN["proxy_deterministic_deployment_collision"] = r"""
pragma solidity ^0.8.20;
contract Create2Factory {
    function deploy(bytes32 salt, bytes memory bytecode) external returns (address addr) {
        assembly {
            addr := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
    }
}
"""

VULN["proxy_transparent_admin_misdirection"] = r"""
pragma solidity ^0.8.20;
contract OpaqueProxy {
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    function _admin() internal view returns (address a) {
        assembly { a := sload(ADMIN_SLOT) }
    }
    function _implementation() internal view returns (address impl) {
        assembly { impl := sload(IMPL_SLOT) }
    }
    function upgradeTo(address newImpl) external {
        require(msg.sender == _admin(), "not admin");
        assembly { sstore(IMPL_SLOT, newImpl) }
    }
    fallback() external payable {
        address impl = _implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
        }
    }
}
"""

CLEAN["proxy"] = r"""
pragma solidity ^0.8.20;
contract CleanProxy {
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    constructor(address impl) {
        assembly {
            sstore(IMPL_SLOT, impl)
            sstore(ADMIN_SLOT, caller())
        }
    }
    function admin() public view returns (address a) {
        assembly { a := sload(ADMIN_SLOT) }
    }
    function upgradeTo(address newImpl) external {
        require(msg.sender == admin(), "not admin");
        assembly { sstore(IMPL_SLOT, newImpl) }
    }
    fallback() external payable {
        if (msg.sender == admin()) {
            revert("admin cannot call implementation");
        }
        assembly {
            let impl := sload(IMPL_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
contract CleanImpl {
    address public owner;
    constructor() { _disableInitializers(); }
    function _disableInitializers() internal { }
    function initialize(address _owner) external initializer {
        owner = _owner;
    }
    modifier initializer() { _; }
}
"""

# ===========================================================================
# Access control / signatures
# ===========================================================================

VULN["access_control_tx_origin_reliance"] = r"""
pragma solidity ^0.8.20;
contract OriginAuth {
    address public owner;
    uint256 public vault;
    function withdraw() external {
        require(tx.origin == owner, "not owner");
        vault = 0;
    }
}
"""

VULN["access_control_role_revocation_hole"] = r"""
pragma solidity ^0.8.20;
contract NoRevoke {
    mapping(bytes32 => mapping(address => bool)) public roles;
    function grantRole(bytes32 role, address account) external {
        roles[role][account] = true;
    }
}
"""

VULN["ecdsa_signature_malleability"] = r"""
pragma solidity ^0.8.20;
contract MalleableClaim {
    mapping(address => uint256) public nonces;
    function claimWithSignature(uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, amount, nonce, nonces[msg.sender]));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0));
        nonces[msg.sender] = nonce + 1;
    }
}
"""

VULN["ecdsa_signature_replay_cross_chain"] = r"""
pragma solidity ^0.8.20;
contract CrossChainClaim {
    mapping(address => uint256) public nonces;
    function claimWithSignature(uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(address(this), amount, nonce));
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "s");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0));
        nonces[msg.sender] = nonce + 1;
    }
}
"""

VULN["ecdsa_nonce_reuse_vulnerability"] = r"""
pragma solidity ^0.8.20;
contract ReplayClaim {
    function claimWithSignature(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(this), amount));
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "s");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0));
    }
}
"""

VULN["access_control_unprotected_initializer"] = r"""
pragma solidity ^0.8.20;
contract OpenVault {
    address public owner;
    uint256 public totalDeposits;
    function initialize(address _owner) external {
        owner = _owner;
    }
}
"""

VULN["access_control_ownership_renunciation_trap"] = r"""
pragma solidity ^0.8.20;
contract RenounceTrap {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function renounceOwnership() external onlyOwner {
        owner = address(0);
    }
    function rescueFunds(address to, uint256 amount) external onlyOwner {
        (bool ok, ) = to.call{value: amount}("");
        require(ok);
    }
}
"""

VULN["access_control_multi_sig_threshold_bypass"] = r"""
pragma solidity ^0.8.20;
contract WeakMultisig {
    address[] public owners;
    uint256 public threshold = 2;
    mapping(uint256 => bool) public executed;
    function execute(uint256 txId, address target, bytes memory data) external {
        executed[txId] = true;
        target.call{value: 0}(data);
    }
}
"""

VULN["access_control_hierarchical_privilege_leak"] = r"""
pragma solidity ^0.8.20;
contract LeakyRoles {
    mapping(bytes32 => mapping(address => bool)) public roles;
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return roles[role][account];
    }
    function grantRole(bytes32 role, address account) external {
        require(hasRole(role, msg.sender), "not holder");
        roles[role][account] = true;
    }
}
"""

VULN["access_control_arbitrary_call_injection"] = r"""
pragma solidity ^0.8.20;
contract OpenExecutor {
    function exec(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        require(ok);
        return ret;
    }
}
"""

CLEAN["access"] = r"""
pragma solidity ^0.8.20;
contract CleanAccess {
    address public owner;
    mapping(address => bool) public minters;
    mapping(address => uint256) public nonces;
    uint256 public constant MAX_SIG_S = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function grantMinter(address account) external onlyOwner {
        minters[account] = true;
    }
    function removeMinter(address account) external onlyOwner {
        minters[account] = false;
    }
    function initialize(address _owner) external initializer {
        owner = _owner;
    }
    modifier initializer() { _; }
    function claimWithSignature(uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[msg.sender], "bad nonce");
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(this), amount, nonce));
        require(uint256(s) <= MAX_SIG_S, "high s");
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "not owner");
        nonces[msg.sender] = nonce + 1;
    }
}
"""

# ===========================================================================
# GameFi / NFTs / marketplaces
# ===========================================================================

VULN["bep721_mint_index_overflow"] = r"""
pragma solidity ^0.7.6;
contract OverflowMint {
    uint256 public tokenIdCounter;
    mapping(uint256 => address) public owners;
    function mint() external {
        tokenIdCounter++;
        owners[tokenIdCounter] = msg.sender;
    }
}
"""

VULN["bep721_reentrancy_on_safe_mint"] = r"""
pragma solidity ^0.8.20;
contract ReentrantMint {
    uint256 public nextId;
    uint256 public maxPerWallet = 1;
    mapping(address => uint256) public minted;
    mapping(uint256 => address) public owners;
    function mint() external {
        _safeMint(msg.sender, nextId);
        nextId++;
        minted[msg.sender]++;
    }
    function _safeMint(address to, uint256 id) internal {
        owners[id] = to;
    }
}
"""

VULN["bep1155_batch_transfer_balance_mismatch"] = r"""
pragma solidity ^0.8.20;
contract BatchToken {
    mapping(uint256 => mapping(address => uint256)) public balances;
    function safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amounts) external {
        for (uint256 i = 0; i < ids.length; i++) {
            balances[ids[i]][from] -= amounts[i];
            balances[ids[i]][to] += amounts[i];
        }
    }
}
"""

VULN["marketplace_atomic_match_frontrun"] = r"""
pragma solidity ^0.8.20;
interface IERC721G {
    function transferFrom(address from, address to, uint256 tokenId) external;
}
contract SpoofMarket {
    function buy(address nft, uint256 tokenId, uint256 price, address seller) external payable {
        require(msg.value == price);
        IERC721G(nft).transferFrom(seller, msg.sender, tokenId);
    }
}
"""

VULN["marketplace_fee_deduction_underflow"] = r"""
pragma solidity ^0.7.6;
contract UnderflowMarket {
    uint256 public lastProceeds;
    function settle(uint256 price, uint256 fee) external {
        lastProceeds = price - fee;
    }
}
"""

VULN["marketplace_royalties_recipient_spoofing"] = r"""
pragma solidity ^0.8.20;
contract RoyaltySpoofMarket {
    function settle(uint256 price, address royaltyRecipient) external payable {
        uint256 royalty = price * 10 / 100;
        (bool ok, ) = payable(royaltyRecipient).call{value: royalty}("");
        require(ok);
    }
}
"""

VULN["gamefi_randomness_blockhash_reliance"] = r"""
pragma solidity ^0.8.20;
contract HashGame {
    mapping(uint256 => address) public owners;
    uint256 public nextId;
    function mint() external {
        uint256 rand = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
        uint256 id = nextId++;
        owners[id] = msg.sender;
        if (rand > 90) { owners[id + 1000] = msg.sender; }
    }
}
"""

VULN["gamefi_state_desync_reward_claim"] = r"""
pragma solidity ^0.8.20;
contract DesyncGame {
    mapping(address => uint256) public pendingRewards;
    IERC20S public rewardToken;
    function claim() external {
        uint256 amount = pendingRewards[msg.sender];
        rewardToken.transfer(msg.sender, amount);
    }
}
"""

VULN["gamefi_asset_duplication_on_burn"] = r"""
pragma solidity ^0.8.20;
contract DupeBurn {
    mapping(uint256 => address) public owners;
    IERC20S public rewardToken;
    function burn(uint256 tokenId) external {
        rewardToken.transfer(msg.sender, 100);
    }
}
"""

VULN["marketplace_expired_order_execution"] = r"""
pragma solidity ^0.8.20;
contract StaleMarket {
    struct Order { address seller; uint256 price; uint256 expiry; }
    mapping(uint256 => Order) public orders;
    function buy(uint256 orderId, address nft, uint256 tokenId) external payable {
        Order storage o = orders[orderId];
        require(msg.value == o.price);
        IERC721G(nft).transferFrom(o.seller, msg.sender, tokenId);
    }
}
"""

CLEAN["gamefi"] = r"""
pragma solidity ^0.8.20;
contract CleanGame {
    uint256 public nextId;
    uint256 public totalSupply;
    mapping(uint256 => address) public owners;
    mapping(address => uint256) public pendingRewards;
    mapping(uint256 => uint256) public orderExpiry;
    bool private locked;
    modifier nonReentrant() { require(!locked); locked = true; _; locked = false; }
    function mint() external nonReentrant {
        uint256 id = nextId;
        nextId = id + 1;
        owners[id] = msg.sender;
        _safeMint(msg.sender, id);
    }
    function _safeMint(address to, uint256 id) internal {
        owners[id] = to;
    }
    function safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amounts) external {
        require(ids.length == amounts.length, "length mismatch");
        for (uint256 i = 0; i < ids.length; i++) {
            owners[ids[i]] = to;
        }
    }
    function claim() external {
        uint256 amount = pendingRewards[msg.sender];
        pendingRewards[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
    function burn(uint256 id) external {
        require(owners[id] == msg.sender);
        owners[id] = address(0);
        totalSupply -= 1;
    }
    function buy(uint256 orderId) external {
        require(block.timestamp <= orderExpiry[orderId], "expired");
    }
}
"""

# ===========================================================================
# MEV / bridges
# ===========================================================================

VULN["mev_sandwich_attack_vulnerability"] = r"""
pragma solidity ^0.8.20;
interface IPancakeRouter07 {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory);
}
contract VictimVault {
    address public router;
    function swap(uint256 amountIn, address[] calldata path) external {
        IPancakeRouter07(router).swapExactTokensForTokens(amountIn, 1, path, address(this), block.timestamp);
    }
}
"""

VULN["bridge_deposit_event_spoofing"] = r"""
pragma solidity ^0.8.20;
contract SpoofBridge {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    function _mint(address to, uint256 amount) internal {
        balances[to] += amount;
        totalSupply += amount;
    }
    function claimDeposit(uint256 amount) external {
        _mint(msg.sender, amount);
    }
}
"""

VULN["bridge_validator_quorum_manipulation"] = r"""
pragma solidity ^0.8.20;
contract WeakQuorumBridge {
    mapping(address => bool) public validators;
    uint256 public executedCount;
    function executeMessage(bytes32 messageHash, bytes[] calldata signatures) external {
        uint256 count = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = ecrecover(messageHash, 28, bytes32(0), bytes32(0));
            if (validators[signer]) { count += 1; }
        }
        require(count >= 1, "any");
        executedCount += 1;
    }
}
"""

VULN["bridge_wrapped_token_mint_unbacked"] = r"""
pragma solidity ^0.8.20;
contract WrappedBridgeToken {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }
}
"""

VULN["bridge_message_payload_injection"] = r"""
pragma solidity ^0.8.20;
contract InjectBridge {
    function executeMessage(address target, bytes calldata data) external {
        target.call(data);
    }
}
"""

VULN["mev_block_number_lock_bypass"] = r"""
pragma solidity ^0.8.20;
contract AsymToken {
    event Transfer(address indexed from, address indexed to, uint256 amount);
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastBuyBlock;
    function buy(uint256 amount) external {
        lastBuyBlock[msg.sender] = block.number;
        balances[msg.sender] += amount;
        emit Transfer(address(0), msg.sender, amount);
    }
    function sell(uint256 amount) external {
        require(block.number > lastBuyBlock[msg.sender] + 3, "locked");
        balances[msg.sender] -= amount;
        emit Transfer(msg.sender, address(0), amount);
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
"""

VULN["bridge_withdrawer_identity_spoof"] = r"""
pragma solidity ^0.8.20;
contract SpoofWithdrawBridge {
    function withdraw(uint256 amount, address to) external {
        (bool ok, ) = payable(to).call{value: amount}("");
        require(ok);
    }
}
"""

VULN["bridge_emergency_pause_lockup"] = r"""
pragma solidity ^0.8.20;
contract PauseTrap {
    bool public paused;
    mapping(address => uint256) public balances;
    function pause() external {
        paused = true;
    }
    function withdraw(uint256 amount) external {
        require(!paused, "paused");
        balances[msg.sender] -= amount;
    }
}
"""

VULN["mev_arbitrary_liquidation_frontrun"] = r"""
pragma solidity ^0.8.20;
contract FrontrunLiquidator {
    mapping(address => uint256) public collateralOf;
    function liquidate(address victim, uint256 price) external {
        uint256 seized = collateralOf[victim] * price / 100;
        collateralOf[victim] = 0;
        collateralOf[msg.sender] += seized;
    }
}
"""

VULN["bridge_native_gas_drain"] = r"""
pragma solidity ^0.8.20;
contract GasDrainRelay {
    function claimGasRefund(uint256 fee) external {
        (bool ok, ) = msg.sender.call{value: fee}("");
        require(ok);
    }
}
"""

CLEAN["mev_bridge"] = r"""
pragma solidity ^0.8.20;
contract CleanBridge {
    mapping(address => bool) public validators;
    mapping(bytes32 => mapping(address => bool)) public seenSigners;
    uint256 public quorum = 3;
    mapping(uint256 => address) public depositRecipient;
    bool public paused;
    address public guardian;
    function processMessage(bytes32 messageHash, bytes[] calldata signatures) external {
        uint256 count = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(messageHash, signatures[i]);
            require(validators[signer], "not validator");
            require(!seenSigners[messageHash][signer], "dup");
            seenSigners[messageHash][signer] = true;
            count += 1;
        }
        require(count >= quorum, "quorum");
    }
    function recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        return address(0);
    }
    function withdraw(uint256 depositId) external {
        address to = depositRecipient[depositId];
        (bool ok, ) = to.call{value: 1 ether}("");
        require(ok);
    }
    function pause() external {
        require(msg.sender == guardian, "not guardian");
        paused = true;
    }
}
"""

# ===========================================================================
# Math / system
# ===========================================================================

VULN["math_unchecked_downcasting"] = r"""
pragma solidity ^0.8.20;
contract Downcaster {
    uint128 public storedAmount;
    function store(uint256 amount) external {
        storedAmount = uint128(amount);
    }
}
"""

VULN["gas_denial_of_service_loop"] = r"""
pragma solidity ^0.8.20;
contract DistributeAll {
    address[] public users;
    function distribute() external {
        for (uint256 i = 0; i < users.length; i++) {
            (bool ok, ) = users[i].call{value: 1 ether}("");
            require(ok);
        }
    }
}
"""

VULN["system_stale_oracle_data"] = r"""
pragma solidity ^0.8.20;
interface IChainlinkFeed {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}
contract StaleOracleUser {
    IChainlinkFeed public feed;
    function getPrice() external view returns (uint256) {
        (, int256 price, , , ) = feed.latestRoundData();
        return uint256(price);
    }
}
"""

VULN["math_division_before_multiplication"] = r"""
pragma solidity ^0.8.20;
contract DivFirst {
    uint256 public lastFee;
    function feeFor(uint256 amount, uint256 percent) external {
        lastFee = amount / 100 * percent;
    }
}
"""

VULN["system_ether_transfer_fallback_brick"] = r"""
pragma solidity ^0.8.20;
contract BrickPayout {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
"""

VULN["system_hardcoded_gas_limits"] = r"""
pragma solidity ^0.8.20;
contract GasStipend {
    function poke(address target, bytes calldata data) external {
        target.call{gas: 5000}(data);
    }
}
"""

VULN["math_signed_unsigned_comparison"] = r"""
pragma solidity ^0.8.20;
contract SignFlip {
    int256 public delta;
    function isAbove(uint256 threshold) external view returns (bool) {
        return uint256(delta) > threshold;
    }
}
"""

VULN["system_selfdestruct_funds_trap"] = r"""
pragma solidity ^0.8.20;
contract TrapVault {
    address public owner;
    function destroy() external {
        selfdestruct(payable(owner));
    }
    receive() external payable { }
}
"""

VULN["system_assembly_memory_overwrite"] = r"""
pragma solidity ^0.8.20;
contract MemStomp {
    uint256 public stomped;
    function stomp() external {
        assembly { mstore(0x40, 0x1234) }
        stomped = 1;
    }
}
"""

VULN["system_unbounded_fee_parameter"] = r"""
pragma solidity ^0.8.20;
contract UnboundedFee {
    uint256 public taxFee;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setTaxFee(uint256 fee) external onlyOwner {
        taxFee = fee;
    }
}
"""

CLEAN["math_system"] = r"""
pragma solidity ^0.8.20;
interface ISafeCast {
    function toUint128(uint256 value) external pure returns (uint128);
}
interface IChainlinkFeedM {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}
contract CleanMath {
    uint256 public total;
    uint128 public stored;
    uint256 public feePercent = 3;
    address[] public users;
    IChainlinkFeedM public feed;
    ISafeCast public safeCast;
    function store(uint256 amount) external {
        stored = safeCast.toUint128(amount);
        total += amount;
    }
    function feeFor(uint256 amount) external {
        total = amount * feePercent / 100;
    }
    function aboveSwapThreshold(uint256 amount) external view returns (bool) {
        return amount > total / 10 ** 5;
    }
    function getPrice() external view returns (uint256) {
        (, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();
        require(block.timestamp - updatedAt <= 3600, "stale");
        return uint256(price);
    }
    function process(uint256 start, uint256 end) external {
        require(end - start <= 50, "page too big");
        for (uint256 i = start; i < end && i < users.length; i++) {
            (bool ok, ) = users[i].call{value: 1 ether}("");
            require(ok);
        }
    }
    function setFeePercent(uint256 fee) external {
        require(fee <= 10, "fee too high");
        feePercent = fee;
    }
    function memRead() external pure returns (uint256 x) {
        assembly { x := mload(0x40) }
    }
}
"""
