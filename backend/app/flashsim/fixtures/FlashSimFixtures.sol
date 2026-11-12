// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Fixtures for the flash-loan simulation matrix gate.
/// - SpotOracleVault reproduces the DUEL convertRain shape: the payout for a
///   conversion is LINEAR in the spot unit price read from
///   router.getAmountsOut(1 unit, path), paid out of the vault's own balance.
/// - TwapOracleVault exposes the identical interface but prices from a
///   TWAP-style oracle whose price cannot move inside one block/attack.
/// - MockV2Pair implements real V2 swap semantics (997/1000 fee, K check,
///   flash-swap callback). MockFlashLender charges a 0.09% fee.

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "bal");
        require(allowance[from][msg.sender] >= amount, "allow");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

interface IV2Callee {
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

contract MockV2Pair {
    address public token0;
    address public token1;
    uint112 private reserve0;
    uint112 private reserve1;

    constructor(address _token0, address _token1) {
        token0 = _token0;
        token1 = _token1;
    }

    function getReserves() public view returns (uint112, uint112, uint32) {
        return (reserve0, reserve1, 0);
    }

    function sync() external {
        reserve0 = uint112(IERC20Like(token0).balanceOf(address(this)));
        reserve1 = uint112(IERC20Like(token1).balanceOf(address(this)));
    }

    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external {
        require(amount0Out > 0 || amount1Out > 0, "out=0");
        require(amount0Out < reserve0 && amount1Out < reserve1, "liq");
        if (amount0Out > 0) require(IERC20Like(token0).transfer(to, amount0Out), "t0");
        if (amount1Out > 0) require(IERC20Like(token1).transfer(to, amount1Out), "t1");
        if (data.length > 0) {
            IV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);
        }
        uint256 balance0 = IERC20Like(token0).balanceOf(address(this));
        uint256 balance1 = IERC20Like(token1).balanceOf(address(this));
        uint256 amount0In = balance0 > uint256(reserve0) - amount0Out
            ? balance0 - (uint256(reserve0) - amount0Out) : 0;
        uint256 amount1In = balance1 > uint256(reserve1) - amount1Out
            ? balance1 - (uint256(reserve1) - amount1Out) : 0;
        require(amount0In > 0 || amount1In > 0, "in=0");
        uint256 adj0 = balance0 * 1000 - amount0In * 3;
        uint256 adj1 = balance1 * 1000 - amount1In * 3;
        require(adj0 * adj1 >= uint256(reserve0) * uint256(reserve1) * (1000 ** 2), "K");
        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
    }
}

contract MockRouter {
    mapping(bytes32 => address) private pairs;

    function setPair(address tokenA, address tokenB, address pair) external {
        pairs[keccak256(abi.encodePacked(tokenA, tokenB))] = pair;
        pairs[keccak256(abi.encodePacked(tokenB, tokenA))] = pair;
    }

    function _pair(address a, address b) internal view returns (address) {
        address p = pairs[keccak256(abi.encodePacked(a, b))];
        require(p != address(0), "no pair");
        return p;
    }

    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        public pure returns (uint256)
    {
        uint256 withFee = amountIn * 997;
        return (withFee * reserveOut) / (reserveIn * 1000 + withFee);
    }

    function getAmountsOut(uint256 amountIn, address[] memory path)
        public view returns (uint256[] memory amounts)
    {
        require(path.length >= 2, "path");
        amounts = new uint256[](path.length);
        amounts[0] = amountIn;
        for (uint256 i = 0; i + 1 < path.length; i++) {
            MockV2Pair pair = MockV2Pair(_pair(path[i], path[i + 1]));
            (uint112 r0, uint112 r1, ) = pair.getReserves();
            (uint256 rin, uint256 rout) = pair.token0() == path[i]
                ? (uint256(r0), uint256(r1)) : (uint256(r1), uint256(r0));
            amounts[i + 1] = getAmountOut(amounts[i], rin, rout);
        }
    }
}

interface IFlashBorrower {
    function flashCallback(address token, uint256 amount, uint256 fee, bytes calldata data) external;
}

contract MockFlashLender {
    uint256 public constant FEE_BPS = 9; // 0.09%

    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external {
        uint256 before = IERC20Like(token).balanceOf(address(this));
        require(before >= amount, "lender liq");
        uint256 fee = (amount * FEE_BPS) / 10000;
        if (fee == 0 && amount > 0) fee = 1;
        require(IERC20Like(token).transfer(receiver, amount), "lend");
        IFlashBorrower(receiver).flashCallback(token, amount, fee, data);
        require(IERC20Like(token).balanceOf(address(this)) >= before + fee, "not repaid");
    }
}

contract SpotOracleVault {
    MockRouter public router;
    address public inputToken;
    address public payoutToken;
    address[] public path;

    constructor(address _router, address _input, address _payout) {
        router = MockRouter(_router);
        inputToken = _input;
        payoutToken = _payout;
        path.push(_input);
        path.push(_payout);
    }

    /// Spot unit price of 1 input unit (1e18) in payout units, read live from
    /// the AMM via getAmountsOut. This is the manipulable oracle read.
    function unitPrice() public view returns (uint256) {
        uint256[] memory amounts = router.getAmountsOut(1e18, path);
        return amounts[amounts.length - 1];
    }

    function quoteConvert(uint256 amountIn) public view returns (uint256) {
        return (amountIn * unitPrice()) / 1e18;
    }

    /// DUEL shape: payout is LINEAR in the spot unit price, paid from the
    /// vault's own payout-token balance. Pump the spot price and the same
    /// input amount converts for proportionally more payout.
    function convert(uint256 amountIn) external returns (uint256 payout) {
        require(IERC20Like(inputToken).transferFrom(msg.sender, address(this), amountIn), "in");
        payout = quoteConvert(amountIn);
        require(IERC20Like(payoutToken).balanceOf(address(this)) >= payout, "vault liq");
        require(IERC20Like(payoutToken).transfer(msg.sender, payout), "out");
    }
}

contract MockTwapOracle {
    /// Payout units per 1e18 input units. Set once at fixture setup to the
    /// honest pre-attack spot price. Intentionally has no intra-block update
    /// path: a TWAP over a real window cannot move inside one attack tx.
    uint256 public price;

    constructor(uint256 _price) {
        price = _price;
    }
}

contract TwapOracleVault {
    MockTwapOracle public oracle;
    address public inputToken;
    address public payoutToken;

    constructor(address _oracle, address _input, address _payout) {
        oracle = MockTwapOracle(_oracle);
        inputToken = _input;
        payoutToken = _payout;
    }

    function unitPrice() public view returns (uint256) {
        return oracle.price();
    }

    function quoteConvert(uint256 amountIn) public view returns (uint256) {
        return (amountIn * oracle.price()) / 1e18;
    }

    function convert(uint256 amountIn) external returns (uint256 payout) {
        require(IERC20Like(inputToken).transferFrom(msg.sender, address(this), amountIn), "in");
        payout = quoteConvert(amountIn);
        require(IERC20Like(payoutToken).balanceOf(address(this)) >= payout, "vault liq");
        require(IERC20Like(payoutToken).transfer(msg.sender, payout), "out");
    }
}

/// Generic step executor used as the unfunded stranger. Starts with nothing;
/// every token it ends an attack holding is measured by the matrix.
contract FlashExecutor {
    address public immutable controller;

    constructor() {
        controller = msg.sender;
    }

    receive() external payable {}

    function _run(address[] memory targets, bytes[] memory datas) internal {
        require(targets.length == datas.length, "steps");
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, bytes memory ret) = targets[i].call(datas[i]);
            if (!ok) {
                assembly {
                    revert(add(ret, 32), mload(ret))
                }
            }
        }
    }

    function execute(address[] calldata targets, bytes[] calldata datas) external {
        require(msg.sender == controller, "ctrl");
        _run(targets, datas);
    }

    /// MockFlashLender callback. data = abi.encode(targets, datas).
    function flashCallback(address token, uint256 amount, uint256 fee, bytes calldata data) external {
        (address[] memory targets, bytes[] memory datas) =
            abi.decode(data, (address[], bytes[]));
        _run(targets, datas);
        require(IERC20Like(token).transfer(msg.sender, amount + fee), "repay");
    }

    function _v2Callback(bytes calldata data) internal {
        (address[] memory targets, bytes[] memory datas, address repayToken, uint256 repayAmount) =
            abi.decode(data, (address[], bytes[], address, uint256));
        _run(targets, datas);
        require(IERC20Like(repayToken).transfer(msg.sender, repayAmount), "repay");
    }

    /// V2 flash-swap callback. data = abi.encode(targets, datas, repayToken, repayAmount).
    function uniswapV2Call(address, uint256, uint256, bytes calldata data) external {
        _v2Callback(data);
    }

    /// PancakeSwap V2 uses a differently-named callback, same semantics.
    function pancakeCall(address, uint256, uint256, bytes calldata data) external {
        _v2Callback(data);
    }
}
