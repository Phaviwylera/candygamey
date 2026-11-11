// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Fork-only regression probes for the unauthenticated callback finding.
/// @dev These calls execute only against a local Foundry fork. They never submit a transaction.
interface Vm {
    function envString(string calldata name) external view returns (string memory value);
    function createSelectFork(string calldata url) external returns (uint256 forkId);
    function prank(address msgSender) external;
}

interface IERC20Balance {
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract CallbackAuthForkTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address private constant BOT = 0xBdb3ba9ffe392549E1f8658DD2630c141fDF47B6;
    address private constant ATTACKER = address(uint160(0xabad1dea));

    address private constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address private constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address private constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address private constant WBTC = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;
    address private constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address private constant USDS = 0xdC035D45d973E3EC169d2276DDab16f1e407384F;
    address private constant WSTETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
    address private constant USDE = 0x4c9EDD5852cd905f086C759E8383e09bff1E68B3;

    event DirectCallbackAttempt(bytes4 indexed selector, uint256 indexed scenario, bool accepted);

    function setUp() public {
        vm.createSelectFork(vm.envString("RPC_URL"));
        require(block.chainid == 1, "RPC_URL must point to Ethereum mainnet");
        require(BOT.code.length != 0, "target has no code at fork head");
    }

    // Keep each probe in its own test transaction: EIP-1153 transient storage persists across
    // calls within one transaction, while a real direct attack starts with clean transient state.
    function test_uni_emptyPayload_amount0() public {
        _attempt(_uniSelector(), 1, 0, bytes(""), 0);
    }

    function test_uni_emptyPayload_amount1() public {
        _attempt(_uniSelector(), 0, 1, bytes(""), 1);
    }

    function test_uni_longPayload_amount0() public {
        _attempt(_uniSelector(), 1, 0, new bytes(0x200), 2);
    }

    function test_uni_longPayload_amount1() public {
        _attempt(_uniSelector(), 0, 1, new bytes(0x200), 3);
    }

    function test_pancake_emptyPayload_amount0() public {
        _attempt(_pancakeSelector(), 1, 0, bytes(""), 0);
    }

    function test_pancake_emptyPayload_amount1() public {
        _attempt(_pancakeSelector(), 0, 1, bytes(""), 1);
    }

    function test_pancake_longPayload_amount0() public {
        _attempt(_pancakeSelector(), 1, 0, new bytes(0x200), 2);
    }

    function test_pancake_longPayload_amount1() public {
        _attempt(_pancakeSelector(), 0, 1, new bytes(0x200), 3);
    }

    function _uniSelector() private pure returns (bytes4) {
        return bytes4(keccak256("uniswapV3SwapCallback(int256,int256,bytes)"));
    }

    function _pancakeSelector() private pure returns (bytes4) {
        return bytes4(keccak256("pancakeV3SwapCallback(int256,int256,bytes)"));
    }

    function _attempt(
        bytes4 selector,
        int256 amount0Delta,
        int256 amount1Delta,
        bytes memory data,
        uint256 scenario
    ) private {
        uint256 nativeBefore = BOT.balance;
        uint256 attackerNativeBefore = ATTACKER.balance;
        address[8] memory tokens = [WETH, USDC, USDT, WBTC, DAI, USDS, WSTETH, USDE];
        uint256[8] memory botBefore;
        uint256[8] memory attackerBefore;
        uint256[8] memory allowanceBefore;

        for (uint256 i; i < tokens.length; ++i) {
            botBefore[i] = _balanceOf(tokens[i], BOT);
            attackerBefore[i] = _balanceOf(tokens[i], ATTACKER);
            allowanceBefore[i] = _allowance(tokens[i], BOT, ATTACKER);
        }

        bytes memory callData = abi.encodeWithSelector(
            selector, amount0Delta, amount1Delta, data
        );
        vm.prank(ATTACKER);
        (bool accepted,) = BOT.call{gas: 10_000_000}(callData);
        emit DirectCallbackAttempt(selector, scenario, accepted);

        // A callback may revert (the expected result for an unauthenticated call), or it may
        // accept a harmless/no-op payload. The security invariant is that neither outcome moves
        // the bot's assets to the arbitrary caller.
        require(BOT.balance >= nativeBefore, "bot native balance decreased");
        require(ATTACKER.balance <= attackerNativeBefore, "attacker gained native currency");
        for (uint256 i; i < tokens.length; ++i) {
            require(_balanceOf(tokens[i], BOT) >= botBefore[i], "bot token balance decreased");
            require(
                _balanceOf(tokens[i], ATTACKER) <= attackerBefore[i],
                "attacker gained a tracked token"
            );
            require(
                _allowance(tokens[i], BOT, ATTACKER) <= allowanceBefore[i],
                "bot granted attacker a token allowance"
            );
        }
    }

    function _balanceOf(address token, address account) private view returns (uint256 value) {
        (bool ok, bytes memory result) = token.staticcall(
            abi.encodeWithSelector(IERC20Balance.balanceOf.selector, account)
        );
        require(ok && result.length >= 32, "balanceOf failed; check fork/token addresses");
        value = abi.decode(result, (uint256));
    }

    function _allowance(address token, address owner, address spender)
        private
        view
        returns (uint256 value)
    {
        (bool ok, bytes memory result) = token.staticcall(
            abi.encodeWithSelector(IERC20Balance.allowance.selector, owner, spender)
        );
        require(ok && result.length >= 32, "allowance failed; check fork/token addresses");
        value = abi.decode(result, (uint256));
    }
}
