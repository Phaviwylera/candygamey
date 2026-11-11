// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Fork-only regression probes for the unauthenticated callback finding.
/// @dev These calls execute only against a local Foundry fork. They never submit a transaction.
interface Vm {
    function envString(string calldata name) external view returns (string memory value);
    function createSelectFork(string calldata url) external returns (uint256 forkId);
    function prank(address msgSender) external;
    function load(address target, bytes32 slot) external returns (bytes32 value);
    function loadTransient(address target, bytes32 slot) external returns (bytes32 value);
    function record() external;
    function accesses(address target)
        external
        returns (bytes32[] memory reads, bytes32[] memory writes);
}

interface IERC20Balance {
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
}

/// @dev Models an unprivileged contract caller making two callback calls in one transaction.
contract CallbackBatcher {
    function callTwice(address target, bytes calldata callData)
        external
        returns (bool firstAccepted, bytes32 firstReturnHash, bool secondAccepted, bytes32 secondReturnHash)
    {
        bytes memory result;
        (firstAccepted, result) = target.call(callData);
        firstReturnHash = keccak256(result);
        (secondAccepted, result) = target.call(callData);
        secondReturnHash = keccak256(result);
    }
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

    // Runtime CODECOPY constant used as the transient-storage key around offsets 0x0bcd/0x0c26.
    bytes32 private constant CALLBACK_TRANSIENT_SLOT =
        0x0c1559971a4909806e7ae64509897f962b31c92de0effb36e7c2f25c9a5c4d34;
    uint256 private constant STORAGE_SLOTS_TO_SNAPSHOT = 32;

    CallbackBatcher private batcher;

    event DirectCallbackAttempt(
        bytes4 indexed selector,
        uint256 indexed scenario,
        bool accepted,
        uint256 gasUsed,
        uint256 returnDataLength,
        bytes32 returnDataHash
    );
    event NativeBalanceDiff(uint256 botBefore, uint256 botAfter, uint256 callerBefore, uint256 callerAfter);
    event TokenBalanceDiff(
        address indexed token,
        uint256 botBefore,
        uint256 botAfter,
        uint256 callerBefore,
        uint256 callerAfter
    );
    event TokenAllowanceDiff(address indexed token, uint256 beforeValue, uint256 afterValue);
    event PersistentSlotDiff(bytes32 indexed slot, bytes32 beforeValue, bytes32 afterValue);
    event PersistentWriteObserved(bytes32 indexed slot, bytes32 afterValue);
    event TransientSlotDiff(bytes32 indexed slot, bytes32 beforeValue, bytes32 afterValue);
    event CallbackSequenceResult(
        bytes4 indexed selector,
        bool firstAccepted,
        bool secondAccepted,
        uint256 gasUsed,
        uint256 scenario
    );
    event CallbackSequenceReturnHashes(bytes32 firstReturnHash, bytes32 secondReturnHash);

    function setUp() public {
        vm.createSelectFork(vm.envString("RPC_URL"));
        require(block.chainid == 1, "RPC_URL must point to Ethereum mainnet");
        require(BOT.code.length != 0, "target has no code at fork head");
        batcher = new CallbackBatcher();
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

    /// @notice Attempts to reuse callback transient state across calls in one attacker transaction.
    function test_uni_callbackTwiceInOneTransaction() public {
        _attemptTwice(_uniSelector(), 1, 0, new bytes(0x200), 4);
    }

    function test_pancake_callbackTwiceInOneTransaction() public {
        _attemptTwice(_pancakeSelector(), 1, 0, new bytes(0x200), 5);
    }

    function _uniSelector() private pure returns (bytes4) {
        return bytes4(keccak256("uniswapV3SwapCallback(int256,int256,bytes)"));
    }

    function _pancakeSelector() private pure returns (bytes4) {
        return bytes4(keccak256("pancakeV3SwapCallback(int256,int256,bytes)"));
    }

    struct Snapshot {
        uint256 botNative;
        uint256 callerNative;
        uint256[8] botTokens;
        uint256[8] callerTokens;
        uint256[8] allowances;
        bytes32[32] persistentSlots;
        bytes32 callbackTransientSlot;
    }

    function _attempt(
        bytes4 selector,
        int256 amount0Delta,
        int256 amount1Delta,
        bytes memory data,
        uint256 scenario
    ) private {
        bytes memory callData = abi.encodeWithSelector(
            selector, amount0Delta, amount1Delta, data
        );
        Snapshot memory beforeState = _snapshot(ATTACKER);

        vm.record();
        uint256 gasStart = gasleft();
        vm.prank(ATTACKER);
        (bool accepted, bytes memory returnData) = BOT.call{gas: 10_000_000}(callData);
        uint256 gasUsed = gasStart - gasleft();

        emit DirectCallbackAttempt(
            selector, scenario, accepted, gasUsed, returnData.length, keccak256(returnData)
        );
        _reportAndAssert(beforeState, ATTACKER);
        _emitPersistentWrites();
    }

    function _attemptTwice(
        bytes4 selector,
        int256 amount0Delta,
        int256 amount1Delta,
        bytes memory data,
        uint256 scenario
    ) private {
        bytes memory callData = abi.encodeWithSelector(
            selector, amount0Delta, amount1Delta, data
        );
        address receiver = address(batcher);
        Snapshot memory beforeState = _snapshot(receiver);

        vm.record();
        uint256 gasStart = gasleft();
        vm.prank(ATTACKER);
        (
            bool firstAccepted,
            bytes32 firstReturnHash,
            bool secondAccepted,
            bytes32 secondReturnHash
        ) = batcher.callTwice(BOT, callData);
        uint256 gasUsed = gasStart - gasleft();

        emit CallbackSequenceResult(selector, firstAccepted, secondAccepted, gasUsed, scenario);
        emit CallbackSequenceReturnHashes(firstReturnHash, secondReturnHash);
        _reportAndAssert(beforeState, receiver);
        _emitPersistentWrites();
    }

    function _snapshot(address caller) private returns (Snapshot memory s) {
        s.botNative = BOT.balance;
        s.callerNative = caller.balance;
        address[8] memory tokens = _tokens();
        for (uint256 i; i < tokens.length; ++i) {
            s.botTokens[i] = _balanceOf(tokens[i], BOT);
            s.callerTokens[i] = _balanceOf(tokens[i], caller);
            s.allowances[i] = _allowance(tokens[i], BOT, caller);
        }
        for (uint256 i; i < STORAGE_SLOTS_TO_SNAPSHOT; ++i) {
            s.persistentSlots[i] = vm.load(BOT, bytes32(i));
        }
        s.callbackTransientSlot = vm.loadTransient(BOT, CALLBACK_TRANSIENT_SLOT);
    }

    function _reportAndAssert(Snapshot memory beforeState, address caller) private {
        address[8] memory tokens = _tokens();
        uint256 botNativeAfter = BOT.balance;
        uint256 callerNativeAfter = caller.balance;
        emit NativeBalanceDiff(
            beforeState.botNative, botNativeAfter, beforeState.callerNative, callerNativeAfter
        );
        require(botNativeAfter >= beforeState.botNative, "bot native balance decreased");
        require(callerNativeAfter <= beforeState.callerNative, "caller gained native currency");

        for (uint256 i; i < tokens.length; ++i) {
            uint256 botAfter = _balanceOf(tokens[i], BOT);
            uint256 callerAfter = _balanceOf(tokens[i], caller);
            uint256 allowanceAfter = _allowance(tokens[i], BOT, caller);
            emit TokenBalanceDiff(
                tokens[i], beforeState.botTokens[i], botAfter, beforeState.callerTokens[i], callerAfter
            );
            emit TokenAllowanceDiff(tokens[i], beforeState.allowances[i], allowanceAfter);
            require(botAfter >= beforeState.botTokens[i], "bot token balance decreased");
            require(callerAfter <= beforeState.callerTokens[i], "caller gained a tracked token");
            require(allowanceAfter <= beforeState.allowances[i], "bot granted caller a token allowance");
        }

        for (uint256 i; i < STORAGE_SLOTS_TO_SNAPSHOT; ++i) {
            bytes32 slot = bytes32(i);
            bytes32 afterValue = vm.load(BOT, slot);
            if (afterValue != beforeState.persistentSlots[i]) {
                emit PersistentSlotDiff(slot, beforeState.persistentSlots[i], afterValue);
            }
        }

        bytes32 transientAfter = vm.loadTransient(BOT, CALLBACK_TRANSIENT_SLOT);
        emit TransientSlotDiff(
            CALLBACK_TRANSIENT_SLOT, beforeState.callbackTransientSlot, transientAfter
        );
    }

    function _emitPersistentWrites() private {
        (, bytes32[] memory writes) = vm.accesses(BOT);
        for (uint256 i; i < writes.length; ++i) {
            emit PersistentWriteObserved(writes[i], vm.load(BOT, writes[i]));
        }
    }

    function _tokens() private pure returns (address[8] memory tokens) {
        tokens = [WETH, USDC, USDT, WBTC, DAI, USDS, WSTETH, USDE];
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
