// Prints the decoded revert reason for each of the 5 scanner payloads.
const { VM } = require('@ethereumjs/vm');
const { Common, Hardfork } = require('@ethereumjs/common');
const { Address, hexToBytes, bytesToHex, Account } = require('@ethereumjs/util');
const { Interface, AbiCoder } = require('ethers');
const build = require('./artifacts/MevWeth.json');

const iface = new Interface(build.abi);
const coder = AbiCoder.defaultAbiCoder();
const ONE = 10n ** 18n;
const MAX = (1n << 256n) - 1n;
const deployer = '0x1111111111111111111111111111111111111111';
const alice = '0x2222222222222222222222222222222222222222';
const attacker = '0x000000000000000000000000000000000badc0de';

(async () => {
  const vm = await VM.create({ common: new Common({ chain: 'mainnet', hardfork: Hardfork.Cancun }) });
  const at = (a) => new Address(hexToBytes(a));
  for (const a of [deployer, alice, attacker]) {
    const acct = (await vm.stateManager.getAccount(at(a))) ?? new Account();
    acct.balance = 1000n * ONE;
    await vm.stateManager.putAccount(at(a), acct);
  }
  const d = await vm.evm.runCall({
    caller: at(deployer), to: undefined, data: hexToBytes(build.bytecode),
    gasLimit: 30_000_000n, value: 0n, createdAddresses: new Set(),
    salt: hexToBytes('0x13061f1c1bbc52beabac07a60520c45cf18845c922387ca542de860049e90910'),
  });
  const TARGET = bytesToHex(d.createdAddress.bytes);

  async function run(caller, data, value = 0n) {
    const r = await vm.evm.runCall({
      caller: at(caller), to: at(TARGET), data: typeof data === 'string' ? hexToBytes(data) : data,
      gasLimit: 10_000_000n, value, createdAddresses: new Set(),
    });
    return r.execResult;
  }
  // fund: alice deposits 10 ETH, alice adds 5 ETH of MEV
  await run(alice, iface.encodeFunctionData('deposit', []), 10n * ONE);
  await run(alice, iface.encodeFunctionData('addMev(uint256)', [5n * ONE]));
  const pot = BigInt(coder.decode(['uint256'], (await run(attacker, iface.encodeFunctionData('mev', []))).returnValue)[0]);
  console.log('seeded pot =', pot, '\n');

  const cases = [
    ['#1  getMev(uint256) pot+1', 'getMev(uint256)', [pot + 1n]],
    ['#1  getMev(uint256) 2^255', 'getMev(uint256)', [1n << 255n]],
    ['#2  getMev(addr,2^255)', 'getMev(address,uint256)', [attacker, 1n << 255n]],
    ['#3  transfer(max)', 'transfer(address,uint256)', [attacker, MAX]],
    ['#4  transferFrom(max)', 'transferFrom(address,address,uint256)', [alice, attacker, MAX]],
    ['#5  transferAndCall(max)', 'transferAndCall(address,uint256,bytes)', [attacker, MAX, '0x']],
  ];
  for (const [label, fn, args] of cases) {
    const res = await run(attacker, iface.encodeFunctionData(fn, args));
    const err = res.exceptionError;
    let reason = '(executed — no revert)';
    if (err) {
      const hex = bytesToHex(res.returnValue);
      if (hex && hex !== '0x' && hex.length > 10) {
        try { reason = coder.decode(['string'], '0x' + hex.slice(10))[0]; } catch { reason = hex.slice(0, 74); }
      } else reason = `${err.error} (no reason string)`;
    }
    console.log(`${label.padEnd(28)} -> ${err ? 'REVERT' : 'OK'} | gas ${res.executionGasUsed} | ${reason}`);
  }
})();
