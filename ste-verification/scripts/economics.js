// Tests the real economic dynamic: withdraw() charges 5% unless tokens == totalSupply(),
// so the LAST holder out pays no fee and receives all ETH accumulated from everyone else's fees.
const { VM } = require('@ethereumjs/vm');
const { Common, Hardfork } = require('@ethereumjs/common');
const { Address, hexToBytes, bytesToHex, Account } = require('@ethereumjs/util');
const { Interface, AbiCoder, parseEther, formatEther } = require('ethers');
const steBuild = require('../artifacts/STE.json');
const ONE = 10n ** 18n;

(async () => {
  const vm = await VM.create({ common: new Common({ chain: 'mainnet', hardfork: Hardfork.London }) });
  const ste = new Interface(steBuild.abi);
  const coder = AbiCoder.defaultAbiCoder();
  const at = (a) => new Address(hexToBytes(a));
  const D = '0x1111111111111111111111111111111111111111';
  const A = '0x2222222222222222222222222222222222222222';
  const B = '0x4444444444444444444444444444444444444444';
  const P = '0x5555555555555555555555555555555555555555';
  for (const a of [D, A, B, P]) { const x = at(a); const ac = (await vm.stateManager.getAccount(x)) ?? new Account(); ac.balance = parseEther('100'); await vm.stateManager.putAccount(x, ac); }
  const run = (to, data, value = 0n, caller = D) => vm.evm.runCall({ caller: at(caller), to: to ? at(to) : undefined, data: hexToBytes(data), gasLimit: 30_000_000n, value, createdAddresses: new Set() });
  const d = await run(null, steBuild.bytecode);
  const STE = bytesToHex(d.createdAddress.bytes);
  const bal = async (a) => { const x = await vm.stateManager.getAccount(at(a)); return x ? x.balance : 0n; };
  const call = async (caller, fn, args = [], value = 0n) => {
    const r = await run(STE, ste.encodeFunctionData(fn, args), value, caller);
    return { ok: !r.execResult.exceptionError, out: r.execResult.returnValue };
  };
  const n = (h) => BigInt(coder.decode(['uint256'], h)[0]);
  const tok = async (a) => n((await call(P, 'balanceOf', [a])).out);
  const wd = async (a) => n((await call(P, 'withdrawable', [a])).out);
  const supply = async () => n((await call(P, 'totalSupply', [])).out);

  console.log('=== Two honest depositors, 10 ETH each ===');
  await run(STE, '0x', 10n * ONE, A);
  await run(STE, '0x', 10n * ONE, B);
  console.log('supply     :', formatEther(await supply()));
  console.log('A tokens   :', formatEther(await tok(A)), '| withdrawable', formatEther(await wd(A)));
  console.log('B tokens   :', formatEther(await tok(B)), '| withdrawable', formatEther(await wd(B)));
  console.log('contract ETH:', formatEther(await bal(STE)));
  console.log('NOTE: each deposited 10 ETH but only 19 ETH is in the contract (5% fee on 2nd deposit).\n');

  console.log('=== A withdraws first (pays 5%) ===');
  const aTok = await tok(A);
  const aBank0 = await bal(A);
  await call(A, 'withdraw', [aTok], 0n);
  const aGot = (await bal(A)) - aBank0;
  console.log(`A burned ${formatEther(aTok)} tokens, received ${formatEther(aGot)} ETH`);
  console.log('contract ETH now:', formatEther(await bal(STE)), '| supply', formatEther(await supply()));

  console.log('\n=== B withdraws second, holding ALL remaining supply ===');
  const bTok = await tok(B);
  const isAll = bTok === (await supply());
  const bBank0 = await bal(B);
  await call(B, 'withdraw', [bTok], 0n);
  const bGot = (await bal(B)) - bBank0;
  console.log(`B tokens == totalSupply ? ${isAll}  -> fee waived: ${isAll}`);
  console.log(`B burned ${formatEther(bTok)} tokens, received ${formatEther(bGot)} ETH`);
  console.log('contract ETH now:', formatEther(await bal(STE)));

  console.log('\n=== RESULT ===');
  const aNet = aGot - parseEther('10');
  const bNet = bGot - parseEther('10');
  console.log(`A deposited 10 ETH -> got ${formatEther(aGot)} ETH  | net ${formatEther(aNet)}`);
  console.log(`B deposited 10 ETH -> got ${formatEther(bGot)} ETH  | net ${formatEther(bNet)}`);
  console.log(`Difference B-A: ${formatEther(bNet - aNet)} ETH`);
  console.log('=> The last holder out is subsidised by everyone who withdrew before them.');
})();
