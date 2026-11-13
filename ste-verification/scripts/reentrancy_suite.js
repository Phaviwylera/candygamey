// ============================================================================
// STE 0x792f5bdde5f8cf4b075b7a9dc4f296341d00b0d1 — reentrancy finding test
// ----------------------------------------------------------------------------
// Compiles the byte-exact verified source (solc 0.8.0, optimizer off, istanbul)
// and executes the scanner's stated attack on a local @ethereumjs EVM (London,
// so the pre-0.8.1 SELFBALANCE/burn bug is not in play). No RPC, no broadcast.
// ============================================================================
const fs = require('fs');
const path = require('path');
const solc = require('solc');
const { VM } = require('@ethereumjs/vm');
const { Common, Hardfork } = require('@ethereumjs/common');
const { Address, hexToBytes, bytesToHex, Account } = require('@ethereumjs/util');
const { Interface, AbiCoder, keccak256, id } = require('ethers');

const ONE = 10n ** 18n;
const artifactsDir = path.join(__dirname, '..', 'artifacts');
const steBuild = require('../artifacts/STE.json');

const ADDR = {
  deployer: '0x1111111111111111111111111111111111111111',
  attacker: '0x000000000000000000000000000000000deb0de1',
  alice: '0x2222222222222222222222222222222222222222',
  bob: '0x4444444444444444444444444444444444444444',
  probe: '0x5555555555555555555555555555555555555555',
  zero: '0x0000000000000000000000000000000000000000',
};
const TRACKED = [ADDR.deployer, ADDR.attacker, ADDR.alice, ADDR.bob, ADDR.probe];

function compileAttacker() {
  const src = fs.readFileSync(path.join(__dirname, 'ReentrantAttacker.sol'), 'utf8');
  const input = {
    language: 'Solidity',
    sources: { 'ReentrantAttacker.sol': { content: src } },
    settings: {
      optimizer: { enabled: false, runs: 200 },
      evmVersion: 'istanbul',
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  for (const e of out.errors ?? []) if (e.severity === 'error') throw new Error(e.formattedMessage);
  const c = out.contracts['ReentrantAttacker.sol'].ReentrantAttacker;
  fs.writeFileSync(path.join(artifactsDir, 'ReentrantAttacker.json'),
    JSON.stringify({ abi: c.abi, bytecode: '0x' + c.evm.bytecode.object }, null, 2));
  return { abi: c.abi, bytecode: '0x' + c.evm.bytecode.object };
}

const rows = [];
function log(s = '') { console.log(s); }

(async () => {
  const attackerBuild = compileAttacker();
  const vm = await VM.create({ common: new Common({ chain: 'mainnet', hardfork: Hardfork.London }) });
  const ste = new Interface(steBuild.abi);
  const atk = new Interface(attackerBuild.abi);
  const coder = AbiCoder.defaultAbiCoder();
  const at = (a) => new Address(hexToBytes(a));

  async function setBal(a, wei) {
    const x = at(a);
    const acct = (await vm.stateManager.getAccount(x)) ?? new Account();
    acct.balance = wei;
    await vm.stateManager.putAccount(x, acct);
  }
  for (const a of TRACKED) await setBal(a, 1000n * ONE);

  async function deploy(bytecode, args = [], iface) {
    const data = bytecode + (args.length ? iface.encodeDeploy(args).slice(2) : '');
    const r = await vm.evm.runCall({
      caller: at(ADDR.deployer), to: undefined, data: hexToBytes(data),
      gasLimit: 30_000_000n, value: 0n, createdAddresses: new Set(),
    });
    if (r.execResult.exceptionError) throw new Error('deploy: ' + r.execResult.exceptionError.error);
    return bytesToHex(r.createdAddress.bytes);
  }

  async function call(caller, to, data, value = 0n) {
    const r = await vm.evm.runCall({
      caller: at(caller), to: at(to),
      data: typeof data === 'string' ? hexToBytes(data) : data,
      gasLimit: 12_000_000n, value, createdAddresses: new Set(),
    });
    const e = r.execResult.exceptionError;
    return { ok: !e, err: e ? e.error : null, ret: bytesToHex(r.execResult.returnValue), gas: r.execResult.executionGasUsed };
  }
  const ethBal = async (a) => { const x = await vm.stateManager.getAccount(at(a)); return x ? x.balance : 0n; };
  const num = (hex) => BigInt(coder.decode(['uint256'], hex)[0]);

  const TARGET = await deploy(steBuild.bytecode, [], ste);
  log(`STE deployed locally at ${TARGET}`);
  const acct = await vm.stateManager.getAccount(at(TARGET));
  const onchainHash = bytesToHex(acct.codeHash);
  log(`deployed runtime hash: ${onchainHash}`);
  log(`compiled runtime hash: ${steBuild.runtimeHash}`);
  log(`RUNTIME MATCHES      : ${onchainHash === steBuild.runtimeHash}`);
  log('');

  // --- realistic state: two honest depositors -------------------------------
  await call(ADDR.alice, TARGET, '0x', 10n * ONE);
  await call(ADDR.bob, TARGET, '0x', 5n * ONE);
  const supply = num((await call(ADDR.probe, TARGET, ste.encodeFunctionData('totalSupply', []))).ret);
  log(`seeded: contract ETH=${await ethBal(TARGET)} | totalSupply=${supply}`);
  const aliceTok = num((await call(ADDR.probe, TARGET, ste.encodeFunctionData('balanceOf', [ADDR.alice]))).ret);
  log(`        alice tokens=${aliceTok}`);
  log('');

  // === Control: honest withdrawal works, and is it CEI-correct? =============
  log('--- CONTROL: honest withdraw() (single, no reentry) ---');
  {
    const tok = num((await call(ADDR.probe, TARGET, ste.encodeFunctionData('balanceOf', [ADDR.alice]))).ret);
    const before = await ethBal(ADDR.alice);
    const r = await call(ADDR.alice, TARGET, ste.encodeFunctionData('withdraw', [tok]));
    const after = await ethBal(ADDR.alice);
    const left = num((await call(ADDR.probe, TARGET, ste.encodeFunctionData('balanceOf', [ADDR.alice]))).ret);
    log(`    withdraw(${tok}) -> ${r.ok ? 'OK' : 'revert ' + r.err}; alice ETH +${after - before}; tokens left ${left}`);
  }
  log('');

  // === The scanner's payload, both variants ================================
  log('--- ATTACK: scanner payload = deposit, then withdraw() again from receive() ---');
  const variants = [
    ['attackCached (drain shape: re-uses the pre-call token amount)', 'attackCached'],
    ['attackLive   (re-reads balanceOf() inside the callback)', 'attackLive'],
  ];
  for (const [label, fn] of variants) {
    log(`  ${label}`);
    for (const depth of [1n, 7n]) {
      const attacker = await deploy(attackerBuild.bytecode, [TARGET], atk);
      const deposit = 5n * ONE;
      const steBefore = await ethBal(TARGET);
      const eoaBefore = await ethBal(ADDR.attacker);
      const atkEthBefore = await ethBal(attacker);

      const r = await call(ADDR.attacker, attacker, atk.encodeFunctionData(fn, [depth]), deposit);
      const q = async (name) => num((await call(ADDR.probe, attacker, atk.encodeFunctionData(name, []))).ret);
      const attempts = await q('attempts'), successes = await q('successes'), reverted = await q('reverted');
      const received = await q('totalReceived'), tokensLeft = await q('tokens');
      const seen = await q('withdrawalsSeenInsideCallback');
      const steAfter = await ethBal(TARGET);
      const eoaDelta = (await ethBal(ADDR.attacker)) - eoaBefore;
      const contractDelta = (await ethBal(attacker)) - atkEthBefore;
      const net = eoaDelta + contractDelta;
      const twNow = num((await call(ADDR.probe, TARGET, ste.encodeFunctionData('totalWithdrawals', []))).ret);
      let sel = '0x00000000';
      try { sel = (await call(ADDR.probe, attacker, atk.encodeFunctionData('lastRevertSelector', []))).ret.slice(0, 10); } catch {}

      log(`    depth=${depth}: ${r.ok ? 'OK' : 'revert ' + r.err} | attempts=${attempts} ok=${successes} reverted=${reverted}`);
      log(`      tokens after=${tokensLeft} | ETH received=${received} | NET=${net} wei`);
      log(`      totalWithdrawals inside callback=${seen === (2n ** 256n - 1n) ? 'n/a' : seen} | final=${twNow}`);
      log(`      reentry ${successes > 0n ? 'ACCEPTED but paid 0' : 'blocked'}${sel !== '0x00000000' ? ' (revert selector ' + sel + ')' : ''}`);

      rows.push({
        variant: fn, depth: String(depth), attackOk: r.ok,
        attempts: String(attempts), successes: String(successes), reverted: String(reverted),
        received: String(received), tokensAfter: String(tokensLeft),
        totalWithdrawalsSeenInsideCallback: seen === (2n ** 256n - 1n) ? null : String(seen),
        eoaDelta: String(eoaDelta), contractDelta: String(contractDelta),
        attackerNetWei: String(net), steEthDelta: String(steAfter - steBefore),
        verdict: net > 0n ? 'PROFITABLE' : 'NO PROFIT',
      });
    }
  }
  log('');

  // === The classic drain shape: repeat withdraw with the SAME tokens =======
  log('--- ATTACK 2: withdraw twice with the same token balance ---');
  {
    const attacker = await deploy(attackerBuild.bytecode, [TARGET], atk);
    await call(ADDR.attacker, attacker, atk.encodeFunctionData('attackLive', [0n]), ONE);
    const t1 = num((await call(ADDR.probe, attacker, atk.encodeFunctionData('tokens', []))).ret);
    log(`    after first withdrawal, attacker tokens = ${t1}`);
    const balBefore = await ethBal(attacker);
    const second = await call(ADDR.attacker, attacker, atk.encodeFunctionData('pull', []));
    log(`    pull() -> ${second.ok ? 'OK' : 'revert'}; attacker withdrew ${await ethBal(attacker)} back to EOA`);
    rows.push({ check: 'double withdraw with same tokens', tokensAfterFirst: String(t1), verdict: t1 === 0n ? 'IMPOSSIBLE (burned)' : 'reached' });
  }
  log('');

  // === Differential check: attacker vs honest users ========================
  log('--- DIFFERENTIAL: did any honest user lose funds? ---');
  for (const who of [ADDR.alice, ADDR.bob]) {
    const tok = num((await call(ADDR.probe, TARGET, ste.encodeFunctionData('balanceOf', [who]))).ret);
    const wb = num((await call(ADDR.probe, TARGET, ste.encodeFunctionData('withdrawable', [who]))).ret);
    log(`    ${who.slice(0, 10)} tokens=${tok} withdrawable=${wb} wei`);
  }
  const finalEth = await ethBal(TARGET);
  const finalSupply = num((await call(ADDR.probe, TARGET, ste.encodeFunctionData('totalSupply', []))).ret);
  log(`    contract ETH=${finalEth} | totalSupply=${finalSupply} | fully backed: ${finalSupply <= finalEth}`);

  fs.writeFileSync(path.join(artifactsDir, 'reentrancy_results.json'), JSON.stringify({ target: TARGET, runtimeHash: steBuild.runtimeHash, rows }, null, 2));
  log('');
  log('=== FINAL ===');
  const profitable = rows.filter((r) => r.verdict === 'PROFITABLE');
  log(`scenarios: ${rows.length} | profitable: ${profitable.length}`);
  log('wrote artifacts/reentrancy_results.json');
})().catch((e) => { console.error('HARNESS ERROR', e); process.exit(1); });
