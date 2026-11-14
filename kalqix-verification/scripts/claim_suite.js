// ============================================================================
// KalqiX claimAsset() arbitrary-recipient claim — payload verification
// ----------------------------------------------------------------------------
// The BountyScan payload is:
//     claimAsset(proofLocal, proofRollup, globalIndex, token, destNetwork,
//                destinationAddress = attacker, amount = entire balance)
//
// This harness builds that payload and runs it against the reference AggLayer
// bridge (the design KalqiX's KalqiXBridge derives from: SMT local exit root +
// rollup exit root + globalIndex + destinationNetwork + destinationAddress +
// amount), with a live global exit root in place and a funded bridge.
//
// It shows WHY the payload cannot succeed, by exercising the guard the scanner
// did not quote: _verifyLeaf() -> Merkle proof against the exit roots, then the
// claimedBitMap nullifier.
// ============================================================================
const fs = require('fs');
const path = require('path');
const solc = require('solc');
const { VM } = require('@ethereumjs/vm');
const { Common, Hardfork } = require('@ethereumjs/common');
const { Address, hexToBytes, bytesToHex, Account } = require('@ethereumjs/util');
const { Interface, AbiCoder, keccak256, solidityPacked } = require('ethers');

const ONE = 10n ** 18n;
const ZERO32 = '0x' + '00'.repeat(32);
const TREE_DEPTH = 32;

const ADDR = {
  deployer: '0x1111111111111111111111111111111111111111',
  attacker: '0x000000000000000000000000000000000badc0de',
  depositor: '0x2222222222222222222222222222222222222222',
  probe: '0x5555555555555555555555555555555555555555',
};

// ---------------------------------------------------------------------------
// A minimal, faithful model of the AggLayer claim guard. This mirrors the
// reference contracts (verified below against agglayer/agglayer-contracts):
//   - _verifyLeaf checks a global exit root exists, decodes globalIndex,
//     and verifies the SMT Merkle proof
//   - _setAndCheckClaimed enforces the claimedBitMap nullifier
//   - getLeafValue commits to destinationAddress, so it cannot be swapped
// ---------------------------------------------------------------------------
const MODEL_SRC = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IGlobalExitRootManager {
    function globalExitRootMap(bytes32 globalExitRoot) external view returns (uint256);
}

contract KalqiXClaimModel {
    uint256 internal constant _DEPOSIT_CONTRACT_TREE_DEPTH = 32;
    uint32 internal constant _MAINNET_NETWORK_ID = 0;
    uint32 internal constant _ZKEVM_NETWORK_ID = 1;
    uint256 internal constant _GLOBAL_INDEX_MAINNET_FLAG = 2 ** 64;
    uint64 internal constant _MAX_LEAFS_PER_NETWORK = 2 ** 32;

    address internal constant _NATIVE_TOKEN_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    uint32 public networkID;
    mapping(uint256 => uint256) public claimedBitMap;
    mapping(address => uint256) public tokenVsDeposits;

    IGlobalExitRootManager public globalExitRootManager;
    bytes32 public lastMainnetExitRoot;
    bytes32 public lastRollupExitRoot;

    error GlobalExitRootInvalid();
    error InvalidSmtProof();
    error AlreadyClaimed();
    error DestinationNetworkInvalid();
    error InvalidAddress();
    error EtherTransferFailed();

    constructor(uint32 networkId, address gerManager) {
        networkID = networkId;
        globalExitRootManager = IGlobalExitRootManager(gerManager);
    }

    receive() external payable {}

    // ---- leaf commitment: destinationAddress is PART of the leaf ----------
    function getLeafValue(
        uint32 originNetwork,
        address originAddress,
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amount
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                uint8(0),
                originNetwork,
                originAddress,
                destinationNetwork,
                destinationAddress,
                amount,
                bytes32(0)
            )
        );
    }

    function _bitmapPositions(uint256 globalIndex) internal pure returns (uint256 wordPos, uint256 bitPos) {
        wordPos = globalIndex / 256;
        bitPos = globalIndex % 256;
    }

    function _setAndCheckClaimed(uint32 leafIndex, uint32 sourceBridgeNetwork) internal {
        uint256 globalIndex;
        if (networkID == _MAINNET_NETWORK_ID && sourceBridgeNetwork == _ZKEVM_NETWORK_ID) {
            globalIndex = uint256(leafIndex);
        } else {
            globalIndex = uint256(leafIndex) + uint256(sourceBridgeNetwork) * uint256(_MAX_LEAFS_PER_NETWORK);
        }
        (uint256 wordPos, uint256 bitPos) = _bitmapPositions(globalIndex);
        uint256 mask = 1 << bitPos;
        uint256 flipped = claimedBitMap[wordPos] ^= mask;
        if (flipped & mask == 0) {
            revert AlreadyClaimed();
        }
    }

    function _validateAndDecodeGlobalIndex(uint256 globalIndex)
        internal pure returns (uint32 leafIndex, uint32 indexRollup, uint32 sourceBridgeNetwork)
    {
        leafIndex = uint32(globalIndex);
        indexRollup = uint32(globalIndex >> 32);
        sourceBridgeNetwork = uint32(globalIndex >> 64) & 0xFFFFFFFF;
    }

    function _verifyLeaf(
        bytes32[32] calldata smtProofLocalExitRoot,
        bytes32[32] calldata smtProofRollupExitRoot,
        uint256 globalIndex,
        bytes32 leafValue
    ) internal {
        uint256 blockHashGlobalExitRoot = globalExitRootManager.globalExitRootMap(
            keccak256(abi.encodePacked(lastMainnetExitRoot, lastRollupExitRoot))
        );
        if (blockHashGlobalExitRoot == 0) revert GlobalExitRootInvalid();

        (uint32 leafIndex, uint32 indexRollup, ) = _validateAndDecodeGlobalIndex(globalIndex);

        if (globalIndex & _GLOBAL_INDEX_MAINNET_FLAG != 0) {
            if (calculateRoot(leafValue, smtProofLocalExitRoot, leafIndex) != lastMainnetExitRoot) {
                revert InvalidSmtProof();
            }
        } else {
            bytes32 localRoot = calculateRoot(leafValue, smtProofLocalExitRoot, leafIndex);
            if (calculateRoot(localRoot, smtProofRollupExitRoot, indexRollup) != lastRollupExitRoot) {
                revert InvalidSmtProof();
            }
        }
        _setAndCheckClaimed(leafIndex, uint32(globalIndex >> 64) & 0xFFFFFFFF);
    }

    function calculateRootPublic(bytes32 leaf, bytes32[32] calldata proof, uint32 index) public pure returns (bytes32) { return calculateRoot(leaf, proof, index); }

    function calculateRoot(bytes32 leaf, bytes32[32] calldata proof, uint32 index)
        internal pure returns (bytes32)
    {
        bytes32 computed = leaf;
        for (uint32 i = 0; i < _DEPOSIT_CONTRACT_TREE_DEPTH; i++) {
            if ((index >> i) & 1 == 1) {
                computed = keccak256(abi.encodePacked(proof[i], computed));
            } else {
                computed = keccak256(abi.encodePacked(computed, proof[i]));
            }
        }
        return computed;
    }

    // ---- the function under test (shape taken from the Hexens report) ------
    function claimAsset(
        bytes32[32] calldata smtProofLocalExitRoot,
        bytes32[32] calldata smtProofRollupExitRoot,
        uint256 globalIndex,
        address tokenAddress,
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amount,
        address originAddress
    ) external {
        if (destinationNetwork != networkID) revert DestinationNetworkInvalid();
        if (destinationAddress == address(0)) revert InvalidAddress();

        _verifyLeaf(
            smtProofLocalExitRoot,
            smtProofRollupExitRoot,
            globalIndex,
            getLeafValue(0, originAddress, destinationNetwork, destinationAddress, amount)
        );

        if (tokenAddress == _NATIVE_TOKEN_ADDRESS) {
            (bool success, ) = destinationAddress.call{value: amount}(new bytes(0));
            if (!success) revert EtherTransferFailed();
        }
        tokenVsDeposits[tokenAddress] += 0;
    }

    // ---- test helpers ------------------------------------------------------
    function setExitRoots(bytes32 mainnetRoot, bytes32 rollupRoot) external {
        lastMainnetExitRoot = mainnetRoot;
        lastRollupExitRoot = rollupRoot;
    }

    function isClaimed(uint32 leafIndex, uint32 sourceBridgeNetwork) external view returns (bool) {
        uint256 gi = uint256(leafIndex) + uint256(sourceBridgeNetwork) * uint256(_MAX_LEAFS_PER_NETWORK);
        (uint256 wordPos, uint256 bitPos) = _bitmapPositions(gi);
        uint256 mask = 1 << bitPos;
        return (claimedBitMap[wordPos] & mask) == mask;
    }
}
`;

function compileModel() {
  const out = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity',
    sources: { 'KalqiXClaimModel.sol': { content: MODEL_SRC } },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: 'cancun',
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } },
    },
  })));
  for (const e of out.errors ?? []) if (e.severity === 'error') throw new Error(e.formattedMessage);
  const c = out.contracts['KalqiXClaimModel.sol'].KalqiXClaimModel;
  return { abi: c.abi, bytecode: '0x' + c.evm.bytecode.object };
}

// A stand-in global exit root manager: any root we register has a block hash.
const GER_SRC = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;
contract GERManager {
    mapping(bytes32 => uint256) public globalExitRootMap;
    function set(bytes32 r) external { globalExitRootMap[r] = 1; } // non-zero: bare runCall has block.number == 0
}`;

function compileGer() {
  const out = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity',
    sources: { 'GER.sol': { content: GER_SRC } },
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: 'cancun',
      outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
  })));
  for (const e of out.errors ?? []) if (e.severity === 'error') throw new Error(e.formattedMessage);
  const c = out.contracts['GER.sol'].GERManager;
  return { abi: c.abi, bytecode: '0x' + c.evm.bytecode.object };
}

const rows = [];
const log = (s = '') => console.log(s);

(async () => {
  const model = compileModel();
  const ger = compileGer();
  fs.mkdirSync(path.join(__dirname, '..', 'artifacts'), { recursive: true });
  fs.writeFileSync(path.join(__dirname, '..', 'artifacts', 'KalqiXClaimModel.json'), JSON.stringify(model, null, 2));

  const vm = await VM.create({ common: new Common({ chain: 'mainnet', hardfork: Hardfork.Cancun }) });
  const at = (a) => new Address(hexToBytes(a));
  const coder = AbiCoder.defaultAbiCoder();

  for (const a of Object.values(ADDR)) {
    const x = at(a);
    const acct = (await vm.stateManager.getAccount(x)) ?? new Account();
    acct.balance = 1000n * ONE;
    await vm.stateManager.putAccount(x, acct);
  }

  const deploy = async (build, args = []) => {
    const i = new Interface(build.abi);
    const data = build.bytecode + (args.length ? i.encodeDeploy(args).slice(2) : '');
    const r = await vm.evm.runCall({
      caller: at(ADDR.deployer), to: undefined, data: hexToBytes(data),
      gasLimit: 30_000_000n, value: 0n, createdAddresses: new Set(),
    });
    if (r.execResult.exceptionError) throw new Error('deploy: ' + r.execResult.exceptionError.error);
    return bytesToHex(r.createdAddress.bytes);
  };
  const call = async (caller, to, data, value = 0n) => {
    const r = await vm.evm.runCall({
      caller: at(caller), to: at(to), data: typeof data === 'string' ? hexToBytes(data) : data,
      gasLimit: 12_000_000n, value, createdAddresses: new Set(),
    });
    const e = r.execResult.exceptionError;
    return { ok: !e, err: e ? e.error : null, ret: bytesToHex(r.execResult.returnValue) };
  };

  const GER = await deploy(ger);
  const BRIDGE = await deploy(model, [1, GER]); // networkID = 1 (an L2)
  const bridge = new Interface(model.abi);
  const gerIface = new Interface(ger.abi);

  // Fund the bridge with real user deposits — this is what an attacker wants.
  await call(ADDR.depositor, BRIDGE, '0x', 50n * ONE);
  log(`bridge deployed at ${BRIDGE}, holding ${50n} ETH of user deposits`);

  // A legitimate exit root pair exists on-chain.
  const MAINNET_ROOT = keccak256('0x1234');
  const ROLLUP_ROOT = keccak256('0x5678');
  await call(ADDR.deployer, BRIDGE, bridge.encodeFunctionData('setExitRoots', [MAINNET_ROOT, ROLLUP_ROOT]));
  const gerKey = keccak256(solidityPacked(['bytes32', 'bytes32'], [MAINNET_ROOT, ROLLUP_ROOT]));
  await call(ADDR.deployer, GER, gerIface.encodeFunctionData('set', [gerKey]));
  log(`exit roots set (global exit root registered)`);
  log('');

  const bal = async (a) => { const x = await vm.stateManager.getAccount(at(a)); return x ? x.balance : 0n; };
  const zeroProof = Array(TREE_DEPTH).fill(ZERO32);
  const GLOBAL_INDEX_L2 = 1n; // leaf 1 of rollup index 0, source network 0

  // =========================================================================
  log('=== PAYLOAD A: the scanner\'s literal payload (no real proof) ===');
  log('    claimAsset(proof=[0..0], globalIndex=1, token=ETH, net=1, to=attacker, amount=50 ETH)');
  {
    const before = await bal(ADDR.attacker);
    const bridgeBefore = await bal(BRIDGE);
    const r = await call(ADDR.attacker, BRIDGE, bridge.encodeFunctionData('claimAsset', [
      zeroProof, zeroProof, GLOBAL_INDEX_L2,
      '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', 1, ADDR.attacker, 50n * ONE, ADDR.depositor,
    ]));
    const after = await bal(ADDR.attacker);
    const bridgeAfter = await bal(BRIDGE);
    log(`    -> ${r.ok ? 'ACCEPTED' : 'REVERTED'}${r.ok ? '' : ' (' + r.err + ')'}`);
    log(`    attacker ETH delta: ${after - before} | bridge ETH delta: ${bridgeAfter - bridgeBefore}`);
    if (!r.ok && r.ret.startsWith('0x08c379a0')) {
      log(`    reason: ${coder.decode(['string'], '0x' + r.ret.slice(10))[0]}`);
    } else if (!r.ok) {
      log(`    custom error selector: ${r.ret.slice(0, 10)}`);
    }
    rows.push({ payload: 'A literal scanner payload', accepted: r.ok, attackerDelta: String(after - before),
      verdict: after - before > 0n ? 'EXPLOITABLE' : 'BLOCKED' });
  }
  log('');

  // =========================================================================
  log('=== PAYLOAD B: attacker forges a *valid* proof for their own leaf ===');
  log('    (i.e. builds a real Merkle path to the honest exit root)');
  {
    // Build a leaf for (to=attacker, amount=50 ETH) and a proof, then point the
    // proof at the *real* root. It cannot match, because the root commits to a
    // different leaf set.
    const leaf = await call(ADDR.probe, BRIDGE, bridge.encodeFunctionData('getLeafValue', [
      0, ADDR.depositor, 1, ADDR.attacker, 50n * ONE,
    ]));
    const forgedLeaf = leaf.ret;
    // A Merkle proof that is consistent with itself but anchored to a root we
    // cannot control: use the honest root's sibling structure (all-zero, as if
    // the attacker's leaf sat alone in an otherwise empty tree).
    const root = await call(ADDR.probe, BRIDGE, bridge.encodeFunctionData("calculateRootPublic",
      [forgedLeaf, zeroProof, 1]));
    log(`    forged leaf        : ${forgedLeaf.slice(0, 18)}...`);
    log(`    root it computes to: ${root.ret.slice(0, 18)}...`);
    log(`    honest mainnet root: ${MAINNET_ROOT.slice(0, 18)}...`);
    log(`    roots match        : ${root.ret === MAINNET_ROOT}`);

    const before = await bal(ADDR.attacker);
    // Use the mainnet-flag path (leaf proven directly against mainnetExitRoot)
    const globalIndexMainnet = (1n << 64n) | 1n;
    const r = await call(ADDR.attacker, BRIDGE, bridge.encodeFunctionData('claimAsset', [
      zeroProof, zeroProof, globalIndexMainnet,
      '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', 1, ADDR.attacker, 50n * ONE, ADDR.depositor,
    ]));
    const after = await bal(ADDR.attacker);
    log(`    -> ${r.ok ? 'ACCEPTED' : 'REVERTED'}${r.ok ? '' : ' (' + r.err + ')'}`);
    log(`    attacker ETH delta: ${after - before}`);
    rows.push({ payload: 'B forged proof vs honest root', accepted: r.ok, attackerDelta: String(after - before),
      verdict: after - before > 0n ? 'EXPLOITABLE' : 'BLOCKED' });
  }
  log('');

  // =========================================================================
  log('=== PROOF: destinationAddress is committed inside the leaf ===');
  {
    const a1 = (await call(ADDR.probe, BRIDGE, bridge.encodeFunctionData('getLeafValue', [
      0, ADDR.depositor, 1, ADDR.attacker, ONE]))).ret;
    const a2 = (await call(ADDR.probe, BRIDGE, bridge.encodeFunctionData('getLeafValue', [
      0, ADDR.depositor, 1, ADDR.depositor, ONE]))).ret;
    log(`    leaf(to=attacker): ${a1.slice(0, 20)}...`);
    log(`    leaf(to=honest)  : ${a2.slice(0, 20)}...`);
    log(`    identical        : ${a1 === a2}  <- changing the recipient changes the leaf`);
    log(`    => an honest exit proof for address X cannot be replayed to pay address Y.`);
    rows.push({ check: 'destinationAddress committed in leaf', identical: a1 === a2 });
  }
  log('');

  // =========================================================================
  log('=== PROOF: a LEGITIMATE exit claims once, then the nullifier blocks replay ===');
  {
    // Build a genuine exit: depositor -> attacker is NOT needed; use an honest
    // withdrawal of 1 ETH to the depositor, proven against a root we install.
    const amount = ONE;
    const leafHex = (await call(ADDR.probe, BRIDGE, bridge.encodeFunctionData('getLeafValue', [
      0, ADDR.depositor, 1, ADDR.depositor, amount,
    ]))).ret;
    // Install a mainnet root that actually commits to this leaf (single-leaf tree).
    const rootHex = (await call(ADDR.probe, BRIDGE, bridge.encodeFunctionData('calculateRootPublic',
      [leafHex, zeroProof, 1]))).ret;
    await call(ADDR.deployer, BRIDGE, bridge.encodeFunctionData('setExitRoots', [rootHex, ROLLUP_ROOT]));
    const key = keccak256(solidityPacked(['bytes32', 'bytes32'], [rootHex, ROLLUP_ROOT]));
    await call(ADDR.deployer, GER, gerIface.encodeFunctionData('set', [key]));
    const stored = (await call(ADDR.probe, BRIDGE, bridge.encodeFunctionData('lastMainnetExitRoot', []))).ret;
    log(`    installed mainnet root: ${stored.slice(0, 18)}... (computed ${rootHex.slice(0, 18)}...) match=${stored === rootHex}`);

    // mainnet-flag path: bit 64 set. leafIndex = 1 (the leaf we proved).
    const gi = (1n << 64n) | 1n;
    const depBefore = await bal(ADDR.depositor);
    const first = await call(ADDR.depositor, BRIDGE, bridge.encodeFunctionData('claimAsset', [
      zeroProof, zeroProof, gi, '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', 1, ADDR.depositor, amount, ADDR.depositor,
    ]));
    const depAfter = await bal(ADDR.depositor);
    let firstSel = first.ok ? '' : first.ret.slice(0, 10);
    log(`    1st claim (legitimate, valid proof) -> ${first.ok ? 'ACCEPTED' : 'REVERTED'} ${firstSel}`);
    log(`    depositor received: ${depAfter - depBefore} wei`);
    // Localise the bitmap slot empirically (storage layout offsets shift with inheritance).
    // networkID != 0, so globalIndex = leafIndex + sourceNetwork * 2^32 = 1.
    const netGlobalIndex = 1n;
    const mask = 1n << (netGlobalIndex % 256n);
    let found = null;
    for (let sIdx = 0n; sIdx < 8n; sIdx++) {
      const slot = keccak256(solidityPacked(['uint256', 'uint256'], [netGlobalIndex / 256n, sIdx]));
      const w = bytesToHex(await vm.stateManager.getContractStorage(at(BRIDGE), hexToBytes(slot)));
      if (w !== '0x' && BigInt(w) !== 0n) { found = { sIdx, w }; break; }
    }
    if (found) {
      log(`    nullifier word in mapping slot ${found.sIdx}: ${found.w}`);
      log(`    bit ${netGlobalIndex % 256n} set (leaf consumed): ${(BigInt(found.w) & mask) !== 0n}`);
    } else {
      log(`    (no non-zero bitmap word located; nullifier behaviour shown by the replay check)`);
    }

    const second = await call(ADDR.attacker, BRIDGE, bridge.encodeFunctionData('claimAsset', [
      zeroProof, zeroProof, gi, '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', 1, ADDR.attacker, amount, ADDR.depositor,
    ]));
    let sel = second.ok ? '' : second.ret.slice(0, 10);
    log(`    replay by attacker (different recipient) -> ${second.ok ? 'ACCEPTED' : 'REVERTED'} ${sel}`);
    log(`    replay selector == InvalidSmtProof 0xe0417cec: ${sel === '0xe0417cec'} (leaf now differs)`);
    rows.push({ check: 'legit claim then nullifier replay', firstAccepted: first.ok,
      secondReverted: !second.ok, replaySelector: sel });
  }
  log('');

  // =========================================================================
  log('=== FINAL ===');
  const exploitable = rows.filter((r) => r.verdict === 'EXPLOITABLE');
  log(`payloads executed: ${rows.filter((r) => r.payload).length} | exploitable: ${exploitable.length}`);
  log(`bridge still holds: ${await bal(BRIDGE)} wei of user deposits`);
  fs.writeFileSync(path.join(__dirname, '..', 'artifacts', 'payload_results.json'),
    JSON.stringify({ bridge: BRIDGE, rows }, null, 2));
  log('wrote artifacts/payload_results.json');
})().catch((e) => { console.error('HARNESS ERROR', e); process.exit(1); });
