// Compile the genuine blunt-instruments/MevWeth sources with the exact compiler reported
// (0.7.6+commit.7338295f) and verify the CREATE2 address from the repo's deploy script.
const fs = require('fs');
const path = require('path');
const solc = require('solc');

const ROOT = process.env.MEVWETH_SRC || './vendor/MevWeth';

function read(rel, diskRel) {
  return { content: fs.readFileSync(path.join(ROOT, diskRel || rel), 'utf8') };
}

const sources = {
  'src/MevWeth.sol': read('src/MevWeth.sol'),
  'src/WETH10Mod.sol': read('src/Weth10Mod.sol'),
  'src/IMevWeth.sol': read('src/IMevWeth.sol'),
  'WETH10/interfaces/IWETH10.sol': read('WETH10/interfaces/IWETH10.sol', 'lib/WETH10/interfaces/IWETH10.sol'),
  'WETH10/interfaces/IERC3156FlashBorrower.sol': read('WETH10/interfaces/IERC3156FlashBorrower.sol', 'lib/WETH10/interfaces/IERC3156FlashBorrower.sol'),
  'WETH10/interfaces/IERC20.sol': read('WETH10/interfaces/IERC20.sol', 'lib/WETH10/interfaces/IERC20.sol'),
  'WETH10/interfaces/IERC2612.sol': read('WETH10/interfaces/IERC2612.sol', 'lib/WETH10/interfaces/IERC2612.sol'),
  'WETH10/interfaces/IERC3156FlashLender.sol': read('WETH10/interfaces/IERC3156FlashLender.sol', 'lib/WETH10/interfaces/IERC3156FlashLender.sol'),
};

const input = {
  language: 'Solidity',
  sources,
  settings: {
    optimizer: { enabled: true, runs: 200 },
    // Live contract is 0.7.6; match the default target of that era.
    evmVersion: 'istanbul',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.bytecode.linkReferences'] } },
  },
};

const out = JSON.parse(solc.compile(JSON.stringify(input)));
if (out.errors) {
  for (const e of out.errors) {
    if (e.severity === 'error') console.error('ERROR:', e.formattedMessage);
  }
}
const c = out.contracts['src/MevWeth.sol']['MevWeth'];
const creation = '0x' + c.evm.bytecode.object;
console.log('compiled MevWeth creation bytecode bytes:', (creation.length - 2) / 2);

// --- reproduce the CREATE2 address from script/DeployMevWeth.s.sol -----------------
const { keccak256, getCreate2Address, concat, getAddress } = require('ethers');
const SALT = '0x13061f1c1bbc52beabac07a60520c45cf18845c922387ca542de860049e90910';
const FACTORY = '0x4e59b44847b379578588920ca78fbf26c0b4956c'; // forge create2 deployer
const initCodeHash = keccak256(creation);
const predicted = getCreate2Address(FACTORY, SALT, initCodeHash);
console.log('init code hash :', initCodeHash);
console.log('predicted addr :', predicted);
console.log('README live addr: 0x00000000008C43efC014746c230049e330039Cb3');
console.log('MATCH          :', predicted.toLowerCase() === '0x00000000008c43efc014746c230049e330039cb3');

fs.mkdirSync(path.join(__dirname, 'artifacts'), { recursive: true });
fs.writeFileSync(path.join(__dirname, 'artifacts', 'MevWeth.json'), JSON.stringify({
  abi: c.abi, bytecode: creation, initCodeHash, predicted,
}, null, 2));
console.log('wrote artifacts/MevWeth.json');
