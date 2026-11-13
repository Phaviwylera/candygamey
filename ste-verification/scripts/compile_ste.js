// Compiles the byte-exact verified source for STE 0x792f5bdde5f8cf4b075b7a9dc4f296341d00b0d1
// using solc 0.8.0+commit.c7dfd78e with the settings from the verified compiler input.json
// (optimizer disabled, evmVersion istanbul).
const fs = require('fs');
const path = require('path');
const solc = require('solc');
const { keccak256, Interface } = require('ethers');

const INPUT = path.join(__dirname, '..', 'artifacts', 'input.json');
const OUT = path.join(__dirname, '..', 'artifacts');
fs.mkdirSync(OUT, { recursive: true });

const verified = JSON.parse(fs.readFileSync(INPUT, 'utf8'));

// Use the verified source-unit names verbatim: solc resolves both STE.sol's absolute
// URL import and the OZ files' relative "./IERC20.sol" imports against this map.
const sources = {};
for (const [name, src] of Object.entries(verified.sources)) {
  sources[name] = { content: src.content };
}


const input = {
  language: 'Solidity',
  sources,
  settings: {
    optimizer: { enabled: false, runs: 200 },
    evmVersion: 'istanbul',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object', 'evm.deployedBytecode.object'] } },
  },
};

const out = JSON.parse(solc.compile(JSON.stringify(input)));
for (const e of out.errors ?? []) {
  if (e.severity === 'error') throw new Error(e.formattedMessage);
}
const c = out.contracts['browser/STE.sol'].STE;
if (!c) throw new Error('STE not found; keys=' + Object.keys(out.contracts));

const creation = '0x' + c.evm.bytecode.object;
const runtime = '0x' + c.evm.deployedBytecode.object;
fs.writeFileSync(path.join(OUT, 'STE.json'), JSON.stringify({
  abi: c.abi, bytecode: creation, deployedBytecode: runtime,
  runtimeHash: keccak256(runtime),
  compiler: solc.version(), settings: input.settings,
}, null, 2));

const iface = new Interface(c.abi);
console.log('compiler      :', solc.version());
console.log('contract      : STE');
console.log('abi functions :', iface.fragments.filter((f) => f.type === 'function').map((f) => f.format()).join(' | '));
console.log('creation bytes:', (creation.length - 2) / 2);
console.log('runtime bytes :', (runtime.length - 2) / 2);
console.log('runtime hash  :', keccak256(runtime));
console.log('wrote artifacts/STE.json');
