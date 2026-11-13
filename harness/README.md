# Payload verification harness

Executes candidate exploit payloads against the **real** MevWeth source on a local EVM.
No RPC endpoint, no mainnet fork, no broadcast — everything runs in-process.

Companion to [`../PAYLOAD_VERIFICATION.md`](../PAYLOAD_VERIFICATION.md).

## What it does

1. Compiles `blunt-instruments/MevWeth` @ `8477008` (see `PAYLOAD_VERIFICATION.md`) with **solc 0.7.6+commit.7338295f**,
   the compiler named in the scanner report.
2. Deploys `MevWeth` into an `@ethereumjs/vm` instance (Cancun rules) at the CREATE2 address derived
   from the repo's own deploy salt.
3. Seeds a realistic state: two users deposit 10 ETH each, one funds a 3 ETH `mev` pot.
4. Fires every payload the report proposes, plus batched single-transaction replays, and measures
   attacker/victim native + token deltas and the solvency invariant.

## Setup

The source isn't vendored here (GPLv3, upstream repo is the authority). Fetch it:

```bash
git clone https://github.com/blunt-instruments/MevWeth vendor/MevWeth
cd vendor/MevWeth && git checkout 84770081cc456284e5347b2091595a601f42d353
git clone https://github.com/WETH10/WETH10 /tmp/WETH10
cd /tmp/WETH10 && git checkout 87ec30256dab62459a2e6d2a1741b44d345881f1
mkdir -p vendor/MevWeth/lib/WETH10 && cp -r /tmp/WETH10/contracts/interfaces vendor/MevWeth/lib/WETH10/
```

`compile.js` reads `$MEVWETH_SRC` (default `./vendor/MevWeth`).

## Run

```bash
npm install
node compile.js          # -> artifacts/MevWeth.json  (prints predicted CREATE2 address)
node compile_helpers.js  # -> artifacts/Helpers.json  (Batcher + FlashProbe, solc 0.8.28)
npm run check            # -> all scenarios, writes artifacts/payload_results.json
```

## Files

| Path | Purpose |
|---|---|
| `compile.js` | compiles MevWeth with solc 0.7.6, recomputes the CREATE2 address |
| `compile_helpers.js` | adversarial helper contracts (`Batcher`, `FlashProbe`) |
| `payload_suite.js` | the 14 scenarios + invariant checks |
| `artifacts/MevWeth.json` | compiled MevWeth ABI + creation bytecode |
| `artifacts/payloads.json` | the exact calldata for each report finding |
| `artifacts/payload_results.json` | per-scenario verdicts and deltas from the last run |

## Reading the result

`verdict: "NOT EXPLOITABLE"` for a payload means the call either reverted or moved no value to the
attacker. `invariantAfter: true` means `sum(balanceOf) + mev == address(this).balance + flashMinted`
still held after the payload — i.e. no token was conjured or lost.

The `GRIEF:` rows are expected to show `executed: true` with `potBefore -> 0`: that is the real
(low-severity) issue this review found, not a fund-theft bug. See the report for details.
