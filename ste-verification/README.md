# STE reentrancy verification harness

Byte-exact verification of the `STE.withdraw()` reentrancy finding against
`0x792f5bdde5f8cf4b075b7a9dc4f296341d00b0d1`.

Companion to [`../STE_VERIFICATION.md`](../STE_VERIFICATION.md).

## Why this one is byte-exact

`artifacts/input.json` is the **verified compiler input** (standard-json) for the deployed
contract, and `artifacts/STE.json` records the compiled runtime hash. It matches the on-chain
runtime hash `0xf1d9fa6b…54cc61` published in `EthVM/evm-source-verification`'s `metadata.json`.
The compiled bytecode therefore *is* the deployed bytecode.

## Files

| Path | Purpose |
|---|---|
| `src/STE.sol` | verified STE source (from the compiler input) |
| `src/oz/*.sol` | OpenZeppelin ERC20 base at the versions the input pinned |
| `scripts/compile_ste.js` | compiles with solc 0.8.0, optimizer off, istanbul; prints + stores the runtime hash |
| `scripts/ReentrantAttacker.sol` | the attack contract (`attackCached` / `attackLive`) |
| `scripts/reentrancy_suite.js` | deposits, re-enters, measures net P&L and the solvency invariant |
| `scripts/revert_reason.js` | decodes the revert reason the drain-shape reentry receives |
| `scripts/economics.js` | last-holder-out fee asymmetry table |
| `artifacts/` | compiler input, compiled build, attack contract build, last results |

## Run

```bash
npm install
npm run compile     # -> artifacts/STE.json (assert runtime hash)
npm test            # -> artifacts/reentrancy_results.json
npm run reasons
npm run economics
```

## Reading the output

- `attackCached` is the drain shape (re-uses the token amount cached before the call). It reverts
  with `ERC20: burn amount exceeds balance` — the burn already debited the balance.
- `attackLive` recurses successfully but transfers 0 wei each time. A non-reverting call is **not**
  profit; the suite's net figure includes the deposit leg (EOA delta + contract delta), which is
  why every scenario reports a net **loss** of the 5% fee.
- `npm run economics` shows the genuine, unrelated last-exit advantage, for completeness only.
