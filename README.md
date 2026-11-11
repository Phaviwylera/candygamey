# Callback-authentication fork test

This repository contains the deployed runtime bytecode (`bot_runtime.hex`) and its disassembly for
Ethereum contract `0xbdb3ba9ffe392549e1f8658dd2630c141fdf47b6`. The Foundry test in
`test/CallbackAuthFork.t.sol` probes the two reported swap-callback entry points using direct calls
from an unprivileged address on a **local mainnet fork**. Separate direct-call cases keep each probe
in a fresh transaction; two additional cases invoke a callback twice in one attacker-controlled
top-level transaction to test transient-state reuse. The tests emit call success/return-data details,
native and tracked ERC-20 balance deltas, caller allowance deltas, diffs for persistent slots 0–31,
observed persistent writes, and the callback's known transient slot. They fail if the bot loses a
tracked asset or grants the caller a new allowance.

## Run

Install Foundry, then provide an Ethereum mainnet RPC endpoint. For Alchemy, make the key
available as the `ALCHEMY_API_KEY` environment variable through your local secret manager (do not
put it in this repository or paste it into chat), then run:

```sh
export RPC_URL="https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
forge test --match-path test/CallbackAuthFork.t.sol -vvvvv
```

Alternatively, set `RPC_URL` directly to another Ethereum mainnet endpoint. The endpoint is only
used by Foundry to create a local fork. Test calls are simulated and are not
broadcast. Do not replace this with a live transaction or call the deployed contract outside the
fork. The test covers WETH, USDC, USDT, WBTC, DAI, USDS, wstETH, USDe, and native ETH; it is a
regression probe, not a proof that every token or every callback payload is safe.

## How to interpret the result

- A passing test means these direct-call payloads did not move the sampled assets at the fork head.
  A callback may revert or accept a harmless payload; acceptance by itself is not evidence of a
  drain.
- A failing balance invariant is a reproducible fork signal to investigate. Keep the fork local,
  inspect the traces, and do not submit a transaction to the live contract.
- The probe does not claim that the scanner finding is confirmed. Verify deployed bytecode and
  configuration at the chosen fork block, inspect call paths, and establish attacker profit before
  making a report.

The callback dispatcher decodes the standard three-argument shape `(int256, int256, bytes)` and
checks the dynamic-data bounds before entering the callback body. The disassembly then performs a
`TLOAD`-based comparison before the token transfer path (`transfer(address,uint256)`). The expanded
probes now include two candidate 32-byte callback-data layouts for WETH: packed `address + uint96`
and canonical `abi.encode(address)`. The packed layout is repeated twice in one attacker-controlled
top-level transaction to exercise any transient-state change between attempts. These are decoder-
informed candidates, not a claim that either is the contract's intended callback schema; inspect the
new `-vvvvv` traces to see whether each reaches the guard, token call, or revert path.

The transient key sampled by the test is the 32-byte constant loaded via `CODECOPY` immediately
before the callback `TLOAD`/`TSTORE` sequence. Other code paths use separate transient keys, so do
not conflate those with this callback slot. The fork probe is intended to test behavior, including
the separate Pancake V3 entry point, rather than infer safety from the alert text alone.
