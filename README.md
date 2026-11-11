# Callback-authentication fork test

This repository contains the deployed runtime bytecode (`bot_runtime.hex`) and its disassembly for
Ethereum contract `0xbdb3ba9ffe392549e1f8658dd2630c141fdf47b6`. The Foundry test in
`test/CallbackAuthFork.t.sol` probes the two reported swap-callback entry points using direct calls
from an unprivileged address on a **local mainnet fork**. Separate test cases keep each callback in
a fresh transaction (important for EIP-1153 transient storage). The checks reject a decrease in the
bot's native or tracked ERC-20 balances, an increase in the caller's balances, or a new token
allowance granted to the caller.

## Run

Install Foundry, then provide an Ethereum mainnet RPC endpoint. For Alchemy, make the key
available as the `ALCHEMY_API_KEY` environment variable through your local secret manager (do not
put it in this repository or paste it into chat), then run:

```sh
export RPC_URL="https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
forge test --match-path test/CallbackAuthFork.t.sol -vv
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

The disassembly already contains a relevant guard on the Uniswap selector path: after loading a
transient-storage value (`TLOAD`), it compares the encoded address against `CALLER` before the
subsequent token transfer. This is a potential mitigating guard that a source-level finding may
have missed. The fork probe is intended to test behavior, including the separate Pancake V3 entry
point, rather than infer safety from the alert text alone.
