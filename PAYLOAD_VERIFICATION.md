# BountyScan findings 1–5 — independent verification

Target: **MevWeth** `0x00000000008C43efC014746c230049e330039Cb3` (ethereum)
Source: `blunt-instruments/MevWeth` @ `84770081cc456284e5347b2091595a601f42d353`
Compiler: solc `0.7.6+commit.7338295f` (reported compiler reproduced exactly)
Method: local EVM execution (`@ethereumjs/vm` 8.1.1, Cancun rules). **No RPC, no fork, no broadcast.**

## Verdict

**All five HIGH findings are FALSE POSITIVES. The payload is not exploitable.**

| # | Finding | Payload sent | Result | Revert reason | Attacker gain |
|---|---|---|---|---|---|
| 1 | `MevWeth.getMev(uint256)` `:50` | `getMev(pot+1)` / `2^255` / `uint256.max` | **revert** ×3 (443 gas) | bare revert at `require(current >= value)` | 0 |
| 2 | `MevWeth.getMev(address,uint256)` `:65` | `getMev(attacker, 2^255)` / `max` | **revert** ×2 (432 gas) | bare revert at `require(current >= value)` | 0 |
| 3 | `WETH10.transfer` `:316` | `transfer(attacker, max)` | **revert** ×2 (2,734 gas) | `WETH: transfer amount exceeds balance` | 0 |
| 4 | `WETH10.transferFrom` `:359` | `transferFrom(alice, attacker, max)` | **revert** (2,802 gas) | `WETH: request exceeds allowance` | 0 |
| 5 | `WETH10.transferAndCall` `:389` | `transferAndCall(attacker, max, 0x)` | **revert** (2,873 gas) | `WETH: transfer amount exceeds balance` | 0 |

Every payload dies *before* the arithmetic the scanner flagged. #1/#2 revert in 443/432 gas — that is
the `require` on line 49/64 and nothing else. #4 never even reaches the credit: it is rejected at the
allowance check.

Reproduce the reasons with `node revert_reasons.js`.

Solvency invariant `sum(balanceOf) + mev == address(this).balance + flashMinted` held in **14/14** scenarios.

## Why the scanner is wrong (three independent reasons)

**1. There is no multiplication to overflow.** The report says the input
"overflows the unchecked **multiplication**" and the exploit needs "2 receivers × 2^255".
`grep` over `src/MevWeth.sol` and `src/Weth10Mod.sol` finds **zero** `*` or `/` operators in any
arithmetic path. The finding's stated mechanism does not exist in this contract — that text is a
generic `mul`-overflow template (note the proposed fix even uses a `_value.mul(cnt)` snippet that
isn't from this codebase).

**2. Every `+=` is gated by an exact `>=` debit guard.** The pattern is uniform:

```solidity
uint256 balance = balanceOf[msg.sender];
require(balance >= value, "WETH: transfer amount exceeds balance");
balanceOf[msg.sender] = balance - value;   // exact subtraction
balanceOf[to] += value;                    // overflow-only if value was free — it never is
```

For `balanceOf[to] += value` to wrap it needs `value > 2^256 - balanceOf[to]`, i.e. an
astronomically large `value`. But the same `value` must satisfy `balance >= value` on the debit
side, and the debit only ever holds real, previously-deposited balance. With a zero starting
balance, `require(0 >= value)` permits only `value == 0`. That is why every max-value probe reverts
in 432–2,873 gas — it fails at the guard, before any arithmetic.

**3. `getMev` has a bounded subtraction, not an unchecked one.** `require(current >= value)` then
`mev = current - value` cannot underflow. `balanceOf[msg.sender] += value` cannot wrap because
`value <= current = mev`, and `mev` was only ever funded by `addMev` burning real balances.

The report's own §4 is self-refuting: *"Attacker delta 0 · Target delta 0 · assertion FAIL — not a
confirmed exploit"*. The "confirmed by independent second pass" line contradicts the test outcome.

## Additional probes (all negative)

| Probe | Outcome |
|---|---|
| Report's exact mechanism in **one** tx: two `getMev(to, 2^255)` via a batcher contract | both inner calls reverted `[0,0]` |
| 8× `getMev(to, uint256.max)` in one tx | 0/8 accepted |
| `claimTwice()` in one tx (transient-state reuse) | 1st claim won, 2nd got 0 — correct |
| `overflowTransfer(uint256.max)` from a 0-balance account | returns `false`, no state change |
| Flash-mint 5 ETH then `withdraw()` in the ERC-3156 callback | reverted — unbacked mint can't be laundered |
| `totalSupply()` vs `sum(balanceOf)+mev` vs ETH balance | all equal (18e18) |

## What *is* real (not a fund-theft bug — griefing / design issue)

`getMev(address to)` and `getMev()` have **no access control and no recipient validation**. Anyone
can name any recipient, including `address(0)` or the contract itself, and the contract cannot check
whether that address can ever redeem.

- `getMev(address(0))` moves the entire prize pot to `address(0)`'s internal ledger entry for
  **~2,653 gas**. The tokens are still "backed" (invariant holds), but `address(0)` can never call
  `withdraw()`, so the pot is permanently unclaimable.
- Same with `getMev(address(this))` — the contract has no path to spend its own balance.
- This is a classic **front-running / DoS-grief**: an attacker watching the mempool for an intended
  `getMev()` claim (or for `addMev` funding) can burn the pot one transaction ahead. The victim's
  `getMev()` still succeeds but pays out **0** (measured: alice gained 0 METH).

Impact is *loss of the MEV pot*, not theft of user deposits: `sum(balanceOf)` is unchanged, so
ordinary depositors' WETH10 balances stay redeemable 1:1 against the ETH the contract holds. The
maximum at-risk value is whatever sits in the `mev` pot at the moment of the sweep — the report's
own scan measured ~1.55 native / $3,122 in the contract, but the *pot* portion could be far smaller.

Severity: **LOW/INFO** (griefing, no attacker profit beyond denying a competitor's claim). Anyone
who runs the pump claims the pot — which in the MevWeth design is the *intended* behavior — so the
practical exploitable delta is "denial of a specific MEV claim", not a drain.

**Fix:** add an access-control/design guard so the pot can only go to a `to` that is provably able
to redeem, e.g. `require(to != address(0) && to != address(this))` on the `getMev(address)`
overloads, and/or route payouts through `getMev()` (the `msg.sender` overload) only, or add a
commit-reveal/allowlist for intended recipients.

## Caveat on source fidelity

The source compiles cleanly and its line numbers match the report exactly (`:50`, `:65`, `:316`,
`:359`, `:389`), and `script/DeployMevWeth.s.sol` documents this address via CREATE2. I could not
reproduce the exact init-code hash (metadata-sensitive; the live contract's constructor args /
metadata may differ slightly), so treat this as a **high-confidence** but not byte-identical
verification. The behavior tested is the behavior of the code lines the report cites; the security
argument (no multiplication, exact `>=` guard, bounded `mev - value`) does not depend on byte
identity.

## How to reproduce

```bash
cd harness
npm install
npm run compile      # compiles MevWeth (0.7.6) + helper contracts (0.8.28)
npm run check        # runs all 14 scenarios
node revert_reasons.js   # exact revert reason per finding
cat artifacts/payload_results.json
```

`artifacts/MevWeth.json` is the compiled deployment bytecode used. `artifacts/payloads.json` holds
the exact calldata for each of the five findings if you want to replay them elsewhere.

## Disclosure checklist

- [x] reachable by an unprivileged caller — yes, but **no profit**
- [x] funds actually at risk — only the `mev` pot, via griefing
- [x] not a known/accepted issue — the `getMev(address)` openness is documented design intent
      ("allows users to create explicit MEV"); the *unredeemable recipient* is the gap
- [x] PoC passes — the **negative** PoC (all 5 payloads revert) passes on a local EVM

**Do not submit findings 1–5.** They will be rejected as non-reproducible. If you want to report
something, report the `getMev(address)` unredeemable-recipient grief as a low-severity design note —
and check first whether the maintainer considers it out of scope.
