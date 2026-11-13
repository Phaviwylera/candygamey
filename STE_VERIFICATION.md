# STE reentrancy finding — independent verification

Target: **STE** ("Stored Ethereum") `0x792f5bdde5f8cf4b075b7a9dc4f296341d00b0d1` (ethereum)
Source: verified compiler input from `EthVM/evm-source-verification`
Compiler: solc `0.8.0+commit.c7dfd78e`, optimizer **off**, evmVersion `istanbul`
Method: local EVM execution (`@ethereumjs/vm` 8.1.1, **London** rules). No RPC, no fork, no broadcast.

## Verdict

**FALSE POSITIVE. The reentrancy payload is not exploitable.**

The finding's stated mechanism — *"the attacker's receive() calls withdraw again before the balance
is set to 0"* — is directly contradicted by the code. `_burn()` runs on **line 43**, before the
external call on **line 45**, and OpenZeppelin's `_burn` debits balance **and** totalSupply:

```solidity
_burn(_msgSender(), tokens);                 // <-- balance + totalSupply debited HERE (line 43)

(bool success, ) = _msgSender().call{value: netWithdrawal}("");
require(success, "ETH transfer failed");

totalWithdrawals += netWithdrawal;           // line 48 — written, never read
```

## Proof it is byte-exact

| | |
|---|---|
| Compiled runtime hash | `0xf1d9fa6b876a53c7dd0e11963876dd83ee4d6cb29d9e80e307002a5d6154cc61` |
| **On-chain runtime hash** (`metadata.json`) | `0xf1d9fa6b876a53c7dd0e11963876dd83ee4d6cb29d9e80e307002a5d6154cc61` |
| Byte-identical | **YES** |

Unlike the MevWeth report, there is no fidelity caveat here: the runtime is identical to mainnet,
so the bytecode tested *is* the bytecode deployed.

## Executed payloads

An attacker contract deposits 5 ETH, then re-enters `withdraw()` from `receive()`. Two variants,
because they are not equivalent:

| Variant | Reenters with | attempts | succeeded | Result |
|---|---|---|---|---|
| `attackCached` — the real drain shape | token amount cached **before** the call | 1 | **0** | reverts `"ERC20: burn amount exceeds balance"` |
| `attackLive` — reads `balanceOf()` live | balance observed inside callback (= 0) | 1–7 | 1–7 | executes but transfers **0 ETH** |

`attackCached` is the only shape that could drain, and it is precisely the one the burn blocks. It
fails with the standard `Error(string)` selector `0x08c379a0` and reason
**`"ERC20: burn amount exceeds balance"`** — the attacker's balance was already 0, so the second
burn has nothing to burn.

`attackLive` "succeeds" and can be made to recurse 7 deep, but each nested call recomputes
`netWithdrawal` from a zero balance and pays out **0 wei**. A successful call is not a profit; the
harness originally reported these as profit until the accounting was fixed to include the deposit
leg.

**Attacker net result in every scenario: −487,500,000,000,000,001 wei (−0.4875 ETH)** — the 5%
deposit fee plus rounding. There is no profit at any depth.

## The flagged state variable is inert

`totalWithdrawals` appears **twice** in the contract: the declaration (line 9) and the write
(line 48). It is never read by `withdraw`, `withdrawable`, `totalSupply`, or the ERC20 base. So
even if the ordering were wrong, no value calculation depends on it. The scanner's
"State updated after an external call → HIGH fund-theft" is structurally inapplicable: the only
post-call state update is a write-only counter.

Proof from the run: `totalWithdrawals` read *inside* the callback was already
`9,737,500,000,000,000,000` — i.e. the effect had been applied before the interaction.

## Independent corroboration

- **InPlusLab ReentrancyStudy-Data** (a peer-reviewed reentrancy ground-truth dataset) lists this
  exact address with `true_positive = N/A`, and **all seven** detectors (`oyente`, `mythril`,
  `securify1`, `securify2`, `smartian`, `sailfish`) report `N/A` — nobody flagged it.
- Etherscan metadata (`contract_information_etherscan.csv`) agrees with the verified build:
  `v0.8.0+commit.c7dfd78e`, `OptimizationUsed = 0`, `EVMVersion = Default`.

## What is actually worth noting (not this finding)

STE charges a **5% withdrawal fee unless `tokens == totalSupply()`** — i.e. the *last* holder out
pays no fee and receives all ETH accumulated from everyone else's fees. Measured with two honest
10 ETH depositors:

| | deposited | received | net |
|---|---|---|---|
| A (withdrew first, paid 5%) | 10 ETH | 9.975 ETH | **−0.025 ETH** |
| B (withdrew last, all remaining supply) | 10 ETH | 10.025 ETH | **+0.025 ETH** |

That is a real **last-exit advantage** worth ~0.025 ETH per 10 ETH pair, funded entirely by earlier
withdrawers. It is an economic/design property, not a reentrancy bug, and it is not in the scanner's
report. It is documented here for completeness: it is *not* a fund-theft vulnerability and should
not be reported as such.

Also note the deposit formula applies the 5% fee *before* the `priorBalance` division, so
`totalSupply()` tracks token accounting rather than ETH 1:1 — consistent with the fee model.

## Caveats

- The `migrate`-style caveat that applied to the MevWeth report does **not** apply: runtime hash
  matches on-chain exactly.
- `withdraw()` also reverts if the caller's `receive()` reverts or exceeds the 2300-gas stipend
  expectations — normal for `call{value}` and not a vulnerability.
- The 5% fee means any "attack" must first pay the deposit fee, which dominates any rounding.

## Recommendation

**Do not submit this finding.** It will be rejected: the burn is CEI-correct, the flagged state
variable is write-only, and the payload provably yields a net loss. The only defensible comment for
the project is the last-exit advantage above, as a low/informational design note — and it is
inherent to the advertised "stored Ethereum" fee model.

## Reproduce

```bash
cd ste-verification
npm install
npm run compile     # compiles verified source, asserts runtime hash
npm test            # runs attacker contracts, prints net P&L
npm run reasons     # decodes the exact revert reason
npm run economics   # last-holder-out table
```
