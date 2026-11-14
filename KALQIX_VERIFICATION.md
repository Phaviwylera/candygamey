# KalqiX `claimAsset()` arbitrary-recipient finding — verification

Target: **TransparentUpgradeableProxy** `0x3adfbdceec009cd6a99b6c8f9d80522598c7c8ac` (ethereum)
Implementation: `0x0457012B4827Abc84536381F0fAd1eE2FcE9554B` → `contracts/KalqiXBridge.sol`
Reported compiler: solc `0.8.30+commit.73712a01`
Method: local EVM execution (`@ethereumjs/vm` 8.1.1, Cancun), solc `0.8.30+commit.73712a01`. No RPC, no broadcast.

## Verdict

**FALSE POSITIVE — with a fidelity caveat.** The payload cannot succeed. `claimAsset()` is gated by
a Merkle **exit-proof** that commits to the destination address; "no check on the caller" is true but
irrelevant, because the payer never needed to be the caller.

## The payload, and why it dies

```
claimAsset(proofLocal[32], proofRollup[32], globalIndex, token, destNetwork,
           destinationAddress = attacker, amount = whole bridge balance)
```

Executed against the bridge design KalqiX derives from (SMT local exit root + rollup exit root +
`globalIndex`), with a live global exit root installed and 50 ETH of user deposits in the bridge:

| Payload | Result | Revert |
|---|---|---|
| A — the scanner's literal payload (zeroed proofs) | **REVERTED** | `InvalidSmtProof()` `0xe0417cec` |
| B — forged leaf, real proof attempted against honest root | **REVERTED** | `InvalidSmtProof()` `0xe0417cec` |

Attacker ETH delta in both cases: **0**. Bridge still holds all 50 ETH of user deposits.

The guard the report omits is `_verifyLeaf(...)`, which `claimAsset` calls **before** the transfer:

```solidity
_verifyLeaf(
    smtProofLocalExitRoot,
    smtProofRollupExitRoot,
    globalIndex,
    SMTHelper.getLeafValueForExitTree(
        tokenAddress, destinationNetwork, destinationAddress, amount   // <-- recipient IS committed
    )
);
```

That is not a "caller check" — it is stronger. `destinationAddress` is a **hashed element of the
Merkle leaf**:

```solidity
keccak256(abi.encodePacked(leafType, originNetwork, originAddress,
                           destinationNetwork, destinationAddress, amount, metadataHash))
```

so paying a different address requires a different leaf, which requires a different proof, which
cannot be produced without the exit root's preimage. Proof from the run:

```
leaf(to=attacker): 0xac7c4731...
leaf(to=honest)  : 0x968e0968...
identical        : false   <- changing the recipient changes the leaf
```

## Positive control (this is the part that makes the negative result meaningful)

It is not enough to show payloads reverting — a contract that reverts everything would look "safe".
The harness therefore builds a **genuine** exit:

```
installed mainnet root: 0x0fdca4f5... (computed 0x0fdca4f5...) match=true
1st claim (legitimate, valid proof) -> ACCEPTED
depositor received: 1000000000000000000 wei
replay by attacker (different recipient) -> REVERTED 0xe0417cec
```

An honest claim against the same code path **pays out correctly** (1 ETH, bridge balance drops
50 → 49 ETH). Only the forged/redirected claims fail. The reverts are the guard working, not the
harness being unable to execute anything.

The design also carries a replay nullifier (`claimedBitMap`), which the reference implementation sets
via `_setAndCheckClaimed` after proof verification and which reverts `AlreadyClaimed()` on reuse.

## Independent corroboration

KalqiX was audited by **Hexens** (engagement dated 2026-01-13, published report):

| | |
|---|---|
| Findings | 9 total — **0 critical**, 0 high, 3 medium, 3 low, 3 info |
| `claimAsset` findings | read-only reentrancy of `tokenVsDeposits` (**info**, fixed); minimum-withdrawal lock (**low**, acknowledged) |
| Arbitrary-recipient / missing-auth finding | **none** |

The Hexens report quotes `claimAsset` at `contracts/KalqiXBridge.sol#L309-L386` with the signature
`(smtProofLocalExitRoot, smtProofRollupExitRoot, globalIndex, tokenAddress, destinationNetwork,
destinationAddress, amount) external override nonReentrant` and its body calling `_verifyLeaf` —
matching exactly what this review found. The auditor's own concern about this function was the
*ordering* of `tokenVsDeposits`, i.e. they treated the proof gate as working.

## Fidelity caveat (read this before acting)

I could **not** obtain the live verified source: neither `EthVM/evm-source-verification`,
`tintinweb/smart-contract-sanctuary-ethereum` nor `thec00n/etherscan_verified_contracts` mirrors a
Nov-2025 deployment, and I have no RPC egress in this environment. So:

- **Confirmed from a primary source:** the `claimAsset` signature, its `nonReentrant` modifier, and
  the `_verifyLeaf(...)` call — quoted verbatim by Hexens in their audit of this exact file.
- **Reconstructed:** the specific exit-root/Merkle implementation, from the reference AggLayer
  bridge that KalqiX's parameter names match. The harness runs that reconstruction.
- **Therefore:** the argument "recipient is a committed Merkle leaf, proof required, caller
  irrelevant" is solid because it follows from the signature Hexens quotes. The *exact* revert
  selector on mainnet may differ from my model's (a bespoke `SMTHelper` could revert differently).

This is weaker than the STE verification (where the runtime hash matched mainnet exactly). Treat the
verdict as high-confidence, not byte-exact.

## What the scanner got wrong, methodologically

It quoted lines 400–408 — the transfer — and concluded from the absence of `msg.sender` that nothing
gated the payout. `msg.sender` is deliberately absent in this design; the authorisation is a proof
bound to the recipient. Quoting a function body from its *middle* is how this false positive
survives its own "independent second pass".

Its own §4 also records `_Not measured (no dynamic run)_` — the finding was never executed, which is
exactly where a payload test would have caught this.

## Recommendation

**Do not submit this finding.** It will be rejected: there is no reachable path that pays an
attacker without a valid exit proof, and a public Hexens audit of the same file already treats this
gate as sound. If you want something defensible from the Hexens corpus instead, the **read-only
reentrancy of `tokenVsDeposits`** (marked *fixed*) is the only thing in this function ever found —
and if the deployed implementation predates the fix, verifying **that** would be a legitimate,
targeted question rather than a fabricated critical.

## Reproduce

```bash
cd kalqix-verification
npm install
node scripts/claim_suite.js
```

`reference/` holds the AggLayer bridge, the `DepositContract` leaf hashing, and the Hexens report
excerpt used as evidence.
