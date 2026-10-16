# P3: append-only anchors, compact self ciphertexts, multi-output withdrawals, 16-transaction batches

Run: `tools/p3_e2e.py` on the optimized `gsr` node (jmoik/bitcoin `gsr`, `-vbparams=tapleaf_0xc2:0:3999999999`),
SDK wallets -> `pr-batcher` HTTP -> settlement proof -> mined with `generateblock`. 8 vCPU machine, CPU prover
(`GSR_BUILD_CPU_BATCH=1`). Raw output: [p3-e2e.json](p3-e2e.json). All numbers below are measured unless
marked as an estimate.

## What changed

* **Anchors never expire.** The 64-entry `ANCHOR_WINDOW` is replaced by an append-only depth-32 Merkle tree of
  `AnchorEntry` leaves (`anchor_leaf`, `anchor_node`, empty-subtree padding). The state commits to its root;
  each join-split carries an `AnchorProof` (entry + 32 siblings) checked against the old root, and the guest
  appends the batch's anchor into the next empty slot, proven by `anchor_slot` (the empty-leaf path to
  `batch_number + 1`). The anchor-expiry griefing attack (fill 64 batches with empty settlements) no longer
  forces users to re-prove; `expiry_batch_number` remains the only expiry, chosen by the user.
* **Change / self outputs: 120-byte ciphertexts.** Outputs to the sender's own address are encrypted with
  XChaCha20-Poly1305 under the wallet's outgoing key (nonce `sha256(commitment)[..24]`, AD = rollup id +
  commitment), kind 1, instead of a 1,232-byte ML-KEM ciphertext (kind 0). The annex carries a kind byte per
  output; scanners trial-decrypt kind 1 with their outgoing key and kind 0 with the ML-KEM key.
* **Up to 4 withdrawal outputs per join-split** (`MAX_WITHDRAWALS_PER_TX`), each non-dust, summing exactly to
  `withdrawal_sats`, kept in declaration order in the settlement.
* **Batch cap 8 -> 16** (`MAX_BATCH_TRANSACTIONS`), with selection bounded by weight:
  `select()` fills `MAX_SETTLEMENT_WEIGHT - EMPTY_SETTLEMENT_WEIGHT = 400,000 - 332,000` WU using the per-entry
  upper bounds `entry_weight` / `escrow_weight`. `EMPTY_SETTLEMENT_WEIGHT` rounds up the measured 331,699 WU
  empty settlement (P1).

## Optimized-GSR run

| Step | Wall time | Settlement weight | Annex |
|---|---:|---:|---:|
| 4 deposit proofs (one per wallet) | 313.0 / 299.9 / 300.0 / 299.8 s | | |
| **Batch 1: four deposits** | 1,945.5 s | **333,850 WU** (83,463 vB) | 1,632 B |
| Transfer A -> B proof | 695.7 s | | |
| Transfer D -> A proof | 699.4 s | | |
| Withdrawal proof, C -> 4 outputs | 688.6 s | | |
| **Batch 2: two transfers + one 4-output withdrawal** | 1,930.5 s | **335,724 WU** (83,931 vB) | 3,486 B |

Settlement proving breakdown:

| Batch | Segments | Total / user cycles | Segment proving | Lift + join | `resolve_zk` | Padded-SHA identity |
|---|---:|---:|---:|---:|---:|---:|
| 1 (4 deposits) | 18 | 18,874,368 / 17,797,355 | 1,469.0 s | 321.1 s | 36.3 s | 6.1 s |
| 2 (2 transfers + withdrawal) | 17 | 17,825,792 / 16,592,383 | 1,411.8 s | 364.1 s | 32.8 s | 7.3 s |

User receipts were 276,139-276,500 B (3 segments for a deposit, 7 for a spend).

Checks in the run: every annex ciphertext kind parsed at the offsets in `spec/encoding.md`, with the parser
consuming the annex exactly (batch 1: all 8 outputs kind 1; batch 2: `[1, 1, 1, 0, 0, 1]`, i.e. the two
transfer recipients are ML-KEM and all change outputs compact); all four withdrawal outputs present on chain
with their values and scripts; every wallet's scan matches its expected live notes; a replayed deposit
submission is refused (HTTP 400; the transition checks expiry before duplicates and the
deposit's `expiry_batch_number` had passed, so this run does not by itself exercise the duplicate-nullifier path, which
`tests/tests/scenario.rs` covers); the batcher's status is identical after a restart.

## Weight per join-split

Increments over the P1 empty settlement (331,699 WU, measured in P1 with the same leaf size of 101,688 B):

* Deposit: (333,850 - 331,699) / 4 = **538 WU** each, vs 2,760 WU per join-split in P1. The annex part is
  370 B = 2 nullifiers (64) + 2 x (commitment 32 + kind 1 + 120-byte ciphertext); the rest is the funding input.
* Batch 2: 4,025 WU for two transfers and one 4-output withdrawal. Annex 3,334 B = 3 x 64 nullifier bytes +
  2 ML-KEM recipient outputs (2 x 1,265) + 4 compact outputs (4 x 153); the remaining ~690 WU are the four
  withdrawal outputs.

Local upper bound vs actual: `entry_weight` gives 978 WU per deposit from the actual submissions (558 B of
statement + external data counted at 1 WU/B, plus 420 WU per funding input), so the selector's batch-1 bound is
332,000 + 4 x 978 = 335,912 WU against 333,850 measured. For batch 2 the same formula, evaluated by hand from
the encoding (estimate), is about 336,650 WU against 335,724 measured. The bound held in both batches.

Batch-size estimates (not measured): with compact change, a spend with one external recipient adds about
1,650 WU (estimate), so the 68,000 WU budget fits the 16-transaction cap for deposits and for transfers alike.
Settlement proving grew from ~1,816 s (2 transactions, P1) to ~1,946 s (4 transactions): at this size it is
dominated by fixed costs, but the rate for 16 transactions has not been measured (P5).

## Limits

* The anchor tree has depth 32 (2^32 batches); `AnchorHistory` is stored in full by the operator and SDK
  (48 B per batch).
* Compact self ciphertexts are recoverable only with the wallet seed's outgoing key; that is the point
  (only the sender recovers them), and it is why they are used only for outputs to the sender's own address.
* Escrow-minted notes may carry either kind; an escrow paying someone else must use kind 0 for the recipient to
  find it.
* Measurements are from one run on one machine.
