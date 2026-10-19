# Recursive lineage: measured cost

`apply_batch` now proves that its old state descends from genesis. For batch number 0 the old state must
equal `genesis(descriptor)`. For every later batch the guest verifies the previous settlement's
`apply_batch` receipt against a journal it rebuilds from the predecessor transaction (non-witness bytes
plus the outputs its inputs spent) and the predecessor annex digest. The host supplies that receipt in
one of two ways:

* **receipt mode** (what the batcher uses): the previous settlement's unconditional succinct receipt
  (`unconditional.bin`) is added with `ExecutorEnv::add_assumption`; the guest calls `env::verify`, and the
  host discharges the assumption with `recursion::resolve` after lifting and joining.
* **seal mode** (fallback when only the published padded-SHA receipt is available): `receipt.json` plus
  `seal.bin` are rebuilt into a `SuccinctReceipt` and verified inline by the guest.

Harness: `tools/lineage_e2e.py` on one patched gsr regtest node (jmoik/bitcoin `gsr` plus
bitcoin/bitcoin#36466), driving `pr-batcher`. Two escrow deposits of 20,000 sats are made; batch 1 spends
genesis and batch 2 spends batch 1. Raw results: `reports/lineage-e2e.json`.

Machine: 8-core Intel Xeon, 31 GiB RAM, `GSR_BUILD_CPU_BATCH=1`, `GSR_CPU_BATCH_LANES=16`, one prover
worker.

## Proven and mined settlements

| | batch 1 | batch 2 |
| --- | --- | --- |
| lineage | genesis | receipt (batch 1's `unconditional.bin`) |
| user cycles | 13,799,746 | 7,332,418 |
| segments | 14 | 8 |
| segment proving | 3,255 s | 1,850 s |
| lift + join | 625 s | 361 s |
| `resolve` of the predecessor | n/a | 22.4 s |
| padded-SHA identity | 18.7 s | 20.0 s |
| seal words | 55,667 | 55,667 |
| mined weight | 333,803 WU | 333,803 WU |
| inputs / outputs | 3 / 1 (escrow deposits swept) | 2 / 1 |

Both were mined and confirmed; both depositors' scans recovered their 20,000-sat notes (leaves 0 and 1).
The whole `pr-batcher` process (both proofs) took 2:00:59 wall clock, 45,716 s user CPU and at most
9.8 GB resident (`/usr/bin/time -v`).

**On chain the recursion costs nothing:** the weight is identical to the pre-lineage settlement in
`reports/relay-e2e.json` (333,803 WU), because the predecessor receipt is resolved before the final seal.

**Receipt mode costs one `resolve` (22.4 s) and no extra segments:** batch 2 needed 8 segments, the same
as the pre-lineage genesis batch A of PR #11 (8 segments, about 1,825 s).

**Genesis is the expensive case (one-off per pool):** batch 1 grew from 8 to 14 segments. Inference, not
profiled: the new base-case check `*old == genesis(descriptor)` recomputes the empty commitment-tree root
with Poseidon2 twice (`Frontier::root`, depth-many hashes each). Short-circuiting `Frontier::root` for
`count == 0` to the constant `ZERO_HASHES[DEPTH]` is exactly equivalent and removes them; it changes the
image ID, so it is left to the next image-changing PR.

## Executed (not proven) against batch 2's witness

| case | result |
| --- | --- |
| seal mode with batch 1's real `receipt.json` + `seal.bin` | accepted; 30,194,917 cycles, 32 segments; journal equal to the mined batch 2 journal |
| receipt mode with batch 1's `unconditional.bin` | accepted; 7,332,418 cycles, 8 segments |
| no predecessor proof | rejected: "the old state is not genesis; a predecessor proof is required" |
| batch 2's own receipt as the predecessor (wrong journal) | rejected: "predecessor receipt is for another journal" |
| `old_state.parent` changed to a fabricated outpoint | rejected: native transition `Lineage` |

Seal mode costs about 22.9 M more cycles than receipt mode (24 more segments, roughly 4x the proving),
which is why the batcher keeps `unconditional.bin` and uses receipt mode whenever it has it.

## What this fixes

Before this change `check_lineage` only checked that the predecessor transaction's input 0 spent
`old.parent`, where `old` was unauthenticated witness data. A native probe made up a state with the genuine
rollup id and a `parent` of the attacker's own, and `apply_batch` accepted a sweep of a 1,000,000-sat
escrow into it. `tests/tests/lineage.rs` keeps that case as a regression test: the fabricated state now
either fails the native transition or names a predecessor journal for which no receipt exists.

Run notes: the first attempt failed after batch 1 was proven because `covenant_cli.py` was run before the
receipt existed and was restarted from scratch; the run above then proved both batches without interruption.
The executed cases were run with `lineage_e2e.py --resume` against the same node and batcher state after a
path bug in the harness stopped it right after batch 2 was mined.
