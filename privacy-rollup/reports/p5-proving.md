# P5: faster settlement proving

8 vCPU / 31 GiB machine, CPU prover built with `GSR_BUILD_CPU_BATCH=1 GSR_CPU_BATCH_LANES=16` and run with
`GSR_BATCH_CPU=1 GSR_PERIODIC_CPU=1 GSR_BATCH_EVAL_CPU=1 GSR_HASH_LANES=16 GSR_FAST_NTT=1`. Every number below is
measured on that machine unless marked as an estimate. Raw output: [p5-proving.json](p5-proving.json) (benchmarks),
[p5-e2e.json](p5-e2e.json) (end-to-end run).

## What changed

The settlement guest got about 3.6x cheaper; the proof system, the covenant Script and the protocol rules are
unchanged apart from the new image IDs and the `commitment_frontier` state field.

* **Poseidon2 in the guest (`pr-crypto`).** Profiling `apply_batch` (`settle_profile`, pprof) showed the BN254
  Poseidon2 permutation, mostly inside `Frontier::append` / `Frontier::root`, was over half of all cycles, and a
  large part of that was parsing the hex round constants and converting them to Montgomery form on every call.
  * Native: constants are precomputed Montgomery tables (`poseidon2_mont.rs`).
  * Guest (`target_os = "zkvm"`): a new `zkvm.rs` permutation on canonical `[u32; 8]` limbs with the RISC Zero
    BigInt2 accelerator (`modmul_256`, `modadd_256`), constants as static canonical tables
    (`poseidon2_canonical.rs`), no Montgomery conversion at the boundary.
  * Tests: both tables against the original hex constants, and the guest permutation (run natively) against the
    Arkworks one on 16 fixed input pairs, and modular addition on edge cases up to `2^256 - 1`.
* **Commitment tree.** Static `ZERO_HASHES` (tested against repeated `merkle_node`), and the state now stores
  `commitment_frontier`, a SHA-256 digest of the canonical frontier. The guest authenticates the incoming
  frontier with one SHA-256 instead of recomputing its 32-level Poseidon2 root, and computes the new root once.
  Sound by induction: `genesis` and every accepted transition set the digest from the same frontier as
  `commitment_root` (`spec/protocol.md`). This changes the `RollupState` encoding, hence the state root.
* **Batched nullifier insertion** (`verify_batch_insertion`, `IndexedTree::insert_batch`). The batch's sorted
  nullifiers are inserted together: one authenticated path per distinct low leaf (consecutive nullifiers in the
  same gap share it), then all new leaves are appended at consecutive slots from one 32-node left-sibling
  frontier. Before, each nullifier carried its own low-leaf path and its own empty-slot path (2 x 32 SHA-256
  nodes per nullifier, recomputed against a moving root). The resulting tree is identical to inserting one by
  one in ascending order (tested against `insert` over successive batches, including runs that share a low leaf,
  plus reordered, split, missing and duplicated low updates, a tampered low leaf, a non-empty slot frontier,
  duplicate, unbracketed and unsorted values).
* **Tagged SHA-256 midstates** for the protocol's own tags are computed once (`OnceBox`), so a tagged hash costs
  only its data blocks.
* **Parallel host proving** (`prover/src/settle.rs`). `prove_conditional` proves segments, lifts and each join
  level with `PR_PROVE_WORKERS` threads (default 1); results keep segment order and the first error is
  returned. Each worker runs a full CPU prover, so memory scales with workers.
* Tools: `settle_bench <witness.json> [workers]` (conditional receipt with open join-split claims, no user
  receipts needed), `settle_profile` (pprof), `tests/examples/bench_witness` (deposit / transfer witnesses at
  1, 2, 4, 8, 16 transactions), `tools/pprof_top.py`, `tools/regen_joinsplit_id.sh`.

The join-split guest shares `pr-crypto`, so its image ID changed (regenerated), as did `APPLY_BATCH_ID` and the
receipt template.

## Settlement proving, segments + lift/join (measured)

`settle_bench` stops at the joined conditional receipt. The remaining steps were not run here: `resolve_zk`
(one per transaction; 29-48 s for 3-4 transactions in P3/P4) and the padded-SHA identity (6-7 s), which do not
depend on what the guest does.

| Workload | Workers | Total / user cycles | Segments | Segment proving | Lift + join | Sum | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1 transfer | 1 | 4,456,448 / 4,170,387 | 5 | 350.7 s | 84.4 s | 435.2 s | 9.2 GiB |
| 1 transfer | 2 | 4,456,448 / 4,170,387 | 5 | 336.9 s | 79.3 s | 416.2 s | 18.4 GiB |
| 1 deposit | 1 | 4,227,072 / 3,936,156 | 5 | 336.0 s | 84.8 s | 420.8 s | 9.2 GiB |
| 1 deposit | 2 | 4,227,072 / 3,936,156 | 5 | 321.4 s | 79.5 s | 400.9 s | 18.4 GiB |
| 4 transfers | 1 | 6,291,456 / 5,631,952 | 6 | 523.4 s | 103.8 s | 627.1 s | 9.2 GiB |
| 4 transfers | 2 | 6,291,456 / 5,631,952 | 6 | 475.8 s | 98.2 s | 574.0 s | 18.4 GiB |
| 4 deposits | 1 | 5,505,024 / 4,992,084 | 6 | 448.2 s | 106.7 s | 554.9 s | 9.2 GiB |
| 4 deposits | 2 | 5,505,024 / 4,992,084 | 6 | 429.0 s | 101.2 s | 530.2 s | 18.4 GiB |
| 16 transfers | 1 | 12,582,912 / 11,235,740 | 12 | 1,021.8 s | 223.3 s | 1,245.1 s | 9.2 GiB |
| 16 transfers | 2 | 12,582,912 / 11,235,740 | 12 | 978.1 s | 213.2 s | 1,191.3 s | 18.4 GiB |
| 16 deposits | 1 | 10,485,760 / 9,256,523 | 10 | 859.9 s | 178.7 s | 1,038.6 s | 9.2 GiB |
| 16 deposits | 2 | 10,485,760 / 9,256,523 | 10 | 816.8 s | 173.7 s | 990.5 s | 18.3 GiB |

Executor-only counts (no proving) for the other sizes: 2 deposits 4,288,065 user cycles (5 segments), 8 deposits
6,419,091 (7), 2 transfers 4,518,202 (5), 8 transfers 7,874,776 (9).

### Against P3/P4 (measured, earlier runs of comparable batches)

| Batch | Code | Segments | User cycles | Segment proving + lift/join |
|---|---|---:|---:|---:|
| 4 deposits | P3 report | 18 | 17,797,355 | 1,790.1 s |
| 4 deposits | P4 report | 18 | 18,874,368 (total) | 2,148.0 s |
| 4 deposits | P5, 1 worker | 6 | 4,992,084 | 554.9 s |
| 2 transfers + 4-output withdrawal | P3 report | 17 | 16,592,383 | 1,775.9 s |
| 16 transfers | P5, 1 worker | 12 | 11,235,740 | 1,245.1 s |

The witnesses differ (P3/P4 deposits came from the end-to-end runs, P5 from `bench_witness`), but the shape is
the same: about 3.6x fewer guest cycles and 3.2x less proving time for 4 deposits, and a 16-transfer batch now
proves faster than a 3-transaction batch did.

### Parallel workers

Two workers saved only 4-9% of segment + lift/join time and doubled peak memory (9.2 -> 18.4 GiB). The CPU
prover already uses all 8 cores for one segment, so on this machine the default stays at 1 worker. On a machine
with many more cores than one prover saturates, or with one GPU per worker, more workers should help (estimate,
not measured).

### User join-split proof (measured)

The join-split guest uses the same Poseidon2 code. Regenerating `fixtures/joinsplit-receipt` (one deposit,
`joinsplit_fixture`): 1,410,560 user cycles in 2 segments, 128.1 s segment proving, 27.8 s lift/join, 10.9 s
ZK identity, 167.0 s total, 276,164-byte receipt. The same deposit proof in the P4 end-to-end run took 2,876,836
user cycles in 3 segments and 305.0 s.

## Full settlement on the `gsr` node (measured)

`tools/p4_e2e.py` rerun unchanged on the P5 code (optimized `gsr` node, `-vbparams=tapleaf_0xc2:0:3999999999`,
1 worker): four deposits, a mid-proof double-spend, re-prove of the other three, CPFP bump, mining and adoption
by a second batcher. Every step passed; whole script 37.7 min wall (P4: about 2 h).

| Settlement | Segments | User cycles | Segment proving | Lift + join | `resolve_zk` | Identity | Weight |
|---|---:|---:|---:|---:|---:|---:|---:|
| A, 4 deposits (abandoned before broadcast) | 5 | 4,804,976 | 422.1 s | 86.0 s | 40.0 s | 6.0 s | 334,022 WU |
| P4 run of A | 18 | 17,801,775 | 1,731.8 s | 416.2 s | 48.5 s | 9.1 s | 334,022 WU |
| B, 3 deposits (mined, confirmed) | 5 | 4,403,266 | 383.7 s | 88.8 s | 31.8 s | 6.4 s | 333,485 WU |
| P4 run of B | 17 | 16,553,110 | 1,616.7 s | 326.2 s | 29.0 s | 6.5 s | 333,485 WU |

* Batch-to-confirmed wall time for B: 640 s (P4: 2,101 s). The double-spend now costs the batcher 669 s of
  wasted proving instead of 2,337 s.
* The seal (55,667 words) and the transaction weight are identical to P4: the settlement transaction layout and the
  covenant Script logic did not change (only the pinned image ID), only the guest work behind the receipt.
* User deposit proofs in the same run: 169.5-188.2 s each (P4: 305-351 s).

## What is not measured

* A full settlement (with `resolve_zk` and the identity wrap) at 16 transactions, and its weight: only 3 and 4
  deposits were fully settled. 16 transactions should fit `MAX_SETTLEMENT_WEIGHT` (estimate, from about
  0.5-3k WU per transaction measured in P3/P4); `resolve_zk` should add about 10 s per transaction (estimate,
  from 31.8 s for 3 and 40.0 s for 4).
* Batches of 2 and 8 were only executed, not proven.
