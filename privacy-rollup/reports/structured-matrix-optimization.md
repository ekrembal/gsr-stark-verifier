# Fixed JoinSplit structured-matrix evaluator

Unpublished experiment based on local SHA-accelerated commit
`5a2b71d81cdd9f7ebf309ac0f8ac30eaee43dca0`. No AIR, transcript, proof format,
security parameter, or client proving change is introduced.

## Measured result

Two paired runs use the identical frozen VK/proof/witness frames documented
in the SHA experiment. These are execution measurements, not full proofs.

| Settlement metric | SHA baseline | Structured reverse evaluator |
|---|---:|---:|
| User cycles | 746,732,029 | 523,884,080 |
| Segments, limit 2^20 | 842 | 610 |
| Median execution seconds | 26.3935 | 21.6365 |
| Maximum host RSS, KiB | 143,480 | 128,568 |
| Client proof bytes | 635,142 | 635,142 |
| VK frame bytes | 3,213,548 | 3,213,548 |

Settlement cycles decreased 29.8431%; median runtime decreased 18.0235%.
Both settlement journals have SHA-256
`4e366d165e21f04fcb31f5cd46b0abfecd9d6503f8d542c3f45399256890b43f`.
The diagnostic verifier decreased from 726,666,128 to 506,728,232–257 cycles
and from 821 to 594 segments. Its count-only journal is not a substitute for
the settlement input-binding and journal checks.

The matrix phase decreased from 295,035,330 to 71,477,042 inclusive cycles,
including the essentially unchanged 21,425,238-cycle equality table. The new
fixed entry point adds a complete key hash to the diagnostic guest, increasing
its key phase from 78,805,615 to 82,427,724 cycles. Prefix MLE evaluation remains
95,760,329 cycles; sparse NTT remains 128,089,503 cycles. These are the next
optimization targets, alongside fixed-key parsing.

Raw paired measurements, exact commands, phase counters, image IDs, input
hashes and memory figures are in `structured-matrix-measurements.json`.
Preserved host/guest baselines are in ignored
`build/aggregation/structured-reverse-baseline/` and
`build/aggregation/fused-sha-baseline/`.

## What changes

The pinned ProveKit compiler expands Poseidon2 linear layers into sparse rows.
The evaluator reconstructs the same linear map using four running adjoints
per matrix, reversing the external and internal linear layers. S-box outputs
are still independent witness columns. Their nonlinear constraints are neither
recomputed nor assumed satisfied. The remaining 763 rows use the existing
scatter/cache implementation.

`structured_matrix_plan.py` independently detected 142 blocks in the exact VK
and checked every coefficient of their 38,056 rows in all three matrices:
114,168 matrix rows. It starts with literal initial forms, reconstructs each
subsequent linear form from the pinned t=4 diagonal and external matrix, checks
the three-row S-box constraint pattern, and checks all final output rows.
Identical round constants across blocks are accumulated before multiplying.
The checked JSON plan is 300,963 bytes, SHA-256
`851a773762c0a8d9a72ccac277bf9c624a9981d4e79f765c098fadb1db5d9826`.

`FixedJoinSplitVerifier::from_postcard` checks SHA-256 over every VK byte before
deserialization and keeps the resulting configuration private. Only this
constructor enables the specialized matrix path. Its pinned key is
`bc1384089b1dc1654e61561089523ae521d2cf9b664589ec1e965108b4e2a183`.
Generic native verification retains the original path. The settlement guest
still checks each proof's public inputs against the transaction statement and
commits the complete native-checked batch journal.

The incremental dependency patch is `patches/provekit-structured.patch`,
applied after the existing pinned compatibility and aggregation patches.
Apply it with `git apply --unidiff-zero` (zero context avoids trailing blank
context lines inside the tracked patch artifact).
The verifier adds direct dependencies on already present `postcard` and
`sha2` packages to bind and decode its fixed key. The only lockfile changes
are these two dependency-list entries in the native and guest workspaces;
package versions, source identities, and checksums are unchanged.

## Validation and formal coverage

All 37 native workspace tests passed. New tests compare all 155,415 matrix
outputs for 13 arbitrary row-weight vectors, 15 boundary impulses, and five
sumcheck points. Fresh real client proofs pass both generic and fixed
verification. Existing proof mutations are rejected by both paths, and valid
proofs remain accepted after failed attempts. The fixed constructor rejects
changed, truncated, and extended VK frames.

All nine guest rejection cases passed for the same built images. A fresh
operator-generated client proof also passed settlement execution with the
complete journal matching native state transition; admission, replay checks,
acceptance, and rollback passed. Reapplying the pinned compatibility,
aggregation, and structured patches reproduced all 11 affected dependency
files byte-for-byte.

Lean 4.34.0 checks the four integer identities for the addition-only external
transpose in `formal/ExternalTranspose.lean` using standard `propext` and
`Quot.sound` axioms. The exact coefficient reconstruction is an executable
symbolic check, not a Lean proof. The reverse traversal, Rust compilation,
memory layout, hash binding, and protocol soundness have not been formally
verified. The earlier narrow coefficient/cache and Montgomery lemmas do not
cover this implementation as a whole.

The independent research archive supplied through Library could not be
materialized in this executor because its current tools expose uploads but
no Library materialization/read action. No storage URL was guessed. The
compiler/VK analysis and evaluator here were reconstructed locally and passed
the checks above; the external prototype's claimed results were not treated
as measured evidence.

## Reproduce

After applying all three ProveKit patches and activating the existing environment:

```sh
cargo +1.97 build --locked --release --manifest-path privacy-rollup/Cargo.toml --bin matrix-dump
privacy-rollup/target/release/matrix-dump build/aggregation/inputs/vk.pc build/feasibility/matrices.json
python3 privacy-rollup/tools/structured_matrix_plan.py \
  build/feasibility/matrices.json build/feasibility/structured-plan.json \
  --rust-output /workspace/provekit/provekit/common/src/utils/structured_matrix_data.rs
cargo +1.97 test --locked --release --manifest-path privacy-rollup/Cargo.toml --workspace
/workspace/.gsr-env/lean/bin/lean privacy-rollup/formal/ExternalTranspose.lean
```

Build the guest with the locked SDK environment from
`fused-bigint2-feasibility.md`. Add GNU time to PATH before profiling:

```sh
export PATH="/workspace/.gsr-env/sysroot/usr/bin:$PATH"
export RAYON_NUM_THREADS=4
python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
  --label structured-reverse-0 --kind verify --runs 1
python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
  --label structured-reverse-0 --kind batch --runs 1
```

Do not overwrite evidence labels from a previous run. Baseline commands pass
`--binary build/aggregation/fused-sha-baseline/exec_joinsplit` and
`--program build/aggregation/fused-sha-baseline/verify_joinsplit.bin` for the
verifier, or `--binary build/aggregation/fused-sha-baseline/settle` for settlement.

## Feasibility limits

The bounded real proof/lift/join/padded-identity chains and their verified
checkpoints are documented separately in `fused-bigint2-feasibility.md` and
`bounded-proof-checkpoints.json`. A full optimized JoinSplit proof has not
been generated. Lower execution cycles alone do not establish practical
aggregation. The unaudited padded RISC Zero hash patch and upstream ignored
FinalClaim results remain explicit correctness/soundness caveats.
