# Optional host CPU hashing experiment

The same saved 2^18 complete dot-product guest trace proved in 77.983 seconds
with eight-lane host hashing, versus 100.338 seconds with scalar hashing and
the same phase instrumentation. This is a single paired experiment, about
22% less proving time. Peak memory and seal size were essentially unchanged.
The guest, trace, AIR, Poseidon2 constants, sponge rate, hash bytes, transcript,
proof parameters and dependency revisions did not change.

| Host operation | Scalar seconds | Batched seconds |
|---|---:|---:|
| Leaf-row hashing | 34.244 | 14.921 |
| Merkle-parent hashing | 5.872 | 2.738 |
| Complete segment proof | 100.338 | 77.983 |

Compiling only the new `risc0_zkp` host code with `target-cpu=native` and one
codegen unit reduced the same proof to 67.966 seconds (67.979 supervisor
seconds): about 32% below the scalar reference. Leaf hashing took 4.413 seconds
and parent hashing 0.768 seconds. Its lift took 21.369 seconds. The saved
standard host again independently verified and converted that lifted receipt,
checked the complete diagnostic image/journal, and rejected a corrupted seal.
This later compiler result applies to the new packed implementation; it does
not invalidate the earlier negative compiler result for scalar hashing.

The native build is machine-specific and optional. It was produced using the
existing compiler-experiment wrapper with `GSR_NATIVE_RUST_CRATES=risc0_zkp`;
the log confirms only host targets received the flags. Clear `RUSTC_WRAPPER`,
`GSR_NATIVE_RUST_CRATES` and `GSR_NATIVE_RUST_LOG`, clean only the generated
`risc0-zkp` package artifacts, and rebuild to restore ordinary compilation.
Exact commands, timed phases, resource bounds, test results and receipt digests
are in [the machine-readable measurements](cpu-prover-batch-measurements.json).

The batched segment proof passed integrity verification. Its lift took 29.985
prover seconds. The saved standard host, built before these SDK changes,
independently verified that lifted receipt, converted it to the existing padded
suite, verified the complete diagnostic guest image and journal, and rejected a
corrupted seal. Padded conversion took 19.981 prover seconds; the final seal
remained 222,668 bytes. This is a complete small diagnostic receipt, not a full
JoinSplit receipt or validation of a new on-chain transaction.

## Changes and activation

Apply these supplemental patches to the pinned RISC Zero checkout, after its
existing `risc0-succinct/risc0-v3.0.6.patch`, in this order:

```sh
git -C /workspace/risc0 apply /workspace/gsr-stark-verifier/privacy-rollup/patches/risc0-cpu-profile.patch
git -C /workspace/risc0 apply /workspace/gsr-stark-verifier/privacy-rollup/patches/risc0-cpu-batch.patch
```

The source SHA remains `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`; the supplemental
patches are an explicit additional local source deviation. All three patches
reapplied byte-for-byte to the 19 affected SDK files. The original patch is
unchanged, and no Cargo lockfile or dependency revision was changed.

`GSR_PROFILE_CPU=1` enables one wall-time record per complete host HAL call,
including its Rayon workers. `tools/summarize_cpu_profile.py` aggregates those
records alongside the real-proof result and resource guard evidence. These
are wall times for calls, not CPU-time samples or a complete profiler for
constraint evaluation and witness generation.

`GSR_BATCH_CPU=1` opts the CPU HAL into batches of up to eight adjacent rows
or digest pairs. Leaving it unset retains the original scalar HAL path. The
new trait methods have scalar defaults for other hash suites. The Poseidon2
implementation uses safe fixed-size arrays of canonical Montgomery words;
it adds no unsafe code or architecture intrinsics. The original round constants
and round counts are reused. Partial rows, empty rows, capacity cells and
unpadded sponge behavior are preserved exactly. Unreduced row values fall
back to the original scalar implementation. Digest pairs still reject words
at or above the modulus, including the INVALID sentinel.

When field-operation counting is enabled, both batch entry points use the
original scalar operations. Permutation counting retains the actual number
of hashes, excluding unused lanes. Batching is confined to the host CPU prover;
the scalar verifier and guest code remain unchanged. The final guest binaries
are byte-identical to the measured 191.12M-cycle checkpoint.

## Validation and limits

All 35 pinned SDK library tests passed with `GSR_BATCH_CPU=1` and one test
thread. This includes new arithmetic, row and pair differential cases,
counter-fallback comparisons, arbitrary batch offsets and tails, unchanged
regions in the in-place Merkle buffer, both scalar-default SHA and specialized
Poseidon2 dispatch, noncanonical digest rejection, and the SDK's existing
Merkle rejection tests. The new HAL differential test also passed with
`GSR_BATCH_CPU=0`.

```sh
export CARGO_TARGET_DIR=/workspace/gsr-stark-verifier/privacy-rollup/prover/target
export CARGO_PROFILE_RELEASE_LTO=false
export RAYON_NUM_THREADS=4
GSR_BATCH_CPU=1 cargo +1.97 test --manifest-path /workspace/risc0/Cargo.toml \
  --locked --release -p risc0-zkp --features prove,unstable --lib -- --test-threads=1
```

The profile override disables the SDK workspace's release LTO for this test
build, matching the host benchmark build; it changes no source or lockfile.
Use the bounded command tool and saved capture files to reproduce proving.
The raw output/resource files preserve each exact command, runtime environment
is `RAYON_NUM_THREADS=4 GSR_PROFILE_CPU=1 GSR_BATCH_CPU=1` for the batched runs.

`formal/PackedBabyBear.lean` proves addition and Montgomery-intermediate
overflow bounds under canonical-input hypotheses, the sufficient numerator
bound for one final subtraction, and the concrete Montgomery inverse constant.
The bound proofs use Lean's standard `propext` and `Quot.sound`; the constant
check uses no axioms. These results do not establish Rust/LLVM refinement,
Montgomery congruence for the implementation, lane indexing, complete hash
equivalence, or protocol soundness. The original padded hashing patch remains
unaudited. Differential tests and small receipts are evidence, not those proofs.

The same saved normal application segment 100 (2^20 rows) proved in 264.455
seconds, versus 411.343 seconds with the saved standard host. Peak RSS was
9,588,112 KiB and the seal remained 281,128 bytes. The native lift took
21.836 seconds. A separate complete two-segment diagnostic join took 21.970
seconds and passed independent standard-host conversion, image/journal
verification and corrupted-seal rejection. These are selected-segment and
small-chain measurements, not a complete application receipt. See
[the application-segment evidence](optimized191-cpu-proving.json).

Extrapolating 208 equally expensive leaves and 207 measured joins gives about
17.81 serial hours. That assumption is unverified, and the estimate excludes
operational and full-application validation costs. Constraint evaluation,
transforms, witness generation, memory and full-application verification remain
obstacles; the next bounded experiment measures constraint evaluation.
