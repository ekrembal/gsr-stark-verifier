# Optional CPU constraint evaluation

The same complete diagnostic trace proves in 34.469 prover seconds with the
optional eight-cycle evaluator, compared with 66.193 seconds for the preceding
native batch-hash and periodic-quotient configuration. Constraint evaluation
falls from 44.849 to 13.761 seconds. The seal remains 255,656 bytes. This is one
paired workload with sequential measurements, not a statistical performance
guarantee or a complete JoinSplit proof.

The saved standard host independently verified and lifted this receipt in
43.228 seconds, then performed padded conversion in 20.405 seconds. Complete
diagnostic image/journal verification and corrupted-seal rejection passed.
The padded seal remains 222,668 bytes. The original unaudited padded-hash patch
and its returned verifier parameters remain in the trust boundary.

## Scope and implementation

This is optional host prover scheduling of the **existing constraint
polynomials**. It adds no AIR, guest precompile, constraint, field modulus,
proof parameter, verifier behavior, transcript operation or guest instruction.
Both application guest binaries remain byte-identical to the 191.12M-cycle
checkpoint. The ordinary build retains the scalar evaluator.

Apply `patches/risc0-cpu-poly-batch.patch` after the original RISC Zero patch
and the CPU profile, batch-hash and periodic-quotient patches. The complete
ordered stack reapplies byte-for-byte to all 26 affected files at the pinned
RISC Zero SHA. No manifest, lockfile or dependency revision changes here.

The build-time generator accepts only the exact SHA-256 digests of the four
original generated polynomial files and the original base/extension field
headers. A source-divergence rejection test passes. It propagates pointer roles
through the 21-function call chain, converting 3,526 raw input reads into eight
independent lane reads. Each lane retains the original masked index expression,
including wraparound. Scratch arrays become lane arrays, and uniform mix powers
are broadcast. The original extension formulas and scalar polynomial source
remain intact. Generated files stay in Cargo's output directory.

Unsigned GCC vector operations implement the scalar C++ word operations,
including wrapping addition/subtraction, the strict subtraction comparison,
and Montgomery reduction. The ABI copies each exact Montgomery word into its
original scalar representation; compile-time size, layout and trivially-copyable
checks protect this operation. GCC emits a class-memaccess warning because the
class has a nontrivial constructor; the type is nevertheless trivially copyable
and the explicit assertions pass. No field re-encoding is performed.

The Rust caller holds an exclusive output lock and distributes disjoint chunks
of all four extension components to Rayon. It checks FFI errors, retains the
original quotient expression unless the separate periodic option is enabled,
and retains scalar evaluation for domains not divisible by eight.

## Failures found and corrected

An initial standalone O3 compilation exceeded a self-imposed 600-second guard.
O2 with automatic loop/SLP vectorization disabled compiled the explicit SIMD
prototype in 47.410 seconds. This was a compiler-time guard, not a quota,
memory or disk failure. The integrated native host built in 191.487 seconds.

The first real-proof run aborted with stack overflow before producing a
receipt. The 21 generated functions have approximately 3,015,168 bytes of fixed
frame allocations in this compiler's disassembly, before other overhead. A
dedicated pool now uses eight-MiB stacks and the caller's configured Rayon
worker count. The scalar path uses its original pool. No process-wide stack
environment override is required. The corrected host rebuilt in 43.950 seconds
and the real proof and independent verification passed. Both failed runs and
their resource evidence are retained.

## Differential evidence and reproduction

The checked-in C++ test compares 32,768 arithmetic lanes, including arbitrary
32-bit words, modulus boundaries and INVALID, with the original C++ field.
It compares 1,176 full polynomial evaluations across seven domains, seven
unaligned/wrapping starts and zero/maximal/random input patterns. C ABI output
canaries and unchanged input/mix buffers are checked. Another 6,144 benchmark
points compare all four extension components. All passed. Isolated evaluator
speedups were 3.09–3.21x; real proving is measured separately above.

```sh
# From privacy-rollup/prover, with the standard workspace environment initialized:
export RAYON_NUM_THREADS=4 GSR_FUSED_DOT32=1 GSR_BUILD_CPU_BATCH=1
export RISC0_BUILD_LOCKED=1
export RUSTC_WRAPPER=/workspace/gsr-stark-verifier/privacy-rollup/tools/native_prover_rustc.py
export GSR_NATIVE_RUST_CRATES=risc0_zkp
# If changing compiler flags, clean only generated risc0-zkp artifacts first.
cargo build --locked --release

# From the repository root; SYS_OUT is the sys crate OUT_DIR in Cargo's build log.
python3 privacy-rollup/tools/check_cpu_poly.py --sdk /workspace/risc0 \
  --sys-out "$SYS_OUT" --out build/feasibility/new-poly-differential
export GSR_PROFILE_CPU=1 GSR_BATCH_CPU=1 GSR_PERIODIC_CPU=1 GSR_BATCH_EVAL_CPU=1
python3 privacy-rollup/tools/bounded_command.py \
  --output build/feasibility/new-poly-proof --seconds 300 --rss-mib 4096 \
  --free-mib 1024 -- build/feasibility/cpu-poly-host/proof_chain_bench \
  prove build/feasibility/dot32-cpu-poly 0
```

Use fresh directories/output prefixes to preserve earlier evidence. The build
requires native x86-64 GCC and Python 3; native binaries are machine-specific.
An ordinary build needs neither the generator nor vector compilation. Requesting
batched evaluation from that ordinary build fails explicitly.

[The measurement JSON](cpu-polynomial-measurements.json) records exact argv, environment, hashes,
resources, phases, failures and selected application-segment results. There is
no Lean proof of this C++ generator, vector/compiler semantics, FFI layout,
lane indexing, or complete polynomial equivalence. Narrow field-bound lemmas,
differential tests and independently checked small receipts are distinct forms
of evidence, not a protocol soundness proof.

The same saved normal-size application segment 100 proves in 140.443 seconds
(140.505 supervisor seconds), with 9,601,988 KiB peak RSS and the unchanged
281,128-byte seal. The saved standard host independently verified and lifted it
in 44.825 seconds. This is a partial application claim. Its phase profile is
56.572 seconds for constraint evaluation, 24.660 for expansion/NTT, 17.184 for
row hashing, and 10.562 for evaluation at arbitrary points. The full guest
still has 208 segments. A 10.65-hour serial projection combines that selected
leaf with earlier native lift/join timings; it is not a measured full receipt.

Ordinary CPU compilation was restored successfully in 144.120 seconds. The
portable build's unavailable-batch stub passed its explicit rejection check,
and the guest binaries remain byte-identical. The restoration script clears
the optional host compiler and batching flags, cleans only generated
`risc0-zkp` artifacts, and retains `GSR_FUSED_DOT32=1` for the measured guest.
Thus ordinary CPU compilation and the guest's optional field backend are
separate settings. The saved native host remains available for reproduction.

The final scalar-path regression proved the complete diagnostic in 102.596
seconds with 2,396,392 KiB peak RSS and the original 255,656-byte seal. The saved
standard host independently lifted it in 42.765 seconds and performed padded
conversion in 20.905 seconds. Complete image/journal binding and corrupted-seal
rejection passed, with a 222,668-byte padded seal. These checks validate the
restored ordinary path after the Rust output-borrowing refactor as well as the
optional path's earlier validation.
