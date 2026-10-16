# Host quotient evaluation and remaining bottleneck

A bounded optional host experiment proved the same complete diagnostic trace
in 66.193 seconds, compared with the earlier 67.966-second native batch-hash
run. These are single unpaired samples; they do not establish a reliable
additional speedup. Its new timer does establish that circuit constraint
evaluation consumed 44.849 seconds, about 68% of this run.

The pinned CPU prover computes the inverse of
`(3 * g^cycle)^(2^po2) - 1` independently for every cycle. Since `g` has order
`2^po2 * INV_RATE`, this expression has period `INV_RATE=4`. The optional
`GSR_PERIODIC_CPU=1` path evaluates the original expression at the four
residues and reuses those values. Its inverse semantics are unchanged. The
default path retains the original expression. The four FFI argument pointers
now use a fixed stack array in their original order, avoiding an allocation
per cycle. No constraint polynomial, AIR, transcript or verifier changed.

Apply `patches/risc0-cpu-periodic.patch` after the original SDK patch and the
two CPU profile/batch patches. It additionally emits `circuit_eval_check`
timing under `GSR_PROFILE_CPU=1`. This is another explicit local source patch
at the same RISC Zero revision; it changes no manifest, lockfile or revision.

The focused SDK test compares 2,580 direct evaluations at po2 values
5/10/15/18/20, consecutive cycles, domain edges and `u32::MAX`, and checks
nonzero denominators for those cases. It passed. The real diagnostic receipt
was independently verified and lifted by the saved standard host, then
converted and checked against its complete image/journal. Corrupted-seal
rejection passed. There is no formal Rust or universal quotient-equivalence
proof; the algebraic argument relies on the pinned field/root definitions.

Exact commands and resource evidence are in
[the measurement JSON](cpu-periodic-measurements.json). The focused test uses
`cargo +1.97 test --manifest-path /workspace/risc0/Cargo.toml --locked --release
-p risc0-circuit-rv32im --features prove --lib periodic_divisors_match_reference
-- --test-threads=1`, with the shared target directory and test-profile settings
documented in the CPU batching report. The 69 other RV32IM tests were filtered
out; this is not a claim that the full circuit test suite ran.

The remaining evaluator comprises 52,622 generated C++ lines. The subsequent
[optional CPU polynomial experiment](cpu-polynomial-batching.md) batches that
same scalar polynomial, with separate differential and real-proof validation.
No custom AIR or direct WHIR recursion is implemented.
