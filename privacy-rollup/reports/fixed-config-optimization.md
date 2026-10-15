# Hash-bound fixed JoinSplit configuration

Unpublished follow-up to structured reverse checkpoint `9773e0f`. The fixed
entry point still hashes every supplied VK byte against the pinned SHA-256
`bc1384089b1dc1654e61561089523ae521d2cf9b664589ec1e965108b4e2a183`.
It now loads the 5,959-byte compiled WHIR configuration instead of decoding the
expanded 3,213,548-byte VK. Every security parameter, domain separator input,
commitment offset, and R1CS hash is preserved. A differential test compares the
entire typed configuration and its exact postcard encoding with the original VK.
The generated plan now includes all 763 residual rows literally, alongside the
142 symbolically checked Poseidon2 blocks. Proof framing, transcript reads,
checks and client proving are unchanged. S-box columns remain independent.

## Execution evidence

Identical frozen inputs, 2^20 segment limit, four CPU quota, two runs each:

| Metric | Structured reverse checkpoint | Fixed configuration |
|---|---:|---:|
| Settlement user cycles | 523,884,055–080 | 443,708,894–923 |
| Settlement segments | 610 | 512 |
| Settlement execution seconds | median 21.6365 | 17.4724–18.7235 |
| Settlement peak RSS KiB | 128,568 | 106,444 |
| Diagnostic user cycles | 506,728,232–257 | 426,795,684–709 |
| Diagnostic segments | 594 | 496 |
| Diagnostic execution seconds | median 21.0133 | 17.2436–17.2617 |
| Diagnostic peak RSS KiB | 130,020 | 108,968 |

The settlement cycle reduction from the original instrumented PR10 baseline
(1,216,081,348 cycles, 1,278 segments) is about 63.5%. This is execution-only
and does not establish practical proving or aggregation. Runtime measurements
are two samples, not a statistical performance guarantee.

The full settlement journal remains 196 bytes with SHA-256
`4e366d165e21f04fcb31f5cd46b0abfecd9d6503f8d542c3f45399256890b43f`.
Client proof and VK sizes remain 635,142 and 3,213,548 bytes. The new settlement
image ID is `a8b1ee8d7c5416ddbeb211701ad7add76ef1f23fa0fa870a1d32d72c258d4d96`;
any eventual covenant/genesis deployment must intentionally bind that image.
No deployment occurred.

The diagnostic key phase fell from 82,427,724 to 3,627,695 cycles. The compiled
matrix phase is 70,308,588 cycles inclusive of the 21,425,235-cycle equality
table. Prefix MLE (95,760,329) and sparse NTT (128,089,503) remain targets.
Raw measurements, exact commands, hashes and rejection/operator results are in
`fixed-config-measurements.json`. Preserved binaries are under
`build/aggregation/fixed-config-baseline/`.

## Validation and reproduction

All 38 native workspace tests and nine guest rejection cases passed. A freshly
generated client proof passed operator admission and settlement execution,
including native journal equality, replay rejection, accept and rollback.
All 12 dependency files reproduce byte-for-byte after applying compatibility,
aggregation and the cumulative structured patch. No pins or package identities
changed. The structured patch includes the binary configuration.

```sh
source /workspace/.gsr-env/activate.sh
cargo +1.97 build --locked --release --manifest-path privacy-rollup/Cargo.toml --bin matrix-dump
privacy-rollup/target/release/matrix-dump build/aggregation/inputs/vk.pc \
  build/feasibility/matrices-fixed.json /workspace/provekit/provekit/verifier/src/joinsplit_whir.pc
python3 privacy-rollup/tools/structured_matrix_plan.py \
  build/feasibility/matrices-fixed.json build/feasibility/structured-fixed-plan.json \
  --rust-output /workspace/provekit/provekit/common/src/utils/structured_matrix_data.rs
cargo +1.97 test --locked --release --manifest-path privacy-rollup/Cargo.toml --workspace
```

Build/profile commands and baseline invocation are unchanged from
`structured-matrix-optimization.md`; use new evidence labels to preserve runs.
The compiled configuration SHA-256 is
`58b4885aea7ad25c1d031ecee50540886ca0911a0ab20fce46cc2380a04fe889`.
The complete symbolic plan SHA-256 is
`a5de69d0856b4405a322c37d40d2d68a47b0d2d74b7e296d55afb3b385a189dd`.

## Coverage and limits

The narrow Lean identities, exact coefficient reconstruction and differential
tests cover distinct claims; none proves the Rust verifier or protocol sound.
The upstream ignored FinalClaim results and unaudited padded RISC Zero hashing
remain unresolved caveats. See the earlier reports for their analysis.
The separate bounded proof harness now encodes a native-checked settlement
witness/journal for proving selected actual settlement segments. Partial segment
integrity is explicitly distinguished from a complete guest receipt.
