# Current unpublished aggregation checkpoint

The optimized optional guest executes the frozen real JoinSplit settlement in
191,119,146–171 cycles over 208 segments, versus the instrumented PR10 baseline
of 1,216,081,348–365 cycles over 1,278 segments. That is about 84.3% fewer cycles.
The 196-byte journal, 635,142-byte client proof and supplied 3,213,548-byte VK
remain unchanged. There is **no complete real JoinSplit receipt**.

Standard CPU compilation has been restored (144.12 seconds). Its final complete
small receipt passed independent image/journal and corrupted-seal checks. The
optional native executable is preserved separately for reproduction.

Actual proving of the same saved normal-size application segment now takes
140.443 seconds with the optional native CPU hash/polynomial paths, versus
411.343 seconds with the standard host. This is about 65.9% less proving time
for that selected segment. Its seal remains 281,128 bytes and peak RSS is
9,601,988 KiB. The saved pre-optimization host independently verified and lifted
the new receipt. Selected-segment integrity is not complete guest verification.

| Measured configuration | Settlement cycles | Segments | Same normal segment prover seconds |
|---|---:|---:|---:|
| Instrumented PR10 | 1,216,081,348–365 | 1,278 | Not this paired trace |
| Previous review checkpoint | 423,486,268 | 475 | Earlier-image evidence only |
| Lazy blinding, fused scalar/dot, iterative equality tables | 191,119,146–171 | 208 | 411.343 |
| Also optional native host hash batching | Identical guest | 208 | 264.455 |
| Also optional host polynomial batching/periodic quotient | Identical guest | 208 | 140.443 |
| Final guest source with original field backend | 237,933,282–307 | 255 | Not measured |

The uninstrumented background result, 1,215,383,914 cycles / 1,276 segments,
is distinct from the instrumented paired baseline above. Execution takes
6.053–6.059 seconds at at most 78,640 KiB process RSS for the 191.12M guest;
this is execution memory, not prover memory.

## Implementation and reproduction

Start from PR10 commit `86649820f8c68733617c84c4efeaae48e07e9268`. The workspace
initially started on a different main/work commit; the PR branch was fetched
and verified to match that baseline before changes. The current local branch
is `local/fused-bigint2-feasibility`. An earlier checkpoint `0d49071` was
separately approved and published as PR11; all subsequent work described here
remains unpublished. Nothing from this continuation was pushed, merged,
deployed or sent to external agents.

Row-major scatter already existed in PR10. Subsequent guest changes reuse
coefficients/configuration, apply exact sparse transforms and structured matrix
forms, use the official same-version SHA accelerator, hash-bind the fixed
configuration, evaluate matrix and blinding covectors lazily, and construct
truncated equality tables iteratively. The optional BN254 scalar and 32-term
kernels use the existing BigInt2 AIR, with explicit canonical remainder and
integer/carry checks. Native client proving retains its dense blinding path.
See [guest implementation and measurements](lazy-blinding-and-fused-kernels.md).

Host optimizations batch the same Poseidon2 computation and evaluate eight
copies of the existing constraint polynomial. Original field equations, AIR,
scalar verifier, transcript, hash constants and security parameters remain.
The compiler-specific host paths are opt-in, and their build/runtime flags,
source pins, exact commands, differential tests and real proof evidence are in
[the hash report](cpu-prover-batching.md) and
[the polynomial report](cpu-polynomial-batching.md). Their generated patch
stack reproduces all 26 affected SDK files exactly.

Privacy-rollup remains on Rust `1.97` (installed 1.97.1), recursive-stwo on
`nightly-2025-01-02`, RISC Zero on
`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`, ProveKit on
`4ee40639fb8849aeeba37761fdda07f28367e81d`, and Bitcoin on
`d2799052604eb138c5a79acf88514a0c8b07f4ef`. Original compatibility patches are
unchanged. Supplemental SDK and ProveKit patches are explicit source deviations.
No lockfile changed in this continuation. Earlier necessary sibling-path fixes
and same-version WHIR/SHA source overrides and lockfile effects are documented
in [the initial review](aggregation-optimizations.md); do not omit those when
reconstructing the environment. Resolve paths from the actual manifests.

## Validation and coverage

The guest checkpoint passed 43 native tests, nine rejection regressions, fresh
operator admission/journal/replay/rollback, independent field/dot vectors and
dispatch cases across alternate moduli and lengths. The original field backend
separately passed the nine rejections and 6,486 arithmetic vectors. Incorrect
kernel quotient witnesses fail real proving with `bad carry`; noncanonical
remainders fail in the guest. Small complete scalar and dot-kernel receipts
passed independent image/journal binding and corrupted-seal rejection.

CPU hashing passed all 35 pinned SDK library tests, including new differential,
tail/offset, dispatch, counter, noncanonical-input and existing Merkle rejection
tests. Quotient reuse passed 2,580 direct comparisons. CPU polynomial batching
passed 32,768 arithmetic lanes, 1,176 full polynomial points with C ABI canaries
and readonly-input checks, and 6,144 additional benchmark points. The saved
standard host independently verified its complete small receipt and rejected
a corrupted padded seal. These counts describe separate suites, not one
end-to-end formal verification.

Preserved failed experiments include compilation diagnostics, an O3 compiler
run stopped by a 600-second self-imposed guard, and the first packed evaluator
proof aborting on worker stack overflow. The corrected explicit stack pool
passed real proving and independent verification. No memory/quota failure or
security-parameter reduction was used to obtain the reported result.

Lean proves narrow algebraic factorization/equivalence and concrete carry or
intermediate bounds under stated assumptions. The reports identify standard
axioms and coverage gaps. There is no Rust/LLVM/C++ refinement proof, generated
bytecode/AIR audit, complete transcript proof, zero-knowledge proof or end-to-end
protocol soundness proof. In particular, differential CPU SIMD tests are not a
Lean proof of the generator or compiled lane semantics.

The original padded RISC Zero hashing patch remains unaudited. Native checks
using its returned parameters do not prove equivalence with the on-chain Script
covenant. Upstream ignored `FinalClaim` warnings remain visible; source
inspection found the fixed blinded RLC checked inline and the blinding final
claim explicitly verified. That inspection and the regression tests do not
establish general WHIR soundness.

## Remaining feasibility obstacles

Using 208 equally costly leaves, measured native lifts and 207 measured joins
projects about 10.65 serial hours on this four-CPU, 16-GiB host. This is an
unverified extrapolation, not a full-proof measurement or architectural lower
bound. Normal segments still consume about 9.16 GiB, so two do not fit
concurrently. The new normal-segment profile still spends 56.57 seconds in
constraint evaluation, 24.66 in expansion/NTT, 17.18 in row hashing, 10.56 in
evaluation at arbitrary points and 10.43 in zk shifting. Compatible CPU
optimization routes have not been exhausted.

Complete real application proving, recursive aggregation with full input and
196-byte journal binding, final proof/profile compatibility, actual Script
verification, transaction weight/data availability and regtest settlement for
this new relation remain unperformed. Earlier BWS regtest results do not cover
the new JoinSplit relation. Small receipts do not establish aggregation
feasibility. No roughly 100-hour full proof was launched.

Proof-format and WHIR-parameter tradeoffs are evaluated in the earlier reports;
no encoding, query count, grinding or security parameter was weakened. GPU and
multi-machine measurements require other resources. Custom AIR, precompiles,
direct WHIR recursion and covenant redesign remain proposals requiring separate
approval; see [the next-stage proposal](aggregation-next-stage-proposal.md).
