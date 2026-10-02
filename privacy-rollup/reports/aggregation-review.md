# Unpublished aggregation optimization review

The original PR10 baseline is commit
`86649820f8c68733617c84c4efeaae48e07e9268`. All current work remains on the local
branch `local/fused-bigint2-feasibility`, descended from that baseline. The
previously approved PR11 checkpoint is `0d49071`; later SHA, structured-matrix,
fixed-configuration and lazy-covector work has not been pushed, submitted as a
new PR, merged or deployed. Existing baseline artifacts and pinned checkouts
were preserved.

## Outcome

The fixed frozen JoinSplit settlement went from approximately 1.216 billion
instrumented guest cycles / 1,278 segments to approximately 423.49 million /
475 segments: about 65.2% fewer cycles. The 196-byte journal remains identical.
The 635,142-byte client proof and 3,213,548-byte supplied VK remain unchanged.
These improvements do **not** establish practical full aggregation. The final
settlement image is `cb7562cfb2f17108502ebab6af755747ca88c16ee5ddd7429537b720ac8b319b`.

| Checkpoint | Settlement cycles | Segments at 2^20 |
|---|---:|---:|
| Instrumented PR10 baseline | 1,216,081,348–365 | 1,278 |
| First coefficient/configuration + WHIR pass | 971,363,518–543 | 1,067 |
| Sparse NTT | 852,104,533–558 | 948 |
| Official guest SHA-256 accelerator | 746,732,029–054 | 842 |
| Exact structured reverse matrices | 523,884,055–080 | 610 |
| Compiled hash-bound key/configuration | 443,708,894–923 | 512 |
| Lazy covector checkpoint `76ae74a` | 423,237,844–869 | 475 |
| Final linear-form contract coverage | 423,486,268 | 475 |

The original uninstrumented background result was 1,215,383,914 cycles / 1,276
segments; it should not be substituted for the instrumented paired baseline.
Precise runtime, memory, phase, image and command evidence is linked below.

Row-major scatter was already present in PR10. The work adds coefficient reuse,
configuration borrowing, exact subgroup/sparse-NTT reductions, the official
same-version SHA accelerator, and fixed-key matrix/configuration specialization.
The fixed matrix implementation reconstructs all 114,168 selected matrix rows
symbolically and keeps independent S-box witness columns. Lazy covectors share
column equality tables across A/B/C while preserving separate commitment points
and the second commitment's `column - 5530` indexing.

## Evidence and reproduction

- [Initial paired baseline and optimizations](aggregation-optimizations.md):
  exact original pin/path setup, row-major finding, phase profiles, client
  measurements, proof-representation and WHIR-parameter tradeoffs, and original
  recursive-stwo verification commands/results.
- [Sparse NTT](sparse-ntt-experiment.md) and [official SHA accelerator](sha256-accelerator-experiment.md):
  isolated comparisons, differential tests, and same-version source deviations.
- [Structured reverse matrix](structured-matrix-optimization.md),
  [fixed key/configuration](fixed-config-optimization.md), and
  [lazy covectors](lazy-covector-optimization.md): implementation, full commands,
  frozen input hashes, native/guest rejection results, fresh operator workflows,
  and narrow Lean coverage. Their adjacent measurement JSON files are the
  machine-readable evidence.
- [Bounded real proving and recursion](fused-bigint2-feasibility.md),
  [normal-size segment proving](normal-segment-proving.md), and
  [receipt/checkpoint manifest](bounded-proof-checkpoints.json): distinguish
  actual proofs from execution and partial claims from complete guest receipts.

The final cumulative ProveKit dependency patch is
`../patches/provekit-structured.patch`, applied after the pinned compatibility
and aggregation patches using `git apply --unidiff-zero`. Reapplication matches
all 12 affected dependency files byte-for-byte. Source, tests and lockfiles are
in the local commits; reproducibility inputs, binaries and raw logs are retained
under `build/aggregation/` and `build/feasibility/`.

Final validation passed: 40 native workspace tests, two diagnostic and two
settlement acceptance runs, all nine guest rejection cases, fresh operator
admission/journal/replay/rollback, narrow Lean checks, and byte-for-byte patch
reapplication. The final test suites have no failures. Full JoinSplit proving
and Script settlement remain unperformed; the supplied Library archive remains
unread because materialization tools were unavailable.

## Real proving and resource limit

Two bounded normal-size segment proofs passed integrity checks, each producing
a 281,128-byte seal in about 416–418 seconds at roughly 9.15 GiB RSS. The local
environment has four CPUs of quota and a 16 GiB memory limit. A normal-size partial receipt also passed lifting
and integrity verification in 44.05 seconds, producing a 222,668-byte seal. The 475-segment
lazy checkpoint represents 474.5 full-size segments; a one-sample linear
extrapolation is about 55 hours for segment proving alone, before lifts/joins.
No long full JoinSplit proof was launched and no paid or external proving
service was used. Two concurrent normal-size provers would exceed this memory
budget at the observed peaks, while one already uses nearly all four CPU cores.
The two normal-size receipts belong to fixed-config and `76ae74a` images; the
final longer-point image has execution/rejection validation, not a new receipt.

A real two-segment proof/lift/join/padded chain at 2^18 passed in about 352
seconds; it proves only the selected range of a JoinSplit verifier execution.
A complete small arithmetic guest went through proof/lift/join/padded conversion
and image/journal verification in about 219 seconds. Both padded seals rejected
a deliberate local corruption. Neither constitutes a complete JoinSplit receipt.

## Correctness, formal coverage and open work

All verification equations, input/key binding, EOF checks, transcript/hash bytes,
security parameters and client proof format are preserved. The configuration's
entire typed value and exact encoded bytes are compared to the pinned VK.
Native differential tests, guest rejection tests and fresh operator checks are
concrete evidence, not a proof of universal equivalence or protocol soundness.

Lean proves small-coefficient identities/cache substitutions, the four forward
and four transpose linear-map identities, a row reassociation lemma under
explicit laws, and narrow Montgomery/no-wrap statements for an unintegrated
candidate. It does not prove Rust refinement, the full matrix traversal, NTT,
parsing, transcript implementation, field backend, zero knowledge or end-to-end
soundness. ArkLib's relevant Sumcheck/STIR specifications were inspected; no
verified bridge to this Rust implementation was established.

The existing padded RISC Zero hashing patch is unaudited. Native padded checks
use its returned verifier parameters; they do not establish equivalence to the
final Script covenant. Upstream ignored FinalClaim warnings remain visible.
The pinned blinded WHIR verifier performs its linear-form RLC check internally,
so the warning alone does not prove an omitted check; this source inspection is
not a soundness proof and must be revisited on dependency upgrades.

The supplied independent Library research archive could not be materialized
with the available read tools. The fixed-key reconstruction was independently
implemented from the pinned compiler/VK and tested; no comparison against the
unread prototype is claimed.

Remaining requirements are a complete real JoinSplit receipt; complete recursive
aggregation and padded wrapping; independent native and Script verification of
that exact receipt; intentional covenant/genesis image binding; isolated regtest
settlement and multi-transaction/resource measurements. Normal-size proving
cost is a material cloud resource obstacle. Further arithmetic/prover tuning
may help but has not demonstrated the order-of-magnitude reduction needed for
short full-proving experiments. The fused BigInt2 candidate remains unintegrated
and unbenchmarked as a replacement. Material AIR/covenant redesign and direct
WHIR recursion remain proposals requiring separate approval.
