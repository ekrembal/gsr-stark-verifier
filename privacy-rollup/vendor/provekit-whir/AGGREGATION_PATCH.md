# Local WHIR 0.2.0 algebra patch

This directory contains the published `provekit-whir` **0.2.0** source, with a
local optimization represented by [`whir-blinding.patch`](../../patches/whir-blinding.patch).
The original crate archive is pinned by SHA-256
`e79f9438fb42671b8437826b5d03233b0584154a300e648de38b0dae6725db6b`.
Its `.cargo_vcs_info.json` identifies upstream commit
`d986dee918dbec7e4e245dcd7b431450da1fc8da`.

The changes compute subgroup contributions to weighted geometric sums using
the existing forward NTT, retain the original loop for arbitrary points and
uneconomical configurations, derive the subgroup size from the existing
configuration, and make the NTT engine's maximum representable domain order
depend on `usize::BITS`. The latter preserves the 64-bit behavior and permits
compilation on the 32-bit guest. The BN254 root and all protocol/configuration
bytes are unchanged.

No verification check, transcript, hash, proof encoding or security parameter
is changed. This is a source patch and differential validation, not a formal
proof of the Rust implementation or an audit of WHIR protocol soundness.

The registry's cache bookkeeping and upstream standalone `Cargo.lock` are
excluded. The parent workspace and guest lockfiles select this same-version
local source through explicit `[patch.crates-io]` entries. Their source change
is documented in [the review report](../../reports/aggregation-optimizations.md).

The separate, unpublished sparse-prefix experiment additionally applies
[`whir-sparse-ntt.patch`](../../patches/whir-sparse-ntt.patch) after the first patch.
It substitutes a bounded sparse-input, prefix-output forward NTT in the zkVM
guest. Native/client builds retain the existing full NTT. The same subgroup
classification, exact discrete-log reconstruction, arbitrary-point fallback,
root convention and periodic extension remain in place. See the
[experiment report](../../reports/sparse-ntt-experiment.md) for differential
validation, guest measurements and the remaining formal coverage gap.
