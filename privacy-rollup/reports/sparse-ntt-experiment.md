# Sparse-prefix NTT experiment — 2026-10-02

The validated sparse-prefix NTT pass reduces fixed-input settlement execution from the
previous pass's **971,363,493–971,363,543 cycles / 1,067 segments** to
**852,104,533–852,104,558 cycles / 948 segments**. This is **12.28% fewer cycles**
and 119 fewer segments than the first version of [draft PR #11](https://github.com/ekrembal/gsr-stark-verifier/pull/11),
or **29.93% fewer cycles** than the original instrumented PR #10 baseline.
The same 196-byte settlement journal is produced. The 500M-cycle goal remains unmet.

This is an execution optimization. No real JoinSplit RISC Zero receipt was
generated, and these measurements do not establish aggregation proving feasibility.

## Scope and source

- Baseline commit: `cdf514f0bb1e2ac8ca5038858b9d71affb09be97`, the first PR #11 pass.
- Validated implementation commit: `03ccc827f191d8536e99ebd7d07ea1b5905d993d`.
- Published in the existing draft PR #11 on `codex/proof-aggregation-optimizations`
  after explicit approval. The original private review archive remains a historical
  snapshot from before publication.
- Incremental source patch: [`whir-sparse-ntt.patch`](../patches/whir-sparse-ntt.patch),
  applied after `whir-blinding.patch` inside `vendor/provekit-whir`.
- Implementation: [`sparse_prefix.rs`](../vendor/provekit-whir/src/algebra/ntt/sparse_prefix.rs).
- Tests: [`sparse_ntt.rs`](../crates/provekit-adapter/tests/sparse_ntt.rs).
- Full samples, phase profiles, hashes, commands and validation evidence:
  [`sparse-ntt-measurements.json`](sparse-ntt-measurements.json).

There are no manifest, lockfile, dependency-version or security-parameter changes
relative to the parent. The previously verified Rust, RISC Zero, ProveKit, WHIR
and Bitcoin pins and patches remain as documented in the
[first-pass report](aggregation-optimizations.md). No custom AIR, precompile or
direct WHIR recursion integration is introduced.

## Implementation and equivalence argument

The published pass maps subgroup points to sparse coefficients and computes a
complete forward NTT. In the guest, this experiment computes only the requested
output prefix and skips butterflies whose right input is known to be zero.
Native/client builds retain the existing full NTT implementation. Subgroup
membership checks, release-mode discrete-log reconstruction, the cost gates,
arbitrary-point fallback and periodic extension remain unchanged.

For input terms `(i, a)`, duplicate indices add into a coefficient vector `c`.
The required output is `sum_i c[i] * omega^(i*k)` for each requested `k`, using
the same generator and forward convention, with no normalization. Terms are
placed in bit-reversed order before radix-two butterfly stages.

The stage invariant is that every block's first `min(output_len, width)` entries
match the complete transform for that stage. The next stage reads only valid
prefixes from its two half-blocks. Upper outputs are written only when they
belong to the requested prefix. A false activity flag implies an exact zero;
true flags may remain set after cancellation, which costs work without changing
the result. The domain is bounded at 32,768 entries, and indices and prefix
lengths are checked. This is an informal mathematical argument supported by
tests, **not a machine-checked proof of the algorithm or its Rust implementation**.

The change does not alter proof parsing, public-input or key binding, transcript
operations, hash functions, verification equations, proof representation, WHIR
configuration or security parameters.

## Paired guest measurements

Two samples per variant and entry point were executed sequentially, alternating
the saved published-pass binary and the candidate. No builds or other validation
jobs ran concurrently with these measurements. The saved baseline was not rebuilt.

| Measurement | Published pass | Sparse-prefix experiment | Reduction |
| --- | ---: | ---: | ---: |
| Verifier cycles | 950,071,895–950,071,970 | 827,292,477 | 12.92% |
| Verifier segments | 1,045 | 923 | 122 segments |
| Verifier median execution time | 29.235 s | 27.778 s | 4.98% |
| Verifier maximum measured host RSS | 144,760 KiB | 126,984 KiB | 12.28% |
| Settlement cycles | 971,363,493–971,363,543 | 852,104,533–852,104,558 | 12.28% |
| Settlement segments | 1,067 | 948 | 119 segments |
| Settlement median execution time | 29.743 s | 28.323 s | 4.77% |
| Settlement maximum measured host RSS | 147,744 KiB | 142,952 KiB | 3.24% |

The verifier's `build_beq_tables` phase falls from **277,542,750** to
**156,659,030 cycles** (43.55%). The new sparse-prefix kernel takes
128,089,503 cycles over four calls. Its surrounding subgroup helper takes
152,360,297 cycles, including the kernel. Inclusive spans overlap and must not
be added. Unchanged matrix code also changes by about 1.82M cycles between
linked guest programs; the total improvement should not all be attributed to
the transform itself.

Read, key-deserialization and proof-deserialization phases stay at 353,884,
78,805,615 and 6,994,049 cycles respectively. Prefix-MLE evaluation remains
95,760,329 cycles. The exact profiles are preserved in the measurement JSON.

The machine exposes an AMD EPYC 9V74 CPU, a four-CPU cgroup quota, a 16 GiB RAM
limit and no GPU. RSS is measured by GNU `time` for the **host executor**, not
the guest heap or a prover. Two samples are a small diagnostic, not a statistical
throughput study. Reduced execution cycles do not imply an equal reduction in
proving time or memory.

### Frozen frames and outputs

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| `vk.pc` | 3,213,548 | `bc1384089b1dc1654e61561089523ae521d2cf9b664589ec1e965108b4e2a183` |
| `proof0.pc` | 635,142 | `e3ed84cde408df6b83ace47e77358dd3eb6cf34d092d01a9f256702cb7f256fa` |
| `witness.json` | 29,326 | `0beabb1cb720abaf578400dc3f8116ec2838e8589fc1087f7b157d208d34a0f8` |

All paired settlement journals have SHA-256
`4e366d165e21f04fcb31f5cd46b0abfecd9d6503f8d542c3f45399256890b43f`.
The candidate settlement image ID is
`7a8d444de0f050178bc523a85ba54cdd26a1e101bd5d9893b13f7691c5aeaa93`.
This is a new image; execution validation does not authorize a deployment or
establish covenant compatibility for an actual receipt.
The covenant binds the guest image, and `RollupDescriptor` includes that image
in the rollup identity. Adoption therefore requires a new genesis or an explicitly
supported migration; an existing deployment cannot simply substitute this guest.
Neither genesis deployment nor migration is implemented or validated here.

The fixed ProveKit proof is unchanged at 635,142 bytes. Candidate combined guest
programs are 2,391,992 bytes for verification and 2,459,264 bytes for settlement.
Program sizes are not receipt sizes. No recursive receipt size was measured.

## Validation

- **33 native workspace tests passed**, including five new sparse-prefix tests.
  The new tests make 7,716 successful prefix comparisons and check five invalid
  bound cases. They cover BN254 and Field64, every prefix for power-of-two domains
  through 128, all support masks through domain size eight, duplicate/canceling
  terms, zero and dense inputs, deterministic varied coefficients, and the
  1,024/2,048/16,384/32,768 domain sizes at prefix boundaries. Small-domain
  references are checked against direct polynomial evaluation as well as the
  existing NTT. Exhaustive support masks do not mean exhaustive field inputs.
- Existing native tests still accept a fresh real client proof and reject all
  11 mutations through both verifier APIs, checking valid reuse after failures.
- Both saved baseline and candidate pass the fixed valid proof in verifier and
  settlement execution, twice each; their verifier and settlement journals match.
- **Nine guest rejections passed on each version**: changed public input, first
  argument byte, middle hint byte, and extra argument byte through both entry
  points, plus a changed key frame through settlement. Each produced a guest
  panic; no acceptance or unrelated host failure was counted as a rejection.
- A fresh client proof also passes the operator/settlement flow, with matching
  guest/native journal, admission/replay checks, and accept/rollback checks.
  This uses the repository's fixture descriptor, not a deployed covenant or
  real recursive receipt.
- The incremental source patch reapplies exactly to the parent and reproduces all
  three modified/new WHIR source files. Focused Rust formatting and `git diff
  --check` pass. The guest locked release build passed in 39.98 seconds at the
  preserved checkpoint; guest sources have not changed since that build.

There are no remaining failed checks in this validation set. Existing upstream
`FinalClaim` warnings remain visible. This experiment does not add or rerun
the unrelated Lean identities, padded-hash or Recursive Stwo suites; their prior
results and limitations are recorded in the first-pass report.

## Reproduction

Use the same environment and source pins as the first-pass report. The saved
baseline binaries are in `build/aggregation/sparse-baseline`; retain them before
changing the guest. The exact fixed frames are in `build/aggregation/inputs` and
the private review archive. A newly generated proof must be frozen and used for
both variants; it cannot be compared with these cycle denominators.

```sh
source /workspace/.gsr-env/activate.sh
cd /workspace/gsr-stark-verifier
export PATH="/workspace/.gsr-env/shims:/workspace/.gsr-env/sysroot/usr/bin:$PATH"
export RISC0_HOME=/workspace/.gsr-env/risc0-home
export RISC0_BUILD_LOCKED=1
export RECURSION_SRC_PATH=/workspace/.gsr-env/recursion_zkr.zip
RAYON_NUM_THREADS=4 cargo +1.97 test --locked --release --manifest-path privacy-rollup/Cargo.toml --workspace
(cd privacy-rollup/prover && cargo build --locked --release)

guest_dir=privacy-rollup/prover/target/riscv-guest/pr-methods/pr-guest/riscv32im-risc0-zkvm-elf/release
for sample in 0 1; do
  python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
    --label "sparse-base-$sample" --kind verify --runs 1 \
    --binary build/aggregation/sparse-baseline/exec_joinsplit \
    --program build/aggregation/sparse-baseline/verify_joinsplit.bin
  python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
    --label "sparse-prefix-$sample" --kind verify --runs 1 \
    --program "$guest_dir/verify_joinsplit.bin"
  python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
    --label "sparse-base-$sample" --kind batch --runs 1 \
    --binary build/aggregation/sparse-baseline/settle
  python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
    --label "sparse-prefix-$sample" --kind batch --runs 1
done

python3 privacy-rollup/tools/reject_aggregation.py build/aggregation/inputs build/aggregation/cases \
  --verify build/aggregation/sparse-baseline/exec_joinsplit \
  --program build/aggregation/sparse-baseline/verify_joinsplit.bin \
  --settle build/aggregation/sparse-baseline/settle \
  --out build/aggregation/rejections-sparse-baseline
python3 privacy-rollup/tools/reject_aggregation.py build/aggregation/inputs build/aggregation/cases \
  --verify privacy-rollup/prover/target/release/exec_joinsplit \
  --settle privacy-rollup/prover/target/release/settle \
  --out build/aggregation/rejections-sparse-prefix
RAYON_NUM_THREADS=4 python3 privacy-rollup/tools/operator_joinsplit.py
```

The local archive retains the comparison script, raw logs and JSON, source patch,
fixed inputs and both versions' combined guest programs. Generated proof/program
artifacts are excluded from Git. The existing profile and rejection tools are
unchanged.

## Remaining limits

This candidate has no formal NTT/Rust equivalence proof and no protocol soundness
proof. The narrow Lean identities from the earlier pass do not cover the new
transform. The existing unaudited padded RISC Zero hashing and ignored upstream
`FinalClaim` results retain the correctness/security caveats documented in the
first-pass report; passing these tests does not resolve them.

No real JoinSplit RISC Zero proof, proof-generation throughput, prover memory,
real-receipt Script differential, or settlement validation of a real receipt for
the new image was produced. Multi-proof aggregation was not profiled. The tested
client proof format and protocol parameters are unchanged. No new paired
client-proving measurement was performed; native/client builds retain the same
NTT algorithm. Broader
architecture and proving-feasibility research is outside this experiment.

### Next bounded experiment: existing SHA-256 acceleration

Local source and the guest lockfile confirm that WHIR's `DigestEngine<sha2::Sha256>`
and the ProveKit `TranscriptSponge` / Spongefish `SHA256` resolve to registry
`sha2` 0.10.9. That crate's SHA-256 dispatch selects the software backend on
`riscv32`; the `sha2-asm` lockfile entry does not provide a RISC Zero backend.
The settlement key hash explicitly uses `risc0_zkvm::sha::Impl`. It would be
incorrect to infer from that call that WHIR and transcript SHA-256 are already
accelerated. BN254 multiplication already uses two checked `modmul_256` calls
in the existing vendored field backend.

The official same-version fork exists at tag `sha2-v0.10.9-risczero.0`, resolved
here to commit `8631fabdea7bdffa97b11868e04e73491d8e5bcf`. Its
[dispatch](https://github.com/risc0/RustCrypto-hashes/blob/8631fabdea7bdffa97b11868e04e73491d8e5bcf/sha2/src/sha256.rs)
selects a RISC Zero backend for `target_os = "zkvm"` and `target_arch = "riscv32"`
unless a force-software feature is enabled. Its
[backend](https://github.com/risc0/RustCrypto-hashes/blob/8631fabdea7bdffa97b11868e04e73491d8e5bcf/sha2/src/sha256/risc0.rs)
calls `sys_sha_buffer`, which is present in the pinned RISC Zero v3.0.6 source.
It handles state endianness and copies unaligned blocks.

Applying this existing accelerator is a sensible next, comparatively low-risk
**separate experiment**: it targets measured hash work while retaining SHA-256
and transcript semantics. It still needs source/lockfile pin review, ABI and
feature-dispatch verification on v3.0.6, native/guest digest comparisons for
padding boundaries, streaming and unaligned inputs, the same proof/rejection
regressions, and paired execution measurements. The full Merkle phase includes
non-hash work, so its cycle count is not an achievable-savings estimate. No fork
was applied, built or benchmarked in this NTT experiment. A fused BigInt2 design
remains a separate proposal requiring approval.
