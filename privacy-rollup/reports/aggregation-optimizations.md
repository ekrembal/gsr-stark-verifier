# Proof-aggregation optimization review

Implemented locally from PR #10's approved commit `86649820f8c68733617c84c4efeaae48e07e9268`.
The fixed real JoinSplit batch now executes in approximately **971M cycles / 1,067 segments**, versus
**1.216B / 1,278** in the instrumented baseline: **20.12% fewer cycles and 211 fewer segments**.
The initial coefficient-cache/configuration-reuse implementation reached 1.172B / 1,231; the additional
WHIR blinding-table optimization saves a further 201M settlement cycles.
Its journal matches the baseline and native state transition byte for byte. This is execution evidence;
no real JoinSplit RISC Zero receipt was produced. The experimental 500M-cycle goal remains unmet.

## Baseline, pins and environment

The workspace started clean on `work` at `e555d6c`, rather than the PR branch. Fetching
`devin/1790871096-privacy-rollup` confirmed that its head exactly matched the approved commit.
The implementation was developed and validated on local branch `local/proof-aggregation-optimizations`.
The user separately approved publishing the validated pass as a draft PR stacked on PR #10's branch.
Generated proof and program binaries remain local and in the private review archive; they are excluded
from the published changes. No existing user work was overwritten. No subagents, remote agents or paid
proving services were used. No merge, deployment or Bitcoin broadcast was performed.

| Component | Verified pin |
|---|---|
| Privacy rollup host | `rust-toolchain.toml`: `1.97`; resolves to installed Rust 1.97.1 |
| RISC Zero guest compiler | official RISC Zero Rust `r0.1.97.0` |
| Recursive Stwo | `nightly-2025-01-02`, unchanged |
| RISC Zero | `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9` (v3.0.6), original `risc0-succinct/risc0-v3.0.6.patch` |
| ProveKit | `4ee40639fb8849aeeba37761fdda07f28367e81d`, original `provekit-4ee40639.patch`, then new `provekit-aggregation.patch` |
| WHIR | same `provekit-whir` 0.2.0, vendored published source at `d986dee918dbec7e4e245dcd7b431450da1fc8da` plus `whir-blinding.patch` |
| Bitcoin submodule | `d2799052604eb138c5a79acf88514a0c8b07f4ef`, unchanged |

Fixture keys, toolchain files, original dependency patches, dependency versions and security parameters
are unchanged. The ProveKit patch is incremental and applies after the original patch; it fully
represents the sibling-checkout changes. Patch reapplication was checked with a temporary Git index.

The WHIR optimization requires an explicit local source patch. Its published 0.2.0 archive was verified
against the original lockfile checksum
`e79f9438fb42671b8437826b5d03233b0584154a300e648de38b0dae6725db6b`, and every original archive file
was compared before vendoring. This is a necessary, limited lockfile deviation: the workspace and guest
WHIR entries lose their registry source/checksum lines to select the local same-version source; the
adapter gains two already-resolved test dependencies. No package is upgraded or added to the resolved
graph. The prover and Recursive Stwo lockfiles remain unchanged. Original and current lock hashes are
recorded in the measurement JSON, and the minimal WHIR changes are in `patches/whir-blinding.patch`.

The PR Cargo paths climbed one directory too far, resolving `/provekit` and `/risc0`. Five manifests
now resolve the actual sibling checkouts `/workspace/provekit` and `/workspace/risc0` from
`/workspace/gsr-stark-verifier`. This necessary environment repair changes paths, not dependency versions.
The README now describes paths relative to the repository root correctly.

Measurements used Linux x86-64, a 4-CPU cgroup quota (`cpu.max = 400000 100000`), 16 GiB memory limit,
and up to four Cargo jobs. OS affinity reports five CPUs; this is not the available CPU quota.
GNU time reports **peak host process RSS**, not peak guest RAM or prover memory.

The guest SDK initially hit a read-only default Cargo home; the local Cargo wrapper restores the
workspace Cargo home because RISC Zero's builder removes `CARGO_*` variables. The recursion build's
S3 archive was blocked by the network proxy. The official v3.0.6 `r0vm` release contains an embedded
copy: extraction recovered the **exact original build.rs SHA-256**
`744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849`.
No hash check was bypassed and no replacement recursion circuit was used.

## Implementation and preserved behavior

**Row-major scatter already existed in PR #10.** Its `±1` shortcuts and transpose-free guest path
are baseline behavior. The new implementation caches `coefficient × eq(alpha, row)` for each
coefficient index in the current row, sharing products across A, B and C. A row tag prevents reuse
in a different row. It handles zero and `±2`, `±3` with exact field additions/negation, and keeps
general coefficients on the existing field multiplication path. Each output column receives its
contributions in the same row and entry order. The cache stores tags and products together and adds
borrowed products to avoid an extra field-element copy.

The fixed key has 921,139 terms beyond the baseline `±1` shortcuts but 614,423 distinct
`(row, coefficient index)` products. This suggests arithmetic reuse; it does not predict cycle savings
by itself because lookups, branching, field additions and cache storage also cost cycles.

`Verifier::verify_ref` borrows the immutable WHIR configuration. `apply_batch` and native admission
use it instead of cloning the complete verifier for each proof. The original consuming `verify`
method keeps its consumption and error behavior. Both call the same WHIR verifier, which creates
a fresh domain separator and transcript state on every invocation. Tests also verify a valid proof
after every failed borrowed verification to check reuse after errors.

The additional blinding-table optimization targets `m_inner[k] = sum_j scalar[j] * base[j]^k`.
For a power-of-two domain of order N, subgroup points have `base[j] = omega^index[j]`. Accumulate
`scalar[j]` at that sparse coefficient index, then the existing **forward** NTT gives those same
power sums. No inverse transform or normalization is used. Duplicate points add at the same index;
periodic extension handles outputs longer than N. The existing scalars, including tau powers and
free-bit products, are unchanged. Arbitrary OOD points retain the original geometric loop.

The domain bound comes from the existing initial and first-following codeword lengths; power-of-two
domains are nested. Raising bases along the existing squaring ladder reduces that bound. Every point
is classified by an exact `base^N == 1` test, and each discrete-log index is reconstructed and checked
in release builds. Unsupported domains, lengths that differ, small workloads and insufficient subgroup
points fall back to the original routine. Scratch allocation is capped at N = 32,768. This is an
algorithmic optimization, with no custom AIR, precompile or direct recursion integration.

Instantiating the upstream NTT on riscv32 exposed its hard-coded `1 << 63`. Its representable maximum
is now `usize::BITS - 1`: native 64-bit behavior is identical, and the guest can compile it. The BN254
root has order 2^28 and is unchanged. The original NTT algorithm itself was retained.

The settlement guest still hashes the entire key frame against the pinned SHA-256, compares every
proof's public-input vector with the transaction statement, performs all upstream verification checks,
applies the same state transition, and commits the same 196-byte journal. Circuit, proof encoding,
transcript bytes, challenge ordering, hash identities, query counts and WHIR configuration are unchanged.
The profiled `verify_joinsplit` guest remains a diagnostic accepting a supplied key; settlement key
and statement binding are checked by `apply_batch`.

Profiling now distinguishes span module names, aggregates call counts and reports inclusive and
exclusive cycles with nesting checks. Metadata is interned rather than growing a name vector for
every invocation. It also separates frame reading, key parsing and proof parsing. The host CLI can
execute a saved combined RISC Zero program and emits structured measurements. RISC Zero v3 requires
the combined **`.bin`** program; passing the raw user ELF fails with `Malformed ProgramBinary`.

Guest IDs changed, as expected for a new build. The baseline settlement image was
`e1e2e8a0e10c8b32bee990badc7bbd8e339f14f365eb15d543f9d7b4cf1294d9`; the optimized image is
`4eeebe2102c05669c9fc17c68ab9040d7acbc9bc40d955df325ff99fbd860ee6`.
The first-review optimized image was `4fe8fe7553c3cd2903b868020865561545244d8f2d853cebf97257595489d9b7`.
Any future settlement experiment must generate its receipt and covenant for the new image.
Existing empty-batch receipt fixtures were preserved and are not evidence for this new image.

## Measurements

Both builds used the same frozen proof, key and witness. Two runs per entry were executed sequentially,
without competing compilation. The baseline includes the path repair, profiler and host measurement
support; it calls the original consuming verifier and original scatter. Optional baseline-only patches
capture that source. Small cycle variations are retained in the raw measurements rather than hidden.

| Execution | Original baseline | First review | With WHIR optimization |
|---|---:|---:|---:|
| Profiled verifier cycles | 1,185,019,562–1,185,019,587 | 1,148,926,951 | 950,071,895 |
| Profiled verifier segments | 1,238 | 1,208 | 1,045 |
| Profiled verifier median runtime | 34.722 s | 33.571 s | 29.561 s |
| Profiled verifier max host RSS | 126,488 KiB | 126,992 KiB | 144,756 KiB |
| Settlement cycles | 1,216,081,348–1,216,081,365 | 1,172,496,470–1,172,496,499 | 971,363,518–971,363,543 |
| Settlement segments | 1,278 | 1,231 | 1,067 |
| Settlement median runtime | 35.737 s | 33.311 s | 30.232 s |
| Settlement max host RSS | 143,160 KiB | 125,636 KiB | 148,000 KiB |

The final verifier saves 19.83% of original cycles; settlement saves 20.12%. Settlement runtime is
15.41% lower in these samples, while peak host RSS is 3.38% above the original baseline and 17.80%
above the first review. The NTT's temporary vectors, cached roots and execution trace behavior cost
memory; the cycle gain does not imply a prover-memory gain. Two isolated sequential samples were
used for the final comparison. Earlier candidate runs overlapped compilation and are excluded from
runtime claims.

Runtime is a small-sample diagnostic, not a statistically established speedup. Cycle and segment
reductions are the stronger evidence. The original PR's 1,215,383,914-cycle / 1,276-segment measurement
used a separately randomized proof and build; it is historical context, not the denominator above.

| Profiled phase | Original baseline | First review | With WHIR optimization |
|---|---:|---:|---:|
| Input frame read | 353,884 | 353,884 | 353,884 |
| Key deserialization | 78,802,968 | 78,805,615 | 78,805,615 |
| Proof deserialization | 6,994,049 | 6,994,049 | 6,994,049 |
| Complete verification | 1,097,606,429 | 1,061,510,302 | 862,653,309 |
| Sparse external row, inclusive | 331,130,164 | 295,035,330 | 296,858,668 |
| Equality table, child of sparse external row | 21,425,233 | 21,425,235 | 21,425,235 |
| WHIR blinding tables, two calls | 478,428,717 | 478,428,717 | 277,542,750 |
| Subgroup geometric sums, child of blinding tables | original loop | original loop | 273,247,375 |
| Merkle verification, twenty calls | 118,352,785 | 118,352,785 | 118,352,785 |
| Prefix multilinear evaluations, seven calls | 95,760,329 | 95,760,329 | 95,760,329 |

Nested inclusive spans overlap and must not be summed. Blinding-table construction saves 200.886M
cycles (41.99%); its remaining 273.247M-cycle geometric-sum child is primarily the dense NTT path and
associated classification/indexing. The sparse external row is now the largest profiled phase.

The guest's existing field checks passed 200 accelerated multiplication/squaring comparisons against
software CIOS. Its microbenchmark measured 179 cycles per BN254 multiplication, 94 per addition and
100 per raw `bigint2::modmul_256`; these measure different call paths and are not interchangeable costs.
The BN254 accelerator was already present in the PR and was not modified here.

Native matrix diagnostics (five samples, four Rayon threads) had median scatter runtime 28.228 ms
baseline and 26.292 ms optimized. The native production verifier retains its parallel transpose path.
A separate warm native diagnostic from the **first review**, before the WHIR patch, compared cloning
plus consuming verification with borrowed verification of the fixed proof: median 90.754 ms versus 77.519 ms. This diagnostic ran alongside
rejection validation and is not an isolated native throughput benchmark. Initial cold client proof generation took 3.652 s under a different workload. A new paired diagnostic
uses the saved original and final client executables, two sequential samples each, with four Rayon
threads. The WHIR utility is shared by prover and verifier; its client consequence is measured below.

Client ProveKit proof generation (two warm sequential samples per build, `RAYON_NUM_THREADS=4`):

| Diagnostic | Original client | Final client |
|---|---:|---:|
| Proof-generation phase | 0.548 / 0.586 s | 0.507 / 0.486 s |
| Median phase time | 0.567 s | 0.497 s |
| Maximum host RSS, whole process | 138,020 KiB | 137,396 KiB |
| Release postcard proof sizes | 633,222 / 636,102 B | 636,358 / 633,318 B |

This small sample suggests no client cost increase, with an observed 12.40% lower median phase time;
it is not a statistical throughput claim. Independent random proofs have different opening/hint counts,
so these sizes are not an encoding reduction. The 635,142-byte fixed comparison proof is unchanged.
The saved **original** settlement guest accepts a newly generated optimized-client proof and checks
its journal against the native transition (1,216,509,486 cycles / 1,278 segments). This cross-version
acceptance uses a different randomized input, not the fixed-input performance denominator.

| Input / proof artifact | Bytes |
|---|---:|
| Exported verifier key | 3,213,548 |
| Proof narg | 32,656 |
| Proof hints | 601,984 |
| Complete release postcard proof | 635,142 |
| Frozen proof gzip, timestamp zero | 631,700 |
| Witness JSON | 29,326 |
| Batch journal | 196 |
| Real JoinSplit RISC Zero receipt | not produced |

The key remains SHA-256 `bc1384089b1dc1654e61561089523ae521d2cf9b664589ec1e965108b4e2a183`.
The proof and witness hashes are documented in [the fixture README](../fixtures/aggregation/README.md).
The complete settlement journal hash remains
`4e366d165e21f04fcb31f5cd46b0abfecd9d6503f8d542c3f45399256890b43f`.

Full samples, spans, commands, executable hashes and validation results are recorded in
[aggregation-measurements.json](aggregation-measurements.json). Raw logs and saved executables remain
in ignored `build/aggregation/` in this workspace.

## Correctness, rejection coverage and caveats

* Baseline workspace: 23 tests passed. Final optimized workspace: **28 tests passed**, including three
  aggregation tests and two new subgroup power-sum differential tests. Synthetic sparse boundary shapes and the real fixed-key matrices match the
  independent transpose implementation at four evaluation points, including zero and one.
* Both consuming and borrowed APIs accept a real client proof. Eleven variants covering altered
  public inputs, beginning/middle/end transcript and hints, truncation and surplus transcript/hints
  are rejected by both APIs. Borrowed verification accepts the original proof after each rejection.
* Baseline, first-review and final WHIR-optimized guests each reject nine cases: four proof variants in both diagnostic and
  settlement guests, plus an appended-byte verifier key rejected by settlement's whole-frame key hash.
  The runner requires a guest panic, so setup errors do not count as proof rejections.
* The new helper is compared with the untouched direct geometric routine at the real 32,768/4,096 and
  2,048/512 dimensions, with duplicate roots, OOD points, zero, one, minus one, zero scalars, nonzero
  initial accumulators, periodic outputs, unequal lengths and fallback conditions.
* The operator's real-proof path checks admission rejections, reservation/replay behavior, batch
  construction, guest/native journal equality, acceptance and rollback. Results are included in the
  measurement JSON. No Bitcoin transaction was broadcast by this test.
* Two new host tests pass for the existing padded suite: FIPS SHA-256 anchors, pair hashes, empty and
  multi-block field-slice preimages, and 24 independently generated little-endian RNG words across
  pool rollover and mixing. They establish limited byte-level regressions, not cryptographic soundness.
* The selected Recursive Stwo validation sequence passes: four tests, native verification, frozen-profile
  comparison, compilation, witness preparation, differential Script check, negative cases and metering.
  This is a regression check for unchanged repository components, not validation of a real JoinSplit receipt.
* Targeted Rust formatting, Python compilation, patch reapplication and whitespace checks pass.
  No existing lockfile or dependency pin changed.

The ProveKit compiler still warns about ignored `FinalClaim` return values in three branches. Inspection
of locked [WHIR's verifier](https://github.com/worldfnd/whir/blob/d986dee918dbec7e4e245dcd7b431450da1fc8da/src/protocols/whir_zk/verifier.rs)
finds `expected_rlc == linear_form_rlc` checked inside the blinded verifier, and the blinding polynomial's
returned claim checked internally against its linear forms. The outward blinded claim was already
checked in this version. Thus the warnings alone do not establish an omitted acceptance check.
They remain visible; no check or warning was suppressed. This is a source-level finding specific to
WHIR 0.2.0, not a protocol soundness proof or a guarantee for another version. The fixed JoinSplit key
exercises the dual-commitment branch; the single-commitment path lacks new end-to-end coverage here.

The original padded RISC Zero suite is unaudited. It deliberately changes Merkle and transcript
hashing from stock bare compression to padded SHA-256, including digest byte order, RNG stepping and
control-ID/root derivation. Patched prover, receipt context and Script must agree on the suite and all
those encodings. Stock receipts cannot be treated as interchangeable. The new primitive tests do not
establish the security of that construction or equivalence of the complete recursion/Script verifier.
Historical empty-batch and receipt differential results in `risc0-succinct/` are existing evidence;
they were not rerun as real JoinSplit receipt validation in this task.

## Formal coverage

[SmallCoefficients.lean](../formal/SmallCoefficients.lean) checks with Lean 4.34.0 and core `Std`, without
additional packages, custom axioms or `sorry`. It proves doubling and signed doubling under explicit
field laws, the triple identity in both multiplication orders, substitution of equal contributions
in an ordered fold, and a cache lookup lemma under an explicit valid-hit invariant. Lean reports
only standard `propext` where applicable; the ordered-fold lemma uses no axioms.

These are tractable algebraic equivalence proofs. They do **not** prove that Rust establishes the cache
invariant, follows the model, indexes safely, or implements BN254 field laws. Rust extraction/refinement,
Montgomery arithmetic and the accelerator, parsing, transcript, Merkle hashes, zero knowledge and
protocol soundness remain outside the proved coverage. Differential tests cover concrete behavior
at selected inputs, not universal equivalence. The additional subgroup/NTT optimization has a
mathematical reduction and differential/rejection validation; **none of the supplied Lean lemmas proves
that implementation or the NTT**, and no formal Rust equivalence is claimed.

[ArkLib](https://github.com/Verified-zkEVM/ArkLib/tree/2297eb06cdacae909fc1fb4a7bfd87b1e5639cc7)
was inspected at that revision. Its Sumcheck `Spec`, `Impl` and interaction modules are applicable
specification/reference material; its STIR theory is also relevant to WHIR's foundations. Its README
describes Rust functional equivalence as future work. No verified bridge from this ProveKit/WHIR Rust
implementation to ArkLib was established, and ArkLib was not added as a dependency or built wholesale.

## Representation and parameter tradeoffs

The fixed configuration remains the compiler's 128-bit Johnson-bound setting, with 10-bit PoW,
SHA2 hashing, initial/following folding factor 3, and starting log inverse rate 2. Configuration and
key bytes match the baseline. Initial codeword lengths are 32,768 for the blinded polynomial and
4,096 for blinding, both with interleaving depth 8 and 127 initial in-domain queries. Subsequent query
counts are `[62, 41, 31, 24]` and `[62, 41, 31]`; folding schedules are `[3,3,3,3,3]` and `[3,3,3,3]`.
These are configuration values and soundness assumptions, not a security proof by this task.

| Candidate | Recursive verifier consequence | Client consequence / review requirement |
|---|---|---|
| Larger folding/interleaving | fewer rounds and paths, but wider opened rows and potentially much larger blinding tables | measure both proving work and proof bytes with matched keys; retain the same soundness target |
| Different inverse rate | changes codeword size, query requirements and tree depth | higher redundancy costs client work/memory; a parameter change needs fresh key/proof and security accounting |
| Different PoW allocation | extra grinding can trade against algebraic query work | adds client grinding/latency; preserve total security assumptions and measure resource costs |
| Alternate proof encoding | might reduce parsing/IO and repeated authentication data | changes adapters and potentially transcript/hint semantics; require strict decoding and byte-equivalence tests |
| Generic gzip | only 0.54% smaller for this high-entropy proof | guest decompression adds work; no evidence of an aggregation benefit |
| Fixed key/image embedding | could avoid 78.8M key-parsing cycles | increases image size/maintenance and requires a reviewed binding/migration design |
| Subgroup geometric sums / existing NTT | **implemented**: reduces the phase from 478.4M to 277.5M cycles | shared utility also affects the client; paired generation diagnostics and baseline cross-acceptance are recorded below |
| Sparse or truncated NTT | next experiment for the remaining dense transform work | prototype against the existing forward NTT and direct sums; include memory and arbitrary-point fallbacks |

Only the subgroup geometric-sum candidate above was implemented; no check was weakened. Prefix MLE already uses the single-
multiplication difference fold; its remaining costs and zero-padded regions merit measured follow-up.
SHA acceleration and sparse scatter already existed. Further transcript/hash changes must preserve
domain separation and exact bytes, rather than substituting a faster hash implicitly.

Custom AIR/precompiles and direct WHIR recursion integration are proposals requiring separate approval.
Neither was implemented. The current work is ordinary verifier/configuration reuse and field-algebra
optimization within the existing RISC Zero guest.

## Reproduction commands

In this cloud environment initialize every fresh shell with:

```sh
source /workspace/.gsr-env/activate.sh
cd /workspace/gsr-stark-verifier
export PATH="/workspace/.gsr-env/shims:/workspace/.gsr-env/sysroot/usr/bin:$PATH"
export RISC0_HOME=/workspace/.gsr-env/risc0-home
export RISC0_BUILD_LOCKED=1
export RECURSION_SRC_PATH=/workspace/.gsr-env/recursion_zkr.zip
(cd privacy-rollup && cargo test --workspace --locked)
(cd privacy-rollup && cargo build --locked --release -p pr-provekit-adapter -p pr-operator)
(cd privacy-rollup/prover && cargo build --locked --release)
(cd privacy-rollup/prover && cargo test --locked --release --test padded_hash)
```

Restore the exact fixed inputs from the private review archive, or generate a fresh valid proof/frame
pair once with the commands in the fixture README and freeze that directory across builds. Newly
generated proofs have different bytes and costs; record their hashes and do not compare them with the
published fixed-input cycle denominator. For the optimized measurement:

```sh
python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs --label blinding-final --kind verify --runs 2 \
  --program privacy-rollup/prover/target/riscv-guest/pr-methods/pr-guest/riscv32im-risc0-zkvm-elf/release/verify_joinsplit.bin
python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs --label blinding-final --kind batch --runs 2
RAYON_NUM_THREADS=4 privacy-rollup/target/release/aggregation-bench \
  privacy-rollup/fixtures/joinsplit/joinsplit.pkv build/aggregation/inputs/proof0.pc
privacy-rollup/target/release/aggregation-cases build/aggregation/inputs/proof0.pc build/aggregation/cases
python3 privacy-rollup/tools/reject_aggregation.py build/aggregation/inputs build/aggregation/cases \
  --verify privacy-rollup/prover/target/release/exec_joinsplit \
  --settle privacy-rollup/prover/target/release/settle --out build/aggregation/rejections-blinding
python3 privacy-rollup/tools/operator_joinsplit.py
/workspace/.gsr-env/lean/bin/lean privacy-rollup/formal/SmallCoefficients.lean
```

The paired client and cross-version commands were:

```sh
for i in 0 1; do
  RAYON_NUM_THREADS=4 /workspace/.gsr-env/sysroot/usr/bin/time -v -o build/aggregation/client-original-$i.time \
    build/aggregation/joinsplit-batch-baseline privacy-rollup/fixtures/joinsplit/joinsplit.pkp \
    privacy-rollup/fixtures/joinsplit/joinsplit.pkv build/aggregation/client-original-$i
 done
for i in 0 1; do
  RAYON_NUM_THREADS=4 /workspace/.gsr-env/sysroot/usr/bin/time -v -o build/aggregation/client-blinding-$i.time \
    privacy-rollup/target/release/joinsplit-batch privacy-rollup/fixtures/joinsplit/joinsplit.pkp \
    privacy-rollup/fixtures/joinsplit/joinsplit.pkv build/aggregation/client-blinding-$i
 done
build/aggregation/baseline/settle exec build/aggregation/client-blinding-0/witness.json \
  build/aggregation/client-blinding-0/baseline-journal build/aggregation/client-blinding-0/vk.pc \
  build/aggregation/client-blinding-0/proof0.pc
```

Save `privacy-rollup/target/release/joinsplit-batch` when rebuilding the original baseline to reproduce
these paired client diagnostics. Keep compilation, execution measurement, rejection runs and client
proving sequential to avoid competing runtime workloads.

The saved baseline executables permit a comparison without changing the working implementation:

```sh
python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs --label baseline-serial --kind verify --runs 2 \
  --binary build/aggregation/baseline/exec_joinsplit --program build/aggregation/baseline/verify_joinsplit.bin
python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs --label baseline-serial --kind batch --runs 2 \
  --binary build/aggregation/baseline/settle
python3 privacy-rollup/tools/reject_aggregation.py build/aggregation/inputs build/aggregation/cases \
  --verify build/aggregation/baseline/exec_joinsplit --program build/aggregation/baseline/verify_joinsplit.bin \
  --settle build/aggregation/baseline/settle --out build/aggregation/rejections-baseline
```

To rebuild a baseline elsewhere, use disposable separate checkouts, keeping the same sibling layout.
Checkout the approved repository commit and apply `patches/aggregation-profile-baseline.patch` from
this review. On pristine pinned ProveKit, apply `patches/provekit-profile-baseline.patch` **instead of**
the original ProveKit patch: it includes the original changes plus baseline profiling/reuse API support,
but the baseline guests still use consuming verification and clone the settlement key. Apply the original
RISC Zero patch to its exact pinned checkout. Build the host and guests in release mode with the same
toolchains, then save `prover/target/release/{exec_joinsplit,settle}` and the guest `*.bin` before comparing.
Absolute paths/toolchains can change image IDs; keep hashes and commands for each actual build.

The network fallback is reproducible without changing RISC Zero source:

```sh
curl -fL https://github.com/risc0/risc0/releases/download/v3.0.6/cargo-risczero-x86_64-unknown-linux-gnu.tgz \
  -o /tmp/aggregation-risc0.tgz
# Observed official archive SHA-256: 615d961bfb81d318db5071d7548389c850e324ac7f421c075176daf26082a60a
mkdir -p /tmp/aggregation-risc0-release
tar -xzf /tmp/aggregation-risc0.tgz -C /tmp/aggregation-risc0-release
python3 privacy-rollup/tools/extract_recursion_zkr.py /tmp/aggregation-risc0-release/r0vm /tmp/aggregation-recursion.zip
export RECURSION_SRC_PATH=/tmp/aggregation-recursion.zip
```

The extraction tool refuses any embedded ZIP that does not match RISC Zero's original pinned hash.
Official guest toolchain archive URL:
`https://github.com/risc0/rust/releases/download/r0.1.97.0/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz`;
observed SHA-256 `100b597d605b706bec94e1d32bfaaf5851df8d75173f986d4b56a3e90916be53`.
The local wrapper and toolchain registration are environment setup, not dependency source changes.

For the selected Recursive Stwo checks, the exact sequence was:

```sh
cd recursive-stwo
cargo test --locked
cargo run --locked -- verify-native build/aggregation-native-reference.json
cargo run --locked -- freeze-profile build/aggregation-regenerated-profile.json
cmp profiles/bws-v1.json build/aggregation-regenerated-profile.json
cargo run --locked -- compile
cargo run --locked -- prepare-witness
cargo run --locked -- differential-reference
build/harness/gsr-meter build/differential.json > build/aggregation-differential-result.json
python3 tools/test-negative.py
cargo run --locked -- measure
```

## Remaining feasibility obstacles

The real settlement guest is now below one billion cycles but still approximately **971M**, far above 500M. Full CPU proving time, prover memory, segment proof
generation, recursive joins, succinct compression, padded identity conversion and the complete real-
batch receipt size have not been measured. Execution runtime is not proving runtime; the historical
roughly 100-hour estimate cannot be updated confidently from this cycle reduction alone.

A full real JoinSplit receipt, native verification of that receipt, regenerated Script differential
checks and an isolated regtest settlement for the new image remain required. Multi-transaction proving
and client latency/resource benchmarks must also be measured before claiming useful aggregation.
The original empty-batch seal size of 222,668 bytes and settlement weight close to the consensus limit
are historical fixtures; any real receipt and growing data-availability annex still need measurement.
Formal implementation coverage, the padded-hash audit and protocol soundness review remain open.
The largest current measured phase is the 297M-cycle sparse external row, followed by 278M-cycle
blinding tables. A concrete next experiment is a sparse/truncated forward NTT on the mostly-zero
32,768-entry coefficient vector: the existing dense transform computes all outputs, while the second
window needs only the first 4,096. Benchmark sparse butterflies and partial outputs against both the
existing NTT and direct sums, retain all fallback paths, and track guest/prover memory. This task stops
for review with the current measured optimization; it does not silently change hashes or parameters.
