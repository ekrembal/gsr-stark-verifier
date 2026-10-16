# SHA-256 accelerator experiment — 2026-10-02

The unpublished SHA experiment reduces fixed-input settlement from the validated
NTT pass's **852,104,533–852,104,558 cycles / 948 segments** to
**746,732,029–746,732,054 cycles / 842 segments**. This is **12.37% fewer cycles**
and 106 fewer segments, or **38.60% fewer cycles than the original instrumented
PR #10 baseline**. The same 196-byte settlement journal is produced.

Median settlement execution time falls 7.21%; maximum measured host RSS rises
0.30%. These are execution measurements. No real JoinSplit RISC Zero receipt,
proving-throughput measurement or prover-memory measurement was produced. The
500M-cycle target remains unmet.

## Publication boundary

The approved NTT pass was integrated into the existing [draft PR #11](https://github.com/ekrembal/gsr-stark-verifier/pull/11).
Its remote head was verified as `0d490712107537efcfaeeec93dc5e4bb223418ab`, containing
validated NTT commit `03ccc827f191d8536e99ebd7d07ea1b5905d993d` and publication-note
updates. GitHub reports that it remains draft/open, and returned no PR-triggered
workflow runs or commit statuses for that head. No new PR, merge or deployment
was performed.

This SHA experiment starts from that head on the separate local branch
`local/sha256-accelerator-experiment` and remains unpublished. PR #11 reports the
NTT pass's 852.105M cycles, 948 segments and 29.93% reduction; its measurements do
not include this SHA experiment.

## Exact implementation and dependency scope

The only production optimization is the guest workspace's `sha2` 0.10.9 source
override to the official RISC Zero fork:

```toml
[patch.crates-io]
sha2 = { git = "https://github.com/risc0/RustCrypto-hashes", rev = "8631fabdea7bdffa97b11868e04e73491d8e5bcf" }
```

The revision is the resolved `sha2-v0.10.9-risczero.0` tag, pinned by commit rather
than mutable tag. Comparison with registry 0.10.9 finds only two Rust source
differences: the SHA-256 backend selection and added `src/sha256/risc0.rs`.
The fork is used unchanged. Its
[dispatch](https://github.com/risc0/RustCrypto-hashes/blob/8631fabdea7bdffa97b11868e04e73491d8e5bcf/sha2/src/sha256.rs)
selects the RISC Zero backend on `target_os = "zkvm"`, `target_arch = "riscv32"`;
neither force-software feature is enabled. The existing `asm` feature does not
select an x86/aarch64 backend on the guest.

The [bridge](https://github.com/risc0/RustCrypto-hashes/blob/8631fabdea7bdffa97b11868e04e73491d8e5bcf/sha2/src/sha256/risc0.rs)
calls the pinned v3.0.6 `sys_sha_buffer` ABI, converts state word endianness and
copies unaligned input blocks. The SDK implementation limits each SHA ecall to
1,000 blocks; validation covers both sides of that boundary. No new precompile,
custom AIR, BigInt2 implementation or protocol code is introduced.

The override applies to **all guest consumers of sha2 0.10.9**, including WHIR,
Spongefish/ProveKit transcripts and other protocol/state hashes. SHA-224 shares
the same compression backend and is also checked. SHA-512 source is unchanged.
The settlement verifier-key hash already explicitly used `risc0_zkvm::sha::Impl`.
Guest SHA-2 0.11.0 remains untouched. Native/client and host-prover SHA-2 sources
remain on the registry.

There are **no package additions/removals or version changes** in any of the four
existing lockfiles. Necessary deviations are limited to:

- Guest lockfile: sha2 0.10.9 changes from registry checksum
  `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` to the pinned Git
  source; the diagnostic guest directly names already-resolved SHA-2 and WHIR.
- Host-prover lockfile: its root package directly names already-resolved
  `tracing` 0.1.44 for execution diagnostics.
- Native adapter test configuration exposes the existing SHA-2 compression API;
  the native workspace lockfile is unchanged. The new guest diagnostic's direct
  dependency features were already present transitively in the production guest.

Rust 1.97, recursive-stwo's nightly, RISC Zero
`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`, ProveKit
`4ee40639fb8849aeeba37761fdda07f28367e81d`, Bitcoin
`d2799052604eb138c5a79acf88514a0c8b07f4ef`, their existing source patches and all
protocol/security parameters are preserved.

## Runtime dispatch and correctness evidence

The guest vectors' **11,702 output bytes match the native registry implementation
exactly**. Python `hashlib` independently checks 301 digest results. Coverage
includes 32 message lengths at four byte alignments, SHA-256/SHA-224 padding
boundaries, six streaming chunk sizes with reset and cloned state, an unchanged
SHA-512 case, WHIR `hash_many` including empty inputs, 24 raw-compression cases
with arbitrary initial states and block counts 0/1/2/999/1000/1001, and 11
transcript sequences with split absorb/squeeze, ratchet and clone operations.
Raw compression and transcript outputs use the native/guest differential; Python
does not expose those APIs. These are finite regression tests, not a formal proof.

Execution logging confirms actual accelerator use:

| Fixed verifier diagnostic | NTT baseline | SHA candidate |
| --- | ---: | ---: |
| SHA ecalls | 4 | 20,703 |
| SHA ecall cycles | 296 | 1,849,174 |
| BigInt ecalls | 2,807,972 | 2,807,972 |
| BigInt ecall cycles | 95,471,048 | 95,471,048 |

The vector diagnostic separately records 18,316 SHA ecalls. Ecall-cycle totals
cover accelerator invocation costs, not all surrounding hash/field computation.
The diagnostic verifier journal is the existing eight-byte public-input **count**,
not a commitment to the input values. Value binding is exercised by the full
verifier, public-input rejection tests and the settlement guest's statement check
and 196-byte journal. No checks or transcript operations were removed.

The dispatch diagnostics overlapped native validation jobs, so their runtimes
are excluded from the performance comparison below.

## Isolated paired measurements

Two sequential samples per variant and entry point alternate the saved NTT
baseline with the SHA candidate. No builds or other validation jobs ran during
these profiles. The baseline binaries were copied before changes and were not
rebuilt. Exact samples, profiles, commands and file hashes are in
[`sha256-accelerator-measurements.json`](sha256-accelerator-measurements.json).

| Measurement | Published NTT pass | SHA candidate | Change |
| --- | ---: | ---: | ---: |
| Verifier cycles | 827,292,477–827,292,502 | 726,666,128–726,666,195 | −12.16% |
| Verifier segments | 923 | 821 | −102 |
| Verifier median execution | 28.588 s | 25.574 s | −10.54% |
| Verifier maximum measured host RSS | 127,024 KiB | 125,992 KiB | −0.81% |
| Settlement cycles | 852,104,533–852,104,558 | 746,732,029–746,732,054 | −12.37% |
| Settlement segments | 948 | 842 | −106 |
| Settlement median execution | 28.125 s | 26.097 s | −7.21% |
| Settlement maximum measured host RSS | 142,856 KiB | 143,284 KiB | **+0.30%** |

WHIR matrix-commitment verification falls from 118,350,931 to **24,819,008 cycles**.
The major unchanged field-arithmetic costs remain: sparse-row computation
295,035,330 cycles, blinding tables 156,659,030 cycles, and prefix-MLE evaluation
95,760,329 cycles. Key deserialization remains 78,805,615 cycles. These phases
explain why hash acceleration alone cannot meet the 500M-cycle goal. Inclusive
profiles overlap; do not sum parent and child spans.

The same four-CPU-quota AMD EPYC environment, 16 GiB RAM limit and no exposed
GPU were used. The cycle metric is the existing executor's `SessionInfo::cycles()`;
segment padding and accelerator proving work are not a proving-time estimate.
RSS is GNU `time`'s host-executor measurement, not guest heap or prover memory.
Two samples do not establish a statistical throughput or memory bound.

### Fixed artifacts

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| `vk.pc` | 3,213,548 | `bc1384089b1dc1654e61561089523ae521d2cf9b664589ec1e965108b4e2a183` |
| `proof0.pc` | 635,142 | `e3ed84cde408df6b83ace47e77358dd3eb6cf34d092d01a9f256702cb7f256fa` |
| `witness.json` | 29,326 | `0beabb1cb720abaf578400dc3f8116ec2838e8589fc1087f7b157d208d34a0f8` |

The ProveKit proof bytes and format are unchanged. All paired settlement journals
have SHA-256 `4e366d165e21f04fcb31f5cd46b0abfecd9d6503f8d542c3f45399256890b43f`.
Candidate image ID:
`68b777e4fc034cdead1da74323bd255a89731447cf45c2663aad19537e93f6c6`.
Program sizes and hashes are recorded separately from proof sizes in the JSON.
No recursive receipt size was measured.

## Validation and reproduction

The completed validation comprises 34 native workspace tests, the native/guest
and `hashlib` vector comparisons above, both existing padded-hash primitive
tests, fixed-proof acceptance, nine rejection cases on each guest version,
fresh-proof operator/settlement and rollback checks, exact patch reapplication,
Rust formatting and Python syntax checks. The fresh operator flow uses the
repository's fixture descriptor, not a deployed covenant or real receipt.
Raw logs and exact results are retained in the private review archive and JSON.

Initialize each shell using the environment setup in the previous reports.

```sh
source /workspace/.gsr-env/activate.sh
cd /workspace/gsr-stark-verifier
export PATH="/workspace/.gsr-env/shims:/workspace/.gsr-env/sysroot/usr/bin:$PATH"
export RISC0_HOME=/workspace/.gsr-env/risc0-home
export RISC0_BUILD_LOCKED=1
export RECURSION_SRC_PATH=/workspace/.gsr-env/recursion_zkr.zip
GSR_SHA256_REFERENCE="$PWD/build/aggregation/sha256-native-reference.bin" \
  cargo +1.97 test --locked --release --manifest-path privacy-rollup/Cargo.toml \
  -p pr-provekit-adapter --test sha256_vectors -- --nocapture
python3 privacy-rollup/tools/check_sha256_vectors.py build/aggregation/sha256-native-reference.bin
(cd privacy-rollup/prover && cargo build --locked --release)
guest_dir=privacy-rollup/prover/target/riscv-guest/pr-methods/pr-guest/riscv32im-risc0-zkvm-elf/release
privacy-rollup/prover/target/release/exec_sha256_check \
  "$guest_dir/sha256_vectors.bin" build/aggregation/sha256-native-reference.bin
RAYON_NUM_THREADS=2 cargo +1.97 test --locked --release --manifest-path privacy-rollup/Cargo.toml --workspace
(cd privacy-rollup/prover && cargo test --locked --release --test padded_hash)
```

`cargo tree --locked --manifest-path privacy-rollup/methods/guest/Cargo.toml -i
sha2@0.10.9 -e features --target riscv32im-risc0-zkvm-elf` records the effective
dependency source and features. The original source switch was made with targeted
`cargo update -p sha2@0.10.9`; subsequent commands are locked. The host diagnostic
root dependency was resolved with offline `cargo update -p pr-prover`; the recorded
lockfile comparison confirms no package-version changes.

Retain `build/aggregation/sha-ntt-baseline/{exec_joinsplit,settle,verify_joinsplit.bin,apply_batch.bin}`
before changing the guest. Use the exact frozen frames for both variants. Fresh
randomized proofs cannot be compared to the reported cycle denominators.

```sh
for sample in 0 1; do
  python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
    --label "sha-ntt-$sample" --kind verify --runs 1 \
    --binary build/aggregation/sha-ntt-baseline/exec_joinsplit \
    --program build/aggregation/sha-ntt-baseline/verify_joinsplit.bin
  python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
    --label "sha-accel-$sample" --kind verify --runs 1 --program "$guest_dir/verify_joinsplit.bin"
  python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
    --label "sha-ntt-$sample" --kind batch --runs 1 --binary build/aggregation/sha-ntt-baseline/settle
  python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
    --label "sha-accel-$sample" --kind batch --runs 1
done
python3 privacy-rollup/tools/reject_aggregation.py build/aggregation/inputs build/aggregation/cases \
  --verify build/aggregation/sha-ntt-baseline/exec_joinsplit \
  --program build/aggregation/sha-ntt-baseline/verify_joinsplit.bin \
  --settle build/aggregation/sha-ntt-baseline/settle --out build/aggregation/rejections-sha-ntt
python3 privacy-rollup/tools/reject_aggregation.py build/aggregation/inputs build/aggregation/cases \
  --verify privacy-rollup/prover/target/release/exec_joinsplit \
  --settle privacy-rollup/prover/target/release/settle --out build/aggregation/rejections-sha-accel
RAYON_NUM_THREADS=4 python3 privacy-rollup/tools/operator_joinsplit.py
```

The rejected variants change a public input, first argument byte, middle hint
byte or add an argument byte through both entry points; the ninth changes the
settlement key frame. Every rejection must be a guest panic, not an unrelated
host failure. Native tests also retain the 11-mutation checks through both
verifier APIs and valid reuse after failures.

## Remaining correctness, security and deployment limits

The existing accelerator bridge's unsafe ABI/alignment/endian behavior has finite
differential coverage, not a formal Rust/SHA equivalence proof or an audit. The
earlier Lean coefficient/cache identities do not cover this bridge, SHA circuits,
NTT implementation or protocol soundness. Existing ignored `FinalClaim` warnings
and unaudited padded RISC Zero hashing retain the caveats in the
[original report](aggregation-optimizations.md). The two padded-hash tests do not
establish soundness of a real recursive receipt.

No full JoinSplit proof, real-receipt Script differential, real-receipt settlement
validation, multi-proof aggregation profile or paired client-proving benchmark
was run. Native/client hashing remains the registry implementation. Execution
improvements alone do not establish practical aggregation feasibility or a
proportional proving improvement. The new image is bound by the covenant and
rollup descriptor; adoption requires a new genesis or explicitly supported
migration. No deployment or migration is implemented here.
