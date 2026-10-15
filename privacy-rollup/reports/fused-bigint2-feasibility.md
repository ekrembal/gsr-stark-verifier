# Bounded proving and fused arithmetic investigation

This is an unpublished, ongoing experiment based on local SHA accelerator commit
`5a2b71d81cdd9f7ebf309ac0f8ac30eaee43dca0`. It does not establish that a full real
JoinSplit aggregation is practical. No AIR, transcript, security parameter, or
covenant changes have been made in this experiment.

## Real proof and recursion milestone

The exact frozen verifier input (`vk.pc` SHA-256
`bc1384089b1dc1654e61561089523ae521d2cf9b664589ec1e965108b4e2a183`)
executed with the existing SHA-accelerated verifier, a segment limit of 2^18,
and all journal bytes compared with its reference. Two adjacent segments,
indices 500 and 501, were retained; the other traces were discarded.
These are **partial execution claims**, not a completed JoinSplit receipt.
The historical output-directory label `sha-row18` does not establish which
verifier phase these two segments belong to.

| Stage | Prover wall seconds | Sampled peak RSS KiB | Seal bytes |
|---|---:|---:|---:|
| Segment 500, 2^18 rows | 99.710 | 2,407,060 | 255,656 |
| Segment 501, 2^18 rows | 99.962 | 2,403,596 | 255,656 |
| Lift 500 | 45.168 | 1,449,576 | 222,668 |
| Lift 501 | 43.059 | 1,449,460 | 222,668 |
| Join | 42.834 | 1,477,104 | 222,668 |
| Padded SHA-256 identity | 20.355 | 1,426,960 | 222,668 |

All six receipts passed their corresponding integrity checks. The padded
receipt used the parameters returned by the existing patched implementation;
a flipped seal word was rejected. The sum of prover stage timers is 351.088
seconds (resource supervisor elapsed time is slightly longer). This validates
the implementation on these inputs; it is not an audit of the patched padded
hash suite or a protocol soundness proof.

Full execution at 2^18: 726,666,128 user cycles, 3,943 segments,
192,277,691 paging cycles, 114,689,973 reserved cycles, and 1,033,633,792 total
padded cycles. At the usual 2^20 limit the same verifier has 821 segments.
The smaller limit increases overhead significantly. These measurements use
four CPU cores, a 16 GiB cgroup memory limit, and no GPU. A linear extrapolation
of the 2^18 segment proof timings alone is about 109 hours for this execution,
before lifts and joins. This is an estimate from two segments, not a full proof
measurement; larger segment sizes and optimized guests must be measured.

The reusable `proof_chain_bench` binary directly selects the local prover,
explicitly disables development-mode proving, verifies each stage, and writes
postcard checkpoints. `bounded_command.py` checks aggregate process-group RSS
and free disk every 250 ms and stops on explicit limits. It does not replace
the hard cgroup limit. Current guards: 900 seconds per proof stage, 12 GiB RSS,
and at least 1 GiB free disk. No full JoinSplit proof was launched.

A second chain covers the **complete** `field_kernel` guest: 400 iterations of
`a = a*b + 5` in BN254 Fr, starting at `a=123456789`, `b=987654321`.
The journal matched an independent Python modular-integer reference. Its
125,034 user cycles occupied two segments (2^17 and 2^16 rows), totaling
196,608 padded rows. Both segment proofs, both lifts, join, padded identity,
and full image-ID/journal verification passed. Total supervisor time was
218.675 seconds; maximum sampled RSS was 1,475,600 KiB. This remains the
existing two-modmul arithmetic baseline, not the unintegrated fused candidate.
The complete diagnostic field-vector guest also matched 6,486 independently
calculated outputs (207,552 journal bytes), covering 1,081 boundary/random input
pairs and multiplication, square, addition, subtraction, multiply-add, and a
butterfly identity. The resource supervisor timeout guard was exercised and
stopped a test process after about one second.

## Reproduction

Initialize the environment and build:

```sh
source /workspace/.gsr-env/activate.sh
export PATH="/workspace/.gsr-env/shims:$PATH"
export RISC0_HOME=/workspace/.gsr-env/risc0-home
export RISC0_BUILD_LOCKED=1
export RECURSION_SRC_PATH=/workspace/.gsr-env/recursion_zkr.zip
export RAYON_NUM_THREADS=4
cd privacy-rollup/prover
cargo build --locked --release --bin proof_chain_bench --bin exec_sha256_check
cd ../..
```

Use a fresh output directory for each experiment. The reference files below
were preserved from the SHA experiment; input hashes are recorded in its report.

```sh
privacy-rollup/prover/target/release/proof_chain_bench capture \
  build/feasibility/sha-row18 \
  build/aggregation/fused-sha-baseline/verify_joinsplit.bin \
  build/aggregation/sha256-expected-verify-journal.bin \
  500 2 18 build/aggregation/inputs/vk.pc build/aggregation/inputs/proof0.pc
```

Run the following operations sequentially, each through the resource wrapper:
`prove 500`, `prove 501`, `lift 500`, `lift 501`, `join 500 501`, and
`padded joined`. For example:

```sh
python3 privacy-rollup/tools/bounded_command.py \
  --output build/feasibility/example-prove500 --seconds 900 -- \
  privacy-rollup/prover/target/release/proof_chain_bench \
  prove build/feasibility/sha-row18 500
```

Raw logs and receipt checkpoints are under ignored `build/feasibility/`.
The harness only performs full image/journal receipt verification when capture
metadata establishes that the retained range covers the complete execution.

## Fused Montgomery candidate — not integrated

The current Arkworks backend uses two checked BigInt2 modular multiplications
for `a*b*R^-1 mod p`, where `R=2^256`. The candidate generator instead describes
one fixed-BN254-Fr relation:

```
a*b + p*R = q*p + r*R, with a separate guest check 0 <= r < p.
```

Because `gcd(R,p)=1`, this uniquely selects the same canonical output.
The witness generator computes the remainder and quotient, but is not trusted
for correctness. The verifier program reads both inputs, writes the quotient
to a 48-byte stack allocation, writes the 32-byte output, and checks the relation
using the existing BigInt2 byte-polynomial/carry instructions. Constants are
part of the guest image. Inputs are read before writing the output, to support
the intended in-place multiplication. The final canonicality check is mandatory.

The candidate has 34 verifier instructions, a 35-cycle ecall, 176 bytes of
constants, and a 640-byte blob. Its byte polynomial has at most 80 coefficients.
The conservative coefficient magnitude bound is 4,162,110. The pinned v2
circuit allows a full byte for the second carry digit; the untrusted-carry
bound is therefore 2,146,303, not merely the honest generator's six-bit middle
digit range. Even including this larger bound, a coefficient cannot wrap
BabyBear. Honest carry magnitude is bounded by 16,322.

`generate_montgomery_blob.py` checks 10,036 integer boundary/random cases.
This is a design and test artifact only: no production dispatch uses the blob,
and no real proof of this custom kernel has yet been validated.

`formal/MontgomeryRelation.lean` checks four narrow statements with Lean 4.34.0,
without axioms: the abstract field identity, the concrete no-wrap inequality,
the honest carry bound fitting its encoding, and the coprime radix. It does not
verify bytecode generation, memory binding, Rust, or protocol soundness.

The official BigInt2 compiler source was inspected at Zirgen
`df6fb9dda1c20209058d6ee90a8912351b741081` as supplementary documentation.
The executable format and carry behavior were checked against the pinned local
RISC Zero source; no compiler or dependency pin was changed. The upstream
[BigInt2 audit](https://veridise.com/wp-content/uploads/2025/04/BigInt2_Report_V1.pdf)
documents the importance of implicit precompile assumptions; it does not audit
this new candidate.

## Priority and remaining gates

New structured-matrix research suggests avoiding expanded Poseidon2 linear
forms in the fixed VK while preserving every matrix output. Its reverse
evaluator is now the first integration priority. Claimed arithmetic reductions
from that research are modeling results until reproduced in this executor.

Remaining work includes complete arithmetic-kernel proof/journal verification,
structured-matrix differential and rejection gates, measured optimized guest
cycles, real proving comparisons, and resource-based full-pipeline feasibility.
The prior padded-hash audit gap, upstream FinalClaim handling caveat, and lack
of a full real JoinSplit receipt remain unchanged.
