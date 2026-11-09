# RISC Zero Groth16 verifier

Direct measurements below use the compressed transaction and the GSR meter
built against Bitcoin Core `ad6c16ff0214014023ff2a81504048a8850a1c1c` (PR #20's
Core pin). Both claim modes pass without witness or annex padding.

## Final measurements

| Metric | Fixed claim | Witness claim |
|---|---:|---:|
| Committed compressed Script | 117,868 B | 118,023 B |
| Unrolled Script | 1,562,773 B | 1,563,258 B |
| Witness items / payload | 746 / 21,460 B | 747 / 21,492 B |
| Transaction weight | 140,494 WU | 140,682 WU |
| Varops budget | 1,404,440,000 | 1,406,320,000 |
| Varops, compressed execution | 1,233,221,358 | 1,232,871,788 |
| GSR macro references | 166,534 | 163,015 |
| Peak stack entries | 779 | 780 |
| Peak stack payload | 22,423 B | 22,455 B |
| Largest stack element | 65 B | 65 B |
| Interpreter result | Pass (`ok=true`) | Pass (`ok=true`) |
| Final stack contract | Exactly `true` | One truthy 32-byte claim digest |

The witness-claim output is the original claim digest in RISC Zero byte order.
The test suite compares those output bytes with the fixture digest. Its final
stack is intentionally not the single-byte value `true`.

| Limit | Fixed claim | Witness claim | Limit |
|---|---:|---:|---:|
| Standard transaction weight | Pass | Pass | 400,000 WU |
| Varops budget | Pass | Pass | 1,404,440,000 / 1,406,320,000 |
| Unrolled Script size | Pass | Pass | 4,000,000 B |
| Peak stack entries | Pass | Pass | 32,768 |
| Peak live stack payload | Pass | Pass | 8,000,000 B |
| Largest stack element | Pass | Pass | 4,000,000 B |
| `OP_SUCCESS` absent | Pass | Pass | Required |
| Script evaluation | Pass | Pass | `ok=true`, one truthy result |

| Comparison | Weight | Varops | Committed verifier | Witness |
|---|---:|---:|---:|---:|
| This Groth16 verifier, fixed claim | 140,494 WU | 1,233,221,358 | 117,868 B | 21,460 B |
| This Groth16 verifier, witness claim | 140,682 WU | 1,232,871,788 | 118,023 B | 21,492 B |
| [PR #20 STARK verifier](https://github.com/zkpinbtc/gsr-stark-verifier/pull/20) | 272,064 WU | 2.32B | 48,776 B | 221,068 B |

These are the generated transactions' direct compressed-execution results;
the budget is derived from each transaction's weight by the pinned Core meter.
The fixed-claim margin is 171,218,642 varops; the witness-claim margin is
173,448,212 varops. No padding was needed.

## How it works

The fixture is a real RISC Zero 3.0.6 Groth16 receipt produced with
`ProverOpts::groth16()` and verified natively with `Receipt::verify`. The
verifier is dynamic: proof points, slopes, residue witnesses, and (in witness
mode) the claim digest are witness data, not compiled proof constants.

The pairing relation is
`e(A, B) · e(−L, γ) · e(−C, δ) = e(α, β)`. Script checks canonical field
encodings, G1 curve membership for A/C/L, B's BN254 twist membership and G2
subgroup criterion, affine slope hints, and the final residue-witness
relation. Fixed `a0`, `a1`, and `bn254_control_id` are folded into the
constant part of L; two 4-bit, 32-window tables compute the variable
`c0·IC3 + c1·IC4` term. Fixed mode binds the two claim scalars to the fixture.
Witness mode checks the supplied digest bytes against those scalars and
returns the digest for covenant composition.

The Miller loop uses the signed NAF schedule for BN254's optimal-ate loop,
D-twist line placement, fixed gamma/delta/beta line schedules, and the final
Frobenius-twisted additions. The B-line slopes are checked by multiplication,
without inversions. The residue witness checks `c·c⁻¹ = 1`, folds the inverse
Miller factor into the loop, applies the Frobenius powers, and checks the
result against `wi`. The formulas follow BitVM commit
`c620dbfaacebdf778e765a6681985350389973b1`: `bitvm/src/bn254/ell_coeffs.rs`,
`bitvm/src/bn254/pairing.rs`, and
`bitvm/src/groth16/offchain_checker.rs::compute_c_wi`.

Standalone field-operation microbenchmarks use one random canonical input per
operation. These are per-operation varops, not full-transaction measurements:

| Field | Add | Sub | Mul | Square | Frobenius p | Sparse mul (3 terms) |
|---|---:|---:|---:|---:|---:|---:|
| Fp | 18,744 | 24,032 | 26,478 | 29,074 | 17,078 | 26,478 |
| Fp2 | 34,988 | 45,564 | 80,928 | 86,152 | 41,040 | 80,928 |
| Fp6 | 99,964 | 131,692 | 808,620 | 824,304 | 254,294 | 358,266 |
| Fp12 | 197,440 | 260,896 | 3,316,878 | 3,348,576 | 574,208 | 711,463 |

### Reproduction

Install dependencies with `python3 -m pip install -r requirements.txt`. The
compression wrapper is copied unchanged from PR #20's
`risc0-succinct/tools/gsr_tooling.py`; it uses GSR tooling revision
`bf31cc4ac70e440e49f9a3695a6fd05f7b2866d4`. Install that revision with:

```sh
cargo install --locked --git https://github.com/bitcoin-gsr/gsr-tooling --rev bf31cc4ac70e440e49f9a3695a6fd05f7b2866d4
```

or set `GSR` to the binary path. Generate both compressed bundles and meter
them directly:

```sh
python tools/generate.py --claim fixed --compress --out build/fixed.json
python tools/generate.py --claim witness --compress --out build/witness.json
GSR_METER=/path/to/ad6c16ff-gsr-meter python tools/measure.py build/fixed.json
GSR_METER=/path/to/ad6c16ff-gsr-meter python tools/measure.py build/witness.json
```

Run `PYTHON=/path/to/python bash tools/test.sh` for the Python reference,
field and pairing differential tests, tamper checks, compression equivalence,
and native fixture verification.

### Security notes

BN254 is not post-quantum: an attacker able to solve its discrete-log problem
can forge proofs and steal covenant funds. The verifier relies on RISC Zero's
Groth16 trusted setup. It checks canonical encodings, G1 curve membership,
the G2 twist and subgroup, and the claim binding described above. The fixture
is an example proof, not a trusted setup contribution.

## Optimization history

Standalone rows are per-operation probes. Transaction-level WU and varops
appear only where the compressed transaction itself was metered.

| Change or probe | Before | After | Scope / outcome |
|---|---:|---:|---|
| Lazy reduction, Fp2 multiply | 125,222 varops | 80,928 varops | Standalone field operation |
| Lazy reduction, Fp6 multiply | 1,671,196 varops | 808,620 varops | Standalone field operation |
| Lazy reduction, Fp12 multiply | 7,241,479 varops | 3,316,878 varops | Standalone field operation |
| Sparse Fp12 line multiply | 7,241,479 varops | 711,463 varops | Standalone dense/sparse operation comparison |
| Bottom-anchored macro compression | 1,562,773 B unrolled | 117,868 B committed | Fixed-claim script; 13.26× size reduction |
| Hinted-quotient probe | 23,372 varops (`MUL; MOD`) | 26,246 varops | Single Fp probe; not adopted |
| Kronecker-packed Fp2 probe | 80,928 varops | 185,218 varops | Standalone probe; not adopted |
