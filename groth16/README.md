# RISC Zero Groth16 verifier

This directory contains a real RISC Zero Groth16 receipt, a pure-Python BN254
reference, Script field emitters, and a dynamic-witness affine Miller-loop
verifier. `tools/native` verifies the fixture with `Receipt::verify`. See
`fixtures/README.md` for seal layout and the five public-input order. The
pairing-stage Script takes A, B, C and L from the witness; claim-mode Scripts
bind L to the public claim and add canonical, curve, twist and subgroup checks.

## Stage 1 field-emitter microbenchmarks

`tools/fields.py` emits canonical Fp, Fp2, Fp6 and Fp12 addition, subtraction,
multiplication, squaring, sparse multiplication and Frobenius maps. Its Python
twins are tested against `bn254.py` and py-ecc. The following varops are
**measured** by the pinned standalone `bitcoin-util evalscript` interpreter,
with one random canonical input per operation. They are opcode execution costs,
not full-transaction WU or the final verifier cost.

| Field | Add | Sub | Mul | Square | Frobenius p | Sparse mul |
|---|---:|---:|---:|---:|---:|---:|
| Fp | 18,744 | 24,032 | 28,978 | 31,574 | 17,078 | 28,978 |
| Fp2 | 34,988 | 45,564 | 125,222 | 130,446 | 41,040 | 125,222 |
| Fp6 | 99,964 | 131,692 | 1,671,196 | 1,686,880 | 254,294 | 631,510 |
| Fp12 | 197,440 | 260,896 | 7,241,479 | 7,273,177 | 574,208 | 1,257,951 |

Sparse multiplication in this table uses three nonzero right-hand
coefficients. These are standalone operation costs, not per-operation
amortized transaction measurements.

## Stage 2 affine Miller-loop verifier

`tools/pairing_script.py` emits one dynamic B loop and fixed line schedules for
the RISC Zero gamma, delta and beta G2 points. A, B, C and L are witness values;
the Script checks the G1 evaluation inverses, each B tangent/chord slope,
`c*c_inv == 1`, the allowed `wi` coset, and the residue-witness final equality.
The B slopes, c, c-inverse and wi are not embedded in the Script. The real
fixture passes and mutations of c, wi and a slope are rejected.

The following **measured** values are for the pairing-stage script executed by
the pinned standalone interpreter, before transaction compression. They are
not the complete Stage 3/4 verifier cost:

| Metric | Measured |
|---|---:|
| Uncompressed Script bytes | 5,182,058 |
| Witness items | 226 |
| Varops | 1,818,911,457 |

The NAF line schedule, affine slope checks, and D-twist sparse line placement
follow BitVM at commit `c620dbfaacebdf778e765a6681985350389973b1`:
`bitvm/src/bn254/ell_coeffs.rs::G2Prepared::from_affine`,
`bitvm/src/bn254/pairing.rs::hinted_quad_miller_loop_with_c_wi`, and
`bitvm/src/groth16/offchain_checker.rs::compute_c_wi`. The BN254 loop digits
and Frobenius-twist constants are taken from Arkworks'
`ark-bn254-0.5.0/src/curves/mod.rs`. `tools/pairing_ref.py` differentially
checks the signed-loop raw product against final exponentiation on the fixture.
The Script uses the same c-inverse folding across loop squarings and the
Frobenius powers, and checks wi against `{1, W, W²}`.

## Stage 3 statement and input checks

`build_pairing_script(..., claim_mode=...)` adds these checks before the
pairing equation:

- Proof coordinates, evaluation hints, residue witnesses and slopes are
  canonical coefficients in Fp (`0 <= v < p`).
- A, C and L are on `y² = x³ + 3`; B is on the Arkworks BN254 twist. B's
  subgroup check uses Arkworks' `psi(B) = [6X²]B` criterion from
  `ark-bn254-0.5.0/src/curves/g2.rs`; the affine double/add slopes are witness
  values checked by multiplication.
- Fixed `a0`, `a1` and `id` are folded into
  `IC0 + a0·IC1 + a1·IC2 + id·IC5`. Two 4-bit, 32-window tables compute
  `c0·IC3 + c1·IC4` in Script. Script range-checks each digit, re-composes
  both 128-bit scalars, and checks the result against witness L. Deterministic
  per-window offset points make every table entry finite, including digit
  zero; Script rejects zero affine denominators.
- `fixed` mode compares c0/c1 to the fixture claim. `witness` mode takes the
  raw 32-byte digest as a witness item, checks its little-endian halves against
  c0/c1 byte-by-byte, and leaves the original digest in RISC Zero byte order
  below the final true stack item.

`tools/verifier_test.py` exercises both modes and rejects coordinate
mutations of A/B/C, an off-curve A, a noncanonical A coordinate, an on-twist B
outside G2, a wrong fixed claim, corrupted c/c-inverse/wi, a corrupted B
slope, and a wrong window digit. A second valid receipt for a different claim
was not generated; fixed-mode claim binding is tested by mutating c0.

## Reproduction

Install Python dependencies with `python3 -m pip install -r requirements.txt`.
Run `tools/test.sh` from this directory. `tools/generate.py` emits both claim
modes and can compress the bundle. The GSR compression wrapper is copied
unchanged from PR #20's `risc0-succinct/tools/gsr_tooling.py`; it uses GSR
tooling revision `bf31cc4ac70e440e49f9a3695a6fd05f7b2866d4`.

The real fixture was generated with RISC Zero 3.0.6 and `ProverOpts::groth16()`;
`tools/native` calls `Receipt::verify` before exporting it. The fixture can be
recreated with `tools/native` and the guest in `tools/guest`. Groth16/BN254 is
not post-quantum: an attacker able to solve the BN254 discrete-log problem can
forge proofs and steal covenant funds. Verification relies on RISC Zero's
Groth16 trusted setup. The Script checks canonical field encodings, G1 curve
membership, G2 twist membership and the G2 subgroup criterion.

## Direct compressed-transaction measurement

These are measurements of the actual compressed fixed-claim transaction,
including GSR macro execution. The meter is from Core revision
`ad6c16ff0214014023ff2a81504048a8850a1c1c`, the PR #20 pin. Select it with
`GSR_METER=/path/to/gsr-meter` when running `tools/measure.py`.

| Metric | Measured |
|---|---:|
| Committed verifier Script | 117,868 bytes |
| Unrolled verifier Script | 1,562,773 bytes |
| Witness | 746 items / 21,460 bytes |
| Transaction weight | 140,494 WU |
| Varops budget | 1,404,440,000 |
| Varops | 1,233,221,358 |
| GSR macro references | 166,534 |
| Peak stack | 779 entries / 22,423 payload bytes |
| Largest stack element | 65 bytes |
| Final stack is exactly true | Pass |

| Limit | Result | Measured value |
|---|---|---:|
| Standard transaction weight, 400,000 WU | Pass | 140,494 WU |
| Varops budget | Pass | 1,233,221,358 / 1,404,440,000 |
| Unrolled Script, 4,000,000 bytes | Pass | 1,562,773 bytes |
| Stack entries | Pass | 779 |
| Stack payload | Pass | 22,423 bytes |
| Largest stack element | Pass | 65 bytes |
| No OP_SUCCESS | Pass | None present |
| Exact true final stack | Pass | Interpreter result |

| Comparison | Weight | Varops | Committed verifier | Witness |
|---|---:|---:|---:|---:|
| This Groth16 verifier | 140,494 WU | 1,233,221,358 | 117,868 B | 21,460 B |
| PR #20 STARK verifier | 272,064 WU | 2.32B | 48,776 B | 221,068 B |

PR #20 values are from
<https://github.com/zkpinbtc/gsr-stark-verifier/pull/20>.
