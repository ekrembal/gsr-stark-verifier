# RISC Zero Groth16 verifier

This directory contains a real RISC Zero Groth16 receipt, a pure-Python BN254
reference, Script field emitters, and a dynamic-witness affine Miller-loop
verifier. `tools/native` verifies the fixture with `Receipt::verify`. See
`fixtures/README.md` for seal layout and the five public-input order. The
pairing-stage Script takes A, B, C and L from the witness; Stage 3 will bind L
to the public claim and add canonical, curve, twist and subgroup checks.

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

## Reproduction

Install Python dependencies with `python3 -m pip install -r requirements.txt`.
Run `tools/test.sh` from this directory. The GSR compression wrapper is copied
unchanged from PR #20's `risc0-succinct/tools/gsr_tooling.py`; it uses GSR
tooling revision `bf31cc4ac70e440e49f9a3695a6fd05f7b2866d4`. Full transaction
measurement, compressed execution, the statement MSM, input/subgroup checks,
and optimization deltas are reported after the remaining stages.
