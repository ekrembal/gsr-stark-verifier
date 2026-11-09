# RISC Zero Groth16 verifier

This directory contains the RISC Zero Groth16 fixture, its pure-Python BN254
reference, and the Stage 1 Script field emitters intended for the dynamic
Tapleaf verifier. The fixture is a real Groth16 receipt from RISC Zero 3.0.6;
`tools/native` verifies it with `Receipt::verify`. See `fixtures/README.md`
for seal layout and the five public-input order.

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
coefficients. These are correctness-first algebraic emitters; the subsequent
verifier stages will determine which reductions and multiplication strategies
are suitable for the complete pairing script.

## Reproduction

Install Python dependencies with `python3 -m pip install -r requirements.txt`.
Run `tools/test.sh` from this directory. The GSR compression wrapper is copied
unchanged from PR #20's `risc0-succinct/tools/gsr_tooling.py`; it uses GSR
tooling revision `bf31cc4ac70e440e49f9a3695a6fd05f7b2866d4`.
