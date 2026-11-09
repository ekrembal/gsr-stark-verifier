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

## Stage 4 transaction measurement and optimization

The fixed-claim verifier has 746 witness items and 21,460 witness bytes. The
following values were measured with the pinned transaction builder and
interpreter. The uncompressed transaction executes successfully. GSR `check`
reported zero errors, and unrolling the compressed script exactly matched the
anchored script byte-for-byte.

| Metric | Uncompressed transaction | Compressed transaction |
|---|---:|---:|
| Committed verifier Script bytes | 1,559,208 | 117,868 |
| Unrolled/anchored Script bytes | 1,559,208 | 1,562,773 |
| Witness items / bytes | 746 / 21,460 | 746 / 21,460 |
| Transaction weight | 1,581,834 WU | 140,494 WU |
| Transaction varops budget | 15,818,340,000 | 1,404,940,000 |
| Varops | 1,125,192,441 | Not directly available |
| Peak stack entries | 779 | 779 on equivalent Script |
| Peak stack payload | 22,423 bytes | 22,423 bytes on equivalent Script |
| Largest stack element | 65 bytes | 65 bytes on equivalent Script |
| Final stack is exactly true | Pass | Pass on equivalent Script |

The compressed transaction's weight and budget are measured from its actual
transaction. The Tapleaf `0xc2` meter does not understand the compressed GSR
macro opcode: after rebuilding the pinned meter from the pinned Core source,
running the compressed script still returns `Opcode missing or not
understood` after 1,250 varops. The equivalent compressed script passes
`bitcoin-util evalscript`; its GSR check and unroll-equivalence checks pass.
Consequently the varops and stack figures shown for the compressed transaction
come from executing the equivalent uncompressed verifier, not from metering
the macro calls themselves. At 1,125,192,441 varops, that execution fits below
the compressed transaction's measured 1,404,940,000-unit budget. This is not
a direct measurement of compressed-macro varops. The compressed transaction
is below the 400,000 standard weight limit; the uncompressed transaction's
weight is not.

| Limit | Result | Evidence |
|---|---|---|
| 400,000 standard transaction weight | Compressed pass; uncompressed fail | 140,494 / 1,581,834 WU |
| Varops budget | Equivalent Script pass; compressed macro path unavailable | 1,125,192,441 < 1,404,940,000 |
| 4,000,000 unrolled Script bytes | Pass | 1,562,773 bytes |
| Stack entries | Pass | Peak 779 |
| Stack payload | Pass | Peak 22,423 bytes |
| Largest stack element | Pass | Peak 65 bytes |
| Exact true final stack | Pass on equivalent Script | Interpreter result |

The measured post-lazy stage breakdown is:

| Stage | Varops | Script bytes |
|---|---:|---:|
| Canonical/curve/twist/subgroup checks, MSM and claim binding (combined) | 186,475,861 | 458,965 |
| Miller loop and residue-witness final exponent check | 938,716,580 | 1,100,243 |
| Full fixed-claim verifier | 1,125,192,441 | 1,559,208 |

The first row is the measured difference between the full verifier and the
pairing-only script; the available instrumentation does not split input
checks, subgroup checking, MSM and claim binding from one another.

### Measured optimization deltas

| Optimization | Before | After | Result |
|---|---:|---:|---|
| Lazy reduction, complete fixed verifier | 2,039,576,255 varops / 5,747,982 bytes | 1,125,192,441 varops / 1,559,208 bytes | 44.8% fewer varops and 72.9% fewer Script bytes |
| Sparse Fp12 line multiplication, before lazy reduction | 7,241,479 dense / 1,257,951 sparse varops | — | 82.6% fewer varops per Fp12 multiply |
| Sparse Fp12 line multiplication, after lazy reduction | 3,316,878 dense / 711,463 sparse varops | — | 78.5% fewer varops per Fp12 multiply |
| Repeated-block GSR compression | 1,559,208 raw Script bytes | 117,868 committed / 1,562,773 unrolled bytes | 13.23× committed-size reduction; unrolling is byte-identical to the anchored Script |
| Fp hinted quotient microbenchmark | 23,372 varops with `MUL; MOD p` | 26,246 with quotient relation | 12.3% more; not adopted |
| Fp2 Kronecker convolution probe | 80,928 varops for normal lazy Fp2 mul | 185,218 for packed convolution and coefficient extraction | Not adopted; probe costs more and omits full reduction/output handling |

The hinted-quotient and Kronecker figures are isolated interpreter
microbenchmarks, not verifier-level WU deltas. The sparse-multiplication
comparison is also per operation; a dense full-verifier variant was not
generated, so no end-to-end WU delta is claimed. The verifier uses sparse line
multiplication and lazy reduction. Kronecker packing and hinted quotients were
not landed because the measured probes were more expensive. Compression's
macro-call varops were not directly measurable with the current Tapleaf `0xc2`
meter, as detailed above.

| Comparison | Weight | Varops | Committed verifier | Witness |
|---|---:|---:|---:|---:|
| This Groth16 verifier, compressed transaction | 140,494 WU | 1,125,192,441 on equivalent uncompressed execution; compressed path unavailable | 117,868 B | 21,460 B |
| PR #20 STARK verifier | 272,064 WU | 2.32B | 48,776 B | 221,068 B |

PR #20 values are from
<https://github.com/zkpinbtc/gsr-stark-verifier/pull/20>. Its compressed
verifier byte and witness sizes are smaller/larger respectively than the
Groth16 values above; the Groth16 committed Script is larger, while its
compressed transaction weight is lower. The varops comparison is indicative:
the Groth16 number is measured on the equivalent uncompressed Script, not on
the compressed macro execution.
