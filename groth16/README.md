# RISC Zero Groth16 verifier

Final figures are direct measurements of the compressed spend transaction,
using the pinned GSR meter built against Bitcoin Core
`ad6c16ff0214014023ff2a81504048a8850a1c1c`. Neither claim mode uses padding.

## Final measurements

| Metric | Fixed claim | Witness claim |
|---|---:|---:|
| Committed compressed Script | 80,458 B | 80,672 B |
| Unrolled Script | 1,490,285 B | 1,490,840 B |
| Witness items / payload | 2,368 / 54,087 B | 2,369 / 54,119 B |
| Transaction weight | 137,333 WU | 137,580 WU |
| Varops budget | 1,372,830,000 | 1,375,300,000 |
| Varops, compressed execution | 1,170,939,207 | 1,171,753,157 |
| GSR macro references | 158,452 | 158,681 |
| SHA-256 calls / input bytes | 64 / 35,695 B | 64 / 35,695 B |
| Peak stack entries | 2,401 | 2,402 |
| Peak stack payload | 55,050 B | 55,082 B |
| Largest stack element | 824 B | 824 B |
| Interpreter result | Pass (`ok=true`) | Pass (`ok=true`) |
| Final stack contract | Exactly `true` | One truthy 32-byte claim digest |

Witness mode returns the original claim digest in RISC Zero byte order; the
test suite compares it with the fixture digest. Its final stack is intentionally
not the single-byte value `true`.

| Limit | Fixed claim | Witness claim | Limit |
|---|---:|---:|---:|
| Standard transaction weight | Pass | Pass | 400,000 WU |
| Varops budget | Pass | Pass | 1,372,830,000 / 1,375,300,000 |
| Unrolled Script size | Pass | Pass | 4,000,000 B |
| Peak stack entries | Pass | Pass | 32,768 |
| Peak live stack payload | Pass | Pass | 8,000,000 B |
| Largest stack element | Pass | Pass | 4,000,000 B |
| `OP_SUCCESS` absent | Pass | Pass | Required |
| Script evaluation | Pass | Pass | `ok=true`, one truthy result |

| Comparison | Weight | Varops | Committed verifier | Witness |
|---|---:|---:|---:|---:|
| This Groth16 verifier, fixed claim | 137,333 WU | 1,170,939,207 | 80,458 B | 54,087 B |
| This Groth16 verifier, witness claim | 137,580 WU | 1,171,753,157 | 80,672 B | 54,119 B |
| [PR #20 STARK verifier](https://github.com/zkpinbtc/gsr-stark-verifier/pull/20) | 272,064 WU | 2.32B | 48,776 B | 221,068 B |

The fixed-claim varops margin is 201,890,793; the witness-claim margin is
203,546,843. Both spends fit without padding. The current result is about half
PR #20's WU and varops, but it does not reach the later optimization target of
less than 100,000 WU, 0.7B varops, or 50 KB committed Script.

## How it works

The fixture is a real RISC Zero 3.0.6 Groth16 receipt produced with
`ProverOpts::groth16()` and verified natively with `Receipt::verify`. The
verifier is dynamic: proof points A/B/C, B-line slopes, residue witnesses
`c`, `c⁻¹`, and `wi`, and (in witness mode) the claim digest are witness data,
not compiled proof values.

The checked pairing relation is
`e(A, B) · e(−L, γ) · e(−C, δ) = e(α, β)`. Script checks canonical field
encodings, G1 curve membership for A/C/L, B's BN254 twist membership and G2
subgroup criterion, affine slope hints, and the residue-witness relation.
Fixed `a0`, `a1`, and `bn254_control_id` are folded into the constant part of
L; two 4-bit, 32-window tables compute the variable `c0·IC3 + c1·IC4` term.
Fixed mode binds both claim scalars to the fixture. Witness mode checks the
supplied digest bytes against those scalars and returns the digest for covenant
composition.

The Miller loop uses the signed NAF schedule for BN254's optimal-ate loop,
D-twist line placement, fixed gamma/delta/beta line schedules, and the final
Frobenius-twisted additions. The B-line slopes are checked by multiplication,
without inversions. Fixed line coefficients are witness items, bound by a
domain-separated SHA-256 chain with a length prefix for every encoded
coefficient; the chain is checked against a Script constant. The length prefixes
bind item boundaries, so the hash fixes each canonical encoding without
separate range checks on these fixed coefficients. The NAF loop has three
byte-identical step classes (double, double+add for each sign); its accumulator
and point are carried through a fixed altstack layout. The final Frobenius line
coefficients remain Script constants.

The residue witness checks `c·c⁻¹ = 1`, folds the inverse Miller factor into
the loop, applies the Frobenius powers, and checks the result against `wi`. The
formulas follow BitVM commit `c620dbfaacebdf778e765a6681985350389973b1`:
`bitvm/src/bn254/ell_coeffs.rs`, `bitvm/src/bn254/pairing.rs`, and
`bitvm/src/groth16/offchain_checker.rs::compute_c_wi`.

### Cost model and operation profile

`tools/cost.py` models the compressed transaction with the ad6c16ff formulas:
300 varops per opcode; `WriteCost(n) = 800 + 7·wordspan(n)`;
`ReadCost(n) = 350 + 2·wordspan(n)`; `MoveCost(d) = 200 + 23d`;
`MulCost(n,m) = 700 + n + 18m + n·m` plus the product write; trimmed operand
sizes for MOD; and the macro-unroll precharge. The fixed-claim result is
1,170,939,207 model varops versus 1,170,939,207 meter varops, with identical
opcode counts (difference 0).

| Fixed-claim stage | Varops |
|---|---:|
| Input checks | 152,060,140 |
| Claim MSM | 22,987,894 |
| Pairing preamble | 4,766,966 |
| Miller loop | 756,374,097 |
| Finalization | 24,433,528 |
| Macro-unroll precharge | 210,316,216 |
| Final stack check | 366 |
| **Total** | **1,170,939,207** |

The largest opcode costs are MUL at 262,675,020 varops, macro-unroll
precharge at 210,316,216, PICK at 197,383,934, ADD at 98,700,472, MOD at
63,477,374, and ROLL at 43,196,632. This profile includes the step hash
length-prefixing and the fixed stack schedule.

Standalone field-operation microbenchmarks use one random canonical input per
operation. These are per-operation varops, not whole-transaction deltas:

| Field | Add | Sub | Mul | Square | Frobenius p | Sparse mul | Line mul |
|---|---:|---:|---:|---:|---:|---:|---:|
| Fp | 16,212 | 21,500 | 23,946 | 26,542 | 15,828 | 23,946 | — |
| Fp2 | 33,722 | 44,298 | 79,662 | 84,886 | 38,524 | 79,662 | — |
| Fp6 | 98,698 | 130,426 | 807,354 | 823,038 | 249,262 | 355,734 | — |
| Fp12 | 196,174 | 259,630 | 3,315,612 | 3,347,310 | 569,176 | 706,399 | 1,174,327 |

### Reproduction

Install dependencies with `python3 -m pip install -r requirements.txt`. The
compression wrapper is copied unchanged from PR #20's
`risc0-succinct/tools/gsr_tooling.py`; it uses GSR tooling revision
`bf31cc4ac70e440e49f9a3695a6fd05f7b2866d4`. Install that revision with:

```sh
cargo install --locked --git https://github.com/bitcoin-gsr/gsr-tooling --rev bf31cc4ac70e440e49f9a3695a6fd05f7b2866d4
```

or set `GSR` to the binary path. Generate both compressed bundles and meter
them directly with a Core ad6c16ff meter:

```sh
python tools/generate.py --claim fixed --compress --out build/fixed.json
python tools/generate.py --claim witness --compress --out build/witness.json
GSR_METER=/path/to/ad6c16ff-gsr-meter python tools/measure.py build/fixed.json
GSR_METER=/path/to/ad6c16ff-gsr-meter python tools/measure.py build/witness.json
GSR_METER=/path/to/ad6c16ff-gsr-meter python tools/cost.py build/fixed.json
```

`tools/generate.py` checks GSR `compress`, `unroll`, and `check` equivalence.
Run `PYTHON=/path/to/python bash tools/test.sh` for the Python reference,
field and pairing differential tests, tamper checks, byte-identical Miller
steps, compression equivalence, and native fixture verification.

### Security notes

BN254 is not post-quantum: an attacker able to solve its discrete-log problem
can forge proofs and steal covenant funds. The verifier relies on RISC Zero's
Groth16 trusted setup and on SHA-256 collision resistance for the fixed
line-coefficient binding. It checks canonical encodings, G1 curve membership,
the G2 twist and subgroup, and the claim binding described above. The fixture
is an example proof, not a trusted setup contribution.

## Optimization history

Transaction figures below are direct compressed fixed-claim measurements. A
dash means no retained candidate delta; rejected probes are labeled as
standalone rather than presented as transaction results.

| Step | Change or probe | Before | After | Result |
|---|---|---|---|---|
| 0 | Static cost model | — | 1,170,939,207 model / meter varops; opcode counts match | Validated exactly on the final compressed transaction |
| 1a | Lazy sums and deferred reductions | Step 1d baseline | No retained change | Candidate regressed on compressed cost; reverted (candidate totals were not retained) |
| 1b | Symmetric Fp12 square | Step 1d baseline | No retained change | Candidate increased compressed WU; reverted (candidate totals were not retained) |
| 1c | Shallow copies and fewer deep picks | 140,494 WU / 1,233,221,358 varops / 117,868 B | 140,476 WU / 1,218,605,654 varops / 117,850 B | Retained; −18 WU, −14,615,704 varops, −18 B |
| 1d | Normalized sparse line coefficients | 140,476 WU / 1,218,605,654 varops / 117,850 B | 140,406 WU / 1,131,526,042 varops / 117,780 B | Retained; −70 WU, −87,079,612 varops, −70 B |
| 1d probe | Combine sparse lines before dense multiply | 3,519,061 varops for separate lines | 3,567,975 (two combined); 5,395,912 (three combined) | Standalone probe; rejected as more expensive |
| 1e | Revisit `c`/`c⁻¹` factors | — | No retained change | No safe NAF or final Frobenius multiplication was eliminated |
| 2 | Witness-bound fixed lines; identical Miller steps | 140,406 WU / 1,131,526,042 varops / 117,780 B | 137,333 WU / 1,170,939,207 varops / 80,458 B | −3,073 WU and −37,322 B, but +39,413,165 varops; 3 byte-identical step classes |
| 2 check | Input-check/MSM repeated-block inspection | 766 canonical checks; 3 G1 checks; 64 table selects and 64 window adds | All blocks byte-unique | No safe repeated block to hoist; table constants differ by window |
| Probe | Hinted quotient | 23,372 varops (`MUL; MOD`) | 26,246 varops | Standalone Fp probe; not adopted |
| Probe | Kronecker-packed Fp2 | 80,928 varops | 185,218 varops | Standalone probe, without the full reduction/output path; not adopted |

The line-binding change moves fixed coefficient bytes from Script pushes into
the witness. The fixed claim therefore has 32,627 more witness payload bytes
than the Step 1d result, while committed Script falls by 37,322 B. The final
transaction weight is lower by 3,073 WU; the varops increase is reported above.
Moving the fixed MSM tables into witness data was not attempted: those
per-window point constants account for roughly 65 KB, so a simple move would
not reduce total spend bytes.
