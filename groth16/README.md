# RISC Zero Groth16 verifier

Final figures are direct measurements of the compressed spend transaction,
using the pinned GSR meter built against Bitcoin Core
`ad6c16ff0214014023ff2a81504048a8850a1c1c`. Neither claim mode uses padding.

## Final measurements

| Metric | Fixed claim | Witness claim |
|---|---:|---:|
| Committed compressed Script | 79,884 B | 80,100 B |
| Unrolled Script | 1,322,069 B | 1,322,624 B |
| Witness items / payload | 2,234 / 47,561 B | 2,235 / 47,593 B |
| Transaction weight | 130,099 WU | 130,348 WU |
| Varops budget | 1,300,490,000 | 1,302,980,000 |
| Varops, compressed execution | 1,065,748,388 | 1,066,553,068 |
| GSR macro references | 142,010 | 142,238 |
| SHA-256 calls / input bytes | 64 / 35,695 B | 64 / 35,695 B |
| Peak stack entries | 2,271 | 2,272 |
| Peak stack payload | 48,652 B | 48,684 B |
| Largest stack element | 824 B | 824 B |
| Interpreter result | Pass (`ok=true`) | Pass (`ok=true`) |
| Final stack contract | Exactly `true` | One truthy 32-byte claim digest |

Witness mode returns the original claim digest in RISC Zero byte order; the
test suite compares it with the fixture digest. Its final stack is intentionally
not the single-byte value `true`.

| Limit | Fixed claim | Witness claim | Limit |
|---|---:|---:|---:|
| Standard transaction weight | Pass | Pass | 400,000 WU |
| Varops budget | Pass | Pass | 1,300,490,000 / 1,302,980,000 |
| Unrolled Script size | Pass | Pass | 4,000,000 B |
| Peak stack entries | Pass | Pass | 32,768 |
| Peak live stack payload | Pass | Pass | 8,000,000 B |
| Largest stack element | Pass | Pass | 4,000,000 B |
| `OP_SUCCESS` absent | Pass | Pass | Required |
| Script evaluation | Pass | Pass | `ok=true`, one truthy result |

| Comparison | Weight | Varops | Committed verifier | Witness |
|---|---:|---:|---:|---:|
| This Groth16 verifier, fixed claim | 130,099 WU | 1,065,748,388 | 79,884 B | 47,561 B |
| This Groth16 verifier, witness claim | 130,348 WU | 1,066,553,068 | 80,100 B | 47,593 B |
| [PR #20 STARK verifier](https://github.com/zkpinbtc/gsr-stark-verifier/pull/20) | 272,064 WU | 2.32B | 48,776 B | 221,068 B |

The fixed-claim varops margin is 234,741,612; the witness-claim margin is
236,426,932. Both spends fit without padding. The current result is about half
PR #20's WU and varops, but it does not reach the later optimization target of
less than 100,000 WU, 0.7B varops, or 50 KB committed Script.

### Compressed Script bytes by stage

Macro-definition bytes are attributed to stages in proportion to the expanded
bytes of their invocations in each stage. Main-body bytes, including inline
instructions and macro call sites, are attributed by the expanded execution
span. This allocation is reproducible with `tools/breakdown.py`; each column
totals to the directly measured compressed Script size.

| Claim | Stage | Macro definitions | Main body / call sites | Committed bytes |
|---|---|---:|---:|---:|
| Fixed | Input checks | 45 B | 2,897 B | 2,942 B |
| Fixed | G2 subgroup | 631 B | 270 B | 901 B |
| Fixed | MSM / window tables | 158 B | 69,001 B | 69,159 B |
| Fixed | Miller | 3,538 B | 520 B | 4,058 B |
| Fixed | Final | 828 B | 1,996 B | 2,824 B |
| Witness | Input checks | 45 B | 2,897 B | 2,942 B |
| Witness | G2 subgroup | 629 B | 270 B | 899 B |
| Witness | MSM / window tables | 194 B | 69,185 B | 69,379 B |
| Witness | Miller | 3,540 B | 520 B | 4,060 B |
| Witness | Final | 828 B | 1,992 B | 2,820 B |

### Witness payload by category

| Category | Fixed claim | Witness claim |
|---|---:|---:|
| Proof points A/B/C | 256 B | 256 B |
| Slopes (Miller, subgroup, MSM) | 13,561 B | 13,561 B |
| Fixed line coefficients | 32,627 B | 32,627 B |
| Line-binding witness bytes | 0 B | 0 B |
| Residue values (`c`, `c⁻¹`, `wi`) | 769 B | 769 B |
| Window digits | 60 B | 60 B |
| Everything else | 288 B | 320 B |
| **Total** | **47,561 B** | **47,593 B** |

The line hash and initial domain hash are 64 Script-constant bytes, not witness
payload. The meter reports 64 SHA-256 calls and 35,695 input bytes.

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
The G2 check uses gnark-crypto's BN254 Frobenius relation
`[x₀+1]B + ψ([x₀]B) + ψ²([x₀]B) = ψ³([2x₀]B)`, with the 63-bit
`x₀ = 4965661367192848881`. Script computes `[x₀]B` once (62 doubles and 27
double-add steps), forms `[x₀+1]B` with one addition, and obtains `[2x₀]B`
with one doubling. Its two byte-identical scalar-step classes and the final
relation additions use witness slope hints checked by Script. The Python
reference accepted 200 random G2 points and rejected 200 random on-twist
non-subgroup points, agreeing with `[r]B = ∞` on all 400 samples.
Affine exceptional cases are rejected: doubles require `2y ≠ 0`, and additions
require distinct x-coordinates. For honest finite subgroup B, every scalar
prefix is nonzero and below r. On that subgroup `ψ` acts by
`λ = 6x₀² mod r`; integer checks give `x₀ ≠ ±1`,
`x₀+1 ≠ ±x₀λ`, and `x₀+1+x₀λ ≠ ±x₀λ² mod r`, so the fixed relation
additions are neither equal nor opposite. Infinity has no affine witness
encoding.
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
1,065,748,388 model varops versus 1,065,748,388 meter varops, with identical
opcode counts (difference 0).

| Fixed-claim stage | Varops |
|---|---:|
| Input checks | 5,766,910 |
| G2 subgroup | 60,922,179 |
| MSM / window tables | 23,005,558 |
| Miller, including pairing preamble | 761,636,759 |
| Final | 24,446,412 |
| Macro-unroll precharge | 189,970,204 |
| Final stack check | 366 |
| **Total** | **1,065,748,388** |

The largest opcode costs are MUL at 255,961,412 varops, macro-unroll
precharge at 189,970,204, PICK at 183,121,554, ADD at 93,316,344, MOD at
55,961,470, and ROLL at 23,926,259. This profile includes the step hash
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
python tools/breakdown.py --claim fixed --bundle build/fixed.json
python tools/breakdown.py --claim witness --bundle build/witness.json
```

`tools/generate.py` checks GSR `compress`, `unroll`, and `check` equivalence.
Run `PYTHON=/path/to/python bash tools/test.sh` for the Python reference,
400-point G2 subgroup relation test, field and pairing differential tests,
tamper checks, byte-identical Miller and subgroup steps, compression
equivalence, and native fixture verification.

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
| 0 | Static cost model | — | 1,170,939,207 model / meter varops; opcode counts match | Validated exactly at the Round 1 baseline |
| Round 2 B | 63-bit Frobenius G2 subgroup relation | 137,333 WU / 1,170,939,207 varops / 80,458 B | 130,099 WU / 1,065,748,388 varops / 79,884 B | Retained; −7,234 WU, −105,190,819 varops, −574 B |
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
