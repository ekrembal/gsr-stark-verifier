# RISC Zero Groth16 verifier

Final figures are direct measurements of the compressed spend transaction,
using the pinned GSR meter built against Bitcoin Core
`ad6c16ff0214014023ff2a81504048a8850a1c1c`. Both transactions include a real
Taproot annex to fund the measured execution under the weight-derived varops
budget. The annex is transaction weight, not Script witness data, and is
excluded from the verifier witness payload below.

## Final measurements

| Metric | Fixed claim | Witness claim |
|---|---:|---:|
| Committed compressed Script | 13,589 B | 13,824 B |
| Unrolled Script | 1,361,457 B | 1,362,013 B |
| Verifier witness items / payload | 2,618 / 52,707 B | 2,619 / 52,739 B |
| Taproot annex bytes | 35,190 B | 34,994 B |
| Transaction weight without annex | 69,332 WU | 69,600 WU |
| Annex-funded transaction weight | 104,525 WU | 104,597 WU |
| Varops budget | 1,044,750,000 | 1,045,470,000 |
| Varops, compressed execution | 1,044,742,987 | 1,045,467,295 |
| GSR macro references | 145,762 | 145,733 |
| SHA-256 calls / input bytes | 64 / 35,695 B | 64 / 35,695 B |
| Peak stack entries | 2,655 | 2,656 |
| Peak stack payload | 53,798 B | 53,830 B |
| Largest stack element | 824 B | 824 B |
| Interpreter result | Pass (`ok=true`) | Pass (`ok=true`) |
| Final stack contract | Exactly `true` | One truthy 32-byte claim digest |

Witness mode returns the original claim digest in RISC Zero byte order; the
test suite compares it with the fixture digest. Its final stack is intentionally
not the single-byte value `true`.
The annex-funded weights are the minimum measured transaction weights that
cover each execution. The no-annex weights are insufficient: the meter's
budget is `transaction_weight × 10,000 − 500,000` varops.

| Limit | Fixed claim | Witness claim | Limit |
|---|---:|---:|---:|
| Standard transaction weight | Pass | Pass | 400,000 WU |
| Varops budget | Pass | Pass | 1,044,750,000 / 1,045,470,000 |
| Unrolled Script size | Pass | Pass | 4,000,000 B |
| Peak stack entries | Pass | Pass | 32,768 |
| Peak live stack payload | Pass | Pass | 8,000,000 B |
| Largest stack element | Pass | Pass | 4,000,000 B |
| `OP_SUCCESS` absent | Pass | Pass | Required |
| Script evaluation | Pass | Pass | `ok=true`, one truthy result |

| Comparison | Weight | Varops | Committed verifier | Witness |
|---|---:|---:|---:|---:|
| This Groth16 verifier, fixed claim | 104,525 WU | 1,044,742,987 | 13,589 B | 52,707 B |
| This Groth16 verifier, witness claim | 104,597 WU | 1,045,467,295 | 13,824 B | 52,739 B |
| [PR #20 STARK verifier](https://github.com/zkpinbtc/gsr-stark-verifier/pull/20) | 272,064 WU | 2.32B | 48,776 B | 221,068 B |

The fixed-claim varops margin is 7,013; the witness-claim margin is 2,705.
Relative to PR #20, the fixed-claim spend is 61.6% lower in weight, 55.0%
lower in varops, and 72.1% smaller in committed Script, but it does not reach
the requested targets of less than 100,000 WU and 0.7B varops. It does meet
the 50 KB committed-Script target.

### Compressed Script bytes by stage

Macro-definition bytes are attributed to stages in proportion to the expanded
bytes of their invocations in each stage. Main-body bytes, including inline
instructions and macro call sites, are attributed by the expanded execution
span. This allocation is reproducible with `tools/breakdown.py`; each column
totals to the directly measured compressed Script size.

| Claim | Stage | Macro definitions | Main body / call sites | Committed bytes |
|---|---|---:|---:|---:|
| Fixed | Input checks | 45 B | 3,896 B | 3,941 B |
| Fixed | G2 subgroup | 716 B | 342 B | 1,058 B |
| Fixed | Claim MSM (Shamir) | 639 B | 152 B | 791 B |
| Fixed | Miller | 4,396 B | 530 B | 4,926 B |
| Fixed | Final | 936 B | 1,937 B | 2,873 B |
| Witness | Input checks | 45 B | 3,897 B | 3,942 B |
| Witness | G2 subgroup | 715 B | 344 B | 1,059 B |
| Witness | Claim MSM (Shamir) | 676 B | 344 B | 1,020 B |
| Witness | Miller | 4,400 B | 530 B | 4,930 B |
| Witness | Final | 936 B | 1,937 B | 2,873 B |

### Witness payload by category

| Category | Fixed claim | Witness claim |
|---|---:|---:|
| Proof points A/B/C | 256 B | 256 B |
| Slopes (Miller, subgroup, MSM) | 18,642 B | 18,642 B |
| Fixed line coefficients plus binding | 32,627 B | 32,627 B |
| Residue values (`c`, `c⁻¹`, `wi`) | 769 B | 769 B |
| Shamir bits | 125 B | 125 B |
| Everything else | 288 B | 320 B |
| **Total** | **52,707 B** | **52,739 B** |

| Binding bytes | Fixed claim | Witness claim |
|---|---:|---:|
| Witness binding bytes | 0 B | 0 B |
| Hash and domain constants in Script | 64 B | 64 B |

The line hash and initial domain hash are Script-constant bytes, not witness
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
L. A Shamir joint double-and-add computes `c0·IC3 + c1·IC4`: both 128-bit
scalars are decomposed into boolean-checked bits, recomposed in Script, and
jointly select `0`, `IC3`, `IC4`, or `IC3+IC4`. The fixed point K is folded
into the initial accumulator as `[2⁻¹²⁸]K. The 128 step bodies are
byte-identical. Fixed mode binds both claim scalars to the fixture; witness
mode checks the supplied digest bytes against those scalars, preserving their
RISC Zero byte order, and returns the digest for covenant composition.

The Miller loop uses the signed NAF schedule for BN254's optimal-ate loop,
D-twist line placement, fixed gamma/delta/beta line schedules, and the final
Frobenius-twisted additions. The B-line slopes are checked by multiplication,
without inversions. Fixed line coefficients are witness items, bound by a
domain-separated SHA-256 chain with a length prefix for every encoded
coefficient; the chain is checked against a Script constant. The length prefixes
bind item boundaries, so the hash fixes each canonical encoding without
separate range checks on these fixed coefficients. The NAF loop has three
byte-identical step classes (double, double+add for each sign); its accumulator
and point are carried through a fixed altstack layout. Under lazy arithmetic,
the point coordinates are reduced at each step boundary so the next macro has
the same bounds and bytecode. The final Frobenius line coefficients remain
Script constants.

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
sizes for MOD; and the macro-unroll precharge. It follows executed `IF` /
`ELSE` branches using the supplied Python-twin witness. With the fixed-claim
bundle and its measured annex size, it reports 1,044,742,987 model varops
versus 1,044,742,987 meter varops, with identical opcode counts (difference 0).

| Fixed-claim stage | Varops |
|---|---:|
| Input checks | 7,221,214 |
| G2 subgroup | 59,261,043 |
| Claim MSM (Shamir) | 57,348,657 |
| Miller | 700,136,151 |
| Final | 24,326,808 |
| Macro-unroll precharge | 196,448,748 |
| Final stack check | 366 |
| **Total** | **1,044,742,987** |

The largest opcode costs are MUL at 213,796,696 varops, macro-unroll
precharge at 196,448,748, PICK at 173,439,442, ADD at 102,915,520, MOD at
58,791,250, and ROLL at 23,334,794. The fixed-claim runtime is 848,293,873
varops before macro-unroll and final-stack checks.

Standalone field-operation microbenchmarks use deterministic random canonical
inputs and the final lazy-add/symmetric-square emitters. These are
per-operation varops, not whole-transaction deltas:

| Field | Add | Sub | Mul | Square | Frobenius p | Sparse mul | Line mul |
|---|---:|---:|---:|---:|---:|---:|---:|
| Fp | 10,480 | 15,768 | 23,946 | 26,542 | 15,828 | 23,946 | — |
| Fp2 | 22,258 | 32,834 | 79,662 | 84,886 | 38,524 | 79,662 | — |
| Fp6 | 64,306 | 96,034 | 807,357 | 823,038 | 249,262 | 355,740 | — |
| Fp12 | 127,396 | 190,852 | 3,315,003 | 2,136,559 | 569,164 | 706,453 | 1,174,309 |

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
GSR_METER=/path/to/ad6c16ff-gsr-meter python tools/measure.py build/fixed.json --annex-bytes 35190
GSR_METER=/path/to/ad6c16ff-gsr-meter python tools/measure.py build/witness.json --annex-bytes 34994
GSR_METER=/path/to/ad6c16ff-gsr-meter python tools/cost.py build/fixed.json --annex-bytes 35190
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

Transaction WU and varops below come from the compressed transaction itself;
WU includes any annex used to fund varops, while committed Script bytes exclude
the annex. The earlier pre-macro attempts at lazy sums and symmetric squaring
did not retain candidate totals; their macro-based retries are measured below.

| Step | Change or candidate | Before: WU / varops / compressed B | After: WU / varops / compressed B | Result |
|---|---|---|---|---|
| Round 1 model | Static cost model | — | 137,333 / 1,170,939,207 / 80,458; model matched meter | Exact opcode-level validation |
| Round 1 1c | Shallow copies, fewer deep picks | 140,494 / 1,233,221,358 / 117,868 | 140,476 / 1,218,605,654 / 117,850 | Retained; −18 WU, −14,615,704 varops, −18 B |
| Round 1 1d | Normalized sparse line coefficients | 140,476 / 1,218,605,654 / 117,850 | 140,406 / 1,131,526,042 / 117,780 | Retained; −70 WU, −87,079,612 varops, −70 B |
| Round 1 1d probe | Combine sparse lines before dense multiplication | 3,519,061 varops, separate lines | 3,567,975 for two combined; 5,395,912 for three combined | Standalone probe; rejected |
| Round 1 1e | Revisit `c` / `c⁻¹` factors | 140,406 / 1,131,526,042 / 117,780 | No code change | No safe NAF or final Frobenius multiplication eliminated |
| Round 1 2 | Bind fixed lines in witness; identical Miller steps | 140,406 / 1,131,526,042 / 117,780 | 137,333 / 1,170,939,207 / 80,458 | −3,073 WU, −37,322 B, but +39,413,165 varops; retained |
| Round 1 check | Canonical/input/MSM repeat scan | 766 canonical checks; 3 G1 checks; 64 table selects and 64 window adds | Blocks byte-unique | No safe repeat to hoist; table constants differ by window |
| Earlier 1a / 1b | Lazy sums / symmetric Fp12 square, before macro steps | Totals not retained | Totals not retained | Reverted; Round 2 retries below are measured |
| Round 2 B | 63-bit Frobenius G2 subgroup relation | 137,333 / 1,170,939,207 / 80,458 | 130,099 / 1,065,748,388 / 79,884 | Retained; −7,234 WU, −105,190,819 varops, −574 B |
| Round 2 C | Shamir joint MSM, witness bits and hinted slopes | 130,099 / 1,065,748,388 / 79,884 | 112,138 / 1,120,875,613 / 12,306 | Retained; −17,961 WU and −67,578 B, but +55,127,225 varops |
| Round 2 D | Uniform canonical-check macro | 112,138 / 1,120,875,613 / 12,306 | 112,377 / 1,123,266,453 / 12,359 | Rejected and reverted; +239 WU, +2,390,840 varops, +53 B |
| Round 2 E1b | Symmetric Fp12 square (78 products) | 112,138 / 1,120,875,613 / 12,306 | 105,132 / 1,050,811,493 / 13,215 | Retained; −7,006 WU, −70,064,120 varops, +909 B |
| Round 2 E1a | Lazy add/sub with tracked bounds | 105,132 / 1,050,811,493 / 13,215 | 104,525 / 1,044,742,987 / 13,589 | Retained; −607 WU, −6,068,506 varops, +374 B |
| Probe | Hinted quotient | 23,372 varops (`MUL; MOD`) | 26,246 varops | Standalone Fp probe; not adopted |
| Probe | Kronecker-packed Fp2 | 80,928 varops | 185,218 varops | Standalone probe without full reduction/output; not adopted |

The corresponding witness-mode before/after totals were: C,
130,348 / 1,066,553,068 / 80,100 → 112,215 / 1,121,641,077 / 12,535
(−18,133 WU, +55,088,009 varops, −67,565 B); D,
112,215 / 1,121,641,077 / 12,535 → 112,458 / 1,124,074,817 / 12,587
(+243 WU, +2,433,740 varops, +52 B); E1b,
112,215 / 1,121,641,077 / 12,535 → 105,208 / 1,051,575,457 / 13,445
(−7,007 WU, −70,065,620 varops, +910 B); E1a,
105,208 / 1,051,575,457 / 13,445 → 104,597 / 1,045,467,295 / 13,824
(−611 WU, −6,108,162 varops, +379 B). D's uniform macro was reverted; the
noncanonical tamper test remains. The final fixed-line hash binding uses
64 Script-constant bytes and no binding witness bytes.
