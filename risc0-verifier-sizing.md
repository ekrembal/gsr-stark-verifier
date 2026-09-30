# Sizing a BabyBear FRI verifier for the RISC Zero seal

[`risc0-measurement.md`](risc0-measurement.md) priced the *hashing* of a real RISC Zero v3.0.6
succinct receipt and found it cheap: 30.5M varops, 0.76% of a maximal standard spend. It left two
questions open. This note answers both, then revisits the second with metered Script kernels.

1. RISC Zero's `"sha-256"` suite is the raw compression function, so `OP_SHA256` cannot reproduce
   its digests. A padded suite plus regenerated control IDs was inferred to be enough. **It is:** a
   `"sha-256-padded"` suite was implemented and a genuine succinct receipt proven and verified under
   it, with no change to the recursion circuit, no change to seal size, and identical hash counts.
2. Hashing is a lower bound that ignores field arithmetic. With every BabyBear operation in the
   verifier counted and priced as one scalar modular opcode each, the verifier needs 8,386,531,106
   varops — 210% of what a maximal 400,000 WU spend funds. Hashing is 0.36% of that total.
3. That scalar pricing is not a lower bound on a Script verifier, because GSR's per-opcode charge
   dominates it and one opcode can operate on many packed field elements. **Section 5 meters real
   packed Tapscript v2 kernels and projects an optimised verifier at 1,586,610,518 varops**, 40% of
   a maximal spend and 71% of the budget the seal's own weight contributes. That is a projection
   composed from metered kernels, not a measured verifier: no complete verifier script exists yet.

Reproduction and raw artifacts: [`research/risc0/README.md`](research/risc0/README.md).

## 1. The padded SHA-256 suite

`sha-256-padded` hashes exactly what GSR's `OP_SHA256` hashes:

- `hash_pair(a, b)` is `SHA256(a.bytes || b.bytes)` over the 64-byte concatenation, with FIPS
  padding and the length trailer, rather than `compress(SHA256_INIT, a, b)`.
- `hash_elem_slice` / `hash_ext_elem_slice` are `SHA256` over the serialized field elements, rather
  than an unpadded Merkle–Damgård walk.
- The Fiat–Shamir RNG uses the same padded pair hash for its pool transitions.

A unit test pins the equivalence: `SHA256("abc")` against the FIPS vector, padded pair hashing
against `Sha256::hash_bytes` over the 64-byte preimage, padded slice hashing against
`Sha256::hash_bytes` over the serialized bytes, and the stock suite differing from all of them.

Control IDs are derived at runtime with `Program::compute_control_id` under the padded suite, since
the shipped `SHA256_CONTROL_IDS` are for the raw suite. The identity recursion program's padded
control ID is `a71e992ab67b268768f93eb47135e9ebbc8dc24f3622ab156c1e82ea4f19f062`, against
`d7ecd18c7d06fc468166147cf20869aa10f32e097a0c166146a5a62dd2d975ea` for the stock suite.

A three-segment aggregate was re-proven through `Prover::new_identity` under the padded suite and
verified with `verify_integrity_with_context`:

| | stock `sha-256` | `sha-256-padded` |
| --- | --- | --- |
| Succinct seal | 222,668 B | 222,668 B |
| Serialized `Receipt` | 223,224 B | 223,231 B |
| Digest-pair hashes to verify | 4,363 | 4,363 |
| Slice hashes to verify | 355, over 86,028 B | 355, over 86,028 B |
| Poseidon2 permutations to verify | 0 | 0 |

So the inference held: the hash suite is a verifier-side parameter of the outer layer, the recursion
circuit is unchanged, the seal is the same size, and the verifier does the same amount of hash work
— now in a form a Script verifier can reproduce with `OP_CAT` and `OP_SHA256`. The receipt is seven
bytes longer only because the metadata records the longer hash-function name.

## 2. What the verifier actually computes

Counters were added to the BabyBear base and extension operators and attributed to four phases,
enabled only around verification. Base counters include the base operations performed inside
extension operations, so they are the complete arithmetic:

| Phase | mul | add | sub | ext inv |
| --- | ---: | ---: | ---: | ---: |
| Setup and mixing | 152,942 | 110,016 | 4 | 0 |
| Constraint evaluation | 138,453 | 108,600 | 5,540 | 0 |
| FRI folding (50 queries × 3 rounds) | 259,376 | 176,000 | 19,200 | 0 |
| DEEP-ALI per query (50 queries) | 136,589 | 85,400 | 6,900 | 300 |
| **Total** | **687,360** | **480,016** | **31,644** | **300** |

The same verification under the stock Poseidon2 suite costs 9,636,610 multiplications, because the
5,693 permutations are themselves field arithmetic — a 14x difference that is the arithmetic-side
restatement of the hash-side result.

### The shape behind those counts

[`research/risc0/fri-structure.py`](research/risc0/fri-structure.py) derives the proof's Merkle and
FRI structure from the pinned constants — `QUERIES = 50`, `INV_RATE = 4`, `FRI_FOLD = 16`,
`FRI_MIN_DEGREE = 256`, `RECURSION_PO2 = 18`, and the 643-tap recursion tap set — and reproduces the
measured hash counts exactly:

```
po2 18, 262144 cycles, evaluation domain 1048576
3 FRI rounds, final degree 64, 256 final coefficients

tree                rows   cols   top  path
accum            1048576     12    32    15
code             1048576     23    32    15
data             1048576    128    32    15
check            1048576     16    32    15
fri round 0        65536     64    32    11
fri round 1         4096     64    32     7
fri round 2          256     64    32     3

setup pairs 217, 81 path pairs per query
predicted digest pairs     4267  measured    4363  delta    96  (Fiat-Shamir rng steps, 2 pairs each)
predicted slice hashes      355  measured     355  delta     0
predicted slice bytes     86028  measured   86028  delta     0
```

So a Script verifier has to do, per query: seven Merkle branches totalling 81 parent hashes and
seven leaf hashes, one DEEP-ALI combination over 163 tap columns and the 16-column check row, three
16-point NTT interpolations with their folds, and one evaluation of the 64-coefficient final
polynomial. Once, outside the query loop: 217 parent hashes to build the seven tree tops, the
2,636-element DEEP coefficient hash, and the 12,359-step recursion constraint program evaluated at
the DEEP point `z`.

That constraint program is the part with no loop structure to exploit: 4,679 multiplications, 4,061
additions, 1,385 subtractions, 1,076 `AndEqz` and 152 `AndCond` mix steps, generated straight-line
in `poly_ext.rs`. In Script it is a 12,359-entry program interpreted by a loop, so it costs script
bytes for the table and varops for every step.

## 3. Pricing against GSR

From [`research/risc0/fri-costs.txt`](research/risc0/fri-costs.txt), pricing each counted field
operation as one modular operation on 4-byte operands with the pinned varops functions (a BabyBear
multiplication is 7,720 varops, an addition 5,802, a subtraction 8,362, a SHA-256 Merkle parent
5,892):

| Verifier work | Varops | Of budget |
| --- | ---: | ---: |
| Arithmetic: setup and mixing | 1,819,058,520 | 45.48% |
| Arithmetic: constraint evaluation | 1,745,279,840 | 43.63% |
| Arithmetic: FRI folding | 3,184,085,120 | 79.60% |
| Arithmetic: DEEP-ALI per query | 1,607,655,680 | 40.19% |
| Hashing: padded SHA-256, all phases | 30,451,946 | 0.76% |
| **Total, primitive lower bound** | **8,386,531,106** | **209.66%** |
| Total, x4.05 calibrated projection | 33,965,450,979 | 849.14% |
| Total, calibrated, against post-seal budget | 33,965,450,979 | 1,915.36% |

The varops budget is 10,000 per weight unit, so the measured verifier alone needs 838,653 WU of
transaction weight at the lower bound and 3,396,545 WU calibrated, against a 400,000 WU policy
target and the roughly 300,000 WU that is practical once the 222,668-byte seal is paid for as
witness. Script size has not been measured, since no verifier script was written; a rough, unmeasured
estimate is 60–150 KB, dominated by the 12,359-step constraint program (table-driven or unrolled),
against Recursive Stwo's 144,905-byte script. Either way it is not the binding constraint, and
neither is proof size. Under this pricing varops is, by a factor of at least two and probably eight;
section 5 revisits the pricing.

For scale, the shipped Recursive Stwo verifier does 8,667 multiplications, 15,747 additions and
10,562 subtractions in 370,387 WU. RISC Zero's recursion verifier does 79x the multiplications. That
is the whole story: it is not a heavier hash, it is a much larger circuit verified at a much larger
`po2` with more taps and more queries.

## 4. What would have to change

Cutting queries does not rescue it. Setup, mixing and constraint evaluation are query-independent
and already cost 3,564,338,360 varops — 89% of a maximal spend before a single query is verified,
and over budget as soon as the calibration factor is applied. The per-query work
(4,791,740,800 varops for 50 queries, so about 95.8M each) would have to drop to zero *and* the
fixed part would have to shrink.

The levers, in order of leverage:

- **A smaller final wrapper circuit.** The 222,668-byte seal proves the recursion circuit at
  `po2 = 18` with 643 taps. A purpose-built final layer — one whose only job is to verify the
  Poseidon2 aggregate, with a small tap set and a small `po2` — would shrink the constraint program,
  the DEEP-ALI combination and the FRI domain together. This is the same move RISC Zero makes for
  Groth16 with `identity_p254`, pointed at Script instead, and it is the only lever that touches all
  four phases at once.
- **Witness-supplied intermediate values.** Mix powers, roots of unity and inverses can be supplied
  in the witness and checked with one multiplication each. This is worth real money in the setup
  phase, where 643 tap mix powers and the coefficient-to-evaluation conversion dominate, but the
  inversions themselves are not the prize: 300 extension inversions are roughly 22,500
  multiplications, about 3% of the total.
- **Fewer, larger FRI folds or fewer queries.** Both trade against the 97-bit conjectured security
  that `QUERIES = 50` already buys, and both only touch the per-query half.

These are all changes to the proof that gets produced, and this section's reasoning assumed the
scalar pricing of section 3 was a floor for the Script side. It is not: section 5 shows that packing
lowers the Script cost of the same verification by about 5x, which moves the default recursion
circuit from 210% of a maximal spend to a projected 40%. A smaller wrapper remains the lever with
the most headroom, but it is no longer a prerequisite on the evidence here.

## 5. Script-side packing, metered

GSR prices an opcode at 1,250 varops before any per-byte work, while a BabyBear multiplication of
4-byte operands costs a few hundred varops of actual arithmetic. The scalar model therefore spends
most of its 8.4B on opcode dispatch. Big-integer opcodes operate on up to 4 MB operands at linear
or quadratic per-byte cost, so several field elements can share one opcode, provided every lane
stays below its spacing and reduction is done lane-wise. Kernels for that were written as real
Script and run in the pinned interpreter
([`research/risc0/kernels/`](research/risc0/kernels/README.md)):

- **Extension elements** occupy four 96-bit lanes. A product is one `OP_MUL` (a Kronecker
  substitution producing seven convolution lanes), a fold of the top three lanes by `x^4 = -11`
  and a lane-wise Barrett reduction to `[0, 4p)`. Inputs below `2^35` are admissible, so
  additions stay lazy.
- **Query vectors** put the same value for all 50 queries in 50 96-bit lanes (4,800-bit integers),
  so a constant times a column is one `OP_MUL` for all queries. After the seal rearrangement below,
  columns arrive as three 22-lane *phase vectors*, which is the layout the projection uses.
- **Reduction** is Barrett with masks, shifts, one `OP_MUL` and one `OP_SUB`; `OP_MULTI` has no
  multiply or modulo. Worst-case lane bounds are asserted for every reduction instance.
- **Equality** of lazily reduced values uses witness-supplied lane quotients, range-checked to 32
  bits, so that `a - b = p * Q` lane-wise; negative cases are checked to fail.
- **Seal rearrangement** turns 50 query rows of 4-byte words into lane vectors with a 64x64 word
  transpose (six delta-swap stages, masks built in Script), then splits and spreads the result.

Marginal costs, from [`kernels.txt`](research/risc0/kernels/kernels.txt) and
[`transpose.txt`](research/risc0/kernels/transpose.txt):

| Kernel | Varops | Scalar-model equivalent |
| --- | ---: | ---: |
| Extension multiply, reduced | 64,078 | 216,304 |
| Extension multiply via `OP_INVOKE` | 70,006 | — |
| Extension add / subtract, lazy | 4,321 / 7,229 | 23,208 / 33,448 |
| Extension times per-query base, reduced | 35,478 | 30,880 + reduction |
| Constant times 50-lane vector, accumulated | 32,976 | 676,100 (50 mul + add) |
| Constant times 22-lane phase vector, accumulated | 18,864 | — |
| Barrett reduction, 50 lanes / 22 lanes | 77,905 / 48,001 | — |
| Hinted equality of two extension elements | 28,375 | — |
| Extract one query's extension value from 4 vectors | 53,050 | — |
| Rearrange 50 x 179 DEEP-ALI words | 27,274,318 | — |
| Rearrange 50 x 371 DEEP-ALI and FRI words | 54,454,954 | — |

Packing pays unevenly. Query-vector work is 10–20x cheaper per value than scalar, but single-point
extension arithmetic gains only 3.4x, and moving a value between the packed and per-query forms
costs about as much as a multiplication. The design that follows from that keeps work vectorised
wherever the operation is the same for every query (tap sums, DEEP-ALI numerators and divisors, the
16-point inverse NTT of each FRI round, and scaling by mix powers) and drops to per-query scalars
only where the evaluation point differs per query (FRI Horner steps in `w_q`, DEEP-ALI inverses
checked against witness hints, goal checks). The final polynomial is evaluated once on its whole
256-point domain by an NTT and read by index per query, instead of 6,400 per-query extension
multiplications.

Composed with the measured operation counts ([`projection.txt`](research/risc0/kernels/projection.txt)):

| Phase | Scalar model (section 3) | Packed projection |
| --- | ---: | ---: |
| Setup and mixing | 1,819,058,520 | 273,494,532 |
| Constraint evaluation | 1,745,279,840 | 499,802,320 |
| `OP_INVOKE` overhead, single-point ext mul | — | 65,249,496 |
| Final polynomial | (in FRI) | 52,008,172 |
| Seal rearrangement | — | 54,454,954 |
| DEEP-ALI, 50 queries | 1,607,655,680 | 144,947,554 |
| FRI folding, 3 rounds | 3,184,085,120 | 444,386,544 |
| Hashing and Merkle direction handling | 30,451,946 | 52,266,946 |
| **Total** | **8,386,531,106** | **1,586,610,518** |

The projection needs 158,661 WU of varops budget. The seal alone is 222,668 WU of witness and so
funds 2,226,680,000 varops; with a script of the estimated 60–150 KB the spend is roughly 290,000–
375,000 WU. The verifier fits if the stack scheduling, control flow and parsing that the kernels do
not include cost less than about 1.8–2.3x the kernel total, and at 2.0x it needs 317,322 WU of
budget. The shipped Stwo verifier's 4.05x factor is not the right comparison, because it is measured
against bare primitive prices while these kernel prices already include operand fetches and
reduction.

Two limits are closer than the varops total suggests. Invoking `ext_mul` as a defined function
11,607 times uses 2,623,182 of the 4,000,000 cumulative invoked-body bytes, because the 226-byte
body inlines its mask and fold constants; keeping those on the stack instead costs `OP_PICK`s.
Constraint evaluation, at 500M, is now the largest single phase and gains least from packing, since
its 7,287 multiplications are at a single point; deferring reductions across its sums of products,
which this projection does not do, is the next lever there.

What the projection does not contain: the composed verifier itself; Fiat-Shamir field sampling and
query-index derivation; parsing the seal into witness items; canonical range checks on seal words;
and the Montgomery form of seal words, which the design absorbs by folding `R^{-1}` into the
constants that multiply them. Two unit prices are unmetered estimates (25,565,000 varops in total):
root-of-unity table powers and Merkle direction handling. The conclusion stands on those terms:
**RISC Zero's default recursion circuit is projected to verify in one standard spend with about 2x
headroom for glue, and the evidence for that is a composition of metered kernels, not a verifier.**
Writing the verifier, with a native reference differential test, is what would turn it into a
measurement.

## Caveats

The arithmetic rows price one modular operation per counted field operation and nothing else: no
operand retrieval (`OP_PICK`/`OP_ROLL`), no witness parsing, no canonical range checks, no
`OP_INVOKE` overhead, and no stack plumbing. They are lower bounds in the same sense as the hashing
rows, which is why the 4.05x calibration from the shipped Stwo verifier is reported alongside. The
measurement is of RISC Zero's own Rust verifier; a Script verifier is free to compute different
things (batching, witness hints), so these counts bound the *port*, not the *problem*. Section 5
quantifies how much: its kernels are metered in the interpreter, but its operation schedule is
derived from these counts, the tap set and the FRI structure, and its total is a projection.
