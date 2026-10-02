# Lazy blinding forms and bounded fused-field experiments

This unpublished follow-up starts at `45a1bc6147b81a04345e3a99e54e72902839ec80`.
It keeps the PR10 dependency pins, frozen client proof, complete VK binding,
transcript sequence, verification equations, security parameters and settlement
journal. There is still no complete real JoinSplit receipt.

## Measured execution

Two sequential runs use the same frozen `build/aggregation/inputs` frames. The
adjacent [measurement JSON](lazy-blinding-measurements.json) records commands,
input/binary digests, image IDs, phase costs, wall time and peak host RSS.

| Settlement configuration | User cycles | Segments |
|---|---:|---:|
| Previous checkpoint | 423,486,268 | 475 |
| Lazy blinding covectors | 255,324,368 | 270 |
| Also fused Montgomery multiplication | 219,438,570 | 234 |
| Also batched matrix dot products | 206,379,610 | 222 |
| Also iterative equality tables | 191,119,146–171 | 208 |

The last configuration executes in 6.053–6.059 seconds, at at most 78,640 KiB
peak host process RSS. Its diagnostic verifier uses 178,765,205–209 cycles;
exclusive costs include 77.45M for direct matrix evaluation, 26.11M for equality
tables, 13.95M for Merkle verification and 10.74M for leaf encoding/hashing.
Execution memory is not prover memory. The unchanged frozen client proof is
635,142 bytes and the supplied VK is 3,213,548 bytes.

## Exact algebraic changes

`ProjectedPowerSum` represents the coefficient table defined by projecting a
weighted sum of `eq[c] * z^m` onto a contiguous bit window of `c|m`. It sums the
unused equality coordinates and factors free exponent bits as `1+z^(2^k)`.
At an MLE point, captured exponent bits contribute
`1+y*(z^(2^k)-1)`. This works for arbitrary field points, including zero,
without division or a subgroup assumption. Interleaving uses the last point
coordinate, with the same even/odd scales as the original dense covectors.
Longer points retain the required leading zero-padding factors.

The guest uses these forms at the existing blinding-WHIR final linear-form
check. It retains every transcript read, diagonal evaluation check and final
claim verification. Native prover/client code keeps the dense implementation.
This removes the guest's dense BEQ/NTT construction; it does not modify WHIR
parameters. Independent tests enumerate the defining coefficient sums and
compare both accumulation and MLE evaluation across bit-window boundaries.

The matrix evaluator groups products into 32-term sums with explicitly zeroed
unused slots. A separate common accumulator preserves the shared A/B terms.
S-box outputs remain independent columns. Native differential tests compare
against all original matrix coefficients, including arbitrary invalid-witness
column values, split offsets and changing evaluation points.

The iterative equality-table path retains exactly
`ceil(output_length / remaining_subtree_size)` prefixes per level and expands
them backwards in place. This avoids recursive field copies and adding a leaf
to an already-zero destination. Native client code keeps its parallel path.
Independent bit-product tests cover dimensions 0–16, truncation boundaries,
zero/one/minus-one points, and the actual 5,530/38,819/46,275 lengths.

## Experimental existing-AIR kernels

The optional fixed-BN254 kernels use the unchanged RISC Zero BigInt2 AIR and
interpreter. They introduce no SDK, custom AIR or covenant change. Their
integer relation is `sum(a_i*b_i) + p*R = q*p + r*R`, with `R=2^256`, one or
32 terms, and a mandatory Rust `r<p` check. The modulus is compiled into the
program. Generic dispatch requires exactly four limbs and this exact modulus;
other fields retain the previous backend. The 32-term path also requires the
exact input length. Input limbs are copied rather than assuming a Rust `Fp`
memory layout.

The generator emits witness-generation bytecode, verification instructions,
fixed constants and bounds. Witness generation is untrusted. The scalar kernel
uses 35 syscall cycles; the dot kernel uses 159 for all 32 products. The dot
coefficient bound is 68,666,910 and the conservative adversarial carry bound is
2,146,303. Their combined no-wrap bound is below the BabyBear modulus, including
the full byte range accepted by the pinned v2 carry circuit. These checks are
not a bytecode or circuit audit.

The scalar backend matched 6,486 independent arithmetic outputs. The dot backend
matched 120 independent 32-term vectors. Both reject noncanonical `r=p` in the
guest. For each kernel, a local negative-only guest changes witness stores while
retaining identical verifier instructions and constants: fast execution returns
zero, but real proof generation rejects the incorrect quotient with `bad carry`.

At a common segment limit of 2^18, complete 400-iteration scalar-kernel chains
passed proof, lift, padded conversion, full image/journal verification and seal
corruption rejection:

| Complete synthetic guest | User cycles | Padded rows | Chain supervisor seconds | Peak RSS KiB |
|---|---:|---:|---:|---:|
| Previous two-modmul backend | 125,034 | 262,144 | 168.099 | 2,395,880 |
| Fused scalar backend | 85,841 | 131,072 | 116.735 | 1,446,112 |

See [scalar kernel evidence](fused-kernel-measurements.json) for exact stages.
A complete four-vector dot guest also passed the same chain: 107,514 user
cycles, 262,144 rows, 163.332 supervisor seconds and 2,397,628 KiB peak RSS.
Both final padded seals are 222,668 bytes. These are complete diagnostic
receipts, not application aggregation receipts. The unaudited original padded
hash patch and returned verifier parameters remain part of their trust boundary.

## Reproduce and review boundaries

```sh
source /workspace/.gsr-env/activate.sh
export PATH="/workspace/.gsr-env/shims:$PATH"
export RISC0_HOME=/workspace/.gsr-env/risc0-home
export RISC0_BUILD_LOCKED=1
export RECURSION_SRC_PATH=/workspace/.gsr-env/recursion_zkr.zip
export RAYON_NUM_THREADS=4
# Optional experimental kernels; leave both unset for the original backend.
export GSR_FUSED_DOT32=1
# GSR_FUSED_BN254=1 instead enables only the scalar kernel.
cd privacy-rollup/prover
cargo build --locked --release
cd ../..
cargo +1.97 test --locked --release --manifest-path privacy-rollup/Cargo.toml --workspace
export PATH="/workspace/.gsr-env/sysroot/usr/bin:$PATH"
python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
  --label new-review --runs 2 --kind verify
python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
  --label new-review --runs 2 --kind batch
```

The current combined configuration passed 43 native tests, nine guest rejection
cases and a fresh operator admission/journal/replay/rollback workflow. The
cumulative ProveKit patch reapplies exactly to all 12 affected files. No
lockfile changed in this follow-up. Earlier failed test compilation (an
ambiguous integer type) and a build invoked from the older root toolchain are
retained in logs; both were corrected without changing pins.

Lean checks the new Boolean-product factorization under explicit distributivity
and concrete scalar/dot carry bounds, in addition to earlier narrow lemmas.
The factorization uses Lean's standard `propext` axiom; the concrete bound checks
use no axioms. This does not verify indexing, generated bytecode, Rust/AIR
refinement, field implementation, transcript, zero knowledge or end-to-end
soundness. Upstream ignored `FinalClaim` warnings remain visible; the pinned
WHIR implementation checks the blinded linear-form RLC inline and the blinding
final claim explicitly. Source inspection and tests are not a soundness proof.

Host compiler tuning and representative application-segment proving remain
separate measurements. The previous roughly 416-second normal-size segment
proof shows why cycle reductions alone do not establish cloud feasibility.
Material AIR/covenant changes and direct WHIR recursion remain unimplemented
and require a separate concrete proposal and approval.
