# Lazy covectors for the fixed JoinSplit matrices

The original lazy checkpoint is `76ae74a`; its measurements below remain
recorded separately from the final contract extension described at the end.
This unpublished follow-up to `7f7c303` avoids constructing three full witness
weight vectors and folding six padded commitment prefixes. It evaluates the
same three matrix bilinear forms directly at each WHIR commitment's final point.
The entire incoming VK is still hash-bound and all parameters are unchanged.

## Construction and equivalence

For each fixed matrix M, the result is the row-weighted sum of M's dot products
with the column equality basis. The two commitments have independent points and
separate caches. The first covers global columns [0,5530); the second covers
[5530,51805), using local index `column - 5530`. Zero padding, including all
leading point factors, is supplied by the existing truncated equality-table
routine. A changed point invalidates the cache. All three matrices share one
basis table and one traversal for the same commitment point.

The traversal applies the four-lane linear maps **only**. At each S-box row it
reads the independent y2, y4 and y5 columns. It never assumes those columns form
a valid nonlinear witness, and does not replace constraints with Poseidon
recomputation. Residual rows use the generated literal coefficients. Multiplying
by publicly known zero basis values is skipped exactly.

The generic verifier retains materialized prefix weights. The `LinearForm`
accumulation method remains implemented and is tested against materialization,
although the verifier itself calls only the MLE method. Transcript message
order, public/challenge binding, WHIR RLC checks, sumcheck equality, proof EOF
checks and settlement journal construction remain intact.

## Measurements

Identical frozen inputs, two execution-only runs per variant, normal 2^20 rows:

| Metric | Fixed configuration | Lazy covectors |
|---|---:|---:|
| Settlement user cycles | 443,708,894–923 | 423,237,844–869 |
| Settlement segments | 512 | 475 |
| Settlement runtime seconds | 17.4724–18.7235 | 14.4061–14.7773 |
| Settlement peak host RSS KiB | 106,444 | 85,948 |
| Diagnostic user cycles | 426,795,684–709 | 405,700,079 |
| Diagnostic segments | 496 | 457 |
| Diagnostic runtime seconds | 17.2436–17.2617 | 14.1451–14.6701 |
| Diagnostic peak host RSS KiB | 108,968 | 90,492 |

Settlement cycles decrease 4.61%, segments 7.23%, and median runtime about
19.4% from the fixed-configuration checkpoint. Runtime figures are two samples,
not a statistical guarantee. Against instrumented PR10, settlement cycles fall
about 65.2% (1,216,081,348 to 423,237,844) and segments 1,278 to 475.

The improvement is smaller than a simple count of removed folds might suggest:
the two direct bilinear traversals cost 102,332,998 cycles. Their shared column
equality tables cost 28,587,619; initial row equality costs 21,425,235. The six
lazy MLE calls together cost 130,946,068, including both traversals and column
tables. Ordinary prefix MLE cost falls from 95,760,329 to 10,795 (public inputs).
Avoided vector allocation and padding also contribute. Sparse NTT remains the
largest single profiled arithmetic target at 128,089,503 cycles.

The new settlement image is
`e15b6136bdab860f53e8fb1e67594652094cdddba790c36f7f4f6af33c72b025`.
The same 196-byte settlement journal has SHA-256
`4e366d165e21f04fcb31f5cd46b0abfecd9d6503f8d542c3f45399256890b43f`.
Proof and VK sizes remain 635,142 and 3,213,548 bytes. Saved host/guest artifacts
are under `build/aggregation/lazy-baseline/`, including their SHA-256 manifest.

## Validation and formal scope

All 40 native tests pass. New differential tests compare 48 bilinear cases
against independently evaluated expanded matrices, using arbitrary independent
column values and split/boundary layouts. Cache and prefix tests exercise three
layouts and seven point sequences, including zero, one, repeated and changed
points, permuted matrix access, and nine accumulation comparisons. Existing
full-column reverse tests and exact embedded-configuration equality still pass.
Fresh real proofs pass both generic and fixed verification, and proof mutations
remain rejected in both paths. All nine guest rejection cases passed on the same
images as the acceptance runs. A fresh operator proof passed admission, guest
settlement with native journal equality, replay rejection, accept and rollback.

Lean checks four additional external-forward identities and a direct-row
reassociation lemma under explicit algebraic laws. The latter uses only standard
`propext`; linear-map identities use `propext` and `Quot.sound`. These are narrow
algebraic results. They do not prove the complete traversal, split offsets, cache
invariant, generated matrix extraction, Rust compilation, field backend, or
protocol soundness. The existing padded-hash audit gap and upstream FinalClaim
handling caveat are unchanged.

## Reproduce

Apply the cumulative `patches/provekit-structured.patch` after the pinned
compatibility and aggregation patches, using `git apply --unidiff-zero`.
The reapplication check reproduces all 12 affected dependency files byte-for-byte.
No package versions or source pins changed in this follow-up.

```sh
source /workspace/.gsr-env/activate.sh
cargo +1.97 test --locked --release --manifest-path privacy-rollup/Cargo.toml --workspace
/workspace/.gsr-env/lean/bin/lean privacy-rollup/formal/ExternalTranspose.lean
/workspace/.gsr-env/lean/bin/lean privacy-rollup/formal/BilinearRow.lean
export PATH="/workspace/.gsr-env/shims:$PATH"
export RISC0_HOME=/workspace/.gsr-env/risc0-home
export RISC0_BUILD_LOCKED=1
export RECURSION_SRC_PATH=/workspace/.gsr-env/recursion_zkr.zip
(cd privacy-rollup/prover && cargo build --locked --release)
export PATH="/workspace/.gsr-env/sysroot/usr/bin:$PATH"
export RAYON_NUM_THREADS=4
python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
  --label lazy-new --kind verify --runs 2
python3 privacy-rollup/tools/profile_aggregation.py build/aggregation/inputs \
  --label lazy-new --kind batch --runs 2
python3 privacy-rollup/tools/reject_aggregation.py build/aggregation/inputs \
  build/aggregation/cases --verify privacy-rollup/prover/target/release/exec_joinsplit \
  --settle privacy-rollup/prover/target/release/settle --out build/aggregation/rejections-lazy-new
RAYON_NUM_THREADS=4 python3 privacy-rollup/tools/operator_joinsplit.py
```

Use new evidence labels. Raw paired measurements and validation evidence are in
`lazy-covector-measurements.json`; full real proving remains separate from these
execution measurements. Normal-size real segment proving is documented in
`normal-segment-proving.md`. Lower guest cycles alone do not establish feasible
full aggregation or close the outstanding protocol audit requirements.

## Final linear-form contract extension

The final implementation also accepts evaluation points longer than the domain
dimension, as required by `LinearForm`. Extra leading zero-padding factors are
computed separately, so even a point longer than the machine word does not cause
an oversized bit shift. Differential tests now include 19- and 65-coordinate
points, changed/repeated cache keys, and the original exact-dimension points.
All 40 native tests and all nine guest rejection cases pass. A fresh operator
proof also passes native/guest journal equality, replay rejection, accept and
rollback on the final image.

Two final settlement runs both use 423,486,268 cycles and 475 segments, taking
14.4585 and 14.3285 seconds; peak host RSS is 85,556 KiB. Two diagnostic runs use
405,890,640–657 cycles and 457 segments, taking 13.8703 and 13.8323 seconds; peak
RSS is 90,688 KiB. This extension adds about 0.06% settlement cycles relative to
`76ae74a`. The final settlement journal remains unchanged. Its image ID is
`cb7562cfb2f17108502ebab6af755747ca88c16ee5ddd7429537b720ac8b319b`.

Final artifacts and hashes are preserved in `build/aggregation/lazy-final-baseline/`;
final measurements and validation are in `lazy-final-measurements.json`. The real
normal-size partial receipt documented separately belongs to `76ae74a`, not this
final image. No complete JoinSplit receipt is claimed for either image.
