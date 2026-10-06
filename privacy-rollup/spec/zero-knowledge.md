# Zero-knowledge argument for user join-split receipts

Status: **proof sketch**, written for this repository. It has not been peer reviewed or
machine checked. The construction follows Haböck and Kindi, "A note on adding zero-knowledge to
STARKs" (ePrint 2024/1037). Each step below says whether it is an exact counting argument, a
standard random-oracle step, or an assumption. Lemma 2 still needs a careful formal proof.

## 1. What is claimed

A user proves the `joinsplit` guest locally and sends the operator one receipt,
`identity_zk(succinct)`: a `SuccinctReceipt<ReceiptClaim>` whose seal comes from the
zero-knowledge prover (`risc0_zkp::prove::Prover::new_zk`, run by `recursion::identity_zk`).

**Claim.** In the random-oracle model, a simulator that is given only the public data

* the claim `ReceiptClaim::ok(JOINSPLIT_ID, statement)` (image ID, the canonical
  `JoinSplitPublic` journal, exit code, no assumptions),
* the recursion program and its control ID, the allowed control root, and the hash suite,

outputs a seal whose distribution is within statistical distance

    eps <= eps_trace + eps_quot + eps_fri + eps_salt + eps_fs + eps_z

of the real seal, against any verifier making at most `q` random-oracle queries. With the
parameters in section 4 this is about `q * 2^-120`. That is statistical, not perfect, zero
knowledge. The argument covers the seal only. The journal is public by design, and the
join-split guest commits only the public statement (`methods/guest/src/bin/joinsplit.rs`).

**Not claimed:**
* Zero knowledge of RISC Zero's ordinary (non-ZK) seals. The rv32im segment proofs and the
  lift/join seals are not hiding, so they never leave the user's machine. Only the
  `identity_zk` seal does. Those inner seals are witness data of the recursion circuit, and
  that circuit is what the ZK prover proves.
* Protection against side channels: proving time, memory, or network timing.
* Security of the hash functions beyond the random-oracle idealisation.
* Anything about `add_assumption` beyond section 5. Composition is soundness machinery; it adds
  no hiding of its own.

## 2. The ZK prover (what the code does)

Field `F` = BabyBear (`p = 2^31 - 2^27 + 1`, about `2^30.9`). Extension `K = F[x]/(x^4 - 11)`
(`|K|` about `2^123.6`). Trace length `n = 2^po2` with `po2 = RECURSION_PO2 = 18`. Rate
`INV_RATE = 4`. The seal has `QUERIES = 50` query positions.

1. **Fresh padding (`circuit/recursion/src/prove/witgen.rs`).** The last `ZK_CYCLES = 1024`
   rows of every hidden column (`data`, `accum`) get independent uniform field elements. The
   upstream code drew one random value and repeated it. The circuit's constraints are disabled
   on those rows: the native tests below accept such proofs, and tampering is still rejected.
2. **Salted leaves (`zkp/src/prove/poly_group.rs::new_salted`).** Each Merkle leaf of a hidden
   group (`data`, `accum`, and the check group) is the row of evaluations plus `ZK_SALT_SIZE = 4`
   fresh uniform field elements (about 123.6 bits). The `control` group is public (its root is
   the control ID) and stays unsalted. So does the register (globals) group.
3. **Randomised quotient (`prover.rs::zk_check_pieces`).** The quotient `h` (degree below
   `INV_RATE * n`) is cut into `P = ZK_QUOTIENT_PIECES = INV_RATE + 1 = 5` pieces,
   `h = sum_i x^(i*k) h_i` with `k = n - m` and `m = ZK_QUOTIENT_MASK_SIZE = 64`. The pieces are
   then re-randomised with uniform `r_1..r_{P-1}` in `K[x]` of degree below `m`:
   `h_i' = h_i + x^k r_{i+1} - r_i`. The sum telescopes, so `h` is unchanged. Each `h_i'` has
   degree below `n`. Pieces are opened at the DEEP point `z` itself (the plain protocol uses
   `z^4`).
4. **FRI mask (`prover.rs` finalize, `verify/mod.rs::fri_eval_taps`).** A uniform `R` in `K[x]`
   of degree below `n` is committed as 4 extra columns of the salted check group, before `z` is
   drawn. The FRI input is `DEEP(x) + a * R(x)`, with
   `a = mix^(reg_count + check_size)` taken from the FRI batching challenge `mix`. The verifier
   adds `a * R(x)` from the opened check row at each query.

The Rust verifier (`Verifier::new_zk`, `SuccinctReceipt::verify_integrity_zk_with_context`)
and Zirgen's recursion verifier (`zirgen/circuit/verify/verify.cpp`, compiled into
`resolve_zk.zkr`) both implement this same transcript order:
commit `data`, `accum`, then check (pieces, mask, salt); draw `z`; read openings; draw `mix`;
then FRI.

## 3. Simulator

The simulator `S` programs the random oracle used for Fiat–Shamir. It runs the IOP simulator
with the challenges chosen up front, and answers oracle queries consistently.

1. **Challenges.** `S` samples every verifier challenge itself: `poly_mix`, the accumulation
   challenges, `z`, `mix`, FRI folding challenges, and query positions. Later it programs the
   oracle so the transcript produces exactly these. This fails only if the adversary already
   queried a programmed point (`eps_fs`, at most `q * c / 2^247` for `c` challenge
   derivations, since a digest is 8 BabyBear elements or 256 SHA bits).
2. **Public columns.** `control` and the globals are public. `S` computes them honestly.
3. **Hidden trace openings (Lemma 1).** For each hidden column, `S` samples the opened values,
   at the `QUERIES` query points and at `z * w^-b` for each tap `b`, uniformly and
   independently. One exception: the `accum`/`data` values at `z` must satisfy the constraint
   identity `C(openings(z)) = h(z) * Z_H(z)` with the `h(z)` of step 4. `S` handles this by
   choosing `h(z)` from the sampled openings, not the other way round.
4. **Quotient openings (Lemma 2).** `S` samples `h_0'..h_{P-2}'` at `z` and at the query
   points uniformly. It sets `h_{P-1}'` at each point so that `sum_i x^(ik) h_i'(x)` equals the
   value of `h` implied by the trace openings at `x`, and at `z` equals `C(...)/Z_H(z)`.
5. **FRI (Lemma 3).** `S` samples a uniform polynomial `G` in `K[x]` of degree below `n` and
   runs the honest FRI prover on it. It sets each opened mask value to
   `R(x) = (G(x) - DEEP(x)) / a`, where `DEEP(x)` comes from the simulated openings.
6. **Commitments (Lemma 4).** For each salted tree, `S` builds the leaves at the opened rows as
   `H(simulated row || fresh salt)`, sets every other leaf to a fresh uniform digest, and hashes
   up to the root. It answers authentication-path queries from this tree.

**Lemma 1 (trace, exact up to `eps_trace`).** Fix a hidden column with polynomial `f` of
degree below `n`. Its values on the trace domain `H` are `w_0..w_{n-1}`, and the last 1024 are
uniform. Write `f = g + sum_{j in R} w_j L_j` with Lagrange basis `L_j` and padding rows `R`.
For distinct base-field points `x_1..x_s` outside `H` with `s <= |R|`, the matrix
`[L_j(x_i)]` equals `diag((x_i^n - 1)/n) * [h_j / (x_i - h_j)]`, a scaled Cauchy matrix. Every
square submatrix of a Cauchy matrix is nonsingular, so `(f(x_i))_i` is uniform on `F^s`,
independent of `g`. Query points lie on the shifted evaluation coset, hence outside `H`.

The opening at `z`, and at its tap shifts, is in `K`. Each is 4 `F`-linear functionals of
`w`, so `4t` per column with `t` taps. Revealed functionals per column:
`s = QUERIES + 4t <= 50 + 4 * t_max`. That is far below 1024 for every recursion column
(`t_max` is a single-digit number of back-rows; recount this from the generated TapSet for a
formal proof).

The remaining requirement is that these functionals stay independent when some are taken at
`z` in `K`. The relevant minor's determinant is a nonzero polynomial in `z` of degree at most
`D <= 4 * n * t_max`, so by Schwartz–Zippel a random `z` makes it vanish with probability at
most `D / |K|`. That gives `eps_trace <= (#hidden columns) * D / |K|`, about
`2^10 * 2^23 / 2^123.6`, or about `2^-90`. This uses a loose bound on `D` and is the weakest
term. It also folds in the event that `z` lands in `H` or the evaluation domain (`eps_z`, at
most `2^20 / |K|`).

**Lemma 2 (quotient pieces; counting, sketch).** In base-field coordinates, each
`r_i` is 4 polynomials of degree below `m = 64`, giving `256` uniform `F`-elements per mask.
Each coordinate polynomial of `r_i` is revealed at `QUERIES = 50` base points plus `z` (4
`F`-functionals), so 54 functionals, below `m = 64`. Evaluations of a degree-below-`m`
polynomial at at most `m` distinct points form a Vandermonde system and are uniform. For `z`,
use the Schwartz–Zippel step as in Lemma 1.

Piece `h_i'` (for `i < P-1`) contains `x^k r_{i+1}(x) - r_i(x)`, and `r_{i+1}` occurs in no
earlier piece. Fixing pieces `0..i-1` therefore leaves `h_i'` uniform at the revealed points.
The last piece is determined by `h`, which is itself determined by the trace openings. So the
pieces reveal nothing beyond `h` at the opened points, which the simulator already reproduces.
`eps_quot` is at most `(P-1) * 4 * 54 * 4 / |K|` (the `z` coordinate step). Status: this is the
step Haböck–Kindi flag as error-prone ("a source for mistakes"). The overlap layout `k = n - m`
and the check that `h` has no coefficients at or above `(P-1)k + n` are in the code. They need
independent review.

**Lemma 3 (FRI mask, exact up to `a = 0`).** `R` is uniform of degree below `n` and
independent of everything committed before `mix`. Given `a != 0`, `DEEP + a * R` is uniform of
degree below `n`, independent of `DEEP`. So the FRI transcript of a uniform polynomial is
exactly simulable, and the opened `R(x)` values are the determined differences.
`eps_fri <= Pr[a = 0] <= (reg_count + check_size) / |K|`.

**Lemma 4 (salted Merkle, ROM).** An unopened leaf is `H(row || salt)` with `salt` uniform in
`F^4`. A verifier that never queries the oracle on that exact input sees a uniform digest. Over
all leaves, `eps_salt <= q * 2^-123.6`. Opened leaves reveal their row and salt; the
simulator's row and salt have the right distribution by Lemmas 1–3. Collision resistance is
**not** used for zero knowledge. It is used for soundness: binding of the Merkle commitments.

## 4. Parameters and bound

| term | bound | value |
| --- | --- | --- |
| `eps_trace` + `eps_z` | Schwartz–Zippel on `z`, loose degree bound | about `2^-90` |
| `eps_quot` | revealed 54 < `m` = 64, plus `z` step | about `2^-110` |
| `eps_fri` | `Pr[a = 0]` | about `2^-116` |
| `eps_salt` | `q / 2^123.6` | about `q * 2^-123` |
| `eps_fs` | `q * c / 2^247` | negligible |

These values are computed from the formulas above, not measured. `ZK_SALT_SIZE` was lowered
from 8 to 4 so that `resolve_zk.zkr` fits the recursion circuit's fixed program capacity
(24,007,400 of 24,023,040 values). Four salt elements still give about 123.6 bits of entropy per
leaf.

## 5. Composition with `add_assumption`

* **User to operator.** The operator receives the `identity_zk` receipt and checks it with
  `verify_integrity_zk_with_context` and the claim `ReceiptClaim::ok(JOINSPLIT_ID,
  statement)`. The statement is the transaction's public data. By section 3, the operator's
  view is simulable from it.
* **Rollup guest.** `apply_batch` calls `env::verify(JOINSPLIT_ID, statement)`. The executor
  needs only the claim (`add_assumption(claim)`), and the guest learns nothing more.
* **Resolution.** `resolve_zk.zkr` verifies the user's ZK seal inside the recursion circuit
  and removes the assumption. The resulting receipt, and the final `sha-256-padded` receipt the
  covenant checks, are ordinary seals over the operator's witness. That witness contains the
  user's ZK seal, which is already simulable, and public rollup data. What appears on chain
  therefore reveals no user witness beyond the statement. This follows from the simulator above
  applied to every user seal, plus the fact that the operator's own data is public.
* **Soundness** of the composition is unchanged RISC Zero recursion soundness. The extra
  conditions are that `resolve_zk.zkr` correctly verifies ZK seals (tested: valid seals
  resolve; a tampered seal, a receipt of another claim, and a plain seal are all rejected), and
  that its control ID is in the allowed control root (`5edc9538…5b01`).

## 6. Evidence and gaps

| item | status |
| --- | --- |
| ZK prover/verifier (`risc0-zkp`) | implemented |
| native accept/reject (`zk_po2_16_accept_and_reject`, `zk_identity_of_lifted_segment`, `zk_resolve_e2e`) | tested (empirical) |
| Zirgen `resolve_zk.zkr` matches the Rust verifier | tested on real seals (empirical) |
| Lemmas 1, 3, 4 | standard arguments, written here as sketches |
| Lemma 2 (quotient split) | counting sketch; needs independent review |
| tap counts per column, exact `D` | not computed; loose bound used |
| peer review / audit | none |
