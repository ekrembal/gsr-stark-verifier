# Prover speedups: AVX-512 host prover, recursion batching, po2=21, scheduler, fixed key, dot4

Machine: Intel Xeon Platinum 8375C, 8 vCPU, AVX-512 (f/bw/dq/vl/ifma/vnni), 31 GiB RAM, no GPU.
Every number below is measured on this machine unless it is explicitly labelled as an estimate.
Bonsai, Boundless, GPU and multi-machine proving were **not** run.

## What changed

Host prover only (`patches/risc0-cpu-avx512.patch`, applied on top of the PR #11 RISC Zero patch stack).
None of this changes the circuits, the verifier, the control root or the covenant:

| Change | Switch |
|---|---|
| 16-lane (AVX-512) packed rv32im constraint evaluation; 8-lane and scalar paths kept | build `GSR_BUILD_CPU_BATCH=1 GSR_CPU_BATCH_LANES=8\|16`, run `GSR_BATCH_EVAL_CPU=1` |
| 16-row Poseidon2 row hashing | `GSR_HASH_LANES=16` |
| Packed recursion-circuit evaluation (lift, join, identity) | same build/run switches |
| Exact tabulated BabyBear NTT and `zk_shift` | `GSR_FAST_NTT=1` |
| po2=21 segments (the existing control root already admits the po2=21 lift program) | `full_proof_check capture <dir> <program> <journal> 21 <segments> ...` |
| Bounded concurrent scheduler with deterministic balanced join tree, checkpoint/restart | `full_proof_runner.py --jobs N --leaf-jobs M` |

Guest (new image ID):

| Change | Effect |
|---|---|
| Verifier configuration compiled into the guest, bound to `KEY_HASH` (SHA-256 of the 3.2 MB postcard key); the guest no longer reads or hashes a key frame. Host APIs reject any other key (`ensure_guest_key`). | removes the 3.2 MB input frame |
| Fused BigInt2 `dot32` and `dot4` Montgomery kernels (`sum a_i*b_i mod p` in one accelerator call) in the structured matrix evaluator, with explicit canonical-remainder checks | fewer BigInt2 calls |
| Explicit WHIR final-claim checks in the ProveKit verifier (`patches/provekit-final-claim.patch`) | soundness hardening, ~0.2M cycles |

## Guest cycles (execution, same frozen proof `proof0.pc`, journal identical in every row)

| Guest | Cycles (executor) | Segments (po2=20) |
|---|---:|---:|
| PR #11 guest (reads + hashes the key frame) | 195,958,366 | 213 |
| + compiled key, dot32 kernel | 192,160,088 | 207 |
| + dot4 kernel | 187,143,313 | 201 |
| Final guest, image `552b779f…3cb8` (capture at po2=21: user cycles) | 187,344,079 user / 205,520,896 total | 98 at po2=21 |

Journal SHA-256 for all rows: `cfc93803f0ec70b92c43ac8a7b0e06f8c93c196fe526e2c889b46f22e2a25b9d`.

## Selected-segment timings (8 Rayon threads, one stage at a time)

These are timings of selected segments of the same execution, not a full proof.

| Config | Hash lanes | Poly lanes | Fast NTT | Recursion batch | po2=20 prove | lift | join |
|---|---:|---:|:-:|:-:|---:|---:|---:|
| A | 8 | 8 | no | no | 117.4 s / 116.1 s | 14.9 s | 14.9 s |
| B | 16 | 16 | no | no | 96.4 s | 11.9 s | |
| C | 16 | 16 | yes | no | 77.6 s | 9.9 s | |
| D | 16 | 16 | yes | yes | 78.7 s / 79.9 s | 8.1 s / 8.1 s | 8.3 s |

Config D at po2=21: 161.4 s prove (19.3 GiB peak RSS), 8.1 s lift. Peak RSS at po2=20 is ~9.6 GiB;
lift/join ~1.45 GiB.

po2=22 is **not feasible on this machine**: the leaf prover was killed by the kernel OOM killer at
27.6 GiB anonymous RSS (31 GiB host).

Raw data: `reports/prover-speedups-segments.json`.

## Full JoinSplit proof (measured, one machine, po2=21)

The frozen one-JoinSplit batch (same `proof0.pc`, witness and journal as PR #11) was proved end to end
with config D at po2=21 by `tools/full_proof_runner.py` (`--jobs 2 --leaf-jobs 1`, 8 Rayon threads per stage).
One supervisor ran from start to finish; no stage was retried. Raw data: `reports/full-joinsplit-po2-21.json`.

| Item | Measured |
|---|---:|
| Segments (po2=21) / leaves / lifts / joins | 98 / 98 / 98 / 97, then 1 padded identity step |
| Wall time, capture excluded | **16,299.6 s (4.53 h)** |
| Leaf prove: mean / min / max / sum | 156.3 s / 143.6 s / 186.0 s / 15,321 s |
| Lift: mean / sum | 8.36 s / 820 s |
| Join: mean / sum | 13.12 s / 1,273 s |
| Padded SHA-256 identity step | 6.05 s |
| Peak sampled RSS (whole process group) | 19,360,740 KiB (18.5 GiB) |
| Run directory on disk at completion | 244 MiB |
| Final seal / journal | 222,668 B / 196 B |

Only one po2=21 leaf runs at a time: two would need ~38.6 GiB against 31 GiB of RAM. Lifts and joins
(~1.5 GiB each) overlap the next leaf, which is why the wall time is below the 17,414 s stage sum.

For comparison (not same-machine measurements): PR #11 projected 10.65 h for its 208-segment po2=20 run on
a 4-CPU host, and the earlier estimate for PR #11's prover on this machine was ~6.2 h.

Final checks, all passed:

| Check | Result |
|---|---|
| Native RISC Zero verify, unpadded (Poseidon2) and padded (`sha-256-padded`) receipts, image `552b779f…3cb8` | pass |
| Journal equals the frozen expected journal (SHA-256 `cfc93803…5b9d`); `assumptions_digest` zero; successful exit | pass |
| Wrong image, wrong journal, corrupted seal | rejected |
| Python reference verifier on the padded seal | pass |
| Trusted Script profile (control roots, parameter digest, circuit IDs) | matched |
| Full fixed-statement transaction in the pinned meter: 388,398 WU, 2,083,399,455 varops (budget 3,883,980,000), every limit satisfied | pass |
| Same Script with a changed claim output | rejected |

The receipt is committed as `fixtures/full-joinsplit/{receipt.json,seal.bin,journal.bin}`.
It cannot be settled on regtest as-is: the frozen batch commits placeholder input/output scripts
(`full-proof-covenant-binding.md`), so the OP_TX covenant on a real chain needs a batch built against
actual chain outputs. The OP_TX covenant itself was re-run with the new image on 10 consecutive proven
empty-batch settlements (below).

## Validation

Host SIMD is only a different evaluation order of the same field arithmetic; every packed path is
checked against the scalar path it replaces:

| Check | Result |
|---|---|
| rv32im packed vs scalar `poly_fp` (random rows, domains `lanes`/64/256), 8- and 16-lane builds | pass |
| recursion packed vs scalar `eval_check` (po2 4, 6), 8- and 16-lane builds | pass |
| exact NTT / `zk_shift` vs generic (`word_ops_match_field`, `ntt_matches_generic`, `large_ntt_matches_generic`, `shift_matches_scalar`) | pass |
| Poseidon2 batched rows/pairs vs scalar, row boundaries, unreduced-input rejection, golden vectors (11 tests) | pass |
| Fixed key: other keys rejected, real proof accepted, mutated proof rejected, one changed R1CS coefficient rejects the proof | pass |
| dot4 differential vectors (guest journal = independent Python reference) | pass |
| Malicious dot4 witness: non-canonical output rejected in the guest; bad carry witness rejected by the real prover (`bad carry`) | rejected as required |
| Scheduler: balanced post-order tree, resume without reproving, active-stage cleanup, noncontiguous children rejected, leaf-job bound (5 tests) | pass |
| `cargo test --workspace`, `cargo clippy --workspace --all-targets --all-features` (workspace and prover) | pass |
| `tools/operator_joinsplit.py` (forged/corrupted/replayed/unfunded rejected, guest journal = native) | pass |
| `tools/regtest_demo.py --batches 10` with the new image: 10 consecutive settlements at 389,240 WU / ~2.0955B varops, 12 policy and 4 consensus negative spends rejected, reorg rollback/replay | pass |

## Not done

- po2=22: out of memory on this machine (above).
- Bonsai, Boundless, GPU and multi-machine proving: not run. The scheduler proves independent leaves
  concurrently on one host when memory allows (`--leaf-jobs`); distributing leaves across machines is not
  implemented.

