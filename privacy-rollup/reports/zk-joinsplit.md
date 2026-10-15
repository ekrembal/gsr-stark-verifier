# Zero-knowledge user receipts composed with `add_assumption`

Machine: Intel Xeon Platinum 8375C, 8 vCPU, AVX-512, 31 GiB RAM, no GPU. Every number below is
measured on this machine unless it is labelled as an estimate. Raw data: [regtest.json](regtest.json)
(the regtest run), [operator-joinsplit.json](operator-joinsplit.json) (operator checks).

## Pipeline

```
user:      JoinSplitWitness -> joinsplit guest (commits only the canonical JoinSplitPublic)
           -> segments, lift, join (local, not hiding) -> identity_zk (ZK prover) -> receipt (~276 KB)
operator:  verify_integrity_zk + exact ReceiptClaim check -> ExecutorEnv::add_assumption(claim)
           apply_batch: env::verify(JOINSPLIT_ID, statement) per tx, then the state transition
           segments -> lift/join -> resolve_zk (one per tx) -> identity_sha256_padded
chain:     unchanged GSR verifier + OP_TX covenant, new image 00eb5e47…e50f and control root 5edc9538…5b01
```

`settle prove` runs the session directly and proves each segment, because RISC Zero's composite prover
looks up assumption receipts only among receipts it produced itself. It rebuilds the final segment's
output with the session's assumptions, then lifts, joins and calls `resolve_zk` for each user receipt.

## What changed below the rollup

| Component | Change | Artifact |
|---|---|---|
| `risc0-zkp` prover/verifier | `Prover::new_zk` / `Verifier::new_zk`: fresh per-cell padding, salted Merkle leaves (4 salt elements), `INV_RATE + 1` randomised quotient pieces, FRI/DEEP mask column. Non-ZK path unchanged | [`patches/risc0-zk.patch`](../patches/risc0-zk.patch) |
| RISC Zero recursion | fresh per-cell recursion padding (was one repeated value); `identity_zk`, `resolve_zk`, `verify_integrity_zk_with_context` | same patch |
| Zirgen | ZK seal verification in `circuit/verify`; new `resolve_zk` predicate program | [`patches/zirgen-zk.patch`](../patches/zirgen-zk.patch) |
| `resolve_zk.zkr` | 24,007,400 of 24,023,040 recursion values; SHA-256 `eb56ec11…0d3e`; control ID `0420c857…8231` | `tools/assemble_zk_recursion_zip.py` adds it to the upstream archive (`744b999f…8849` -> `d7315352…632c`) |
| Allowed control root | `a54dc85a…1f56` -> `5edc9538…5b01` (33 programs per suite) | `control_id.rs` in the patch |

The Script logic is unchanged. Only the receipt template ([fixtures/apply-batch/receipt-template.json](../fixtures/apply-batch/receipt-template.json))
changed: new image, control root and claim.

## Tests

| Check | Result |
|---|---|
| `zk_po2_16_accept_and_reject`, `zk_identity_of_lifted_segment`, `zk_resolve_e2e`, `stable_root` (risc0-zkvm, release) | pass; rejects a ZK seal under the ordinary verifier and vice versa, tampered/truncated/extended seals and a wrong claim; two ZK proofs of one claim differ |
| Zirgen `golden_hashes_test` (includes `resolve_zk.zkr`) | pass |
| `tools/operator_joinsplit.py` | forged statement, corrupted receipt, other statement's receipt, resubmission, missing funding all rejected; receipt forwarded unchanged; guest journal equals native; accept/rollback |
| `tools/check_padded_script.py` on a settlement receipt | Python reference and GSR meter accept; wrong claim output rejected |
| `tools/regtest_demo.py --batches 2` | settlement 1 (real deposit join-split funded by a regtest coin) and settlement 2 mined; 12 Script negatives and 4 consensus negatives rejected; same-block second settlement rejected; reorg and replay from chain data match |

## Measurements (regtest run)

| | Value |
|---|---:|
| User join-split guest | 2,877,102 user cycles, 3 segments (3,145,728 total) |
| User proving, wall clock | 332.0 s (succinct 320.8 s + `identity_zk` 11.2 s) |
| User proving, other runs | 314.9 s + 11.6 s; peak RSS ~9.7 GB (`/usr/bin/time`) |
| User receipt (postcard `SuccinctReceipt`) | 276,262 B; seal 56,683 words |
| `tx.json` submitted to the operator (hex receipt + data) | 1,010,140 B |
| Operator receipt check | ~0.06 s per `submit` (incl. process start) |
| Settlement guest, 1 join-split | 14,055,695 user cycles, 15 segments (14,942,208 total) |
| Settlement proving, 1 join-split | 1,487 s wall: segments 1,188 s, lift/join 282 s, `resolve_zk` 9.6 s, padded identity 6.8 s |
| Settlement guest / proving, empty batch | 40,396 user cycles, 1 segment; 26 s wall |
| Settlement tx, 1 join-split (deposit) | 392,001 WU, 2,095,600,656 varops of 3,918,340,000 budget, annex 2,743 B |
| Settlement tx, empty batch | 389,240 WU, 2,095,433,301 varops of 3,892,400,000 budget, annex 151 B |
| Settlement seal | 222,668 B (55,667 words), independent of batch contents |

Compared with the ProveKit path (PR #12, same machine): user proving goes from ~3 s to ~5.5 min,
the user artifact from 633 KB (proof + hints) to 276 KB, and settlement proving of a one-join-split
batch from 4.53 h (205.5M cycles, 98 po2=21 segments) to 24.8 min. The settlement's on-chain cost
is the same verifier; the extra 2,761 WU over an empty batch is the annex and the funding input.

Settlement cycles are now dominated by the BN254 Poseidon2 tree updates in `apply_batch`, not proof
verification. **Estimate, not measured:** a batch of `n` join-splits costs roughly `n × 14M` cycles
and `n × 25 min` here, plus ~10 s of `resolve_zk` per transaction. Only one-join-split batches were run.

## Caveats

* The zero-knowledge argument is a proof sketch ([spec/zero-knowledge.md](../spec/zero-knowledge.md)),
  statistical in the random-oracle model. It is not peer reviewed; neither the ZK mode nor
  `resolve_zk.zkr` is upstream or audited.
* Settlements carry an annex, so they are nonstandard under the pinned node's policy
  (`bad-witness-nonstandard`); the demo mines them with `generateblock`.
