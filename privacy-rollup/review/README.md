# External review package

This package is what an external reviewer needs to assess the privacy rollup. **No external review has taken
place.** Everything below was written and tested by the authors only. The zero-knowledge argument is a proof
sketch, and none of the patched components are upstream or audited.

## 1. Scope, in priority order

| # | component | where | what to check |
|---|---|---|---|
| 1 | Zero-knowledge prover mode for `risc0-zkp` v3.0.6 | `patches/risc0-zk.patch` (1,130 lines) | fresh per-cell padding noise, salted Merkle leaves, FRI mask polynomial, randomised quotient pieces; the native ZK verifier accepts exactly the proofs the prover makes |
| 2 | `resolve_zk.zkr` recursion program | `patches/zirgen-zk.patch` (234 lines), `tools/assemble_zk_recursion_zip.py` | the Zirgen verifier matches the Rust ZK verifier; adding it to the control root admits no other program |
| 3 | Zero-knowledge argument | `spec/zero-knowledge.md` | simulator (§3); Lemma 2, quotient split, is only a counting sketch; the parameter bound (§4); composition through `add_assumption` (§5) |
| 4 | Join-split guest | `methods/guest/src/bin/joinsplit.rs`, `crates/joinsplit`, `crates/crypto` (BN254 Poseidon2, including the BigInt2 guest path `crates/crypto/src/zkvm.rs`) | the statement in `spec/joinsplit.md`: membership, nullifier derivation, range checks, balance |
| 5 | Settlement guest | `methods/guest/src/bin/apply_batch.rs`, `crates/state-transition`, `crates/indexed-nullifier-tree`, `crates/commitment-tree`, `crates/protocol-types` | the invariants in `spec/security-model.md`; lineage (`Lineage`), escrow openings, fee and dust rules, the batched nullifier insertion and the authenticated commitment frontier |
| 6 | Covenant Script | `tools/rollup_covenant.py`, `risc0-succinct/` (padded SHA-256 suite verifier), `spec/bitcoin-binding.md` | the journal digests rebuilt with `OP_TX` cover every input, every output and the annex; successor-leaf derivation; `1 CSV`; escrow sweep and refund leaves (`tools/deposit_escrow.py`) |
| 7 | Wallet, SDK, batcher | `crates/wallet-core`, `prover/sdk`, `prover/batcher` | key handling, ciphertexts (ML-KEM-768 + XChaCha20-Poly1305), conflict handling, fee policy; liveness only: none of these can break soundness |

Pinned dependencies: RISC Zero v3.0.6 (with the patches above), Zirgen at the commit in
`patches/zirgen-zk.patch`, and the Bitcoin node `jmoik/bitcoin` branch `gsr` (`OP_TX = 0xbf`, deployment
`tapleaf_0xc2`).

## 2. Threat model

* **Users** are untrusted. They may submit malformed or replayed receipts, double-spend notes or funding coins,
  and race refunds against sweeps.
* **Operators (batchers)** are untrusted for soundness but trusted for liveness. Anyone can settle, because the
  covenant needs no signature. An operator may censor, reorder, delay, or race other operators.
* **Miners** may reorder or withhold settlements, and may mine any valid transaction.
* **Third parties** may create covenant copies, pay to the rollup script, or try to take empty-batch slots.
* **Not in scope:** side channels on user devices, the soundness of RISC Zero's own RV32IM and recursion
  circuits (an assumption), and GSR consensus bugs.

Privacy goal: a settlement reveals only the public statement of each join-split (nullifiers, output
commitments, ciphertexts, deposit and withdrawal amounts and scripts, fee, anchor, expiry). Deposit coins and
withdrawal outputs are public by design.

## 3. Adversarial coverage

| attack | result | evidence |
|---|---|---|
| tampered settlement (every input, output, sequence, lock time, amount, anchor, nullifier and frontier field) | the guest rejects it | `transition_rejects_every_settlement_tamper` (`tests/tests/scenario.rs`) |
| tampered settlement with a real receipt, on the gsr node: outputs changed, added or redirected, annex flipped or padded by 100 kB, seal flipped | the node rejects the block: the covenant Script fails an `OP_VERIFY` on input 0. Dropping the funding input fails earlier, on the value balance (`bad-txns-in-belowout`) | `tools/p6_adversarial.py` → `reports/p6-adversarial.json` |
| covenant copy: a real receipt and witness moved onto a copy coin | the node rejects it: the covenant Script fails an `OP_VERIFY` (the input digest no longer matches) | same run |
| covenant copy with a self-made receipt | the guest rejects it (`Lineage`) | `lineage_rejects_covenant_copies_and_forged_predecessors` |
| double-spent note, in the pool or in one batch | rejected | `double_spend_is_rejected_by_mempool_and_transition` |
| depositor double-spends a funding coin while the batch is being proven | the batcher abandons that proof, drops the entry, and re-proves without it | `tools/p4_e2e.py` (`reports/p4-e2e.json`, `reports/p5-e2e.json`) |
| competing settler wins the race | the loser's settlement no longer applies; its join-splits re-batch with their old anchors; a second batcher adopts the chain | `competing_settlements_extend_the_chain_once` (`tests/tests/adversarial.rs`), `tools/p4_e2e.py` |
| replaying a mined settlement | rejected by the node and the replica | `a_mined_settlement_cannot_be_replayed`, `tools/p6_adversarial.py` |
| empty-batch slot taking, to expire anchors | anchors never expire (append-only anchor tree). Taking slots only delays settlement, at the attacker's cost of a proof and a miner payment per block | `old_anchor_still_spends_after_many_batches`, `spec/protocol.md` |
| operator crash after broadcast | the restarted batcher resumes the in-flight settlement and records it once mined | `tools/p6_adversarial.py` |
| oversized or malformed annex | the scanner rejects padded or truncated bytes, a foreign rollup ID or a wrong root; the Script rejects any annex other than the one bound in the journal | `malformed_annexes_are_rejected_by_the_scanner`, `tools/p6_adversarial.py` |
| fee pinning or a low-fee settlement | admission floor, reward/CPFP anchor output, direct-to-miner submission | `reports/p4-fees.md`, `tools/p4_e2e.py` |
| refund racing a sweep after the escrow delay | the batcher stops sweeping at half the delay; a late settlement can still lose to a refund, costing the operator a re-prove | `tools/escrow_e2e.py`, `spec/security-model.md` |
| tampered or foreign user receipt | the batcher rejects it before pooling; RISC Zero accept/reject tests for the ZK mode | `prover/sdk/src/tests.rs`, `zk_*` tests in the patched `risc0-zkp` |

## 4. Reproducing

```sh
cd privacy-rollup
cargo test --workspace                                   # native protocol, trees, crypto, scenarios
(cd prover && GSR_BUILD_CPU_BATCH=1 GSR_CPU_BATCH_LANES=16 cargo build --release --bins --examples)
python3 tools/binding_check.py                           # covenant binding on gsr, stand-in verifier
python3 tools/p4_e2e.py                                  # fees, funding conflict, CPFP, adoption (~40 min)
python3 tools/p6_adversarial.py                          # real-receipt tampering, crash-resume, replay (~15 min)
```

The node is built from `jmoik/bitcoin` `gsr` with `-DENABLE_IPC=OFF` into `build/bitcoin`. Timings are for an
8-vCPU CPU host (`reports/p5-proving.md`).

## 5. Open questions for reviewers

1. Is Lemma 2 (the randomised quotient split) correct for RISC Zero's quotient degree and query pattern? Does the
   bound in §4 of `spec/zero-knowledge.md` hold with exact per-column tap counts, which were not computed?
2. Is it sound to admit `resolve_zk.zkr` to the control root next to the stock recursion programs?
3. Does any public field of the join-split statement (amounts, expiry, anchor choice) leak more than intended?
   Fixed denominations are not enforced.
4. Is genesis lineage by induction (`spec/security-model.md`, "Copies of the covenant") complete, including
   across reorgs?
5. Does the escrow sweep leaf's `OP_TX` check of input 0 admit any spend other than a genuine settlement?
6. Are there consensus edge cases in `OP_TX` on the pinned `gsr` commit that change what the journal digests cover?

## 6. Known limitations

* The privacy guarantee is statistical zero-knowledge in the random-oracle model, not perfect, and only sketched.
* Settlements carry an annex, so they are nonstandard and must go directly to miners.
* Proving times are from one 8-vCPU CPU host. The 16-transaction full settlement and batches of 2 and 8 were not
  fully proven (see `reports/p5-proving.md`).
* Funding coins in the regtest flows are `P2WSH(OP_TRUE)`. Real deposits should use the escrow addresses.
