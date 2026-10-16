# Security model and limitations

## Assumptions

* **RISC Zero**: soundness of the v3.0.6 RV32IM, recursion and padded-SHA-256 identity circuits (~97-bit
  conjectured FRI security, as stock); the padded hash suite patch in `risc0-succinct/` is not upstream and
  not audited.
* **User join-split receipts**: each user proves the `joinsplit` guest and releases only an `identity_zk`
  receipt, a seal from the zero-knowledge prover mode added to `risc0-zkp`. Privacy rests on that mode:
  fresh padding, salted Merkle leaves, randomised quotient pieces and a FRI mask. Soundness rests on RISC
  Zero recursion plus the new `resolve_zk.zkr` recursion program, built with a patched Zirgen and added to
  the allowed control root. The zero-knowledge argument is a proof sketch
  ([zero-knowledge.md](zero-knowledge.md)), statistical in the random-oracle model. It has not been
  reviewed, and neither the ZK mode nor `resolve_zk.zkr` is upstream or audited.
* **Poseidon2 (BN254)** for notes, nullifiers and the commitment tree; **SHA-256** everywhere else;
  **ML-KEM-768 + XChaCha20-Poly1305** for note confidentiality.
* **GSR** consensus rules at the pinned commit, including `OP_TX` semantics as implemented there.

## Invariants and where they are enforced

| invariant | enforced by |
|---|---|
| only valid join-splits change the state | guest calls `env::verify(JOINSPLIT_ID, statement)` per transaction; `resolve_zk` discharges each assumption with the user's receipt |
| the user witness stays private | only the `identity_zk` seal leaves the user; ordinary segment and lift/join seals stay local |
| no double spend | nullifier tree insertion witnesses; sorted distinct nullifiers |
| value conservation, no overflow | circuit range checks + `apply_batch` checked arithmetic |
| the transaction is the one the guest saw | journal digests recomputed by the script with `OP_TX` |
| state continuity | old root is the leaf prefix; successor leaf derived by the script |
| verifier cannot be replaced | successor leaf keeps the identical suffix; single leaf under NUMS |
| at most one settlement per block | `1 CSV` on the leaf |
| data availability | every nullifier and ciphertext is in the input-0 annex, bound by the journal |

## Copies of the covenant

Anyone can pay to the leaf of an existing state root, creating a second coin with the same script. The covenant
only sees its own prevout, but `apply_batch` proves lineage by induction: the state commits to `parent`, the
outpoint spent to create the coin holding it, and a settlement must spend output 0 of a transaction
(`predecessor_tx`, a private witness hashed to input 0's txid, which the journal's input digest commits) whose
input 0 spent `parent`. At genesis `parent = genesis_nonce`, which only the genesis transaction can spend; each
genuine settlement spends the previous genuine output, which nothing else can spend. A copy coin, at the
current or any older root, was created by some other transaction, so no receipt for spending it exists: paying
to a copied leaf burns the coins. This is what lets deposit escrows (P2b) trust "input 0 is the rollup leaf".
Tests: `lineage_rejects_covenant_copies_and_forged_predecessors` in `tests/tests/scenario.rs`.

## Deposit escrows

Escrow deposits (`protocol.md`) can be swept only by a settlement whose input 0 runs this rollup's covenant
(script, checked with `OP_TX`) and whose receipt opens the escrow to the note it commits to (guest). The
depositor can refund through the CSV leaf after the delay. Remaining risk: a refund and a sweep race once the
delay has passed; the batcher stops sweeping an escrow at half its delay, but a settlement that is proven and
then delayed past the refund height can be invalidated by the refund, which costs the operator a re-prove.
Tests: `tools/deposit_escrow.py node-test` (sweep body on the gsr node), `tools/escrow_e2e.py` (SDK → batcher →
proven sweep, refunds), `deposit_addresses` in `prover/sdk/src/tests.rs`, escrow cases in
`tests/tests/scenario.rs`.

## Not implemented / not yet established

* **Proving cost.** User proving and settlement proving were measured on one 8-vCPU CPU host only. See
  [the measurements](../reports/zk-joinsplit.md). Multi-transaction batches are estimated, not measured.
* **Operator**: `pr-operator submit` verifies the zero-knowledge receipt and its claim and reserves nullifiers and funding coins in a
  persisted pool (`tools/operator_joinsplit.py`), but funding coins are taken from the submitter's
  `funding.json` rather than looked up over Bitcoin RPC, nothing is signed or broadcast (the demo builds,
  signs and mines the transactions itself), and cadence is left to the leaf's `1 CSV` rather than tracked.
* **Relay policy**: annex-bearing spends are nonstandard on the pinned node.
* **External review** of the circuit, adapter, guest, covenant script and wallet has not happened.
