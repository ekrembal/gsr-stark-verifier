# Security model and limitations

## Assumptions

* **RISC Zero**: soundness of the v3.0.6 RV32IM, recursion and padded-SHA-256 identity circuits (~97-bit
  conjectured FRI security, as stock); the padded hash suite patch in `risc0-succinct/` is not upstream and
  not audited.
* **ProveKit / WHIR**: soundness of the ProveKit WHIR-R1CS verifier compiled into the guest, at the revision
  pinned in `crates/provekit-adapter/Cargo.toml`. Post-quantum: hash-based only. Its own verifier ignores a
  returned `FinalClaim` in three places (compiler warnings in `provekit/verifier/src/whir_r1cs.rs`). In pinned
  `provekit-whir` 0.2.0, the zkWHIR path checks that blinded linear-form claim inline and checks the
  blinding polynomial's claim internally. These warnings therefore do not, by themselves, demonstrate
  an omitted check in this version. This is source inspection, not a soundness proof; upstream review
  and regression coverage are still needed. See [the optimization audit](../reports/aggregation-optimizations.md).
* **Poseidon2 (BN254)** for notes, nullifiers and the commitment tree; **SHA-256** everywhere else;
  **ML-KEM-768 + XChaCha20-Poly1305** for note confidentiality.
* **GSR** consensus rules at the pinned commit, including `OP_TX` semantics as implemented there.

## Invariants and where they are enforced

| invariant | enforced by |
|---|---|
| only valid join-splits change the state | guest verifies every ProveKit proof against its exact public inputs |
| no double spend | nullifier tree insertion witnesses; sorted distinct nullifiers |
| value conservation, no overflow | circuit range checks + `apply_batch` checked arithmetic |
| the transaction is the one the guest saw | journal digests recomputed by the script with `OP_TX` |
| state continuity | old root is the leaf prefix; successor leaf derived by the script |
| verifier cannot be replaced | successor leaf keeps the identical suffix; single leaf under NUMS |
| at most one settlement per block | `1 CSV` on the leaf |
| data availability | every nullifier and ciphertext is in the input-0 annex, bound by the journal |

## Copies of the covenant

Anyone can pay to the leaf of an existing state root, creating a second coin with the same script. Spending it
requires a valid receipt whose predecessor amount equals the copied state's `backing_sats`, so a copy is a
self-funded fork: notes valid at the forked state could be withdrawn from it, paid entirely by whoever funded
the copy. Wallets and the operator follow only the outpoint chain that descends from the genesis output.

## Not implemented / not yet established

* **Proving join-split batches.** A batch containing one ProveKit proof is executed in the guest
  (the original baseline was 1.21B cycles; see [current measurements](../reports/aggregation-optimizations.md))
  with a journal identical to the native transition, but the original proving estimate was ~100 h
  on the available 8-core CPU, so no such receipt exists yet. Only empty (anchor-only) batches are proven
  and settled on regtest.
* **Operator**: `pr-operator submit` verifies the ProveKit proof and reserves nullifiers and funding coins in a
  persisted pool (`tools/operator_joinsplit.py`), but funding coins are taken from the submitter's
  `funding.json` rather than looked up over Bitcoin RPC, nothing is signed or broadcast (the demo builds,
  signs and mines the transactions itself), and cadence is left to the leaf's `1 CSV` rather than tracked.
* **Relay policy**: annex-bearing spends are nonstandard on the pinned node.
* **External review** of the circuit, adapter, guest, covenant script and wallet has not happened.
