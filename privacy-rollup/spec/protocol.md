# Protocol (version 1)

A BTC-only shielded pool whose entire state lives in one Taproot output, the *rollup output*. Each Bitcoin
settlement transaction spends the rollup output and creates its successor; a RISC Zero receipt of the
`apply_batch` guest proves that the successor state is the correct transition for exactly that transaction.

## Identity and genesis

`RollupDescriptor { protocol_version, genesis_nonce, image_id, internal_key, seed_sats }` fixes one instance.
`rollup_id = Fe(tagged("gsr-privacy-rollup/rollup-id", encode(descriptor)))` (top three bits cleared, so it is a canonical BN254 Fr element).

The genesis state (`pr_state_transition::genesis`) is: batch 0, empty commitment tree, the indexed nullifier
tree holding only the zero sentinel (`nullifier_next_index = 1`), a one-entry anchor history, zero data
history and `backing_sats = seed_sats`. The genesis transaction must spend `genesis_nonce` (which makes the
id unique: an outpoint can be spent once) and pay `seed_sats` to the covenant leaf of the genesis state root.
Scanners and wallets accept only the chain of rollup outputs that descends from that genesis output (see
`security-model.md` for why copies of the covenant are harmless).

## State

```
RollupState { rollup_id, protocol_version, batch_number, commitment_root, commitment_count,
              nullifier_root, nullifier_next_index, anchor_history_commitment,
              data_history_commitment, backing_sats }
state_root = tagged("gsr-privacy-rollup/state", encode(state))
```

* commitment tree: depth-32 append-only Poseidon2 Merkle tree of note commitments (`pr-commitment-tree`);
* nullifier tree: depth-32 indexed (linked-list) Merkle tree over SHA-256 (`pr-indexed-nullifier-tree`);
  insertion is authenticated by the low leaf whose interval brackets the new value, Aztec style;
* anchor history: the last 64 `(batch_number, commitment_root, commitment_count)` entries;
* data history: `next = tagged("…/data-history", prev || batch_number || body_digest)`, a hash chain of
  every published batch body;
* `backing_sats`: exactly the value of the rollup output.

## Notes and keys

`note = (value, authority, randomness)`, `commitment = H(TAG_NOTE, H(TAG_NOTE_INNER, rollup_id, value,
authority), randomness, 0)`; `authority = H(TAG_OWNER, secret)`, `nk = H(TAG_NK, secret)`;
`nullifier = H(TAG_NULLIFIER, nk, commitment, leaf_index)`. `H` is Poseidon2 over BN254 (t = 4, rate 3, tag
in the capacity lane), identical in `pr-crypto` and the Noir circuit. Note plaintexts are encrypted to the
recipient with ML-KEM-768 + XChaCha20-Poly1305 (`pr-wallet-core::encryption`), associated data
`rollup_id || commitment`, 1,232-byte ciphertexts.

## Transactions

Each user transaction is a 2-input / 2-output join-split proof (`joinsplit.md`) plus `ExternalData`:
an optional deposit declaration (funding outpoints, optional change), an optional withdrawal script and the
two output ciphertexts, committed through `external_data_commitment`. Accounting is
`in0 + in1 + deposit = out0 + out1 + withdrawal + fee`, every term ≤ `MAX_MONEY`.

## Batch transition (`apply_batch`)

For up to 8 transactions, all of which must be valid against the old state:

1. statement checks (`check_transaction`): version, rollup id, expiry, anchor ∈ window with matching root and
   count, external-data commitment, ciphertext lengths, deposit/withdrawal declarations, dust, nonzero
   nullifiers;
2. all nullifiers sorted, distinct, each inserted with a verified insertion witness;
3. all output commitments sorted, distinct, appended in that order to the authenticated frontier;
4. the settlement transaction: version 2, locktime 0, inputs `[rollup, funding..]` in declaration order,
   input 0 sequence 1 with empty scriptSig and amount `backing_sats`, outputs
   `[rollup successor, withdrawals.., changes.., reward?]`, each funding set paying exactly
   `deposit + change`;
5. fees: `F = Σ fee_sats`, optional reward output `R ≥ dust`, miner fee `M = F − R ≥ 0`,
   `Σ inputs − Σ outputs = M`, new `backing_sats = old + deposits − withdrawals − F ≥ dust`;
6. new anchor entry, data history, annex and the 196-byte journal (`bitcoin-binding.md`).

An empty batch (no transactions) is valid and only advances the batch number, anchors and data history.

## Cadence

The rollup leaf starts with `<old_root> 1 OP_CHECKSEQUENCEVERIFY OP_DROP`, so a successor cannot be spent in
the block that creates it: at most one settlement per block, enforced by consensus.
