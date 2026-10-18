# Protocol (version 1)

A BTC-only shielded pool whose entire state lives in one Taproot output, the *rollup output*. Each Bitcoin
settlement transaction spends the rollup output and pays the same fixed rollup address again, publishing the
new state root as `OP_RETURN <root>` in output 1; a RISC Zero receipt of the `apply_batch` guest proves that
the new state is the correct transition for exactly that transaction.

## Identity and genesis

`RollupDescriptor { protocol_version, genesis_nonce, image_id, internal_key, seed_sats }` fixes one instance.
`rollup_id = Fe(tagged("gsr-privacy-rollup/rollup-id", encode(descriptor)))` (top three bits cleared, so it is a canonical BN254 Fr element).

The genesis state (`pr_state_transition::genesis`) is: batch 0, empty commitment tree, the indexed nullifier
tree holding only the zero sentinel (`nullifier_next_index = 1`), a one-entry anchor history, zero data
history and `backing_sats = seed_sats`. The genesis transaction must spend `genesis_nonce` (which makes the
id unique: an outpoint can be spent once) and pay `seed_sats` to the covenant leaf of the genesis state root.
The genesis transaction must spend `genesis_nonce` as input 0 and hold the rollup at output 0; the genesis
state's `parent` is `genesis_nonce`. Every settlement proves lineage recursively (below), so only coins
descending from that genesis output can settle (see `security-model.md`).

## State

```
RollupState { rollup_id, protocol_version, batch_number, commitment_root, commitment_count,
              commitment_frontier, nullifier_root, nullifier_next_index, anchor_history_commitment,
              data_history_commitment, backing_sats, parent }
state_root = tagged("gsr-privacy-rollup/state", encode(state))
```

* commitment tree: depth-32 append-only Poseidon2 Merkle tree of note commitments (`pr-commitment-tree`);
  `commitment_frontier = tagged("…/commitment-frontier", count_le64 || node[0..32])` commits to the canonical
  frontier (left siblings of slot `commitment_count`) of that tree. Every accepted transition (and `genesis`)
  sets it from the same frontier as `commitment_root`, so the batch guest authenticates the frontier with one
  SHA-256 instead of recomputing the 32-level Poseidon2 root;
* nullifier tree: depth-32 indexed (linked-list) Merkle tree over SHA-256 (`pr-indexed-nullifier-tree`);
  insertion is authenticated by the low leaf whose interval brackets the new value, Aztec style. A batch's
  sorted nullifiers are inserted together (`verify_batch_insertion`): one path per distinct low leaf, then the
  new leaves are appended at consecutive slots from the left siblings of slot `nullifier_next_index`; the
  result equals inserting them one by one in ascending order;
* anchor history: the root of an append-only SHA-256 Merkle tree of depth 32 whose leaf `i` is
  `tagged("…/anchors", batch_number || commitment_root || commitment_count)` for the anchor after batch `i`
  (unused leaves are zero, nodes `tagged("…/anchor-node", left || right)`). Anchors never leave the history,
  so filling batches with empty settlements cannot invalidate a pending transaction; only the statement's
  own `expiry_batch_number` ends it;
* data history: `next = tagged("…/data-history", prev || batch_number || body_digest)`, a hash chain of
  every published batch body;
* `backing_sats`: exactly the value of the rollup output.
* `parent`: the outpoint spent by input 0 of the transaction that created the rollup output holding this
  state (`genesis_nonce` at genesis, otherwise the previous rollup output).

## Notes and keys

`note = (value, authority, randomness)`, `commitment = H(TAG_NOTE, H(TAG_NOTE_INNER, rollup_id, value,
authority), randomness, 0)`; `authority = H(TAG_OWNER, secret)`, `nk = H(TAG_NK, secret)`;
`nullifier = H(TAG_NULLIFIER, nk, commitment, leaf_index)`. `H` is Poseidon2 over BN254 (t = 4, rate 3, tag
in the capacity lane), identical in `pr-crypto` and the Noir circuit. Note plaintexts are encrypted to the
recipient with ML-KEM-768 + XChaCha20-Poly1305 (`pr-wallet-core::encryption`), associated data
`rollup_id || commitment`, 1,232-byte ciphertexts (kind 0). A note the sender pays to itself (change) is
instead sealed with XChaCha20-Poly1305 under the wallet's outgoing key `tagged("…/note-key", "outgoing" ||
seed)`, nonce `sha256(commitment)[..24]`, same associated data: 120 bytes (kind 1). Each commitment, and so
each nonce, is used once per key; scanners trial-decrypt kind 1 with their outgoing key and kind 0 with
their ML-KEM key.

## Transactions

Each user transaction is a 2-input / 2-output join-split proof (`joinsplit.md`) plus `ExternalData`:
an optional deposit declaration (funding outpoints, optional change), up to `MAX_WITHDRAWALS_PER_TX = 4`
withdrawal outputs `(value, script_pubkey)` whose values sum to the proven `withdrawal_sats`, and the two
output ciphertexts, committed through `external_data_commitment`. Accounting is
`in0 + in1 + deposit = out0 + out1 + withdrawal + fee`, every term ≤ `MAX_MONEY`.

## Batch transition (`apply_batch`)

For up to `MAX_BATCH_TRANSACTIONS = 16` transactions, all of which must be valid against the old state.
The witness carries the siblings of the next empty anchor slot (leaf `batch_number + 1`), which must hash
to the old anchor root, and one membership path per transaction anchor:

1. statement checks (`check_transaction`): version, rollup id, expiry, anchor a member of the history tree with
   matching root and count, external-data commitment, ciphertext kinds, deposit/withdrawal declarations (each
   withdrawal ≥ dust, Σ = `withdrawal_sats`, each with a withdrawal leaf as below), no deposit change, nonzero
   nullifiers;
2. all nullifiers sorted, distinct, each inserted with a verified insertion witness;
3. all output commitments sorted, distinct, appended in that order to the authenticated frontier;
4. the settlement transaction: version 2, locktime 0, inputs `[rollup, funding.., escrows..]` (funding in
   declaration order, sequence `FUNDING_INPUT_SEQUENCE = 1`; escrows as below, sequence `ESCROW_INPUT_SEQUENCE = 2`),
   input 0 sequence 1 with empty scriptSig and amount `backing_sats`, spending output 0 of the private
   witness `predecessor_tx` (witness-free; `sha256d(predecessor_tx) = input 0 txid`) whose own input 0
   spent `old.parent`; the new state's `parent` is input 0's prevout (`check_lineage`). At batch 0 `old` must
   be `genesis(descriptor)`; past it, the guest verifies a receipt of `descriptor.image_id` for the
   predecessor journal rebuilt from `predecessor_tx`, the outputs it spent, its old root and annex digest
   (`LineageClaim`); `predecessor_tx` output 1 must be `OP_RETURN 0x20 <old.root()>` with value 0. Outputs
   `[rollup (same scriptPubKey as input 0, RollupScript), OP_RETURN 0x20 <new root> (value 0, RootOutput),
   withdrawals..]`, each funding set paying exactly `deposit`, each withdrawal output
   `P2TR(NUMS, {leaf})` for its committed leaf;
5. fees: `F = Σ fee_sats` is the miner fee, `Σ inputs − Σ outputs = F`,
   new `backing_sats = old + deposits − withdrawals − F ≥ dust`;
6. new anchor leaf (written into the empty slot, giving the new root), data history, annex and the 196-byte journal (`bitcoin-binding.md`).

## Fee policy (batcher, not consensus)

The guest only enforces item 5 above; who pays how much is the batcher's policy (`prover/batcher/src/fees.rs`).
Let `r` be the feerate (sat/vB: fixed, or `estimatesmartfee` with a floor) and `fee(w) = ceil(w * r / 4)`.

* **Quote** (`GET /v1/fees`): the verifier spend (`EMPTY_SETTLEMENT_WEIGHT`, 332,000 WU, rounded up from the
  measured 331,699 WU empty settlement) is shared over the target batch size `T`:
  `price(kind) = ceil(fee(332,000) / T) + fee(typical weight of kind)`. The response also reports what the
  current pool would pay and whether a settlement is due.
* **Admission**: a transaction paying less than `fee(entry_weight)` (its own content) is rejected with 400.
* **Shortfall**: before proving, `Σ fee_sats` (pool selection plus sweepable escrows) must cover
  `fee(332,000 + content)`; otherwise `POST /v1/batches` returns 409 and nothing is proven.
* **All fees to the miner**: there is no reward, P2A or other anchor output and no CPFP. A user raises a fee by
  proving the same join-split again with a higher `fee_sats`; the next batch replaces the pending settlement
  under ordinary RBF (it spends the same rollup coin and pays more).
* **When** (`--auto SECS`): only when fees cover the settlement, and then when the pool holds `T` transactions,
  the content would not fit another transfer, or the oldest admitted transaction has waited `--max-wait`.
  Empty settlements are never started automatically.
* **Submission**: under the pinned node's policy settlements carry an annex and are nonstandard, so
  `--submit-url` sends them straight to a miner's node; under bitcoin/bitcoin#36466 (open, not merged) they
  relay publicly (`reports/relay-pinning.md`).
* **No spendable handles**: nothing in a settlement is spendable while it is unconfirmed, so it can have no
  descendants to pin it, and it has no unconfirmed parents:
  * withdrawal outputs are `P2TR(NUMS, {leaf})` with `leaf = OP_1 OP_CHECKSEQUENCEVERIFY OP_DROP || tail`
    (`WITHDRAWAL_LEAF_PREFIX`, ≤ `MAX_WITHDRAWAL_LEAF_LEN` = 1,024 bytes, version `0xc0`). The leaf is part
    of the join-split's `RollupTransaction` (`withdrawal_leaves`) and the guest checks each withdrawal
    script against it. Wallets build them with `withdrawal(value, key_tail(xonly))`: the recipient's key
    spends with sequence ≥ 1, one block after the settlement confirms. Paying an exchange address directly
    is not possible; the recipient forwards the coin. The one-block delay is a protocol choice;
  * the rollup leaf already carries `1 OP_CHECKSEQUENCEVERIFY`, and the root output is an unspendable `OP_RETURN`;
  * there are no change, reward or P2A outputs (a declared deposit change is rejected, `ChangeOutput`);
  * funding inputs (sequence 1) and escrows (sequence 2) are BIP 68 locked, so a settlement spending an
    unconfirmed funding coin or escrow is non-final. The batcher defers settling while a funding coin is
    unconfirmed and sweeps escrows only from two confirmations.

  Tests: `settlement_has_no_unconfirmed_spend_path` (`tests/tests/scenario.rs`) and
  `tools/policy/gsrpp_no_pin_handles.py` (node policy, `reports/no-pin-handles.json`).
* **Pinning and conflicts**: funding coins and escrows are re-checked with `gettxout` (mempool included) before
  proving and before every (re)broadcast. A coin spent elsewhere, including by a low-fee unconfirmed
  transaction from its own depositor, drops that transaction from the pool and abandons the proven settlement,
  which is rebuilt without it. Before proving and before broadcasting, the batcher also checks whether the
  rollup output was already spent; a confirmed spender is decoded from its annex, verified against the replica
  (`Store::accept`) and adopted as the new tip, and any conflicting in-flight settlement is dropped.

## Deposit escrows (non-interactive deposits)

A depositor needs no proof and no round trip: the SDK (`Wallet::deposit_address`) picks a note and returns a
taproot address `P2TR(NUMS, {sweep (leaf version 0xc2), refund (0xc0)})` that any wallet can pay.

* `D = sha256("GSR-rollup/escrow-v1" || rollup_id || authority || randomness || value || fee_sats ||
  sha256(ciphertext))`, where the ciphertext may be either kind (a depositor paying its own wallet can use a
  120-byte self ciphertext); the sweep leaf is `0x20 D OP_DROP || body`, where `body` (`covenant_cli escrow-body`,
  served at `GET /v1/escrow`) uses `OP_TX` to require that the escrow input's own annex is exactly the one-byte marker `0x50`, that the
  sweeping transaction's input 0 spends this rollup's fixed address (its scriptPubKey, the same for every state,
  whose only spend path is the covenant), and that the escrow input itself has sequence `ESCROW_INPUT_SEQUENCE = 2` (matched as
  `OP_TX`'s minimal numeric encoding `02`; as a BIP 68 lock it also requires two confirmations of the escrow).
* The refund leaf is `<delay> OP_CHECKSEQUENCEVERIFY OP_DROP <xonly> OP_CHECKSIG`; the batcher requires
  `delay ≥ --min-refund-delay` (default 144 blocks).
* `apply_batch` gets each escrow's opening privately (`BatchWitness::escrows`), checks that the sweep leaf
  starts with `D`, that the input's output key is the NUMS key tweaked by `{sweep, sibling}`, that the input
  has the escrow sequence and an empty scriptSig and holds exactly `value + fee_sats`, then appends the note's
  commitment and ciphertext and counts `value + fee_sats` as deposited and `fee_sats` as fee. Only escrow inputs
  may carry the escrow sequence, so the covenant check in the sweep leaf cannot be satisfied by a funding input.
* Copies: P2a lineage means only the genuine rollup coin has receipts, and `D` commits to the rollup id, so an
  escrow can be swept only by the genuine rollup, minting exactly the depositor's note.

The batcher (`POST /v1/escrows`) accepts a registration (outpoint, opening, refund leaf) only if the output
exists (`gettxout`), opens to the escrow, pays exactly `value + fee_sats`, and the refund leaf is the sweep
leaf's sibling with a long enough delay. Before each batch it re-reads every registered escrow and sweeps only
those with `confirmations ≥ --confirmations` and `2 · confirmations ≤ delay` (far from refundable); spent or
changed outputs are dropped, swept ones removed once the settlement confirms.

An empty batch (no transactions) is valid and only advances the batch number, anchors and data history.

## Cadence

The rollup leaf starts with `1 OP_CHECKSEQUENCEVERIFY OP_DROP`, so a new rollup output cannot be spent in
the block that creates it: at most one settlement per block, enforced by consensus.
