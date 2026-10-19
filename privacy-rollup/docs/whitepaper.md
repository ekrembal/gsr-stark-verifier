# gsr-privacy-pool: a shielded Bitcoin pool settled by an on-chain STARK verifier

Version 1 (protocol version 1). This describes the code in `privacy-rollup/` at the end of phases P0–P6.

> **Status.** Research code, not audited and not for production. No external review has taken place. Unless
> marked as an estimate, every number here was measured on one 8-vCPU, 31 GiB CPU machine, on regtest with the
> optimized GSR node (`jmoik/bitcoin`, branch `gsr`). Domain-separation tags in the code still use the
> earlier name, `gsr-privacy-rollup/…`. They are part of the protocol encoding and are kept as they are.

## Abstract

gsr-privacy-pool is a shielded pool for BTC whose entire state is one Taproot output. Users own private notes
and spend them with 2-input/2-output join-split transactions. Each user proves their join-split locally as a
zero-knowledge RISC Zero receipt. A permissionless batcher composes up to 16 such receipts into one
settlement receipt using RISC Zero assumptions (`add_assumption`, `env::verify`, `resolve_zk`). The pool's
Tapscript v2 leaf is a complete RISC Zero succinct-receipt verifier written in Bitcoin Script. It uses `OP_TX`
to bind the receipt's journal to the spending transaction's inputs, outputs and annex. No signature, operator
key or federation can spend the pool. Genesis lineage, proven recursively inside the guest, makes copies of
the covenant unspendable. That also lets non-interactive deposit addresses trust that only the genuine pool
sweeps them. On regtest, a settlement of three deposits weighs 333,485 WU, an empty one 331,699 WU, and a
3-deposit batch went from batch request to confirmation in 640 s.

## 1. Goals and non-goals

**Goals.**
- **Trust-minimised custody:** the pool's coins move only under a valid proof of a valid state transition.
- **Privacy of transfers:** a transfer reveals no amounts, senders or recipients, only nullifiers, note
  commitments and ciphertexts.
- **Post-quantum assumptions:** hash-based proofs (STARKs over BabyBear with SHA-256 and Poseidon2),
  ML-KEM-768 for note encryption, and no pairings, elliptic-curve discrete logs or trusted setup in the
  proof path.
- **Data availability on Bitcoin:** everything needed to rebuild the state is in the settlement's annex.
- **Permissionless operation:** anyone can batch and settle, and a user can settle their own transaction.
- **Usable deposits:** a deposit can be an ordinary payment from any wallet.

**Non-goals (v1).** Assets other than BTC, hiding deposit and withdrawal amounts (they are public by design),
relay through the standard mempool, and network-level privacy.

## 2. Background

**GSR.** A soft-fork proposal that restores disabled opcodes and adds Tapscript v2 (leaf version `0xc2`),
with budgets based on *varops* rather than opcode counts. Two parts matter here:
- **`OP_TX` (`0xbf`):** pushes selected fields of the spending transaction (inputs, outputs, annex, the
  current input's tapscript and taptree data).
- **Arithmetic and hashing:** enough of both to verify a STARK in Script.

The node used is `jmoik/bitcoin` branch `gsr` (built with `-DENABLE_IPC=OFF`), activated on regtest with
`-vbparams=tapleaf_0xc2:0:3999999999`. Its `OP_MACRO`/`OP_CALLMACRO` compression shrinks the verifier leaf to
101,688 B.

**RISC Zero.** A zkVM for RV32IM. Execution is split into segments, each proven with a STARK over BabyBear.
Recursion programs (`lift`, `join`, `resolve`, `identity`) compress them into one *succinct receipt*. A receipt
proves a `ReceiptClaim`: image ID, journal digest, exit code and assumptions. `env::verify(image, journal)`
inside a guest adds an *assumption*, which the host later discharges with a receipt for that claim. We use
v3.0.6 with three patches:
- **`risc0-succinct/`:** a padded SHA-256 hash suite, so that the final receipt is cheap to verify in Script.
- **`patches/risc0-zk.patch`:** a zero-knowledge prover mode (§8).
- **`patches/zirgen-zk.patch`:** a new recursion program, `resolve_zk.zkr`, that discharges an assumption
  using a zero-knowledge seal.

## 3. System overview

```
user device                         batcher (anyone)                          Bitcoin (GSR)
-----------                         ----------------                          -------------
JoinSplitWitness
 -> joinsplit guest                 verify ZK receipt + exact claim
 -> segments, lift, join (local)    pool (nullifier / funding reservations)
 -> identity_zk  ── receipt ──────► apply_batch guest:
    (~276 KB, ZK)                     env::verify(JOINSPLIT_ID, stmt) × n
                                      state transition, journal (196 B)
                                    segments -> lift/join -> resolve_zk × n
                                    -> identity (padded SHA-256)
                                    settlement tx + witness  ─────────────►  rollup leaf:
                                                                              Script STARK verifier
                                                                              + OP_TX journal binding
                                                                              -> output 0: same address
                                                                              -> output 1: OP_RETURN <new root>
```

**Roles.**
- **Users:** hold note secrets and an ML-KEM key. They prove join-splits and scan annexes for their notes.
- **Batchers:** untrusted for safety and trusted only for liveness. Several can compete, and a user can be
  their own batcher.
- **Miners:** include settlements submitted directly to them (§11.4).
- **Scanners and replicas:** anyone can replay annexes to rebuild the state (`pr-scanner`).

## 4. Cryptographic primitives

| purpose | primitive |
|---|---|
| note commitments, nullifiers, key derivation, commitment tree | BIP-340-style tagged SHA-256, top three bits cleared (`Fe::from_digest`) |
| state root, anchors, nullifier tree, data history, journal digests, rollup id | BIP-340-style tagged SHA-256 |
| recipient note encryption | ML-KEM-768 + XChaCha20-Poly1305 (1,232-byte ciphertext, kind 0) |
| self/change note encryption | XChaCha20-Poly1305 under the wallet's outgoing key (120 bytes, kind 1) |
| user and settlement proofs | RISC Zero STARKs (BabyBear, Poseidon2 inside recursion, SHA-256 claim digests) |
| final receipt verified on chain | RISC Zero succinct receipt under the padded SHA-256 suite |

Note, nullifier, key and commitment-tree hashes are tagged SHA-256 with the top three bits cleared, so every
value is a canonical BN254 `Fe` (253 bits, about 126-bit collision resistance). In the guests they run on the
RISC Zero SHA-256 accelerator. The Noir/ProveKit reference circuit in `circuits/joinsplit-2x2` still uses the
former Poseidon2 hashes and no longer matches.

All protocol objects have exactly one encoding (`spec/encoding.md`):
- integers are fixed-width little endian;
- field elements are 32-byte big endian and must be canonical;
- lengths use minimal CompactSize;
- decoders reject trailing bytes.

## 5. State

The pool is fixed by a descriptor:

```
RollupDescriptor { protocol_version, genesis_nonce: Outpoint, image_id, internal_key, seed_sats }
rollup_id = Fe(tagged("…/rollup-id", encode(descriptor)))      (top 3 bits cleared)
```

The state, whose root is the leaf's first push:

```
RollupState {
  rollup_id, protocol_version, batch_number,
  commitment_root, commitment_count, commitment_frontier,     // note commitments
  nullifier_root, nullifier_next_index,                       // spent nullifiers
  anchor_history_commitment,                                  // every past commitment root
  data_history_commitment,                                    // hash chain of batch bodies
  backing_sats,                                               // == value of the pool output
  parent,                                                     // lineage (§9)
}
state_root = tagged("…/state", encode(state))
```

- **Commitment tree:** a depth-32 append-only Merkle tree, node `tagged("…/note-node", left || right)`.
  `commitment_frontier = tagged("…/commitment-frontier", count || left siblings)` lets the guest authenticate
  the frontier with one SHA-256. It does not recompute the 32-level root. Every transition sets both
  values from the same frontier, so they stay consistent by induction.
- **Nullifier tree:** a depth-32 indexed (sorted linked-list) Merkle tree over SHA-256. Non-membership and
  insertion are proven against the *low leaf* whose interval brackets the new value. A batch's sorted
  nullifiers are inserted together: one path per distinct low leaf, then the new leaves are appended at
  consecutive slots from one 32-node frontier (`verify_batch_insertion`). The result equals inserting them one
  at a time.
- **Anchor history:** an append-only depth-32 SHA-256 Merkle tree. Leaf `i` is the anchor after batch `i`:
  `(batch_number, commitment_root, commitment_count)`. Anchors never leave it (§11.3).
- **Data history:** `next = tagged("…/data-history", prev || batch_number || sha256(body))`.

**Genesis.** The genesis transaction must spend `genesis_nonce` as input 0 and pay `seed_sats` at output 0 to
the leaf of the genesis state. That state is batch 0, with empty trees, one anchor, and
`parent = genesis_nonce`. Because an outpoint can be spent only once, `rollup_id` is unique.

## 6. Notes and join-splits

```
note        = (value, authority, randomness)
authority   = H(OWNER, secret)          nk = H(NK, secret)
commitment  = H(NOTE, H(NOTE_INNER, rollup_id, value, authority), randomness, 0)
nullifier   = H(NULLIFIER, nk, commitment, leaf_index)
```

**Public statement** (`JoinSplitPublic`, committed as the user guest's journal):

```
rollup_id, protocol_version, anchor_root, anchor_commitment_count, anchor_batch_number,
nullifiers[2], output_commitments[2], deposit_sats, withdrawal_sats, fee_sats,
external_data_commitment, expiry_batch_number
```

**What the join-split guest proves** (`JoinSplitWitness::check`, `methods/guest/src/bin/joinsplit.rs`):
1. **Version and expiry:** `protocol_version = 1` and `anchor_batch_number ≤ expiry_batch_number`.
2. **Ranges:** every amount (both inputs, both outputs, deposit, withdrawal, fee) is at most `MAX_MONEY`.
3. **Inputs:** for each input, the note is recomputed from its secret. If its value is nonzero, the note sits
   at `index < anchor_commitment_count` under `anchor_root`. Its nullifier is derived correctly and is nonzero,
   and the two nullifiers differ. A zero-value (dummy) input skips membership but still consumes a nullifier.
4. **Outputs:** both output commitments are recomputed correctly and are distinct.
5. **Balance:** `in0 + in1 + deposit = out0 + out1 + withdrawal + fee`.

**External data** (`ExternalData`) is bound through `external_data_commitment`:
- an optional deposit declaration: up to 4 funding outpoints (a change output is rejected);
- up to 4 withdrawal outputs `(value, script_pubkey)`, each above dust and summing to `withdrawal_sats`, each
  paying `P2TR(NUMS, {OP_1 OP_CSV OP_DROP || tail})` for a leaf carried with the transaction (§11);
- the two output ciphertexts.

**Transaction kinds.**
- **Deposit:** `deposit_sats > 0`, with dummy inputs. The funding coins become settlement inputs and must
  pay exactly `deposit`.
- **Transfer:** real inputs and outputs, no public amount except `fee_sats`.
- **Withdrawal:** `withdrawal_sats > 0`, paid as up to 4 settlement outputs.

Mixed batches of any kinds are allowed.

## 7. Batch transition (`apply_batch`)

The same Rust code runs natively (batcher, scanner, tests) and in the guest (`pr-state-transition`). For up to
`MAX_BATCH_TRANSACTIONS = 16` transactions and `MAX_BATCH_ESCROWS = 16` escrow openings:

1. **Per-transaction statement checks:**
   - **Identity:** version, rollup id, and not expired.
   - **Anchor:** a member of the anchor-history tree, with matching root and count.
   - **External data:** matches its commitment.
   - **Ciphertexts and declarations:** ciphertext kinds and lengths valid, deposit and withdrawal
     declarations consistent.
   - **Proof:** `env::verify(JOINSPLIT_ID, encode(statement))`.
2. **Nullifiers:** all sorted, distinct and nonzero, and inserted with a verified batch-insertion witness.
3. **Commitments:** all output commitments (plus escrow-minted ones) sorted, distinct and appended from the
   authenticated frontier.
4. **Settlement transaction:**
   - **Header:** version 2, locktime 0.
   - **Input order:** `[rollup, funding.., escrows..]`. Input 0 spends output 0 of the private
     `predecessor_tx` with sequence 1 and amount `backing_sats`; lineage is checked (§9).
   - **Output order:** `[rollup, OP_RETURN <new_state_root>, withdrawals..]`. Output 0 pays `backing_sats` to the
     same scriptPubKey input 0 spent (the pool's fixed address); output 1 is exactly `0x6a 0x20 <new root>` with
     value 0 (`RootOutput`); no change or reward outputs.
   - **Sequences:** funding inputs 1, escrows 2 (BIP 68 locks: no unconfirmed parents).
   - **Funding:** each funding set pays exactly `deposit`.
5. **Fees:** `F = Σ fee_sats` is the miner fee: `Σ inputs − Σ outputs = F`. The new `backing_sats = old + deposits − withdrawals − F ≥ dust`.
6. **New state:** the new anchor is written into the next empty anchor slot, the data history is extended,
   and the guest outputs the annex and the journal.

Every check returns a typed `TransitionError` (for example `Lineage`, `Escrow`, `FeeShortfall`,
`DuplicateNullifier`, `UnknownAnchor`). The native and guest journals are equal byte for byte.

**Journal (196 bytes):**

```
protocol_version u32 || rollup_id || old_state_root || new_state_root
|| SHA256(inputs preimage) || SHA256(outputs preimage) || SHA256(annex)
```

**Annex (input 0):** `0x50 || 0x00 || "GSRP" || 0x01 || old_root || new_root || BatchBody`, where `BatchBody` holds:
- rollup id, batch number and predecessor outpoint;
- section counts;
- sorted nullifiers;
- sorted `(commitment, kind, ciphertext)` entries.

An empty-batch annex is 153 bytes. A deposit adds 370 bytes; a transfer with one recipient and self change
adds 1,482 bytes.

## 8. Zero-knowledge user receipts and composition

**ZK mode** (`Prover::new_zk` / `Verifier::new_zk`). Ordinary RISC Zero seals are not hiding. On the CPU path
we found no padding noise in the main circuit, and recursion padding repeated one random value. The ZK mode
follows Haböck and Kindi (ePrint 2024/1037):
1. **Fresh padding:** fresh uniform values in the last 1,024 rows of every hidden column.
2. **Salted leaves:** Merkle leaves of hidden groups carry 4 uniform BabyBear salt elements (about 123.6 bits).
3. **Randomised quotient:** the quotient is split into `INV_RATE + 1 = 5` pieces, re-randomised by
   telescoping degree-below-64 masks, and opened at `z`.
4. **FRI mask:** a uniform masking polynomial is committed before `z` and added to the DEEP/FRI batch.

The user releases only the `identity_zk` seal. Segment and lift/join seals stay on the device.

**Claim** (`spec/zero-knowledge.md`): statistical zero-knowledge in the random-oracle model, with distance
about `q · 2^-120` for a verifier making `q` oracle queries (computed from the bounds, not measured). The
simulator samples the hidden openings: a determinant (independence) argument for padding rows, a counting argument for
the quotient pieces, a uniform FRI polynomial, and salted-leaf hiding.

**This is a proof sketch.** Lemma 2 (the quotient split) is only a counting argument, the per-column tap
counts were bounded loosely rather than computed, and nothing has been reviewed.

**Composition.** The batcher checks the user receipt (`verify_integrity_zk_with_context` plus the exact claim
`ReceiptClaim::ok(JOINSPLIT_ID, statement)`), then adds the claim with `add_assumption`. The guest calls
`env::verify` per transaction.

RISC Zero's composite prover won't resolve receipts it didn't produce, so `settle prove` runs the
pipeline itself:

```
segments -> lift -> join -> resolve_zk (one per user receipt) -> identity under the padded SHA-256 suite
```

`resolve_zk.zkr` (24,007,400 of the recursion circuit's 24,023,040 program values) is in the allowed control
root `5edc9538…5b01`. The on-chain receipt is an ordinary seal over the batcher's witness. That witness is
public data plus user ZK seals, which are already simulable, so composition adds no leak beyond the
statements.

## 9. Bitcoin binding and lineage

The pool output is P2TR with the NUMS internal key and exactly one `0xc2` leaf, the same for every state, so
the pool has one fixed address:

```
leaf = 1 OP_CHECKSEQUENCEVERIFY OP_DROP || suffix
```

`suffix` embeds the rollup id, the `apply_batch` image ID, the control root and the complete verifier. The
state root is not in the script: each settlement publishes its new root as output 1, `OP_RETURN <new_root>`,
in non-witness data that the next settlement's txid-checked lineage reads. Using `OP_TX`, the suffix checks that:
- it runs as input 0;
- the coin is a single-leaf tree under NUMS;
- output 0 pays the scriptPubKey input 0 spent (its own address);
- the journal's three digests match the real transaction (every input's prevout, amount, scriptPubKey,
  scriptSig and sequence, plus version and locktime; every output; and input 0's annex).

It then rebuilds the `ReceiptClaim` for the fixed image with exit code `Halted(0)`, and verifies the succinct
receipt. The key path is unspendable, and there is no other leaf.

The guest reads the transaction from the same bytes whose digests the Script recomputes. So the
transaction the guest checked is the one being spent.

**Lineage.** A script sees only its own coin, so anyone can create a *copy*: another output paying the same
address (with any `OP_RETURN` root beside it), or a leaf of their own. The guest closes this recursively:
1. `state.parent` is the outpoint that input 0 of the creating transaction spent.
2. The settlement witness includes that transaction, `predecessor_tx`, without its witness data, and the
   outputs its inputs spent.
3. The guest checks that `sha256d(predecessor_tx)` equals input 0's txid, that input 0 spends `vout 0`, and
   that `predecessor_tx`'s own input 0 spent `state.parent`. The new state sets `parent` to input 0's prevout.
4. At batch 0 the old state must be `genesis(descriptor)` (`parent = genesis_nonce`).
5. Past genesis, the guest rebuilds the predecessor's journal (its inputs and outputs digests from
   `predecessor_tx` and the spent outputs, its old root and annex digest, and `new_state_root = old.root()`,
   which must also be what `predecessor_tx` published in its output 1)
   and verifies a receipt of the pool's own image for it. The batcher supplies the predecessor's unconditional
   receipt as an assumption, which recursion discharges (`resolve`); anyone holding only the chain can instead
   pass the predecessor's on-chain padded-SHA receipt, which the guest verifies itself.

Steps 1–3 alone are not enough: an attacker can choose a state with the genuine rollup id and its own coin as
`parent`. Step 5 makes every proven state descend from the genuine genesis, so no receipt can exist for a copy,
and paying to the pool's address outside a settlement burns the coins. This costs no extra on-chain bytes; the guest and proving cost is measured in `reports/lineage.md`; the fixed-address layout (weight, varops, relay, RBF, mining) in `reports/static-address.md`.

**Cadence.** `1 CSV` stops the new pool output being spent in the block that creates it, so there is at most one
settlement per block.

## 10. Deposits

**Interactive deposit.** The depositor proves a deposit join-split, and its funding coins become settlement
inputs. Weakness: the depositor can double-spend a funding coin while the batch is being proven. The batcher
re-checks every funding coin with `gettxout` (mempool included) before proving and before every broadcast. On
a conflict it drops that entry and abandons the proof, which is rebuilt without it (§13).

**Non-interactive deposit addresses (escrows).** With no proof and no round trip, the SDK
(`Wallet::deposit_address`) chooses a note and derives:

```
D = sha256("GSR-rollup/escrow-v1" || rollup_id || authority || randomness || value || fee_sats || sha256(ciphertext))
address = P2TR(NUMS, { sweep (0xc2): 0x20 D OP_DROP || body,
                       refund (0xc0): <delay> OP_CSV OP_DROP <xonly> OP_CHECKSIG })
```

- **The sweep body** uses `OP_TX` to require three things: the escrow input's own annex is exactly the marker `0x50`
  (so a relayer cannot inflate its weight), input 0 of the sweeping transaction spends the pool's fixed address (`P2TR(NUMS, leaf)`, whose only
  spend path is the covenant), and the escrow input has sequence
  `2` (a BIP 68 lock: the escrow needs two confirmations).
- **The guest** receives the escrow opening privately. It checks `D`, the taproot tweak, the sequence and the
  exact amount `value + fee_sats`, then mints the note and counts `fee_sats` as fee.
- **Funding inputs** may not use the escrow sequence, so a funding input cannot satisfy the sweep leaf.
- **Copies:** lineage (§9) means only the genuine pool can satisfy "input 0 is the covenant", and `D` commits
  to `rollup_id`.
- **Refunds:** the depositor can refund after `delay`, which is at least `--min-refund-delay`
  (144 blocks by default).
- **Batcher sweep rule:** it sweeps only with enough confirmations and while `2 · confirmations ≤ delay`.

Remaining risk: a settlement proven near the refund height can lose to a refund. That costs the batcher a
re-prove, never the user's funds.

## 11. Batching, anchors, fees and races

### 11.1 Batch size

Selection is bounded by weight. `select()` fills
`MAX_SETTLEMENT_WEIGHT − EMPTY_SETTLEMENT_WEIGHT = 400,000 − 332,000` WU using per-entry upper bounds. The
proof is a constant size (55,667 words), so the content is what varies.

| content | measured cost |
|---|---:|
| empty settlement | 331,699 WU |
| per deposit (funding input + 370 B annex) | 538 WU (P3, 4 deposits); 581–595 WU (P5 runs of 4 and 3) |
| 2 transfers + one 4-output withdrawal | 4,025 WU |
| recipient ciphertext | 1,232 B (ML-KEM); self/change 120 B |

Sixteen transactions fit the 68,000 WU budget for deposits and for transfers (estimate, from the per-entry
costs above). The largest batch fully settled on chain had 4 deposits (334,022 WU).

### 11.2 Fees

Each join-split commits `fee_sats` in its proof, paid from shielded value (for a deposit, from the deposited
amount). The guest enforces only that `Σ fee_sats` is the miner fee (§7). How much each user pays is the batcher's policy
(`prover/batcher/src/fees.rs`), with `fee(w) = ceil(w · r / 4)`:
- **Quote (`GET /v1/fees`):** `ceil(fee(332,000) / T) + fee(typical weight of kind)` for target batch size
  `T`.
- **Admission:** a transaction is rejected unless it pays `fee(entry_weight)`.
- **Shortfall:** proving is refused (HTTP 409) if the pool's fees don't cover the whole settlement.
- **No reward, no CPFP:** every fee goes to the miner. A user bumps by proving the join-split again with a
  higher `fee_sats`; the next batch replaces the pending settlement under ordinary RBF. No Bitcoin coin of
  the user is spent, so bumping links no address.
- **No pinning handle:** withdrawal outputs carry `1 OP_CSV` in their leaf, the pool output carries `1 OP_CSV`, the root output is
  an unspendable `OP_RETURN`,
  and there are no change, reward or P2A outputs, so nothing in an unconfirmed settlement can be spent and
  it can have no descendants. Funding and escrow sequences are BIP 68 locks, so it has no unconfirmed
  parents either. Measured on a node patched with bitcoin/bitcoin#36466 (`reports/no-pin-handles.json`):
  every child of an unconfirmed settlement (either output, sequences 0, 1, `0xfffffffd`, `0xffffffff`) is
  rejected, a settlement on an unconfirmed funding coin is `non-BIP68-final`, a higher-fee settlement
  replaces it, and the withdrawal key spends one block after confirmation. The cost: a withdrawal cannot pay
  an arbitrary address directly; the recipient forwards it.

The verifier dominates, so fees per user fall with batch size. At 10 sat/vB, a 3-deposit batch costs about
280,000 sats each, and 16 transfers about 56,000 sats each (estimates from the quote formula).

### 11.3 Anchors

A join-split proves membership against an *anchor*: the commitment root after some earlier batch. Anchors
live in an append-only tree and never expire, so a user's proof stays valid however many batches pass. The
only expiry is the user's own `expiry_batch_number`. Filling blocks with empty settlements ("slot taking")
therefore only delays honest batches. It cannot force users to prove again, and each empty batch costs the
attacker a proof plus a miner payment, since empty batches carry no fees.

### 11.4 Relay and submission

The annex makes settlements nonstandard under the pinned node's policy. Batchers submit them directly to a
miner's node (`--submit-url`, `sendrawtransaction` / `submitpackage`). This also sidesteps classic mempool
pinning of the settlement itself.

### 11.5 Races

| race | outcome |
|---|---|
| two batchers settle the same tip | one wins (`1 CSV`, a single spendable output); the other sees the output spent, decodes the winner's annex, checks it against its replica (`Store::accept`) and adopts it; the loser's users re-batch with their old anchors |
| depositor double-spends a funding coin | the batcher drops the entry and abandons the proof; other users settle in the next proof |
| refund vs sweep | the batcher stops sweeping at half the delay; a late settlement can lose and must be re-proven |
| same note in two transactions | the batcher rejects the second spend of a nullifier; the guest rejects duplicates and tree members |
| replaying a mined settlement | its input is spent: rejected by node and replica |

## 12. Proving performance

CPU prover with the GSR optimization flags. All measured.

| step | P4 (before P5) | P5 (current) |
|---|---:|---:|
| user deposit proof | 305–351 s | 170–190 s |
| user join-split guest (fixture deposit) | — | 1,410,560 cycles, 2 segments, 167 s, 276,164 B |
| settlement, 4 deposits: segments | 18 | 5 |
| settlement, 4 deposits: segment proving + lift/join | 2,148 s | 508 s |
| settlement, 3 deposits: batch to confirmed | 2,101 s | 640 s |
| settlement, 16 transfers: segment proving + lift/join | — | 1,245 s (12 segments) |
| `resolve_zk` per user receipt | about 10 s | about 10 s |
| peak memory, one worker | — | 9.2 GiB |

What changed in P5:
- BigInt2-accelerated Poseidon2 in the guest (since replaced by SHA-256 note hashing);
- static zero hashes;
- the authenticated commitment frontier;
- batched nullifier insertion;
- cached tagged-hash midstates.

A second parallel worker saved only 4–9% and doubled memory, so the default is one worker. A full 16-transaction
settlement (with `resolve_zk` and the final wrap) has not been run.

**Browser.** The SDK compiles to WASI and runs in a browser worker. One segment of 2^16 rows took 407 s in
desktop Chrome, using 1.54 GB. A full receipt was not completed in a browser: about 20 h single-threaded is an
estimate. Segments of 2^20 rows or more exceed the 2 GiB that a single wasm32 allocation can hold.

## 13. Adversarial evaluation

Native tests (`cargo test --workspace`):
- `transition_rejects_every_settlement_tamper`: every input, output, sequence, locktime, amount, anchor,
  nullifier and frontier field tampered;
- `lineage_rejects_covenant_copies_and_forged_predecessors`;
- in `tests/tests/lineage.rs`: genesis needs no predecessor receipt, a genuine chain rebuilds every
  predecessor journal, a fabricated genesis state and a fabricated state with an attacker-made predecessor
  are rejected, and past genesis a predecessor settlement is required;
- `double_spend_is_rejected_by_mempool_and_transition`;
- `old_anchor_still_spends_after_many_batches`;
- the escrow, fee, dust, batch-cap and ciphertext cases;
- in `tests/tests/adversarial.rs`: competing settlements, replay, and malformed annexes (padded, truncated,
  foreign rollup, wrong root).

On the `gsr` node with a real receipt (`tools/p6_adversarial.py`, `reports/p6-adversarial.json`), a settlement
was proven (532.9 s, 332,411 WU) and broadcast, then the batcher was killed. Each tampered copy was offered in
a block:
- Rejected by the covenant Script (`OP_VERIFY` failure on input 0): rollup output value −1, last output −1,
  last output redirected, an extra output, annex byte flipped, annex padded by 100 kB, seal byte flipped, and
  the real witness on a covenant copy.
- Rejected earlier, on the value balance: the variant with the funding input dropped.

The restarted batcher resumed the in-flight settlement and recorded it once mined, and replay was rejected.
`tools/p4_e2e.py` covers the double-spend-during-proving, CPFP and adoption flow.

## 14. Security model

**Assumptions:**
- soundness of RISC Zero v3.0.6's RV32IM, recursion and padded-SHA-256 identity circuits (about 97 bits of
  conjectured FRI security, as in stock RISC Zero);
- correctness of `resolve_zk.zkr` and the ZK-mode verifier;
- the hash functions as random oracles for zero-knowledge, and collision resistance for binding;
- ML-KEM-768 and XChaCha20-Poly1305;
- `OP_TX` semantics at the pinned GSR commit.

**Invariants and where they are enforced:**

| invariant | enforced by |
|---|---|
| only valid join-splits change state | `env::verify` + `resolve_zk` |
| no double spend | nullifier tree |
| value conserved, no overflow | range checks + checked arithmetic |
| the transaction is the one proven | `OP_TX` digests in the journal |
| state continuity, verifier can't be replaced | output 0 = own address (fixed leaf, single leaf under NUMS); root in output 1, checked by the guest |
| only the genuine pool settles | recursive lineage (predecessor receipt) |
| data availability | annex bound by the journal |
| ≤ 1 settlement per block | `1 CSV` |

**Privacy, assuming the ZK mode is sound.** A settlement reveals each statement's nullifiers, commitments,
ciphertexts, anchor, expiry and fee, plus deposit coins and amounts and withdrawal scripts and amounts.
Matching deposit and withdrawal amounts can link users; fixed denominations would help but are not enforced.

**Trust in batchers.** Batchers are trusted for liveness only. A censored user can prove their own settlement.

## 15. Limitations and open problems

- **Privacy proof is a sketch:** zero-knowledge rests on an unreviewed argument for a patch that isn't
  upstream.
- **Relay:** settlements need an annex-aware relay policy, or miner submission.
- **Proving cost:** settlement proving costs minutes on a CPU and needs about 9 GiB; user proving costs
  minutes and is not yet practical in a browser.
- **Failure costs fall on the batcher:** a funding double-spend or a late escrow refund wastes one batcher
  proof.
- **One-machine numbers:** measurements are from one machine; nothing has run on signet or mainnet.
- **Regtest-only funding:** the interactive deposit flows use `P2WSH(OP_TRUE)` funding coins, which are only
  safe on regtest. Real deposits should use escrow addresses.
- **Open questions for review** (`review/README.md`): Lemma 2, admitting `resolve_zk.zkr` to the control root,
  lineage across reorgs, the escrow sweep check, and `OP_TX` edge cases.

## 16. Reproducing

See `privacy-rollup/README.md` (Reproduce) and `review/README.md` §4. In short:
- build the `gsr` node;
- apply the RISC Zero patches;
- run `cargo test --workspace`;
- run the end-to-end scripts `tools/batcher_e2e.py`, `tools/p4_e2e.py` and `tools/p6_adversarial.py`.

## References

- U. Haböck, A. Kindi, "A note on adding zero-knowledge to STARKs", ePrint 2024/1037.
- RISC Zero v3.0.6; Zirgen `df6fb9d`.
- GSR node: `jmoik/bitcoin`, branch `gsr`.
- Specs in this repository: `spec/protocol.md`, `spec/encoding.md`, `spec/bitcoin-binding.md`,
  `spec/joinsplit.md`, `spec/zero-knowledge.md`, `spec/security-model.md`.
