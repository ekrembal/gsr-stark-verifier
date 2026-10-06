# Canonical encoding

All protocol objects implement `Canonical` (`pr-protocol-types::codec`). Decoding is strict: `decode` fails on
trailing bytes, so every value has exactly one encoding.

* integers: fixed-width little endian (`u8`, `u32`, `u64`); `bool` is one byte, 0 or 1 only;
* amounts: `u64` rejected above `MAX_MONEY = 2.1e15`;
* field elements (`Fe`): 32 bytes big endian, rejected unless `< p` (BN254 Fr);
* variable bytes: Bitcoin CompactSize length, minimal form only (non-minimal prefixes are rejected), with a
  per-field maximum length;
* `Option<T>`: one byte 0/1, then `T`;
* fixed arrays and sorted sequences: no length prefix where the count is implied by the layout, sorted strictly
  ascending where the protocol says so (`BatchBody` nullifiers and output commitments).

Hashes outside the circuit are BIP-340-style tagged SHA-256, tags `gsr-privacy-rollup/{state, anchors,
batch-body, data-history, external-data, nullifier-leaf, nullifier-node, rollup-id, note-key}`.

## Annex (input 0)

```
0x50 || "GSRP" || 0x01 || old_state_root[32] || new_state_root[32] || BatchBody
BatchBody = rollup_id[32] || batch_number u64 || predecessor (txid[32] || vout u32)
         || transactions u8 || funding_inputs u8 || withdrawals u8 || changes u8 || reward u8
         || nullifiers[2·transactions][32]          (strictly ascending, nonzero)
         || (commitment[32] || ciphertext[1232])[2·transactions]   (strictly ascending commitments)
```

The counts bound every section, so the annex has no length prefixes. An empty-batch annex is 151 bytes; each transaction adds 2·32 + 2·(32 + 1,232) = 2,592 bytes.
Scanners decode the annex with the same strict decoder and replay it against their own trees.

## Journal (196 bytes)

```
protocol_version u32 || rollup_id[32] || old_state_root[32] || new_state_root[32]
|| SHA256(inputs preimage) || SHA256(outputs preimage) || SHA256(annex)
```

## Guest input

RISC Zero frame: postcard `BatchWitness`. The guest reads no proofs. For each transaction the host adds the
claim of the user's zero-knowledge receipt with `ExecutorEnv::add_assumption`, and the guest calls
`env::verify(JOINSPLIT_ID, statement)` with the transaction's canonical `JoinSplitPublic` encoding.
`resolve_zk` discharges each assumption when the receipt is proven.

A `RollupTransaction` carries `public`, `external`, and `receipt`: a postcard
`SuccinctReceipt<ReceiptClaim>` produced by `identity_zk`, at most `MAX_RECEIPT_BYTES = 2^20` bytes.
