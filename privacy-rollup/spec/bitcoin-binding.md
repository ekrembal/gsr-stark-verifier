# Bitcoin binding (`tools/rollup_covenant.py`, `pr-bitcoin-adapter`)

The rollup output is P2TR with the NUMS internal key and exactly one tapscript-v2 (`0xc2`) leaf, the same
for every state of one rollup, so the rollup lives at one fixed address:

```
leaf = 1 OP_CHECKSEQUENCEVERIFY OP_DROP || suffix
```

`suffix` embeds the rollup id, the `apply_batch` image id, the padded-SHA RISC Zero control root/ID and the
complete succinct-receipt verifier from `risc0-succinct`. The state root is not in the script. Every settlement
publishes it in non-witness data:

```
outputs = [ rollup (value = backing, scriptPubKey = the fixed address),
            OP_RETURN 0x20 <new_state_root> (value 0, 34-byte script),
            withdrawals.. ]
```

The txid commits to output 1, so the next settlement's lineage check (the guest rebuilds the predecessor from
its non-witness bytes) reads `old_state_root` from there. State never lives only in the annex: the txid does not
commit to the witness, so a successor could not prove which annex its predecessor carried.

## What the suffix checks (all with `OP_TX`, no signatures)

| check | `OP_TX` selector |
|---|---|
| it runs as input 0 | `00 00 01 00 00 00` (current input index) `== 0` |
| the coin is a single-leaf tree under NUMS | `00 00 68 00 00 00` (tapleaf hash, internal key, taptree root): root == leaf hash, key == NUMS |
| output 0 pays the rollup's own address | output 0's scriptPubKey (bytes 9..43 of the outputs preimage below) `==` `00 00 00 30 08 00` with index 0 (input 0's scriptPubKey) |
| journal input digest | `00 07 00 20 3f 00`: version, locktime, every input's prevout, amount, scriptPubKey, scriptSig, sequence |
| journal output digest | `00 01 00 02 00 03`: every output's amount and scriptPubKey (the BIP 341 `sha_outputs` preimage) |
| journal annex digest | `00 00 02 00 00 00`: input 0's annex |

It then assembles the 196-byte journal (`protocol_version ‖ rollup_id ‖ old_root ‖ new_root ‖ the three
digests`; both roots are 32-byte witness items), derives the RISC Zero `ReceiptClaim` for the fixed image with exit code `Halted(0)`,
empty input and no assumptions, and verifies the succinct receipt against it. There is no other leaf and the
key path is unspendable, so no other spending branch exists.

Everything the guest interprets — predecessor amount and sequence, funding inputs and their amounts and
scripts, version, locktime, every output — is read by the guest from the same bytes whose digests the
script recomputes from the real transaction, so the guest's view of the transaction *is* the transaction.
In particular the Script does not look at output 1: the guest requires it to be exactly
`OP_RETURN 0x20 <new_state_root>` with value 0 (`TransitionError::RootOutput`), and the output digest binds it.
The guest also rejects an `old_root` the predecessor did not publish in its own output 1 or, at batch 0, one
other than the genesis root (`TransitionError::Lineage`); a stale or invented witness `old_root` therefore has
no receipt.
`pr-bitcoin-adapter::SettlementTx::{inputs,outputs}_preimage` mirror the `OP_TX` layouts byte for byte; the
regtest demo checks that every real settlement verifies and that each altered field is rejected.

## Measured (empty batch, `tools/regtest_demo.py`)

See the README of this directory for the table. The receipt dominates: 222,668 seal bytes, 159,229 script
bytes, ~2.1B of the ~3.9B varops budget.

## Consensus versus policy

The spend is consensus-valid on the pinned GSR node with `script_restoration` active. The node's standard
policy rejects any input carrying an annex, so on an unpatched node settlements are not relayed; the demo
mines them with `generateblock` (consensus checks only) or submits them directly to a miner.

With the open annex-relay proposal bitcoin/bitcoin#36466 applied, settlements are standard if every
annex is unstructured (`0x50 0x00 ...`, or the one-byte marker `0x50`) and every non-P2A input carries
one. The input-0 annex therefore starts `50 00`, and escrow sweeps carry the marker `50`, which the
sweep leaf checks with `OP_TX` (`00 00 02 00 00 00`, the current input's annex) so no relayer can inflate
it. Funding inputs that are not taproot (P2WPKH, P2WSH) cannot carry an annex, so a settlement spending
one is nonstandard even under #36466. Measurements: `reports/relay-pinning.md`. Empty
batches also pay no miner fee (there are no user fees to pay it from), so they need a miner who includes
them for free or out-of-band payment.
