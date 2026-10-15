# Bitcoin binding (`tools/rollup_covenant.py`, `pr-bitcoin-adapter`)

The rollup output is P2TR with the NUMS internal key and exactly one tapscript-v2 (`0xc2`) leaf:

```
leaf(root) = PUSH32 <state_root> 1 OP_CHECKSEQUENCEVERIFY OP_DROP || suffix
```

`suffix` is identical for every state of one rollup: it embeds the rollup id, the `apply_batch` image id,
the padded-SHA RISC Zero control root/ID and the complete succinct-receipt verifier from `risc0-succinct`.

## What the suffix checks (all with `OP_TX`, no signatures)

| check | `OP_TX` selector |
|---|---|
| it runs as input 0 | `00 00 01 00 00 00` (current input index) `== 0` |
| the coin is a single-leaf tree under NUMS | `00 00 68 00 00 00` (tapleaf hash, internal key, taptree root): root == leaf hash, key == NUMS |
| output 0 is the successor: `P2TR(TWEAKADD(NUMS, TapTweak(NUMS ‖ TapLeaf(0xc2 ‖ leaf(new_root)))))` | `00 01 04 00 00 00` (own tapscript, root bytes replaced by the witness `new_root`) and the outputs below |
| journal input digest | `00 07 00 20 3f 00`: version, locktime, every input's prevout, amount, scriptPubKey, scriptSig, sequence |
| journal output digest | `00 01 00 02 00 03`: every output's amount and scriptPubKey (the BIP 341 `sha_outputs` preimage) |
| journal annex digest | `00 00 02 00 00 00`: input 0's annex |

It then assembles the 196-byte journal (`protocol_version ‖ rollup_id ‖ old_root (its own prefix) ‖ new_root
‖ the three digests`), derives the RISC Zero `ReceiptClaim` for the fixed image with exit code `Halted(0)`,
empty input and no assumptions, and verifies the succinct receipt against it. There is no other leaf and the
key path is unspendable, so no other spending branch exists.

Everything the guest interprets — predecessor amount and sequence, funding inputs and their amounts and
scripts, version, locktime, every output — is read by the guest from the same bytes whose digests the
script recomputes from the real transaction, so the guest's view of the transaction *is* the transaction.
`pr-bitcoin-adapter::SettlementTx::{inputs,outputs}_preimage` mirror the `OP_TX` layouts byte for byte; the
regtest demo checks that every real settlement verifies and that each altered field is rejected.

## Measured (empty batch, `tools/regtest_demo.py`)

See the README of this directory for the table. The receipt dominates: 222,668 seal bytes, 159,229 script
bytes, ~2.1B of the ~3.9B varops budget.

## Consensus versus policy

The spend is consensus-valid on the pinned GSR node with `script_restoration` active. The node's standard
policy rejects any input carrying an annex, so settlements are not relayed by default nodes; the demo
mines them with `generateblock` (consensus checks only) and records the `testmempoolaccept` verdict.
Deploying this design needs either an annex-aware relay policy or direct submission to miners. Empty
batches also pay no miner fee (there are no user fees to pay it from), so they need a miner who includes
them for free or out-of-band payment.
