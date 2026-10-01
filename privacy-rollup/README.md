# Privacy rollup on GSR

A two-input/two-output private join-split rollup whose state is a single Taproot UTXO. Each settlement
spends the current rollup UTXO and creates its successor; the only spending condition is a RISC Zero
succinct receipt of the `apply_batch` guest, verified in Script by the [`risc0-succinct`](../risc0-succinct/README.md)
verifier and bound to the spending transaction with `OP_TX`.

```
ProveKit join-split proofs (Noir, WHIR over BN254, hash-only)
  -> apply_batch guest: verifies every proof, applies the batch, commits a 196-byte journal
  -> succinct receipt re-proven under the padded SHA-256 suite
  -> rollup leaf: PUSH32 <state_root> 1 CSV DROP || fixed verifier suffix
  -> settlement transaction: input 0 = rollup UTXO (+ deposit funding), output 0 = successor, annex = batch data
```

> Research code, not audited. See [spec/security-model.md](spec/security-model.md) for assumptions and
> what is not established.

## Status

| | Status |
|---|---|
| Protocol, encodings, trees, accounting, annex, native transition | Implemented, tested (`cargo test --workspace`) |
| Wallet (keys, ML-KEM-768 + XChaCha20-Poly1305 notes, join-split witnesses), scanner, mempool, operator CLI | Implemented, tested |
| ProveKit join-split circuit | Implemented; proofs generated and verified natively and inside the guest |
| `apply_batch` guest | Implemented; journal equals the native transition byte for byte |
| Empty / anchor-only batches | **Proven** (succinct receipt) and settled consecutively on activated regtest |
| Batches containing join-splits | **Executed, not proven**: 1.22B cycles per transaction, ~100 h estimated on the 8-core CPU used |
| Covenant (`OP_TX` binding, successor leaf, `1 CSV`) | Implemented, metered, mined on regtest; altered spends rejected |
| Relay | Consensus-valid; **nonstandard** under the pinned node's policy (annex) |

## Measurements

| Metric | Value |
|---|---:|
| Join-split R1CS constraints / witnesses | 38,819 / 51,805 (142 Poseidon2 permutations) |
| ProveKit proof (`narg` + hints) | 32,656 + 600,480 B |
| ProveKit native proving / verification + admission | ~3 s / ~0.19 s (operator `submit`, incl. process start) |
| Guest, one join-split batch (executed) | 1,215,383,914 cycles, 1,276 segments, 48 s to execute |
| Guest, empty batch (proven) | 262,144 cycles, 1 segment, 82–110 s to a padded-SHA succinct receipt |
| Settlement transaction (empty batch) | 389,240 WU (limit 400,000) |
| Settlement varops | ~2.0955B of 3,892,400,000 (53.8%) |
| Verifier suffix + prefix (tapscript) | 159,229 bytes |
| Seal | 222,668 bytes |

Settlement weight does not depend on batch contents beyond the annex (one nullifier is 32 bytes, one output
32 bytes plus a 1,232-byte ciphertext), because the receipt is constant-size.

## Layout

| Path | |
|---|---|
| `crates/protocol-types` | constants, fixed-width types, strict codec (minimal CompactSize, no trailing bytes), journal and annex |
| `crates/crypto` | Poseidon2 (BN254) commitments, nullifiers, key derivation |
| `crates/commitment-tree`, `crates/indexed-nullifier-tree` | depth-32 incremental and indexed trees with insertion/absence witnesses |
| `crates/state-transition` | `apply_batch`: shared by the native node, the operator and the guest |
| `crates/bitcoin-adapter` | settlement transaction, `OP_TX` preimages, successor leaf |
| `crates/provekit-adapter` | proving/verification; `joinsplit-batch`, `provekit-export` |
| `crates/wallet-core`, `crates/scanner`, `crates/mempool`, `operator` | wallet, replay/rollback, admission, `pr-operator` CLI |
| `circuits/joinsplit-2x2` | Noir circuit |
| `methods/guest`, `prover` | `apply_batch` guest; `settle prove|exec` host |
| `tools/rollup_covenant.py`, `tools/regtest_demo.py`, `tools/operator_joinsplit.py` | covenant generator, regtest demo, real-proof operator check |
| `tests` | scenario and differential tests |
| `spec/` | [protocol](spec/protocol.md), [encoding](spec/encoding.md), [join-split](spec/joinsplit.md), [Bitcoin binding](spec/bitcoin-binding.md), [security model](spec/security-model.md) |
| `patches/`, `vendor/` | ProveKit patch (zkVM build, transpose-free verifier row); spongefish/ark-ff copies with target-independent hashing and the BN254 accelerator |

## Reproduce

Dependencies are path dependencies on two sibling checkouts of the repository directory (`../../risc0`,
`../../provekit` relative to this repository's root):

* RISC Zero v3.0.6 (`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`) with [`../risc0-succinct/risc0-v3.0.6.patch`](../risc0-succinct/risc0-v3.0.6.patch);
* ProveKit `4ee40639fb8849aeeba37761fdda07f28367e81d` with [`patches/provekit-4ee40639.patch`](patches/provekit-4ee40639.patch).

Build the pinned node and meter first (`bash recursive-stwo/tools/build.sh` from the repository root).

```sh
cd privacy-rollup
cargo test --workspace                                   # protocol, trees, transition, wallet, scanner, mempool, scenarios
cargo build --release -p pr-operator -p pr-provekit-adapter
(cd prover && cargo build --release)                     # builds the guest; prints its image id
../../provekit/target/release/provekit-cli prepare circuits/joinsplit-2x2 -p js.pkp -v js.pkv   # byte-identical to fixtures/joinsplit
python3 tools/operator_joinsplit.py                      # real ProveKit proof through the operator and the guest (executed) (copy in reports/operator-joinsplit.json)
python3 tools/regtest_demo.py --batches 10               # proven empty batches settled on regtest -> build/privacy-rollup-regtest.json (copy in reports/regtest.json)
```
