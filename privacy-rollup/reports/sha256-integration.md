# gsr-privacy-pool on SHA-256 notes

This branch puts the whole gsr-privacy-pool line (deposits, transfers, withdrawals, escrow deposits, the anchor tree,
fee-only settlement, recursive lineage, the fixed rollup address with an `OP_RETURN` state root) on top of
`sha256-notes` (zkpinbtc/gsr-stark-verifier#17). Every protocol hash — spend authority, nullifier key, note
commitment, nullifier, commitment-tree node and the frontier digest — is tagged SHA-256 reduced with
`Fe::from_digest`. No production crate (`crypto`, `protocol-types`, `commitment-tree`, `state-transition`,
`scanner`, `wallet-core`, the guests, `prover`, `sdk`, `batcher`) depends on a Poseidon2 protocol hash. The
remaining `poseidon2` mentions in `prover/src/settle.rs`, `prover/batcher/src/service.rs` and
`methods/guest/src/bin/apply_batch.rs` name RISC Zero's recursion hash suite (the unconditional succinct receipt
before the padded-SHA identity step), not a note hash.

## Image IDs

| guest | image ID |
|---|---|
| `joinsplit` | `[1299965498, 3906493562, 1416100988, 3930945087, 1860782183, 3167177730, 1581876363, 3757494401]` |
| `apply_batch` | `90330884fb690c24e7b21567eba8a372c3ca904e4a7ae4d151c91952ff9f8dc5` |

`fixtures/apply-batch/receipt-template.json` (claim digest `5a6e89cd…d419`) and `fixtures/joinsplit-receipt/` were
regenerated from these guests (`tools/retemplate.py`, `cargo run --release -p pr-sdk --example joinsplit_fixture`).

## Measured guest cycles (executor, not proving)

`cargo run --release --bin cycles` in `prover/`. Every guest journal equals the native `apply_batch` /
join-split journal; non-genesis batches get their predecessor claim as an assumption.

| statement | user cycles | segments |
|---|---:|---:|
| join-split, deposit | 67,963 | 1 |
| join-split, transfer | 136,375 | 1 |
| join-split, withdrawal | 136,316 | 1 |
| batch, empty | 213,702 | 1 |
| batch, 1 deposit | 1,110,293 | 2 |
| batch, 1 transfer | 857,778 | 1 |
| batch, 1 withdrawal | 4,485,648 | 5 |

Not profiled: the withdrawal batch is probably dominated by deriving the CSV-locked withdrawal's taproot output key
with `k256` in the guest (inference from the code, not measured).

A zero-knowledge join-split receipt for a deposit (one segment, lift, identity-zk) took 84.0 s end to end on this
host (`joinsplit_fixture`).

## Checks run on this branch

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
  in `privacy-rollup/`; `cargo clippy` and `cargo test --release --workspace` (27 tests) in `privacy-rollup/prover/`.
- `tools/binding_check.py` on the `gsr` regtest node: the fixed-address covenant accepts the valid spend and rejects
  every tampered one.
- `tools/deposit_escrow.py node-test`: 12/12 escrow sweep and refund cases behave as expected.

## Not done

- No settlement has been proven and mined with the `apply_batch` image above. The real-proof runs in
  `reports/static-address.md` and `reports/relay-pinning.md` used the earlier Poseidon2-note images.
- The two real-proof tests in `crates/provekit-adapter/tests/aggregation.rs` are ignored: the Noir circuit
  `circuits/joinsplit-2x2` still hashes with Poseidon2 and cannot prove a SHA-256 witness.
