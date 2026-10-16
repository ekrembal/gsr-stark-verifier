# Privacy rollup on GSR

A two-input/two-output private join-split rollup whose state is a single Taproot UTXO. Each settlement
spends the current rollup UTXO and creates its successor; the only spending condition is a RISC Zero
succinct receipt of the `apply_batch` guest, verified in Script by the [`risc0-succinct`](../risc0-succinct/README.md)
verifier and bound to the spending transaction with `OP_TX`.

```
user: joinsplit guest (private witness) -> zero-knowledge receipt (`identity_zk`, ~276 KB)
  -> operator: ExecutorEnv::add_assumption; apply_batch guest calls env::verify per transaction,
     applies the batch, commits a 196-byte journal
  -> resolve_zk per transaction, then the succinct receipt re-proven under the padded SHA-256 suite
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
| Join-split statement | `crates/joinsplit` (`JoinSplitWitness::check`), proven by the `joinsplit` RISC Zero guest; the Noir/ProveKit circuit is kept for reference |
| Zero-knowledge user receipts | `identity_zk` seals from a ZK mode added to `risc0-zkp` ([argument](spec/zero-knowledge.md), proof sketch, not reviewed) |
| `apply_batch` guest | Implemented; `env::verify` per transaction; journal equals the native transition byte for byte |
| `resolve_zk.zkr` | Built with patched Zirgen and added to the allowed control root (`5edc9538…5b01`) |
| Batches containing join-splits | **Proven and settled on regtest** (image `00eb5e47…e50f`): a real deposit join-split, 15 segments, 24.8 min to the padded receipt; mined, altered spends rejected. See [reports/zk-joinsplit.md](reports/zk-joinsplit.md) |
| Empty batches | **Proven** and settled consecutively on activated regtest |
| Covenant (`OP_TX` binding, successor leaf, `1 CSV`) | Implemented, metered, mined on regtest; altered spends rejected |
| Relay | Consensus-valid; **nonstandard** under the pinned node's policy (annex) |

## Measurements

The [current draft-PR review](reports/aggregation-current-review.md) summarizes the latest
results and remaining proving obstacles. The table below records the original PR measurements. The aggregation optimization
measurements, phase profile, validation results and remaining limits are in
[reports/aggregation-optimizations.md](reports/aggregation-optimizations.md). The earlier
[lazy-covector experiment](reports/lazy-covector-optimization.md) follows
[fixed-key specialization](reports/fixed-config-optimization.md).
[Normal-size real segment proving](reports/normal-segment-proving.md) measures actual
CPU/memory cost; execution improvements do not establish full aggregation feasibility.

Current pipeline (zero-knowledge RISC Zero user receipts; details in [reports/zk-joinsplit.md](reports/zk-joinsplit.md)):

| Metric | Value |
|---|---:|
| User join-split guest | 2,877,102 cycles, 3 segments |
| User proving (succinct + `identity_zk`) | 332 s wall, ~9.7 GB peak RSS |
| User receipt | 276,262 B |
| Settlement guest, one join-split | 14,055,695 cycles, 15 segments |
| Settlement proving, one join-split | 1,487 s (incl. `resolve_zk` 9.6 s) |
| Settlement transaction, one deposit join-split | 392,001 WU, 2,095,600,656 varops (annex 2,743 B) |
| Settlement transaction, empty batch | 389,240 WU, 2,095,433,301 varops |

Earlier ProveKit pipeline (kept for reference):

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
| `crates/joinsplit` | join-split witness and constraint check, shared by the wallet and the guest |
| `crates/provekit-adapter` | ProveKit proving/verification (reference path); `joinsplit-batch`, `provekit-export` |
| `crates/wallet-core`, `crates/scanner`, `crates/mempool`, `operator` | wallet, replay/rollback, admission, `pr-operator` CLI |
| `circuits/joinsplit-2x2` | Noir circuit |
| `methods/guest`, `prover` | `joinsplit` and `apply_batch` guests; `joinsplit prove|verify|id` and `settle prove|exec <witness> <dir> <receipts…>` hosts |
| `tools/rollup_covenant.py`, `tools/regtest_demo.py`, `tools/operator_joinsplit.py` | covenant generator, regtest demo, real-proof operator check |
| `tests` | scenario and differential tests |
| `spec/` | [protocol](spec/protocol.md), [encoding](spec/encoding.md), [join-split](spec/joinsplit.md), [Bitcoin binding](spec/bitcoin-binding.md), [security model](spec/security-model.md), [zero knowledge](spec/zero-knowledge.md) |
| `patches/`, `vendor/` | RISC Zero ZK mode and Zirgen `resolve_zk` patches; ProveKit patch (zkVM build, transpose-free verifier row); spongefish/ark-ff copies with target-independent hashing and the BN254 accelerator |

## Reproduce

Dependencies are path dependencies on two sibling checkouts of the repository directory (`../risc0`,
`../provekit` relative to this repository's root):

* RISC Zero v3.0.6 (`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`) with [`../risc0-succinct/risc0-v3.0.6.patch`](../risc0-succinct/risc0-v3.0.6.patch);
* ProveKit `4ee40639fb8849aeeba37761fdda07f28367e81d` with [`patches/provekit-4ee40639.patch`](patches/provekit-4ee40639.patch),
  then [`patches/provekit-aggregation.patch`](patches/provekit-aggregation.patch),
  then the cumulative [`patches/provekit-structured.patch`](patches/provekit-structured.patch)
  with `git apply --unidiff-zero`. The last patch includes the hash-bound compiled
  configuration and exact matrix specialization; it is required by the current guest.
* Optional host-prover speedups (no circuit, verifier or covenant change): after the RISC Zero patch apply
  `patches/risc0-cpu-profile.patch`, `risc0-cpu-batch.patch`, `risc0-cpu-periodic.patch`,
  `risc0-cpu-poly-batch.patch`, then [`patches/risc0-cpu-avx512.patch`](patches/risc0-cpu-avx512.patch)
  (16-lane AVX-512 evaluation, packed recursion circuit, exact NTT/`zk_shift`); ProveKit additionally takes
  [`patches/provekit-dot4.patch`](patches/provekit-dot4.patch) and
  [`patches/provekit-final-claim.patch`](patches/provekit-final-claim.patch). See
  [reports/prover-speedups.md](reports/prover-speedups.md).
* Zero-knowledge receipts (required by the current guests): after the CPU patches apply
  [`patches/risc0-zk.patch`](patches/risc0-zk.patch). Its `recursion_zkr.zip` is RISC Zero's upstream
  archive plus `resolve_zk.zkr`, built from Zirgen `df6fb9d` with
  [`patches/zirgen-zk.patch`](patches/zirgen-zk.patch)
  (`bazel build -c opt //zirgen/circuit/predicates:resolve_zk.zkr`) and combined with
  `tools/assemble_zk_recursion_zip.py <upstream zip> <resolve_zk.zkr> <out zip>`.
* WHIR remains version 0.2.0; the vendored published source has the local
  [`patches/whir-blinding.patch`](patches/whir-blinding.patch) algorithmic optimization. Its original
  archive checksum and necessary same-version lockfile source deviation are documented in the review report.
* Guest SHA-2 remains 0.10.9, with the official RISC Zero accelerator source pinned to
  `8631fabdea7bdffa97b11868e04e73491d8e5bcf`; the native/client workspace retains its
  registry source. See [the SHA experiment](reports/sha256-accelerator-experiment.md).

Build the pinned node and meter first (`bash recursive-stwo/tools/build.sh` from the repository root).

```sh
cd privacy-rollup
cargo test --workspace                                   # protocol, trees, transition, wallet, scanner, mempool, scenarios
cargo build --release -p pr-operator -p pr-provekit-adapter
(cd prover && cargo build --release && cargo test)      # builds the guests; checks methods/guest/src/joinsplit_id.rs
../../provekit/target/release/provekit-cli prepare circuits/joinsplit-2x2 -p js.pkp -v js.pkv   # fixtures pin the exported verifier-key bytes
python3 tools/operator_joinsplit.py                      # real ZK user receipt through the operator and add_assumption (copy in reports/operator-joinsplit.json)
python3 tools/regtest_demo.py --batches 2                # proven deposit join-split + empty batch settled on regtest -> build/privacy-rollup-regtest.json (copy in reports/regtest.json)
```
