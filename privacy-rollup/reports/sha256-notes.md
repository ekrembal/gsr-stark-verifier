# SHA-256 note hashing

Notes, nullifiers, spend keys and commitment-tree nodes switch from BN254 Poseidon2 to tagged SHA-256
(`crates/crypto`, [protocol](../spec/protocol.md#notes-and-keys)). The nullifier tree and every other
protocol hash already used SHA-256, so the rollup now has a single hash. Digests have their top three bits
cleared (`Fe::from_digest`), so every value stays a canonical BN254 element and no type or encoding changes.

Two reasons: the RISC Zero guests hash with the SHA-256 accelerator instead of BN254 big-number
arithmetic, and a Tapleaf 0xC2 Script can recompute a note's membership with `OP_SHA256`, which a Script
exit (forced withdrawal without the operator) needs.

## Guest cycles

Same scenario for both (`prover/target/release/cycles`: deposit, transfer, empty batch, withdraw; journals
checked against the native transition), both built with `GSR_FUSED_BN254=1`, the faster Poseidon2 build.

| Run | Poseidon2 | SHA-256 | |
|---|---:|---:|---:|
| Join-split, deposit | 2,875,937 (3 segments) | 68,119 (1) | 42× |
| Join-split, transfer | 6,905,435 (7) | 148,005 (1) | 47× |
| Join-split, withdraw | 6,906,338 (7) | 147,947 (1) | 47× |
| Settlement, 1 deposit | 14,057,211 (15) | 1,130,941 (2) | 12× |
| Settlement, 1 transfer | 14,176,945 (15) | 1,131,300 (2) | 13× |
| Settlement, 1 withdrawal | 14,059,078 (15) | 1,133,742 (2) | 12× |
| Settlement, empty | 41,695 (1) | 41,695 (1) | 1× |

User cycles; segments are po2 20.

## Proving time

`cycles --prove` on an Apple M4 Pro (14 cores, CPU only, no Metal), succinct receipts. The settlement
resolves the plain succinct join-split receipt with `resolve`, where the operator resolves the
`identity_zk` receipt with `resolve_zk`; both are one recursion step (9.6 s in
[zk-joinsplit.md](zk-joinsplit.md)). `identity_zk` and the padded wrap are not included. The Poseidon2 run is the `gsr-port` branch with the
same tool.

| Proof | Poseidon2 | SHA-256 | |
|---|---:|---:|---:|
| Join-split, transfer | 636 s (7 segments) | 26 s (1) | 24× |
| Settlement, 1 transfer | 1,342 s (15) | 127 s (2) | 11× |
| Settlement, empty | 17 s (1) | 17 s (1) | 1× |

## Script exit

`tools/exit_hash_cost.py` checks a note's membership in the depth-32 commitment tree in Script
(`bitcoin-util evalscript`, `tapleaf_0xc2`): the leaf, 32 siblings and direction bits as witness, one level
macro called 32 times, `<root> EQUAL`. Both accept a valid path and reject a flipped sibling.

| | Poseidon2 | SHA-256 |
|---|---:|---:|
| Script bytes | 34,464 (permutation macro 34,352) | 191 (level macro 91) |
| Witness bytes | 1,072 | 1,072 |
| Varops | 401,082,372 | 1,288,468 |
| Weight the varops budget requires (`10,000 × WU − 500,000`) | 40,159 WU | 179 WU |
| Weight of the check | ~40,200 WU (needs ~4,600 WU of padding) | ~1,300 WU |

A Poseidon2 Script exit is possible but about 30× heavier per membership proof, and opening the note
(its commitment from value, authority and randomness) adds two more permutations, ~12.5M varops each. With
SHA-256 the opening is one more `OP_SHA256`.

## Costs

* **The ProveKit/Noir reference path is stale.** `circuits/joinsplit-2x2` still hashes with Poseidon2, so
  its commitments no longer match `pr-crypto`. SHA-256 in R1CS costs ~30,000 constraints per compression,
  so that path would not come back with SHA-256; RISC Zero is the live path.
* **Security level.** Truncating to 253 bits leaves ~126-bit collision resistance, the same order as
  BN254 Poseidon2.
* **New image IDs.** Both guests changed. `methods/guest/src/joinsplit_id.rs` holds the join-split image
  of this toolchain (rzup Rust 1.97.0); a reproducible build has to regenerate it. A regtest settlement
  with the new `apply_batch` image needs `resolve_zk`, whose recursion program is not in this checkout,
  so it was not rerun. Settlement weight does not change: the receipt and the verifier are the same.

An alternative is to drop the BN254 bound and use full 32-byte digests: the Script level would lose its
masking (91 → ~60 bytes), but `Fe` is canonical-BN254 throughout the codec and `JoinSplitPublic`, so that is
a protocol-wide type change for a few bytes per exit.
