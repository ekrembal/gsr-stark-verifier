# Join-split circuit (`circuits/joinsplit-2x2`)

Noir program proven with ProveKit (WHIR over BN254 R1CS, hash-only, no trusted setup). The proof is verified
natively by mempools and inside the RISC Zero guest; ProveKit's Groth16/gnark export is not used.

## Public inputs (15, in this order)

`rollup_id, protocol_version, anchor_root, anchor_commitment_count, anchor_batch_number, nullifier[0..2],
output_commitment[0..2], deposit_sats, withdrawal_sats, fee_sats, external_data_hi, external_data_lo,
expiry_batch_number` — `JoinSplitPublic::public_inputs()`; the guest and mempool compare the proof's public
inputs with this vector before verifying.

## Constraints

* `protocol_version == 1`, `anchor_batch_number ≤ expiry_batch_number`;
* every amount (`in`, `out`, deposit, withdrawal, fee) ≤ `MAX_MONEY`, so the balance equation
  `in0 + in1 + deposit == out0 + out1 + withdrawal + fee` cannot wrap in the field (both sides < 2^54);
* input `i`: `authority = H(OWNER, secret)`, `nk = H(NK, secret)`, commitment recomputed from the note; if
  `value ≠ 0` the commitment must be at `index < anchor_commitment_count` under `anchor_root`;
  `nullifier[i] = H(NULLIFIER, nk, cm, index) ≠ 0`; `nullifier[0] ≠ nullifier[1]`;
* outputs: commitments recomputed from `(value, authority, randomness)`, distinct;
* external-data halves are 128-bit typed and bound only as public inputs.

**Dummy inputs.** A zero-valued input skips membership but still yields a nonzero nullifier that is inserted
into the nullifier tree. It cannot move value (value 0) and cannot collide with a real nullifier without a
Poseidon2 preimage, so it only consumes one nullifier slot.

## Measured (ProveKit `circuit-stats`, `joinsplit-batch`)

| | |
|---|---:|
| R1CS constraints | 38,819 (2^15.24) |
| witnesses | 51,805 |
| Poseidon2 permutations | 142 |
| proof (`narg` + hints) | 32,656 + 602,912 B |
| native proving | 0.34 s |
| native verification + mempool admission | 46 ms |
| verification in the `apply_batch` guest | 1,215,383,914 cycles, 1,276 segments, 48 s to execute (one transaction) |

The verifier key SHA-256 pinned in the guest is in `fixtures/joinsplit/verifier-key.sha256`.
