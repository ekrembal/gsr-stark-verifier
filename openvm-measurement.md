# OpenVM v2.0.2 measured against GSR

[`next-verifiers.md`](next-verifiers.md) put one experiment ahead of any implementation work: produce a real multi-segment OpenVM proof with more than one aggregation level, count the Poseidon2 permutations its verifier performs and its raw canonical proof bytes, and compare both against a standard GSR spend. This note records that measurement. The harness and the raw runs are in [`research/openvm/`](research/openvm/README.md).

## What was measured

OpenVM `v2.0.2`, CPU backend, stock parameters (`app_params_with_100_bits_security`, `leaf_params_with_100_bits_security`, `internal_params_with_100_bits_security`), proving the SDK's prebuilt `fibonacci` ELF and verifying the resulting `VmStarkProof` with `Sdk::verify_proof`, which is the same code path as `verify_vm_stark_proof`.

Proof bytes are the canonical `Encode` output — the encoding the host verifier decodes — not the zstd artifact that `verify_vm_stark_proof` accepts, since GSR has no decompressor. Poseidon2 permutations are counted by a global counter in `Poseidon2::permute_mut`, read as a delta around the verification call, so proving is excluded and both the sponge and the two-to-one compressor are captured.

| | single segment | 35 segments |
|---|---:|---:|
| Fibonacci iterations | 100 | 2,000,000 |
| App segments proved | 1 | 35 |
| Aggregation above leaf | internal-for-leaf, then internal-recursive | internal-for-leaf, then internal-recursive |
| Raw canonical proof bytes | 267,271 | 315,319 |
| zstd-compressed bytes | 232,534 | 280,419 |
| AIRs in the final proof | 42 | 42 |
| Poseidon2 permutations, total | 13,643 | 14,737 |
| — in the STARK verifier | 13,604 | 14,698 |
| — in public-value and memory Merkle checks | 39 | 39 |
| Host verification time | 15.2 ms | 16.1 ms |

Both proofs go through two aggregation levels above the leaf layer, so the recursive pipeline is genuinely exercised; the 35-segment run reaches internal node index 4 rather than 2. Aggregation does its job: 35 segments cost 18% more proof bytes and 8% more permutations than one, not 35x. The measurement is therefore about a fixed shape, not about program size.

## What that costs under GSR

A standard spend is 400,000 WU and its varops budget is 10,000 per weight unit, so 4.0 billion varops. [`research/gsr-primitive-costs.txt`](research/gsr-primitive-costs.txt) prices one Poseidon2 permutation over a 31-bit field at width 16 at 10,769,698 varops, and that row is a lower bound: it counts the S-boxes and the linear layers and ignores operand retrieval, canonical range checks and invocation overhead, which the shipped verifier's calibration puts at a further 4.05x.

| | 13,643 permutations | 14,737 permutations |
|---|---:|---:|
| Varops, primitive lower bound | 146.9 billion | 158.7 billion |
| Multiple of a maximal standard spend | 36.7x | 39.7x |
| Same, after the 4.05x real-verifier factor | 148.8x | 160.7x |

Even the lower bound needs 15.9 million WU of transaction weight to fund its hashing alone, against a 400,000 WU standard limit and a 4,000,000 WU block. This is not a tuning problem. Cutting the query count in half, or halving the proof, moves a 40x-to-160x overrun by a factor of two.

Nothing else in the verifier was measured, so these figures remain lower bounds in a second sense: FRI or SWIRL folding, the constraint evaluation over the degree-four BabyBear extension, and witness parsing all cost varops that are not counted above. They do not change the conclusion, because the hashing alone already fails.

**A direct port of the stock OpenVM verifier to GSR is not feasible.** The SHA-256-terminated outer layer that [`next-verifiers.md`](next-verifiers.md) ranked first is a hard dependency for OpenVM, not a nice-to-have.

## What the outer layer has to achieve

Keeping the shape of the measured proof and only substituting the hash is enough on the execution side. At 5,892 varops per padded SHA-256 two-to-one parent, 14,737 parents cost 86.8 million varops, 2.2% of the budget, or 8.8% after the 4.05x factor. Hashing stops being the constraint entirely.

Bytes then become the constraint, and the measured proof is too big for them. At 1 WU per witness byte, the 35-segment proof's 315,319 bytes consume 79% of a 400,000 WU spend on their own, leaving 84,681 WU for the verifier script, the hints, the control block and the transaction overhead. The shipped Recursive Stwo verifier's script alone is 144,905 bytes. So a wrapper that merely re-commits the same proof shape with SHA-256 would fail on weight even though it passes on varops.

That gives the outer layer a concrete, falsifiable target rather than a vague one:

- Its own commitments and Fiat-Shamir transcript use the padded SHA-256 that `OP_SHA256` computes, not `p3-sha256`'s padding-free compression.
- Its raw canonical proof is at most about 200 KB, and preferably 150 KB, so that a 100-150 KB verifier script fits in the same spend with headroom.
- It verifies the measured `VmStarkProof` in-circuit, including the public-value Merkle proof, the executable commitment, the exit code and the aggregation verifying-key commitments that `verify_vm_stark_proof_pvs` checks — the 39 permutations in the bottom row of the table above are that entire binding, and they are cheap.
- Its security level is stated, not inherited by assumption. OpenVM's documented profile here is about 100 bits.

Until such a layer exists and is measured, OpenVM's position in the ranking is unchanged but blocked, and the next piece of work is item 1 of [`next-verifiers.md`](next-verifiers.md) rather than an OpenVM verifier.

## Caveats

The permutation count is specific to these parameter sets; a different app log-stacked-height or a different query count moves it, though not by the two orders of magnitude that would be needed. The 4.05x factor is calibrated from one verifier, the shipped Recursive Stwo one, and is a projection rather than a measurement of an OpenVM verifier that does not exist yet. Proving ran on CPU only; that affects timings, not proof contents.
