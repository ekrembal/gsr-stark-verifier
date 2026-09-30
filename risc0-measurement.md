# RISC Zero v3.0.6 measured against GSR

This measures a real RISC Zero succinct receipt, in both its stock Poseidon2 configuration and
its SHA-256 configuration, and prices its verifier against the GSR limits that
[`next-verifiers.md`](next-verifiers.md) pins. Reproduction: [`research/risc0/README.md`](research/risc0/README.md).

> Follow-up: [`risc0-verifier-sizing.md`](risc0-verifier-sizing.md) validates the padded SHA-256
> suite this note calls for, and measures the verifier's BabyBear arithmetic as well as its hashing.
> That measurement reverses the conclusion below: hashing and proof size fit comfortably, but the
> arithmetic costs 8.4 billion varops, over twice a maximal standard spend.

The short version: on the two axes measured here, proof size and hashing, RISC Zero is the first
candidate that fits. Its succinct receipt is 222,668 bytes regardless of program length, and its final proof layer can be produced with a
stock SHA-256 hash suite, which costs 30,451,946 varops of hashing to verify — 0.76% of a maximal
standard spend on the primitive lower bound, 3.08% after the calibrated overhead factor. The same
receipt in the stock Poseidon2 configuration costs 2,013x more and is 15x over the whole budget.

## What was measured

A three-segment and an eighteen-segment `BusyLoop` execution of the `multi_test` guest, each proven
segment by segment and then aggregated with the stock `lift`/`join` recursion pipeline into one
succinct receipt. The final receipt was then re-proven through `Prover::new_identity` with
`ProverOpts::succinct().with_hashfn("sha-256")`, the supported analogue of the `identity_p254`
wrapper that RISC Zero uses to hand off to Groth16. Both receipts were verified with counters around
`verify_integrity_with_context`, so the numbers are verification work only and exclude proving.

| | 3 segments | 18 segments |
| --- | --- | --- |
| Segment seals in | 662,712 B | 3,964,624 B |
| Succinct seal out | 222,668 B | 222,668 B |
| Serialized `Receipt` | 223,226 B | 223,226 B |
| Poseidon2 permutations to verify | 5,693 | 5,693 |
| SHA-256 digest-pair hashes to verify | 4,363 | 4,363 |
| SHA-256 slice hashes to verify | 355, over 86,028 B | 355, over 86,028 B |

Both columns are identical because the succinct receipt is a proof of a fixed-size recursion
circuit: the aggregation tree grows with the program, the receipt does not. This is the property
OpenVM lacks — [`openvm-measurement.md`](openvm-measurement.md) measured 315,319 bytes for a
35-segment proof, and that figure grows with the segment count.

## Pricing

From [`research/risc0/gsr-risc0-costs.txt`](research/risc0/gsr-risc0-costs.txt), against the
4,000,000,000 varops a 400,000 WU standard spend funds:

| Verifier hashing | Varops | Of budget |
| --- | --- | --- |
| SHA-256 digest pairs | 25,706,796 | 0.64% |
| SHA-256 leaf slices | 4,745,150 | 0.12% |
| SHA-256 total, primitive lower bound | 30,451,946 | 0.76% |
| SHA-256 total, x4.05 calibrated projection | 123,330,381 | 3.08% |
| Poseidon2 total, primitive lower bound | 61,311,890,714 | 1,532.80% |
| Poseidon2 total, x4.05 calibrated projection | 248,313,157,391 | 6,207.83% |

Charging the 222,668-byte seal as witness leaves 177,332 WU for the script and the rest of the
transaction, and the calibrated hashing projection is then 6.95% of what those bytes fund. For
scale, the shipped Recursive Stwo verifier's script is 144,905 bytes against a 224,896-byte witness
payload — a very similar shape, landing at 370,387 WU in total. A RISC Zero verifier of comparable
script size would land in the same place.

As in [`research/gsr-primitive-costs.cpp`](research/gsr-primitive-costs.cpp), these rows are hashing
only. FRI folding, constraint evaluation over BabyBear and its degree-four extension, witness
parsing and stack plumbing are not counted; the 4.05x row is the calibration that projects a
comparable full verifier. Counting the arithmetic, in
[`risc0-verifier-sizing.md`](risc0-verifier-sizing.md), adds 8.36 billion varops: per-operation
BabyBear arithmetic is cheap, but this verifier does 687,360 multiplications, and that dominates
the table above by two orders of magnitude.

## What the SHA-256 path actually is, and what it is not

RISC Zero exposes `"sha-256"` from `hash_suite_from_name`, ships `SHA256_CONTROL_IDS` for the
recursion programs, and selects them in `zkr::get_zkr`. The measured SHA-256 receipt above uses only
stock API.

Two limits are load-bearing, and neither is a blocker for GSR:

1. **The aggregation pipeline stays Poseidon2.** `lift`, `join` and `resolve` all assert
   `receipt.hashfn == "poseidon2"` on their inputs. SHA-256 applies to the final layer only,
   produced by an identity recursion over the Poseidon2 aggregate. That is exactly the shape GSR
   wants: the Poseidon2 hashing of the inner layers is verified inside the identity circuit, not in
   Script, and the script only ever sees the SHA-256 outer proof. The counters confirm this — the
   SHA-256 verification performs zero Poseidon2 permutations.

2. **RISC Zero's "SHA-256" is the raw compression function, not FIPS SHA-256.** `hash_pair` is
   `compress(SHA256_INIT, a, b)` and `hash_raw_data_slice` is an unpadded Merkle–Damgård walk; both
   are documented in-tree as not standards compliant. GSR's `OP_SHA256` always appends the FIPS
   padding, so a Script verifier cannot reproduce these digests directly. The fix is a padded
   SHA-256 hash suite, and reading the source suggests it is contained: the outer layer's own
   commitment hash is verified by the external verifier, not inside the recursion circuit, so a new
   `HashSuite` plus regenerated control IDs should suffice with no circuit change. That inference
   has since been validated by implementing the suite and proving a receipt under it; see
   [`risc0-verifier-sizing.md`](risc0-verifier-sizing.md). The cost is already
   accounted for above: the padded variant costs one extra compression per pair, and the GSR rows
   price a padded `OP_SHA256` over 64 bytes to begin with.

## Security posture

RISC Zero pins `QUERIES = 50` and documents it as "our security target of 97 bits (conjectured
security)". That is the same band as OpenVM's roughly 100 bits, and it is not 128. It is a hash-only
system in this configuration — no elliptic-curve assumption enters unless the Groth16 wrapper is
used, which GSR would not use. As elsewhere in this repository: a post-quantum proof system does not
make the Taproot key-path envelope post-quantum, and SHA-256's generic quantum collision complexity
is about 2^(256/3), not 2^128.

## Where this leaves the ranking

RISC Zero displaces OpenVM as the first candidate to port. It is the only system measured so far
whose proof size is independent of program length and already inside the standard-spend envelope,
and the only one with a supported SHA-256 outer layer in stock releases. The remaining work is a
padded SHA-256 hash suite and then the verifier itself; the hash budget, which killed a direct
OpenVM port, is a rounding error here.

Not measured here, and measured next in [`risc0-verifier-sizing.md`](risc0-verifier-sizing.md): the
arithmetic op count of an actual BabyBear FRI verifier over this seal. It is 687,360 multiplications
and over twice the varops budget, which makes it, not hashing, the reason a direct port does not
fit.
