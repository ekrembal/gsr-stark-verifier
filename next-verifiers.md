# Which verifier to add next

This note ranks candidate proof systems for a second GSR verifier in this repository. It is a research note: nothing here is implemented, and every external proof-size or security claim is attributed to its source rather than verified onchain. The only measured GSR numbers in this repository remain those of the shipped [Recursive Stwo](recursive-stwo/README.md) verifier.

It complements the two existing notes. [`potential-starks.md`](potential-starks.md) surveys the candidate field and [`recursive-proof-system-decision.md`](recursive-proof-system-decision.md) records the choice of OpenVM for the next computation stack. This note adds the missing piece: a priced GSR cost model, and the ranking that falls out of it.

## The cost model the ranking is built on

[`research/gsr-primitive-costs.cpp`](research/gsr-primitive-costs.cpp) evaluates the metering formulas of the pinned GSR checkout (`bitcoin/src/script/varops.h`, commit `d2799052604eb138c5a79acf88514a0c8b07f4ef`) over hand-written opcode sequences for the primitives these candidates need. Output is in [`research/gsr-primitive-costs.txt`](research/gsr-primitive-costs.txt). Rebuild it with:

```sh
git submodule update --init bitcoin
g++ -std=c++20 -I bitcoin/src research/gsr-primitive-costs.cpp -o /tmp/gsr-primitive-costs
/tmp/gsr-primitive-costs
```

The rows are lower bounds. They count the arithmetic, bitwise and hashing opcodes of each primitive and ignore operand retrieval, witness parsing, canonical range checks and invocation overhead. The shipped verifier calibrates that gap: its arithmetic, hashing and invocation opcodes account for 346,056,480 of its 1,399,895,948 measured varops, so stack plumbing, parsing and control flow are 75% of a real GSR verifier and the rows below should be multiplied by roughly 4 before being compared to a budget.

| Primitive | Varops | Copies affordable in one 400,000 WU spend, after the 4x factor |
|---|---:|---:|
| SHA-256 two-to-one Merkle parent | 5,892 | 170,000 |
| BLAKE3 compression, 7 rounds | 4,084,192 | 244 |
| BLAKE2s compression, 10 rounds | 5,834,560 | 171 |
| Poseidon2 permutation, 31-bit field, width 16 | 10,769,698 | 92 |
| Keccak-f[1600] permutation | 11,688,672 | 85 |
| Tip5 permutation, Goldilocks, width 16 | 25,042,400 | 39 |
| RPO permutation, Goldilocks, width 12 | 34,871,088 | 28 |
| M31 multiplication mod p (4 B) | 7,720 | 130,000 |
| Goldilocks multiplication mod p (8 B) | 8,028 | 125,000 |
| 128-bit field multiplication mod p (16 B) | 9,580 | 104,000 |
| 252-bit field multiplication mod p (32 B) | 15,004 | 67,000 |

Three consequences drive everything below.

**Only SHA-256 scales.** GSR prices `OP_SHA256` at a flat 1,250 plus 50 per input byte, so a Merkle parent is 5,892 varops, while an arithmetic hash must be built out of thousands of metered opcodes. Poseidon2 costs about 1,800x a SHA-256 parent, RPO about 5,900x. A verifier that authenticates 2,000 Merkle parents spends about 0.05 billion varops with SHA-256 and about 86 billion with Poseidon2, which is 21x a maximal standard spend. The two-digit "copies affordable" numbers in the table are the whole story: an unmodified Poseidon2, Keccak, Tip5 or RPO Merkle layer cannot be verified onchain at any realistic query count. This is not a new constraint discovered here — it is why the shipped verifier's proof terminates in a SHA-256 layer and spends only 9,491 `OP_SHA256` calls — but it is now quantified, and it reorders the candidate list.

**Field size is almost free.** A 32-byte modular multiplication costs 1.9x a 4-byte one, not 64x, because `MulCost` is quadratic in machine words on top of a 3,000-unit floor that dominates at these sizes. A verifier can afford on the order of 10^5 field multiplications regardless of whether the field is M31, Goldilocks, a 128-bit lattice ring, or a 252-bit Cairo prime. Nothing should be rejected for using a big field, and small-field systems get no GSR discount for their field choice — only for the smaller proofs it buys them.

**Witness bytes pay for themselves.** Each witness byte costs 1 WU and funds 10,000 varops. A 32-byte digest costs 32 WU and funds 320,000 varops, while verifying it with a SHA-256 parent spends 1.84% of that. So a SHA-256-based verifier is bound by transaction weight, not by the execution budget: the shipped spend uses 38% of its varops budget but 93% of the standard weight limit. The scarce resource is bytes. With a verifier script in the 100-150 KB range, the practical proof budget for a second verifier is roughly 150-250 KB, and proof size is the primary ranking criterion after the hash question.

## Ranking

The order below is the order the ranking was written in; two of its entries have since been measured, and the measurements reorder it. [`risc0-measurement.md`](risc0-measurement.md) shows RISC Zero already ships most of item 1 and fits the byte budget; [`openvm-measurement.md`](openvm-measurement.md) shows OpenVM does not yet fit on either axis. Read item 4 before item 2.

A third measurement then added an axis this ranking did not have. It ranks on proof bytes and on the commitment hash, on the finding that field arithmetic is cheap per operation. That finding is correct and not sufficient: [`risc0-verifier-sizing.md`](risc0-verifier-sizing.md) counts every BabyBear operation in a RISC Zero succinct-receipt verification and gets 687,360 multiplications, 8.4 billion varops, 210% of a maximal spend — with hashing at 0.36% of the total. **Operation count is a first-class screen, alongside proof size and hash choice, and the affordable budget is on the order of 10^5 field multiplications for the whole verifier.** No candidate below has been screened on it except RISC Zero, which fails it, and the shipped Stwo verifier, which passes at 8,667 multiplications. That screen moves the lead back to item 1: what a GSR script can afford is not a vendor's default recursion circuit but a small, purpose-built final wrapper, and how small it has to be is now a measured number rather than a guess.

### 1. A SHA-256-terminated outer layer, as a reusable component

This is a prerequisite rather than a verifier, and it is the highest-leverage thing to add. Every general-purpose recursive stack worth porting — OpenVM, RISC Zero, Miden, SP1 — commits with Poseidon2 or another arithmetic hash, because that is what makes their own recursion cheap. The table says that choice is fatal onchain. The fix is the one the shipped verifier already relies on: a final recursion layer, proved offchain, whose own commitments use SHA-256, verifying the arithmetic-hash proof inside its circuit.

Plonky3 is the concrete vehicle: it ships `p3-sha256`, and OpenVM's backend already pins Plonky3, so an OpenVM proof and a SHA-256-committed Plonky3 wrapper share a field and a Merkle abstraction. Plonky3's recent Merkle multiproof pruning also reduces example proof sizes by roughly 40% in upstream benchmarks, which matters directly under a byte-bound budget.

One detail decides whether the priced SHA-256 row applies. `p3-sha256` exposes both the padded hash and a padding-free compression function, and the padding-free variant is the one a Plonky3 Merkle tree would normally use, because it is cheaper to prove. `OP_SHA256` computes the padded hash, which for a 64-byte input is two compressions plus length encoding, so a padding-free node digest is a different value and cannot be recomputed by a single GSR opcode. The wrapper must therefore be configured with the padded hash as its Merkle and duplex compression — the shape the `Sha256Parent` row prices and the shipped verifier already spends — and the prover pays for that choice, not the script.

Acceptance: a Plonky3 STARK whose commitment scheme and Fiat-Shamir transcript are the padded SHA-256 throughout, verifying a fixed inner statement, with a raw canonical proof under 200 KB and a query count and blowup chosen at a stated security level. This cannot be obtained by substituting hash calls in an already-serialized proof; it is a different proving configuration and has to be proved that way. Caveat: generic Plonky3 recursion is less mature than the vendor-maintained recursion in OpenVM or RISC Zero, and is unaudited.

### 2. OpenVM v2.0.2, SWIRL/WHIR — measured, and blocked on item 1

OpenVM remains the strongest candidate on paper. It is the only one that combines a maintained multi-level recursive aggregation pipeline, a transparent hash-based commitment, and WHIR, whose whole point is a small proof and a low query count. Its verifier algebra is BabyBear with a degree-four extension, which the second finding above says is cheap.

It remains the better proof-size story if its hash problem is ever solved, and the WHIR proof should compress further than a fixed-size recursion receipt can. WHIR's low query count also matters more than it appeared to when this was written: queries drive the per-query arithmetic that the operation-count screen charges for. Its verifier has not been counted on that screen, and should be before any port.

The risk is entirely in the hash, and that risk has now been measured rather than modelled. [`openvm-measurement.md`](openvm-measurement.md) records a real 35-segment proof with two aggregation levels above the leaf layer: 315,319 raw canonical bytes, and 14,737 Poseidon2 permutations in the host verifier, against the 92 this table affords. That is 40x a maximal standard spend on the primitive lower bound and 161x after the overhead factor, so item 1 is a hard dependency for OpenVM. The same proof shape verified with padded SHA-256 parents would spend 8.8% of the budget instead, which leaves proof size as the binding constraint: 315 KB of witness already consumes 79% of a 400,000 WU spend.

Acceptance criteria for the eventual port are unchanged from [`recursive-proof-system-decision.md`](recursive-proof-system-decision.md): bind public values, executable identity, successful termination, the aggregation verifying keys, recursion metadata and a trusted baseline, then serialize and execute the complete spend under activated GSR rules within 400,000 WU. Note that OpenVM's documented security profile is about 100 bits and must not be relabelled as 128-bit.

### 3. Lattice Jolt — the best proof-size profile of any post-quantum system, on a different assumption

a16z crypto's September 2026 release replaces Jolt's elliptic-curve Dory commitment with Akita, a Module-SIS lattice commitment, and reports proofs under 100 KB against 200-600 KB for hash-based post-quantum zkVMs, with a 128-bit target under Module-SIS. On a byte-bound chain those claims, if they hold in canonical serialized form, are worth more than any hash-side optimisation: under 100 KB would leave room for both the proof and a large verifier script well inside the standard limit.

It also happens to suit GSR's arithmetic. The verifier is sumcheck plus lattice checks over a roughly 128-bit modulus, and the table prices a 16-byte modular multiplication at 9,580 varops with about 10^5 affordable — so the feasibility question is the operation count of Akita's verifier, not its word size. GSR's native arbitrary-length unsigned arithmetic is a better fit for a lattice verifier than for a small-field STARK.

Two caveats keep it below OpenVM. It is not hash-based, so adopting it means accepting a lattice assumption alongside the repository's current hash-only posture; a16z's own argument is precisely that hash-based post-quantum security is less conservative than it is marketed as, and that argument deserves to be weighed rather than assumed. And it is new: there is no audit history, and the companion zero-knowledge paper was still forthcoming at release.

Acceptance for a feasibility study, before any port: count the ring multiplications, norm checks and transcript hashes in one Akita verification at the released parameters, price them with the model above, and measure the raw proof bytes. Swap the Fiat-Shamir transcript to SHA-256 if it is not already — a Keccak transcript costs 85 permutations per spend and would dominate everything else.

### 4. RISC Zero succinct receipts — fits on bytes and hashing, fails on arithmetic

This entry was written as a fallback behind OpenVM on the strength of published claims. Measurement reversed that. [`risc0-measurement.md`](risc0-measurement.md) records a real v3.0.6 succinct receipt over a lift/join aggregation of 3 and of 18 segments: 222,668 seal bytes in both cases, and, once the final layer is re-proved under the stock `sha-256` hash suite, 4,363 SHA-256 digest-pair hashes and 355 slice hashes over 86,028 bytes to verify — 30,451,946 varops, 0.76% of a maximal standard spend, 3.08% after the overhead factor. The same receipt verified in its stock Poseidon2 configuration costs 2,013x more.

That clears both constraints this note ranks on. Proof size is constant in program length, unlike OpenVM's, and 222,668 bytes against the shipped verifier's 224,896-byte witness payload and 144,905-byte script is the same shape as a spend that already lands at 370,387 WU. The dependency on item 1 is mostly discharged in-stock: SHA-256 applies to the outer layer only — `lift` and `join` still assert Poseidon2 inputs — but that is precisely the arrangement item 1 asks for, since the inner Poseidon2 hashing is verified inside the identity circuit rather than in Script.

What remained of item 1 was narrow, and is now discharged: RISC Zero's `sha-256` suite hashes with the raw compression function rather than padded FIPS SHA-256, so `OP_SHA256` cannot reproduce its digests. [`risc0-verifier-sizing.md`](risc0-verifier-sizing.md) adds a `sha-256-padded` suite and proves and verifies a real succinct receipt under it, with no circuit change, no change in seal size, and identical hash counts — the digests are now exactly what `OP_CAT`/`OP_SHA256` computes.

The same note then sizes the verifier itself, and that is where the port stops. Verifying the seal costs 687,360 BabyBear multiplications, 480,016 additions and 31,644 subtractions, which price at 8,386,531,106 varops: 210% of a maximal standard spend at the primitive lower bound, 849% after the overhead factor, needing 838,653 WU of transaction weight against a 400,000 WU limit. Cutting queries does not fix it — the query-independent setup, mixing and constraint evaluation alone are 89% of the budget. The obstacle is that the seal proves a 643-tap recursion circuit at `po2 = 18` with a 12,359-step constraint program, so the fix is a deliberately small final wrapper circuit, which is proof-side work rather than Script-side work.

### 5. Stwo/Cairo with a SHA-256 channel — the cheapest incremental win

This repository already contains a working Circle-STARK verifier with M31 arithmetic, SHA-256 Merkle handling, witness packing and a measured spend. `stwo-cairo` is a production Circle STARK prover and verifier for the Cairo architecture with a recursive Cairo verifier, and Stwo supports Blake2s, Blake3, Poseidon252 and Keccak256 channels. A Cairo-program verifier would reuse most of the existing arithmetic layer, and the marginal work is the AIR and the proof shape rather than a new field or hash stack. The table rules out the Blake2s and Keccak channels at scale (171 and 85 compressions per spend), so this depends on reproducing the hybrid SHA-256 final layer the shipped bundle already uses. Highest ratio of value to new risk if a Cairo workload is wanted; no value if the goal is arbitrary Rust programs.

### 6. Binius64 — revisit when proofs shrink

A transparent, hash-based system over characteristic 2, built around 64-bit machine words and bitwise AND, 64-bit multiplication and GHASH-field multiplication, claiming plausible post-quantum security on conservative hash assumptions. Its word-oriented constraint model maps unusually well onto GSR's native bitwise and multiplication opcodes. The blocker is size: documented proofs run 250-500 KiB, with a published hash-signature benchmark at 322.11 KiB. That does not fit alongside a verifier script under 400,000 WU. Track it; reconsider if proofs reach the 150 KB range.

### 7. Triton VM and Miden — specialised, and hash-blocked

Triton VM offers native recursive STARK verification with Tip5 over a Goldilocks-like field, and Miden's lifted STARK is built on Plonky3 with RPO, RPX, Poseidon2, BLAKE3 and Keccak256 available. Both chose their hashes to make recursion cheap inside their own circuits, which is exactly the wrong optimisation target for GSR: 39 Tip5 and 28 RPO permutations per spend. Hint-checked inverse S-boxes (the prover supplies `y = x^(1/7)`, the verifier checks `y^7 = x` with four multiplications) are already assumed in those figures and do not change the order of magnitude. Neither is worth porting unless someone specifically wants Triton or Miden programs onchain, and either way only behind item 1.

### 8. WHIR and Ligerito — components, not verifiers

Both are polynomial commitment and opening schemes, not complete application proof systems, and neither authenticates a program, its public inputs or its termination on its own. WHIR already reaches this repository through OpenVM. Ligerito reports a 255 KiB proof for a 2^24-coefficient binary-field instance and has SHA-256 transcript variants, which makes it interesting as a future commitment layer under a SHA-256 outer proof, not as a standalone second verifier.

### 9. SP1 — only if elliptic-curve assumptions are acceptable

SP1 has mature recursive shard aggregation, but its global memory argument hashes with Poseidon2 into an elliptic curve and accumulates with curve addition, so its soundness rests on a discrete-log assumption in addition to hash assumptions. That is outside the repository's stated hash-only posture and, unlike Lattice Jolt, the added assumption is not post-quantum. Skip unless that posture changes.

### 10. Plonky2 and Nova — not recommended

Plonky2 has working recursion but is officially deprecated and a poor base for a new maintained integration. Nova-style folding currently relies on curve cycles and Pedersen or KZG-family commitments, which are neither transparent in the required sense nor post-quantum.

## Measurement protocol any candidate must follow

These rules exist because published numbers are not GSR numbers.

1. Measure the raw canonical proof encoding. Not JSON, not a zstd-compressed artifact — GSR has no decompressor, so compressed transport size is not onchain size.
2. Measure the complete spend: proof, verifier script, hints, public values, length prefixes, control block and transaction overhead. The target is 400,000 WU, and about 300,000 WU is the sane engineering goal so the shape has room to change.
3. Check every limit, not just weight: varops, 32,768 stack and altstack and definition entries, 8,000,000 bytes of live payload, 4,000,000 cumulative invoked function-body bytes, 256 function definitions.
4. Count arithmetic-hash invocations before writing any Script. Divide the affordable-copies column by the count; if the answer is below 1 there is no point continuing without item 1.
5. Bind the application statement. A verifier that checks a proof but not the program identity, the public inputs, successful termination and the aggregation metadata is not a verifier.
6. Hold security parameters fixed. Query counts and blowup factors must not be reduced to make a candidate fit, and a system's documented security level must be reported as documented.
7. Run against the pinned GSR node with Tapscript v2 activated, and record the result as a machine-readable cost report next to the implementation, as `recursive-stwo/reports/` does.

A post-quantum proof inside a Tapscript v2 leaf does not make the spend post-quantum: the Taproot output key is still an elliptic-curve point and the key path is still spendable. That is a property of the envelope, not of the candidate, and it applies equally to all of the above.

## Recommendation

Item 2's measurement is done and is recorded in [`openvm-measurement.md`](openvm-measurement.md): the count came back 40x to 161x above the affordable range, so item 1 is a hard dependency and is now the next piece of work, with the proof-size target it has to hit set by that measurement. Start the item 3 feasibility study in parallel, since it shares no code with the rest and its proof-size claim is the only one on the list that would comfortably fit a complete spend.
