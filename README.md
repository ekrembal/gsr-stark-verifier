# GSR ZKP verifiers

Implementations of zero-knowledge proof-system verifiers for Bitcoin's Great Script Restoration (GSR), using Tapscript v2. Each verifier lives in its own directory with its source, dependencies, fixtures, tests, and measured results. The pinned Bitcoin checkout in [`bitcoin/`](bitcoin/) is shared.

> **Warning — research code. Do not use in production.**
>
> This is an experimental research artifact published to document a GSR feasibility milestone. It has not been audited or independently reviewed for cryptographic or implementation security. It targets a proposed Tapscript v2 that is not part of Bitcoin consensus, and the verifiers are fixed-shape: each verifies one pinned proof statement with hard-coded circuit commitments, FRI parameters, and public inputs, not arbitrary STARK proofs. Use it at your own risk; see [`LICENSE`](LICENSE) for the applicable disclaimer of warranty and liability.

## Implemented verifiers

- **[RISC Zero succinct receipt](risc0-succinct/README.md)** — verifies a RISC Zero v3.0.6 succinct (recursion-circuit) receipt, proven under a padded SHA-256 hash suite, in one standard Taproot spend: 388,398 WU and 2,083,395,104 of 3,883,980,000 varops, mined on activated regtest. It is checked against RISC Zero's native verifier on the valid receipt and 34 negative cases. A [covenant demo](risc0-succinct/README.md#covenant-demo-a-utxo-only-a-stark-proof-can-spend) locks a UTXO so that only a receipt of a demo guest can spend it, and only to the outputs in the guest's journal (388,641 WU, mined on regtest); the Script reads the outputs with `OP_TX`.
- **[Recursive Stwo](recursive-stwo/README.md)** — a GSR port built on [Bitcoin Wildlife Sanctuary's recursive-stwo-bitcoin](https://github.com/Bitcoin-Wildlife-Sanctuary/recursive-stwo-bitcoin). It verifies the existing recursive proof bundle, including its delegated obligations, in one standard Taproot spend. The upstream project supplies the recursive proof pipeline and Bitcoin verifier; this implementation adapts its arithmetic, witness handling, and Script compilation to GSR.

## Current results and limits

All results are measured on the complete spending transaction on the unmodified GSR node at commit `d2799052604eb138c5a79acf88514a0c8b07f4ef`, and each spend was accepted under standard policy and mined on activated regtest. No consensus limits, policy limits, or proof parameters were changed. The varops budget is 10,000 times eligible transaction weight, so it differs slightly per transaction.

| Metric | Recursive Stwo | RISC Zero succinct receipt | RISC Zero covenant demo | Limit |
|---|---:|---:|---:|---|
| Transaction weight | 370,387 WU | 388,398 WU | 388,641 WU | ≤ 400,000 WU |
| Varops | 1,399,895,948 | 2,083,395,104 | 2,085,001,847 | ≤ 10,000 × weight |
| Varops budget for this transaction | 3,703,870,000 | 3,883,980,000 | 3,886,410,000 | |
| Varops used | 37.8% | 53.6% | 53.6% | |
| Cumulative invoked function-body bytes | 973,854 | 3,231,577 | 3,231,577 | ≤ 4,000,000 |
| Function definitions | 128 | 14 | 14 | ≤ 256; acyclic |
| Function calls | 26,625 | 15,553 | 15,553 | Charged to varops |
| Peak stack + altstack + definitions | 1,481 entries | 2,666 entries | 2,666 entries | ≤ 32,768 entries |
| Peak combined live payload | 234,614 bytes | 347,208 bytes | 346,587 bytes | ≤ 8,000,000 bytes |
| Largest stack element | 4,096 bytes | 16,384 bytes | 16,384 bytes | ≤ 4,000,000 bytes |
| Verifier script | 144,905 bytes | 158,572 bytes | 158,815 bytes | Included in weight |
| Witness items / payload | 224,896 bytes | 762 items / 227,724 bytes | 762 items | Included in weight |
| SHA-256 work | 9,491 calls; 513,141 input bytes | 4,712 calls; 364,876 input bytes | 4,715 calls | Charged to varops |
| Proof | Recursive Stwo bundle, 273 bound public inputs | 222,668-byte seal, `sha-256-padded` suite | same, guest `bb06f6ec…d05b` | |
| Native / differential validation | Both fixtures pass; 31,605 intermediate checks match | Native, Python reference and Script agree; 264 intermediate values match | Native and reference accept; native rejects a changed journal | Match the native verifier |
| Negative validation | 397 malformed cases reject | 34 cases reject in all three verifiers | 6 cases reject (outputs changed, other image, tampered seal) | Reject invalid spends |

**All resource limits pass for all three.** Arithmetic counts describe semantic field operations, separately from emitted opcodes. The Recursive Stwo verifier also performs 8,667 base-field multiplications, 15,747 additions, 10,562 subtractions and 52 negations.

Measured proof systems that do not have a verifier here, for comparison:

| System | Proof bytes | Verifier hash work | Verdict |
|---|---:|---|---|
| OpenVM v2.0.2, 35 segments, aggregated | 315,319 | 14,737 Poseidon2 permutations (~40× a spend) | Needs a SHA-256 outer layer |
| RISC Zero v3.0.6 succinct, stock Poseidon2 | 222,668 | 5,693 Poseidon2 permutations (~15× a spend) | Re-prove the outer layer under SHA-256 (as above) |

For Recursive Stwo, the current milestone uses the original `hybrid_hash.bin` and `bitcoin_proof.bin` fixtures and retains Poseidon in the offchain recursion pipeline. New application proofs, other proof shapes, and SHA-256 throughout recursion remain follow-up work. Research notes elsewhere in this repository do not represent additional implemented verifiers.

Machine-readable reports: Recursive Stwo [cost](recursive-stwo/reports/cost-report.json) and [regtest acceptance](recursive-stwo/reports/regtest-acceptance.json); RISC Zero [cost](risc0-succinct/reports/cost-report.json), [regtest acceptance](risc0-succinct/reports/regtest-acceptance.json), [differential](risc0-succinct/reports/differential.txt) and [covenant](risc0-succinct/reports/covenant.json).

## Research notes

These describe candidate systems and measurements, not implemented verifiers.

- [`next-verifiers.md`](next-verifiers.md) — priced GSR cost model for candidate primitives, and the resulting ranking of which verifier to add next.
- [`openvm-measurement.md`](openvm-measurement.md) — measured proof bytes and Poseidon2 verifier cost of a real OpenVM v2.0.2 aggregated proof, priced against a standard spend.
- [`risc0-measurement.md`](risc0-measurement.md) — measured seal bytes and SHA-256 and Poseidon2 verifier cost of a real RISC Zero v3.0.6 succinct receipt, priced against a standard spend.
- [`risc0-verifier-sizing.md`](risc0-verifier-sizing.md) — a FIPS-padded SHA-256 hash suite for RISC Zero's recursion layer, validated by proving and verifying a receipt under it, the measured BabyBear arithmetic of verifying that seal priced against a standard spend, and packed Tapscript v2 kernels metered in the pinned interpreter that project the verifier at 40% of one spend (a projection, not a written verifier).
- [`potential-starks.md`](potential-starks.md) — survey of candidate STARK and post-quantum proof systems against GSR limits.
- [`recursive-proof-system-decision.md`](recursive-proof-system-decision.md) — the recorded choice of OpenVM for the next recursive computation stack.
- [`gsr-opcodes.md`](gsr-opcodes.md) — the opcodes GSR adds and restores.

## Build and reproduce

From the repository root:

```sh
git submodule update --init bitcoin
cd recursive-stwo
bash tools/build.sh
bash tools/test.sh
cargo run --locked -- regtest-demo
```

The instrumentation harness links against the pinned Core static libraries; on GNU/Linux the link order matters, so `libbitcoin_consensus.a` is passed after the libraries that reference it.

Verifier artifacts and regtest data are written under `recursive-stwo/build/`; the shared node binaries are built under `build/bitcoin/` at the repository root. Each verifier can maintain its own Cargo workspace and toolchain.

## License and attribution

This repository is released under the [MIT License](LICENSE).

It vendors and builds on third-party projects that keep their own licenses and copyright:

- [Bitcoin Wildlife Sanctuary](https://github.com/Bitcoin-Wildlife-Sanctuary) `recursive-stwo-bitcoin` and `recursive-stwo` — MIT, vendored under [`recursive-stwo/vendor/bws-bitcoin`](recursive-stwo/vendor/bws-bitcoin) and [`recursive-stwo/vendor/bws-recursion`](recursive-stwo/vendor/bws-recursion).
- [`stwo`](https://github.com/starkware-libs/stwo) (via `stwo-circle-poseidon-plonk`) — Apache License 2.0, vendored under [`recursive-stwo/vendor/bws-stwo`](recursive-stwo/vendor/bws-stwo).
- [Bitcoin Core](https://github.com/bitcoin/bitcoin) with the GSR branch used by the [`bitcoin/`](bitcoin/) submodule — MIT.

Pinned upstream revisions and the local changes applied to them are recorded in [`recursive-stwo/vendor/README.md`](recursive-stwo/vendor/README.md).
