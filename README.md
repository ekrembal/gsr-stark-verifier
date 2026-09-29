# GSR ZKP verifiers

Implementations of zero-knowledge proof-system verifiers for Bitcoin's Great Script Restoration (GSR), using Tapscript v2. Each verifier lives in its own directory with its source, dependencies, fixtures, tests, and measured results. The pinned Bitcoin checkout in [`bitcoin/`](bitcoin/) is shared.

> **Warning — research code. Do not use in production.**
>
> This is an experimental research artifact published to document a GSR feasibility milestone. It has not been audited or independently reviewed for cryptographic or implementation security. It targets a proposed Tapscript v2 that is not part of Bitcoin consensus, and the verifier is fixed-shape: it verifies one pinned recursive proof bundle with hard-coded circuit commitments, FRI parameters, and public-input count, not arbitrary STARK proofs. Use it at your own risk; see [`LICENSE`](LICENSE) for the applicable disclaimer of warranty and liability.

## Implemented verifiers

- **[Recursive Stwo](recursive-stwo/README.md)** — a GSR port built on [Bitcoin Wildlife Sanctuary's recursive-stwo-bitcoin](https://github.com/Bitcoin-Wildlife-Sanctuary/recursive-stwo-bitcoin). It verifies the existing recursive proof bundle, including its delegated obligations, in one standard Taproot spend. The upstream project supplies the recursive proof pipeline and Bitcoin verifier; this implementation adapts its arithmetic, witness handling, and Script compilation to GSR.

## Current results and limits

These results are for the Recursive Stwo reference bundle on the unmodified GSR node at commit `d2799052604eb138c5a79acf88514a0c8b07f4ef`. No consensus limits, policy limits, or proof parameters were changed.

| Metric | Recursive Stwo result | Limit / requirement |
|---|---:|---|
| Onchain verification | Accepted under standard policy and mined on activated regtest | One Tapscript v2 spend |
| Transaction weight | 370,387 WU | ≤ 400,000 WU |
| Varops | 1,399,895,948 | ≤ 3,703,870,000 for this transaction |
| Cumulative invoked function-body bytes | 973,854 bytes | ≤ 4,000,000 bytes |
| Function definitions | 128; acyclic | ≤ 256; acyclic |
| Peak stack + altstack + definitions | 1,481 entries | ≤ 32,768 entries |
| Peak combined live payload | 234,614 bytes | ≤ 8,000,000 bytes |
| Largest stack element | 4,096 bytes | ≤ 4,000,000 bytes |
| Verifier script | 144,905 bytes | Included in transaction weight |
| Packed witness payload | 224,896 bytes | Included in transaction weight |
| SHA-256 work | 9,491 calls; 513,141 input bytes | Charged to varops |
| Function calls | 26,625 | Charged to varops and invoked-body bytes |
| Base-field arithmetic | 8,667 multiplications; 15,747 additions; 10,562 subtractions; 52 negations | Charged to varops |
| Native reference verification | Both original proof fixtures pass; 273 bound public inputs | Preserve the upstream proof bundle |
| Differential validation | 31,605 intermediate checks pass | Match the pinned native implementation |
| Negative validation | 397 malformed cases reject | Reject altered proofs, hints, commitments, public inputs, and witness sections |

**All resource limits pass**, with 29,613 WU remaining. The varops budget is 10,000 times eligible transaction weight; all inputs in this transaction are eligible. Arithmetic counts describe semantic field operations, separately from emitted opcodes.

The current milestone uses the original `hybrid_hash.bin` and `bitcoin_proof.bin` fixtures and retains Poseidon in the offchain recursion pipeline. New application proofs, other proof shapes, and SHA-256 throughout recursion remain follow-up work. Research notes elsewhere in this repository do not represent additional implemented verifiers.

See the [Recursive Stwo build and usage instructions](recursive-stwo/README.md), [machine-readable cost report](recursive-stwo/reports/cost-report.json), and [regtest acceptance evidence](recursive-stwo/reports/regtest-acceptance.json).

## Research notes

These describe candidate systems and measurements, not implemented verifiers.

- [`next-verifiers.md`](next-verifiers.md) — priced GSR cost model for candidate primitives, and the resulting ranking of which verifier to add next.
- [`openvm-measurement.md`](openvm-measurement.md) — measured proof bytes and Poseidon2 verifier cost of a real OpenVM v2.0.2 aggregated proof, priced against a standard spend.
- [`risc0-measurement.md`](risc0-measurement.md) — measured seal bytes and SHA-256 and Poseidon2 verifier cost of a real RISC Zero v3.0.6 succinct receipt, priced against a standard spend.
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
