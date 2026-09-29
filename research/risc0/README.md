# RISC Zero v3.0.6 measurement harness

Reproduces the numbers in [`../../risc0-measurement.md`](../../risc0-measurement.md).

Files:

- `risc0-gsr-measure.patch` — apply to a RISC Zero `v3.0.6` checkout. It adds a hash-work counter
  module to `risc0-zkp` (SHA-256 digest-pair hashes, SHA-256 slice hashes and their byte counts,
  Poseidon2 permutations), wires it into `Sha256HashFn`, `ShaRng::step` and `poseidon2_mix`, makes
  the busy-loop segment count configurable through `R0_GSR_CYCLES_MULT`, and adds the `gsr_measure`
  test to `risc0/zkvm/src/host/recursion/tests.rs`.
- `three-segment-run.txt`, `eighteen-segment-run.txt` — the recorded runs.
- `gsr-risc0-costs.cpp`, `gsr-risc0-costs.txt` — prices the measured counts with the pinned GSR
  cost functions, in the style of [`../gsr-primitive-costs.cpp`](../gsr-primitive-costs.cpp).

```sh
git clone --depth 1 --branch v3.0.6 https://github.com/risc0/risc0.git
git -C risc0 apply risc0-gsr-measure.patch
# rzup provides the toolchains the prover needs; it reads GITHUB_TOKEN to avoid API rate limits
GITHUB_TOKEN=$(gh auth token) rzup install rust
GITHUB_TOKEN=$(gh auth token) rzup install cpp
cd risc0
RUST_LOG=info cargo test --release -p risc0-zkvm --features prove --lib gsr_measure -- --nocapture
R0_GSR_CYCLES_MULT=8 cargo test --release -p risc0-zkvm --features prove --lib gsr_measure -- --nocapture
```

From the workspace root of this repository:

```sh
g++ -std=c++20 -I bitcoin/src research/risc0/gsr-risc0-costs.cpp -o /tmp/gsr-risc0-costs
/tmp/gsr-risc0-costs
```

The counters are read as a delta around `verify_integrity_with_context`, so proving is excluded.
`Sha256HashFn` and `ShaRng` are the only SHA-256 entry points the verifier's hash suite uses — the
RNG step counts as two digest-pair hashes — and `poseidon2_mix` is the single permutation entry
point of the Poseidon2 suite. The measurement verifies two receipts over the same aggregate: the
stock Poseidon2 succinct receipt, and the SHA-256 receipt produced by `Prover::new_identity` under
`ProverOpts::succinct().with_hashfn("sha-256")`.
