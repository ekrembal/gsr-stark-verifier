# RISC Zero v3.0.6 measurement harness

Reproduces the numbers in [`../../risc0-measurement.md`](../../risc0-measurement.md) and
[`../../risc0-verifier-sizing.md`](../../risc0-verifier-sizing.md).

Files:

- `risc0-gsr-measure.patch` — apply to a RISC Zero `v3.0.6` checkout. It adds a hash-work counter
  module to `risc0-zkp` (SHA-256 digest-pair hashes, SHA-256 slice hashes and their byte counts,
  Poseidon2 permutations), wires it into `Sha256HashFn`, `ShaRng::step` and `poseidon2_mix`, makes
  the busy-loop segment count configurable through `R0_GSR_CYCLES_MULT`, and adds the `gsr_measure`
  test to `risc0/zkvm/src/host/recursion/tests.rs`. It also adds the `sha-256-padded` hash suite
  and the BabyBear operation counters described below.
- `three-segment-run.txt`, `eighteen-segment-run.txt` — the recorded stock runs.
- `padded-suite-run.txt` — the recorded run of the padded suite and the field-operation counters.
- `gsr-risc0-costs.cpp`, `gsr-risc0-costs.txt` — prices the measured hash counts with the pinned GSR
  cost functions, in the style of [`../gsr-primitive-costs.cpp`](../gsr-primitive-costs.cpp).
- `gsr-risc0-fri-costs.cpp`, `fri-costs.txt` — the same, for the complete verifier: BabyBear
  arithmetic by phase plus padded SHA-256 hashing.
- `fri-structure.py`, `fri-structure.txt` — derives the proof's Merkle and FRI structure from the
  pinned constants and checks it against the measured hash counts.
- `kernels/` — packed BabyBear kernels written as real Tapscript v2, metered in the pinned
  interpreter, and composed into a projection of an optimised verifier; see
  [`kernels/README.md`](kernels/README.md).

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
g++ -std=c++20 -I bitcoin/src research/risc0/gsr-risc0-fri-costs.cpp -o /tmp/gsr-risc0-fri-costs
/tmp/gsr-risc0-fri-costs
python3 research/risc0/fri-structure.py
```

The counters are read as a delta around `verify_integrity_with_context`, so proving is excluded.
`Sha256HashFn` and `ShaRng` are the only SHA-256 entry points the verifier's hash suite uses — the
RNG step counts as two digest-pair hashes — and `poseidon2_mix` is the single permutation entry
point of the Poseidon2 suite. The measurement verifies two receipts over the same aggregate: the
stock Poseidon2 succinct receipt, and the SHA-256 receipt produced by `Prover::new_identity` under
`ProverOpts::succinct().with_hashfn("sha-256")`.

## The padded suite and the field-operation counters

The patch adds `risc0/zkp/src/core/hash/sha_padded.rs`, a `"sha-256-padded"` hash suite whose pair
and slice hashes are ordinary FIPS SHA-256 (with padding and the length trailer) rather than the
stock raw compression function, with a matching `PaddedShaRng` so the Fiat-Shamir transitions use
the same hash. It is registered in `hash_suite_from_name`, in the recursion prover's CPU HAL and in
`VerifierContext::default_hash_suites()`. The shipped `SHA256_CONTROL_IDS` are for the raw suite, so
`zkr::identity` derives the control ID at runtime with `Program::compute_control_id` when the padded
suite is selected; the `gsr_measure` test passes it through `ProverOpts::with_control_ids`.

`gsr_padded_sha_matches_fips` pins the equivalence against `Sha256::hash_bytes` and against the FIPS
`"abc"` vector, and asserts the stock suite differs.

The patch also adds `risc0/core/src/field/gsr_ops.rs`, counters on the BabyBear base and extension
operators, and phase markers in `risc0/zkp/src/verify/mod.rs` that attribute each operation to
setup/mixing, constraint evaluation, FRI folding or per-query DEEP-ALI. Counting is off by default
and switched on only around `verify_integrity_with_context`, because counting during proving is
prohibitively slow. The base counters include the base operations performed inside extension
operations, so they are the complete arithmetic and the extension counters must not be added to
them; the extension rows are reported to show the shape of the work.

Run it, optionally dumping the raw seals:

```sh
cd risc0
R0_GSR_SEAL_DIR=/tmp/gsr-seals RUST_LOG=warn \
  cargo test --release -p risc0-zkvm --features prove --lib gsr_measure -- --nocapture
cargo test --release -p risc0-zkvm --features prove --lib gsr_padded_sha_matches_fips -- --nocapture
```
