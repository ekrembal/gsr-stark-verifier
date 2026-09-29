# OpenVM v2.0.2 measurement harness

Reproduces the numbers in [`../../openvm-measurement.md`](../../openvm-measurement.md).

Files:

- `gsr_measure.rs` — the measurement program. Copy into an OpenVM v2.0.2 checkout at `crates/sdk/examples/gsr_measure.rs` and register it as an `[[example]]` in `crates/sdk/Cargo.toml` (that manifest sets `autoexamples = false`). It also needs `p3-poseidon2 = { workspace = true }` and `zstd = "0.13"` added to `[dependencies]` of that manifest.
- `plonky3-poseidon2-counter.patch` — adds a global permutation counter to `p3-poseidon2`. Apply to a Plonky3 `v0.4.3` checkout and point OpenVM at it with a `[patch.crates-io]` section listing every `p3-*` crate in OpenVM's `Cargo.lock` as a path dependency on that checkout, so a single copy of each Plonky3 crate is linked.
- `single-segment-run.txt`, `multi-segment-run.txt` — the recorded runs.

```sh
git clone --depth 1 --branch v2.0.2 https://github.com/openvm-org/openvm.git
git clone --depth 1 --branch v0.4.3 https://github.com/Plonky3/Plonky3.git
git -C Plonky3 apply plonky3-poseidon2-counter.patch
# apply the manifest edits described above, then:
cargo build --release -p openvm-sdk --example gsr_measure
FIB_N=100 ./target/release/examples/gsr_measure
N_STACK=15 FIB_N=2000000 RUST_LOG=info ./target/release/examples/gsr_measure
```

The counter is incremented in `Poseidon2::permute_mut`, which is the single entry point used by both the sponge and the two-to-one compressor for every BabyBear Poseidon2 instance in the verifier, and counts are taken as a delta around the verification call, so proving is excluded.

The multi-segment run needs a smaller app trace (`N_STACK=15`) than the default: at the default height, 500,000 Fibonacci iterations exhaust 31 GB of RAM during proving.
