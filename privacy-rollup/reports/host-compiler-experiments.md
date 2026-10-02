# Host compiler experiments

Neither compiler experiment established a proving speedup. The standard host
build remains the reference. All three runs proved the exact saved 2^18 trace
from the complete four-vector dot-product guest; the guest and proof parameters
did not change. Each receipt passed integrity verification and contained a
255,656-byte seal.

| Host compilation | Prover seconds | Supervisor seconds | Peak RSS KiB |
|---|---:|---:|---:|
| Standard | 100.222 | 100.305 | 2,397,628 |
| C++ `-march=native` | 100.528 | 100.585 | 2,396,448 |
| Also selected Rust CPU/codegen tuning | 105.817 | 105.886 | 2,397,188 |

These are single samples, not a statistical regression study. They give no
reason to adopt either candidate. Exact commands, guards and resource samples
are in [the measurement JSON](host-compiler-measurements.json).
The Rust-tuned receipt was also verified and lifted by the saved standard host
binary in 42.67 supervisor seconds, independently of the tuned verifier build.

The C++ experiment set
`CXXFLAGS_x86_64_unknown_linux_gnu=-march=native` for the existing SDK kernels.
It built in 372.30 supervisor seconds, with a 3,249,352 KiB sampled peak RSS.
The SDK source remained exactly at its original pinned patch.

The Rust experiment additionally used `tools/native_prover_rustc.py` as
`RUSTC_WRAPPER`. It adds `-C target-cpu=native -C codegen-units=1` only for an
explicit list of host proof-engine crates and the benchmark binary. It skips
RISC-V guest compilations. The log records every affected crate and target.
The build took 84.78 supervisor seconds and 1,786,464 KiB peak RSS.

Reproduce from `privacy-rollup/prover`, after the environment exports documented
in the lazy-blinding report. Preserve current executables first. Refresh only
the selected packages' generated artifacts because Cargo does not fingerprint
flags added inside a wrapper:

```sh
cargo clean --release -p risc0-core -p risc0-zkp \
  -p risc0-circuit-rv32im -p risc0-circuit-recursion \
  -p risc0-circuit-keccak -p risc0-zkvm -p pr-prover
export CXXFLAGS_x86_64_unknown_linux_gnu="-march=native"
export RUSTC_WRAPPER=/workspace/gsr-stark-verifier/privacy-rollup/tools/native_prover_rustc.py
export GSR_NATIVE_RUST_LOG=/workspace/gsr-stark-verifier/build/feasibility/native-rust-flags.jsonl
cargo build --locked --release --bin proof_chain_bench
```

For the C++-only case omit the wrapper and Rust flags log. To restore normal
compilation, unset all three variables, repeat the selected-package clean, and
build again. The experiment removed only generated Cargo artifacts; saved
programs, receipts, source, fixtures, dependency pins and lockfiles were retained.
The wrapper is optional and is not referenced by repository Cargo configuration.

The pinned SDK supports only Poseidon2 for these segment proofs. An alternative
hash-suite switch was inspected and ruled out by its explicit runtime guard;
no unsupported proof suite was enabled. GPU and multi-machine proving were not
available in this four-CPU, 16-GiB environment.
