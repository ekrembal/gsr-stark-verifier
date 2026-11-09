# Native RISC Zero fixture helper

Generate a real Groth16 receipt and export the proof, claim, public inputs, and
RISC Zero verifying key:

```sh
../prove.sh
```

This runs a tiny guest with RISC Zero 3.0.6 and
`ProverOpts::groth16()`. Docker is required for Groth16 proving.

Verify an existing Borsh receipt and refresh its JSON export without proving:

```sh
cargo run --release --locked --manifest-path Cargo.toml -- verify ../../fixtures
```

Both paths call `Receipt::verify` before reporting success. Build output stays
in the ignored `target/` directory.
