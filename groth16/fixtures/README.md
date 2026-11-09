# Fixture

`receipt.json` contains a real RISC Zero 3.0.6 Groth16 receipt produced by
`ProverOpts::groth16()` for the small guest in `../tools/native/methods/guest`.
The fixture generator runs `Receipt::verify` before exporting the files.

- `seal.a` and `seal.c` are `[x, y]` decimal field elements.
- `seal.b` is `[[x0, x1], [y0, y1]]`, with each Fp2 value in the seal's
  encoded coefficient order.
- `public_inputs` is exactly `[a0, a1, c0, c1, id]`, as decimal field
  elements, using RISC Zero's `split_digest` byte order.
- `verifying_key.ic` is ordered `[IC0, IC1, IC2, IC3, IC4, IC5]`.
- `seal.bin` is the 256-byte seal consumed by RISC Zero.
- `receipt.borsh` is the serialized receipt used by the native verification
  helper.

Regenerate with `../tools/prove.sh`. The helper uses the Docker-based RISC Zero
Groth16 prover. To verify the committed receipt without proving again, run:

```sh
cargo run --release --locked --manifest-path ../tools/native/Cargo.toml -- verify .
```
