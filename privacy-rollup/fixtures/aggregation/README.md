# Fixed public aggregation input

The locally retained `proof0.pc.gz` is a real ProveKit proof of the synthetic deposit constructed by `joinsplit-batch`
at the approved PR baseline. `witness.json` contains its public demo batch witness. These are local
test inputs with synthetic funding, no external account or funds. The gzip timestamp is zero.

The generated proof binary is excluded from the PR and remains in the private review archive. The
small public `witness.json` is retained as documentation of the measured input. The proof was generated
with release postcard layout; debug ProveKit proofs include an additional
transcript-pattern field. Keep this fixture fixed when comparing guest builds: independently generated
proofs have different hints and execution costs.

| File | Uncompressed bytes | SHA-256 |
|---|---:|---|
| `proof0.pc` | 635,142 | `e3ed84cde408df6b83ace47e77358dd3eb6cf34d092d01a9f256702cb7f256fa` |
| `witness.json` | 29,326 | `0beabb1cb720abaf578400dc3f8116ec2838e8589fc1087f7b157d208d34a0f8` |
| exported `vk.pc` | 3,213,548 | `bc1384089b1dc1654e61561089523ae521d2cf9b664589ec1e965108b4e2a183` |

From `privacy-rollup`, after building the adapter in release mode, generate a fresh pair once and use
the same directory for every build being compared:

```sh
target/release/joinsplit-batch fixtures/joinsplit/joinsplit.pkp fixtures/joinsplit/joinsplit.pkv \
  ../build/aggregation/inputs
sha256sum ../build/aggregation/inputs/{vk.pc,proof0.pc,witness.json}
```

For the exact published measurements, first restore the locally retained proof from the private review
archive. Given that `proof0.pc.gz`, use:

```sh
mkdir -p ../build/aggregation/inputs
gzip -dc fixtures/aggregation/proof0.pc.gz > ../build/aggregation/inputs/proof0.pc
cp fixtures/aggregation/witness.json ../build/aggregation/inputs/witness.json
target/release/provekit-export fixtures/joinsplit/joinsplit.pkv ../build/aggregation/inputs/vk.pc
sha256sum ../build/aggregation/inputs/{vk.pc,proof0.pc,witness.json}
```

See [the measurement report](../../reports/aggregation-optimizations.md) for execution and rejection
commands. This fixture contains a ProveKit client proof, not a RISC Zero receipt.
