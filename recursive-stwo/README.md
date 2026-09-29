# Recursive Stwo verifier on GSR

Part of the [GSR ZKP verifiers collection](../README.md). This implementation is built on [Bitcoin Wildlife Sanctuary's recursive-stwo-bitcoin](https://github.com/Bitcoin-Wildlife-Sanctuary/recursive-stwo-bitcoin), using verifier revision `083df955a7588ae1bb5e4e251dbf7df6733a08bc`. The recursive proof pipeline and original Bitcoin verifier come from that upstream project; this directory contains the GSR port and its reproducible evidence.

The pinned recursive proof bundle verifies in **one standard Tapscript v2 spend**. The uninstrumented GSR node accepted and mined the final transaction on activated regtest. No consensus limits, policy limits, grinding bits, or query counts were changed.

| Final measurement | Result | Limit |
|---|---:|---:|
| Transaction weight | 370,387 WU | 400,000 WU |
| Varops | 1,399,895,948 | 3,703,870,000 |
| Cumulative invoked function bodies | 973,854 bytes | 4,000,000 bytes |
| Function definitions | 128 | 256 |
| Peak stack + altstack + definitions | 1,481 entries | 32,768 |
| Peak combined live payload | 234,614 bytes | 8,000,000 bytes |
| Largest element | 4,096 bytes | 4,000,000 bytes |

Script size is 144,905 bytes; packed witness payload is 224,896 bytes. The complete transaction includes all serialization, script, control-block, input and output overhead. Every input participates in GSR, so eligible weight equals transaction weight. The C++ harness independently calculates both weight and budget from the serialized transaction and spent output using Core.

Measured execution performs 9,491 SHA-256 calls over 513,141 input bytes and 26,625 function calls. Semantic field arithmetic expands to 8,667 M31 multiplications, 15,747 M31 additions, 10,562 M31 subtractions and 52 M31 negations. These counts exclude parsing, transcript masking, and other integer operations; emitted opcode counts are reported separately.

The milestone retains Poseidon in the existing offchain recursion pipeline. It verifies the actual `hybrid_hash.bin` and `bitcoin_proof.bin` fixtures, including 273 bound public inputs. Generating application proofs, other proof shapes, and SHA-256 throughout recursion remain outside this milestone.

## Reproduce

Use a 64-bit host with Rust/rustup, Python 3, CMake and a C++20 compiler. This verifier pins Rust nightly 2025-01-02 and Cargo dependencies. From the repository root, initialize the shared Bitcoin submodule and enter this verifier's directory:

```sh
git submodule update --init bitcoin
cd recursive-stwo
bash tools/build.sh
bash tools/test.sh
cargo run --locked -- regtest-demo
```

Run the remaining commands from `recursive-stwo/`. Its source, fixtures, profiles, reports, and generated artifacts are local to this directory. The Bitcoin checkout at `../bitcoin/` and node build at `../build/bitcoin/` are shared across verifiers.

`regtest-demo` uses this verifier's `build/regtest`, RPC port 19452, no P2P listener, and `-vbparams=script_restoration:0:3999999999`. It starts the pinned node if needed, mines activation and coinbase maturity, funds a NUMS Taproot output, calls `testmempoolaccept`, broadcasts locally, and mines the spend. It never connects to mainnet or testnet. Stop that isolated node with:

```sh
../build/bitcoin/bin/bitcoin-cli -regtest -datadir="$PWD/build/regtest" -rpcport=19452 stop
```

Import the original files independently from the pinned public repository and check their digests:

```sh
python3 tools/import-fixtures.py build/imported-fixtures
cargo run --locked -- verify-native build/imported-reference.json \
  build/imported-fixtures/hybrid_hash.bin build/imported-fixtures/bitcoin_proof.bin
```

The default native verification and witness commands use the identical vendored fixtures. Source pins and local adaptations are documented in `vendor/README.md`; fixture hashes are in `fixtures/source-manifest.json`.

## Interfaces

The Rust library exposes `VerifierProfile`, `ProofBundle`, `PreparedWitness`, `CompiledVerifier`, and `CostReport`.

```sh
cargo run --locked -- verify-native       # Native proofs, roots, challenges, queries, public inputs
cargo run --locked -- compile             # Frozen profile -> script, functions, layout, symbols
cargo run --locked -- prepare-witness     # Proof bundle -> packed witness; also build/verifier.json
cargo run --locked -- measure             # Core interpreter, exact transaction budget, costs
cargo run --locked -- regtest-demo        # Uninstrumented standard acceptance and mining
```

`compile` reads only `profiles/bws-v1.json`, and takes no proof. This profile freezes the verifier template, expected circuit commitments, proof shapes and witness layout. The lowering source remains in Rust. `freeze-profile` regenerates the template from the natively validated reference bundle; `tools/test.sh` requires byte-for-byte equality with the checked-in profile.

Witness preparation separately imports and verifies a proof bundle, constructs its hints, and checks that its candidate lowering exactly matches the frozen script and layout. It cannot modify the deployed script to accommodate proof values. Unsupported shapes fail this comparison. The deployed script checks hints itself; native verification is not a substitute for any onchain check. There are no unused proof hints in the lowered relation.

The generic upstream stage builders use symbolic values. The GSR adaptation shares one symbolic context across all 175 original stages. LDM reads reuse the same symbolic IDs instead of introducing witness copies or cross-transaction stack commitments. Delegated values therefore feed the final proof's public-input accumulator directly.

## Script implementation

| Function family | Implementation |
|---|---|
| Field/digest readers | Fixed-length sequential readers; exact section-size checks; four-byte little-endian field coordinates; canonical range checks; no surplus witness |
| M31 arithmetic | Unsigned `OP_MUL`/`OP_MOD`; subtraction computes `(a + p - b) mod p` |
| CM31/QM31 arithmetic | Shared, locally scheduled extension-field routines; original `i² = -1`, `u² = 2 + i` definitions |
| Inverses | Witness hints constrained by multiplication to one |
| Hash serialization | Convert canonical unsigned fields to original signed Script-number byte encodings at hash boundaries; zero is empty; 128 hashes as `8000` |
| SHA-256/transcript/grinding | Original padded SHA-256, absorption order, eight-byte counter, extraction order, and first-u128 grinding check |
| Merkle/delegation | Original opening authentication and delegated SHA-256 relations |
| Plonk/LogUp | Original arithmetic/wiring constraints and bound public-input accumulation |
| Quotients/Circle-FRI | Original opening reductions, folding stages, and final polynomial check |
| Complete verifier | Fixed preprocessed commitments, all obligations, exact witness consumption, exactly `01` on the final stack |

The witness has separate delegation/global/query groups split into elements of at most 4,096 bytes. The compiler uses last-use stack scheduling and deterministic sharing of complete, balanced script fragments. `OP_DEFINE` bodies have fixed IDs 0–127. Bodies contain no `OP_INVOKE`, so the function graph is acyclic. No multiplication lookup tables remain in GSR execution.

The NUMS internal key is Core's `XOnlyPubKey::NUMS_H`, `50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`. The leaf version is `0xc2`; the control byte includes its output-key parity.

## Validation and saved evidence

- Native verification passes for both original proof files with hybrid FRI `(7,9,8)`, final FRI `(0,9,8)`, and grinding 28.
- Four Core-backed primitive tests cover arithmetic boundaries, legacy encodings, extension operations, zero, inverses, transcript extraction and a grinding boundary.
- A diagnostic-only verifier compares **31,605 intermediate outputs** against the pinned native implementation. This includes every quotient and FRI stage. Those reference-value checks are never emitted into the deployed verifier.
- **397 negative cases** reject after witness preparation, including altered roots/openings/nonces/final polynomial/inverse hints, malformed fields and sections, incorrect expected commitments/public inputs, and independently altered delegated values.
- Standard mempool acceptance and mining pass on the original, uninstrumented node at `d2799052604eb138c5a79acf88514a0c8b07f4ef`.

Saved evidence:

- `reports/cost-report.json`: limits, dynamic opcodes, semantic arithmetic, and 175 stage measurements.
- `reports/regtest-acceptance.json`: activation, standard-policy acceptance, mined transaction and block IDs.
- `reports/mined-transaction-execution.json`: instrumented replay of that exact mined transaction and actual budget.
- `reports/spend.hex`: complete mined transaction.
- `reports/negative-tests.json`, `reports/differential.json`: test evidence.
- `reports/optimization-history.json`: initial aggregate measurements and subsequent stage measurements.
- `fixtures/native-reference.json`: roots, transcript challenges, query positions and delegated public inputs.

The harness builds an observationally instrumented **copy** of Core's interpreter in `build/harness`; it does not modify the Bitcoin submodule or node binary. Standard acceptance is independently established by the uninstrumented node. The 400,000 WU limit remains the tightest resource, with 29,613 WU of remaining space for this transaction shape.
