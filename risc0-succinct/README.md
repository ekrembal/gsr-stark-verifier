# RISC Zero succinct receipt verifier on GSR

Part of the [GSR ZKP verifiers collection](../README.md). A Tapscript v2 verifier for a RISC Zero v3.0.6 succinct receipt (`RECURSION:rev1v1`, `RISC0_STARK:v1__`), proven under a padded SHA-256 hash suite so that every Merkle and transcript digest is reproducible with `OP_CAT`/`OP_SHA256`.

The pinned receipt verifies in **one standard Tapscript v2 spend**. The uninstrumented GSR node at `d2799052604eb138c5a79acf88514a0c8b07f4ef` accepted the spend with `testmempoolaccept` and mined it on activated regtest ([evidence](reports/regtest-acceptance.json)). No consensus limits, policy limits, FRI parameters or query counts were changed: 50 queries, inverse rate 4, fold factor 16, `po2` 18.

| Measurement | Result | Limit |
|---|---:|---:|
| Transaction weight | 388,398 WU | 400,000 WU |
| Varops | 2,083,395,104 | 3,883,980,000 for this transaction |
| Cumulative invoked function bodies | 3,231,577 bytes | 4,000,000 bytes |
| Function definitions | 14 | 256 |
| Peak stack + altstack + definitions | 2,666 entries | 32,768 |
| Peak combined live payload | 347,208 bytes | 8,000,000 bytes |
| Largest element | 16,384 bytes | 4,000,000 bytes |
| Top-level OP_SUCCESSx opcodes | none | none |

Script size is 158,572 bytes; the witness is 762 items and 227,724 bytes (the 222,668-byte seal, 4,800 bytes of per-query DEEP quotient hints and the 256-byte control-ID inclusion path). The measurement is of the complete serialized transaction; Core derives weight and the varops budget (10,000 × eligible weight) itself. Execution performs 4,712 SHA-256 calls over 364,876 input bytes and 15,553 function calls. Full report: [reports/cost-report.json](reports/cost-report.json).

## What the Script checks

The Script is specialized to one statement — control ID, control root, inner control root and claim digest are constants — and to the extracted recursion circuit (643 taps, 12,359-step `poly_ext`). Within that, it performs RISC Zero's complete `verify_integrity` path:

- Transcript: padded-SHA-256 Fiat–Shamir, identical to `ShaRng` over `Sha256Padded`; every seal field word is range-checked `< P`.
- Output and `po2`: as in native `SuccinctReceipt::verify_integrity`, the even words of output slot 0 must equal the (inner) control root and the 16 half-words of slot 1 must equal the expected claim digest, which commits to the journal, successful termination (`sys_exit` = `user_exit` = 0) and empty assumptions; `po2` must be 18.
- Code, data, accum and check Merkle tops; the code root must equal the control ID, and the control ID's inclusion path must reach the control root.
- Constraint evaluation: the generated `poly_ext` program at the DEEP point, combined with `poly_mix`, must equal the check polynomial times the vanishing factor.
- 50 queries: query indices from the transcript; Merkle authentication of four trace rows and three FRI layers; DEEP-ALI combination; three fold-by-16 FRI rounds; final degree-64 polynomial evaluation.
- Exact consumption: every witness item has an exact size, and the Script ends with exactly one `1` on the stack (cleanstack).

The DEEP quotient hints are untrusted: for each query and each tap combination `c` the Script checks `hint_c · D_c(x) = tot_c(x) − U_c(x)`, where `D_c` is the product of `(x − z·ωᵇ)` over the combination's backs, and range-checks every hint word, so a wrong or noncanonical hint is rejected. This replaces per-query field inversions by multiplications.

### Packed arithmetic

BabyBear extension elements are held as one integer with four 96-bit lanes. Extension multiplication is one `OP_MUL` plus a lane-wise reduction `x − 11·hi + K` (K a multiple of P larger than any subtracted value) and a lane-wise Barrett step. The generator tracks an upper bound for every value and inserts reductions only when a bound would exceed a limit; if any bound would exceed the Barrett range (lanes < 2⁷⁸) generation fails with an assertion, so every emitted reduction runs within its proven range:

- Barrett with `m = ⌊2ᵇⁱᵗˢ/P⌋`, `t = ⌊x/2³⁰⌋`, `q = ⌊t·m/2ᵇⁱᵗˢ⁻³⁰⌋` satisfies `x/P − 2.54 < q ≤ x/P`, so `x − qP ∈ [0, 4P)` with no borrow between lanes. `(bits − 30) + bitlen(m) ≤ 96` for all widths 36–78, so `t·m` never carries into the next lane.
- Extension-multiply inputs are `< 2³⁵` per lane, so each product coefficient is `< 4·2⁷⁰ = 2⁷²`; base × extension products are kept `< 2⁷²`; sums are asserted `< 2⁷⁸`; subtraction adds a multiple of P no smaller than the subtrahend's bound.

## Validation

`tools/differential.py` runs three independent verifiers on every case: RISC Zero's native `verify_integrity_with_context` (patched checkout, below), the Python reference verifier `tools/reference.py`, and the generated Script in the complete Taproot transaction under the pinned interpreter. Results: [reports/differential.txt](reports/differential.txt).

- The valid receipt is accepted by all three, and 264 intermediate values (output, mix, `poly_mix`, DEEP point, constraint result, check polynomial, FRI mixes, 50 query positions and every FRI goal) match the native verifier's trace exactly.
- 34 negative cases are rejected by all applicable verifiers: tampered output, `po2`, code top, coefficients, FRI top, final polynomial, trace row, trace path and FRI path; noncanonical and `0xffffffff` field words; truncated, surplus and unaligned seals; control ID, control root, inner control root, claim digest, inclusion index and path, journal, nonzero system and user exit codes, nonempty assumptions; circuit info, proof-system info and hash suite; surplus, missing and empty witness; flipped and noncanonical DEEP hints.

## Reproduce

Needs Python 3, Rust (RISC Zero's toolchain), CMake and a C++20 compiler. Build the shared pinned node and meter as in [recursive-stwo](../recursive-stwo/README.md) (`bash recursive-stwo/tools/build.sh`, which builds `build/bitcoin` and `recursive-stwo/build/harness/gsr-meter`). Then, for the native side, check out RISC Zero v3.0.6 (`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`) at `~/risc0` (or set `RISC0_DIR`) and apply [risc0-v3.0.6.patch](risc0-v3.0.6.patch), which adds the `sha-256-padded` suite, the `GSR_TRACE` instrumentation, the `gsr_verify_file` test used as the native oracle, the `gsr_covenant` demo guest with its `gsr_covenant_prove` test, and `recursion::identity_sha256_padded`, the host API the [privacy rollup](../privacy-rollup/README.md) prover uses to re-prove a succinct receipt under the padded suite.

```sh
cd risc0-succinct/tools
python3 generate.py        # fixtures -> build/bundle.json (script + witness)
python3 measure.py         # complete Taproot spend in gsr-meter -> build/cost-report.json
python3 differential.py    # native / reference / Script, valid and negative cases
python3 ../../recursive-stwo/tools/regtest-demo.py <bundle with script_sha256>   # mine on activated regtest
```

`tools/test.sh` runs the first three. `fixtures/seal.bin` and `fixtures/receipt.json` were produced by the patched `gsr_measure` test with `R0_GSR_SEAL_DIR` set; `fixtures/circuit.json` by `tools/extract-circuit.py` from RISC Zero's generated circuit sources.

## Covenant demo: a UTXO only a STARK proof can spend

`tools/covenant.py` builds a Taproot output whose only spending path is a Script that verifies a receipt of the demo guest `gsr_covenant` (added by the patch, image ID `bb06f6ecf52a330b78d4ce2298247f1568d50c27e959f394f30b0c9b92b2d05b`) and forces the spending transaction's outputs to be exactly the guest's journal.

- **Guest.** It reads a secret and a byte string, asserts `SHA256(secret)` equals a constant lock, checks the byte string parses as a list of Bitcoin outputs with minimal CompactSize lengths (the encoding `OP_TX` produces, so every receipt it issues has a spendable journal), and commits it as the journal. The journal format is BIP 341's `sha_outputs` preimage: for each output, `value` (u64 LE) ‖ compact-size length ‖ `scriptPubKey`. Only a prover who knows the secret gets a receipt, and the receipt fixes where the coins go.
- **Claim from the journal.** The Script recomputes RISC Zero's claim digest, `tagged_struct("risc0.ReceiptClaim", [input, image_id, post, tagged_struct("risc0.Output", [SHA256(journal), assumptions])], [0, 0])`, with image ID, input, post-state, zero assumptions and exit code 0 as constants. It then requires output slot 1 of the seal to equal that digest. A different journal gives a different claim, which the STARK does not prove.
- **Journal bound to the transaction.** The Script does not take the journal from the witness. It reads the spending transaction's outputs with `OP_TX` (selector `00 01 00 02 00 03`: collate, all outputs, amount and scriptPubKey), which yields exactly this serialization, and uses the result as the journal. A transaction with any other outputs, including an extra, missing or reordered one, gives a different claim digest, which the receipt does not prove.

Measured spend (complete transaction, [reports/covenant.json](reports/covenant.json)): 388,641 WU; 2,085,001,847 of 3,886,410,000 varops; 158,815-byte Script; 762 witness items (the same as the fixed-statement verifier); 4,715 SHA-256 calls; 3,231,577 invoked function-body bytes; peak 2,666 entries; all limits pass. The covenant adds 243 WU and 1.6M varops to the fixed-statement verifier. On activated regtest the pinned node accepted the spend to the journal's output and mined it, and rejected the same proof spending to an output 1 sat smaller.

RISC Zero's native verifier and the Python reference accept the receipt, and native rejects it with a different journal. In the complete transaction, the Script rejects:

| Case | Rejected by |
|---|---|
| Output value 1 sat smaller | claim digest |
| Output to another scriptPubKey | claim digest |
| Extra `OP_RETURN` output appended | claim digest |
| Value split over two outputs | claim digest |
| Valid receipt of another image (the busy-loop fixture) | claim digest |
| Tampered seal | STARK verification |

Reproduce, with the patched RISC Zero checkout:

```sh
cd ~/risc0   # writes covenant-receipt.json / covenant-seal.bin
R0_GSR_SEAL_DIR=<dir> R0_GSR_COVENANT_SECRET=$(printf 'gsr covenant demo secret' | xxd -p | tr -d '\n') \
R0_GSR_COVENANT_OUTPUTS=c0e4022a01000000225120ebbb8193d78204bf6880fed5bd735d42d1e5abfb1be2f3acd8b190172cb2cc92 \
  cargo test --release -p risc0-zkvm --features prove --lib gsr_covenant_prove -- --include-ignored --nocapture
cd risc0-succinct/tools
python3 covenant.py --regtest   # generate, meter, negative cases, fund/accept/mine on regtest
```

The outputs above pay 49.998 BTC to a key-path P2TR address derived from `SHA256("gsr covenant demo destination")`. Changing the destination needs a new proof but not a new Script; changing the guest needs a new Script. The transaction's inputs, version, locktime and sequences are not restricted by the journal, only its outputs.

## Scope

This verifies one succinct receipt shape: the recursion circuit at `po2` 18, fixed control ID and root, and the padded hash suite. RISC Zero does not ship `sha-256-padded`; the patch adds it without changing the recursion circuit, so a prover must use the patched suite to produce receipts this Script accepts. Another statement needs a regenerated Script (in the covenant mode, another image ID). The FRI configuration gives about 97 conjectured bits of security, as in stock RISC Zero. This is unaudited research code.
