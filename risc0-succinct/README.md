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

Needs Python 3, Rust (RISC Zero's toolchain), CMake and a C++20 compiler. Build the shared pinned node and meter as in [recursive-stwo](../recursive-stwo/README.md) (`bash recursive-stwo/tools/build.sh`, which builds `build/bitcoin` and `recursive-stwo/build/harness/gsr-meter`). Then, for the native side, check out RISC Zero v3.0.6 (`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`) at `~/risc0` (or set `RISC0_DIR`) and apply [risc0-v3.0.6.patch](risc0-v3.0.6.patch), which adds the `sha-256-padded` suite, the `GSR_TRACE` instrumentation, and the `gsr_verify_file` test used as the native oracle.

```sh
cd risc0-succinct/tools
python3 generate.py        # fixtures -> build/bundle.json (script + witness)
python3 measure.py         # complete Taproot spend in gsr-meter -> build/cost-report.json
python3 differential.py    # native / reference / Script, valid and negative cases
python3 ../../recursive-stwo/tools/regtest-demo.py <bundle with script_sha256>   # mine on activated regtest
```

`tools/test.sh` runs the first three. `fixtures/seal.bin` and `fixtures/receipt.json` were produced by the patched `gsr_measure` test with `R0_GSR_SEAL_DIR` set; `fixtures/circuit.json` by `tools/extract-circuit.py` from RISC Zero's generated circuit sources.

## Scope

This verifies one succinct receipt shape: the recursion circuit at `po2` 18, fixed control ID and root, and the padded hash suite. RISC Zero does not ship `sha-256-padded`; the patch adds it without changing the recursion circuit, so a prover must use the patched suite to produce receipts this Script accepts. Another statement needs a regenerated Script. The FRI configuration gives about 97 conjectured bits of security, as in stock RISC Zero. This is unaudited research code.
