# Packed BabyBear kernels in Tapscript v2

Reproduces section 5 of [`../../../risc0-verifier-sizing.md`](../../../risc0-verifier-sizing.md).
Every kernel is emitted as real Script, run in the pinned interpreter through `bitcoin-util
evalscript`, and its output compared exactly with a Python emulation that is itself checked against
scalar BabyBear arithmetic (and, for the extension, against schoolbook multiplication modulo
`x^4 + 11`). Costs are marginal: each kernel is chained `n` times and the cost of `n = 1` is
subtracted from `n = 2`, so setup and final checks are not counted.

- `gsr_script.py` — a minimal assembler and the interpreter runner.
- `packed_kernels.py`, `kernels.txt` — packed extension arithmetic (four 96-bit lanes), 50-lane and
  22-lane query vectors, lane-wise Barrett reduction built from `OP_AND`/`OP_RSHIFT`/`OP_MUL`/`OP_SUB`
  (`OP_MULTI` has no multiply or modulo), witness-hinted equality with negative cases, lane
  extraction and insertion, and the `OP_INVOKE` overhead of a defined `ext_mul`. Worst-case lane
  bounds are asserted for every Barrett instance and for the largest admissible extension inputs.
- `transpose.py`, `transpose.txt` — rearranges 50 query rows of 179 (DEEP-ALI) and 371 (DEEP-ALI
  plus all three FRI rounds) seal words into 12-byte-lane query vectors: pad and concatenate, six
  delta-swap stages of a 64x64 word transpose with masks built in Script, split, and spread.
- `project.py`, `projection.txt` — composes the metered kernels with the measured operation counts
  into a projection of an optimised verifier. Rows marked `est` use an unmetered unit price.

```sh
# from the repository root; the interpreter must include bitcoin-util
cmake -S bitcoin -B build/bitcoin -DBUILD_UTIL=ON -DBUILD_GUI=OFF -DBUILD_TESTS=OFF \
  -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DENABLE_WALLET=OFF -DWITH_ZMQ=OFF -DENABLE_IPC=OFF
cmake --build build/bitcoin --target bitcoin-util --parallel 8
cd research/risc0/kernels
python3 packed_kernels.py > kernels.txt
python3 transpose.py > transpose.txt
python3 project.py > projection.txt
```
