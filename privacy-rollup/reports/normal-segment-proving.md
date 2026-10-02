# Real settlement proving at the normal segment size

This bounded measurement uses the unpublished fixed-configuration image from
commit `7f7c303`, before the lazy covector follow-up. It proves one selected
segment of a real JoinSplit settlement execution; it is not a complete receipt.

The frozen witness, VK and proof are the same as the execution comparisons.
`encode-witness` computes the expected 196-byte journal using the native state
transition. Full guest execution is checked against those exact bytes before
retaining segments 100 and 101; all other segment memory snapshots are discarded.
The capture has 443,708,894 user cycles, 78,053,212 paging cycles and 15,108,806
reserved cycles: exactly 536,870,912 rows over 512 segments at 2^20 rows each.
The selected index does not by itself identify a verifier phase.

Segment 100 was proved with the direct local RISC Zero prover, dev mode disabled,
four Rayon threads, pinned SDK and the existing hash patch. The resulting
281,128-byte seal passed native integrity verification. Prover timer: 418.2784
seconds; resource supervisor: 418.4921 seconds; sampled peak process-group RSS:
9,590,184 KiB (9.146 GiB). No guard fired, and more than 3.69 GiB disk remained.
The environment has a four-CPU quota and 16 GiB memory limit. Two short Lean
checks and lightweight source/report editing occurred during the proof; no
compilation or other guest execution overlapped it. This is one sample.

At that one-segment rate, 512 segment proofs would take about 59.49 hours,
**before** all lifts, joins and final wrapping. This is a linear extrapolation,
not a measured full-proof time or a feasibility claim. The earlier measurements
at 2^18 show lower per-segment memory but much more paging and many more segments.
Increasing segment size beyond 2^20 would require a separate memory assessment.
No long full-JoinSplit proof was launched.

## Reproduce the bounded experiment

Use the saved binaries in this workspace or rebuild commit `7f7c303` with its
matching cumulative dependency patch. Paths below are relative to repository root:

```sh
source /workspace/.gsr-env/activate.sh
export RAYON_NUM_THREADS=4
export RECURSION_SRC_PATH=/workspace/.gsr-env/recursion_zkr.zip
build/aggregation/fixed-config-baseline/proof_chain_bench encode-witness \
  build/feasibility/fixed-config20 build/aggregation/inputs/witness.json
build/aggregation/fixed-config-baseline/proof_chain_bench capture \
  build/feasibility/fixed-config20 build/aggregation/fixed-config-baseline/apply_batch.bin \
  build/feasibility/fixed-config20/expected-journal.bin 100 2 20 \
  build/feasibility/fixed-config20/witness.pc build/aggregation/inputs/vk.pc \
  build/aggregation/inputs/proof0.pc
python3 privacy-rollup/tools/bounded_command.py \
  --output build/feasibility/fixed-config20-prove100 \
  --seconds 900 --rss-mib 12288 --free-mib 1024 -- \
  build/aggregation/fixed-config-baseline/proof_chain_bench prove \
  build/feasibility/fixed-config20 100
```

Use a new output label to repeat without overwriting evidence. Checkpoints,
commands, hashes and machine-readable resources are recorded in
`bounded-proof-checkpoints.json`; raw files remain under `build/feasibility/`.
A complete real JoinSplit receipt, complete recursive aggregation, final padded
receipt-to-Script validation and the existing soundness/audit gaps remain open.

## Lazy checkpoint measurement

The lazy covector checkpoint `76ae74a` was also captured and a real segment
proved. This precedes the final trait-contract extension for longer MLE points;
the saved guest image is `e15b6136bdab860f53e8fb1e67594652094cdddba790c36f7f4f6af33c72b025`.
All complete-execution journal checks, 40 native tests, nine guest rejection cases
and the fresh operator workflow passed for that checkpoint.

Its capture has 423,237,844 user cycles, 60,307,308 paging cycles, 14,004,160
reserved cycles, and 497,549,312 total rows. There are 475 segments (474.5
full-size equivalents). Segment 100 passed real proving and integrity
verification in 416.3805 seconds (416.5033 supervisor seconds), with a 281,128-byte
seal and sampled peak RSS 9,587,280 KiB. No guard fired. These selected segment
indices are not asserted to cover matching verifier phases across images, so
this is not a controlled comparison of per-phase proving speed.

A row-proportional extrapolation is about 54.88 hours of segment proving before
recursion, from a single measured segment. Even crossing the 500M-cycle goal
therefore has not established practical aggregation on this four-CPU cloud.
The proof/lift/join/padded chain already completed at 2^18 and the complete small
arithmetic guest receipt are documented in `fused-bigint2-feasibility.md`.
Neither is a complete JoinSplit receipt.

The lazy command sequence is the same as above, replacing `fixed-config-baseline`
with `lazy-baseline`, `fixed-config20` with `lazy20`, and capture count 2 with 1.
The resource output label is `build/feasibility/lazy20-prove100`. Its checkpoint,
exact commands, input/receipt hashes and resources are in the JSON report.

The same normal-size partial receipt was lifted and verified in 44.0458 prover
seconds (resource details in the JSON manifest), producing a 222,668-byte
succinct seal. Command: replace `prove` with `lift` in the lazy command and use
resource label `build/feasibility/lazy20-lift100`. This still attests only the
selected segment; no claim of complete execution or joining all 475 segments
is made.
