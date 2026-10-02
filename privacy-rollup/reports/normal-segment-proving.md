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
