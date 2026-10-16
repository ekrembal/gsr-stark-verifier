# P1: deposit, shielded transfer and withdrawal batches mined on the optimized `gsr` node

`tools/flows_e2e.py` run against `bitcoin/` = `jmoik/bitcoin` branch `gsr` (built with `-DENABLE_IPC=OFF`), regtest
with `-vbparams=tapleaf_0xc2:0:3999999999`, SDK wallets -> `pr-batcher` HTTP -> settlement proof -> mined block.
Raw report: [`p1-flows-e2e.json`](p1-flows-e2e.json). Machine: 8 vCPU, CPU prover. All numbers are measured in
this run.

| step | wall | settlement weight | annex | inputs / outputs |
|---|---:|---:|---:|---:|
| batch 1: empty settlement | 155.0 s | 331,699 WU | 151 B | 1 / 1 |
| user proof: deposit A (3 segments) | 346.1 s | | | |
| user proof: deposit B (3 segments) | 327.0 s | | | |
| batch 2: two deposits (batch deposit) | 1,815.6 s | 337,219 WU | 5,335 B | 3 / 1 |
| user proof: transfer A -> B (7 segments) | 761.5 s | | | |
| user proof: withdrawal by B (7 segments) | 717.1 s | | | |
| batch 3: transfer + withdrawal (mixed batch) | 1,710.4 s | 337,057 WU | 5,335 B | 1 / 2 |

Settlement proof breakdown (seconds):

| batch | segments | guest cycles (total / user) | segment proving | lift + join | `resolve_zk` | padded-SHA identity |
|---|---:|---:|---:|---:|---:|---:|
| 1 (0 tx) | 1 | 131,072 / 38,799 | 12.0 | 9.8 | 0 | 6.7 |
| 2 (2 deposits) | 16 | 16,252,928 / 15,119,258 | 1,321.6 | 327.2 | 19.0 | 6.4 |
| 3 (transfer + withdrawal) | 16 | 16,252,928 / 15,245,836 | 1,269.6 | 301.4 | 18.7 | 6.2 |

User receipts are 276,194–276,363 B. A spend (transfer or withdrawal) proves the input-note Merkle paths and runs
7 segments, against 3 for a deposit.

Weight: each of the two join-splits adds ≈2.76 k WU over the empty settlement ((337,219 − 331,699) / 2), almost all
of it the two 1,232-byte ML-KEM ciphertexts per transaction (P3 makes self/change ciphertexts compact). Proving time
is dominated by the commitment and nullifier tree updates in the settlement guest (≈7.5 M user cycles per
join-split), not by `resolve_zk` (≈9.5 s per receipt).

Also checked in the same run: the withdrawal output (5,000 sats to the declared P2WSH script) is in the batch-3
settlement; both wallets' scans find exactly their notes (A: 0 and 10,800 change; B: 8,000 received and 8,700
change); resubmitting A's settled deposit is rejected (400, `Expired`: its expiry batch has passed, and its
nullifiers are spent); the batcher state is identical after a restart.

Run note: the first pass of this run mined all three batches and then stopped at a wrong expectation in the script
(A's transfer has no zero-value output); the script was fixed and the post-settlement checks (scans, replay, restart)
were rerun against the same node and batcher state.

Funding still uses regtest `P2WSH(OP_TRUE)` coins, which are not safe on a public network (replaced in P2b).
