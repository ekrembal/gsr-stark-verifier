# Rust SDK, batch prover and WASM client

Machine: Intel Xeon Platinum 8375C, 8 vCPU, AVX-512, 31 GiB RAM, no GPU. Every number is measured unless it
is labelled as an estimate. Raw data: [batcher-e2e.json](batcher-e2e.json).

## Components

| Crate / path | What it does |
|---|---|
| `prover/sdk` (`pr-sdk`) | `Wallet` (seed keys, address codec, `deposit`, `transfer`, `scan`), `prove` (local join-split proof + `identity_zk`, returns a `RollupTransaction`), canonical hex transaction codec, `submission`, blocking `Client` for the batcher API. Private witnesses never leave the caller; only `Submission { transaction, funding }` is posted. |
| `prover/src/user.rs`, `prover/src/settle.rs` | user proving (`prove_joinsplit`, `profile_joinsplit`, `verify_joinsplit_receipt`) and settlement proving (`prove_settlement`: segments, lift/join, `resolve_zk` per receipt, padded-SHA wrap), shared by the CLIs, the SDK and the batcher |
| `prover/batcher` (`pr-batcher`) | `init`, `genesis`, `serve`. Admission checks each receipt's ZK seal and that its claim is `ReceiptClaim::ok(JOINSPLIT_ID, public.encode())`; then the operator's mempool rules (nullifiers, anchor, deposit funding). Settlement builds the batch, proves it, assembles the covenant witness, broadcasts (`sendrawtransaction`, or `generateblock` on regtest because the annex is nonstandard), and commits state only after the required confirmations. `inflight.json` lets a restart resume a broadcast settlement. |
| `prover/sdk-wasm` (`pr-sdk-wasm`) | `wasm32-wasip1` CLI over the SDK: `deposit`, `prove`, `profile`, `verify` |
| `prover/web` | static benchmark page: a Web Worker runs the WASI module with `@bjorn3/browser_wasi_shim` 0.4.2 (vendored) in an in-memory `/work` directory and reports per-stage wall time, linear-memory size, device data, and posts results to `/v1/benchmarks` |

HTTP API (`pr-batcher serve <dir> [--web prover/web]`):

| Route | |
|---|---|
| `GET /v1/status` | tip state, anchor, rollup UTXO, pool size |
| `POST /v1/transactions` | `Submission` (8 MiB body limit, receipt ≤ 1 MiB); 400 invalid, 409 conflicting nullifier |
| `GET /v1/notes?from=N`, `GET /v1/paths/{leaf}` | note outputs per batch, membership path against the tip anchor |
| `POST /v1/batches`, `GET /v1/batches[/{n}]` | start a settlement (409 if one is running or the pool is below `--min-transactions`), batch reports |
| `POST /v1/benchmarks`, `GET /v1/benchmarks` | benchmark results from the website (64 KiB limit) |

Bitcoin Core credentials come only from `BITCOIN_RPC_URL` with `BITCOIN_RPC_COOKIE` or
`BITCOIN_RPC_USER`/`BITCOIN_RPC_PASSWORD`.

## End to end on regtest (`tools/batcher_e2e.py`)

One run, private regtest node, this machine. The SDK builds and proves the deposit locally, posts only the
serialized public transaction and its funding coin, and the batcher proves, broadcasts and confirms the settlement.

| Step | Result |
|---|---|
| SDK deposit proof (20,000 sats, fee 700) | 305.7 s: execute 0.11 s, 3 segments (2^20) 248.3 s, lift + join 46.6 s, `identity_zk` 10.7 s, verify 0.05 s; 2,879,757 user cycles; receipt 276,370 bytes |
| Admission rejections | duplicate nullifier 409; corrupted receipt 400 (`control_id mismatch`); non-hex body 400; 9 MiB body 413; unknown batch 404 |
| Settlement (1 transaction) | 1,475.3 s wall: 15 segments 1,186.6 s, lift + join 268.4 s, `resolve_zk` 9.2 s, padded-SHA identity 6.2 s; 14,051,863 user cycles |
| Settlement transaction | mined and confirmed; 392,001 WU, 2 inputs, 1 output, 2,743-byte annex |
| After settlement | wallet scan finds both outputs (19,300 and 0 sats); resubmitting the settled transaction is rejected (`Expired`); after a batcher restart `/v1/status` matches the pre-restart state |


## WASM

`bash prover/sdk-wasm/build.sh` (Rust 1.97, WASI SDK 25) builds the whole prover, including RISC Zero's C++
circuit kernels, for `wasm32-wasip1`: 95,000,198 bytes. Builds for WASM run single-threaded (sequential
`poolstl`, no NVTX, no Unix-socket actor). Only `libc++`/`libc++abi` come from the WASI SDK; libc stays Rust's
self-contained copy.

Wasmtime 36.0.2 on this machine (single thread):

| Run (`profile`, 1 segment) | Segments total | Execute | Prove segment | Lift + join | Wall | Peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| po2 = 14 | 1,593 | 5.1 s | 45.5 s | 220.5 s | 271.2 s | ~1.6 GB |
| po2 = 16 | 121 | 0.6 s | 190.8 s | 215.6 s | 407.1 s | 1.60 GB |
| po2 = 18 | 14 | 0.5 s | 749.4 s | 236.7 s | 986.6 s | 2.57 GB |
| po2 = 20 | 4 | – | fails | – | 134.7 s | 2.95 GB |

The po2 = 14, 16 and 18 runs ran on a shared host (16 and 18 concurrently with each other and with the browser
test), so their times are upper bounds for this machine. po2 = 20 aborts with `capacity overflow` in
`CpuHal::alloc_elem` while committing a poly group: one buffer would exceed the 2 GiB (`isize::MAX`) allocation
limit of a 32-bit target, before the 4 GiB linear-memory cap is reached. wasm32 proving is therefore limited to
segments of at most 2^18 rows here.

`verify` of a submission: 0.42 s, 384 MB RSS. A tampered transaction is rejected with a `control_id` mismatch.
A full `prove` under Wasmtime (an earlier configuration) had proven only its first segment after 25 minutes at
~4.1 GB RSS and was stopped.

Estimate, not measured: a full po2 = 16 proof is 121 segment proofs, 121 lifts and 120 joins; at the per-step
times above (taking a join to cost about one lift) that is roughly 20 hours single-threaded.

## Browser

Chrome 137 on this machine, page served by `pr-batcher serve --web prover/web` against the private regtest node.
Mode `profile`, N = 1, po2 = 16; every value is what the page measured.

| Stage | Desktop | Pixel 7 emulation (no CPU throttling) |
|---|---:|---:|
| WASM compile | 0.20 s | 0.29 s |
| Deposit witness | 0.006 s | 0.007 s |
| Witness check | 0.001 s | 0.001 s |
| Execute guest | 0.72 s | 1.24 s |
| Prove first segment (of 121) | 167.4 s | 322.2 s |
| Lift + join | 238.8 s | 454.2 s |
| Worker total | 407.0 s | 777.7 s |
| WASM linear memory | 1,542,586,368 B | 1,542,586,368 B |

The emulated run uses this machine's CPU with DevTools open; it is not a phone measurement. Both runs posted
their result (HTTP 201) and appeared in the history table. A network capture of page and worker traffic shows
only static files, `/v1/status`, `/v1/benchmarks` GET/POST, and POST bodies containing device data and stage
statistics only: no witness, seed or note secrets.

A full `prove` run in the desktop browser was stopped after 607.6 s without a receipt; the page does not report
per-segment progress, so how far it got is unknown. Full proving in a browser has not been demonstrated.

## Limits

* The settlement transaction carries an annex, which the pinned node's mempool policy rejects; on regtest the
  batcher mines it with `generateblock`. `Broadcast::Send` uses `sendrawtransaction` and is subject to that policy.
* The batcher calls `tools/covenant_cli.py` to build the covenant witness from the receipt template.
* wasm32 linear memory is capped at 4 GiB; the native user proof at the default segment size peaks at
  ~9.7 GB, so WASM proving needs smaller segments, which increases the number of segments and of lift/join steps.
