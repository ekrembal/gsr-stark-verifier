# Rust SDK and batch prover

Machine: Intel Xeon Platinum 8375C, 8 vCPU, AVX-512, 31 GiB RAM, no GPU. Every number is measured unless it
is labelled as an estimate. Raw data: [batcher-e2e.json](batcher-e2e.json).

## Components

| Crate / path | What it does |
|---|---|
| `prover/sdk` (`pr-sdk`) | `Wallet` (seed keys, address codec, `deposit`, `transfer`, `scan`), `prove` (local join-split proof + `identity_zk`, returns a `RollupTransaction`), canonical hex transaction codec, `submission`, blocking `Client` for the batcher API. Private witnesses never leave the caller; only `Submission { transaction, funding }` is posted. |
| `prover/src/user.rs`, `prover/src/settle.rs` | user proving (`prove_joinsplit`, `profile_joinsplit`, `verify_joinsplit_receipt`) and settlement proving (`prove_settlement`: segments, lift/join, `resolve_zk` per receipt, padded-SHA wrap), shared by the CLIs, the SDK and the batcher |
| `prover/batcher` (`pr-batcher`) | `init`, `genesis`, `serve`. Admission checks each receipt's ZK seal and that its claim is `ReceiptClaim::ok(JOINSPLIT_ID, public.encode())`; then the operator's mempool rules (nullifiers, anchor, deposit funding). Settlement builds the batch, proves it, assembles the covenant witness, broadcasts (`sendrawtransaction`, or `generateblock` on regtest because the annex is nonstandard), and commits state only after the required confirmations. `inflight.json` lets a restart resume a broadcast settlement. |

HTTP API (`pr-batcher serve <dir>`):

| Route | |
|---|---|
| `GET /v1/status` | tip state, anchor, rollup UTXO, pool size |
| `POST /v1/transactions` | `Submission` (8 MiB body limit, receipt ≤ 1 MiB); 400 invalid, 409 conflicting nullifier |
| `GET /v1/notes?from=N`, `GET /v1/paths/{leaf}` | note outputs per batch, membership path against the tip anchor |
| `POST /v1/batches`, `GET /v1/batches[/{n}]` | start a settlement (409 if one is running or the pool is below `--min-transactions`), batch reports |

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

## Limits

* The settlement transaction carries an annex, which the pinned node's mempool policy rejects; on regtest the
  batcher mines it with `generateblock`. `Broadcast::Send` uses `sendrawtransaction` and is subject to that policy.
* The batcher calls `tools/covenant_cli.py` to build the covenant witness from the receipt template.
