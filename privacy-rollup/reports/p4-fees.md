# P4: fee policy, reward / CPFP anchor, direct-to-miner submission, conflicts and adoption

Run: `tools/p4_e2e.py` on the optimized `gsr` node (jmoik/bitcoin `gsr`, `-vbparams=tapleaf_0xc2:0:3999999999`,
`-acceptnonstdtxn=1`, relay/mining floors 0.1 sat/vB), SDK wallets -> `pr-batcher` HTTP -> settlement proof ->
submitted with `sendrawtransaction` / `submitpackage` to the miner node (`--submit-url`). 8 vCPU machine, CPU
prover (`GSR_BUILD_CPU_BATCH=1`). Raw output: [p4-e2e.json](p4-e2e.json). All numbers below are measured unless
marked as an estimate. The policy itself is specified in [spec/protocol.md](../spec/protocol.md#fee-policy-batcher-not-consensus).

## What changed

* `prover/batcher/src/fees.rs`: `quote`, `admission_floor`, `plan` (shortfall or `FeePlan {miner_fee, reward}`),
  `SettlePolicy` (min / target transactions, fullness, fee coverage, max wait).
* `pr-batcher serve`: `--fee-rate` or `--fee-target`/`--fee-floor` (`estimatesmartfee`), `--reward-script` or
  `PR_BATCHER_REWARD_KEY` (BIP86 key; reward script derived), `--target-transactions`, `--max-wait`, `--auto`,
  `--submit-url`. New endpoints `GET /v1/fees`, `POST /v1/bump`.
* `prover/batcher/src/cpfp.rs`: BIP86 key-path signer for the 1-in/1-out reward child (BIP341 sighash,
  `SIGHASH_DEFAULT`), so CPFP works on the `gsr` node, which is built without a wallet.
* Conflicts: funding coins and escrows re-checked (`gettxout`, mempool included) before proving and before every
  broadcast; a spent one drops its pool transaction and abandons the proven settlement. A rollup output spent by a
  confirmed transaction that is not ours is decoded, checked (`Store::accept`) and adopted.
* `Store::select` exposes the operator's weight-bounded selection so the batcher prices exactly what it will prove.

## End-to-end run (measured, regtest at 0.1 sat/vB)

| Step | Result |
|---|---|
| `GET /v1/fees` (target 3 transactions) | shared verifier share 2,767 sats; deposit 2,792, transfer 2,809, withdrawal 2,790 sats |
| Deposit paying 1 sat | rejected at admission (400), nothing pooled |
| Two deposits paying 3,192 sats each | `POST /v1/batches` -> 409 `fees 6384 do not cover the settlement: 8349 required at 0.1 sat/vB`; nothing proven |
| Four deposits (user proofs 305-351 s each, 276 KB receipts) | pool `ready`: fees 12,768 >= 8,403 required |
| Settlement A (4 deposits) | proven: 18 segments, 18,874,368 cycles, 1,731.8 s segment proving, 416.2 s lift + join, 48.5 s `resolve_zk`; 334,022 WU |
| Depositor double-spends its funding coin while A is proving | A abandoned at the pre-broadcast check after 2,337.4 s; the depositor's pool entry dropped |
| Settlement B (remaining 3 deposits), re-proven | 17 segments, 17,825,792 cycles, 2,101.1 s wall; 333,485 WU (83,372 vB); miner fee 8,378 sats (0.1005 sat/vB), reward output 1,198 sats |
| Submission | B sent with `sendrawtransaction` to the miner node (`--submit-url`) |
| `POST /v1/bump` at 0.1056 sat/vB | 111 vB child spending the reward output, fee 434 sats, accepted by `submitpackage`; package 8,812 sats / 83,483 vB |
| Mining | one block contains B, the CPFP child and the double-spend |
| Second batcher (state copied from before B) | saw the rollup output spent, decoded B, `adopted settlement … made by another operator`; its state equals the first batcher's |

The run proves the conflict path end to end: the double-spend cost the batcher one wasted proof (2,337 s), the
depositor lost nothing but their admission slot, and the other three users were settled in the next proof.

## Findings

* **Fee coverage is conservative.** The batcher priced settlement A at 336,084 WU and B at 335,106 WU; the
  transactions weigh 334,022 and 333,485 WU. `entry_weight` charges about 978 WU per deposit while a deposit adds
  537 WU to the transaction (334,022 - 333,485). Users therefore overpay slightly; the miner never gets less than
  the quoted feerate.
* **The `TYPICAL_*_WEIGHT` constants in the quote are estimates** (deposit 1,000, transfer 1,650, withdrawal
  900 WU); admission uses the exact `entry_weight` of the submitted transaction.
* **RBF is not possible** and is not attempted: the proof commits every input and output, so the fee is fixed.
  A higher fee means CPFP through the reward output (bounded by the reward value minus dust) or proving again.
* **Pinning via funding coins costs the batcher one proof**, not the honest users. P2b escrows (confirmed coins
  that only the rollup can sweep before the refund delay) remove it for depositors who use them; the re-check
  before broadcast still covers refunds racing a sweep.
* **Cost per user (estimate):** at 0.1 sat/vB a 3-deposit batch costs about 2,800 sats each; at 10 sat/vB the
  same batch would cost about 280,000 sats each, and 16 transfers about 56,000 sats each (`quote`), so batch size
  dominates fees.
