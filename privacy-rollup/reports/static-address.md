# Fixed rollup address with an OP_RETURN state root: measured

Every settlement now pays output 0 to the same Taproot address (`P2TR(NUMS, 1 CSV DROP || suffix)`) and
publishes its new state root at output 1 as `OP_RETURN 0x20 <root>` with value 0. Lineage is recursive
(`reports/lineage.md`), so a coin paid to that address from outside the genuine receipt chain can never settle.

Harness: `tools/lineage_e2e.py` on one patched gsr regtest node (jmoik/bitcoin `gsr` plus
bitcoin/bitcoin#36466), driving `pr-batcher`, apply-batch image `e9b075ff…30f2`. Two escrow deposits of
30,000 sats each mint a 20,000-sat note and pay a 10,000-sat fee; batch 1 spends genesis and sweeps the first,
batch 2 spends batch 1 and sweeps the second. Raw results: `reports/static-address-e2e.json` (the `meter`
key holds the varops measurement of both mined transactions under `gsr-meter` built from the pinned node).

Machine: 8-core Intel Xeon, 31 GiB RAM, `GSR_BUILD_CPU_BATCH=1`, `GSR_CPU_BATCH_LANES=16`, one prover worker.

## Proven and mined settlements

| | batch 1 | batch 2 |
| --- | --- | --- |
| lineage | genesis | receipt (batch 1's `unconditional.bin`) |
| inputs (amount, nSequence) | rollup 100,000 (1), escrow 30,000 (2) | rollup 120,000 (1), escrow 30,000 (2) |
| output 0 | 120,000 to `5120c38c8fc5…9194` | 140,000 to `5120c38c8fc5…9194` (same script) |
| output 1 | `6a20 1fd816ca…c22b`, value 0 | `6a20 abc3d8ca…f54e`, value 0 |
| user cycles | 7,549,263 | 7,338,237 |
| segments | 8 | 8 |
| segment proving | 2,001 s | 1,769 s |
| lift + join | 334 s | 314 s |
| `resolve` of the predecessor | n/a | 20.1 s |
| padded-SHA identity | 18.7 s | 17.7 s |
| batcher wall clock | 2,389 s | 2,154 s |
| seal words | 55,667 | 55,667 |
| mined weight / vsize | 333,251 WU / 83,313 vB | 333,251 WU / 83,313 vB |
| varops (budget) | 1,794,307,640 (3,331,510,000) | 1,794,243,586 (3,331,510,000) |
| unrolled script / peak stack entries / peak payload | 3,361,611 B / 2,652 / 333,534 B | 3,361,611 B / 2,652 / 333,530 B |

Both settlements were mined and confirmed, every `gsr-meter` limit holds, and both depositors' scans recovered
their 20,000-sat notes (leaves 0 and 1). The compressed covenant script is 101,432 bytes.

**Weight:** 333,251 WU against 333,803 WU for the same two-input settlement with a root-specific address
(`reports/lineage.md`): −552 WU measured, although the transaction gains a 43-byte OP_RETURN output (+172 WU).
The covenant no longer reads its own tapscript, replaces the root and derives the successor with `OP_TWEAKADD`.

**Genesis proving:** batch 1 needs 8 segments instead of 14 (`reports/lineage.md`), because
`Frontier::root` now returns `ZERO_HASHES[DEPTH]` for an empty tree instead of hashing it twice.

## Executed (not proven) against batch 2's witness

| case | result |
| --- | --- |
| seal mode with batch 1's `receipt.json` + `seal.bin` | accepted; 30,092,571 cycles, 32 segments; same journal as mined batch 2 |
| receipt mode with batch 1's `unconditional.bin` | accepted; 7,338,237 cycles, 8 segments |
| no predecessor proof | rejected: "the old state is not genesis; a predecessor proof is required" |
| batch 2's own receipt as the predecessor | rejected: "predecessor receipt is for another journal" |
| `old_state.parent` fabricated | rejected: native transition `Lineage` |
| predecessor's output 1 root flipped | rejected: `Lineage` |
| predecessor's output 1 removed | rejected: `Lineage` |
| current output 1 publishes a wrong root | rejected: `RootOutput` |
| current output 1 is not an OP_RETURN | rejected: `RootOutput` |
| output 0 paid to another address | rejected: `RollupScript` |

## Relay, replacement and mining between two patched nodes

Harness: `tools/relay_e2e.py` (two gsr nodes with bitcoin/bitcoin#36466, default relay policy,
`-acceptnonstdtxn=0`), same image. Raw results: `reports/static-address-relay-e2e.json`.

| | settlement A (batcher A) | settlement B (batcher B) |
| --- | --- | --- |
| content | rollup genesis + escrow a | rollup genesis + escrows a, b (conflicts with A) |
| nSequence | `[1, 2]` | `[1, 2, 2]` |
| outputs | 120,000 to `5120c38c8fc5…`, `OP_RETURN 0x20 e3ec7bd7…` | 140,000 to the same `5120c38c8fc5…`, `OP_RETURN 0x20 4f6a49a5…` |
| user cycles / segments | 7,549,098 / 8 | 11,508,419 / 12 |
| segment proving + lift/join | 1,842 s + 318 s | 2,746 s + 500 s |
| weight / vsize / fee | 333,251 WU / 83,313 vB / 10,000 sats | 334,850 WU / 83,713 vB / 20,000 sats |

* A relayed from node A to node B over P2P.
* B relayed to node A and replaced A by ordinary RBF (+10,000 sats against an 8,372-sat incremental
  relay floor; 0.12 → 0.2389 sat/vB). Resending A to node A was rejected: "insufficient fee … less fees than
  conflicting txs".
* With B's escrow-input annex removed, or inflated by 20 kB, the block fails consensus (`OP_EQUALVERIFY` at
  input 1); the honest B is a valid block.
* B was mined with 3 inputs and 2 outputs (rollup + root `OP_RETURN`); both depositors' scans through batcher B
  recovered their 20,000-sat notes (leaves 0 and 1).

Run note: the harness restarts node B after B is broadcast. Batcher B's confirmation poll hit the stopped node
and marked the batch failed although its settlement was already in node A's mempool. `pr-batcher` now keeps
polling through RPC errors once a settlement is broadcast. The scans and B's `confirmed` record above come from
restarting both nodes and batcher B on the same data directories (`resume` found the mined settlement); nothing
was re-proven.
