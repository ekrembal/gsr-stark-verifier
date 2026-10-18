# gsr-privacy-pool in one page

> Research code, not audited and not for production. No external review has taken place.

**What it is.** gsr-privacy-pool is a shielded BTC pool on Bitcoin with the GSR soft fork (Tapscript v2
leaf version `0xc2`, `OP_TX`). The whole pool is one Taproot output. Users hold private notes inside it and
move them with join-split transactions that hide who paid whom and how much. Nobody holds keys to the pool:
it can only be spent by a transaction that carries a valid zero-knowledge proof of its own correctness.

**How a payment works.**

1. **The user proves locally.** The wallet builds a 2-input/2-output join-split: it spends up to two notes
   and creates two new ones, keeping value balanced. It proves this in a small RISC Zero program and wraps
   the proof in a zero-knowledge receipt (about 276 KB). Only the public statement leaves the device:
   nullifiers, new note commitments, encrypted notes, and any public deposit, withdrawal and fee amounts.
2. **A batcher aggregates.** Anyone can run a batcher. It collects up to 16 user receipts, runs the
   `apply_batch` program, which checks each receipt (`env::verify`, discharged by `resolve_zk`) and updates
   the pool's trees, and proves the whole batch as one receipt.
3. **Bitcoin verifies.** The settlement transaction spends the pool output and creates its successor. The
   pool's script is a complete STARK verifier in Bitcoin Script. It checks the receipt, and uses `OP_TX` to
   check that the receipt was about exactly this transaction: its inputs, outputs and annex. The annex
   carries the batch data (nullifiers, commitments, ciphertexts), so anyone can rebuild the pool's state from
   the chain.

**Deposits, transfers, withdrawals.**
- **Deposit:** pay BTC into the pool and get a private note. Either prove a deposit join-split, or, with no
  proof at all, pay any wallet's output to a *deposit address*. A batcher sweeps it into the pool and mints
  the note; if no one does, the depositor refunds after a timelock.
- **Transfer:** spend notes to a recipient's note. Amounts and parties stay hidden.
- **Withdrawal:** spend notes to up to four ordinary Bitcoin outputs per join-split.

**Why copies and races don't break it.**
- **Covenant copies:** a pool is defined by its genesis coin. Each settlement proves its coin descends from
  that genesis, so a copy of the script can never be spent, and deposit addresses can only be swept by the
  real pool.
- **Double spends:** every note has a nullifier, and the pool tracks spent nullifiers in a Merkle tree.
- **Competing batchers:** at most one settlement per block (`1 CSV`). The loser re-batches its users, whose
  proofs stay valid because old tree roots (anchors) never expire.
- **Fees:** each user pays `fee_sats`, fixed in their proof, all to the miner. To bump, a user re-proves with a
  higher fee and the next batch replaces the old one (RBF); there is no CPFP, so no address is linked.
- **No pinning:** nothing in a pending settlement is spendable: withdrawals and the successor are `1 CSV`
  locked and there are no change, reward or anchor outputs. A withdrawal recipient spends one block later.

**Measured (8-vCPU CPU machine, regtest on the `gsr` node).**

| | |
|---|---:|
| User deposit proof | 170–190 s |
| 3-deposit settlement, batch to confirmed | 640 s |
| Settlement weight, empty / 3 deposits | 331,699 / 333,485 WU |
| Extra weight per deposit | 538–595 WU |
| Settlement proving, 16 transfers (segments + lift/join only) | 1,245 s |

The pool needs about 332k of the 400k WU a standard transaction may weigh, almost all of it for the
verifier, so fees per user fall with batch size. At 10 sat/vB a 16-transfer batch costs about 56,000 sats per
user (estimate).

**What's not done.**
- **Privacy assumption:** privacy rests on a zero-knowledge mode we added to RISC Zero. It is argued to be
  statistically zero-knowledge in a proof sketch that has not been reviewed.
- **Relay:** settlements carry an annex, so today's nodes reject them and they go directly to miners. With the
  open annex-relay proposal bitcoin/bitcoin#36466 applied, a real settlement relayed between two nodes and was
  replaced by a bigger one through ordinary RBF (`reports/relay-pinning.md`); that proposal is not merged.
- **Wider testing:** only one machine and regtest so far; there's no mainnet or signet deployment.

The full design is in the [whitepaper](whitepaper.md).
