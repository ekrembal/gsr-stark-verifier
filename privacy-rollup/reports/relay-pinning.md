# Relay, replacement and pinning under bitcoin/bitcoin#36466

Everything here runs on the gsr node (jmoik/bitcoin `gsr`) with the commits of the open, unmerged
annex-relay PR bitcoin/bitcoin#36466 (`refs/pull/36466/head` at `b4179ad2`) applied. None of it holds on
an unpatched node, whose policy rejects every annex.

Two harnesses:

* `tools/policy/gsrpp_relay_pinning.py` (a Bitcoin Core functional test; copy it into
  `test/functional/` of the patched tree) uses stand-in settlements: a P2TR coin with a NUMS key and an
  `OP_1 OP_CHECKSEQUENCEVERIFY` leaf, padded by its input-0 annex to the weight of a real settlement.
  Policy depends only on size, fee, version, annexes and topology, so these measure policy; they do not
  run the GSR verifier. Results: `reports/relay-pinning-synthetic.json`.
* `tools/relay_e2e.py` relays and replaces real, proven settlements between two patched nodes.
  Results: `reports/relay-e2e.json` (summarised below).

Two size regimes are measured with the stand-ins: "current" (84,407 vB, the size of today's settlement)
and "target" (5,482 vB, a stand-in for a small future verifier; that size is an assumption, not a
measured verifier).

## Annex encoding

| annex | patched-node policy |
| --- | --- |
| `50 'GSRP' ...` (the previous encoding) | rejected, `bad-witness-nonstandard` |
| `50 00 'GSRP' ...` (new encoding) | accepted |
| marker-only `50` | accepted |
| `50 01 ...` (reserved prefix) | rejected |

So the annex now starts `0x50 0x00` (`ANNEX_UNSTRUCTURED`); an empty-batch annex grows from 152 to 153 bytes.

## Every non-P2A input needs an annex

| inputs | policy |
| --- | --- |
| rollup (annex) + taproot input without annex | rejected |
| rollup (annex) + taproot input with marker `50` | accepted |
| rollup (annex) + P2WSH input | rejected |
| rollup (annex) + taproot input with a 20 kB `50 00` annex | accepted |

Consequences in the code:

* escrow sweeps carry the marker annex `50` (`prover/batcher/src/service.rs`, `tools/deposit_escrow.py`);
* the sweep leaf now also checks, with `OP_TX` selector `00 00 02 00 00 00` (current input's annex),
  that its own annex is exactly `50`. Without that check a relayer could swap in a 20 kB annex (last
  row): same txid, lower feerate. `deposit_escrow.py node-test` rejects both a missing and a 20 kB
  escrow annex at consensus. The check adds 11 bytes to the sweep body (569 bytes for the real template);
* interactive deposits funded from non-taproot coins (P2WPKH, P2WSH) cannot be relayed with a settlement.
  They still work through direct miner submission; for public relay, deposits should be escrows.

## Growing batches replace each other by ordinary RBF

Each settlement's successor output commits to its new state root, so a bigger batch has a different
txid and replaces the smaller one under the full-RBF and cluster-mempool rules, starting at 5 sat/vB:

| regime | old vB / fee | +1 transfer vB | minimum new fee | minimum delta | binding rule |
| --- | --- | --- | --- | --- | --- |
| current | 84,407 / 422,035 | 84,778 | 430,513 | 8,478 | incremental relay fee (0.1 sat/vB × new size) |
| target | 5,482 / 27,410 | 5,853 | 29,263 | 1,853 | feerate-diagram improvement |

In the target regime, "old fee + incremental fee" is rejected (`does not improve feerate diagram`): the
replacement must also not lower the feerate. A batch therefore grows only when the added transfers pay
at least the batch's feerate, and each relay of a ~0.34 MB (current) or ~23 kB (target) transaction costs
at least the minimum delta. Five consecutive replacements relayed in each regime.

## Pinning

| parent | child | replacement minimum (unpinned → pinned) |
| --- | --- | --- |
| current, v2 | 16,543 vB at 1 sat/vB (cluster limit) | 430,513 → 447,056 (+16,543) |
| current, v3 (TRUC) | — | parent rejected: 84,407 > 10,000 vB TRUC limit |
| target, v2 | 95,468 vB at 1 sat/vB (cluster limit) | 29,263 → 123,464 (+94,201) |
| target, v3 (TRUC) | 1,000 vB (1,001 vB and v2 children rejected) | 29,263 → 29,263 (+0) |

Any spendable output of an unconfirmed settlement (withdrawal, change, P2A) lets its owner attach a
child. A non-TRUC settlement can be pinned for up to the remaining cluster size × feerate; the smaller
the verifier, the larger the pin. A TRUC settlement removes the pin in these runs, but needs the whole
settlement under 10,000 vB (40,000 WU), which today's ~83 kvB settlement is far from.

## P2A

| case | policy |
| --- | --- |
| fee-paying v3 parent with a 0-sat or 239-sat P2A | rejected (`dust`) |
| fee-paying v3 parent with a 240-sat P2A | accepted |
| zero-fee v3 parent with a 0-sat P2A, alone | rejected (`min relay fee not met`) |
| third-party CPFP through the P2A (child 145 vB) | accepted |
| recipient child after a P2A child (sibling eviction) | accepted |
| v2 parent, 90 kvB 1 sat/vB child on the P2A | accepted; replacement minimum 29,263 → 118,005 |

A P2A on a settlement that pays its own fee must hold 240 sats, and on a non-TRUC settlement it is one
more pinning handle. On a TRUC settlement it is harmless to miners' choice (one ≤1,000 vB child, which
sibling eviction can replace). It stays optional and off by default; fees are raised by re-proving.

## Secondary-input annex inflation (stand-in)

With an escrow-like input whose annex is unconstrained, the honest (5,482 vB) and inflated (20,483 vB)
versions share a txid. Whichever arrives first stays (`txn-same-nonwitness-data-in-mempool`); both
nodes end with the same wtxid. The inflated version pays the same fee at a ~3.7× lower feerate, so an
attacker can delay a settlement until someone re-proves a replacement. The sweep-leaf annex check above
removes this for escrow inputs; the rollup input's annex is already bound by the journal.

## No spendable handles (implemented)

Instead of shrinking the settlement under the TRUC limit, a settlement now has nothing an attacker can spend
while it is unconfirmed, so it can have no descendant to pin it:

* withdrawal outputs are `P2TR(NUMS, {OP_1 OP_CHECKSEQUENCEVERIFY OP_DROP || tail})`, the leaf carried with
  the join-split and checked by the guest (the wallet's `withdrawal(value, key_tail(xonly))` uses
  `tail = <xonly> OP_CHECKSIG`); the successor already carries `1 OP_CSV`;
* no change, reward or P2A outputs: all fees go to the miner, and a user bumps by re-proving with a higher
  `fee_sats` (RBF by the next batch), not by CPFP;
* funding inputs use sequence 1 and escrows sequence 2, BIP 68 locks, so a settlement never has an
  unconfirmed parent.

`tools/policy/gsrpp_no_pin_handles.py` on the patched node (stand-in settlement with this layout;
`reports/no-pin-handles.json`):

| case | result |
| --- | --- |
| settlement spending an unconfirmed funding coin | rejected (`non-BIP68-final`) |
| child of the unconfirmed settlement, successor or withdrawal output, sequence 1 | rejected (`non-BIP68-final`) |
| same, sequence 0, `0xfffffffd`, `0xffffffff` | rejected (CSV: `Locktime requirement not satisfied`) |
| settlement descendants in the mempool | 1 (itself) |
| higher-fee competing settlement (+20,000 sats) | replaces it (ordinary RBF) |
| withdrawal key spend, sequence 1, one block after confirmation | accepted |

`tools/deposit_escrow.py node-test` adds `reject_sweep_escrow_one_confirmation` (an escrow swept with one
confirmation is `bad-txns-nonfinal`). The cost of the design: a withdrawal cannot pay an arbitrary address
(e.g. an exchange deposit) directly; the recipient forwards it one block later.

## Real settlements: relay, replacement and mining

`tools/relay_e2e.py` with two patched nodes, two batchers and the optimized GSR covenant (this PR's
format: `50 00` annex, sequences `[1, 2, 2]`, no change, reward or P2A output). Results in
`reports/relay-e2e.json`.

| step | measured |
| --- | --- |
| batch A (node A): 333,803 WU, 10,000 sats, 8 segments, 1,825 s segment proving | relayed to node B over P2P |
| batch B (node B, 2 escrow deposits): 335,903 WU, 20,000 sats, 12 segments, 2,908 s segment proving | relayed to node A in 3.5 s; replaced batch A (minimum delta 8,398 sats, paid 10,000) |
| re-sending batch A to node A | rejected: `insufficient fee, rejecting replacement` |
| batch B with escrow annex missing / inflated by 20 kB | invalid at consensus (`OP_EQUALVERIFY` in the sweep leaf) |
| batch B mined | 335,903 WU, 2,683-byte annex starting `500047535250`, 3 inputs, 1 output |
| both depositors scan through batcher B | one 20,000-sat note each |

How the run went: the first attempt timed out while waiting for P2P relay; batch A was valid
(`testmempoolaccept` allowed) but was held in node A's unbroadcast set. In the second attempt batch A
relayed, but batch B was sent before the restarted node's version handshake finished, so it was never
announced. `connect()` now waits for `verack` and `relaytxes` on both peers, and the relay wait is 180 s.
The replacement stage onward was then rerun with the same persisted nodes, batchers and proven
transactions (not re-proven), and passed. A clean end-to-end run with the fixed harness has not been
repeated (about 1.5 h of proving on this machine).
