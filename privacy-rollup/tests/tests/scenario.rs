//! End-to-end native scenarios and negative transition cases.
use pr_bitcoin_adapter::PlainTx;
use pr_mempool::{EscrowCoin, MempoolError};
use pr_protocol_types::{Annex, Canonical, Outpoint, TxOut};
use pr_scanner::{Replica, ScanError};
use pr_state_transition::{apply_batch, BatchWitness, TransitionError};
use pr_tests::{coin, descriptor, escrow_coin, genesis_tx, Harness, Wallet};
use pr_wallet_core::SpendInput;

const WITHDRAW_SPK: [u8; 22] = [0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

/// `(annex, settlement without witnesses)` of every settlement, as published on chain.
type Published = Vec<(Vec<u8>, PlainTx)>;

/// Alice deposits, pays Bob, Bob withdraws; returns the harness, wallets and every published annex.
fn lifecycle() -> (Harness, Wallet, Wallet, Published) {
    let mut h = Harness::new();
    let (mut alice, mut bob) = (Wallet::new(1), Wallet::new(2));
    let mut published = Vec::new();
    let mut record = |h: &Harness, e: &pr_state_transition::BatchEffects| {
        published.push((e.annex_bytes.clone(), h.replica.tip().creating_tx.clone()));
    };

    // Batch 1: deposit 50_000 from a 60_000 coin with 10_000 change; fee 1_000 of which 600 is the prover reward.
    let funding = vec![coin(0x31, 60_000)];
    let change = TxOut { value: 10_000, script_pubkey: vec![0x51, 0x20, 0x31] };
    let b = h.deposit_builder(1_000, &funding, 50_000, Some(change));
    let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(49_000), alice.pay(0)]);
    h.submit(&js, funding).unwrap();
    let e = h.settle(Some(TxOut { value: 600, script_pubkey: vec![0x51, 0x20, 0x99] })).unwrap();
    record(&h, &e);
    alice.scan(&h.replica, &e);
    bob.scan(&h.replica, &e);
    assert_eq!((alice.balance(&h.replica), bob.balance(&h.replica)), (49_000, 0));
    assert_eq!(e.new_state.backing_sats, 10_000 + 49_000);

    // Batch 2: Alice pays Bob 30_000, 18_500 change, fee 500 (all to the miner).
    let b = h.builder(500);
    let note = alice.notes[0].clone();
    let js = h.build(&b, [alice.spend(&h.replica, &note), SpendInput::Dummy], [bob.pay(30_000), alice.pay(18_500)]);
    h.submit(&js, vec![]).unwrap();
    let e = h.settle(None).unwrap();
    record(&h, &e);
    alice.scan(&h.replica, &e);
    bob.scan(&h.replica, &e);
    assert_eq!((alice.balance(&h.replica), bob.balance(&h.replica)), (18_500, 30_000));
    assert_eq!(e.new_state.backing_sats, 58_500);

    // Batch 3: empty (anchor-only) settlement.
    let e = h.settle(None).unwrap();
    record(&h, &e);

    // Batch 4: Bob withdraws 29_000 with fee 1_000 (anchor from batch 2, still in the window).
    let mut b = h.builder(1_000);
    b.withdrawal = Some((WITHDRAW_SPK.to_vec(), 29_000));
    let note = bob.notes[0].clone();
    let js = h.build(&b, [bob.spend(&h.replica, &note), SpendInput::Dummy], [bob.pay(0), bob.pay(0)]);
    h.submit(&js, vec![]).unwrap();
    let w_settle = h.mempool.select();
    let s = h.settlement(&w_settle, None);
    assert_eq!(s.outputs[1], TxOut { value: 29_000, script_pubkey: WITHDRAW_SPK.to_vec() });
    let e = h.settle(None).unwrap();
    record(&h, &e);
    bob.scan(&h.replica, &e);
    assert_eq!((alice.balance(&h.replica), bob.balance(&h.replica)), (18_500, 0));
    assert_eq!(e.new_state.backing_sats, 28_500);
    assert_eq!(e.new_state.batch_number, 4);
    (h, alice, bob, published)
}

#[test]
fn deposit_transfer_withdraw_and_scanner_replay() {
    let (h, _, _, published) = lifecycle();
    let mut fresh = Replica::new(descriptor(), genesis_tx()).unwrap();
    for (annex, tx) in &published {
        fresh.accept_annex_bytes(annex, tx).unwrap();
    }
    assert_eq!(fresh.tip(), h.replica.tip());
    assert_eq!(fresh.commitments.root(), h.replica.commitments.root());
    assert_eq!(fresh.nullifiers.root(), h.replica.nullifiers.root());
}

#[test]
fn scanner_rejects_tampered_or_out_of_order_annexes() {
    let (_, _, _, published) = lifecycle();
    let mut r = Replica::new(descriptor(), genesis_tx()).unwrap();
    let (a2, t2) = &published[1];
    assert_eq!(r.accept_annex_bytes(a2, t2), Err(ScanError::WrongBatchNumber));
    let (a1, t1) = &published[0];
    let mut inflated = t1.clone();
    inflated.outputs[0].value += 1;
    assert_eq!(r.accept_annex_bytes(a1, &inflated), Err(ScanError::NewRootMismatch));
    let mut other_parent = t1.clone();
    other_parent.inputs[0].prevout.vout = 1;
    assert_eq!(r.accept_annex_bytes(a1, &other_parent), Err(ScanError::WrongPredecessor));
    let mut bad = a1.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(r.accept_annex_bytes(&bad, t1).is_err());
    let mut trailing = a1.clone();
    trailing.push(0);
    assert_eq!(r.accept_annex_bytes(&trailing, t1), Err(ScanError::BadAnnex));
    let mut decoded = Annex::decode(a1).unwrap();
    decoded.body.predecessor.vout = 1;
    assert_eq!(r.accept_annex(&decoded, t1), Err(ScanError::WrongPredecessor));
    r.accept_annex_bytes(a1, t1).unwrap();
    assert_eq!(r.accept_annex_bytes(a1, t1), Err(ScanError::WrongBatchNumber));
}

#[test]
fn rollback_restores_state_and_allows_reapplication() {
    let (mut h, _, _, published) = lifecycle();
    let before = h.replica.tip().clone();
    h.replica.rollback().unwrap();
    assert_eq!(h.replica.state().batch_number, 3);
    let (a, t) = &published[3];
    h.replica.accept_annex_bytes(a, t).unwrap();
    assert_eq!(h.replica.tip(), &before);
    for _ in 0..4 {
        h.replica.rollback().unwrap();
    }
    assert_eq!(h.replica.rollback(), Err(ScanError::NothingToRollBack));
    assert_eq!(h.replica.commitments.count(), 0);
    assert_eq!(h.replica.nullifiers.next_index(), h.replica.state().nullifier_next_index);
}

#[test]
fn double_spend_is_rejected_by_mempool_and_transition() {
    let (mut h, mut alice, ..) = lifecycle();
    // Re-spend Alice's first, already-spent note.
    let spent = alice.notes[0].clone();
    assert!(h.replica.spent(&spent.nullifier));
    let b = h.builder(0);
    let js = h.build(&b, [alice.spend(&h.replica, &spent), SpendInput::Dummy], [alice.pay(49_000), alice.pay(0)]);
    assert_eq!(h.submit(&js, vec![]), Err(MempoolError::NullifierSpent));

    // Two pending spends of the same live note: the second is a reserved-nullifier conflict.
    let live = alice.notes[1].clone();
    let js1 = h.build(&b, [alice.spend(&h.replica, &live), SpendInput::Dummy], [alice.pay(18_500), alice.pay(0)]);
    let js2 = h.build(
        &h.builder(500),
        [alice.spend(&h.replica, &live), SpendInput::Dummy],
        [alice.pay(18_000), alice.pay(0)],
    );
    h.submit(&js1, vec![]).unwrap();
    assert_eq!(h.submit(&js2, vec![]), Err(MempoolError::NullifierReserved));

    // Bypassing the mempool: both in one batch is a duplicate nullifier in the transition.
    let w = h.replica.witness(
        vec![
            pr_state_transition::BatchTransaction { public: js1.witness.public, external: js1.external.clone() },
            pr_state_transition::BatchTransaction { public: js2.witness.public, external: js2.external.clone() },
        ],
        h.settlement(&[], None),
    );
    assert_eq!(apply_batch(&w).err(), Some(TransitionError::DuplicateNullifier));
    let _ = h.settle(None).unwrap();
    alice.notes.clear();
}

fn deposit_witness(
    h: &Harness,
    deposit: u64,
    coin_amount: u64,
    fee: u64,
) -> (BatchWitness, pr_wallet_core::BuiltJoinSplit) {
    let alice = Wallet::new(1);
    let funding = vec![coin(0x41, coin_amount)];
    let b = h.deposit_builder(fee, &funding, deposit, None);
    let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(deposit - fee), alice.pay(0)]);
    let entry = pr_mempool::Entry {
        tx: pr_protocol_types::RollupTransaction {
            public: js.witness.public,
            external: js.external.clone(),
            receipt: vec![],
        },
        funding,
        arrival: 1,
    };
    let s = h.settlement(std::slice::from_ref(&entry), None);
    (h.replica.witness(pr_mempool::batch_transactions(&[entry]), s), js)
}

#[test]
fn transition_rejects_every_settlement_tamper() {
    let h = Harness::new();
    let (good, _) = deposit_witness(&h, 20_000, 20_000, 700);
    let ok = apply_batch(&good).unwrap();
    assert_eq!(ok.new_state.backing_sats, 10_000 + 19_300);
    let expect = |f: &dyn Fn(&mut BatchWitness), e: TransitionError| {
        let mut w = good.clone();
        f(&mut w);
        assert_eq!(apply_batch(&w).err(), Some(e));
    };
    expect(&|w| w.settlement.version = 1, TransitionError::TxVersion);
    expect(&|w| w.settlement.lock_time = 1, TransitionError::TxLockTime);
    expect(&|w| w.settlement.inputs[0].sequence = 0xffff_fffe, TransitionError::PredecessorSequence);
    expect(&|w| w.settlement.inputs[0].amount += 1, TransitionError::PredecessorAmount);
    expect(
        &|w| {
            w.settlement.inputs.pop();
        },
        TransitionError::InputCount,
    );
    expect(
        &|w| {
            let i = w.settlement.inputs[1].clone();
            w.settlement.inputs.push(i);
        },
        TransitionError::InputCount,
    );
    expect(&|w| w.settlement.inputs[1].prevout.vout = 9, TransitionError::FundingInput);
    // A funding input carrying the escrow marker (how an escrow would be claimed as a join-split's coin).
    expect(
        &|w| w.settlement.inputs[1].sequence = pr_protocol_types::ESCROW_INPUT_SEQUENCE,
        TransitionError::FundingInput,
    );
    expect(&|w| w.settlement.inputs[1].amount -= 1, TransitionError::FundingAmount);
    expect(&|w| w.settlement.outputs[0].value -= 1, TransitionError::RolloverOutput);
    expect(
        &|w| w.settlement.outputs.push(TxOut { value: 701, script_pubkey: vec![0x6a] }),
        TransitionError::FeeShortfall,
    );
    expect(&|w| w.settlement.outputs.push(TxOut { value: 1, script_pubkey: vec![0x6a] }), TransitionError::Dust);
    expect(
        &|w| {
            w.settlement.outputs.push(TxOut { value: 400, script_pubkey: vec![] });
            w.settlement.outputs.push(TxOut { value: 400, script_pubkey: vec![] });
        },
        TransitionError::OutputCount,
    );
    expect(&|w| w.transactions[0].public.deposit_sats += 1, TransitionError::FundingAmount);
    expect(
        &|w| w.transactions[0].external.ciphertexts[0].pop().map(|_| ()).unwrap(),
        TransitionError::ExternalDataMismatch,
    );
    expect(&|w| w.transactions[0].public.expiry_batch_number = 0, TransitionError::Expired);
    expect(&|w| w.transactions[0].public.anchor_root.0[31] ^= 1, TransitionError::UnknownAnchor);
    expect(&|w| w.transactions[0].public.anchor_commitment_count += 1, TransitionError::UnknownAnchor);
    expect(&|w| w.transactions[0].public.anchor_batch_number = 7, TransitionError::UnknownAnchor);
    expect(&|w| w.transactions[0].public.rollup_id.0[31] ^= 1, TransitionError::WrongRollup);
    expect(&|w| w.transactions[0].public.protocol_version = 2, TransitionError::UnsupportedVersion);
    expect(&|w| w.transactions[0].public.nullifiers[1] = pr_protocol_types::Fe::ZERO, TransitionError::ZeroNullifier);
    expect(
        &|w| {
            let n = w.transactions[0].public.nullifiers[0];
            w.transactions[0].public.nullifiers[1] = n;
        },
        TransitionError::DuplicateNullifier,
    );
    expect(
        &|w| {
            let c = w.transactions[0].public.output_commitments[0];
            w.transactions[0].public.output_commitments[1] = c;
        },
        TransitionError::DuplicateCommitment,
    );
    expect(
        &|w| {
            w.nullifier_witnesses.pop();
        },
        TransitionError::NullifierWitnessCount,
    );
    expect(&|w| w.frontier = None, TransitionError::FrontierMissing);
    expect(&|w| w.old_state.commitment_count += 1, TransitionError::Frontier);
    expect(&|w| w.old_state.backing_sats += 1, TransitionError::PredecessorAmount);
    expect(&|w| w.anchors.0[0].commitment_count = 5, TransitionError::AnchorHistoryMismatch);
    expect(&|w| w.old_state.protocol_version = 2, TransitionError::UnsupportedVersion);
    let mut w = good.clone();
    w.nullifier_witnesses.swap(0, 1);
    assert!(matches!(apply_batch(&w), Err(TransitionError::Nullifier(_))));
}

#[test]
fn journal_binds_digests_of_the_transaction() {
    let h = Harness::new();
    let (w, _) = deposit_witness(&h, 20_000, 20_000, 700);
    let e = apply_batch(&w).unwrap();
    let j = e.journal.encode();
    assert_eq!(j.len(), 196);
    assert_eq!(e.journal.transaction_inputs_digest, w.settlement.inputs_digest());
    assert_eq!(e.journal.transaction_outputs_digest, w.settlement.outputs_digest());
    assert_eq!(e.journal.annex_digest, pr_protocol_types::hash::sha256(&e.annex_bytes));
    assert_eq!(e.journal.old_state_root, w.old_state.root());
    assert_eq!(e.journal.new_state_root, e.new_state.root());
    // A different change script, reward, or funding coin changes the bound digests.
    let mut w2 = w.clone();
    w2.settlement.inputs[1].script_pubkey.push(0);
    assert_ne!(apply_batch(&w2).unwrap().journal.transaction_inputs_digest, e.journal.transaction_inputs_digest);
}

#[test]
fn mempool_admission_rules() {
    let mut h = Harness::new();
    let alice = Wallet::new(1);
    let funding = vec![coin(0x51, 5_000)];
    let b = h.deposit_builder(0, &funding, 5_000, None);
    let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(5_000), alice.pay(0)]);
    assert_eq!(h.submit(&js, vec![coin(0x52, 5_000)]), Err(MempoolError::Rule(TransitionError::FundingInput)));
    let tx = pr_protocol_types::RollupTransaction {
        public: js.witness.public,
        external: js.external.clone(),
        receipt: vec![],
    };
    assert_eq!(h.mempool.submit(tx, funding.clone(), &h.replica, |_| false), Err(MempoolError::Proof));
    h.submit(&js, funding.clone()).unwrap();
    let js2 = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(5_000), alice.pay(0)]);
    assert_eq!(h.submit(&js2, funding), Err(MempoolError::FundingReserved));
    let mut b3 = h.builder(0);
    b3.expiry_batch_number = 0;
    let js3 = h.build(&b3, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(0), alice.pay(0)]);
    assert_eq!(h.submit(&js3, vec![]), Err(MempoolError::Rule(TransitionError::Expired)));

    // Fee ordering and expiry-driven eviction after settlement.
    let mut cheap = h.builder(0);
    cheap.expiry_batch_number = 1;
    let rich = h.builder(0);
    let a = h.build(&cheap, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(0), alice.pay(0)]);
    let c = h.build(&rich, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(0), alice.pay(0)]);
    h.submit(&a, vec![]).unwrap();
    h.submit(&c, vec![]).unwrap();
    assert_eq!(h.mempool.entries.len(), 3);
    h.mempool.entries.retain(|e| e.tx.public.deposit_sats > 0);
    let e = h.settle(None).unwrap();
    assert_eq!(e.new_state.backing_sats, 15_000);
    assert!(h.mempool.entries.is_empty());
}

#[test]
fn anchors_expire_after_the_window() {
    let mut h = Harness::new();
    let alice = Wallet::new(1);
    let mut b = h.builder(0);
    b.expiry_batch_number = 1_000;
    let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(0), alice.pay(0)]);
    for _ in 0..pr_protocol_types::ANCHOR_WINDOW {
        h.settle(None).unwrap();
    }
    assert_eq!(h.submit(&js, vec![]), Err(MempoolError::Rule(TransitionError::UnknownAnchor)));
}

#[test]
fn reward_cannot_exceed_fees() {
    let mut h = Harness::new();
    let alice = Wallet::new(1);
    let b = h.builder(500);
    let funding = vec![coin(0x61, 1_000)];
    let bd = h.deposit_builder(500, &funding, 1_000, None);
    let js = h.build(&bd, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(500), alice.pay(0)]);
    let _ = b;
    h.submit(&js, funding).unwrap();
    let sel = h.mempool.select();
    let s = h.settlement(&sel, Some(TxOut { value: 501, script_pubkey: vec![0x51] }));
    let w = h.replica.witness(pr_mempool::batch_transactions(&sel), s);
    assert_eq!(apply_batch(&w).err(), Some(TransitionError::FeeShortfall));
    let e = h.settle(Some(TxOut { value: 500, script_pubkey: vec![0x51] })).unwrap();
    assert_eq!(e.new_state.backing_sats, 10_500);
}

/// `n` wallets each deposit `amount` (fee 0) in one batch; returns the wallets after scanning it.
fn funded_wallets(h: &mut Harness, n: u8, amount: u64) -> Vec<Wallet> {
    let mut wallets: Vec<Wallet> = (0..n).map(|k| Wallet::new(10 + k)).collect();
    for (k, w) in wallets.iter().enumerate() {
        let funding = vec![coin(0x70 + k as u8, amount)];
        let b = h.deposit_builder(0, &funding, amount, None);
        let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [w.pay(amount), w.pay(0)]);
        h.submit(&js, funding).unwrap();
    }
    while !h.mempool.entries.is_empty() {
        let e = h.settle(None).unwrap();
        for w in wallets.iter_mut() {
            w.scan(&h.replica, &e);
        }
    }
    wallets
}

#[test]
fn batch_withdrawals_pay_each_declared_script_in_order() {
    let mut h = Harness::new();
    let wallets = funded_wallets(&mut h, 3, 10_000);
    let scripts: Vec<Vec<u8>> = (0..3u8).map(|k| [&[0x00, 0x14][..], &[0x40 + k; 20]].concat()).collect();
    for (k, w) in wallets.iter().enumerate() {
        let mut b = h.builder(300);
        b.withdrawal = Some((scripts[k].clone(), 4_000 + k as u64 * 1_000));
        let note = w.notes[0].clone();
        let change = 10_000 - 300 - (4_000 + k as u64 * 1_000);
        let js = h.build(&b, [w.spend(&h.replica, &note), SpendInput::Dummy], [w.pay(change), w.pay(0)]);
        h.submit(&js, vec![]).unwrap();
    }
    let selected = h.mempool.select();
    let s = h.settlement(&selected, None);
    let mut paid: Vec<TxOut> = s.outputs[1..].to_vec();
    paid.sort_by_key(|o| o.value);
    let expected: Vec<TxOut> =
        (0..3).map(|k| TxOut { value: 4_000 + k as u64 * 1_000, script_pubkey: scripts[k].clone() }).collect();
    assert_eq!(paid, expected);
    let e = h.settle(None).unwrap();
    assert_eq!(e.new_state.backing_sats, 10_000 + 30_000 - 15_000 - 900);
}

#[test]
fn withdrawal_dust_and_redirection_are_rejected() {
    let mut h = Harness::new();
    let wallets = funded_wallets(&mut h, 1, 10_000);
    let w = &wallets[0];
    let note = w.notes[0].clone();
    let mut b = h.builder(0);
    b.withdrawal = Some((WITHDRAW_SPK.to_vec(), pr_protocol_types::DUST_LIMIT - 1));
    let dust = b.build(
        &mut rand_core::OsRng,
        [w.spend(&h.replica, &note), SpendInput::Dummy],
        [w.pay(10_000 - pr_protocol_types::DUST_LIMIT + 1), w.pay(0)],
    );
    if let Ok(js) = dust {
        assert_eq!(h.submit(&js, vec![]), Err(MempoolError::Rule(TransitionError::Dust)));
    }

    b.withdrawal = Some((WITHDRAW_SPK.to_vec(), 2_000));
    let js = h.build(&b, [w.spend(&h.replica, &note), SpendInput::Dummy], [w.pay(8_000), w.pay(0)]);
    h.submit(&js, vec![]).unwrap();
    let selected = h.mempool.select();
    let mut s = h.settlement(&selected, None);
    s.outputs[1].script_pubkey = vec![0x51, 0x20, 0xee];
    let wit = h.replica.witness(pr_mempool::batch_transactions(&selected), s.clone());
    assert!(apply_batch(&wit).is_err());
    s = h.settlement(&selected, None);
    s.outputs[1].value -= 1;
    let wit = h.replica.witness(pr_mempool::batch_transactions(&selected), s);
    assert!(apply_batch(&wit).is_err());
    h.settle(None).unwrap();
}

#[test]
fn batches_are_capped_at_max_batch_transactions() {
    let mut h = Harness::new();
    let n = pr_protocol_types::MAX_BATCH_TRANSACTIONS as u8 + 1;
    let wallets = funded_wallets(&mut h, n, 1_000);
    for w in &wallets {
        let mut b = h.builder(0);
        b.withdrawal = Some((WITHDRAW_SPK.to_vec(), 1_000));
        let note = w.notes[0].clone();
        let js = h.build(&b, [w.spend(&h.replica, &note), SpendInput::Dummy], [w.pay(0), w.pay(0)]);
        h.submit(&js, vec![]).unwrap();
    }
    let selected = h.mempool.select();
    assert_eq!(selected.len(), pr_protocol_types::MAX_BATCH_TRANSACTIONS);
    let e = h.settle(None).unwrap();
    assert_eq!(e.annex.body.nullifiers.len(), 2 * pr_protocol_types::MAX_BATCH_TRANSACTIONS);
    assert_eq!(h.mempool.entries.len(), 1);
    h.settle(None).unwrap();
    assert!(h.mempool.entries.is_empty());
}

#[test]
fn stale_anchor_is_refreshed_by_rebuilding_at_the_tip() {
    let mut h = Harness::new();
    let wallets = funded_wallets(&mut h, 1, 5_000);
    let w = &wallets[0];
    let note = w.notes[0].clone();
    let mut b = h.builder(0);
    b.expiry_batch_number = 1_000;
    let stale = h.build(&b, [w.spend(&h.replica, &note), SpendInput::Dummy], [w.pay(5_000), w.pay(0)]);
    for _ in 0..pr_protocol_types::ANCHOR_WINDOW {
        h.settle(None).unwrap();
    }
    assert_eq!(h.submit(&stale, vec![]), Err(MempoolError::Rule(TransitionError::UnknownAnchor)));
    let fresh = h.build(&h.builder(0), [w.spend(&h.replica, &note), SpendInput::Dummy], [w.pay(5_000), w.pay(0)]);
    h.submit(&fresh, vec![]).unwrap();
    h.settle(None).unwrap();
    assert!(h.replica.spent(&note.nullifier));
}

/// A copy of the covenant (same script, any root) is a coin whose creating transaction did not spend
/// the genuine rollup's parent, so no witness for it passes the lineage check.
#[test]
fn lineage_rejects_covenant_copies_and_forged_predecessors() {
    let mut h = Harness::new();
    let (good, _) = deposit_witness(&h, 20_000, 20_000, 700);
    let ok = apply_batch(&good).unwrap();
    assert_eq!(ok.new_state.parent, h.replica.tip().utxo);
    assert_eq!(h.replica.state().parent, descriptor().genesis_nonce);
    let expect = |w: &BatchWitness| assert_eq!(apply_batch(w).err(), Some(TransitionError::Lineage));

    // Copy at the current root: funded by any other transaction paying the same script at output 0.
    let mut copy_tx: PlainTx = genesis_tx();
    copy_tx.inputs[0].prevout = Outpoint { txid: [0x66; 32], vout: 3 };
    let mut w = good.clone();
    w.settlement.inputs[0].prevout = Outpoint { txid: copy_tx.txid(), vout: 0 };
    w.predecessor_tx = copy_tx.clone();
    expect(&w);
    // ... even if the copier claims the genuine creating transaction as the predecessor.
    let mut w = good.clone();
    w.settlement.inputs[0].prevout = Outpoint { txid: copy_tx.txid(), vout: 0 };
    expect(&w);
    // Copy at output 1 of the genuine genesis transaction.
    let mut w = good.clone();
    w.settlement.inputs[0].prevout.vout = 1;
    expect(&w);
    // Forged predecessor whose txid does not match input 0.
    let mut w = good.clone();
    w.predecessor_tx.outputs[0].value += 1;
    expect(&w);

    // After a genuine settlement, a copy at an older root (genesis state) still fails: its parent is
    // the genesis nonce, which only the genuine genesis transaction spent.
    let mut alice = Wallet::new(1);
    let funding = vec![coin(0x42, 20_000)];
    let b = h.deposit_builder(700, &funding, 20_000, None);
    let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(19_300), alice.pay(0)]);
    h.submit(&js, funding).unwrap();
    let e = h.settle(None).unwrap();
    alice.scan(&h.replica, &e);
    let genuine = h.replica.tip().clone();
    assert_eq!(genuine.state.parent, Outpoint { txid: genesis_tx().txid(), vout: 0 });
    let mut stale = good.clone();
    stale.settlement.inputs[0].prevout = Outpoint { txid: copy_tx.txid(), vout: 0 };
    stale.predecessor_tx = copy_tx;
    expect(&stale);
    // The next genuine settlement passes with the settlement that created the tip as predecessor.
    let next = h.replica.witness(vec![], h.settlement(&[], None));
    assert_eq!(next.predecessor_tx, genuine.creating_tx);
    assert_eq!(apply_batch(&next).unwrap().new_state.parent, genuine.utxo);
}

#[test]
fn escrow_deposits_mint_notes_without_a_join_split() {
    let mut h = Harness::new();
    let rid = h.replica.descriptor.rollup_id();
    let mut a = Wallet::new(41);
    let mut b = Wallet::new(42);
    let escrows = [escrow_coin(0x61, &rid, &a, 30_000, 700), escrow_coin(0x62, &rid, &b, 20_000, 300)];
    let backing = h.replica.state().backing_sats;
    let e = h.settle_with_escrows(&escrows, None).unwrap();
    a.scan(&h.replica, &e);
    b.scan(&h.replica, &e);
    assert_eq!(a.balance(&h.replica), 30_000);
    assert_eq!(b.balance(&h.replica), 20_000);
    assert_eq!(e.annex.body.layout.escrows, 2);
    assert_eq!(e.new_state.backing_sats, backing + 50_000);
    let w = h.last_witness.clone().unwrap();
    assert_eq!(w.settlement.inputs.len(), 3);
    assert_eq!(w.settlement.inputs.iter().map(|i| i.amount).sum::<u64>() - w.settlement.outputs[0].value, 1_000);
    // The annex round-trips with the minted notes.
    assert_eq!(<Annex as Canonical>::decode(&e.annex_bytes).unwrap(), e.annex);

    // The minted note is spendable by a normal join-split.
    let note = a.notes[0].clone();
    let built = h.build(&h.builder(1_000), [a.spend(&h.replica, &note), SpendInput::Dummy], [b.pay(29_000), b.pay(0)]);
    h.submit(&built, vec![]).unwrap();
    let e = h.settle(None).unwrap();
    b.scan(&h.replica, &e);
    assert_eq!(b.balance(&h.replica), 49_000);
}

#[test]
fn escrow_openings_that_do_not_match_the_output_are_rejected() {
    let rid = Harness::new().replica.descriptor.rollup_id();
    let a = Wallet::new(43);
    let base = escrow_coin(0x63, &rid, &a, 30_000, 700);
    let reject = |c: EscrowCoin| {
        let mut h = Harness::new();
        h.settle_with_escrows(&[c], None).unwrap_err()
    };
    let mut c = base.clone();
    c.amount += 1;
    reject(c);
    let mut c = base.clone();
    c.opening.value += 1;
    reject(c);
    let mut c = base.clone();
    c.opening.fee_sats = 0;
    reject(c);
    let mut c = base.clone();
    c.script_pubkey[5] ^= 1;
    reject(c);
    let mut c = base.clone();
    c.opening.sibling = [6; 32];
    reject(c);
    let mut c = base.clone();
    c.opening.ciphertext.pop();
    reject(c);
    // An escrow for another rollup id cannot be swept here.
    reject(escrow_coin(0x64, &pr_protocol_types::Fe([3; 32]), &a, 30_000, 700));
    // Dust notes are rejected.
    reject(escrow_coin(0x65, &rid, &a, 10, 700));
    let mut h = Harness::new();
    h.settle_with_escrows(std::slice::from_ref(&base), None).unwrap();
    // Without the escrow marker the input could be a funding coin; the transition requires the marker.
    let mut h = Harness::new();
    h.settle_with_escrows(&[base], None).unwrap();
    let mut w = h.last_witness.clone().unwrap();
    let last = w.settlement.inputs.len() - 1;
    w.settlement.inputs[last].sequence = pr_protocol_types::FUNDING_INPUT_SEQUENCE;
    assert_eq!(apply_batch(&w).err(), Some(TransitionError::Escrow));
}
