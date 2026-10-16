//! Adversarial scenarios: competing settlers, stale settlements, malformed annexes.
use pr_mempool::Entry;
use pr_protocol_types::RollupTransaction;
use pr_scanner::ScanError;
use pr_state_transition::apply_batch;
use pr_tests::{coin, Harness, Wallet};
use pr_wallet_core::SpendInput;

/// Two settlers prove different batches from the same state. Whichever is mined first extends the chain; the
/// other no longer applies (its input 0 is spent, and the replica rejects its annex), and its transaction is
/// re-batched against the new tip with its old anchor.
#[test]
fn competing_settlements_extend_the_chain_once() {
    let mut h = Harness::new();
    let alice = Wallet::new(1);
    let funding = vec![coin(0x51, 20_000)];
    let b = h.deposit_builder(700, &funding, 20_000, None);
    let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(19_300), alice.pay(0)]);
    let entry = Entry {
        tx: RollupTransaction { public: js.witness.public, external: js.external.clone(), receipt: vec![] },
        funding: funding.clone(),
        arrival: 1,
    };
    let settlement = h.settlement(std::slice::from_ref(&entry), None);
    let loser = h.replica.witness(pr_mempool::batch_transactions(std::slice::from_ref(&entry)), settlement);
    let loser_effects = apply_batch(&loser).unwrap();

    // The other settler wins with an empty batch.
    let winner = h.settle(None).unwrap();
    assert_eq!(winner.new_state.batch_number, 1);
    assert_ne!(winner.journal.new_state_root, loser_effects.journal.new_state_root);
    let tip = h.replica.tip().clone();

    // The loser's settlement spends the old rollup output and continues batch 0, so the replica rejects it.
    let mut replica = h.replica.clone();
    assert_eq!(replica.apply_witness(&loser).err(), Some(ScanError::WrongBatchNumber));
    assert_eq!(
        replica.accept_annex(&loser_effects.annex, &loser.settlement.plain()).err(),
        Some(ScanError::WrongBatchNumber)
    );
    assert_eq!(replica.tip(), &tip);

    // Its join-split is still valid against the new tip and settles in the next batch.
    h.submit(&js, funding).unwrap();
    let e = h.settle(None).unwrap();
    assert_eq!(e.new_state.batch_number, 2);
    assert_eq!(e.new_state.backing_sats, tip.state.backing_sats + 20_000 - 700);
}

/// A settlement replayed after it was mined does not apply a second time.
#[test]
fn a_mined_settlement_cannot_be_replayed() {
    let mut h = Harness::new();
    let first = h.settle(None).unwrap();
    let w = h.last_witness.clone().unwrap();
    let mut replica = h.replica.clone();
    assert_eq!(replica.apply_witness(&w).err(), Some(ScanError::WrongBatchNumber));
    assert_eq!(
        replica.accept_annex_bytes(&first.annex_bytes, &w.settlement.plain()).err(),
        Some(ScanError::WrongBatchNumber)
    );
}

/// Annex bytes that are padded, truncated or carry a foreign rollup do not replay.
#[test]
fn malformed_annexes_are_rejected_by_the_scanner() {
    let mut h = Harness::new();
    let base = h.replica.clone();
    let alice = Wallet::new(1);
    let funding = vec![coin(0x52, 20_000)];
    let b = h.deposit_builder(700, &funding, 20_000, None);
    let js = h.build(&b, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(19_300), alice.pay(0)]);
    h.submit(&js, funding).unwrap();
    let e = h.settle(None).unwrap();
    let tx = h.replica.tip().creating_tx.clone();

    let replay = |annex: &[u8]| base.clone().accept_annex_bytes(annex, &tx);
    assert_eq!(replay(&e.annex_bytes), Ok(()));
    let mut padded = e.annex_bytes.clone();
    padded.extend_from_slice(&[0; 100_000]);
    assert_eq!(replay(&padded), Err(ScanError::BadAnnex));
    assert_eq!(replay(&e.annex_bytes[..e.annex_bytes.len() - 1]), Err(ScanError::BadAnnex));
    let mut foreign = e.annex.clone();
    foreign.body.rollup_id.0[0] ^= 1;
    assert_eq!(base.clone().accept_annex(&foreign, &tx), Err(ScanError::WrongRollup));
    let mut root = e.annex.clone();
    root.new_state_root[0] ^= 1;
    assert_eq!(base.clone().accept_annex(&root, &tx), Err(ScanError::NewRootMismatch));
}
