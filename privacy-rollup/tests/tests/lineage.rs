//! Recursive lineage: a state is accepted only at the descriptor's genesis or with a receipt for
//! the journal of the settlement that created it, so a coin paying the covenant with a made-up
//! state (genuine rollup id, attacker-chosen parent) can never settle or sweep escrows.
use pr_bitcoin_adapter::{PlainInput, PlainTx};
use pr_protocol_types::{Outpoint, TxOut};
use pr_state_transition::{apply_batch, BatchWitness, PredecessorSettlement, TransitionError};
use pr_tests::{escrow_coin, Harness, Wallet};

/// Repoints `w` at an attacker coin that pays the covenant script and carries `w.old_state` with
/// `parent = x`, as a copy of the covenant funded by the attacker would.
fn fabricate(w: &mut BatchWitness, x: Outpoint) {
    w.old_state.parent = x;
    let spk = w.predecessor_tx.outputs[0].script_pubkey.clone();
    let attacker_tx = PlainTx {
        version: 2,
        lock_time: 0,
        inputs: vec![PlainInput { prevout: x, script_sig: Vec::new(), sequence: 0xffff_ffff }],
        outputs: vec![TxOut { value: w.old_state.backing_sats, script_pubkey: spk }],
    };
    w.settlement.inputs[0].prevout = Outpoint { txid: attacker_tx.txid(), vout: 0 };
    w.predecessor_tx = attacker_tx;
}

/// Two genuine settlements; returns the harness after the second and the first's effects.
fn two_batches() -> (Harness, pr_state_transition::BatchEffects, BatchWitness) {
    let mut h = Harness::new();
    let rid = h.replica.descriptor.rollup_id();
    let first = h.settle_with_escrows(&[escrow_coin(0x61, &rid, &Wallet::new(9), 1_000_000, 700)]).unwrap();
    let w1 = h.last_witness.clone().unwrap();
    let second = h.settle_with_escrows(&[escrow_coin(0x62, &rid, &Wallet::new(8), 500_000, 700)]).unwrap();
    assert_eq!(second.lineage.unwrap().journal, first.journal, "second settlement proves the first's journal");
    (h, first, w1)
}

#[test]
fn genesis_needs_no_predecessor_receipt() {
    let mut h = Harness::new();
    let e = h.settle().unwrap();
    assert!(e.lineage.is_none());
    let mut w = h.last_witness.unwrap();
    w.predecessor = Some(PredecessorSettlement { spent: Vec::new(), old_state_root: [0; 32], annex_digest: [0; 32] });
    assert_eq!(apply_batch(&w).unwrap_err(), TransitionError::Lineage);
}

#[test]
fn genuine_chain_rebuilds_each_predecessor_journal() {
    let (h, _, _) = two_batches();
    let w = h.replica.witness(Vec::new(), h.settlement(&[]));
    let third = apply_batch(&w).unwrap();
    let second = h.last_witness.unwrap();
    assert_eq!(third.lineage.unwrap().journal, apply_batch(&second).unwrap().journal);
}

#[test]
fn fabricated_genesis_state_is_rejected() {
    let mut h = Harness::new();
    let rid = h.replica.descriptor.rollup_id();
    h.settle_with_escrows(&[escrow_coin(0x61, &rid, &Wallet::new(9), 1_000_000, 700)]).unwrap();
    let mut w = h.last_witness.clone().unwrap();
    fabricate(&mut w, Outpoint { txid: [0xaa; 32], vout: 0 });
    assert_eq!(apply_batch(&w).unwrap_err(), TransitionError::Lineage);
    let mut w = h.last_witness.unwrap();
    w.old_state.commitment_count += 1;
    assert!(apply_batch(&w).is_err(), "a state other than genesis at batch 0");
}

#[test]
fn past_genesis_a_predecessor_settlement_is_required() {
    let (h, _, _) = two_batches();
    let mut w = h.last_witness.unwrap();
    w.predecessor = None;
    assert_eq!(apply_batch(&w).unwrap_err(), TransitionError::Lineage);
}

/// A fabricated non-genesis state passes the native transition only by naming a predecessor
/// journal, and that journal is one no genuine settlement committed: the guest's `env::verify`
/// for it cannot be satisfied, so neither the settlement nor its escrow sweep can be proven.
#[test]
fn fabricated_state_names_an_unprovable_predecessor_journal() {
    let (h, first, _) = two_batches();
    let genuine = h.last_witness.clone().unwrap();
    let genuine_journal = apply_batch(&genuine).unwrap().lineage.unwrap().journal;
    assert_eq!(genuine_journal, first.journal);

    let mut w = genuine.clone();
    fabricate(&mut w, Outpoint { txid: [0xaa; 32], vout: 0 });
    w.predecessor.as_mut().unwrap().spent = vec![TxOut { value: w.old_state.backing_sats, script_pubkey: vec![0x51] }];
    let forged = apply_batch(&w).unwrap().lineage.unwrap().journal;
    assert_ne!(forged.transaction_inputs_digest, first.journal.transaction_inputs_digest);
    assert_ne!(forged, first.journal);

    // Claiming a different old root, spent outputs or annex for the genuine predecessor also names
    // a journal nobody proved.
    let tampers: [fn(&mut PredecessorSettlement); 3] =
        [|p| p.old_state_root[0] ^= 1, |p| p.spent[0].value += 1, |p| p.annex_digest[0] ^= 1];
    for t in tampers {
        let mut w = genuine.clone();
        t(w.predecessor.as_mut().unwrap());
        assert_ne!(apply_batch(&w).unwrap().lineage.unwrap().journal, first.journal);
    }

    // A stale state (the one before the tip) on the tip's coin fails the local check.
    let mut w = genuine.clone();
    w.old_state = h.replica.history[0].state;
    assert!(apply_batch(&w).is_err());
}
