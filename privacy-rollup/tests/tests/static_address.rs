//! The rollup lives at one fixed address; each settlement publishes its new state root as
//! `OP_RETURN 0x20 <root>` (value 0) in output 1, and the guest rejects any other layout.
use pr_protocol_types::{state_root_script, TxOut};
use pr_scanner::ScanError;
use pr_state_transition::{apply_batch, BatchWitness, TransitionError};
use pr_tests::{escrow_coin, Harness, Wallet};

fn settled() -> (Harness, BatchWitness) {
    let mut h = Harness::new();
    let rid = h.replica.descriptor.rollup_id();
    h.settle_with_escrows(&[escrow_coin(0x61, &rid, &Wallet::new(9), 1_000_000, 700)]).unwrap();
    let w = h.last_witness.clone().unwrap();
    (h, w)
}

#[test]
fn every_settlement_pays_the_same_address_and_publishes_its_root() {
    let (mut h, w1) = settled();
    let e1 = apply_batch(&w1).unwrap();
    let spk = w1.predecessor_tx.outputs[0].script_pubkey.clone();
    assert_eq!(w1.settlement.outputs[0].script_pubkey, spk);
    assert_eq!(w1.settlement.outputs[1], TxOut { value: 0, script_pubkey: state_root_script(&e1.new_state.root()) });
    assert_eq!(w1.settlement.outputs[1].script_pubkey.len(), 34);

    let rid = h.replica.descriptor.rollup_id();
    let e2 = h.settle_with_escrows(&[escrow_coin(0x62, &rid, &Wallet::new(8), 500_000, 700)]).unwrap();
    let w2 = h.last_witness.unwrap();
    assert_eq!(w2.settlement.outputs[0].script_pubkey, spk, "same address in every state");
    assert_eq!(w2.predecessor_tx.outputs[1].script_pubkey, state_root_script(&e1.new_state.root()));
    assert_eq!(w2.settlement.outputs[1].script_pubkey, state_root_script(&e2.new_state.root()));
}

#[test]
fn a_wrong_or_malformed_root_output_is_rejected() {
    let (h, w) = settled();
    let edits: [fn(&mut Vec<u8>); 5] = [
        |s| s[2] ^= 1,   // wrong root
        |s| s[0] = 0x51, // not OP_RETURN
        |s| s[1] = 0x1f, // wrong push length
        |s| s.push(0),   // trailing byte
        |s| {
            s.pop();
        }, // short root
    ];
    for edit in edits {
        let mut x = w.clone();
        edit(&mut x.settlement.outputs[1].script_pubkey);
        assert_eq!(apply_batch(&x).unwrap_err(), TransitionError::RootOutput);
        let mut r = h.replica.clone();
        r.rollback().unwrap();
        assert_eq!(r.apply_witness(&x).unwrap_err(), ScanError::Transition(TransitionError::RootOutput));
    }
    let mut x = w.clone();
    x.settlement.outputs[1].script_pubkey = state_root_script(&x.old_state.root());
    assert_eq!(apply_batch(&x).unwrap_err(), TransitionError::RootOutput, "republishing the old root");
}

#[test]
fn a_root_output_with_value_is_rejected() {
    let (_, mut w) = settled();
    w.settlement.outputs[1].value = 1;
    w.settlement.outputs[0].value -= 1;
    assert!(apply_batch(&w).is_err());
}

#[test]
fn a_missing_root_output_is_rejected() {
    let (_, mut w) = settled();
    w.settlement.outputs.remove(1);
    assert_eq!(apply_batch(&w).unwrap_err(), TransitionError::OutputCount);
    let (_, mut w) = settled();
    w.settlement.outputs.truncate(1);
    assert_eq!(apply_batch(&w).unwrap_err(), TransitionError::OutputCount);
}

#[test]
fn output_zero_must_pay_the_rollup_address() {
    let (_, w) = settled();
    for spk in [[&[0x51, 0x20][..], &[0x77; 32]].concat(), vec![0x51], Vec::new()] {
        let mut x = w.clone();
        x.settlement.outputs[0].script_pubkey = spk;
        assert_eq!(apply_batch(&x).unwrap_err(), TransitionError::RollupScript);
    }
}
