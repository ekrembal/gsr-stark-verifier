use pr_commitment_tree::Tree;
use pr_protocol_types::{NoteOutput, Outpoint};
use rand_core::OsRng;

use super::*;
use crate::api::{Anchor, NoteBatch};

const SEED: [u8; 32] = [1; 32];

fn status(tree: &Tree, batch_number: u64) -> Status {
    Status {
        anchor: Anchor { root: hex::encode(tree.root().0), commitment_count: tree.count(), batch_number },
        rollup_id: hex::encode([0x1e; 32]),
        batch_number,
        state_root: hex::encode([0; 32]),
        commitment_count: tree.count(),
        nullifier_next_index: 1,
        backing_sats: 100_000,
        utxo: (hex::encode([3; 32]), 0),
        pending: 0,
    }
}

fn coin(amount: u64) -> FundingCoin {
    FundingCoin { outpoint: Outpoint { txid: [5; 32], vout: 2 }, amount, script_pubkey: vec![0x00, 0x20, 1, 2] }
}

fn deposit() -> (Wallet, BuiltJoinSplit) {
    let w = Wallet::from_seed(&SEED);
    let built = w.deposit(&mut OsRng, &status(&Tree::new(), 0), &[coin(20_000)], 700, 10).unwrap();
    (w, built)
}

fn outputs(built: &BuiltJoinSplit) -> Vec<NoteOutput> {
    (0..2)
        .map(|k| NoteOutput {
            commitment: built.witness.public.output_commitments[k],
            ciphertext: built.external.ciphertexts[k].clone(),
        })
        .collect()
}

#[test]
fn deposit_witness_round_trips_and_checks() {
    let (_, built) = deposit();
    let p = &built.witness.public;
    assert_eq!((p.deposit_sats, p.fee_sats, p.withdrawal_sats, p.expiry_batch_number), (20_000, 700, 0, 10));
    let json = serde_json::to_vec(&built.witness).unwrap();
    let back: JoinSplitWitness = serde_json::from_slice(&json).unwrap();
    assert_eq!(back, built.witness);
    back.check().unwrap();
}

#[test]
fn deposit_rejects_bad_requests() {
    let w = Wallet::from_seed(&SEED);
    let s = status(&Tree::new(), 0);
    assert!(w.deposit(&mut OsRng, &s, &[], 0, 10).is_err());
    assert!(w.deposit(&mut OsRng, &s, &[coin(700)], 700, 10).is_err());
    assert!(w.deposit(&mut OsRng, &s, &[coin(u64::MAX), coin(1)], 0, 10).is_err());
}

#[test]
fn tampered_witness_fails_the_circuit_check() {
    let (_, built) = deposit();
    let mut w = built.witness.clone();
    w.public.fee_sats += 1;
    assert!(w.check().is_err());
    let mut w = built.witness.clone();
    w.out_value[0] += 1;
    assert!(w.check().is_err());
}

#[test]
fn transaction_round_trips_canonically() {
    let (_, built) = deposit();
    let tx = transaction(&built, vec![7; 1000]);
    let s = submission(&tx, Vec::new());
    assert_eq!(decode_transaction(&s.transaction).unwrap(), tx);
    let json = serde_json::to_string(&s).unwrap();
    assert_eq!(serde_json::from_str::<Submission>(&json).unwrap(), s);
    assert!(decode_transaction(&format!("{}00", s.transaction)).is_err(), "trailing bytes");
    assert!(decode_transaction(&s.transaction[..s.transaction.len() - 2]).is_err(), "truncated");
    assert!(decode_transaction(&"0".repeat(MAX_TRANSACTION_HEX + 2)).is_err(), "oversized");
}

#[test]
fn address_round_trips() {
    let a = Wallet::from_seed(&SEED).address();
    assert_eq!(decode_address(&encode_address(&a)).unwrap(), a);
    assert!(decode_address("00").is_err());
}

#[test]
fn scan_then_transfer_spends_the_deposit() {
    let (w, built) = deposit();
    let rollup_id = fe_from_hex(&status(&Tree::new(), 0).rollup_id).unwrap();
    let mut tree = Tree::new();
    let outs = outputs(&built);
    for o in &outs {
        tree.append(o.commitment).unwrap();
    }
    let notes = Notes { batches: vec![NoteBatch { batch_number: 1, first_leaf: 0, outputs: outs }] };
    let owned = w.scan(&rollup_id, &notes);
    assert_eq!(owned.len(), 2);
    assert!(Wallet::from_seed(&[2; 32]).scan(&rollup_id, &notes).is_empty());
    let note = owned.iter().find(|n| n.note.value == 19_300).unwrap().clone();
    let s = status(&tree, 1);
    let path = MerklePath {
        leaf: note.leaf_index,
        commitment: note.commitment,
        anchor: s.anchor.clone(),
        siblings: tree.path(note.leaf_index).to_vec(),
    };
    let bob = Wallet::from_seed(&[2; 32]);
    let pay = vec![OutputSpec { value: 5_000, recipient: bob.address(), memo: [0; 32] }];
    let t =
        w.transfer(&mut OsRng, &s, &[(note.clone(), path.clone())], pay, Some((vec![0x51], 4_000)), 300, 10).unwrap();
    assert_eq!(t.witness.public.nullifiers[0], note.nullifier);
    assert_eq!((t.witness.public.withdrawal_sats, t.witness.public.fee_sats), (4_000, 300));
    assert_eq!(t.output_notes.iter().map(|n| n.value).sum::<u64>(), 19_300 - 4_000 - 300);

    let mut wrong = path.clone();
    wrong.siblings[0] = Fe([9; 32]);
    let pay = || vec![OutputSpec { value: 5_000, recipient: bob.address(), memo: [0; 32] }];
    assert!(w.transfer(&mut OsRng, &s, &[(note.clone(), wrong)], pay(), None, 300, 10).is_err(), "bad path");
    assert!(bob.transfer(&mut OsRng, &s, &[(note.clone(), path.clone())], pay(), None, 300, 10).is_err(), "not ours");
    let over = vec![OutputSpec { value: 19_301, recipient: bob.address(), memo: [0; 32] }];
    assert!(w.transfer(&mut OsRng, &s, &[(note, path)], over, None, 0, 10).is_err(), "overspend");
}

#[cfg(feature = "prove")]
mod receipts {
    use std::path::PathBuf;

    use pr_protocol_types::{ExternalData, JoinSplitPublic};

    use super::*;

    fn fixture() -> (Vec<u8>, JoinSplitPublic, ExternalData) {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/joinsplit-receipt");
        let receipt = std::fs::read(dir.join("receipt.bin")).unwrap();
        let public = serde_json::from_slice(&std::fs::read(dir.join("public.json")).unwrap()).unwrap();
        let external = serde_json::from_slice(&std::fs::read(dir.join("external.json")).unwrap()).unwrap();
        (receipt, public, external)
    }

    #[test]
    fn fixture_receipt_is_a_zero_knowledge_receipt_of_its_statement() {
        let (receipt, public, external) = fixture();
        let tx = RollupTransaction { public, external, receipt };
        verify_transaction(&tx).unwrap();
        assert_eq!(decode_transaction(&encode_transaction(&tx)).unwrap(), tx);
    }

    #[test]
    fn receipt_of_another_statement_is_rejected() {
        let (receipt, mut public, external) = fixture();
        public.fee_sats += 1;
        assert!(verify_transaction(&RollupTransaction { public, external, receipt }).is_err());
    }

    #[test]
    fn corrupted_receipt_is_rejected() {
        let (mut receipt, public, external) = fixture();
        let n = receipt.len();
        receipt[n / 2] ^= 1;
        assert!(verify_transaction(&RollupTransaction { public, external: external.clone(), receipt }).is_err());
        assert!(decode_receipt(&vec![0; MAX_RECEIPT_BYTES + 1]).is_err());
    }

    #[test]
    fn invalid_witness_is_rejected_before_proving() {
        let (_, built) = deposit();
        let mut built = built;
        built.witness.public.deposit_sats += 1;
        let err = prove(&built.witness, &built.external, None).unwrap_err().to_string();
        assert!(err.contains("witness"), "{err}");
    }
}
