use pr_protocol_types::*;

fn fe(b: u8) -> Fe {
    Fe::from_u64(b as u64)
}

fn external(change: Option<TxOut>, withdrawal: Option<Vec<u8>>) -> ExternalData {
    ExternalData {
        deposit: Some(DepositDeclaration {
            funding: vec![Outpoint { txid: [3; 32], vout: 1 }, Outpoint { txid: [4; 32], vout: 0 }],
            change,
        }),
        withdrawal_script: withdrawal,
        ciphertexts: [vec![5; NOTE_CIPHERTEXT_LEN], vec![6; NOTE_CIPHERTEXT_LEN]],
    }
}

fn annex() -> Annex {
    Annex {
        old_state_root: [1; 32],
        new_state_root: [2; 32],
        body: BatchBody {
            rollup_id: fe(9),
            batch_number: 7,
            predecessor: Outpoint { txid: [8; 32], vout: 0 },
            layout: SettlementLayout { transactions: 1, funding_inputs: 1, withdrawals: 1, changes: 0, reward: true },
            nullifiers: vec![fe(1), fe(2)],
            outputs: vec![
                NoteOutput { commitment: fe(3), ciphertext: vec![7; NOTE_CIPHERTEXT_LEN] },
                NoteOutput { commitment: fe(4), ciphertext: vec![8; NOTE_CIPHERTEXT_LEN] },
            ],
        },
    }
}

fn round_trip<T: Canonical + PartialEq + core::fmt::Debug>(v: &T) {
    let bytes = v.encode();
    assert_eq!(&T::decode(&bytes).unwrap(), v);
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(T::decode(&longer), Err(DecodeError::TrailingBytes));
    assert_eq!(T::decode(&bytes[..bytes.len() - 1]).err(), Some(DecodeError::UnexpectedEnd));
}

#[test]
fn round_trips_and_rejects_trailing_or_truncated_bytes() {
    round_trip(&TxOut { value: 1000, script_pubkey: vec![0x51, 0x20, 1] });
    round_trip(&Outpoint { txid: [9; 32], vout: 5 });
    round_trip(&external(Some(TxOut { value: 400, script_pubkey: vec![0x6a] }), Some(vec![0x51])));
    round_trip(&external(None, None));
    round_trip(&annex());
    let journal = BatchJournal {
        protocol_version: 1,
        rollup_id: fe(1),
        old_state_root: [2; 32],
        new_state_root: [3; 32],
        transaction_inputs_digest: [4; 32],
        transaction_outputs_digest: [5; 32],
        annex_digest: [6; 32],
    };
    assert_eq!(journal.encode().len(), BatchJournal::LEN);
    round_trip(&journal);
}

#[test]
fn compact_size_is_minimal_both_ways() {
    for (v, len) in [(0u64, 1), (252, 1), (253, 3), (0xffff, 3), (0x1_0000, 5), (0xffff_ffff, 5), (1 << 32, 9)] {
        let mut w = Writer::new();
        w.compact_size(v);
        let b = w.finish();
        assert_eq!(b.len(), len, "{v}");
        let mut r = Reader::new(&b);
        assert_eq!(r.compact_size(), Ok(v));
        r.finish().unwrap();
    }
    for bad in [&[253u8, 252, 0][..], &[254, 0xff, 0xff, 0, 0], &[255, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]] {
        assert_eq!(Reader::new(bad).compact_size(), Err(DecodeError::NonMinimalCompactSize));
    }
    // A TxOut whose script length is written non-minimally.
    let mut b = 1000u64.to_le_bytes().to_vec();
    b.extend_from_slice(&[253, 1, 0, 0x6a]);
    assert_eq!(TxOut::decode(&b), Err(DecodeError::NonMinimalCompactSize));
}

#[test]
fn rejects_out_of_range_values() {
    let ok = TxOut { value: MAX_MONEY, script_pubkey: vec![] }.encode();
    assert!(TxOut::decode(&ok).is_ok());
    let over = TxOut { value: MAX_MONEY + 1, script_pubkey: vec![] }.encode();
    assert_eq!(TxOut::decode(&over), Err(DecodeError::AmountOutOfRange));
    let long = TxOut { value: 1, script_pubkey: vec![0; MAX_SCRIPT_PUBKEY_LEN + 1] }.encode();
    assert_eq!(TxOut::decode(&long), Err(DecodeError::LengthOutOfRange));

    assert_eq!(Fe::decode(&BN254_MODULUS), Err(DecodeError::NonCanonicalField));
    let mut below = BN254_MODULUS;
    below[31] -= 1;
    assert!(Fe::decode(&below).is_ok());
    assert!(Fe::from_canonical(Fe::from_digest([0xff; 32]).0).is_some());

    let mut b = external(None, None).encode();
    b[0] = 2;
    assert_eq!(ExternalData::decode(&b), Err(DecodeError::NonCanonicalBool));
}

#[test]
fn annex_rejects_bad_magic_order_and_layout() {
    let good = annex().encode();
    for (at, val) in [(0, 0x51u8), (1, b'X'), (5, 2)] {
        let mut b = good.clone();
        b[at] = val;
        assert_eq!(Annex::decode(&b), Err(DecodeError::BadMagic));
    }
    let body_at = 1 + 4 + 1 + 64;
    let nullifiers_at = body_at + 32 + 8 + 36 + 5;

    let mut a = annex();
    a.body.nullifiers.swap(0, 1);
    assert_eq!(Annex::decode(&a.encode()), Err(DecodeError::BadOrder));
    let mut a = annex();
    a.body.nullifiers[1] = a.body.nullifiers[0];
    assert_eq!(Annex::decode(&a.encode()), Err(DecodeError::BadOrder));
    let mut a = annex();
    a.body.nullifiers[0] = Fe::ZERO;
    assert_eq!(Annex::decode(&a.encode()), Err(DecodeError::BadOrder));
    let mut a = annex();
    a.body.outputs.swap(0, 1);
    assert_eq!(Annex::decode(&a.encode()), Err(DecodeError::BadOrder));

    let mut b = good.clone();
    b[body_at + 32 + 8 + 36] = (MAX_BATCH_TRANSACTIONS + 1) as u8;
    assert_eq!(Annex::decode(&b), Err(DecodeError::LengthOutOfRange));
    let mut b = good.clone();
    b[body_at + 32 + 8 + 36 + 4] = 2;
    assert_eq!(Annex::decode(&b), Err(DecodeError::NonCanonicalBool));
    assert_eq!(&good[nullifiers_at..nullifiers_at + 32], &fe(1).0);
}

#[test]
fn hashes_are_deterministic_and_domain_separated() {
    let d = RollupDescriptor {
        protocol_version: 1,
        genesis_nonce: Outpoint { txid: [1; 32], vout: 0 },
        image_id: [2; 32],
        internal_key: [3; 32],
        seed_sats: 100_000,
    };
    assert_eq!(d.rollup_id(), d.clone().rollup_id());
    for change in [
        |d: &mut RollupDescriptor| d.genesis_nonce.vout = 1,
        |d: &mut RollupDescriptor| d.image_id[0] ^= 1,
        |d: &mut RollupDescriptor| d.internal_key[0] ^= 1,
        |d: &mut RollupDescriptor| d.seed_sats += 1,
    ] {
        let mut e = d.clone();
        change(&mut e);
        assert_ne!(e.rollup_id(), d.rollup_id());
    }
    let x = external(None, None);
    assert_eq!(x.commitment(), hash::tagged(hash::tags::EXTERNAL_DATA, &[&x.encode()]));
    assert_ne!(x.commitment(), hash::tagged(hash::tags::BATCH_BODY, &[&x.encode()]));
}
