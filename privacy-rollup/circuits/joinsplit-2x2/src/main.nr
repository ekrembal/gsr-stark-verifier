// 2-input / 2-output BTC join-split for the GSR privacy rollup (see spec/joinsplit.md).
//
// Hashing is Poseidon2 (BN254, t = 4) in rate-3 mode with the domain tag in the capacity lane,
// matching `pr-crypto` bit for bit.

global DEPTH: u32 = 32;
global MAX_MONEY: u64 = 2100000000000000;
global PROTOCOL_VERSION: u32 = 1;

global TAG_OWNER: Field = 1;
global TAG_NK: Field = 2;
global TAG_NOTE_INNER: Field = 3;
global TAG_NOTE: Field = 4;
global TAG_NULLIFIER: Field = 5;
global TAG_NODE: Field = 6;

fn h3(tag: Field, a: Field, b: Field, c: Field) -> Field {
    std::hash::poseidon2_permutation([a, b, c, tag])[0]
}

fn note_commitment(rollup_id: Field, value: u64, auth: Field, randomness: Field) -> Field {
    h3(TAG_NOTE, h3(TAG_NOTE_INNER, rollup_id, value as Field, auth), randomness, 0)
}

fn merkle_root(leaf: Field, index: u32, siblings: [Field; DEPTH]) -> Field {
    let bits: [bool; DEPTH] = (index as Field).to_le_bits();
    let mut node = leaf;
    for i in 0..DEPTH {
        let s = siblings[i];
        node = if bits[i] { h3(TAG_NODE, s, node, 0) } else { h3(TAG_NODE, node, s, 0) };
    }
    node
}

fn assert_money(v: u64) {
    assert(v <= MAX_MONEY);
}

fn main(
    rollup_id: pub Field,
    protocol_version: pub u32,
    anchor_root: pub Field,
    anchor_commitment_count: pub u64,
    anchor_batch_number: pub u64,
    nullifier: pub [Field; 2],
    output_commitment: pub [Field; 2],
    deposit_sats: pub u64,
    withdrawal_sats: pub u64,
    fee_sats: pub u64,
    external_data_hi: pub u128,
    external_data_lo: pub u128,
    expiry_batch_number: pub u64,
    in_value: [u64; 2],
    in_secret: [Field; 2],
    in_randomness: [Field; 2],
    in_index: [u32; 2],
    in_siblings: [[Field; DEPTH]; 2],
    out_value: [u64; 2],
    out_auth: [Field; 2],
    out_randomness: [Field; 2],
) {
    assert(protocol_version == PROTOCOL_VERSION);
    assert(anchor_batch_number <= expiry_batch_number);
    assert_money(deposit_sats);
    assert_money(withdrawal_sats);
    assert_money(fee_sats);
    // The external-data digest halves are 128-bit range checked by their types; as public inputs
    // they are fixed by the proof's public-input binding.
    let _ = (external_data_hi, external_data_lo);

    for i in 0..2 {
        assert_money(in_value[i]);
        let auth = h3(TAG_OWNER, in_secret[i], 0, 0);
        let nk = h3(TAG_NK, in_secret[i], 0, 0);
        let cm = note_commitment(rollup_id, in_value[i], auth, in_randomness[i]);
        // Real (nonzero) inputs must be members of the anchor tree; zero-valued dummy inputs
        // skip membership but still produce a fresh, nonzero, unlinkable nullifier.
        if in_value[i] != 0 {
            assert((in_index[i] as u64) < anchor_commitment_count);
            assert(merkle_root(cm, in_index[i], in_siblings[i]) == anchor_root);
        }
        let nf = h3(TAG_NULLIFIER, nk, cm, in_index[i] as Field);
        assert(nf != 0);
        assert(nf == nullifier[i]);
    }
    assert(nullifier[0] != nullifier[1]);

    for j in 0..2 {
        assert_money(out_value[j]);
        assert(
            note_commitment(rollup_id, out_value[j], out_auth[j], out_randomness[j])
                == output_commitment[j],
        );
    }
    assert(output_commitment[0] != output_commitment[1]);

    // Every term is range checked to <= MAX_MONEY < 2^51, so both sides are below 2^54 and the
    // field equality is exact integer equality.
    let lhs = in_value[0] as Field + in_value[1] as Field + deposit_sats as Field;
    let rhs = out_value[0] as Field
        + out_value[1] as Field
        + withdrawal_sats as Field
        + fee_sats as Field;
    assert(lhs == rhs);
}
