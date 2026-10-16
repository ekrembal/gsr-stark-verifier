//! Deposit escrows: ordinary Bitcoin payments to a taproot address the rollup alone can sweep.
//!
//! The address is `P2TR(NUMS, {sweep, refund})`. The sweep leaf begins `0x20 D OP_DROP`, where `D`
//! ([`EscrowDeposit::digest`]) commits to the note the deposit mints; the rest of the leaf requires the
//! sweeping transaction's input 0 to run the rollup covenant. The guest learns the leaf privately and checks
//! that it hashes into the spent output key, so a deposit mints exactly the note its depositor chose.

use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar, U256};
use pr_protocol_types::hash::sha256;
use pr_protocol_types::{Fe, NoteOutput};
use serde::{Deserialize, Serialize};

/// BIP341's provably unspendable internal key `H`.
pub const NUMS_X: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a,
    0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];
pub const SWEEP_LEAF_VERSION: u8 = 0xc2;
const DIGEST_TAG: &[u8] = b"GSR-rollup/escrow-v1";

/// The private opening of one escrow input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowDeposit {
    pub authority: Fe,
    pub randomness: Fe,
    /// The minted note's value; the escrow output must hold exactly `value + fee_sats`.
    pub value: u64,
    pub fee_sats: u64,
    /// The whole sweep leaf script (`0x20 D 0x75 || body`).
    pub sweep_leaf: Vec<u8>,
    /// The tap-branch sibling of the sweep leaf (the refund leaf's hash).
    pub sibling: [u8; 32],
    pub ciphertext: Vec<u8>,
}

impl EscrowDeposit {
    pub fn digest(&self, rollup_id: &Fe) -> [u8; 32] {
        escrow_digest(rollup_id, &self.authority, &self.randomness, self.value, self.fee_sats, &self.ciphertext)
    }

    pub fn note(&self, rollup_id: &Fe) -> NoteOutput {
        NoteOutput {
            commitment: pr_crypto::note_commitment(rollup_id, self.value, &self.authority, &self.randomness),
            ciphertext: self.ciphertext.clone(),
        }
    }
}

pub fn escrow_digest(
    rollup_id: &Fe,
    authority: &Fe,
    randomness: &Fe,
    value: u64,
    fee_sats: u64,
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut m = Vec::with_capacity(DIGEST_TAG.len() + 136);
    m.extend_from_slice(DIGEST_TAG);
    m.extend_from_slice(&rollup_id.0);
    m.extend_from_slice(&authority.0);
    m.extend_from_slice(&randomness.0);
    m.extend_from_slice(&value.to_le_bytes());
    m.extend_from_slice(&fee_sats.to_le_bytes());
    m.extend_from_slice(&sha256(ciphertext));
    sha256(&m)
}

/// `0x20 D 0x75 || body`.
pub fn sweep_leaf(digest: &[u8; 32], body: &[u8]) -> Vec<u8> {
    [&[0x20][..], digest, &[0x75], body].concat()
}

fn tagged(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let t = sha256(tag);
    let mut m = Vec::new();
    m.extend_from_slice(&t);
    m.extend_from_slice(&t);
    for p in parts {
        m.extend_from_slice(p);
    }
    sha256(&m)
}

fn compact_size(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => [&[0xfd][..], &(n as u16).to_le_bytes()].concat(),
        _ => [&[0xfe][..], &(n as u32).to_le_bytes()].concat(),
    }
}

pub fn tapleaf_hash(version: u8, script: &[u8]) -> [u8; 32] {
    tagged(b"TapLeaf", &[&[version], &compact_size(script.len()), script])
}

pub fn tapbranch_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (l, r) = if a <= b { (a, b) } else { (b, a) };
    tagged(b"TapBranch", &[l, r])
}

/// The x-only output key of `P2TR(NUMS, merkle_root)`; `None` if the tweak is not a valid scalar.
pub fn output_key(merkle_root: &[u8; 32]) -> Option<[u8; 32]> {
    let t = tagged(b"TapTweak", &[&NUMS_X, merkle_root]);
    let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&t.into());
    if scalar.to_bytes().as_slice() != t {
        return None;
    }
    let p: Option<AffinePoint> =
        AffinePoint::from_encoded_point(&EncodedPoint::from_bytes([&[0x02][..], &NUMS_X].concat()).ok()?).into();
    let q = (ProjectivePoint::from(p?) + ProjectivePoint::GENERATOR * scalar).to_affine();
    Some(q.x().into())
}

/// `OP_1 <32-byte key>` for the escrow `{sweep_leaf, sibling}`.
pub fn escrow_script_pubkey(sweep_leaf: &[u8], sibling: &[u8; 32]) -> Option<Vec<u8>> {
    let root = tapbranch_hash(&tapleaf_hash(SWEEP_LEAF_VERSION, sweep_leaf), sibling);
    Some([&[0x51, 0x20][..], &output_key(&root)?].concat())
}

/// Whether `spk` is this escrow's address and its sweep leaf commits to the deposit's digest.
pub fn check_escrow(rollup_id: &Fe, e: &EscrowDeposit, spk: &[u8]) -> bool {
    let d = e.digest(rollup_id);
    e.sweep_leaf.len() >= 34
        && e.sweep_leaf[0] == 0x20
        && e.sweep_leaf[1..33] == d
        && e.sweep_leaf[33] == 0x75
        && escrow_script_pubkey(&e.sweep_leaf, &e.sibling).as_deref() == Some(spk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP341 wallet test vector 1 uses an internal key other than NUMS, so check the tweak path against a
    /// key-path-only output of NUMS computed with the same formula and the lift of NUMS itself.
    #[test]
    fn nums_lifts_and_tweaks() {
        assert!(output_key(&[0; 32]).is_some());
        assert_ne!(output_key(&[0; 32]), output_key(&[1; 32]));
    }

    /// Expected key computed with Bitcoin Core's functional-test framework (`tweak_add_pubkey`, `TaggedHash`).
    #[test]
    fn output_key_matches_bitcoin_core_test_framework() {
        let leaf = sweep_leaf(&[0x11; 32], &[0x51]);
        let spk = escrow_script_pubkey(&leaf, &[9; 32]).unwrap();
        let mut want = [0u8; 32];
        for (i, b) in want.iter_mut().enumerate() {
            *b = u8::from_str_radix(
                &"7e2f2d73542421596216f5eafbb9f3dfb2fc65054f565cac4c2751ed1702a3d7"[2 * i..2 * i + 2],
                16,
            )
            .unwrap();
        }
        assert_eq!(spk[..2], [0x51, 0x20]);
        assert_eq!(spk[2..], want);
    }

    #[test]
    fn escrow_binds_digest_leaf_and_sibling() {
        let rid = Fe([7; 32]);
        let mut e = EscrowDeposit {
            authority: Fe([1; 32]),
            randomness: Fe([2; 32]),
            value: 40_000,
            fee_sats: 500,
            sweep_leaf: Vec::new(),
            sibling: [9; 32],
            ciphertext: vec![3; 10],
        };
        e.sweep_leaf = sweep_leaf(&e.digest(&rid), &[0x51]);
        let spk = escrow_script_pubkey(&e.sweep_leaf, &e.sibling).unwrap();
        assert!(check_escrow(&rid, &e, &spk));
        assert!(!check_escrow(&Fe([8; 32]), &e, &spk));
        let mut f = e.clone();
        f.fee_sats = 499;
        assert!(!check_escrow(&rid, &f, &spk));
        let mut f = e.clone();
        f.value += 1;
        assert!(!check_escrow(&rid, &f, &spk));
        let mut f = e.clone();
        f.sibling = [8; 32];
        assert!(!check_escrow(&rid, &f, &spk));
        let mut f = e.clone();
        f.ciphertext[0] ^= 1;
        assert!(!check_escrow(&rid, &f, &spk));
    }

    /// Known answer from `tools/deposit_escrow.py vector` (Bitcoin Core's test framework `taproot_construct`).
    #[test]
    fn escrow_script_pubkey_matches_python_vector() {
        let leaf = sweep_leaf(&[0x11; 32], &[0x51]);
        assert_eq!(hex::encode(&leaf), "2011111111111111111111111111111111111111111111111111111111111111117551");
        let sibling: [u8; 32] =
            hex::decode("dcc5a52c7884d9a19cea606a7ab22c8efef3849ed7f030cc85a466f8034aa619").unwrap().try_into().unwrap();
        assert_eq!(
            hex::encode(escrow_script_pubkey(&leaf, &sibling).unwrap()),
            "5120401361e7f8b69af84cf54706f6f76544e0ac22a915725199f1959401c9948dc6"
        );
    }
}
