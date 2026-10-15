//! Note commitments, nullifiers and Poseidon2 hashing, bit-for-bit identical to the
//! `joinsplit-2x2` Noir circuit (Noir `std::hash::poseidon2_permutation`, BN254, t = 4).
#![allow(clippy::needless_range_loop)]
mod poseidon2_constants;

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use pr_protocol_types::Fe;

pub mod tags {
    pub const OWNER: u64 = 1;
    pub const NULLIFIER_KEY: u64 = 2;
    pub const NOTE_INNER: u64 = 3;
    pub const NOTE: u64 = 4;
    pub const NULLIFIER: u64 = 5;
    pub const NODE: u64 = 6;
}

struct Constants {
    diagonal: [Fr; 4],
    rounds: [[Fr; 4]; 64],
}

fn parse(h: &str) -> Fr {
    Fr::from_be_bytes_mod_order(&hex::decode(h).expect("constant hex"))
}

fn constants() -> &'static Constants {
    static C: OnceLock<Constants> = OnceLock::new();
    C.get_or_init(|| Constants {
        diagonal: poseidon2_constants::INTERNAL_DIAGONAL.map(parse),
        rounds: poseidon2_constants::ROUND_CONSTANTS.map(|r| r.map(parse)),
    })
}

#[inline]
fn sbox(x: Fr) -> Fr {
    let s = x * x;
    s * s * x
}

fn external_matrix(s: &mut [Fr; 4]) {
    let t0 = s[0] + s[1];
    let t1 = s[2] + s[3];
    let t2 = s[1].double() + t1;
    let t3 = s[3].double() + t0;
    let t4 = t1.double().double() + t3;
    let t5 = t0.double().double() + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    *s = [t6, t5, t7, t4];
}

pub fn poseidon2_permutation(mut s: [Fr; 4]) -> [Fr; 4] {
    let c = constants();
    external_matrix(&mut s);
    for r in 0..4 {
        for i in 0..4 {
            s[i] = sbox(s[i] + c.rounds[r][i]);
        }
        external_matrix(&mut s);
    }
    for r in 4..60 {
        s[0] = sbox(s[0] + c.rounds[r][0]);
        let sum = s[0] + s[1] + s[2] + s[3];
        for i in 0..4 {
            s[i] = s[i] * c.diagonal[i] + sum;
        }
    }
    for r in 60..64 {
        for i in 0..4 {
            s[i] = sbox(s[i] + c.rounds[r][i]);
        }
        external_matrix(&mut s);
    }
    s
}

/// Rate-3 Poseidon2 compression with the domain tag in the capacity lane.
pub fn h3(tag: u64, a: Fr, b: Fr, c: Fr) -> Fr {
    poseidon2_permutation([a, b, c, Fr::from(tag)])[0]
}

pub fn to_fr(f: &Fe) -> Fr {
    Fr::from_be_bytes_mod_order(&f.0)
}

pub fn to_fe(f: &Fr) -> Fe {
    let mut b = [0u8; 32];
    b.copy_from_slice(&f.into_bigint().to_bytes_be());
    Fe(b)
}

pub fn spend_authority(secret: &Fe) -> Fe {
    to_fe(&h3(tags::OWNER, to_fr(secret), Fr::from(0u64), Fr::from(0u64)))
}

pub fn nullifier_key(secret: &Fe) -> Fe {
    to_fe(&h3(tags::NULLIFIER_KEY, to_fr(secret), Fr::from(0u64), Fr::from(0u64)))
}

pub fn note_commitment(rollup_id: &Fe, value: u64, authority: &Fe, randomness: &Fe) -> Fe {
    let inner = h3(tags::NOTE_INNER, to_fr(rollup_id), Fr::from(value), to_fr(authority));
    to_fe(&h3(tags::NOTE, inner, to_fr(randomness), Fr::from(0u64)))
}

pub fn nullifier(nullifier_key: &Fe, commitment: &Fe, leaf_index: u32) -> Fe {
    to_fe(&h3(tags::NULLIFIER, to_fr(nullifier_key), to_fr(commitment), Fr::from(leaf_index as u64)))
}

pub fn merkle_node(left: &Fe, right: &Fe) -> Fe {
    to_fe(&h3(tags::NODE, to_fr(left), to_fr(right), Fr::from(0u64)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fr(h: &str) -> Fr {
        parse(h)
    }

    #[test]
    fn matches_noir_blackbox_vectors() {
        let z = "0000000000000000000000000000000000000000000000000000000000000000";
        let out = poseidon2_permutation([fr(z), fr(z), fr(z), fr(z)]);
        assert_eq!(out[0], fr("18DFB8DC9B82229CFF974EFEFC8DF78B1CE96D9D844236B496785C698BC6732E"));
        assert_eq!(out[3], fr("18A4F34C9C6F99335FF7638B82AEED9018026618358873C982BBDDE265B2ED6D"));
        let out = poseidon2_permutation([Fr::from(0u64), Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        assert_eq!(out[0], fr("01BD538C2EE014ED5141B29E9AE240BF8DB3FE5B9A38629A9647CF8D76C01737"));
        assert_eq!(out[2], fr("04CBB44C61D928ED06808456BF758CBF0C18D1E15A7B6DBC8245FA7515D5E3CB"));
    }

    #[test]
    fn fe_round_trip_and_determinism() {
        let a = Fe::from_u64(7);
        assert_eq!(to_fe(&to_fr(&a)), a);
        let auth = spend_authority(&a);
        let c1 = note_commitment(&Fe::from_u64(1), 5, &auth, &Fe::from_u64(9));
        let c2 = note_commitment(&Fe::from_u64(1), 5, &auth, &Fe::from_u64(9));
        assert_eq!(c1, c2);
        assert_ne!(c1, note_commitment(&Fe::from_u64(1), 6, &auth, &Fe::from_u64(9)));
        let nk = nullifier_key(&a);
        assert_eq!(nullifier(&nk, &c1, 3), nullifier(&nk, &c1, 3));
        assert_ne!(nullifier(&nk, &c1, 3), nullifier(&nk, &c1, 4));
    }
}
