//! zkVM Poseidon2 over canonical (non-Montgomery) BN254 residues: one BigInt2 `modmul_256` per
//! product instead of the two a Montgomery multiply needs, and no Montgomery conversions at the
//! `Fe` boundary. Intermediate results use the unchecked BigInt2 calls: their constraint is a
//! congruence mod `p` for any 256-bit result, so a non-canonical intermediate only changes the
//! representative. The permutation output is checked canonical.
#[cfg(target_os = "zkvm")]
use risc0_bigint2::field::unchecked::{modadd_256, modmul_256};

use super::poseidon2_canonical::{INTERNAL_DIAGONAL, ROUND_CONSTANTS};
use pr_protocol_types::Fe;

type L = [u32; 8];

pub(crate) const MODULUS: L =
    [0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72];

#[cfg(target_os = "zkvm")]
#[inline(always)]
fn add(a: &L, b: &L) -> L {
    let mut r = [0u32; 8];
    modadd_256(a, b, &MODULUS, &mut r);
    r
}

/// Host stand-in for the BigInt2 sum, used only by the tests: `(a + b) mod p` for any `a, b < 2^256`.
#[cfg(not(target_os = "zkvm"))]
fn add(a: &L, b: &L) -> L {
    let mut r = [0u32; 8];
    let mut carry = 0u32;
    for i in 0..8 {
        let (s0, c0) = a[i].overflowing_add(b[i]);
        let (s1, c1) = s0.overflowing_add(carry);
        r[i] = s1;
        carry = (c0 | c1) as u32;
    }
    while carry == 1 || !is_canonical(&r) {
        carry -= sub_modulus(&mut r);
    }
    r
}

/// `x -= p` in place, returning the borrow out of the top limb.
#[inline(always)]
fn sub_modulus(x: &mut L) -> u32 {
    let mut borrow = 0u32;
    for i in 0..8 {
        let (d0, b0) = x[i].overflowing_sub(MODULUS[i]);
        let (d1, b1) = d0.overflowing_sub(borrow);
        x[i] = d1;
        borrow = (b0 | b1) as u32;
    }
    borrow
}

#[cfg(target_os = "zkvm")]
#[inline(always)]
fn mul(a: &L, b: &L) -> L {
    let mut r = [0u32; 8];
    modmul_256(a, b, &MODULUS, &mut r);
    r
}

/// Host stand-in for the BigInt2 product, used only by the tests.
#[cfg(not(target_os = "zkvm"))]
fn mul(a: &L, b: &L) -> L {
    use ark_ff::{BigInt, PrimeField};
    let fr = |x: &L| {
        ark_bn254::Fr::from_bigint(BigInt(core::array::from_fn(|i| x[2 * i] as u64 | (x[2 * i + 1] as u64) << 32)))
            .expect("canonical")
    };
    let p = (fr(&reduce(*a)) * fr(&reduce(*b))).into_bigint().0;
    core::array::from_fn(|i| (p[i / 2] >> (32 * (i % 2))) as u32)
}

#[inline(always)]
fn sbox(x: &L) -> L {
    let s = mul(x, x);
    mul(&mul(&s, &s), x)
}

fn external_matrix(s: &mut [L; 4]) {
    let t0 = add(&s[0], &s[1]);
    let t1 = add(&s[2], &s[3]);
    let t2 = add(&add(&s[1], &s[1]), &t1);
    let t3 = add(&add(&s[3], &s[3]), &t0);
    let t1x2 = add(&t1, &t1);
    let t4 = add(&add(&t1x2, &t1x2), &t3);
    let t0x2 = add(&t0, &t0);
    let t5 = add(&add(&t0x2, &t0x2), &t2);
    let t6 = add(&t3, &t5);
    let t7 = add(&t2, &t4);
    *s = [t6, t5, t7, t4];
}

fn is_canonical(x: &L) -> bool {
    for i in (0..8).rev() {
        if x[i] != MODULUS[i] {
            return x[i] < MODULUS[i];
        }
    }
    false
}

/// Subtracts `p` until `x < p` (at most five times for a 256-bit input).
fn reduce(mut x: L) -> L {
    while !is_canonical(&x) {
        sub_modulus(&mut x);
    }
    x
}

/// The canonical residue of `self` interpreted big-endian, matching `Fr::from_be_bytes_mod_order`.
pub(crate) fn limbs(f: &Fe) -> L {
    let mut x = [0u32; 8];
    for i in 0..8 {
        let o = 32 - 4 * (i + 1);
        x[i] = u32::from_be_bytes([f.0[o], f.0[o + 1], f.0[o + 2], f.0[o + 3]]);
    }
    reduce(x)
}

pub(crate) fn small(v: u64) -> L {
    [v as u32, (v >> 32) as u32, 0, 0, 0, 0, 0, 0]
}

pub(crate) fn to_fe(x: &L) -> Fe {
    let mut f = [0u8; 32];
    for i in 0..8 {
        let o = 32 - 4 * (i + 1);
        f[o..o + 4].copy_from_slice(&x[i].to_be_bytes());
    }
    Fe(f)
}

fn permutation(mut s: [L; 4]) -> [L; 4] {
    external_matrix(&mut s);
    for rc in &ROUND_CONSTANTS[0..4] {
        for i in 0..4 {
            s[i] = sbox(&add(&s[i], &rc[i]));
        }
        external_matrix(&mut s);
    }
    for rc in &ROUND_CONSTANTS[4..60] {
        s[0] = sbox(&add(&s[0], &rc[0]));
        let sum = add(&add(&s[0], &s[1]), &add(&s[2], &s[3]));
        for i in 0..4 {
            s[i] = add(&mul(&s[i], &INTERNAL_DIAGONAL[i]), &sum);
        }
    }
    for rc in &ROUND_CONSTANTS[60..64] {
        for i in 0..4 {
            s[i] = sbox(&add(&s[i], &rc[i]));
        }
        external_matrix(&mut s);
    }
    s
}

/// Rate-3 compression with `tag` in the capacity lane; the output is checked canonical.
pub(crate) fn h3(tag: u64, a: L, b: L, c: L) -> L {
    let out = permutation([a, b, c, small(tag)])[0];
    assert!(is_canonical(&out), "BigInt2 returned a non-canonical Poseidon2 output");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{to_fr, Fr};
    use ark_ff::{BigInt, PrimeField};

    fn fr_of(x: &L) -> Fr {
        let b = BigInt(core::array::from_fn(|i| x[2 * i] as u64 | (x[2 * i + 1] as u64) << 32));
        Fr::from_bigint(b).expect("canonical")
    }

    #[test]
    fn add_reduces_any_256_bit_inputs() {
        let max = [u32::MAX; 8];
        let mut p_minus_1 = MODULUS;
        p_minus_1[0] -= 1;
        for (a, b) in [(max, max), (max, [0; 8]), (MODULUS, MODULUS), (p_minus_1, p_minus_1), (p_minus_1, small(1))] {
            let r = add(&a, &b);
            assert!(is_canonical(&r));
            let fe = |x: &L| to_fr(&to_fe(x));
            assert_eq!(fr_of(&r), fe(&a) + fe(&b));
        }
    }

    #[test]
    fn canonical_permutation_matches_montgomery() {
        let fes = [[0u8; 32], [0xff; 32], [7; 32], [0x30; 32]].map(Fe);
        for a in &fes {
            for b in &fes {
                let ours = h3(crate::tags::NODE, limbs(a), limbs(b), small(9));
                assert_eq!(fr_of(&ours), crate::h3(crate::tags::NODE, to_fr(a), to_fr(b), Fr::from(9u64)));
                assert_eq!(to_fe(&limbs(a)), crate::to_fe(&to_fr(a)));
            }
        }
    }
}
