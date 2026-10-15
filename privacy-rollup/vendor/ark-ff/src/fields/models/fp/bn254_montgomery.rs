// Experimental fixed-BN254-Fr Montgomery kernel using the unchanged BigInt2 AIR.
// The verifier enforces a*b+p*R=q*p+r*R, R=2^256. Witness generation is untrusted.
// The mandatory r<p check makes the Montgomery result unique. See the generator
// and the narrow no-wrap/uniqueness lemmas; these do not constitute a kernel audit.
include!("bn254_montgomery_blob.rs");
#[cfg(feature = "experimental-bn254-dot32")]
include!("bn254_montgomery_dot32_blob.rs");

pub const MODULUS: [u32; 8] =
    [0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72];

#[inline(always)]
pub fn assert_canonical(result: &[u32; 8]) {
    for i in (0..8).rev() {
        if result[i] < MODULUS[i] {
            return;
        }
        if result[i] > MODULUS[i] {
            break;
        }
    }
    panic!("fused Montgomery output must be canonical");
}

/// Multiply two 256-bit Montgomery residues in place. The rhs is a distinct
/// Rust borrow; the bytecode reads both inputs before writing the lhs/result.
#[inline(always)]
pub fn multiply(lhs: &mut [u32; 8], rhs: &[u32; 8]) {
    // SAFETY: the static u32 array is 4-byte aligned and contains the complete
    // generated program, constants and bounded stack header. Both arguments
    // cover eight aligned words. Only lhs is written; input reads precede it.
    unsafe {
        risc0_bigint2::ffi::sys_bigint2_3(
            BN254_MONT_BLOB.as_ptr().cast(),
            lhs.as_ptr(),
            rhs.as_ptr(),
            lhs.as_mut_ptr(),
        );
    }
    assert_canonical(lhs);
}

/// Sum 32 Montgomery products using one checked reduction and canonical result.
#[cfg(feature = "experimental-bn254-dot32")]
pub fn dot32(lhs: &[[u32; 8]; 32], rhs: &[[u32; 8]; 32]) -> [u32; 8] {
    let mut result = [0u32; 8];
    // SAFETY: complete, aligned fixed program; 32 contiguous inputs per arena;
    // separate output covers eight aligned words. No unchecked result escapes.
    unsafe {
        risc0_bigint2::ffi::sys_bigint2_3(
            BN254_MONT_DOT32_BLOB.as_ptr().cast(),
            lhs.as_ptr().cast(),
            rhs.as_ptr().cast(),
            result.as_mut_ptr(),
        );
    }
    assert_canonical(&result);
    result
}
