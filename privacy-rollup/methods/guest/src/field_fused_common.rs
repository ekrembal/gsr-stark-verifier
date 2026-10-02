#[path = "../../../vendor/ark-ff/src/fields/models/fp/bn254_montgomery.rs"]
mod fused;

#[inline(always)]
pub fn multiply(mut a: ark_bn254::Fr, b: ark_bn254::Fr) -> ark_bn254::Fr {
    // SAFETY: Fr has four public u64 Montgomery limbs; the little-endian RISC-V
    // guest uses the same 32 bytes as eight u32 words, with sufficient alignment.
    let lhs = unsafe { &mut *(&mut a.0.0 as *mut [u64; 4] as *mut [u32; 8]) };
    let rhs = unsafe { &*(&b.0.0 as *const [u64; 4] as *const [u32; 8]) };
    fused::multiply(lhs, rhs);
    a
}
