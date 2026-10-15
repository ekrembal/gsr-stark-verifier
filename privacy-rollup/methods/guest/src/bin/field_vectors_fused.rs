//! Differential field operations, checked against an independent integer model.
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use risc0_zkvm::guest::env;
#[path = "../field_fused_common.rs"]
mod fused;

fn field(bytes: &[u8]) -> ark_bn254::Fr {
    let limbs = core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()));
    ark_bn254::Fr::from_bigint(BigInt(limbs)).expect("canonical field input")
}

fn main() {
    let frame = env::read_frame();
    assert!(frame.len() <= 256 * 1024 && frame.len() % 64 == 0);
    for pair in frame.chunks_exact(64) {
        let a = field(&pair[..32]);
        let b = field(&pair[32..]);
        for output in [fused::multiply(a,b), fused::multiply(a,a), a + b, a - b, fused::multiply(a,b)+a, fused::multiply(a+b,a-b)] {
            env::commit_slice(&output.into_bigint().to_bytes_le());
        }
    }
}
