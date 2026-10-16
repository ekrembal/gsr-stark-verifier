//! Differential field operations, checked against an independent integer model.
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use risc0_zkvm::guest::env;

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
        for output in [a * b, a.square(), a + b, a - b, a * b + a, (a + b) * (a - b)] {
            env::commit_slice(&output.into_bigint().to_bytes_le());
        }
    }
}
