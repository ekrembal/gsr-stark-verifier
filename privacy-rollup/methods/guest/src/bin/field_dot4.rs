//! Independent canonical input/output vectors for a bounded 4-term field dot (Poseidon2 linear-layer rows).
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use risc0_zkvm::guest::env;

fn field(bytes: &[u8]) -> ark_bn254::Fr {
    let limbs = core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()));
    ark_bn254::Fr::from_bigint(BigInt(limbs)).expect("canonical dot input")
}

fn main() {
    let frame = env::read_frame();
    assert!(frame.len() <= 256 * 1024 && frame.len() % 256 == 0);
    for chunk in frame.chunks_exact(256) {
        let a = core::array::from_fn(|i| field(&chunk[64 * i..64 * i + 32]));
        let b = core::array::from_fn(|i| field(&chunk[64 * i + 32..64 * i + 64]));
        let result = ark_bn254::Fr::sum_of_products::<4>(&a, &b);
        env::commit_slice(&result.into_bigint().to_bytes_le());
    }
}
