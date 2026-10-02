//! Bounded BN254 arithmetic workload for real proving-cost comparisons.
use ark_ff::{BigInteger, PrimeField};
use risc0_zkvm::guest::env;

fn main() {
    let frame = env::read_frame();
    assert_eq!(frame.len(), 4);
    let iterations = u32::from_le_bytes(frame.try_into().unwrap());
    assert!(iterations <= 100_000);
    let mut a = ark_bn254::Fr::from(123456789u64);
    let b = ark_bn254::Fr::from(987654321u64);
    let c = ark_bn254::Fr::from(5u64);
    for _ in 0..iterations {
        a = a * b + c;
    }
    env::commit_slice(&a.into_bigint().to_bytes_le());
}
