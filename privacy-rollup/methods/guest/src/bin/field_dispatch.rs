//! Exercise experimental dispatch boundaries and unaffected modulus/size paths.
use ark_ff::{BigInteger, Field, Fp256, Fp64, MontBackend, MontConfig, PrimeField};
use risc0_zkvm::guest::env;

#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088696311157297823662689037894645226208583"]
#[generator = "3"]
struct OtherModulus;
type OtherField = Fp256<MontBackend<OtherModulus, 4>>;

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
struct SmallModulus;
type SmallField = Fp64<MontBackend<SmallModulus, 1>>;

fn sample<F: PrimeField>(i: usize, seed: u64) -> F {
    match i % 7 {
        0 => F::ZERO,
        1 => F::ONE,
        2 => -F::ONE,
        _ => F::from(seed + i as u64 * 987654321),
    }
}

fn dot<F: PrimeField, const M: usize>(seed: u64) {
    let a = core::array::from_fn(|i| sample::<F>(i, seed));
    let b = core::array::from_fn(|i| sample::<F>(i + 3, seed + 17));
    let out = F::sum_of_products::<M>(&a, &b);
    env::commit_slice(&out.into_bigint().to_bytes_le());
}

fn cases<F: PrimeField>() {
    for seed in [0u64, 1, 97, 123456789] {
        dot::<F, 0>(seed);
        dot::<F, 1>(seed);
        dot::<F, 7>(seed);
        dot::<F, 31>(seed);
        dot::<F, 32>(seed);
        dot::<F, 33>(seed);
    }
}

fn main() {
    cases::<ark_bn254::Fr>();
    cases::<OtherField>();
    cases::<SmallField>();
}
