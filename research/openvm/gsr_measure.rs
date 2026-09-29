//! Measures the cost of verifying a stock OpenVM v2.0.2 aggregated STARK proof:
//! raw canonical proof bytes and the number of Poseidon2 permutations the host
//! verifier performs. Used to price a GSR (Bitcoin Tapscript v2) verifier.

use std::{sync::atomic::Ordering, time::Instant};

use eyre::Result;
use openvm::platform::memory::MEM_SIZE;
use openvm_sdk::{
    config::{AggregationSystemParams, DEFAULT_APP_L_SKIP},
    Sdk, StdIn,
};
use openvm_stark_backend::codec::Encode;
use openvm_stark_sdk::{
    config::{
        app_params_with_100_bits_security, internal_params_with_100_bits_security,
        leaf_params_with_100_bits_security,
    },
    utils::setup_tracing,
};
use openvm_transpiler::elf::Elf;
use openvm_verify_stark_host::{verify_vm_stark_proof_pvs, vk::VmStarkVerifyingKey};
use p3_poseidon2::PERMUTE_COUNT;

fn main() -> Result<()> {
    if std::env::var("RUST_LOG").is_ok() {
        setup_tracing();
    }
    let n: u64 = std::env::var("FIB_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let n_stack: usize = std::env::var("N_STACK")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(19);
    let app_params = app_params_with_100_bits_security(DEFAULT_APP_L_SKIP + n_stack);
    let agg_params = AggregationSystemParams {
        leaf: leaf_params_with_100_bits_security(),
        internal: internal_params_with_100_bits_security(),
    };
    let sdk = Sdk::riscv32(app_params, agg_params);

    let elf = Elf::decode(
        include_bytes!("../programs/examples/fibonacci.elf"),
        MEM_SIZE as u32,
    )?;
    let exe = sdk.convert_to_exe(elf)?;

    let mut stdin = StdIn::default();
    stdin.write(&n);

    let t = Instant::now();
    let mut prover = sdk.prover(exe)?.with_program_name("fibonacci");
    let (proof, metadata) = prover.prove(stdin, &[])?;
    let baseline = prover.generate_baseline();
    println!("prove took {:?}", t.elapsed());
    println!(
        "internal recursive layer : {}, node idx {}",
        metadata.internal_recursive_layer, metadata.internal_node_idx
    );

    let encoded = proof.encode_to_vec()?;
    let compressed = zstd::encode_all(encoded.as_slice(), 0)?;
    println!("fib n                    : {n}");
    println!("raw canonical proof bytes: {}", encoded.len());
    println!("zstd-compressed bytes    : {}", compressed.len());
    println!(
        "inner proof airs         : {}",
        proof.inner.public_values.len()
    );
    println!(
        "user pvs                 : {}",
        proof.user_pvs_proof.public_values.len()
    );

    let (_agg_pk, agg_vk) = sdk.agg_keygen();
    let before = PERMUTE_COUNT.load(Ordering::Relaxed);
    let t = Instant::now();
    Sdk::verify_proof(agg_vk.clone(), baseline.clone(), &proof)?;
    let verify_time = t.elapsed();
    let permutations = PERMUTE_COUNT.load(Ordering::Relaxed) - before;

    let vk = VmStarkVerifyingKey {
        mvk: agg_vk,
        baseline,
    };
    let before = PERMUTE_COUNT.load(Ordering::Relaxed);
    verify_vm_stark_proof_pvs(&vk, &proof)?;
    let pvs_permutations = PERMUTE_COUNT.load(Ordering::Relaxed) - before;

    println!("verify took              : {verify_time:?}");
    println!("poseidon2 permutations   : {permutations}");
    println!("  of which pvs/merkle    : {pvs_permutations}");
    println!("  of which stark verify  : {}", permutations - pvs_permutations);

    Ok(())
}
