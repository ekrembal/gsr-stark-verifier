//! Reproducible matrix microbenchmark; does not generate a RISC Zero receipt.
use provekit_common::{
    utils::sumcheck::{calculate_external_row_by_scatter, calculate_external_row_of_r1cs_matrices},
    FieldElement, NoirProof,
};
use provekit_verifier::Verify;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Instant,
};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(args.len() == 2 || args.len() == 3, "usage: aggregation-bench <joinsplit.pkv> [release-proof.pc]");
    let verifier = pr_provekit_adapter::load_verifier(Path::new(&args[1]))?;
    let scheme = verifier.whir_for_witness.as_ref().unwrap();
    let alpha: Vec<_> = (0..scheme.m_0).map(|i| FieldElement::from(i as u64 + 2)).collect();
    let mut unique_products = BTreeSet::new();
    let mut generic_terms = 0;
    let one = FieldElement::from(1u64);
    let mut coefficients = BTreeMap::<String, usize>::new();
    for matrix in [&verifier.r1cs.a, &verifier.r1cs.b, &verifier.r1cs.c] {
        for row in 0..matrix.num_rows {
            for (_, index) in matrix.iter_row(row) {
                let value = verifier.r1cs.interner.get(index).unwrap();
                *coefficients.entry(value.to_string()).or_default() += 1;
                if value != one && value != -one {
                    generic_terms += 1;
                    unique_products.insert((row, index.index()));
                }
            }
        }
    }
    let mut common: Vec<_> = coefficients.into_iter().collect();
    common.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    let mut measurements = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let reference = calculate_external_row_of_r1cs_matrices(&alpha, &verifier.r1cs);
        let transpose = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let scatter = calculate_external_row_by_scatter(&alpha, &verifier.r1cs);
        let scatter_seconds = start.elapsed().as_secs_f64();
        anyhow::ensure!(reference == scatter, "scatter differs from transpose reference");
        measurements.push(serde_json::json!({"transpose_seconds":transpose,"scatter_seconds":scatter_seconds}));
        std::hint::black_box(scatter);
    }
    let mut native_verify = Vec::new();
    if let Some(path) = args.get(2) {
        anyhow::ensure!(!cfg!(debug_assertions), "use --release for the frozen proof layout");
        let proof: NoirProof = postcard::from_bytes(&std::fs::read(path)?)?;
        for _ in 0..5 {
            let start = Instant::now();
            verifier.clone().verify(&proof)?;
            let clone_and_verify_seconds = start.elapsed().as_secs_f64();
            let start = Instant::now();
            verifier.verify_ref(&proof)?;
            native_verify.push(serde_json::json!({
                "clone_and_verify_seconds": clone_and_verify_seconds,
                "borrowed_verify_seconds": start.elapsed().as_secs_f64(),
            }));
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "constraints":verifier.r1cs.num_constraints(), "witnesses":verifier.r1cs.num_witnesses(),
            "m":scheme.m,"m_0":scheme.m_0,"w1_size":scheme.w1_size,"num_challenges":scheme.num_challenges,
            "whir_config":scheme.whir_witness,"top_coefficients":common.into_iter().take(20).collect::<Vec<_>>(),
            "generic_terms":generic_terms,"unique_row_products":unique_products.len(),"measurements":measurements,
            "native_verify":native_verify,"equal":true
        }))?
    );
    Ok(())
}
