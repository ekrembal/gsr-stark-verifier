use std::path::Path;

use provekit_common::{
    utils::sumcheck::{calculate_external_row_by_scatter, calculate_external_row_of_r1cs_matrices},
    FieldElement, R1CS,
};
use provekit_verifier::Verify;

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/joinsplit").join(name)
}

#[test]
fn scatter_matches_transpose_on_sparse_boundary_shapes() {
    let one = FieldElement::from(1u64);
    let mut coefficients =
        vec![FieldElement::from(0u64), one, -one, FieldElement::from(3u64), -FieldElement::from(3u64)];
    for k in 1..=16 {
        let power = FieldElement::from(1u64 << k);
        coefficients.extend([power, -power]);
    }
    let mut general = -FieldElement::from(19u64);
    for _ in 0..8 {
        general = general * general + FieldElement::from(17u64);
        coefficients.push(general);
    }
    for rows in [1usize, 2, 3, 5, 17, 31] {
        for cols in [1usize, 3, 17] {
            let mut r1cs = R1CS::new();
            r1cs.add_witnesses(cols);
            for row in 0..rows {
                let a: Vec<_> = (0..cols)
                    .filter(|col| (row + col) % 4 != 0)
                    .map(|col| (coefficients[(row * 3 + col) % coefficients.len()], col))
                    .collect();
                let b: Vec<_> = (0..cols)
                    .filter(|col| (row + col) % 3 != 0)
                    .map(|col| (coefficients[(row * 3 + col) % coefficients.len()], col))
                    .collect();
                r1cs.add_constraint(&a, &b, &a);
            }
            let bits = rows.next_power_of_two().trailing_zeros() as usize;
            for seed in [0u64, 1, 2, 19] {
                let alpha: Vec<_> = (0..bits).map(|i| FieldElement::from(seed + i as u64)).collect();
                assert_eq!(
                    calculate_external_row_by_scatter(&alpha, &r1cs),
                    calculate_external_row_of_r1cs_matrices(&alpha, &r1cs),
                    "rows={rows} cols={cols} seed={seed}"
                );
            }
        }
    }
}

#[test]
fn fixed_key_binding_and_real_matrix_equivalence() {
    use sha2::{Digest, Sha256};
    let verifier = pr_provekit_adapter::load_verifier(&fixture("joinsplit.pkv")).unwrap();
    let encoded = pr_provekit_adapter::guest_verifier_bytes(&verifier).unwrap();
    assert_eq!(&Sha256::digest(encoded)[..], std::fs::read(fixture("verifier-key.sha256")).unwrap());
    let scheme = verifier.whir_for_witness.as_ref().unwrap();
    assert_eq!(
        (verifier.r1cs.num_constraints(), verifier.r1cs.num_witnesses(), scheme.m, scheme.m_0, scheme.num_challenges),
        (38819, 51805, 16, 16, 2)
    );
    for seed in [0u64, 1, 2, 19] {
        let alpha: Vec<_> = (0..scheme.m_0).map(|i| FieldElement::from(seed + i as u64)).collect();
        assert_eq!(
            calculate_external_row_by_scatter(&alpha, &verifier.r1cs),
            calculate_external_row_of_r1cs_matrices(&alpha, &verifier.r1cs)
        );
    }
}

#[test]
fn real_proof_acceptance_and_rejection_regressions() {
    use pr_tests::{coin, Harness, Wallet};
    use pr_wallet_core::SpendInput;
    let h = Harness::new();
    let alice = Wallet::new(1);
    let funding = vec![coin(0x41, 20000)];
    let builder = h.deposit_builder(700, &funding, 20000, None);
    let js = h.build(&builder, [SpendInput::Dummy, SpendInput::Dummy], [alice.pay(19300), alice.pay(0)]);
    let proof = pr_provekit_adapter::prove(
        pr_provekit_adapter::load_prover(&fixture("joinsplit.pkp")).unwrap(),
        &js.witness.prover_toml(),
        &js.witness.public,
    )
    .unwrap();
    let verifier = pr_provekit_adapter::load_verifier(&fixture("joinsplit.pkv")).unwrap();
    verifier.clone().verify(&proof).unwrap();
    // This immutable call must leave the configuration usable for the next proof.
    verifier.verify_ref(&proof).unwrap();
    verifier.verify_ref(&proof).unwrap();
    let mut consumed = verifier.clone();
    consumed.verify(&proof).unwrap();
    assert!(consumed.verify(&proof).is_err());
    assert!(consumed.verify_ref(&proof).is_err());
    let mut negatives = Vec::new();
    let mut changed = proof.clone();
    changed.public_inputs.0[0] += FieldElement::from(1u64);
    negatives.push(changed);
    for position in [0, proof.whir_r1cs_proof.narg_string.len() / 2, proof.whir_r1cs_proof.narg_string.len() - 1] {
        let mut changed = proof.clone();
        changed.whir_r1cs_proof.narg_string[position] ^= 1;
        negatives.push(changed);
    }
    for position in [0, proof.whir_r1cs_proof.hints.len() / 2, proof.whir_r1cs_proof.hints.len() - 1] {
        let mut changed = proof.clone();
        changed.whir_r1cs_proof.hints[position] ^= 1;
        negatives.push(changed);
    }
    let mut changed = proof.clone();
    changed.whir_r1cs_proof.narg_string.push(0);
    negatives.push(changed);
    let mut changed = proof.clone();
    changed.whir_r1cs_proof.hints.push(0);
    negatives.push(changed);
    let mut changed = proof.clone();
    changed.whir_r1cs_proof.narg_string.truncate(1);
    negatives.push(changed);
    let mut changed = proof.clone();
    changed.whir_r1cs_proof.hints.truncate(1);
    negatives.push(changed);
    for (index, changed) in negatives.iter().enumerate() {
        assert!(verifier.clone().verify(changed).is_err(), "consuming accepted case {index}");
        assert!(verifier.verify_ref(changed).is_err(), "borrowed accepted case {index}");
        // Failed proofs must not leave transcript state in the reusable key.
        verifier.verify_ref(&proof).unwrap();
    }
}
