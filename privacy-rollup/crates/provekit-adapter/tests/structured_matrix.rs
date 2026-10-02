use ark_ff::{AdditiveGroup, Field};
use provekit_common::{
    utils::{structured_matrix, sumcheck::calculate_external_row_by_scatter},
    FieldElement, R1CS,
};
use std::path::Path;

fn fixture() -> provekit_common::Verifier {
    pr_provekit_adapter::load_verifier(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/joinsplit/joinsplit.pkv"),
    )
    .unwrap()
}

fn reference(eq: &[FieldElement], r1cs: &R1CS) -> [Vec<FieldElement>; 3] {
    [&r1cs.a, &r1cs.b, &r1cs.c].map(|matrix| {
        let mut out = vec![FieldElement::ZERO; matrix.num_cols];
        for (row, weight) in eq.iter().enumerate().take(matrix.num_rows) {
            for (column, coefficient) in matrix.iter_row(row) {
                out[column] += r1cs.interner.get(coefficient).unwrap() * weight;
            }
        }
        out
    })
}

#[test]
fn reverse_evaluator_matches_every_matrix_column() {
    let verifier = fixture();
    let r1cs = &verifier.r1cs;
    for seed in 0..13u64 {
        let mut x = FieldElement::from(seed + 2);
        let eq: Vec<_> = (0..r1cs.num_constraints())
            .map(|row| match seed {
                0 => FieldElement::ZERO,
                1 => FieldElement::ONE,
                2 => -FieldElement::ONE,
                3 => FieldElement::from((row % 7) as u64),
                _ => {
                    x = x.square() + FieldElement::from(row as u64 + 17);
                    x
                }
            })
            .collect();
        assert_eq!(structured_matrix::evaluate_with_eq(&eq, r1cs), reference(&eq, r1cs), "seed={seed}");
    }
    // Unit vectors cross full/partial-round and block/unstructured boundaries.
    for row in [0, 306, 307, 309, 318, 354, 355, 522, 523, 570, 571, 574, 575, 38362, 38818] {
        let mut eq = vec![FieldElement::ZERO; r1cs.num_constraints()];
        eq[row] = -FieldElement::ONE;
        assert_eq!(structured_matrix::evaluate_with_eq(&eq, r1cs), reference(&eq, r1cs), "unit row={row}");
    }
}

#[test]
fn reverse_evaluator_matches_sumcheck_point_layout() {
    let verifier = fixture();
    for seed in [0, 1, 2, 19, 127] {
        let alpha: Vec<_> = (0..16).map(|i| FieldElement::from(seed + i)).collect();
        assert_eq!(
            structured_matrix::evaluate(&alpha, &verifier.r1cs),
            calculate_external_row_by_scatter(&alpha, &verifier.r1cs)
        );
    }
}

#[test]
fn fixed_entry_point_binds_every_key_byte() {
    use provekit_verifier::FixedJoinSplitVerifier;
    let encoded = pr_provekit_adapter::guest_verifier_bytes(&fixture()).unwrap();
    assert!(FixedJoinSplitVerifier::from_postcard(&encoded).is_ok());
    for position in [0, encoded.len() / 2, encoded.len() - 1] {
        let mut changed = encoded.clone();
        changed[position] ^= 1;
        assert!(FixedJoinSplitVerifier::from_postcard(&changed).is_err());
    }
    let mut changed = encoded.clone();
    changed.push(0);
    assert!(FixedJoinSplitVerifier::from_postcard(&changed).is_err());
    assert!(FixedJoinSplitVerifier::from_postcard(&encoded[..encoded.len() - 1]).is_err());
}
