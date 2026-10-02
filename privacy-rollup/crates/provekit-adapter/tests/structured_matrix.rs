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
        assert_eq!(
            structured_matrix::evaluate_fixed_with_eq(&eq),
            reference(&eq, r1cs),
            "compiled residual seed={seed}"
        );
    }
    // Unit vectors cross full/partial-round and block/unstructured boundaries.
    for row in [0, 306, 307, 309, 318, 354, 355, 522, 523, 570, 571, 574, 575, 38362, 38818] {
        let mut eq = vec![FieldElement::ZERO; r1cs.num_constraints()];
        eq[row] = -FieldElement::ONE;
        assert_eq!(structured_matrix::evaluate_with_eq(&eq, r1cs), reference(&eq, r1cs), "unit row={row}");
        assert_eq!(
            structured_matrix::evaluate_fixed_with_eq(&eq),
            reference(&eq, r1cs),
            "compiled residual unit row={row}"
        );
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
        assert_eq!(
            structured_matrix::evaluate_fixed(&alpha),
            calculate_external_row_by_scatter(&alpha, &verifier.r1cs)
        );
    }
}

#[test]
fn embedded_configuration_matches_every_pinned_parameter() {
    let verifier = fixture();
    // Same dependency path as this crate's Cargo.toml, resolved from its manifest.
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../provekit/provekit/verifier/src/joinsplit_whir.pc");
    let encoded = std::fs::read(path).unwrap();
    let embedded: provekit_common::WhirR1CSScheme = postcard::from_bytes(&encoded).unwrap();
    let expected = verifier.whir_for_witness.as_ref().unwrap();
    assert_eq!(&embedded, expected);
    assert_eq!(encoded, postcard::to_allocvec(expected).unwrap());
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

#[test]
fn bilinear_evaluator_preserves_independent_witness_columns() {
    let verifier = fixture();
    for seed in 0..8u64 {
        let mut x = FieldElement::from(seed + 2);
        let eq: Vec<_> = (0..38819)
            .map(|i| {
                x = x.square() + FieldElement::from(i + 7);
                if seed == 0 {
                    FieldElement::ZERO
                } else if seed == 1 {
                    FieldElement::ONE
                } else {
                    x
                }
            })
            .collect();
        let vectors = reference(&eq, &verifier.r1cs);
        // These are arbitrary independent columns, deliberately not a valid
        // Poseidon witness. Also exercise split, global and boundary layouts.
        for (offset, len) in [(0, 51805), (0, 5530), (5530, 46275), (5529, 2), (0, 1), (51804, 1)] {
            let columns: Vec<_> = (0..len)
                .map(|i| {
                    x = x.square() + FieldElement::from(i as u64 + 13);
                    if seed == 0 {
                        FieldElement::ONE
                    } else if seed == 1 {
                        -FieldElement::ONE
                    } else {
                        x
                    }
                })
                .collect();
            let expected = core::array::from_fn(|m| {
                vectors[m][offset..offset + len].iter().zip(&columns).map(|(a, b)| *a * b).sum()
            });
            assert_eq!(
                structured_matrix::evaluate_bilinear(&eq, &columns, offset),
                expected,
                "seed={seed}, offset={offset}, len={len}"
            );
        }
    }
}

#[test]
fn lazy_covectors_match_prefix_folds_and_cache_each_commitment_point() {
    use provekit_common::{
        prefix_covector::build_prefix_covectors, utils::sumcheck::calculate_evaluations_over_boolean_hypercube_for_eq,
    };
    use std::sync::Arc;
    use whir::algebra::linear_form::LinearForm;
    let alpha: Vec<_> = (0..16).map(|i| FieldElement::from(i + 19)).collect();
    let rows = Arc::new(calculate_evaluations_over_boolean_hypercube_for_eq(&alpha, 38819));
    let vectors = reference(&rows, &fixture().r1cs);
    let groups = [(0, 5530), (5530, 46275), (0, 51805)].map(|(offset, len)| {
        let expected =
            build_prefix_covectors(17, core::array::from_fn::<_, 3, _>(|m| vectors[m][offset..offset + len].to_vec()));
        let actual = structured_matrix::FixedMatrixCovector::new_group(rows.clone(), offset, len, 1 << 17);
        (actual, expected)
    });
    for seed in [0, 1, 2, 7, 19, 2, 0] {
        for (g, (actual, expected)) in groups.iter().enumerate() {
            // Includes points longer than the domain dimension and machine word.
            let dimension = match seed { 7 => 65, 19 => 19, _ => 17 };
            let point: Vec<_> = (0..dimension)
                .map(|i| match seed {
                    0 => FieldElement::ZERO,
                    1 => FieldElement::ONE,
                    _ => FieldElement::from(seed + i + g as u64 * 100),
                })
                .collect();
            // Deliberately permuted/repeated matrix access and changed points.
            for m in [2, 0, 1, 0, 2] {
                assert_eq!(actual[m].size(), expected[m].size());
                assert_eq!(
                    actual[m].mle_evaluate(&point),
                    expected[m].mle_evaluate(&point),
                    "seed={seed}, group={g}, matrix={m}"
                );
            }
        }
    }
    for (actual, expected) in &groups {
        for m in 0..3 {
            let mut a = vec![FieldElement::from(3); 1 << 17];
            let mut b = a.clone();
            actual[m].accumulate(&mut a, -FieldElement::ONE);
            expected[m].accumulate(&mut b, -FieldElement::ONE);
            assert_eq!(a, b);
        }
    }
}
