use ark_ff::{AdditiveGroup, FftField, Field};
use provekit_common::FieldElement as F;
use std::sync::Arc;
use whir::algebra::{
    linear_form::LinearForm,
    multilinear_extend,
    projected_power_sum::{InterleavedProjection, ProjectedPowerSum},
};

// Independent definition: enumerate c|m and extract the requested bit window.
fn reference(mu: usize, ell: usize, start: usize, eq: &[F], scalars: &[F], zs: &[F]) -> Vec<F> {
    let m_bits = mu - eq.len().trailing_zeros() as usize;
    let mut inner = vec![F::ZERO; 1 << m_bits];
    for (&scalar, &z) in scalars.iter().zip(zs) {
        let mut value = scalar;
        for dest in &mut inner {
            *dest += value;
            value *= z;
        }
    }
    let mut out = vec![F::ZERO; 1 << ell];
    for (c, &weight) in eq.iter().enumerate() {
        for (m, &value) in inner.iter().enumerate() {
            let index = (((c << m_bits) | m) >> (mu - start - ell)) & (out.len() - 1);
            out[index] += weight * value;
        }
    }
    out
}

fn padded_mle(table: &[F], point: &[F]) -> F {
    let extra = point.len() - table.len().trailing_zeros() as usize;
    let prefix: F = point[..extra].iter().map(|x| F::ONE - x).product();
    prefix * multilinear_extend(table, &point[extra..])
}

#[test]
fn lazy_projection_matches_enumerated_coefficients_and_mles() {
    let root = F::get_root_of_unity(32768).unwrap();
    let zs = [F::ZERO, F::ONE, -F::ONE, F::from(7u64), root, root.pow([9]), F::from(11u64)];
    let scalars = [F::ONE, F::from(3u64), -F::ONE, F::from(13u64), F::from(27u64), F::ONE, F::ZERO];
    for (mu, ell, folded) in [(4, 3, 0), (6, 4, 2), (7, 3, 3), (3, 3, 3), (13, 12, 3), (16, 12, 3)] {
        // Arbitrary weights deliberately need not sum to one.
        let eq: Vec<_> = (0..1 << folded).map(|i| F::from((i * i + 3) as u64)).collect();
        for start in 0..=mu - ell {
            let expected = reference(mu, ell, start, &eq, &scalars, &zs);
            let form = Arc::new(ProjectedPowerSum::new(mu, ell, start, &eq, &scalars, &zs));
            assert_eq!(form.size(), expected.len());
            let mut actual = vec![F::from(5u64); expected.len()];
            form.accumulate(&mut actual, F::from(2u64));
            assert_eq!(
                actual,
                expected.iter().map(|x| F::from(5u64) + *x * F::from(2u64)).collect::<Vec<_>>(),
                "shape={mu},{ell},{folded},{start}"
            );
            for (even, odd) in
                [(F::ONE, -F::from(17u64)), (F::ZERO, -F::from(19u64)), (F::ONE, F::ZERO), (F::ZERO, F::ZERO)]
            {
                let interleaved = InterleavedProjection::new(form.clone(), even, odd);
                let table: Vec<_> = expected.iter().flat_map(|&x| [x * even, x * odd]).collect();
                let mut actual = vec![F::ZERO; table.len()];
                interleaved.accumulate(&mut actual, F::ONE);
                assert_eq!(actual, table);
                for seed in [0u64, 1, 23] {
                    for length in [ell + 1, 65] {
                        let point: Vec<_> = (0..length)
                            .map(|i| if seed < 2 { F::from(seed) } else { F::from(seed + 3 * i as u64) })
                            .collect();
                        assert_eq!(interleaved.mle_evaluate(&point), padded_mle(&table, &point));
                        assert_eq!(
                            form.mle_evaluate(&point[..length - 1]),
                            padded_mle(&expected, &point[..length - 1])
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn empty_or_zero_terms_and_eq_weights_remain_zero() {
    for (scalars, points) in [(vec![], vec![]), (vec![F::ZERO], vec![F::ONE])] {
        let form = ProjectedPowerSum::new(6, 4, 1, &[F::ZERO; 4], &scalars, &points);
        let mut table = vec![F::from(7u64); 16];
        form.accumulate(&mut table, F::ONE);
        assert_eq!(table, vec![F::from(7u64); 16]);
        assert_eq!(form.mle_evaluate(&[F::from(3u64); 4]), F::ZERO);
    }
}
