use ark_ff::{AdditiveGroup, Field};
use provekit_common::{
    utils::sumcheck::{calculate_eq_iterative, calculate_evaluations_over_boolean_hypercube_for_eq},
    FieldElement as F,
};

#[test]
fn iterative_prefix_tables_match_independent_bit_products() {
    for dimension in [0usize, 1, 2, 3, 7, 13, 16] {
        let full = 1usize << dimension;
        for seed in [0u64, 1, 2, 19] {
            let point: Vec<_> = (0..dimension)
                .map(|i| match seed {
                    0 => F::ZERO,
                    1 => F::ONE,
                    2 => -F::ONE,
                    _ => F::from(seed + 13 * i as u64),
                })
                .collect();
            let reference: Vec<_> = (0..full)
                .map(|index| {
                    point
                        .iter()
                        .enumerate()
                        .map(|(bit, &x)| if index & (1 << (dimension - 1 - bit)) == 0 { F::ONE - x } else { x })
                        .product::<F>()
                })
                .collect();
            for len in [0, 1, full / 2, full.saturating_sub(1), full]
                .into_iter()
                .chain([5530, 38819, 46275].into_iter().filter(|n| *n <= full))
            {
                let got = calculate_eq_iterative(&point, len);
                assert_eq!(got, reference[..len], "dim={dimension},seed={seed},len={len}");
                if len > 0 {
                    assert_eq!(got, calculate_evaluations_over_boolean_hypercube_for_eq(&point, len));
                }
            }
        }
    }
}
