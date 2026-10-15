use ark_ff::{AdditiveGroup, FftField, Field};
use provekit_common::FieldElement;
use whir::algebra::{fields::Field64, ntt};

fn dense_reference<F: FftField>(period: usize, terms: &[(usize, F)]) -> Vec<F> {
    let mut values = vec![F::ZERO; period];
    for &(index, coefficient) in terms {
        values[index] += coefficient;
    }
    ntt::ntt(&mut values);
    values
}

fn direct_reference<F: FftField>(period: usize, terms: &[(usize, F)]) -> Vec<F> {
    let generator = ntt::generator::<F>(period).unwrap();
    (0..period)
        .map(|k| terms.iter().map(|&(index, coefficient)| coefficient * generator.pow([(index * k) as u64])).sum())
        .collect()
}

fn check_prefixes<F: FftField>(period: usize, terms: &[(usize, F)], lengths: impl IntoIterator<Item = usize>) {
    let expected = dense_reference(period, terms);
    if period <= 128 {
        assert_eq!(expected, direct_reference(period, terms), "reference convention for period={period}");
    }
    for length in lengths {
        assert_eq!(
            ntt::sparse_ntt_prefix(period, terms, length),
            expected[..length],
            "period={period}, prefix={length}, terms={}",
            terms.len()
        );
    }
}

fn small_domains<F: FftField>() {
    for period in [1usize, 2, 4, 8, 16, 32, 64, 128] {
        let mut patterns = vec![
            vec![],
            vec![(0, F::ZERO), (period - 1, F::ZERO)],
            vec![(0, F::ONE)],
            vec![(period / 2, -F::ONE)],
            vec![(period - 1, F::from(19u64))],
            // Duplicate terms cancel before the transform, leaving conservative
            // "possibly nonzero" flags which must not change the answer.
            vec![(0, F::from(23u64)), (0, -F::from(23u64)), (period - 1, F::ZERO)],
            (0..period).map(|i| (i, if i % 2 == 0 { F::ONE } else { -F::ONE })).collect(),
        ];
        for seed in [1u64, 19, 91] {
            let mut state = seed;
            let mut scalar = F::from(seed);
            let mut terms = Vec::new();
            for _ in 0..period * 2 + 1 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                scalar = scalar.square() + F::from(17u64);
                terms.push(((state >> 32) as usize % period, scalar));
            }
            patterns.push(terms);
        }
        for terms in patterns {
            check_prefixes(period, &terms, 0..=period);
        }
    }
}

#[test]
fn sparse_prefix_matches_dense_and_direct_transforms_over_bn254() {
    small_domains::<FieldElement>();
}

#[test]
fn sparse_prefix_matches_dense_and_direct_transforms_over_field64() {
    small_domains::<Field64>();
}

#[test]
fn every_small_support_mask_and_prefix_matches_reference() {
    for period in [1usize, 2, 4, 8] {
        for mask in 0..1usize << period {
            let terms: Vec<_> =
                (0..period).filter(|i| mask & (1 << i) != 0).map(|i| (i, Field64::from(i as u64 + 3))).collect();
            check_prefixes(period, &terms, 0..=period);
        }
    }
}

#[test]
fn sparse_prefix_matches_fixed_whir_dimensions_and_boundaries() {
    type F = FieldElement;
    // Initial/first-round domains and both output windows of the fixed key.
    for (period, length) in [(2048, 512), (32768, 4096), (1024, 512), (16384, 4096)] {
        let mut terms: Vec<_> =
            (0..189).map(|i| ((i * 157 + i * i * 37) % period, F::from(17u64).pow([i as u64]))).collect();
        terms.extend([(0, F::ONE), (0, -F::ONE), (period - 1, F::from(23u64)), (period - 1, F::ZERO)]);
        check_prefixes(period, &terms, [0, 1, 2, 3, length - 1, length, length + 1, period / 2, period - 1, period]);
        check_prefixes::<F>(period, &[], [length, period]);
        check_prefixes(period, &[(period - 1, F::ONE), (period - 1, -F::ONE)], [length, period]);
    }
}

#[test]
fn sparse_prefix_rejects_invalid_bounds() {
    for (period, index, length) in [(0, 0, 0), (3, 0, 1), (65536, 0, 1), (4, 4, 1), (4, 0, 5)] {
        assert!(
            std::panic::catch_unwind(|| ntt::sparse_ntt_prefix(period, &[(index, FieldElement::ONE)], length)).is_err(),
            "accepted period={period}, index={index}, prefix={length}"
        );
    }
}
