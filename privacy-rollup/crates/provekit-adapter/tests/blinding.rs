use ark_ff::{AdditiveGroup, Field};
use provekit_common::FieldElement as F;
use whir::algebra::{geometric_accumulate, geometric_accumulate_subgroup, ntt};

fn compare(points: &[F], scalars: Vec<F>, length: usize, period: usize) {
    let mut reference: Vec<_> = (0..length).map(|i| F::from(i as u64 + 7)).collect();
    let mut optimized = reference.clone();
    geometric_accumulate(&mut reference, scalars.clone(), points);
    geometric_accumulate_subgroup(&mut optimized, scalars, points, period);
    assert_eq!(reference, optimized, "length={length}, period={period}");
}

#[test]
fn subgroup_power_sums_match_reference_at_fixed_dimensions() {
    for (period, length) in [(2048, 512), (32768, 4096)] {
        let generator = ntt::generator::<F>(period).unwrap();
        let mut points: Vec<_> = (0..189).map(|i| generator.pow([((i * 157 + i * i * 37) % period) as u64])).collect();
        // Zero, one, negative one, OOD points and repeated roots are all valid
        // algebraic inputs. Classification must be exact for every one of them.
        points.extend([F::ZERO, F::ONE, -F::ONE, F::from(19u64), F::from(123u64), generator]);
        let scalars = (0..points.len()).map(|i| F::from(17u64).pow([i as u64])).collect();
        compare(&points, scalars, length, period);
    }
}

#[test]
fn subgroup_power_sums_cover_periodicity_collisions_and_fallbacks() {
    for period in [1usize, 2, 4, 16, 64] {
        let generator = ntt::generator::<F>(period).unwrap();
        let points: Vec<_> = (0..64).map(|i| generator.pow([(i % period) as u64])).collect();
        let scalars = (0..points.len()).map(|i| F::from(i as u64 + 1)).collect();
        compare(&points, scalars, period * 2 + 1, period);
        compare(&points, vec![F::ZERO; points.len()], period * 2 + 1, period);
        compare(&vec![generator; 64], vec![F::ONE; 64], period * 2 + 1, period);
    }
    let points = [F::ZERO, F::ONE, F::from(5u64), F::from(19u64)];
    for period in [0, 3, 16, 65536] {
        for length in [0, 1, 33] {
            compare(&points, vec![F::ONE; points.len()], length, period);
        }
    }
    compare(&[], vec![], 32, 16);
    compare(&points, vec![], 32, 16);
    compare(&[], vec![F::ONE; 4], 32, 16);
    compare(&points, vec![F::ONE; 2], 32, 16);
}
