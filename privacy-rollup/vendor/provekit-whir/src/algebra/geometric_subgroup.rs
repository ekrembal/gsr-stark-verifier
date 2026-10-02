//! Exact weighted power sums using the existing forward NTT for subgroup points.
use ark_ff::FftField;

use super::{geometric_accumulate, ntt};

/// Compute the same sum as [`geometric_accumulate`]. Points in the order-`period`
/// subgroup are accumulated as sparse coefficients and transformed; arbitrary
/// points retain the original path. This changes no transcript or protocol data.
/// Unsupported or uneconomical domains fall back to the original algorithm.
#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
pub fn geometric_accumulate_subgroup<F: FftField>(accumulator: &mut [F], scalars: Vec<F>, points: &[F], period: usize) {
    // Bound scratch space independently of the caller's configuration. Preserve
    // the original zip behavior when lengths differ.
    let work = period.saturating_mul(period.trailing_zeros() as usize);
    if !period.is_power_of_two()
        || period > 32768
        || scalars.len() != points.len()
        || work >= accumulator.len().saturating_mul(points.len())
    {
        return geometric_accumulate(accumulator, scalars, points);
    }
    let Some(generator) = ntt::generator::<F>(period) else {
        return geometric_accumulate(accumulator, scalars, points);
    };
    let mut in_domain = Vec::new();
    let mut other_scalars = Vec::new();
    let mut other_points = Vec::new();
    for (j, (&scalar, &point)) in scalars.iter().zip(points).enumerate() {
        if point.pow([period as u64]) == F::ONE {
            in_domain.push(j);
        } else {
            other_scalars.push(scalar);
            other_points.push(point);
        }
    }
    if work >= accumulator.len().saturating_mul(in_domain.len()) {
        return geometric_accumulate(accumulator, scalars, points);
    }
    let generator_inverse = generator.inverse().expect("subgroup generator is nonzero");
    let mut coefficients = vec![F::ZERO; period];
    for j in in_domain {
        let index = discrete_log(points[j], generator, generator_inverse, period.trailing_zeros());
        // Repeated points must add, including collisions after a squaring ladder.
        coefficients[index] += scalars[j];
    }
    // Forward convention: output[k] = sum_i coefficients[i] * generator^(i*k).
    // No inverse or normalization is involved. Periodic extension is exact.
    ntt::ntt(&mut coefficients);
    for (entry, contribution) in accumulator.iter_mut().zip(coefficients.iter().cycle()) {
        *entry += contribution;
    }
    if !other_points.is_empty() {
        geometric_accumulate(accumulator, other_scalars, &other_points);
    }
}

// Membership was checked before calling this radix-two discrete logarithm.
// Keep the reconstruction check in release builds as well.
fn discrete_log<F: FftField>(target: F, generator: F, generator_inverse: F, bits: u32) -> usize {
    let mut index = 0;
    let mut current = target;
    let mut inverse_power = generator_inverse;
    for bit in 0..bits {
        let mut test = current;
        for _ in 0..bits - bit - 1 {
            test.square_in_place();
        }
        if test != F::ONE {
            index |= 1 << bit;
            current *= inverse_power;
        }
        inverse_power.square_in_place();
    }
    assert_eq!(generator.pow([index as u64]), target, "subgroup discrete log reconstruction");
    index
}
