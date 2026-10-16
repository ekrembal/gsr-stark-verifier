//! Lazy linear forms for projected, weighted univariate power sums.
//! No subgroup assumption, transform, or division is needed. All equality-basis
//! coordinates use the same most-significant-bit-first convention as WHIR.
use super::{geometric_accumulate, linear_form::LinearForm, multilinear_extend};
use ark_ff::Field;
use std::sync::Arc;

pub struct ProjectedPowerSum<F: Field> {
    ell: usize,
    captured_m: usize,
    partial_eq: Vec<F>,
    // scalar includes all free m-bit factors; powers are ascending by bit.
    terms: Vec<(F, Vec<F>)>,
}

impl<F: Field> ProjectedPowerSum<F> {
    /// The table at k is sum_{j,c,m} scalars[j] * eq_weights[c] * points[j]^m
    /// where the ell-bit window of c|m, starting at `start`, equals k.
    #[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
    pub fn new(
        mu: usize,
        ell: usize,
        start: usize,
        eq_weights: &[F],
        scalars: &[F],
        points: &[F],
    ) -> Self {
        assert!(eq_weights.len().is_power_of_two());
        assert!(ell > 0 && ell < usize::BITS as usize - 1);
        assert!(start <= mu && ell <= mu - start);
        assert_eq!(scalars.len(), points.len());
        let folded = eq_weights.len().trailing_zeros() as usize;
        assert!(folded <= ell && folded <= mu);
        let m_bits = mu - folded;
        let below = mu - start - ell;
        let above = start.saturating_sub(folded);
        let captured_m = m_bits - below - above;
        let captured_c = ell - captured_m;
        let mut partial_eq = vec![F::ZERO; 1 << captured_c];
        let mask = partial_eq.len() - 1;
        for (c, &weight) in eq_weights.iter().enumerate() {
            partial_eq[c & mask] += weight;
        }
        let mut terms = Vec::with_capacity(points.len());
        for (&scalar, &z) in scalars.iter().zip(points) {
            let mut powers = Vec::with_capacity(m_bits);
            let mut power = z;
            for _ in 0..m_bits {
                powers.push(power);
                power.square_in_place();
            }
            let mut scale = scalar;
            for (bit, &power) in powers.iter().enumerate() {
                if bit < below || bit >= below + captured_m {
                    scale *= F::ONE + power;
                }
            }
            if scale != F::ZERO {
                terms.push((scale, powers[below..below + captured_m].to_vec()));
            }
        }
        Self {
            ell,
            captured_m,
            partial_eq,
            terms,
        }
    }
}

impl<F: Field> LinearForm<F> for ProjectedPowerSum<F> {
    fn size(&self) -> usize {
        1 << self.ell
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(skip_all, name = "projected_power_sum_mle")
    )]
    fn mle_evaluate(&self, point: &[F]) -> F {
        assert!(point.len() >= self.ell);
        let extra = point.len() - self.ell;
        let captured_c = self.ell - self.captured_m;
        let prefix_factor: F = point[..extra].iter().map(|x| F::ONE - x).product();
        let c_factor = multilinear_extend(&self.partial_eq, &point[extra..extra + captured_c]);
        let m_point = &point[extra + captured_c..];
        let mut total = F::ZERO;
        for (scalar, powers) in &self.terms {
            let mut value = *scalar;
            for (&y, &power) in m_point.iter().zip(powers.iter().rev()) {
                value *= F::ONE + y * (power - F::ONE);
            }
            total += value;
        }
        prefix_factor * c_factor * total
    }

    fn accumulate(&self, accumulator: &mut [F], scalar: F) {
        assert_eq!(accumulator.len(), self.size());
        let mut inner = vec![F::ZERO; 1 << self.captured_m];
        let scalars: Vec<_> = self.terms.iter().map(|(s, _)| *s).collect();
        let points: Vec<_> = self
            .terms
            .iter()
            .map(|(_, p)| p.first().copied().unwrap_or(F::ONE))
            .collect();
        geometric_accumulate(&mut inner, scalars, &points);
        for (chunk, &eq) in accumulator
            .chunks_exact_mut(inner.len())
            .zip(&self.partial_eq)
        {
            let factor = scalar * eq;
            for (dest, &value) in chunk.iter_mut().zip(&inner) {
                *dest += factor * value;
            }
        }
    }
}

/// Interleave the same projected table at even/odd indices with exact scales.
/// The selector is the last MLE coordinate, including for longer input points.
pub struct InterleavedProjection<F: Field> {
    projection: Arc<ProjectedPowerSum<F>>,
    even: F,
    odd: F,
}

impl<F: Field> InterleavedProjection<F> {
    pub fn new(projection: Arc<ProjectedPowerSum<F>>, even: F, odd: F) -> Self {
        Self {
            projection,
            even,
            odd,
        }
    }
}

impl<F: Field> LinearForm<F> for InterleavedProjection<F> {
    fn size(&self) -> usize {
        2 * self.projection.size()
    }

    fn mle_evaluate(&self, point: &[F]) -> F {
        assert!(point.len() > self.projection.ell);
        let (&selector, prefix) = point.split_last().unwrap();
        self.projection.mle_evaluate(prefix)
            * ((F::ONE - selector) * self.even + selector * self.odd)
    }

    fn accumulate(&self, accumulator: &mut [F], scalar: F) {
        assert_eq!(accumulator.len(), self.size());
        let mut table = vec![F::ZERO; self.projection.size()];
        self.projection.accumulate(&mut table, scalar);
        for (pair, value) in accumulator.chunks_exact_mut(2).zip(table) {
            pair[0] += self.even * value;
            pair[1] += self.odd * value;
        }
    }
}
