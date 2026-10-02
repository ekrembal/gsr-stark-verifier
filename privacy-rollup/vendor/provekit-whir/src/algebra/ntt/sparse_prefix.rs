//! Sparse-input, prefix-output radix-two forward transform for the zkVM guest.
use ark_ff::FftField;

use super::generator;

/// Return the first `output_len` values of the forward NTT of a sparse
/// coefficient vector. Duplicate indices add; no normalization is applied.
///
/// Scratch space is bounded by the same 32,768-entry limit as the caller's
/// subgroup fast path. This is ordinary field arithmetic, not a precompile.
#[cfg_attr(feature = "tracing", tracing::instrument(skip_all))]
pub fn sparse_ntt_prefix<F: FftField>(period: usize, terms: &[(usize, F)], output_len: usize) -> Vec<F> {
    assert!(period.is_power_of_two() && period <= 32768, "bounded power-of-two NTT domain");
    assert!(output_len <= period, "NTT output prefix exceeds domain");
    let root = generator::<F>(period).expect("NTT subgroup is supported by the field");
    let bits = period.trailing_zeros();
    let mut values = vec![F::ZERO; period];
    // A true flag means "possibly nonzero". Cancellation can leave a true flag
    // on zero; that only costs work. A false flag always identifies exact zero.
    let mut active = vec![false; period];
    for &(index, coefficient) in terms {
        assert!(index < period, "NTT coefficient index exceeds domain");
        let reversed = if bits == 0 { 0 } else { index.reverse_bits() >> (usize::BITS - bits) };
        values[reversed] += coefficient;
        active[reversed] = true;
    }
    let mut roots = Vec::with_capacity(period / 2);
    let mut power = F::ONE;
    for _ in 0..period / 2 {
        roots.push(power);
        power *= root;
    }
    // After each stage, every block's first min(output_len, width) entries
    // equal its complete DFT. The next stage reads only those valid prefixes.
    // Once width exceeds output_len, unused upper outputs need not be stored.
    let mut width = 2;
    while width <= period {
        let half = width / 2;
        let step = period / width;
        for begin in (0..period).step_by(width) {
            for j in 0..half.min(output_len) {
                let left = begin + j;
                let right = left + half;
                let high_needed = j + half < output_len;
                if !active[right] {
                    if high_needed {
                        values[right] = values[left];
                        active[right] = active[left];
                    }
                    continue;
                }
                let t = if j == 0 { values[right] } else { values[right] * roots[j * step] };
                if active[left] {
                    let a = values[left];
                    values[left] = a + t;
                    if high_needed {
                        values[right] = a - t;
                    }
                } else {
                    values[left] = t;
                    if high_needed {
                        values[right] = -t;
                    }
                }
                active[left] = true;
                if high_needed {
                    active[right] = true;
                }
            }
        }
        width *= 2;
    }
    values.truncate(output_len);
    values
}
