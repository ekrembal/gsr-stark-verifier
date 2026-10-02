/- Bounds for the optional host packed Poseidon2 implementation.
   This proves natural-number bounds, not Rust/LLVM refinement, Montgomery
   congruence, lane indexing, hash equivalence, or protocol soundness. -/
import Std

namespace Aggregation.PackedBabyBear

def p : Nat := 2013265921
def radix : Nat := 2^32

theorem addition_fits (a b : Nat) (ha : a < p) (hb : b < p) :
    a + b < radix := by
  simp [p, radix] at *
  omega

theorem multiplication_fits (a b red : Nat)
    (ha : a < p) (hb : b < p) (hr : red < radix) :
    a*b + red*p < 2^64 := by
  have hab : a*b ≤ (p-1)*(p-1) := Nat.mul_le_mul (by omega) (by omega)
  have hred : red*p ≤ (radix-1)*p := Nat.mul_le_mul_right p (by omega)
  have hbound : (p-1)*(p-1) + (radix-1)*p < 2^64 := by decide
  omega

theorem reduction_numerator_bound (a b red : Nat)
    (ha : a < p) (hb : b < p) (hr : red < radix) :
    a*b + red*p < 2*p*radix := by
  have hab : a*b ≤ (p-1)*(p-1) := Nat.mul_le_mul (by omega) (by omega)
  have hred : red*p ≤ (radix-1)*p := Nat.mul_le_mul_right p (by omega)
  have hbound : (p-1)*(p-1) + (radix-1)*p < 2*p*radix := by decide
  omega

theorem single_subtraction_canonical (x : Nat) (hx : x < 2*p) :
    (if x ≥ p then x-p else x) < p := by
  split <;> omega

theorem montgomery_constant : (p * 2281701377) % radix = 1 := by decide

#print axioms addition_fits
#print axioms multiplication_fits
#print axioms reduction_numerator_bound
#print axioms single_subtraction_canonical
#print axioms montgomery_constant

end Aggregation.PackedBabyBear
