/- Narrow algebraic contract for the experimental fused Montgomery kernel.
   These hypotheses describe arithmetic after reduction modulo p. This does
   not verify the bytecode, memory binding, carry constraints, Rust, Fiat-Shamir,
   or the connection between field equality and canonical integer encodings. -/
import Std

namespace Aggregation

theorem montgomery_relation {F : Type} (add mul : F → F → F) (zero one : F)
    (add_zero : ∀ x, add x zero = x)
    (zero_add : ∀ x, add zero x = x)
    (mul_zero : ∀ x, mul x zero = zero)
    (zero_mul : ∀ x, mul zero x = zero)
    (mul_one : ∀ x, mul x one = x)
    (assoc : ∀ x y z, mul (mul x y) z = mul x (mul y z))
    (a b q r radix inverse : F)
    (invertible : mul radix inverse = one)
    (relation : add (mul a b) (mul zero radix) =
      add (mul q zero) (mul r radix)) :
    r = mul (mul a b) inverse := by
  simp only [zero_mul, mul_zero, add_zero, zero_add] at relation
  rw [relation, assoc, invertible, mul_one]

/- Concrete bounds used by the generator. Even arbitrary byte-constrained
   carry witnesses cannot hide an integer coefficient by wrapping BabyBear. -/
theorem coefficient_no_wrap :
    4162110 + 257 * (127 * 16384 + 255 * 256 + 255) < 2013265921 := by decide

theorem honest_carry_fits : 16322 < 2^21 := by decide

theorem radix_coprime :
    Nat.gcd (2^256)
      21888242871839275222246405745257275088548364400416034343698204186575808495617 = 1 := by decide

#print axioms montgomery_relation
#print axioms coefficient_no_wrap
#print axioms honest_carry_fits
#print axioms radix_coprime

end Aggregation
