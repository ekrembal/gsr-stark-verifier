/- Narrow algebraic equivalence for the small-coefficient scatter optimization.
   The laws below are explicit hypotheses. This does not verify BN254 arithmetic,
   Rust extraction, memory safety, the transcript, or protocol soundness. -/
import Std

namespace Aggregation

def powerTwo {F : Type} (add : F → F → F) (one : F) : Nat → F
  | 0 => one
  | n + 1 => add (powerTwo add one n) (powerTwo add one n)

def doubled {F : Type} (add : F → F → F) (x : F) : Nat → F
  | 0 => x
  | n + 1 => add (doubled add x n) (doubled add x n)

theorem doubling_equivalent {F : Type} (add mul : F → F → F) (one : F)
    (mul_one : ∀ x, mul x one = x)
    (distribute : ∀ x a b, mul x (add a b) = add (mul x a) (mul x b))
    (x : F) (n : Nat) : doubled add x n = mul x (powerTwo add one n) := by
  induction n with
  | zero => exact (mul_one x).symm
  | succ n ih => simp only [doubled, powerTwo, distribute, ih]

theorem negative_doubling_equivalent {F : Type} (add mul : F → F → F)
    (neg : F → F) (one : F)
    (mul_one : ∀ x, mul x one = x)
    (distribute : ∀ x a b, mul x (add a b) = add (mul x a) (mul x b))
    (mul_neg : ∀ x a, mul x (neg a) = neg (mul x a))
    (x : F) (n : Nat) : neg (doubled add x n) = mul x (neg (powerTwo add one n)) := by
  rw [doubling_equivalent add mul one mul_one distribute, mul_neg]

/- Replacing each contribution with an equal optimized contribution preserves
   an ordered accumulation, for every initial accumulator. No reordering law
   is needed; Rust keeps the contribution order for each matrix column. -/
theorem accumulation_equivalent {F E : Type} (add : F → F → F)
    (reference optimized : E → F) (same : ∀ e, reference e = optimized e)
    (entries : List E) (initial : F) :
    entries.foldl (fun acc e => add acc (reference e)) initial =
    entries.foldl (fun acc e => add acc (optimized e)) initial := by
  induction entries generalizing initial with
  | nil => rfl
  | cons e rest ih =>
    simp only [List.foldl_cons]
    rw [same e]
    exact ih _

/- A cache is scoped by both row and coefficient index. A hit can only return
   the product stored for that same row; otherwise compute the exact product.
   Rust establishes this invariant when storing, and checks the row tag on each
   lookup. Arrays and their indexing are outside this abstract model. -/
theorem row_cache_equivalent {F : Type} (tag row : Nat) (cached product : F)
    (valid_hit : tag = row → cached = product) :
    (if tag = row then cached else product) = product := by
  by_cases h : tag = row
  · simp [h, valid_hit h]
  · simp [h]

theorem triple_equivalent {F : Type} (add mul : F → F → F) (one : F)
    (mul_one : ∀ x, mul x one = x)
    (distribute : ∀ x a b, mul x (add a b) = add (mul x a) (mul x b))
    (x : F) : add (add x x) x = mul x (add (add one one) one) := by
  simp only [distribute, mul_one]

/- Rust's general path multiplies coefficient * row_weight. The field's
   commutative multiplication law connects that order to the lemmas above. -/
theorem left_triple_equivalent {F : Type} (add mul : F → F → F) (one : F)
    (mul_one : ∀ x, mul x one = x)
    (distribute : ∀ x a b, mul x (add a b) = add (mul x a) (mul x b))
    (commute : ∀ x y, mul x y = mul y x)
    (x : F) : add (add x x) x = mul (add (add one one) one) x := by
  rw [commute (add (add one one) one) x]
  exact triple_equivalent add mul one mul_one distribute x

#print axioms doubling_equivalent
#print axioms negative_doubling_equivalent
#print axioms accumulation_equivalent
#print axioms row_cache_equivalent
#print axioms triple_equivalent
#print axioms left_triple_equivalent

end Aggregation
