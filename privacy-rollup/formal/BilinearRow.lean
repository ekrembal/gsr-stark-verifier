/- Narrow equivalence behind direct row evaluation. The algebraic laws are
   explicit hypotheses, not a proof of BN254 arithmetic. This does not verify
   the generated matrix, split offsets, cache, traversal, or Rust extraction. -/
import Std

namespace Aggregation

def rowDot {F : Type} (add mul : F → F → F) (zero : F) : List (F × F) → F
  | [] => zero
  | (coefficient, column) :: tail => add (mul coefficient column) (rowDot add mul zero tail)

def weightedEntries {F : Type} (add mul : F → F → F) (zero weight : F) : List (F × F) → F
  | [] => zero
  | (coefficient, column) :: tail =>
    add (mul (mul weight coefficient) column) (weightedEntries add mul zero weight tail)

theorem direct_row_equivalent {F : Type} (add mul : F → F → F) (zero : F)
    (mul_zero : ∀ x, mul x zero = zero)
    (distribute : ∀ x a b, mul x (add a b) = add (mul x a) (mul x b))
    (associate : ∀ a b c, mul a (mul b c) = mul (mul a b) c)
    (weight : F) (entries : List (F × F)) :
    mul weight (rowDot add mul zero entries) = weightedEntries add mul zero weight entries := by
  induction entries with
  | nil => exact mul_zero weight
  | cons entry tail ih =>
    rcases entry with ⟨coefficient, column⟩
    simp only [rowDot, weightedEntries, distribute, associate, ih]

#print axioms direct_row_equivalent
end Aggregation
