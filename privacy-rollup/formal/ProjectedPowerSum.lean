/- Narrow algebraic factorization used by the lazy projected power sum.
   A pair is the weight for one Boolean bit being zero or one. Free geometric
   bits use (1,z^(2^k)); captured bits use (1-y,y*z^(2^k)).
   This proves recursive two-choice expansion equals a product of sums under
   the explicit distributive law. It does not prove Rust code, bit-window
   indexing, equality marginals, transcript binding, or WHIR soundness. -/
import Std

namespace Aggregation

def expandedBits {F : Type} (add mul : F → F → F) (one : F) : List (F × F) → F
  | [] => one
  | (a,b) :: tail => add (mul a (expandedBits add mul one tail))
                          (mul b (expandedBits add mul one tail))

def factoredBits {F : Type} (add mul : F → F → F) (one : F) : List (F × F) → F
  | [] => one
  | (a,b) :: tail => mul (add a b) (factoredBits add mul one tail)

theorem bit_sum_factorization {F : Type} (add mul : F → F → F) (one : F)
    (distribute : ∀ a b x, mul (add a b) x = add (mul a x) (mul b x))
    (bits : List (F × F)) :
    expandedBits add mul one bits = factoredBits add mul one bits := by
  induction bits with
  | nil => rfl
  | cons entry tail ih =>
    rcases entry with ⟨a,b⟩
    simp only [expandedBits, factoredBits, distribute, ih]

#print axioms bit_sum_factorization
end Aggregation
