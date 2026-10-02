/- The four addition-only formulas used by external_transpose. Integer
   identities also hold after reduction modulo a prime. This file does not
   verify Rust extraction, array indexing, the reverse traversal, or VK binding. -/
import Std

namespace Aggregation

theorem transpose_lane0 (a b c d : Int) :
    4*(a+b)+a+(c+d) = 5*a+4*b+c+d := by omega

theorem transpose_lane1 (a b c d : Int) :
    6*(a+b)+a+(c+d)+(c+c) = 7*a+6*b+3*c+d := by omega

theorem transpose_lane2 (a b c d : Int) :
    (a+b)+4*(c+d)+c = a+b+5*c+4*d := by omega

theorem transpose_lane3 (a b c d : Int) :
    (a+b)+(a+a)+6*(c+d)+c = 3*a+b+7*c+6*d := by omega

#print axioms transpose_lane0
#print axioms transpose_lane1
#print axioms transpose_lane2
#print axioms transpose_lane3

end Aggregation
