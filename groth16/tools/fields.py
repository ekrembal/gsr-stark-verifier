"""BN254 tower-field Script emitters and reference twins.

Each emitter consumes the coefficients of its operands, least-significant basis
coefficient first, and leaves the result in that same order. Values are reduced
modulo p at each base-field operation. The field tower is Fp2[u]/(u^2+1),
Fp6[v]/(v^3-(9+u)), and Fp12[w]/(w^2-v).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "risc0-succinct/tools"))
from gsr import Script

from bn254 import P


def _basis(field: str) -> list[tuple[int, int, int]]:
    if field == "Fp":
        return [(0, 0, 0)]
    if field == "Fp2":
        return [(u, 0, 0) for u in range(2)]
    if field == "Fp6":
        return [(u, v, 0) for v in range(3) for u in range(2)]
    if field == "Fp12":
        return [(u, v, w) for w in range(2) for v in range(3) for u in range(2)]
    raise ValueError(field)


def _reduce_monomial(u: int, v: int, w: int, scale: int = 1) -> dict[tuple[int, int, int], int]:
    terms = {(u, v, w): scale}
    while any(vv >= 3 or ww >= 2 or uu >= 2 for uu, vv, ww in terms):
        reduced: dict[tuple[int, int, int], int] = {}
        for (uu, vv, ww), coeff in terms.items():
            if ww >= 2:
                reduced[(uu, vv + ww // 2, ww % 2)] = (
                    reduced.get((uu, vv + ww // 2, ww % 2), 0) + coeff
                )
            elif vv >= 3:
                v0 = vv % 3
                q = vv // 3
                reduced[(uu, v0, ww)] = reduced.get((uu, v0, ww), 0) + coeff * 9**q
                # (9+u)^q, expanded exactly; q is at most 2 for these basis products.
                for k in range(1, q + 1):
                    from math import comb

                    key = (uu + k, v0, ww)
                    reduced[key] = reduced.get(key, 0) + coeff * comb(q, k) * 9 ** (q - k)
            else:
                q = uu // 2
                reduced[(uu % 2, vv, ww)] = reduced.get((uu % 2, vv, ww), 0) + coeff * (-1) ** q
        terms = {key: value for key, value in reduced.items() if value}
    return terms


@dataclass(frozen=True)
class Field:
    name: str
    basis: tuple[tuple[int, int, int], ...]
    index: dict[tuple[int, int, int], int]
    tensor: tuple[tuple[tuple[tuple[int, int], ...], ...], ...]

    @classmethod
    def create(cls, name: str) -> "Field":
        basis = _basis(name)
        index = {monomial: i for i, monomial in enumerate(basis)}
        products = []
        for left in basis:
            row = []
            for right in basis:
                terms = _reduce_monomial(*(a + b for a, b in zip(left, right, strict=True)))
                row.append(tuple((index[monomial], coeff) for monomial, coeff in terms.items()))
            products.append(tuple(row))
        return cls(name, tuple(basis), index, tuple(products))

    @property
    def degree(self) -> int:
        return len(self.basis)

    def normalize(self, value: list[int] | tuple[int, ...]) -> tuple[int, ...]:
        if len(value) != self.degree:
            raise ValueError(f"{self.name} requires {self.degree} coefficients")
        return tuple(int(x) % P for x in value)

    def add(self, a, b) -> tuple[int, ...]:
        a, b = self.normalize(a), self.normalize(b)
        return tuple((x + y) % P for x, y in zip(a, b, strict=True))

    def sub(self, a, b) -> tuple[int, ...]:
        a, b = self.normalize(a), self.normalize(b)
        return tuple((x - y) % P for x, y in zip(a, b, strict=True))

    def add_lazy(self, a, b, left_bound: int = 1, right_bound: int = 1):
        a, b = tuple(map(int, a)), tuple(map(int, b))
        if len(a) != self.degree or len(b) != self.degree:
            raise ValueError(f"{self.name} requires {self.degree} coefficients")
        if left_bound < 1 or right_bound < 1:
            raise ValueError("lazy bounds must be positive")
        if any(not 0 <= value < left_bound * P for value in a):
            raise AssertionError("left operand exceeds its lazy bound")
        if any(not 0 <= value < right_bound * P for value in b):
            raise AssertionError("right operand exceeds its lazy bound")
        bound = left_bound + right_bound
        result = tuple(x + y for x, y in zip(a, b, strict=True))
        if any(not 0 <= value < bound * P for value in result):
            raise AssertionError("lazy addition exceeds its output bound")
        return result, bound

    def sub_lazy(self, a, b, left_bound: int = 1, right_bound: int = 1):
        a, b = tuple(map(int, a)), tuple(map(int, b))
        if len(a) != self.degree or len(b) != self.degree:
            raise ValueError(f"{self.name} requires {self.degree} coefficients")
        if left_bound < 1 or right_bound < 1:
            raise ValueError("lazy bounds must be positive")
        if any(not 0 <= value < left_bound * P for value in a):
            raise AssertionError("left operand exceeds its lazy bound")
        if any(not 0 <= value < right_bound * P for value in b):
            raise AssertionError("right operand exceeds its lazy bound")
        bound = left_bound + right_bound
        result = tuple(x + right_bound * P - y for x, y in zip(a, b, strict=True))
        if any(not 0 <= value < bound * P for value in result):
            raise AssertionError("lazy subtraction exceeds its output bound")
        return result, bound

    def mul_sparse(self, a, b, rhs_indices: tuple[int, ...]) -> tuple[int, ...]:
        a = self.normalize(a)
        if len(b) != len(rhs_indices) or any(i < 0 or i >= self.degree for i in rhs_indices):
            raise ValueError("sparse multiplier does not match its coefficient indices")
        out = [0] * self.degree
        for i, row in enumerate(self.tensor):
            for right, basis_index in enumerate(rhs_indices):
                for k, factor in row[basis_index]:
                        out[k] += a[i] * (int(b[right]) % P) * factor
        return tuple(x % P for x in out)

    def mul_line(self, a, b, rhs_indices: tuple[int, ...]) -> tuple[int, ...]:
        a = self.normalize(a)
        if len(b) != len(rhs_indices) or any(i < 0 or i >= self.degree for i in rhs_indices):
            raise ValueError("line multiplier does not match its coefficient indices")
        out = list(a)
        for left, row in enumerate(self.tensor):
            for right, basis_index in enumerate(rhs_indices):
                for output, factor in row[basis_index]:
                    out[output] += a[left] * (int(b[right]) % P) * factor
        return tuple(value % P for value in out)

    def mul(self, a, b) -> tuple[int, ...]:
        a, b = self.normalize(a), self.normalize(b)
        out = [0] * self.degree
        for i, row in enumerate(self.tensor):
            if not a[i]:
                continue
            for j, c in enumerate(b):
                if c:
                    for k, factor in row[j]:
                        out[k] += a[i] * c * factor
        return tuple(x % P for x in out)

    def square(self, a) -> tuple[int, ...]:
        return self.mul(a, a)

    def frobenius(self, a, power: int) -> tuple[int, ...]:
        if power < 0:
            raise ValueError("Frobenius power must be nonnegative")
        out = self.normalize(a)
        for _ in range(power):
            result = [0] * self.degree
            base = out
            exponent = P
            accumulator = tuple([1] + [0] * (self.degree - 1))
            while exponent:
                if exponent & 1:
                    accumulator = self.mul(accumulator, base)
                base = self.square(base)
                exponent >>= 1
            out = accumulator
        return out

    def emit(
        self,
        operation: str,
        rhs_indices: tuple[int, ...] | None = None,
        input_bounds: tuple[int, int] = (1, 1),
    ) -> Script:
        n = self.degree
        right = tuple(range(n)) if rhs_indices is None else tuple(rhs_indices)
        if operation == "frobenius":
            raise ValueError("use emit_frobenius()")
        if operation not in ("add", "sub", "mul", "square", "sparse_mul"):
            raise ValueError(operation)
        if operation == "square":
            if self.name == "Fp12":
                return self._emit_symmetric_square()
            script = Script()
            for _ in range(n):
                script.int(n - 1).op("PICK")
            script.extend(self._emit_mul(tuple(range(n))))
            return script
        if operation in ("mul", "sparse_mul"):
            return self._emit_mul(right)
        if len(right) != n:
            raise ValueError("add/sub require a full right-hand element")
        return self._emit_add_sub(operation, input_bounds)

    def _copy(self, script: Script, original_depth: int, index: int) -> None:
        depth = original_depth - index - 1
        if depth == 0:
            script.op("DUP")
        elif depth == 1:
            script.op("OVER")
        else:
            script.int(depth).op("PICK")

    def _clear_inputs_and_restore(self, script: Script, input_count: int, output_count: int) -> None:
        while input_count >= 2:
            script.op("2DROP")
            input_count -= 2
        if input_count:
            script.op("DROP")
        for _ in range(output_count):
            script.op("FROMALTSTACK")

    def _emit_add_sub(self, operation: str, input_bounds: tuple[int, int]) -> Script:
        n = self.degree
        left_bound, right_bound = input_bounds
        if left_bound < 1 or right_bound < 1:
            raise ValueError("lazy bounds must be positive")
        script = Script()
        for k in reversed(range(n)):
            self._copy(script, 2 * n, k)
            self._copy(script, 2 * n + 1, n + k)
            if operation == "add":
                script.op("ADD")
            else:
                script.op("SWAP").int(right_bound * P).op("ADD", "SWAP", "SUB")
            script.op("TOALTSTACK")
        self._clear_inputs_and_restore(script, 2 * n, n)
        return script

    def _emit_mul(self, rhs_indices: tuple[int, ...]) -> Script:
        n = self.degree
        if any(index < 0 or index >= n for index in rhs_indices):
            raise ValueError("sparse coefficient index out of range")
        input_count = n + len(rhs_indices)
        script = Script()
        for output in reversed(range(n)):
            terms = []
            for left, row in enumerate(self.tensor):
                for right_pos, right_basis in enumerate(rhs_indices):
                    for out_index, factor in row[right_basis]:
                        if out_index == output and factor:
                            terms.append((left, right_pos, factor))
            if terms and all(factor > 0 for _, _, factor in terms):
                left, right_pos, factor = terms[0]
                self._copy(script, input_count, left)
                self._copy(script, input_count + 1, n + right_pos)
                script.op("MUL")
                if factor != 1:
                    script.int(factor).op("MUL")
                for left, right_pos, factor in terms[1:]:
                    self._copy(script, input_count + 1, left)
                    self._copy(script, input_count + 2, n + right_pos)
                    script.op("MUL")
                    if factor != 1:
                        script.int(factor).op("MUL")
                    script.op("ADD")
                script.int(P).op("MOD", "TOALTSTACK")
                continue
            offset = sum(
                P ** 2 * abs(factor)
                for _, _, factor in terms
                if factor < 0
            )
            script.int(offset)
            for left, right_pos, factor in terms:
                self._copy(script, input_count + 1, left)
                self._copy(script, input_count + 2, n + right_pos)
                script.op("MUL")
                magnitude = abs(factor)
                if magnitude != 1:
                    script.int(magnitude).op("MUL")
                if factor < 0:
                    script.op("SUB")
                else:
                    script.op("ADD")
            script.int(P).op("MOD")
            script.op("TOALTSTACK")
        self._clear_inputs_and_restore(script, input_count, n)
        return script

    def _emit_symmetric_square(self) -> Script:
        n = self.degree
        pairs = [(left, right) for left in range(n) for right in range(left, n)]
        script = Script()
        for pair_index, (left, right) in enumerate(pairs):
            stack_size = n + pair_index
            self._copy(script, stack_size, left)
            self._copy(script, stack_size + 1, right)
            script.op("MUL")

        products = {pair: n + index for index, pair in enumerate(pairs)}
        stack_size = n + len(pairs)
        for output in reversed(range(n)):
            terms = []
            for pair in pairs:
                for out_index, factor in self.tensor[pair[0]][pair[1]]:
                    if out_index == output:
                        terms.append((products[pair], factor, pair[0] != pair[1]))
            offset = sum(
                P ** 2 * abs(factor) * (2 if doubled else 1)
                for _, factor, doubled in terms
                if factor < 0
            )
            script.int(offset)
            for product_index, factor, doubled in terms:
                self._copy(script, stack_size + 1, product_index)
                if doubled:
                    script.op("DUP", "ADD")
                magnitude = abs(factor)
                if magnitude != 1:
                    script.int(magnitude).op("MUL")
                if factor < 0:
                    script.op("SUB")
                else:
                    script.op("ADD")
            script.int(P).op("MOD", "TOALTSTACK")

        self._clear_inputs_and_restore(script, stack_size, n)
        return script

    def emit_line_mul(self, rhs_indices: tuple[int, ...]) -> Script:
        n = self.degree
        if any(index < 0 or index >= n for index in rhs_indices):
            raise ValueError("line coefficient index out of range")
        input_count = n + len(rhs_indices)
        script = Script()
        for output in reversed(range(n)):
            terms = []
            for left, row in enumerate(self.tensor):
                for right_pos, right_basis in enumerate(rhs_indices):
                    for out_index, factor in row[right_basis]:
                        if out_index == output and factor:
                            terms.append((left, right_pos, factor))
            if not terms:
                self._copy(script, input_count, output)
                script.op("TOALTSTACK")
                continue
            if all(factor > 0 for _, _, factor in terms):
                self._copy(script, input_count, output)
                for left, right_pos, factor in terms:
                    self._copy(script, input_count + 1, left)
                    self._copy(script, input_count + 2, n + right_pos)
                    script.op("MUL")
                    if factor != 1:
                        script.int(factor).op("MUL")
                    script.op("ADD")
            else:
                offset = sum(
                    P ** 2 * abs(factor)
                    for _, _, factor in terms
                    if factor < 0
                )
                script.int(offset)
                self._copy(script, input_count + 1, output)
                script.op("ADD")
                for left, right_pos, factor in terms:
                    self._copy(script, input_count + 1, left)
                    self._copy(script, input_count + 2, n + right_pos)
                    script.op("MUL")
                    magnitude = abs(factor)
                    if magnitude != 1:
                        script.int(magnitude).op("MUL")
                    script.op("SUB" if factor < 0 else "ADD")
            script.int(P).op("MOD", "TOALTSTACK")
        self._clear_inputs_and_restore(script, input_count, n)
        return script

    def emit_frobenius(self, power: int) -> Script:
        n = self.degree
        columns = []
        for j in range(n):
            basis = tuple(1 if i == j else 0 for i in range(n))
            columns.append(self.frobenius(basis, power))
        script = Script()
        for output in reversed(range(n)):
            terms = [(j, columns[j][output]) for j in range(n) if columns[j][output]]
            if not terms:
                script.int(0).op("TOALTSTACK")
                continue
            for j, coefficient in terms:
                self._copy(script, n, j)
                if coefficient != 1:
                    script.int(coefficient).op("MUL")
                script.int(P).op("MOD", "TOALTSTACK")
            script.op("FROMALTSTACK")
            for _ in range(len(terms) - 1):
                script.op("FROMALTSTACK", "ADD").int(P).op("MOD")
            script.op("TOALTSTACK")
        self._clear_inputs_and_restore(script, n, n)
        return script


FP = Field.create("Fp")
FP2 = Field.create("Fp2")
FP6 = Field.create("Fp6")
FP12 = Field.create("Fp12")
