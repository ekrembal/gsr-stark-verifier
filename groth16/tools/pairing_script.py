"""GSR Script emitter for the dynamic BN254 affine Miller loop."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "risc0-succinct/tools"))
from gsr import Asm, V, num

from bn254 import FQ, FQ12, P, W, compute_c_wi, g1, g2, linear_combination
from fields import FP, FP2, FP12
from pairing_ref import (
    ATE_LOOP_COUNT,
    LINE_INDICES,
    PSI_X,
    PSI_Y,
    _fq12_from_tower,
    fixture_pairing,
    prepare_g2,
)


def tower_from_fq12(value) -> tuple[int, ...]:
    coefficients = [int(x) % P for x in value.coeffs]
    out = []
    for u, v, w in FP12.basis:
        degree = 2 * v + w
        out.append(
            coefficients[degree + 6]
            if u
            else (coefficients[degree] + 9 * coefficients[degree + 6]) % P
        )
    return tuple(out)


def _fq2(value) -> tuple[int, int]:
    return int(value.coeffs[0]) % P, int(value.coeffs[1]) % P


def _g1(value) -> tuple[int, int]:
    return int(value[0]), int(value[1])


def _eval_point(point) -> tuple[int, int]:
    x, y = point
    y_inv = FQ.one() / y
    return int(-x * y_inv), int(y_inv)


@dataclass
class Witness:
    stack: list[bytes]
    layout: dict
    slopes: tuple[tuple[int, int], ...]


def build_witness(fixture: dict) -> Witness:
    proof, vk = fixture["seal"], fixture["verifying_key"]
    public_inputs = list(map(int, fixture["public_inputs"]))
    linear = linear_combination([g1(point) for point in vk["ic"]], [1, *public_inputs])
    a, c, b = g1(proof["a"]), g1(proof["c"]), g2(proof["b"])
    raw, traces = fixture_pairing(fixture)
    residue, residue_inverse, wi = compute_c_wi(_fq12_from_tower(raw))

    values: list[int] = []

    def add(name: str, sequence) -> list[int]:
        start = len(values)
        values.extend(int(x) % P for x in sequence)
        return list(range(start, len(values)))

    layout = {
        "L": (add("Lx", _g1(linear)[:1]), add("Ly", _g1(linear)[1:])),
        "C": (add("Cx", _g1(c)[:1]), add("Cy", _g1(c)[1:])),
        "A": (add("Ax", _g1(a)[:1]), add("Ay", _g1(a)[1:])),
    }
    layout["evals"] = {
        name: (add(name + "_xx", [evals[0]]), add(name + "_yy", [evals[1]]))
        for name, point in (("L", linear), ("C", c), ("A", a))
        for evals in [ _eval_point(point) ]
    }
    layout["B"] = (add("Bx", _fq2(b[0])), add("By", _fq2(b[1])))
    b_trace = traces[3]
    layout["slopes"] = [add("slope", slope) for slope in b_trace.slope_witnesses]
    layout["c"] = add("c", tower_from_fq12(residue))
    layout["c_inv"] = add("c_inv", tower_from_fq12(residue_inverse))
    layout["wi"] = add("wi", tower_from_fq12(wi))
    return Witness([num(x) for x in values], layout, b_trace.slope_witnesses)


class FieldCode:
    def __init__(self, asm: Asm):
        self.asm = asm

    def op(self, field, operation: str, *operands, consume: bool | tuple[bool, ...] = False):
        flags = (consume,) * len(operands) if isinstance(consume, bool) else consume
        if len(flags) != len(operands):
            raise ValueError("one consume flag is required per operand")
        for operand, consume_operand in zip(operands, flags, strict=True):
            for value in operand:
                self.asm.fetch(value, consume_operand)
        output = tuple(V(field.name) for _ in range(field.degree))
        self.asm.raw(field.emit(operation), sum(len(x) for x in operands), *output)
        return output

    def frobenius(self, value, power: int, consume: bool = False):
        for item in value:
            self.asm.fetch(item, consume)
        output = tuple(V("Fp12") for _ in range(FP12.degree))
        self.asm.raw(FP12.emit_frobenius(power), len(value), *output)
        return output

    def frobenius_fp2(self, value, power: int = 1, consume: bool = False):
        for item in value:
            self.asm.fetch(item, consume)
        output = tuple(V("Fp2") for _ in range(FP2.degree))
        self.asm.raw(FP2.emit_frobenius(power), len(value), *output)
        return output

    def copy(self, value):
        return tuple(self.asm.pick(item) for item in value)

    def push(self, value, tag: str):
        return tuple(self.asm.push(int(x) % P, V(tag)) for x in value)

    def equal(self, left, right, consume_left: bool = False, consume_right: bool = False):
        for a, b in zip(left, right, strict=True):
            self.asm.fetch(a, consume_left)
            self.asm.fetch(b, consume_right)
            self.asm.op("NUMEQUALVERIFY", 2)

    def equal_constant(self, left, right, consume: bool = False):
        for value, constant in zip(left, right, strict=True):
            self.asm.fetch(value, consume)
            self.asm.push(int(constant) % P)
            self.asm.op("NUMEQUALVERIFY", 2)

    def drop(self, *values):
        for value in values:
            for item in value:
                if self.asm.has(item):
                    self.asm.drop(item)

    def multiply(self, left, right, consume_left: bool = False, consume_right: bool = False):
        return self.op(FP, "mul", left, right, consume=(consume_left, consume_right))

    def fp2_scale(self, value, scalar, consume: bool = False):
        return tuple(
            self.op(FP, "mul", (coefficient,), scalar, consume=consume)[0]
            for coefficient in value
        )

    def fp2_add(self, left, right, consume_left: bool = False, consume_right: bool = False):
        return self.op(FP2, "add", left, right, consume=(consume_left, consume_right))

    def fp2_sub(self, left, right, consume_left: bool = False, consume_right: bool = False):
        return self.op(FP2, "sub", left, right, consume=(consume_left, consume_right))

    def fp2_mul(self, left, right, consume_left: bool = False, consume_right: bool = False):
        return self.op(FP2, "mul", left, right, consume=(consume_left, consume_right))

    def fp2_square(self, value, consume: bool = False):
        return self.op(FP2, "square", value, consume=consume)

    def push_fp2(self, value):
        return self.push(_fq2(value), "Fp2")

    def push_fp12(self, value):
        return self.push(tower_from_fq12(value), "Fp12")

    def bool_and(self, left, right):
        self.asm.fetch(left, consume=True)
        self.asm.fetch(right, consume=True)
        output = V("bool")
        self.asm.op("AND", 2, output)
        return output

    def bool_or(self, left, right):
        self.asm.fetch(left, consume=True)
        self.asm.fetch(right, consume=True)
        output = V("bool")
        self.asm.op("OR", 2, output)
        return output

    def allowed_wi(self, value):
        candidates = (FQ12.one(), W, W**2)
        matches = []
        for candidate in candidates:
            comparisons = []
            for variable, constant in zip(value, tower_from_fq12(candidate), strict=True):
                self.asm.fetch(variable, consume=False)
                self.asm.push(constant)
                result = V("bool")
                self.asm.op("NUMEQUAL", 2, result)
                comparisons.append(result)
            match = comparisons[0]
            for comparison in comparisons[1:]:
                match = self.bool_and(match, comparison)
            matches.append(match)
        match = self.bool_or(matches[0], matches[1])
        match = self.bool_or(match, matches[2])
        self.asm.fetch(match, consume=True)
        self.asm.op("VERIFY", 1)

    def line_rhs(self, accumulator, slope, minus_bias, eval_x, eval_y):
        slope_x = self.fp2_scale(slope, eval_x)
        bias_y = self.fp2_scale(minus_bias, eval_y)
        rhs = self.push((1, 0), "line")
        rhs += slope_x + bias_y
        output = tuple(V("Fp12") for _ in range(FP12.degree))
        for value in (*accumulator, *rhs):
            self.asm.fetch(value, consume=True)
        self.asm.raw(
            FP12.emit("sparse_mul", LINE_INDICES),
            FP12.degree + len(LINE_INDICES),
            *output,
        )
        self.drop(slope_x, bias_y)
        return output

    def line_rhs_constant(self, accumulator, line, eval_x, eval_y):
        slope = self.push_fp2(line.slope)
        minus_bias = self.push_fp2(line.minus_bias)
        output = self.line_rhs(accumulator, slope, minus_bias, eval_x, eval_y)
        self.drop(slope, minus_bias)
        return output

    def fp12_multiply(self, left, right, consume_left=True, consume_right=True):
        return self.op(
            FP12,
            "mul",
            left,
            right,
            consume=(consume_left, consume_right),
        )

    def fp12_square(self, value, consume=True):
        return self.op(FP12, "square", value, consume=consume)


def _layout_vars(layout: dict):
    count = max(max(indices) for indices in (
        layout["L"][0] + layout["L"][1],
        layout["C"][0] + layout["C"][1],
        layout["A"][0] + layout["A"][1],
        layout["evals"]["L"][0] + layout["evals"]["L"][1],
        layout["evals"]["C"][0] + layout["evals"]["C"][1],
        layout["evals"]["A"][0] + layout["evals"]["A"][1],
        layout["B"][0] + layout["B"][1],
        *layout["slopes"],
        layout["c"],
        layout["c_inv"],
        layout["wi"],
    )) + 1
    variables = [V(f"w{i}") for i in range(count)]

    def vector(indices):
        return tuple(variables[index] for index in indices)

    return variables, {
        "L": tuple(vector(part) for part in layout["L"]),
        "C": tuple(vector(part) for part in layout["C"]),
        "A": tuple(vector(part) for part in layout["A"]),
        "evals": {
            name: tuple(vector(part) for part in layout["evals"][name])
            for name in ("L", "C", "A")
        },
        "B": tuple(vector(part) for part in layout["B"]),
        "slopes": [vector(part) for part in layout["slopes"]],
        "c": vector(layout["c"]),
        "c_inv": vector(layout["c_inv"]),
        "wi": vector(layout["wi"]),
    }


def _double_dynamic(fc: FieldCode, accumulator, t, slope, eval_x, eval_y):
    tx, ty = t
    twice_y = fc.fp2_add(ty, ty)
    tangent_lhs = fc.fp2_mul(slope, twice_y)
    x_squared = fc.fp2_square(tx)
    twice_x_squared = fc.fp2_add(x_squared, x_squared)
    tangent_rhs = fc.fp2_add(twice_x_squared, x_squared)
    fc.equal(tangent_lhs, tangent_rhs)

    slope_squared = fc.fp2_square(slope)
    twice_x = fc.fp2_add(tx, tx)
    next_x = fc.fp2_sub(slope_squared, twice_x)
    x_difference = fc.fp2_sub(tx, next_x)
    slope_times_difference = fc.fp2_mul(slope, x_difference)
    next_y = fc.fp2_sub(slope_times_difference, ty)
    slope_times_x = fc.fp2_mul(slope, tx)
    minus_bias = fc.fp2_sub(slope_times_x, ty)
    next_accumulator = fc.line_rhs(accumulator, slope, minus_bias, eval_x, eval_y)

    fc.drop(twice_y, tangent_lhs, x_squared, twice_x_squared, tangent_rhs)
    fc.drop(slope_squared, twice_x, x_difference, slope_times_difference)
    fc.drop(slope_times_x, minus_bias, slope, tx, ty)
    return next_accumulator, (next_x, next_y)


def _add_dynamic(fc: FieldCode, accumulator, t, q, slope, eval_x, eval_y):
    tx, ty = t
    qx, qy = q
    x_difference = fc.fp2_sub(tx, qx)
    y_difference = fc.fp2_sub(ty, qy)
    slope_times_dx = fc.fp2_mul(slope, x_difference)
    fc.equal(slope_times_dx, y_difference)

    slope_squared = fc.fp2_square(slope)
    next_x = fc.fp2_sub(slope_squared, tx)
    next_x = fc.fp2_sub(next_x, qx, consume_left=True)
    x_difference_to_next = fc.fp2_sub(tx, next_x)
    slope_times_difference = fc.fp2_mul(slope, x_difference_to_next)
    next_y = fc.fp2_sub(slope_times_difference, ty)
    slope_times_x = fc.fp2_mul(slope, tx)
    minus_bias = fc.fp2_sub(slope_times_x, ty)
    next_accumulator = fc.line_rhs(accumulator, slope, minus_bias, eval_x, eval_y)

    fc.drop(x_difference, y_difference, slope_times_dx, slope_times_difference)
    fc.drop(slope_squared)
    fc.drop(x_difference_to_next, slope_times_x, minus_bias, slope, tx, ty)
    return next_accumulator, (next_x, next_y)


def _copy_point(fc: FieldCode, point):
    return tuple(fc.copy(coordinate) for coordinate in point)


def _negate_fp2(fc: FieldCode, point):
    zero = fc.push((0, 0), "zero")
    return fc.op(FP2, "sub", zero, point, consume=(True, False))


def build_pairing_script(fixture: dict):
    """Return a proof-agnostic script and its witness layout for one fixed VK."""
    witness = build_witness(fixture)
    variables, values = _layout_vars(witness.layout)
    asm = Asm(variables)
    fc = FieldCode(asm)
    vk = fixture["verifying_key"]

    for name in ("L", "C", "A"):
        x, y = values[name]
        eval_x, eval_y = values["evals"][name]
        y_inverse = fc.multiply(y, eval_y)
        fc.equal_constant(y_inverse, (1,), consume=True)
        x_inverse = fc.multiply(x, eval_y)
        x_inverse = fc.op(FP, "add", x_inverse, eval_x, consume=(True, False))
        fc.equal_constant(x_inverse, (0,), consume=True)
        fc.drop(x, y)

    c_product = fc.fp12_multiply(values["c"], values["c_inv"], False, False)
    fc.equal_constant(c_product, (1,) + (0,) * 11, consume=True)
    fc.allowed_wi(values["wi"])

    target_eval_values = _eval_point(
        __import__("py_ecc.bn128", fromlist=["neg"]).neg(g1(vk["alpha_g1"]))
    )
    fixed_evals = (
        values["evals"]["L"],
        values["evals"]["C"],
        tuple((fc.push((value,), "target-eval")[0],) for value in target_eval_values),
    )
    fixed_qs = (
        __import__("py_ecc.bn128", fromlist=["neg"]).neg(g2(vk["gamma_g2"])),
        __import__("py_ecc.bn128", fromlist=["neg"]).neg(g2(vk["delta_g2"])),
        g2(vk["beta_g2"]),
    )
    fixed_traces = tuple(prepare_g2(point) for point in fixed_qs)

    t = _copy_point(fc, values["B"])
    neg_b_y = _negate_fp2(fc, values["B"][1])
    q1_x = fc.fp2_mul(
        fc.frobenius_fp2(values["B"][0]),
        fc.push_fp2(PSI_X),
        consume_left=True,
        consume_right=True,
    )
    q1_y = fc.fp2_mul(
        fc.frobenius_fp2(values["B"][1]),
        fc.push_fp2(PSI_Y),
        consume_left=True,
        consume_right=True,
    )
    q2_x = fc.fp2_mul(
        fc.frobenius_fp2(q1_x),
        fc.push_fp2(PSI_X),
        consume_left=True,
        consume_right=True,
    )
    q2_y = fc.fp2_mul(
        fc.frobenius_fp2(q1_y),
        fc.push_fp2(PSI_Y),
        consume_left=True,
        consume_right=True,
    )
    q2_y = _negate_fp2(fc, q2_y)

    accumulator = fc.copy(values["c_inv"])
    slope_index = 0
    digits = tuple(reversed(ATE_LOOP_COUNT[:-1]))
    for step_index, digit in enumerate(digits):
        accumulator = fc.fp12_square(accumulator)
        if digit == 1:
            accumulator = fc.fp12_multiply(accumulator, values["c_inv"], True, False)
        elif digit == -1:
            accumulator = fc.fp12_multiply(accumulator, values["c"], True, False)

        for pair_index, trace in enumerate(fixed_traces):
            line = trace.steps[step_index].double
            accumulator = fc.line_rhs_constant(
                accumulator, line, *fixed_evals[pair_index]
            )

        slope = values["slopes"][slope_index]
        slope_index += 1
        accumulator, t = _double_dynamic(
            fc, accumulator, t, slope, *values["evals"]["A"]
        )

        if digit:
            for pair_index, trace in enumerate(fixed_traces):
                line = trace.steps[step_index].add
                if line is None:
                    raise AssertionError("missing fixed G2 addition line")
                accumulator = fc.line_rhs_constant(
                    accumulator, line, *fixed_evals[pair_index]
                )
            slope = values["slopes"][slope_index]
            slope_index += 1
            q = (values["B"][0], neg_b_y if digit == -1 else values["B"][1])
            accumulator, t = _add_dynamic(
                fc, accumulator, t, q, slope, *values["evals"]["A"]
            )

    for power, residue_value in ((1, values["c_inv"]), (2, values["c"]), (3, values["c_inv"])):
        frobenius = fc.frobenius(residue_value, power)
        accumulator = fc.fp12_multiply(accumulator, frobenius, True, True)

    for line_index in range(2):
        for pair_index, trace in enumerate(fixed_traces):
            accumulator = fc.line_rhs_constant(
                accumulator,
                trace.frobenius_lines[line_index],
                *fixed_evals[pair_index],
            )
        slope = values["slopes"][slope_index]
        slope_index += 1
        q = (q1_x, q1_y) if line_index == 0 else (q2_x, q2_y)
        accumulator, t = _add_dynamic(
            fc, accumulator, t, q, slope, *values["evals"]["A"]
        )

    if slope_index != len(values["slopes"]):
        raise AssertionError("incorrect number of B slope witnesses")
    accumulator = fc.fp12_multiply(accumulator, values["wi"], True, False)
    fc.equal_constant(accumulator, (1,) + (0,) * 11, consume=True)
    fc.drop(
        *values["L"],
        *values["C"],
        *values["A"],
        *values["B"],
        *values["evals"]["L"],
        *values["evals"]["C"],
        *values["evals"]["A"],
        *values["slopes"],
        values["c"],
        values["c_inv"],
        values["wi"],
        *t,
        neg_b_y,
        q1_x,
        q1_y,
        q2_x,
        q2_y,
        *fixed_evals[2],
    )
    asm.drop_top(len(asm.st))
    asm.push(1)
    return asm.s, witness
