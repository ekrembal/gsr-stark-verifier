"""GSR Script emitter for the dynamic BN254 affine Miller loop."""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "risc0-succinct/tools"))
from gsr import Asm, Script, V, num

from bn254 import (
    FQ,
    FQ12,
    P,
    W,
    compute_c_wi,
    g1,
    g2,
    is_g2_subgroup_x0,
    linear_combination,
)
from fields import FP, FP2, FP12
from pairing_ref import (
    ATE_LOOP_COUNT,
    LINE_INDICES,
    PSI_X,
    PSI_Y,
    _fq12_from_tower,
    fixture_pairing,
    g2_x0_subgroup_trace,
    prepare_g2,
)

LINE_HASH_DOMAIN = b"risc0-groth16-fixed-miller-lines-v1"


def _line_hash_item(value: int) -> bytes:
    encoded = num(value)
    return bytes((len(encoded) + 1,)) + encoded


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
    stage_ranges: dict[str, tuple[int, int]] = field(default_factory=dict)
    miller_step_ranges: list[tuple[int, int]] = field(default_factory=list)
    subgroup_step_ranges: list[tuple[int, int]] = field(default_factory=list)
    shamir_step_ranges: list[tuple[int, int]] = field(default_factory=list)


def build_witness(fixture: dict, claim_mode: str | None = None) -> Witness:
    if claim_mode not in (None, "fixed", "witness"):
        raise ValueError(claim_mode)
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
    layout["c"] = add("c", tower_from_fq12(residue))
    layout["c_inv"] = add("c_inv", tower_from_fq12(residue_inverse))
    layout["wi"] = add("wi", tower_from_fq12(wi))
    subgroup_trace = None
    shamir_data = None
    if claim_mode is not None:
        from msm import build_shamir_data, claim_scalars

        c0, c1 = claim_scalars(fixture)
        shamir_data = build_shamir_data(fixture, c0, c1)
        layout["claim"] = (add("c0", [c0]), add("c1", [c1]))
        if not is_g2_subgroup_x0(b):
            raise ValueError("fixture B point is outside the BN254 G2 subgroup")
        subgroup_trace = g2_x0_subgroup_trace(b)
        if not subgroup_trace["accepts"]:
            raise ValueError("fixture B point fails the x0 subgroup relation")

    def line_values(line):
        return [
            int(value) % P
            for value in (*line.slope.coeffs, *line.minus_bias.coeffs)
        ]

    digits = tuple(reversed(ATE_LOOP_COUNT[:-1]))
    fixed_traces = traces[:3]
    step_data = []
    slope_index = 0
    line_hash = hashlib.sha256(LINE_HASH_DOMAIN).digest()
    for step_index, digit in enumerate(digits):
        double_slope = b_trace.slope_witnesses[slope_index]
        slope_index += 1
        has_add = bool(digit)
        if digit:
            add_slope = b_trace.slope_witnesses[slope_index]
            slope_index += 1
        else:
            add_slope = (0, 0)
        double_lines = [
            trace.steps[step_index].double for trace in fixed_traces
        ]
        hash_add_lines = [
            trace.steps[step_index].add for trace in fixed_traces
        ] if digit else []
        add_lines = hash_add_lines or [[0] * 4 for _ in fixed_traces]
        constant_lines = (*double_lines, *hash_add_lines)
        double_line_values = [line_values(line) for line in double_lines]
        add_line_values = (
            [line_values(line) for line in hash_add_lines]
            if hash_add_lines
            else add_lines
        )
        constants = [
            value
            for line in constant_lines
            for value in line_values(line)
        ]
        line_hash = hashlib.sha256(
            line_hash + b"".join(_line_hash_item(value) for value in constants)
        ).digest()
        step_data.append({
            "double_slope": double_slope,
            "add_slope": add_slope,
            "has_add": has_add,
            "double_lines": double_line_values,
            "add_lines": add_line_values,
            "constants": constants,
        })
    final_slopes = b_trace.slope_witnesses[slope_index:]
    if len(final_slopes) != 2:
        raise AssertionError("incorrect Miller-loop slope count")

    stack = [num(x) for x in values]
    if claim_mode == "witness":
        layout["claim_digest"] = len(stack)
        stack.append(bytes.fromhex(fixture["claim_digest"]))

    def append_stack_values(sequence):
        start = len(stack)
        stack.extend(num(int(value) % P) for value in sequence)
        return list(range(start, len(stack)))

    layout["final_slopes"] = [
        append_stack_values(slope) for slope in final_slopes
    ]
    miller_steps = [None] * len(step_data)
    for step_index in reversed(range(len(step_data))):
        step = step_data[step_index]
        step_layout = {
            "double_slope": append_stack_values(step["double_slope"]),
            "double_lines": [
                append_stack_values(line) for line in step["double_lines"]
            ],
            "add_slope": append_stack_values(step["add_slope"]),
            "add_lines": [
                append_stack_values(line) for line in step["add_lines"]
            ],
            "has_add": step["has_add"],
        }
        step_layout["constants"] = [
            index
            for line in (
                *step_layout["double_lines"],
                *(
                    step_layout["add_lines"]
                    if step_layout["has_add"]
                    else ()
                ),
            )
            for index in line
        ]
        miller_steps[step_index] = step_layout
    layout["miller_steps"] = miller_steps
    layout["slopes"] = [
        group
        for step in miller_steps
        for group in (step["double_slope"], step["add_slope"])
    ] + layout["final_slopes"]
    layout["line_constants"] = [
        line
        for step in miller_steps
        for line in (
            *step["double_lines"],
            *(step["add_lines"] if step["has_add"] else ()),
        )
    ]
    if shamir_data is not None:
        bits = ([None] * 128, [None] * 128)
        steps = [None] * 128
        slopes = []
        for step in reversed(shamir_data["steps"]):
            double_slope = append_stack_values([step["double_slope"]])
            add_slope = append_stack_values([step["add_slope"]])
            bit0 = append_stack_values([step["bit0"]])
            bit1 = append_stack_values([step["bit1"]])
            slopes.extend((double_slope, add_slope))
            bits[0][step["index"]] = bit0
            bits[1][step["index"]] = bit1
            steps[127 - step["index"]] = {
                "bit0": bit0,
                "bit1": bit1,
                "double_slope": double_slope,
                "add_slope": add_slope,
            }
        layout["bits"] = bits
        layout["shamir_steps"] = steps
        layout["shamir_slopes"] = slopes
    if subgroup_trace is not None:
        layout["subgroup_slopes"] = []
        layout["subgroup_steps"] = [None] * len(subgroup_trace["steps"])
        for step_index in reversed(range(len(subgroup_trace["steps"]))):
            step = subgroup_trace["steps"][step_index]
            double_slope = append_stack_values(step["double_slope"])
            add_slope = append_stack_values(step["add_slope"])
            layout["subgroup_slopes"].extend((double_slope, add_slope))
            layout["subgroup_steps"][step_index] = {
                "double_slope": double_slope,
                "add_slope": add_slope,
                "has_add": step["has_add"],
            }
        layout["subgroup_relations"] = {}
        for name in ("double_x0", "psi2_x0", "psi_x0", "x0_plus_one"):
            slope = append_stack_values(subgroup_trace["relations"][name])
            layout["subgroup_slopes"].append(slope)
            layout["subgroup_relations"][name] = slope
    layout["line_hash"] = line_hash
    return Witness(stack, layout, b_trace.slope_witnesses)


class FieldCode:
    def __init__(self, asm: Asm):
        self.asm = asm
        self.bounds = {}

    def _bound(self, value):
        return self.bounds.get(value, 1)

    def _fetch(self, value, consume: bool, reduce: bool = False):
        bound = self._bound(value)
        fetched = self.asm.fetch(value, consume)
        if consume:
            self.bounds.pop(value, None)
        elif fetched is not value:
            self.bounds[fetched] = bound
        if reduce and bound > 1:
            self.asm.push(P)
            reduced = V(value.tag)
            self.asm.op("MOD", 2, reduced)
            self.bounds[reduced] = 1
            return reduced
        return fetched

    def op(self, field, operation: str, *operands, consume: bool | tuple[bool, ...] = False):
        flags = (consume,) * len(operands) if isinstance(consume, bool) else consume
        if len(flags) != len(operands):
            raise ValueError("one consume flag is required per operand")
        bounds = tuple(max((self._bound(value) for value in operand), default=1)
                       for operand in operands)
        reduce_inputs = operation in ("mul", "square", "sparse_mul")
        for operand, consume_operand in zip(operands, flags, strict=True):
            for value in operand:
                self._fetch(value, consume_operand, reduce_inputs)
        output_bound = bounds[0] + bounds[1] if operation in ("add", "sub") else 1
        if operation in ("add", "sub") and (output_bound * P - 1).bit_length() > 520 * 8:
            raise OverflowError("lazy field value exceeds the Script numeric-element limit")
        output = tuple(V(field.name) for _ in range(field.degree))
        self.asm.raw(
            field.emit(operation, input_bounds=bounds[:2]),
            sum(len(x) for x in operands),
            *output,
        )
        for value in output:
            self.bounds[value] = output_bound
        return output

    def frobenius(self, value, power: int, consume: bool = False):
        for item in value:
            self._fetch(item, consume, reduce=True)
        output = tuple(V("Fp12") for _ in range(FP12.degree))
        self.asm.raw(FP12.emit_frobenius(power), len(value), *output)
        for item in output:
            self.bounds[item] = 1
        return output

    def frobenius_fp2(self, value, power: int = 1, consume: bool = False):
        for item in value:
            self._fetch(item, consume, reduce=True)
        output = tuple(V("Fp2") for _ in range(FP2.degree))
        self.asm.raw(FP2.emit_frobenius(power), len(value), *output)
        for item in output:
            self.bounds[item] = 1
        return output

    def copy(self, value):
        result = tuple(self.asm.pick(item) for item in value)
        for source, target in zip(value, result, strict=True):
            self.bounds[target] = self._bound(source)
        return result

    def push(self, value, tag: str):
        result = tuple(self.asm.push(int(x) % P, V(tag)) for x in value)
        for item in result:
            self.bounds[item] = 1
        return result

    def equal(self, left, right, consume_left: bool = False, consume_right: bool = False):
        for a, b in zip(left, right, strict=True):
            self._fetch(a, consume_left, reduce=True)
            self._fetch(b, consume_right, reduce=True)
            self.asm.op("NUMEQUALVERIFY", 2)

    def equal_constant(self, left, right, consume: bool = False):
        for value, constant in zip(left, right, strict=True):
            self._fetch(value, consume, reduce=True)
            self.asm.push(int(constant) % P)
            self.asm.op("NUMEQUALVERIFY", 2)

    def drop(self, *values):
        for value in values:
            for item in value:
                if self.asm.has(item):
                    self.asm.drop(item)

    def hash_chain_step(self, current, values):
        self.asm.fetch(current, consume=True)
        for value in values:
            item = self.asm.fetch(value, consume=False)
            size = V("miller-line-size")
            self.asm.op("SIZE", 1, item, size)
            length = V("miller-line-length")
            self.asm.op("1ADD", 1, length)
            self.asm.op("SWAP", 2, length, item)
            prefixed = V("miller-line-item")
            self.asm.op("CAT", 2, prefixed)
            preimage = V("miller-line-preimage")
            self.asm.op("CAT", 2, preimage)
        following = V("miller-line-hash")
        self.asm.op("SHA256", 1, following)
        return following

    def multiply(self, left, right, consume_left: bool = False, consume_right: bool = False):
        return self.op(FP, "mul", left, right, consume=(consume_left, consume_right))

    def fp2_scale(
        self, value, scalar, consume_value: bool = False, consume_scalar: bool = False
    ):
        return tuple(
            self.op(
                FP,
                "mul",
                (coefficient,),
                scalar,
                consume=(consume_value, consume_scalar),
            )[0]
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

    def line_rhs(
        self, accumulator, slope, minus_bias, eval_x, eval_y,
        consume_coefficients: bool = False,
    ):
        slope_x = self.fp2_scale(
            slope, eval_x, consume_value=consume_coefficients
        )
        bias_y = self.fp2_scale(
            minus_bias, eval_y, consume_value=consume_coefficients
        )
        rhs = slope_x + bias_y
        output = tuple(V("Fp12") for _ in range(FP12.degree))
        for value in (*accumulator, *rhs):
            self._fetch(value, consume=True, reduce=True)
        self.asm.raw(
            FP12.emit_line_mul(LINE_INDICES),
            FP12.degree + len(LINE_INDICES),
            *output,
        )
        for item in output:
            self.bounds[item] = 1
        self.drop(slope_x, bias_y)
        return output

    def line_rhs_values(self, accumulator, slope, minus_bias, eval_x, eval_y):
        return self.line_rhs(
            accumulator,
            slope,
            minus_bias,
            eval_x,
            eval_y,
            consume_coefficients=True,
        )

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
    index_groups = [
        layout["L"][0] + layout["L"][1],
        layout["C"][0] + layout["C"][1],
        layout["A"][0] + layout["A"][1],
        layout["evals"]["L"][0] + layout["evals"]["L"][1],
        layout["evals"]["C"][0] + layout["evals"]["C"][1],
        layout["evals"]["A"][0] + layout["evals"]["A"][1],
        layout["B"][0] + layout["B"][1],
        *layout["slopes"],
        *layout["line_constants"],
        layout["c"],
        layout["c_inv"],
        layout["wi"],
    ]
    index_groups.extend(
        line
        for step in layout["miller_steps"]
        for line in step["add_lines"]
    )
    if "claim" in layout:
        index_groups.extend(layout["claim"])
        index_groups.extend(layout["bits"][0])
        index_groups.extend(layout["bits"][1])
        index_groups.extend(layout["shamir_slopes"])
        index_groups.extend(layout["subgroup_slopes"])
    if "claim_digest" in layout:
        index_groups.append([layout["claim_digest"]])
    count = max(max(indices) for indices in index_groups) + 1
    variables = [V(f"w{i}") for i in range(count)]

    def vector(indices):
        return tuple(variables[index] for index in indices)

    result = {
        "L": tuple(vector(part) for part in layout["L"]),
        "C": tuple(vector(part) for part in layout["C"]),
        "A": tuple(vector(part) for part in layout["A"]),
        "evals": {
            name: tuple(vector(part) for part in layout["evals"][name])
            for name in ("L", "C", "A")
        },
        "B": tuple(vector(part) for part in layout["B"]),
        "slopes": [vector(part) for part in layout["slopes"]],
        "line_constants": [vector(part) for part in layout["line_constants"]],
        "miller_steps": [
            {
                "double_slope": vector(step["double_slope"]),
                "double_lines": [vector(line) for line in step["double_lines"]],
                "add_slope": (
                    vector(step["add_slope"])
                    if step["add_slope"] is not None
                    else None
                ),
                "add_lines": [vector(line) for line in step["add_lines"]],
                "constants": tuple(variables[index] for index in step["constants"]),
            }
            for step in layout["miller_steps"]
        ],
        "final_slopes": [vector(part) for part in layout["final_slopes"]],
        "c": vector(layout["c"]),
        "c_inv": vector(layout["c_inv"]),
        "wi": vector(layout["wi"]),
    }
    if "claim" in layout:
        result.update({
            "claim": tuple(vector(part) for part in layout["claim"]),
            "bits": tuple(
                [vector(part) for part in scalar_bits]
                for scalar_bits in layout["bits"]
            ),
            "shamir_steps": [
                {
                    name: vector(step[name])
                    for name in ("bit0", "bit1", "double_slope", "add_slope")
                }
                for step in layout["shamir_steps"]
            ],
            "shamir_slopes": [
                vector(part) for part in layout["shamir_slopes"]
            ],
            "subgroup_slopes": [vector(part) for part in layout["subgroup_slopes"]],
            "subgroup_steps": [
                {
                    "double_slope": vector(step["double_slope"]),
                    "add_slope": vector(step["add_slope"]),
                    "has_add": step["has_add"],
                }
                for step in layout["subgroup_steps"]
            ],
            "subgroup_relations": {
                name: vector(indices)
                for name, indices in layout["subgroup_relations"].items()
            },
        })
    if "claim_digest" in layout:
        result["claim_digest"] = variables[layout["claim_digest"]]
    return variables, result


def _double_dynamic(fc: FieldCode, accumulator, t, slope, eval_x, eval_y):
    tx, ty = t
    twice_y = fc.fp2_add(ty, ty)
    tangent_lhs = fc.fp2_mul(slope, twice_y)
    x_squared = fc.fp2_square(tx)
    twice_x_squared = fc.fp2_add(x_squared, x_squared)
    tangent_rhs = fc.fp2_add(twice_x_squared, x_squared)
    fc.equal(tangent_lhs, tangent_rhs)
    _check_fp2_nonzero(fc, twice_y)

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
    _check_fp2_nonzero(fc, x_difference)
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


def _check_canonical(fc: FieldCode, values):
    for value in values:
        for coefficient in value:
            fc.asm.fetch(coefficient, consume=False)
            fc.asm.push(P)
            smaller = V("canonical-field")
            fc.asm.op("LESSTHAN", 2, smaller)
            fc.asm.op("VERIFY", 1)


def _g1_curve_check(fc: FieldCode, point):
    x, y = point
    y_squared = fc.op(FP, "square", y)
    x_squared = fc.op(FP, "square", x)
    x_cubed = fc.multiply(x_squared, x)
    rhs = fc.op(FP, "add", x_cubed, fc.push((3,), "g1-b"))
    fc.equal(y_squared, rhs)
    fc.drop(y_squared, x_squared, x_cubed, rhs)


def _check_fp2_nonzero(fc: FieldCode, value):
    matches = []
    for coefficient in value:
        fc.asm.fetch(coefficient, consume=False)
        fc.asm.push(0)
        equal = V("zero-coordinate")
        fc.asm.op("NUMEQUAL", 2, equal)
        matches.append(equal)
    fc.asm.fetch(matches[0], consume=True)
    fc.asm.fetch(matches[1], consume=True)
    is_zero = V("zero-fp2")
    fc.asm.op("AND", 2, is_zero)
    fc.asm.push(1)
    fc.asm.raw(Script().op("SWAP", "SUB"), 2, V("nonzero-fp2"))
    fc.asm.op("VERIFY", 1)


def _g2_double_point(fc: FieldCode, point, slope):
    x, y = point
    two_y = fc.fp2_add(y, y)
    lhs = fc.fp2_mul(slope, two_y)
    x_squared = fc.fp2_square(x)
    rhs = fc.fp2_add(x_squared, x_squared)
    rhs = fc.fp2_add(rhs, x_squared, consume_left=True)
    fc.equal(lhs, rhs)
    _check_fp2_nonzero(fc, two_y)

    slope_squared = fc.fp2_square(slope)
    twice_x = fc.fp2_add(x, x)
    next_x = fc.fp2_sub(slope_squared, twice_x)
    x_difference = fc.fp2_sub(x, next_x)
    slope_difference = fc.fp2_mul(slope, x_difference)
    next_y = fc.fp2_sub(slope_difference, y)
    fc.drop(two_y, lhs, x_squared, rhs, slope_squared, twice_x)
    fc.drop(x_difference, slope_difference, slope, point[0], point[1])
    return next_x, next_y


def _g2_add_point(fc: FieldCode, point, other, slope):
    x, y = point
    qx, qy = other
    dx = fc.fp2_sub(x, qx)
    dy = fc.fp2_sub(y, qy)
    _check_fp2_nonzero(fc, dx)
    lhs = fc.fp2_mul(slope, dx)
    fc.equal(lhs, dy)
    slope_squared = fc.fp2_square(slope)
    next_x = fc.fp2_sub(slope_squared, x)
    next_x = fc.fp2_sub(next_x, qx, consume_left=True)
    x_difference = fc.fp2_sub(x, next_x)
    slope_difference = fc.fp2_mul(slope, x_difference)
    next_y = fc.fp2_sub(slope_difference, y)
    fc.drop(dx, dy, lhs, slope_squared, x_difference, slope_difference, slope)
    fc.drop(point[0], point[1])
    return next_x, next_y


def _g2_psi(fc: FieldCode, point, power: int):
    x, y = point
    for _ in range(power):
        x = fc.fp2_mul(
            fc.frobenius_fp2(x),
            fc.push_fp2(PSI_X),
            consume_left=True,
            consume_right=True,
        )
        y = fc.fp2_mul(
            fc.frobenius_fp2(y),
            fc.push_fp2(PSI_Y),
            consume_left=True,
            consume_right=True,
        )
    return x, y


def _g2_subgroup_check(fc: FieldCode, values):
    def store(point, base):
        state = (*point[0], *point[1], *base[0], *base[1])
        for index, value in enumerate(state):
            fc.bounds.pop(value, None)
            fc.asm.fetch(value, consume=True)
            if index < 4:
                fc.asm.push(P)
                canonical = V("subgroup-state")
                fc.asm.op("MOD", 2, canonical)
            fc.asm.op("TOALTSTACK", 1)

    def restore():
        restored = []
        for _ in range(8):
            value = V("subgroup-state")
            fc.asm.op("FROMALTSTACK", 0, value)
            fc.bounds[value] = 1
            restored.append(value)
        state = tuple(reversed(restored))
        return (state[:2], state[2:4]), (state[4:6], state[6:8])

    base = _copy_point(fc, values["B"])
    point = _copy_point(fc, values["B"])
    store(point, base)
    step_ranges = []
    for step in values["subgroup_steps"]:
        step_start = len(fc.asm.s.code)
        point, base = restore()
        point = _g2_double_point(fc, point, step["double_slope"])
        if step["has_add"]:
            point = _g2_add_point(fc, point, base, step["add_slope"])
        else:
            fc.drop(step["add_slope"])
        store(point, base)
        step_ranges.append((step_start, len(fc.asm.s.code)))

    point, base = restore()
    psi_x0 = _g2_psi(fc, point, 1)
    psi2_x0 = _g2_psi(fc, point, 2)
    x0_plus_one = _g2_add_point(
        fc,
        _copy_point(fc, point),
        base,
        values["subgroup_relations"]["x0_plus_one"],
    )
    left = _g2_add_point(
        fc, x0_plus_one, psi_x0, values["subgroup_relations"]["psi_x0"]
    )
    left = _g2_add_point(
        fc, left, psi2_x0, values["subgroup_relations"]["psi2_x0"]
    )
    doubled_x0 = _g2_double_point(
        fc, point, values["subgroup_relations"]["double_x0"]
    )
    right = _g2_psi(fc, doubled_x0, 3)
    fc.equal(left[0], right[0])
    fc.equal(left[1], right[1])
    fc.drop(*base, *psi_x0, *psi2_x0, *left, *doubled_x0, *right)
    return step_ranges


def _input_checks(fc: FieldCode, values, stage_ranges=None):
    input_start = len(fc.asm.s.code)
    fields = [
        *values["L"], *values["C"], *values["A"], *values["B"],
        *values["evals"]["L"], *values["evals"]["C"], *values["evals"]["A"],
        *values["slopes"],
        values["c"], values["c_inv"], values["wi"],
        *values["shamir_slopes"], *values["subgroup_slopes"],
    ]
    _check_canonical(fc, fields)
    for name in ("A", "C", "L"):
        _g1_curve_check(fc, values[name])

    b_x, b_y = values["B"]
    y_squared = fc.fp2_square(b_y)
    x_squared = fc.fp2_square(b_x)
    x_cubed = fc.fp2_mul(x_squared, b_x)
    twist_b = fc.push((
        19485874751759354771024239261021720505790618469301721065564631296452457478373,
        266929791119991161246907387137283842545076965332900288569378510910307636690,
    ), "Fp2")
    curve_rhs = fc.fp2_add(x_cubed, twist_b)
    fc.equal(y_squared, curve_rhs)
    fc.drop(y_squared, x_squared, x_cubed, twist_b, curve_rhs)
    subgroup_start = len(fc.asm.s.code)
    subgroup_step_ranges = _g2_subgroup_check(fc, values)
    subgroup_end = len(fc.asm.s.code)
    if stage_ranges is not None:
        stage_ranges["input_checks"] = (input_start, subgroup_start)
        stage_ranges["g2_subgroup"] = (subgroup_start, subgroup_end)
    return subgroup_step_ranges


def build_pairing_script(fixture: dict, claim_mode: str | None = None):
    """Return a proof-agnostic script and its witness layout for one fixed VK."""
    witness = build_witness(fixture, claim_mode)
    variables, values = _layout_vars(witness.layout)
    asm = Asm(variables)
    fc = FieldCode(asm)
    vk = fixture["verifying_key"]
    input_start = len(asm.s.code)
    if claim_mode is not None:
        witness.subgroup_step_ranges = _input_checks(
            fc, values, witness.stage_ranges
        )
    input_end = len(asm.s.code)
    msm_start = input_end
    if claim_mode is not None:
        from msm import append_claim_msm

        claim_output, witness.shamir_step_ranges = append_claim_msm(
            fc, values, witness.layout, fixture, claim_mode
        )
    else:
        claim_output = None
    msm_end = len(asm.s.code)

    for name in ("L", "C", "A"):
        x, y = values[name]
        eval_x, eval_y = values["evals"][name]
        y_inverse = fc.multiply(y, eval_y)
        fc.equal_constant(y_inverse, (1,), consume=True)
        x_inverse = fc.multiply(x, eval_y)
        x_inverse = fc.op(FP, "add", x_inverse, eval_x, consume=(True, False))
        fc.equal_constant(x_inverse, (0,), consume=True)
        if name != "L" or claim_mode is None:
            fc.drop(x, y)

    c_product = fc.fp12_multiply(values["c"], values["c_inv"], False, False)
    fc.equal_constant(c_product, (1,) + (0,) * 11, consume=True)
    fc.allowed_wi(values["wi"])

    target_eval_values = _eval_point(
        __import__("py_ecc.bn128", fromlist=["neg"]).neg(g1(vk["alpha_g1"]))
    )
    fixed_evals = (
        _copy_point(fc, values["evals"]["L"]),
        _copy_point(fc, values["evals"]["C"]),
        tuple((fc.push((value,), "target-eval")[0],) for value in target_eval_values),
    )
    fixed_qs = (
        __import__("py_ecc.bn128", fromlist=["neg"]).neg(g2(vk["gamma_g2"])),
        __import__("py_ecc.bn128", fromlist=["neg"]).neg(g2(vk["delta_g2"])),
        g2(vk["beta_g2"]),
    )
    fixed_traces = tuple(prepare_g2(point) for point in fixed_qs)

    miller_b = _copy_point(fc, values["B"])
    miller_eval_a = _copy_point(fc, values["evals"]["A"])
    miller_c = fc.copy(values["c"])
    miller_c_inv = fc.copy(values["c_inv"])
    t = _copy_point(fc, miller_b)
    neg_b_y = _negate_fp2(fc, miller_b[1])
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

    accumulator = fc.copy(miller_c_inv)
    digits = tuple(reversed(ATE_LOOP_COUNT[:-1]))

    def store_miller_state(accumulator, point, line_hash):
        state = (*accumulator, *point[0], *point[1])
        for index, value in enumerate(state):
            fc.bounds.pop(value, None)
            asm.fetch(value, consume=True)
            if index >= FP12.degree:
                asm.push(P)
                canonical = V("miller-state")
                asm.op("MOD", 2, canonical)
            asm.op("TOALTSTACK", 1)
        asm.fetch(line_hash, consume=True)
        asm.op("TOALTSTACK", 1)

    def restore_miller_state():
        line_hash = V("miller-line-hash")
        asm.op("FROMALTSTACK", 0, line_hash)
        restored = []
        for _ in range(FP12.degree + 4):
            value = V("miller-state")
            asm.op("FROMALTSTACK", 0, value)
            fc.bounds[value] = 1
            restored.append(value)
        accumulator = tuple(reversed(restored[4:]))
        point = tuple(reversed(restored[:4]))
        return line_hash, accumulator, (point[:2], point[2:])

    miller_start = len(asm.s.code)
    line_hash = asm.push(hashlib.sha256(LINE_HASH_DOMAIN).digest(), V("miller-line-hash"))
    store_miller_state(accumulator, t, line_hash)
    miller_step_ranges = []
    for step_index, digit in enumerate(digits):
        step_start = len(asm.s.code)
        step = values["miller_steps"][step_index]
        line_hash, accumulator, t = restore_miller_state()
        line_hash = fc.hash_chain_step(line_hash, step["constants"])
        accumulator = fc.fp12_square(accumulator)
        if digit == 1:
            accumulator = fc.fp12_multiply(accumulator, miller_c_inv, True, False)
        elif digit == -1:
            accumulator = fc.fp12_multiply(accumulator, miller_c, True, False)

        for pair_index, line in enumerate(step["double_lines"]):
            accumulator = fc.line_rhs_values(
                accumulator, line[:2], line[2:], *fixed_evals[pair_index]
            )

        accumulator, t = _double_dynamic(
            fc, accumulator, t, step["double_slope"], *miller_eval_a
        )
        if digit:
            for pair_index, line in enumerate(step["add_lines"]):
                accumulator = fc.line_rhs_values(
                    accumulator, line[:2], line[2:], *fixed_evals[pair_index]
                )
            q = (miller_b[0], neg_b_y if digit == -1 else miller_b[1])
            accumulator, t = _add_dynamic(
                fc, accumulator, t, q, step["add_slope"], *miller_eval_a
            )
        else:
            fc.drop(step["add_slope"], *step["add_lines"])
        store_miller_state(accumulator, t, line_hash)
        miller_step_ranges.append((step_start, len(asm.s.code)))
    line_hash, accumulator, t = restore_miller_state()
    asm.fetch(line_hash, consume=True)
    asm.push(witness.layout["line_hash"])
    asm.op("EQUALVERIFY", 2)
    miller_end = len(asm.s.code)

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
        q = (q1_x, q1_y) if line_index == 0 else (q2_x, q2_y)
        accumulator, t = _add_dynamic(
            fc,
            accumulator,
            t,
            q,
            values["final_slopes"][line_index],
            *miller_eval_a,
        )

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
        *values["line_constants"],
        values["c"],
        values["c_inv"],
        values["wi"],
        *miller_b,
        *miller_eval_a,
        miller_c,
        miller_c_inv,
        *fixed_evals[0],
        *fixed_evals[1],
        *fixed_evals[2],
        *t,
        neg_b_y,
        q1_x,
        q1_y,
        q2_x,
        q2_y,
    )
    asm.drop_top(len(asm.st))
    if claim_output is not None:
        asm.op("FROMALTSTACK", 0, claim_output)
    else:
        asm.push(1)
    if claim_mode is not None:
        witness.stage_ranges["claim_msm"] = (msm_start, msm_end)
    else:
        witness.stage_ranges["input_checks"] = (input_start, input_end)
    witness.stage_ranges["miller"] = (msm_end, miller_end)
    witness.stage_ranges["final"] = (miller_end, len(asm.s.code))
    witness.miller_step_ranges = miller_step_ranges
    return asm.s, witness
