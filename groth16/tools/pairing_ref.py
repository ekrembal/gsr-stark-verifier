"""Dynamic BN254 optimal-Ate line traces and a Python Miller-loop twin."""

from __future__ import annotations

from dataclasses import dataclass

from py_ecc import bn128
from py_ecc.bn128 import FQ, FQ2, FQ12, add, curve_order, is_on_curve, multiply, neg
from py_ecc.bn128.bn128_pairing import final_exponentiate

from bn254 import P, g1, g2, linear_combination
from fields import FP12

ATE_LOOP_COUNT = (
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0,
    -1, 0, 0, 0, 0, -1, 0, 0, 1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 1,
    0, -1, 0, 0, 0, -1, 0, -1, 0, 0, 0, 1, 0, 1, 1,
)
LOOP_X = 6 * 4965661367192848881 + 2
assert len(ATE_LOOP_COUNT) == 65
assert sum(digit << i for i, digit in enumerate(ATE_LOOP_COUNT)) == LOOP_X

PSI_X = FQ2(
    [
        21575463638280843010398324269430826099269044274347216827212613867836435027261,
        10307601595873709700152284273816112264069230130616436755625194854815875713954,
    ]
)
PSI_Y = FQ2(
    [
        2821565182194536844548159561693502659359617185244120367078079554186484126554,
        3505843767911556378687030309984248845540243509899259641013678093033130930403,
    ]
)
LINE_INDICES = (0, 1, 6, 7, 8, 9)


@dataclass(frozen=True)
class Line:
    slope: FQ2
    minus_bias: FQ2

    @property
    def coefficients(self):
        return FQ2.one(), self.slope, self.minus_bias


@dataclass(frozen=True)
class LoopStep:
    double: Line
    add: Line | None


@dataclass(frozen=True)
class G2Trace:
    steps: tuple[LoopStep, ...]
    frobenius_lines: tuple[Line, Line]
    slope_witnesses: tuple[tuple[int, int], ...]


def _frob_g2(q):
    return q[0] ** P * PSI_X, q[1] ** P * PSI_Y


def _double(q):
    x, y = q
    slope = (FQ2([3, 0]) * x * x) / (FQ2([2, 0]) * y)
    line = Line(slope, slope * x - y)
    x3 = slope * slope - x - x
    y3 = slope * (x - x3) - y
    return (x3, y3), line


def _add(q, other):
    x, y = q
    ox, oy = other
    slope = (y - oy) / (x - ox)
    line = Line(slope, slope * x - y)
    x3 = slope * slope - x - ox
    y3 = slope * (x - x3) - y
    return (x3, y3), line


def prepare_g2(q) -> G2Trace:
    """Arkworks affine line formulas, with slope hints retained for dynamic Q."""
    t = q
    steps = []
    slopes = []
    neg_q = (q[0], -q[1])
    for digit in reversed(ATE_LOOP_COUNT[:-1]):
        t, double_line = _double(t)
        add_line = None
        if digit:
            t, add_line = _add(t, q if digit == 1 else neg_q)
        steps.append(LoopStep(double_line, add_line))
        slopes.append((int(double_line.slope.coeffs[0]), int(double_line.slope.coeffs[1])))
        if add_line is not None:
            slopes.append((int(add_line.slope.coeffs[0]), int(add_line.slope.coeffs[1])))

    q1 = _frob_g2(q)
    q2 = _frob_g2(q1)
    q2 = (q2[0], -q2[1])
    t, line1 = _add(t, q1)
    t, line2 = _add(t, q2)
    slopes.extend(
        [
            (int(line1.slope.coeffs[0]), int(line1.slope.coeffs[1])),
            (int(line2.slope.coeffs[0]), int(line2.slope.coeffs[1])),
        ]
    )
    return G2Trace(tuple(steps), (line1, line2), tuple(slopes))


def _fq12_from_tower(coefficients: tuple[int, ...]) -> FQ12:
    coeffs = [0] * 12
    for value, (u, v, w) in zip(coefficients, FP12.basis, strict=True):
        degree = 2 * v + w
        if u:
            coeffs[degree + 6] += value
            coeffs[degree] -= 9 * value
        else:
            coeffs[degree] += value
    return FQ12(coeffs)


def _line_mul(f: tuple[int, ...], line: Line, p):
    xx = -p[0] / p[1]
    yy = FQ.one() / p[1]
    c3 = line.slope * xx
    c4 = line.minus_bias * yy
    rhs = (
        1, 0,
        int(c3.coeffs[0]), int(c3.coeffs[1]),
        int(c4.coeffs[0]), int(c4.coeffs[1]),
    )
    return FP12.mul_sparse(f, rhs, LINE_INDICES)


def miller_product_naf(pairs):
    """Four-pair affine Miller loop, returning the raw Fp12 value before final exponentiation."""
    prepared = [prepare_g2(q) for _, q in pairs]
    accumulator = (1,) + (0,) * 11
    for step_index, step in enumerate(prepared[0].steps):
        if step_index:
            accumulator = FP12.square(accumulator)
        for (p, _), q_trace in zip(pairs, prepared, strict=True):
            accumulator = _line_mul(accumulator, q_trace.steps[step_index].double, p)
        digit = list(reversed(ATE_LOOP_COUNT[:-1]))[step_index]
        if digit:
            for (p, _), q_trace in zip(pairs, prepared, strict=True):
                line = q_trace.steps[step_index].add
                if line is None:
                    raise AssertionError("missing addition line for nonzero Ate digit")
                accumulator = _line_mul(accumulator, line, p)
    for line_index in range(2):
        for (p, _), q_trace in zip(pairs, prepared, strict=True):
            accumulator = _line_mul(accumulator, q_trace.frobenius_lines[line_index], p)
    return accumulator, prepared


def fixture_pairing(fixture: dict):
    proof = fixture["seal"]
    vk = fixture["verifying_key"]
    inputs = list(map(int, fixture["public_inputs"]))
    l = linear_combination([g1(point) for point in vk["ic"]], [1, *inputs])
    a, c = g1(proof["a"]), g1(proof["c"])
    b_point = g2(proof["b"])
    pairs = [
        (l, neg(g2(vk["gamma_g2"]))),
        (c, neg(g2(vk["delta_g2"]))),
        (neg(g1(vk["alpha_g1"])), g2(vk["beta_g2"])),
        (a, b_point),
    ]
    raw, traces = miller_product_naf(pairs)
    if final_exponentiate(_fq12_from_tower(raw)) != FQ12.one():
        raise ValueError("signed-NAF multi-Miller product did not verify")
    if not is_on_curve(b_point, bn128.b2) or multiply(b_point, curve_order) != bn128.Z2:
        raise ValueError("invalid fixture B point")
    return raw, traces
