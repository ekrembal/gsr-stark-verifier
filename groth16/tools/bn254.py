"""Pure-Python BN254 reference using py_ecc's Python field and pairing implementation."""

from __future__ import annotations

import json
import random
from pathlib import Path

from py_ecc import bn128
from py_ecc.bn128 import FQ, FQ2, FQ12, add, b, b2, curve_order, is_on_curve, multiply, neg
from py_ecc.bn128.bn128_pairing import (
    add as ext_add,
    ate_loop_count,
    cast_point_to_fq12,
    double,
    final_exponentiate,
    linefunc,
    log_ate_loop_count,
    twist,
)

P = bn128.field_modulus
R = curve_order
G2_X0 = 4965661367192848881
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
LAMBDA = int(
    "10486551571378427818905133077457505975146652579011797175399169355881771981095211883813744499745558409789005132135496770941292989421431235276221147148858384772096778432243207188878598198850276842458913349817007302752534892127325269"
)
EXP = P**12 - 1
H = EXP // R
S = 3
T = EXP // (3**S)
K = (T + 1) // 3
M = LAMBDA // R
MM = M // 3
MM_INV = pow(MM, -1, R * H)
COFACTOR_CUBIC = 3 ** (S - 1) * T


def sqrt_mod(value: int) -> int | None:
    value %= P
    if value == 0:
        return 0
    if pow(value, (P - 1) // 2, P) != 1:
        return None
    q, s = P - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (P - 1) // 2, P) != P - 1:
        z += 1
    m, c, t, root = s, pow(z, q, P), pow(value, q, P), pow(value, (q + 1) // 2, P)
    while t != 1:
        i, t2 = 1, t * t % P
        while t2 != 1:
            t2 = t2 * t2 % P
            i += 1
        b = pow(c, 1 << (m - i - 1), P)
        root = root * b % P
        c = b * b % P
        t = t * c % P
        m = i
    return root


def sqrt_fp2(value: FQ2) -> FQ2 | None:
    a, b = map(int, value.coeffs)
    norm = sqrt_mod((a * a + b * b) % P)
    if norm is None:
        return None
    inverse_two = pow(2, -1, P)
    for signed_norm in (norm, -norm % P):
        real = sqrt_mod((a + signed_norm) * inverse_two)
        if real is None:
            continue
        if real:
            imaginary = b * pow(2 * real, -1, P) % P
            candidate = FQ2([real, imaginary])
            if candidate * candidate == value:
                return candidate
        elif b == 0:
            imaginary = sqrt_mod((signed_norm - a) * inverse_two % P)
            if imaginary is not None:
                candidate = FQ2([0, imaginary])
                if candidate * candidate == value:
                    return candidate
    return None


def split_digest(digest_hex: str) -> tuple[int, int]:
    raw = bytes.fromhex(digest_hex)
    if len(raw) != 32:
        raise ValueError("RISC Zero digest must be 32 bytes")
    return int.from_bytes(raw[:16], "little"), int.from_bytes(raw[16:], "little")


def g1(point: list[str | int]):
    return FQ(int(point[0])), FQ(int(point[1]))


def g2(point: list[list[str | int]]):
    return FQ2([int(point[0][1]), int(point[0][0])]), FQ2(
        [int(point[1][1]), int(point[1][0])]
    )


def psi_g2(point, power: int = 1):
    if power < 0:
        raise ValueError("Frobenius power must be nonnegative")
    if point is None:
        return None
    x, y = point
    for _ in range(power):
        x, y = x**P * PSI_X, y**P * PSI_Y
    return x, y


def is_g2_subgroup_x0(point) -> bool:
    """Check gnark-crypto's BN254 G2 subgroup relation using the 63-bit x0."""
    if point is None:
        return True
    x0_point = multiply(point, G2_X0)
    x0_plus_one = add(x0_point, point)
    psi_x0 = psi_g2(x0_point)
    psi2_x0 = psi_g2(psi_x0)
    left = add(add(x0_plus_one, psi_x0), psi2_x0)
    doubled_x0 = add(x0_point, x0_point)
    right = psi_g2(doubled_x0, 3)
    return left == right


def add_g1(points):
    acc = bn128.Z1
    for point in points:
        acc = add(acc, point)
    return acc


def linear_combination(points, scalars):
    acc = bn128.Z1
    for point, scalar in zip(points, scalars, strict=True):
        acc = add(acc, multiply(point, scalar % R))
    return acc


def miller_product(pairs):
    acc = FQ12.one()
    for q, p in pairs:
        q = twist(q)
        p = cast_point_to_fq12(p)
        r = q
        f = FQ12.one()
        for i in range(log_ate_loop_count, -1, -1):
            f = f * f * linefunc(r, r, p)
            r = double(r)
            if ate_loop_count & (2**i):
                f *= linefunc(r, q, p)
                r = ext_add(r, q)
        q1 = (q[0] ** P, q[1] ** P)
        nq2 = (q1[0] ** P, -(q1[1] ** P))
        f *= linefunc(r, q1, p)
        r = ext_add(r, q1)
        f *= linefunc(r, nq2, p)
        acc *= f
    return acc


def pairing_equation(proof: dict, public_inputs: list[str], vk: dict) -> bool:
    if len(public_inputs) != 5 or len(vk["ic"]) != 6:
        return False
    a, proof_b, c = g1(proof["a"]), g2(proof["b"]), g1(proof["c"])
    if not is_on_curve(a, b) or not is_on_curve(c, b) or not is_on_curve(proof_b, b2):
        return False
    l = linear_combination([g1(x) for x in vk["ic"]], [1, *map(int, public_inputs)])
    alpha, beta = g1(vk["alpha_g1"]), g2(vk["beta_g2"])
    gamma, delta = g2(vk["gamma_g2"]), g2(vk["delta_g2"])
    lhs = bn128.pairing(proof_b, a)
    lhs *= bn128.pairing(gamma, neg(l))
    lhs *= bn128.pairing(delta, neg(c))
    return lhs == bn128.pairing(beta, alpha)


class Fp6:
    """Fp2[v]/(v^3-(9+i)), matching the BN254 tower used by RISC Zero."""

    __slots__ = ("coeffs",)
    xi = FQ2([9, 1])

    def __init__(self, coeffs=(0, 0, 0)):
        self.coeffs = tuple(x if isinstance(x, FQ2) else FQ2([int(x), 0]) for x in coeffs)
        if len(self.coeffs) != 3:
            raise ValueError("Fp6 needs three Fp2 coefficients")

    def __add__(self, other):
        other = other if isinstance(other, Fp6) else Fp6((other, 0, 0))
        return Fp6(tuple(a + b for a, b in zip(self.coeffs, other.coeffs, strict=True)))

    __radd__ = __add__

    def __neg__(self):
        return Fp6(tuple(-x for x in self.coeffs))

    def __sub__(self, other):
        return self + (-other if isinstance(other, Fp6) else Fp6((-int(other), 0, 0)))

    def __mul__(self, other):
        other = other if isinstance(other, Fp6) else Fp6((other, 0, 0))
        a0, a1, a2 = self.coeffs
        b0, b1, b2 = other.coeffs
        return Fp6(
            (
                a0 * b0 + self.xi * (a1 * b2 + a2 * b1),
                a0 * b1 + a1 * b0 + self.xi * a2 * b2,
                a0 * b2 + a1 * b1 + a2 * b0,
            )
        )

    __rmul__ = __mul__

    def __pow__(self, exponent: int):
        if exponent < 0:
            return self.inverse() ** (-exponent)
        result, base = Fp6((1, 0, 0)), self
        while exponent:
            if exponent & 1:
                result *= base
            base *= base
            exponent >>= 1
        return result

    def inverse(self):
        if not any(self.coeffs):
            raise ZeroDivisionError
        return self ** (P**6 - 2)


Fp = FQ
Fp2 = FQ2
Fp12 = FQ12


def _witness_root() -> FQ12:
    rng = random.Random(0)
    one = FQ12.one()
    for _ in range(100):
        z = FQ12([rng.randrange(P) for _ in range(12)])
        if z**COFACTOR_CUBIC == one:
            continue
        w = z**T
        if w != one and w**H == one and w**COFACTOR_CUBIC != one:
            return w
    raise RuntimeError("failed to find a cubic-nonresidue witness constant")


W = _witness_root()


def _tonelli_shanks_cubic(a: FQ12) -> FQ12:
    r = a**T
    e = 3 ** (S - 1)
    h, cc, c = FQ12.one(), W**e, FQ12.one() / W
    for i in range(1, S):
        d = r ** (3 ** (S - i - 1))
        if d == cc:
            h, r = h * c, r * c**3
        elif d == cc**2:
            h, r = h * c**2, r * c**6
        c = c**3
    root = a**K * h
    if T == 3 * K + 1:
        root = FQ12.one() / root
    return root


def compute_c_wi(f: FQ12) -> tuple[FQ12, FQ12, FQ12]:
    """BitVM's compute_c_wi math; returns c, c^-1, and wi for an r-th residue f."""
    one = FQ12.one()
    if f**H != one:
        raise ValueError("Miller product is not an r-th residue")
    wi = one
    for _ in range(3):
        if (f * wi) ** COFACTOR_CUBIC == one:
            break
        wi *= W
    else:
        raise ValueError("no residue-witness coset selected")
    f1 = f * wi
    f2 = f1 ** pow(R, -1, H)
    f3 = f2**MM_INV
    if f3**COFACTOR_CUBIC != one:
        raise ValueError("residue-witness cubic-root precondition failed")
    c = _tonelli_shanks_cubic(f3)
    c_inv = one / c
    if c**LAMBDA != f1 or f * wi * c_inv**LAMBDA != one:
        raise ValueError("residue-witness relation failed")
    return c, c_inv, wi


def verify_fixture(path: Path) -> dict:
    fixture = json.loads(path.read_text())
    expected = [
        *split_digest(fixture["control_root"]),
        *split_digest(fixture["claim_digest"]),
        int.from_bytes(bytes.fromhex(fixture["bn254_control_id"]), "little"),
    ]
    public_inputs = list(map(int, fixture["public_inputs"]))
    if public_inputs != expected:
        raise ValueError("public-input order or digest split differs from RISC Zero")
    proof = fixture["seal"]
    if not pairing_equation(proof, fixture["public_inputs"], fixture["verifying_key"]):
        raise ValueError("fixture pairing equation failed")
    a, proof_b, c = g1(proof["a"]), g2(proof["b"]), g1(proof["c"])
    if multiply(proof_b, R) != bn128.Z2:
        raise ValueError("fixture B is outside G2 subgroup")
    pairs = [
        (proof_b, a),
        (g2(fixture["verifying_key"]["gamma_g2"]), neg(linear_combination(
            [g1(x) for x in fixture["verifying_key"]["ic"]],
            [1, *public_inputs],
        ))),
        (g2(fixture["verifying_key"]["delta_g2"]), neg(c)),
        (g2(fixture["verifying_key"]["beta_g2"]), neg(g1(fixture["verifying_key"]["alpha_g1"]))),
    ]
    miller = miller_product(pairs)
    c_witness, c_inverse, wi = compute_c_wi(miller)
    if final_exponentiate(miller) != FQ12.one():
        raise ValueError("full final exponentiation rejected fixture")
    return {
        "claim_digest": fixture["claim_digest"],
        "public_inputs": public_inputs,
        "residue_relation": miller * wi * c_inverse**LAMBDA == FQ12.one(),
        "c": [int(x) for x in c_witness.coeffs],
        "c_inverse": [int(x) for x in c_inverse.coeffs],
        "wi": [int(x) for x in wi.coeffs],
    }
