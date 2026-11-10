#!/usr/bin/env python3
import random

from bn254 import G2_X0, P, R, is_g2_subgroup_x0, sqrt_fp2
from py_ecc.bn128 import G2, b2, is_on_curve, multiply
from py_ecc.bn128 import FQ2

ROOT = 200


def random_twist_point(rng):
    while True:
        x = FQ2([rng.randrange(P), rng.randrange(P)])
        y = sqrt_fp2(x**3 + b2)
        if y is None:
            continue
        if rng.randrange(2):
            y = -y
        point = (x, y)
        if is_on_curve(point, b2) and multiply(point, R) is not None:
            return point


def main():
    rng = random.Random(0xB254)
    for _ in range(ROOT):
        point = multiply(G2, rng.randrange(1, R))
        in_subgroup = multiply(point, R) is None
        if not in_subgroup or not is_g2_subgroup_x0(point):
            raise AssertionError("x0 relation rejected a random G2 subgroup point")

    for _ in range(ROOT):
        point = random_twist_point(rng)
        in_subgroup = multiply(point, R) is None
        if in_subgroup or is_g2_subgroup_x0(point):
            raise AssertionError("x0 relation accepted a random non-subgroup twist point")

    if G2_X0.bit_length() != 63:
        raise AssertionError("expected a 63-bit subgroup scalar")
    print(
        f"G2 x0 subgroup relation: PASS ({ROOT} subgroup, {ROOT} non-subgroup; "
        "[r]B comparison agreed)"
    )


if __name__ == "__main__":
    main()
