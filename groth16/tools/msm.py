"""Fixed-window RISC Zero public-input MSM for the BN254 G1 verifying key."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from py_ecc.bn128 import G1, add, multiply, neg

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "risc0-succinct/tools"))
from bn254 import P, R, g1, linear_combination
from fields import FP
from gsr import Script, V

WINDOWS = 32
WINDOW_BITS = 4
TABLE_SIZE = 1 << WINDOW_BITS
_DATA_CACHE = {}


def claim_scalars(fixture: dict) -> tuple[int, int]:
    digest = bytes.fromhex(fixture["claim_digest"])
    c0, c1 = int.from_bytes(digest[:16], "little"), int.from_bytes(digest[16:], "little")
    if [c0, c1] != list(map(int, fixture["public_inputs"][2:4])):
        raise ValueError("claim split disagrees with the RISC Zero public inputs")
    return c0, c1


def _fixed_base(fixture: dict):
    inputs = list(map(int, fixture["public_inputs"]))
    ic = [g1(point) for point in fixture["verifying_key"]["ic"]]
    fixed = linear_combination((ic[i] for i in (0, 1, 2, 5)),
                               (1, inputs[0], inputs[1], inputs[4]))
    return fixed, ic[3], ic[4]


def _make_tables(fixture: dict, c0: int, c1: int, retry: int):
    fixed, ic3, ic4 = _fixed_base(fixture)
    tables = []
    offsets = []
    for index in range(2 * WINDOWS):
        scalar = int.from_bytes(
            hashlib.sha256(f"groth16-msm-offset-v1:{retry}:{index}".encode()).digest(), "little"
        ) % R
        offset = multiply(G1, scalar)
        if offset is None:
            return None
        base = ic3 if index < WINDOWS else ic4
        window = index if index < WINDOWS else index - WINDOWS
        base = multiply(base, 1 << (WINDOW_BITS * window))
        table = [add(offset, multiply(base, digit)) for digit in range(TABLE_SIZE)]
        if any(point is None for point in table):
            return None
        tables.append(table)
        offsets.append(offset)
    offset_sum = None
    for offset in offsets:
        offset_sum = add(offset_sum, offset)
    accumulator = add(fixed, neg(offset_sum))
    if accumulator is None:
        return None

    slopes = []
    digits = [(c0 >> (WINDOW_BITS * i)) & 15 for i in range(WINDOWS)]
    digits += [(c1 >> (WINDOW_BITS * i)) & 15 for i in range(WINDOWS)]
    for table, digit in zip(tables, digits, strict=True):
        q = table[digit]
        dx = accumulator[0] - q[0]
        if not dx:
            return None
        slope = (accumulator[1] - q[1]) / dx
        accumulator = add(accumulator, q)
        if accumulator is None:
            return None
        slopes.append(int(slope) % P)

    expected = add(fixed, add(multiply(ic3, c0), multiply(ic4, c1)))
    if accumulator != expected:
        raise AssertionError("offset MSM does not match the claim linear combination")
    return accumulator, tables, offsets, slopes


def build_msm_data(fixture: dict, c0: int, c1: int):
    """Build deterministic offset tables and the fixture's affine slope trace."""
    key = (
        tuple(map(int, fixture["public_inputs"])),
        tuple(tuple(map(str, point)) for point in fixture["verifying_key"]["ic"]),
        c0,
        c1,
    )
    if key in _DATA_CACHE:
        return _DATA_CACHE[key]
    for retry in range(64):
        result = _make_tables(fixture, c0, c1, retry)
        if result is not None:
            fixed, _, _ = _fixed_base(fixture)
            offsets = [
                multiply(G1, int.from_bytes(
                    hashlib.sha256(f"groth16-msm-offset-v1:{retry}:{index}".encode()).digest(), "little"
                ) % R)
                for index in range(2 * WINDOWS)
            ]
            offset_sum = None
            for offset in offsets:
                offset_sum = add(offset_sum, offset)
            initial = add(fixed, neg(offset_sum))
            _, tables, _, slopes = result
            data = {"initial": initial, "tables": tables, "slopes": slopes,
                    "expected": result[0], "retry": retry}
            _DATA_CACHE[key] = data
            return data
    raise RuntimeError("could not find non-degenerate affine MSM offsets")


def _select_table_point(fc, table, digit):
    asm = fc.asm
    table_items = []
    for point in reversed(table):
        table_items.append(asm.push(int(point[0]), V("msm-table")))
        table_items.append(asm.push(int(point[1]), V("msm-table")))

    def index_for_coordinate():
        asm.pick(digit)
        asm.push(2)
        asm.op("MUL", 2, V("msm-index"))
        asm.push(1)
        asm.op("ADD", 2, V("msm-depth"))

    x, y = V("msm-x"), V("msm-y")
    index_for_coordinate()
    asm.op("PICK", 1, x)
    index_for_coordinate()
    asm.op("PICK", 1, y)

    asm.op("TOALTSTACK", 1)
    asm.op("TOALTSTACK", 1)
    asm.drop_top(len(table_items))
    asm.op("FROMALTSTACK", 0, x)
    asm.op("FROMALTSTACK", 0, y)
    return (x,), (y,)


def _check_nonzero(fc, value):
    asm = fc.asm
    asm.fetch(value[0], consume=False)
    asm.push(0)
    equal = V("msm-zero-denominator")
    asm.op("NUMEQUAL", 2, equal)
    asm.push(1)
    asm.raw(Script().op("SWAP", "SUB"), 2, V("msm-nonzero"))
    asm.op("VERIFY", 1)


def _add_g1(fc, accumulator, point, slope):
    ax, ay = accumulator
    qx, qy = point
    dx = fc.op(FP, "sub", ax, qx)
    dy = fc.op(FP, "sub", ay, qy)
    _check_nonzero(fc, dx)
    slope_dx = fc.multiply(slope, dx)
    fc.equal(slope_dx, dy)

    slope_squared = fc.op(FP, "square", slope)
    next_x = fc.op(FP, "sub", slope_squared, ax)
    next_x = fc.op(FP, "sub", next_x, qx, consume=(True, False))
    x_diff = fc.op(FP, "sub", ax, next_x)
    slope_x_diff = fc.multiply(slope, x_diff)
    next_y = fc.op(FP, "sub", slope_x_diff, ay)
    fc.drop(dx, dy, slope_dx, slope_squared, x_diff, slope_x_diff, slope, ax, ay, qx, qy)
    return next_x, next_y


def append_claim_msm(fc, values, layout, fixture: dict, claim_mode: str):
    """Check claim digits, compute L in Script, and optionally return the digest bytes."""
    if claim_mode not in ("fixed", "witness"):
        raise ValueError(claim_mode)
    c0, c1 = values["claim"]
    digits = values["digits"]
    expected_c0, expected_c1 = claim_scalars(fixture)

    for scalar, start in zip((c0, c1), (0, WINDOWS), strict=True):
        rebuilt = fc.asm.push(0, V("claim-recomposition"))
        for index in range(WINDOWS):
            digit = digits[start + index][0]
            fc.asm.fetch(digit, consume=False)
            fc.asm.push(16)
            below16 = V("claim-digit-range")
            fc.asm.op("LESSTHAN", 2, below16)
            fc.asm.op("VERIFY", 1)

            fc.asm.fetch(digit, consume=False)
            if index:
                fc.asm.push(WINDOW_BITS * index)
                shifted = V("claim-digit-shift")
                fc.asm.op("LSHIFT", 2, shifted)
            else:
                shifted = V("claim-digit-shift")
            total = V("claim-recomposition")
            fc.asm.raw(Script().op("ADD"), 2, total)
            rebuilt = total
        fc.asm.fetch(scalar[0], consume=False)
        fc.asm.op("NUMEQUALVERIFY", 2)

    if claim_mode == "fixed":
        fc.equal_constant(c0, (expected_c0,))
        fc.equal_constant(c1, (expected_c1,))

    data = build_msm_data(fixture, expected_c0, expected_c1)
    accumulator = (
        fc.push((int(data["initial"][0]),), "msm-initial"),
        fc.push((int(data["initial"][1]),), "msm-initial"),
    )
    for index, (table, digit, slope) in enumerate(
        zip(data["tables"], (entry[0] for entry in digits), values["msm_slopes"], strict=True)
    ):
        point = _select_table_point(fc, table, digit)
        accumulator = _add_g1(fc, accumulator, point, slope)
    fc.equal(accumulator[0], values["L"][0])
    fc.equal(accumulator[1], values["L"][1])
    fc.drop(*accumulator)

    if claim_mode == "fixed":
        return None
    output = _claim_bytes(fc, values["claim_digest"], c0[0], c1[0])
    fc.asm.op("TOALTSTACK", 1)
    return output


def _claim_bytes(fc, digest, c0, c1):
    """Bind the raw 32-byte digest to the two little-endian RISC Zero claim scalars."""
    asm = fc.asm
    output = asm.pick(digest)
    for scalar, start in ((c0, 0), (c1, 16)):
        rebuilt = asm.push(0, V("claim-recomposition"))
        for offset in range(16):
            asm.fetch(digest, consume=False)
            asm.push(start + offset)
            asm.push(1)
            byte = V("claim-byte")
            asm.op("SUBSTR", 3, byte)
            asm.push(b"\x01")
            tagged_byte = V("claim-byte-positive")
            asm.op("CAT", 2, tagged_byte)
            asm.push(256)
            unsigned_byte = V("claim-byte-value")
            asm.op("SUB", 2, unsigned_byte)
            if offset:
                asm.push(offset * 8)
                shifted = V("claim-byte-shift")
                asm.op("LSHIFT", 2, shifted)
            else:
                shifted = unsigned_byte
            total = V("claim-recomposition")
            asm.raw(Script().op("ADD"), 2, total)
            rebuilt = total
        asm.fetch(scalar, consume=False)
        asm.op("NUMEQUALVERIFY", 2)
    return output
