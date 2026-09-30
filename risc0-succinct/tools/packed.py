"""Packed BabyBear arithmetic for Tapscript v2.

An extension element (x^4 = -11) is one unsigned integer holding coefficient k in the 96-bit lane at bit 96*k.
Lanes are lazily reduced: every value carries a compile-time exclusive bound per lane, and each Script fragment
here states the input bound it needs and the output bound it guarantees. A base-field value is a scalar, which is
an extension element whose upper lanes are zero.
"""
from babybear import P

W = 96
LANES = 4
NBETA_ABS = 11
MUL_IN_BOUND = 1 << 35  # ext_mul inputs: products of 4 terms stay below 2**72 per lane
REDUCED = 4 * P  # Barrett output bound


def pack(values: list[int]) -> int:
    return sum(v << (W * i) for i, v in enumerate(values))


def unpack(x: int, lanes: int = LANES) -> list[int]:
    return [(x >> (W * i)) & ((1 << W) - 1) for i in range(lanes)]


def lane_mask(bits: int, lanes: int = LANES) -> int:
    return pack([(1 << bits) - 1] * lanes)


def canonical(x: int) -> tuple:
    return tuple(v % P for v in unpack(x))


def barrett_bits(bound: int) -> int:
    bits = max((bound - 1).bit_length(), 36)
    assert bits <= 78, bits
    return min(bits + (-bits) % 4, 78)


class Barrett:
    """Lane-wise x -> x - q*P with q = floor-estimate(x / P); needs lanes < 2**bits, returns lanes < 4P."""

    A = 30

    def __init__(self, bits: int) -> None:
        assert 36 <= bits <= 78
        self.bits = bits
        self.m = (1 << bits) // P
        self.b = bits - self.A
        assert (bits - self.A) + self.m.bit_length() <= W
        self.mask1 = lane_mask(W - self.A)
        self.mask2 = lane_mask(W - self.b)

    def ops(self) -> list:
        return ["DUP", self.A, "RSHIFT", self.mask1, "AND", self.m, "MUL", self.b, "RSHIFT", self.mask2, "AND",
                P, "MUL", "SUB"]

    def emulate(self, x: int) -> int:
        t = (x >> self.A) & self.mask1
        q = ((t * self.m) >> self.b) & self.mask2
        return x - q * P


EXT_PRODUCT = 1 << 72
EXT_K = P * -(-(NBETA_ABS * EXT_PRODUCT) // P)
EXT_K4 = pack([EXT_K] * LANES)
EXT_MASK4 = (1 << (W * LANES)) - 1
EXT_BARRETT = Barrett(barrett_bits(EXT_K + EXT_PRODUCT))


def ext_mul_ops() -> list:
    """(a b -- a*b) for lanes < 2**35; result lanes < 4P."""
    return ["MUL", "DUP", EXT_MASK4, "AND", "SWAP", W * LANES, "RSHIFT", NBETA_ABS, "MUL", "SWAP", EXT_K4, "ADD",
            "SWAP", "SUB"] + EXT_BARRETT.ops()


def ext_mul_emulate(a: int, b: int) -> int:
    c = a * b
    return EXT_BARRETT.emulate((c & EXT_MASK4) + EXT_K4 - NBETA_ABS * (c >> (W * LANES)))


CANON_C2 = pack([(1 << 33) - 2 * P] * LANES)
CANON_C1 = pack([(1 << 32) - P] * LANES)
LANE_ONES = pack([1] * LANES)


def canon_ops() -> list:
    """(x -- canonical x) for lanes < 4P: subtract 2P where lane >= 2P, then P where lane >= P."""
    return ["DUP", CANON_C2, "ADD", 33, "RSHIFT", LANE_ONES, "AND", 2 * P, "MUL", "SUB",
            "DUP", CANON_C1, "ADD", 32, "RSHIFT", LANE_ONES, "AND", P, "MUL", "SUB"]


def canon_emulate(x: int) -> int:
    x -= ((x + CANON_C2) >> 33 & LANE_ONES) * 2 * P
    return x - ((x + CANON_C1) >> 32 & LANE_ONES) * P


ZERO8 = bytes(8)


def spread_ops() -> list:
    """(s -- packed) for a 16-byte string of four little-endian words: w0 | 0^8 | w1 | 0^8 | w2 | 0^8 | w3."""
    return ["DUP", 0, 4, "SUBSTR", ZERO8, "CAT", "OVER", 4, 4, "SUBSTR", "CAT", ZERO8, "CAT", "OVER", 8, 4,
            "SUBSTR", "CAT", ZERO8, "CAT", "SWAP", 12, 4, "SUBSTR", "CAT"]


def spread_emulate(s: bytes) -> int:
    return pack([int.from_bytes(s[4 * k:4 * k + 4], "little") for k in range(4)])


def sub_constant(bound: int, ext: bool) -> int:
    """A lane-wise multiple of P at least `bound`, added before subtracting a value below `bound`."""
    k = P * -(-bound // P)
    return pack([k] * LANES) if ext else k
