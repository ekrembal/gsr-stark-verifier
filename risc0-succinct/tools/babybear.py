"""BabyBear field and its quartic extension F_p[x]/(x^4 + 11), matching risc0-core."""
P = 2013265921
R = (1 << 32) % P
R_INV = pow(R, P - 2, P)
NBETA = P - 11

# risc0-core ROU_FWD / ROU_REV (canonical values), index = log2 of the subgroup order.
ROU_FWD = [1, 2013265920, 284861408, 1801542727, 567209306, 740045640, 918899846, 1881002012,
           1453957774, 65325759, 1538055801, 515192888, 483885487, 157393079, 1695124103, 2005211659,
           1540072241, 88064245, 1542985445, 1269900459, 1461624142, 825701067, 682402162, 1311873874,
           1164520853, 352275361, 18769, 137]
ROU_REV = [1, 2013265920, 1728404513, 1592366214, 196396260, 1253260071, 72041623, 1091445674,
           145223211, 1446820157, 1030796471, 2010749425, 1827366325, 1239938613, 246299276,
           596347512, 1893145354, 246074437, 1525739923, 1194341128, 1463599021, 704606912, 95395244,
           15672543, 647517488, 584175179, 137728885, 749463956]


def to_mont(v: int) -> int:
    return v * R % P


def from_mont(w: int) -> int:
    return w * R_INV % P


Ext = tuple  # (c0, c1, c2, c3), canonical

ZERO = (0, 0, 0, 0)
ONE = (1, 0, 0, 0)


def e(x: int) -> Ext:
    return (x % P, 0, 0, 0)


def add(a: Ext, b: Ext) -> Ext:
    return tuple((x + y) % P for x, y in zip(a, b))


def sub(a: Ext, b: Ext) -> Ext:
    return tuple((x - y) % P for x, y in zip(a, b))


def mul(a: Ext, b: Ext) -> Ext:
    a0, a1, a2, a3 = a
    b0, b1, b2, b3 = b
    return ((a0 * b0 + NBETA * (a1 * b3 + a2 * b2 + a3 * b1)) % P,
            (a0 * b1 + a1 * b0 + NBETA * (a2 * b3 + a3 * b2)) % P,
            (a0 * b2 + a1 * b1 + a2 * b0 + NBETA * (a3 * b3)) % P,
            (a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0) % P)


def scale(a: Ext, s: int) -> Ext:
    return tuple(x * s % P for x in a)


def power(a: Ext, n: int) -> Ext:
    out = ONE
    while n:
        if n & 1:
            out = mul(out, a)
        a = mul(a, a)
        n >>= 1
    return out


def inv(a: Ext) -> Ext:
    return power(a, P ** 4 - 2)


def poly_eval(coeffs: list, x: Ext) -> Ext:
    tot, mul_x = ZERO, ONE
    for c in coeffs:
        tot = add(tot, mul(c, mul_x))
        mul_x = mul(mul_x, x)
    return tot


def interpolate_ntt(io: list) -> None:
    """risc0-zkp core::ntt::interpolate_ntt (rev_butterfly recursion), in place on extension values."""
    def rev(lo: int, n: int) -> None:
        if n == 0:
            return
        half = 1 << (n - 1)
        step, cur = ROU_REV[n], 1
        for i in range(half):
            a, b = io[lo + i], io[lo + i + half]
            io[lo + i] = add(a, b)
            io[lo + i + half] = scale(sub(a, b), cur)
            cur = cur * step % P
        rev(lo, n - 1)
        rev(lo + half, n - 1)
    n = len(io).bit_length() - 1
    assert 1 << n == len(io)
    rev(0, n)
    norm = pow(len(io), P - 2, P)
    for i in range(len(io)):
        io[i] = scale(io[i], norm)


def bit_reverse(io: list) -> None:
    n = len(io).bit_length() - 1
    for i in range(len(io)):
        r = int(format(i, f"0{n}b")[::-1], 2) if n else 0
        if i < r:
            io[i], io[r] = io[r], io[i]
