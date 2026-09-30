#!/usr/bin/env python3
"""Packed BabyBear kernels for a RISC Zero verifier in Tapscript v2, metered in the pinned interpreter.

Each kernel is emitted as real Script, executed by the pinned `bitcoin-util evalscript`, checked for
exact equality against a Python emulation of the same big-integer operations, and the emulation is
checked against BabyBear reference arithmetic. Per-kernel varops are the marginal cost of one more
kernel in a chain: (cost(N2) - cost(N1)) / (N2 - N1).

Layouts. Every field element is a lane of `W` = 12 bytes (96 bits) inside one unsigned integer:
  * extension element (single point): 4 lanes, coefficient k at bit 96*k (Kronecker packing);
  * query vector: 50 lanes, query q at bit 96*q, one base-field coordinate per vector.
Lanes are lazily reduced: values stay below 2**35, not canonical, and are canonicalised only where
the verifier compares them.
"""
import random
import sys

from gsr_script import Script, run

P = 2013265921
NBETA_ABS = 11  # x^4 = -11 in RISC Zero's BabyBear quartic extension
W = 96
EXT_LANES = 4
QUERIES = 50
IN_BITS = 35  # lazily reduced input bound accepted by the multiplication kernels


def lane_mask(bits: int, lanes: int) -> int:
    return sum(((1 << bits) - 1) << (W * i) for i in range(lanes))


def pack(values: list[int]) -> int:
    return sum(v << (W * i) for i, v in enumerate(values))


def unpack(x: int, lanes: int) -> list[int]:
    return [(x >> (W * i)) & ((1 << W) - 1) for i in range(lanes)]


class Barrett:
    """Lane-wise x -> x - floor-estimate(x / p) * p for lanes x < 2**x_bits; result stays < 4p."""

    A = 30

    def __init__(self, x_bits: int, lanes: int):
        self.x_bits, self.lanes = x_bits, lanes
        self.m = (1 << x_bits) // P
        self.b = x_bits - self.A
        assert (x_bits - self.A) + self.m.bit_length() <= W, "lane product overflows"
        self.mask1 = lane_mask(W - self.A, lanes)
        self.mask2 = lane_mask(W - self.b, lanes)

    def script(self) -> Script:
        s = Script().op("DUP").int(self.A).op("RSHIFT").int(self.mask1).op("AND")
        s.int(self.m).op("MUL").int(self.b).op("RSHIFT").int(self.mask2).op("AND")
        return s.int(P).op("MUL", "SUB")

    def emulate(self, x: int) -> int:
        t = (x >> self.A) & self.mask1
        q = ((t * self.m) >> self.b) & self.mask2
        return x - q * P


# Extension multiplication: C = A*B (7 lanes), X = LO + K - 11*HI, then Barrett.
EXT_PRODUCT_BITS = 2 * IN_BITS + 2
EXT_K = P * -(-(NBETA_ABS << EXT_PRODUCT_BITS) // P)
EXT_K4 = pack([EXT_K] * EXT_LANES)
EXT_MASK4 = (1 << (W * EXT_LANES)) - 1
EXT_BARRETT = Barrett((EXT_K + (1 << EXT_PRODUCT_BITS)).bit_length(), EXT_LANES)
EXT_SUB_K = P * -(-(1 << IN_BITS) // P)
EXT_SUB_K4 = pack([EXT_SUB_K] * EXT_LANES)


def ext_ref_mul(a: list[int], b: list[int]) -> list[int]:
    c = [0] * 7
    for i in range(4):
        for j in range(4):
            c[i + j] += a[i] * b[j]
    return [(c[k] - NBETA_ABS * (c[k + 4] if k < 3 else 0)) % P for k in range(4)]


def ext_mul_script(depth: int) -> Script:
    s = Script().int(depth).op("PICK", "MUL", "DUP").int(EXT_MASK4).op("AND", "SWAP").int(W * EXT_LANES)
    s.op("RSHIFT").int(NBETA_ABS).op("MUL", "SWAP").int(EXT_K4).op("ADD", "SWAP", "SUB")
    return s.extend(EXT_BARRETT.script())


def ext_mul_emulate(a: int, b: int) -> int:
    c = a * b
    x = (c & EXT_MASK4) + EXT_K4 - NBETA_ABS * (c >> (W * EXT_LANES))
    return EXT_BARRETT.emulate(x)


def ext_add_script(depth: int) -> Script:
    return Script().int(depth).op("PICK", "ADD")


def ext_sub_script(depth: int) -> Script:
    """top - operand: add a lane-wise multiple of p first so no lane borrows."""
    return Script().int(EXT_SUB_K4).op("ADD").int(depth).op("PICK", "SUB")


# Extension element times a base-field scalar held on the stack (e.g. a per-query power), reduced.
EXT_SCALAR_BARRETT = Barrett(IN_BITS + 33, EXT_LANES)


def ext_scalar_mul_script(depth: int) -> Script:
    return Script().int(depth).op("PICK", "MUL").extend(EXT_SCALAR_BARRETT.script())


# Query vectors.
VEC_BARRETT = Barrett(72, QUERIES)  # after up to 256 multiply-accumulates of (<2**33) * (<p)


def vec_mac_script(depth: int, constant: int) -> Script:
    return Script().int(depth).op("PICK").int(constant).op("MUL", "ADD")


def vec_add_script(depth: int) -> Script:
    return Script().int(depth).op("PICK", "ADD")


def lane_extract_script(depths: list[int], q: int) -> Script:
    """Gather lane q of four coordinate vectors into one packed extension element."""
    s = Script()
    for k in (3, 2, 1, 0):
        s.int(depths[k] + (3 - k)).op("PICK").int(12 * q).int(12).op("SUBSTR")
        if k:
            s.int(W * k).op("LSHIFT")
    return s.int(4).op("MULTI", "ADD")


def row_ext_script(depth: int, index: int) -> Script:
    """Build packed extension element `index` of a 64-word FRI row: words index + 16*k, k = 0..3."""
    s = Script()
    for k in (3, 2, 1, 0):
        s.int(depth + (3 - k)).op("PICK").int(4 * (index + 16 * k)).int(4).op("SUBSTR")
        if k:
            s.int(W * k).op("LSHIFT")
    return s.int(4).op("MULTI", "ADD")


def canonical(v: int) -> list[int]:
    return [x % P for x in unpack(v, EXT_LANES)]


def measure(build, n1: int = 2, n2: int = 6) -> int:
    """Marginal varops of one kernel; `build(n)` returns (script, stack, expected_top, items_below_top)."""
    costs = []
    for n in (n1, n2):
        script, stack, expected, below = build(n)
        script.data(expected.to_bytes((expected.bit_length() + 7) // 8, "little")).op("EQUALVERIFY")
        if below:
            script.int(below).op("MULTI", "DROP")
        script.int(1)
        ok, used, after, err = run(script, stack)
        if not ok:
            sys.exit(f"kernel failed: {err} {after[-3:]}")
        costs.append(used)
    return (costs[1] - costs[0]) // (n2 - n1)


def rand_ext(bound: int = 1 << IN_BITS) -> list[int]:
    return [random.randrange(bound) for _ in range(EXT_LANES)]


def b(v: int) -> bytes:
    return v.to_bytes((v.bit_length() + 7) // 8, "little")


def main() -> tuple[dict[str, int], dict[str, int]]:
    random.seed(1)
    results = {}
    sizes = {}

    # Worst-case bounds: every Barrett instance at its largest admissible lane value, and the extension
    # multiplication at its largest admissible inputs, must stay inside the lanes and reduce below 4p.
    for barrett in (EXT_BARRETT, EXT_SCALAR_BARRETT, VEC_BARRETT, Barrett(72, 22)):
        top = (1 << barrett.x_bits) - 1
        for x in (top, top - 1, P * ((top // P)), 0, P - 1):
            lanes = [x] * barrett.lanes
            out = unpack(barrett.emulate(pack(lanes)), barrett.lanes)
            assert all(o < 4 * P and o % P == x % P for o in out), (barrett.x_bits, x)
    big = [(1 << IN_BITS) - 1] * EXT_LANES
    assert (EXT_K + (1 << EXT_PRODUCT_BITS)) < (1 << EXT_BARRETT.x_bits)
    assert canonical(ext_mul_emulate(pack(big), pack(big))) == ext_ref_mul(big, big)
    assert max(unpack(ext_mul_emulate(pack(big), pack(big)), 4)) < 4 * P
    assert ((1 << IN_BITS) - 1) * (P - 1) < 1 << EXT_SCALAR_BARRETT.x_bits

    # Extension multiply chain: acc <- acc * B, B at depth 1.
    bb = rand_ext()
    a0 = rand_ext()

    def ext_mul_chain(n: int):
        acc, ref = pack(a0), [x % P for x in a0]
        s = Script()
        for _ in range(n):
            s.extend(ext_mul_script(1))
            acc = ext_mul_emulate(acc, pack(bb))
            ref = ext_ref_mul(ref, bb)
            assert canonical(acc) == ref and max(unpack(acc, 4)) < 4 * P
        return s, [b(pack(bb)), b(pack(a0))], acc, 1

    results["ext_mul (Kronecker, reduced)"] = measure(ext_mul_chain)

    def ext_add_chain(n: int):
        acc = pack(a0)
        s = Script()
        for _ in range(n):
            s.extend(ext_add_script(1))
            acc += pack(bb)
        return s, [b(pack(bb)), b(pack(a0))], acc, 1

    results["ext_add (lazy)"] = measure(ext_add_chain)

    small = [random.randrange(4 * P) for _ in range(4)]

    def ext_sub_chain(n: int):
        acc = pack(a0)
        s = Script()
        for _ in range(n):
            s.extend(ext_sub_script(1))
            acc = acc + EXT_SUB_K4 - pack(small)
        return s, [b(pack(small)), b(pack(a0))], acc, 1

    results["ext_sub (lazy)"] = measure(ext_sub_chain)

    w = random.randrange(P)

    def ext_scalar_chain(n: int):
        acc, ref = pack(a0), [x % P for x in a0]
        s = Script()
        for _ in range(n):
            s.extend(ext_scalar_mul_script(1))
            acc = EXT_SCALAR_BARRETT.emulate(acc * w)
            ref = [x * w % P for x in ref]
            assert canonical(acc) == ref and max(unpack(acc, 4)) < 4 * P
        return s, [b(w), b(pack(a0))], acc, 1

    results["ext_scalar_mul (ext x per-query base, reduced)"] = measure(ext_scalar_chain)

    # Query vectors: 50 lanes.
    vec = [random.randrange(4 * P) for _ in range(QUERIES)]
    consts = [random.randrange(P) for _ in range(64)]

    def vec_mac_chain(n: int):
        acc = 0
        s = Script().int(0)
        for i in range(n):
            s.extend(vec_mac_script(1, consts[i]))
            acc += consts[i] * pack(vec)
        return s, [b(pack(vec))], acc, 1

    results["vec_mac (constant x 50-lane vector, accumulate)"] = measure(vec_mac_chain)

    def vec_add_chain(n: int):
        acc = pack(vec)
        s = Script()
        for _ in range(n):
            s.extend(vec_add_script(1))
            acc += pack(vec)
        return s, [b(pack(vec)), b(pack(vec))], acc, 1

    results["vec_add (50 lanes)"] = measure(vec_add_chain)

    unreduced = [random.randrange(1 << 72) for _ in range(QUERIES)]
    for x in unreduced:
        assert VEC_BARRETT.emulate(x) % P == x % P and VEC_BARRETT.emulate(x) < 4 * P

    def vec_reduce_chain(n: int, reduce: bool = True):
        s = Script()
        for _ in range(n):
            s.op("DUP")
            if reduce:
                s.extend(VEC_BARRETT.script())
            s.op("DROP")
        return s, [b(pack(unreduced))], pack(unreduced), 0

    reduced = [VEC_BARRETT.emulate(x) for x in unreduced]
    assert [x % P for x in reduced] == [x % P for x in unreduced] and max(reduced) < 4 * P
    results["vec_reduce (Barrett, 50 lanes)"] = measure(vec_reduce_chain) - measure(
        lambda n: vec_reduce_chain(n, False))

    coords = [[random.randrange(4 * P) for _ in range(QUERIES)] for _ in range(4)]

    def extract_chain(n: int):
        s = Script()
        top = None
        for i in range(n):
            q = (7 * i + 3) % QUERIES
            s.extend(lane_extract_script([3 + i, 2 + i, 1 + i, 0 + i], q))
            top = pack([coords[k][q] for k in range(4)])
        return s, [b(pack(c)) for c in coords], top, 4 + n - 1

    results["lane_extract (4 vectors -> packed ext at one query)"] = measure(extract_chain)

    row = [random.randrange(P) for _ in range(64)]
    row_bytes = b"".join(x.to_bytes(4, "little") for x in row)

    def row_chain(n: int):
        s = Script()
        top = None
        for i in range(n):
            j = (5 * i + 1) % 16
            s.extend(row_ext_script(i, j))
            top = pack([row[j + 16 * k] for k in range(4)])
        return s, [row_bytes], top, n

    results["row_ext (FRI row words -> packed ext)"] = measure(row_chain)

    # Same chain through a defined function: what a table-driven constraint program pays per call.
    body = bytes(ext_mul_script(1).code)

    def ext_mul_invoked(n: int):
        acc = pack(a0)
        s = Script().data(body).int(1).op("DEFINE")
        for _ in range(n):
            s.int(1).op("INVOKE")
            acc = ext_mul_emulate(acc, pack(bb))
        return s, [b(pack(bb)), b(pack(a0))], acc, 1

    results["ext_mul via OP_INVOKE"] = measure(ext_mul_invoked)
    sizes["ext_mul body bytes"] = len(body)

    # Phase vectors: 22 lanes (queries = k mod 3 of a 64-lane column), the layout the transpose emits.
    pvec = [random.randrange(P) for _ in range(22)]

    def pvec_mac_chain(n: int):
        acc = 0
        s = Script().int(0)
        for i in range(n):
            s.extend(vec_mac_script(1, consts[i]))
            acc += consts[i] * pack(pvec)
        return s, [b(pack(pvec))], acc, 1

    results["phase vec_mac (22-lane vector)"] = measure(pvec_mac_chain)
    phase_barrett = Barrett(72, 22)
    punreduced = [random.randrange(1 << 72) for _ in range(22)]
    s_check = Script().extend(phase_barrett.script())
    out = phase_barrett.emulate(pack(punreduced))
    assert [x % P for x in unpack(out, 22)] == [x % P for x in punreduced] and max(unpack(out, 22)) < 4 * P
    ok, _, _, err = run(s_check.data(b(out)).op("EQUAL"), [b(pack(punreduced))])
    assert ok, err
    vout = VEC_BARRETT.emulate(pack(unreduced))
    ok, _, _, err = run(Script().extend(VEC_BARRETT.script()).data(b(vout)).op("EQUAL"), [b(pack(unreduced))])
    assert ok, err

    def pvec_reduce_chain(n: int, reduce: bool = True):
        s = Script()
        for _ in range(n):
            s.op("DUP")
            if reduce:
                s.extend(phase_barrett.script())
            s.op("DROP")
        return s, [b(pack(punreduced))], pack(punreduced), 0

    results["phase vec_reduce (Barrett, 22 lanes)"] = measure(pvec_reduce_chain) - measure(
        lambda n: pvec_reduce_chain(n, False))

    # Equality of two lazily reduced extension elements: D = a + K - b must be p * Q lane-wise, with
    # the per-lane quotients Q supplied in the witness and range-checked to 32 bits.
    eq_a = rand_ext(4 * P)
    eq_b = [(x + random.randrange(4) * P) % (4 * P) for x in eq_a]
    eq_b = [x if x % P == y % P else y for x, y in zip(eq_b, eq_a)]
    eq_d = [x + EXT_SUB_K - y for x, y in zip(eq_a, eq_b)]
    assert all(d % P == 0 for d in eq_d)
    eq_q = pack([d // P for d in eq_d])
    eq_mask = lane_mask(32, EXT_LANES)

    def ext_eq_chain(n: int):
        s = Script()
        for _ in range(n):
            # stack: Q b a  ->  Q b a
            s.op("DUP").extend(ext_sub_script(2)).int(3).op("PICK", "DUP").int(eq_mask).op("AND")
            s.op("OVER", "NUMEQUALVERIFY").int(P).op("MUL", "NUMEQUALVERIFY")
        return s, [b(eq_q), b(pack(eq_b)), b(pack(eq_a))], pack(eq_a), 2

    results["ext_eq (hinted canonical equality)"] = measure(ext_eq_chain)
    script, stack, _, _ = ext_eq_chain(1)
    assert run(script.op("2DROP", "DROP").int(1), stack)[0], "ext_eq rejected equal values"
    for wrong_b, q in ((pack(eq_b) + 1, eq_q), (pack(eq_b), eq_q + 1), (pack(eq_b) + P, eq_q + (1 << 40))):
        script, stack, _, _ = ext_eq_chain(1)
        stack[0], stack[1] = b(q), b(wrong_b)
        assert not run(script.op("2DROP", "DROP").int(1), stack)[0], "ext_eq accepted unequal values"

    # Lane insert: place a per-query scalar into lane q of a 22-lane phase vector.
    scalars = [random.randrange(P) for _ in range(22)]

    def lane_insert_chain(n: int):
        s = Script().int(0)
        acc = 0
        for i in range(n):
            s.int(i + 1).op("PICK").int(W * i).op("LSHIFT", "ADD")
            acc += scalars[i] << (W * i)
        return s, [b(x) for x in reversed(scalars[:n])], acc, n

    results["lane_insert (scalar -> phase-vector lane)"] = measure(lane_insert_chain)

    return results, sizes


def report() -> None:
    results, sizes = main()
    for name, cost in results.items():
        print(f"{name:55s} {cost:>9,}")
    for name, size in sizes.items():
        print(f"{name:55s} {size:>9,}")


if __name__ == "__main__":
    report()
