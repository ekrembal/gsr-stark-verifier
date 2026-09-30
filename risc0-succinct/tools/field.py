"""Emit packed BabyBear arithmetic onto an `Asm`, tracking lane bounds and inserting reductions only when needed."""
import packed as pk
from babybear import P
from gsr import Asm, V, assemble, num as num_bytes

FN_MUL, FN_CANON, FN_SPREAD = 1, 2, 3
ADD_LIMIT = 1 << 76
PRODUCT_LIMIT = 1 << 72


def fn_barrett(bits: int) -> int:
    return 4 + (bits - 33) // 4


def norm(c):
    """Constants: int = base field, tuple = extension; an extension constant with zero upper lanes becomes an int."""
    if isinstance(c, tuple):
        c = tuple(x % P for x in c)
        return c[0] if not any(c[1:]) else c
    return c % P


def lanes(c) -> list[int]:
    return list(c) if isinstance(c, tuple) else [c, 0, 0, 0]


def bound(x) -> int:
    if isinstance(x, V):
        return x.bound
    return max(lanes(x)) + 1


def is_ext(x) -> bool:
    return x.ext if isinstance(x, V) else isinstance(x, tuple)


class Field:
    def __init__(self, a: Asm, inline: bool, used: dict, pool: list[int] | None = None) -> None:
        """`pool`: large constants pushed once, up front, and picked wherever they are used."""
        self.a, self.inline, self.used = a, inline, used
        self.counts: dict[int, int] = {}
        self.pool: dict[int, V] = {}
        serial = V.serial
        for i, value in enumerate(pool or []):
            v = a.push(value, V("pool", 1))
            v.sid = -1 - i
            self.pool[value] = v
        V.serial = serial

    def pooled(self, value: int, v: V) -> V:
        self.counts[value] = self.counts.get(value, 0) + 1
        if value not in self.pool:
            return self.a.push(value, v)
        serial = V.serial
        c = self.a.pick(self.pool[value])
        V.serial = serial
        c.sid, c.bound, c.ext, c.tag = v.sid, v.bound, v.ext, v.tag
        return c

    def pool_candidates(self) -> list[int]:
        """Constants worth pooling: a pick from deep in the stack costs at most four bytes."""
        return sorted(value for value, n in self.counts.items()
                      if (n >= 2 and len(num_bytes(value)) >= 4) or len(num_bytes(value)) >= 8)

    def fn(self, fid: int, ops: list, pops: int, out: V) -> V:
        if self.inline:
            self.a.raw(assemble(ops), pops, out)
        else:
            self.used[fid] = ops
            self.a.call(fid, pops, out)
        return out

    def const(self, c) -> V:
        c = norm(c)
        if isinstance(c, tuple):
            return self.pooled(pk.pack(list(c)), V("c", max(c) + 1, True))
        return self.pooled(c, V("c", c + 1, False))

    def fetch(self, x, consume: bool = False) -> V:
        return self.a.fetch(x, consume) if isinstance(x, V) else self.const(x)

    def reduce_top(self) -> V:
        t = self.a.top()
        if t.ext:
            bits = pk.barrett_bits(t.bound)
            return self.fn(fn_barrett(bits), pk.Barrett(bits).ops(), 1, V("r", pk.REDUCED, True))
        self.a.push(P)
        return self.a.op("MOD", 2, V("r", P, False)).top()

    def reduced_bound(self, x) -> int:
        return (pk.REDUCED if is_ext(x) else P) if isinstance(x, V) else bound(x)

    def operand(self, x, consume: bool, limit: int) -> V:
        v = self.fetch(x, consume)
        if v.bound > limit:
            self.reduce_top()
        return self.a.top()

    def reduce(self, x: V, consume: bool = True) -> V:
        self.fetch(x, consume)
        if self.a.top().bound > (pk.REDUCED if x.ext else P):
            self.reduce_top()
        return self.a.top()

    def canon(self, x: V, consume: bool = True) -> V:
        """Canonical (fully reduced, minimally encoded) value."""
        v = self.reduce(x, consume)
        if v.ext:
            return self.fn(FN_CANON, pk.canon_ops(), 1, V("canon", P, True))
        if v.bound > P:
            self.reduce_top()
        return self.a.top()

    def add(self, x, y, cx: bool = False, cy: bool = False) -> V:
        a = self.operand(x, cx, ADD_LIMIT)
        b = self.operand(y, cy, ADD_LIMIT)
        return self.a.op("ADD", 2, V("+", a.bound + b.bound, a.ext or b.ext)).top()

    def sum(self, items: list[V]) -> V:
        """Sum of the top `len(items)` stack values (already fetched, in order)."""
        n = len(items)
        if n == 1:
            return items[0]
        b = sum(v.bound for v in items)
        assert b < 1 << 78, b.bit_length()
        self.a.push(n)
        self.a.s.op("MULTI", "ADD")
        del self.a.st[-(n + 1):]
        out = V("sum", b, any(v.ext for v in items))
        self.a.st.append(out)
        return out

    def neg_const(self, c):
        return norm(tuple((P - v) % P for v in lanes(c)))

    def sub(self, x, y, cx: bool = False, cy: bool = False) -> V:
        if not isinstance(y, V):
            return self.add(x, self.neg_const(y), cx) if norm(y) else self.fetch(x, cx)
        yb = y.bound if y.bound <= ADD_LIMIT else self.reduced_bound(y)
        k = P << max(0, (-(-yb // P) - 1).bit_length())
        kl = [k] * 4 if y.ext else [k, 0, 0, 0]
        if isinstance(x, V):
            a = self.operand(x, cx, ADD_LIMIT)
            self.pooled(pk.pack(kl), V("k"))
            self.a.op("ADD", 2, V("+k", a.bound + k, a.ext or y.ext))
        else:
            self.pooled(pk.pack([u + v for u, v in zip(lanes(norm(x)), kl)]),
                        V("c", bound(x) + k, is_ext(x) or y.ext))
        a = self.a.top()
        b = self.operand(y, cy, ADD_LIMIT)
        assert b.bound <= k
        return self.a.op("SUB", 2, V("-", a.bound, a.ext or b.ext)).top()

    def mul(self, x, y, cx: bool = False, cy: bool = False) -> V:
        if is_ext(x) and is_ext(y):
            self.operand(x, cx, pk.MUL_IN_BOUND)
            self.operand(y, cy, pk.MUL_IN_BOUND)
            return self.fn(FN_MUL, pk.ext_mul_ops(), 2, V("*", pk.REDUCED, True))
        bx, by = bound(x), bound(y)
        rx = ry = False
        while bx * by >= PRODUCT_LIMIT:
            if bx >= by:
                assert isinstance(x, V) and not rx
                rx, bx = True, self.reduced_bound(x)
            else:
                assert isinstance(y, V) and not ry
                ry, by = True, self.reduced_bound(y)
        a = self.fetch(x, cx)
        if rx:
            a = self.reduce_top()
        b = self.fetch(y, cy)
        if ry:
            b = self.reduce_top()
        return self.a.op("MUL", 2, V("*s", a.bound * b.bound, a.ext or b.ext)).top()
