"""Shrink a Tapleaf 0xc2 script by moving repeated instruction sequences into reusable macros.

Repeated windows of the main script and of existing macro bodies become new OP_MACRO declarations (greedy,
longest windows first, cost-aware); all declarations are then ordered topologically with the most-referenced
first, so the busiest macros get one-byte CompactSize indices. The unrolled script is unchanged, so the spend
performs the same computation with fewer committed bytes; the unrolling charge grows by 300 varops per substituted
instruction.

A byte range of the main script can be protected: its instructions are never merged into a macro, so they stay
at the same position relative to the start of the main script. The rollup covenant protects its head (the state
root push) and its prologue (which embeds the root's offset).
"""
import time
from collections import defaultdict
from heapq import heappop, heappush

from gsr import OPS, compact, instruction_length, read_compact

N_MACRO, N_CALLMACRO = OPS["MACRO"], OPS["CALLMACRO"]
MIN_SAVINGS = (8, 12, 16, 24, 32, 48)
DEFAULT_MIN_SAVINGS = (24,)  # the best threshold for the RISC Zero verifier; MIN_SAVINGS searches all (~6x slower)
LENGTHS = (1024, 768, 512, 384, 256, 192, 128, 96, 64, 48, 40, 32, 28, 24, 20, 16, 14, 12, 10, 8, 7, 6, 5, 4, 3, 2)


def split(script: bytes) -> tuple[list[bytes], bytes, int]:
    """-> (macro bodies, main script, offset of the main script)."""
    i, bodies = 0, []
    while i < len(script) and script[i] == N_MACRO:
        n, j = read_compact(script, i + 1)
        bodies.append(script[j:j + n])
        i = j + n
    return bodies, script[i:], i


def tokens(code: bytes) -> list[tuple[str, object, int]]:
    """('T', instruction bytes, offset) or ('M', macro index, offset)."""
    out, p = [], 0
    while p < len(code):
        n = instruction_length(code, p)
        if code[p] == N_CALLMACRO:
            out.append(("M", read_compact(code, p + 1)[0], p))
        else:
            out.append(("T", bytes(code[p:p + n]), p))
        p += n
    return out


def unroll(script: bytes) -> bytes:
    bodies, main, _ = split(script)
    out = bytearray()

    def emit(code: bytes) -> None:
        for kind, value, p in tokens(code):
            if kind == "M":
                emit(bodies[value])
            else:
                out.extend(value)
    emit(main)
    return bytes(out)


class Compressor:
    def __init__(self, script: bytes, min_saving: int, protect: tuple[int, int] = (0, 0)) -> None:
        bodies, main, _ = split(script)
        self.n_old = len(bodies)
        self.ids: dict = {}
        self.toks: list = []
        self.old_bodies = [[self.tid(t[:2]) for t in tokens(b)] for b in bodies]
        lo, hi = protect
        # A protected instruction gets a token of its own, so no window containing it can repeat.
        self.seqs = {"main": [self.tid(("P", t[1], t[2]) if t[0] == "T" and lo <= t[2] < hi else t[:2])
                              for t in tokens(main)]}
        self.new: list[str] = []
        self.min_saving = min_saving

    def tid(self, t) -> int:
        if t not in self.ids:
            self.ids[t] = len(self.toks)
            self.toks.append(t)
        return self.ids[t]

    def cost(self, i: int) -> int:
        t = self.toks[i]
        return len(t[1]) if t[0] in ("T", "P") else 2

    def best_window(self, n: int):
        b1, m1 = 1_000_003, (1 << 61) - 1
        pow_n = pow(b1, n, m1)
        groups = defaultdict(list)
        costs = [self.cost(i) for i in range(len(self.toks))]
        for name, s in self.seqs.items():
            if len(s) < n:
                continue
            h = 0
            for k in range(n):
                h = (h * b1 + s[k] + 1) % m1
            groups[h].append((name, 0))
            for k in range(n, len(s)):
                h = (h * b1 + s[k] + 1 - (s[k - n] + 1) * pow_n) % m1
                groups[h].append((name, k - n + 1))
        best = None
        for occ in groups.values():
            if len(occ) < 2:
                continue
            name0, p0 = occ[0]
            w = tuple(self.seqs[name0][p0:p0 + n])
            wbytes = sum(costs[i] for i in w)
            cnt, last = 0, {}
            for name, p in occ:
                if p < last.get(name, -1) or tuple(self.seqs[name][p:p + n]) != w:
                    continue
                cnt += 1
                last[name] = p + n
            if cnt < 2:
                continue
            saving = cnt * (wbytes - 2) - (wbytes + 1 + len(compact(wbytes)))
            if saving >= self.min_saving and (best is None or saving > best[0]):
                best = (saving, w, cnt)
        return best

    def replace(self, w: tuple, mid: int) -> None:
        n = len(w)
        for name, s in self.seqs.items():
            out, k = [], 0
            while k < len(s):
                if s[k] == w[0] and tuple(s[k:k + n]) == w:
                    out.append(mid)
                    k += n
                else:
                    out.append(s[k])
                    k += 1
            self.seqs[name] = out

    def run(self) -> None:
        for n in LENGTHS:
            while True:
                b = self.best_window(n)
                if not b:
                    break
                _, w, _ = b
                name = f"n{len(self.new)}"
                mid = self.tid(("N", name))
                self.replace(w, mid)
                self.seqs[name] = list(w)
                self.new.append(name)

    def assemble(self) -> tuple[bytes, dict]:
        """Topological order (dependencies first), most-referenced first among ready macros."""
        nodes = [("M", i) for i in range(self.n_old)] + [("N", n) for n in self.new]
        body = {("M", i): self.old_bodies[i] for i in range(self.n_old)}
        body.update({("N", n): self.seqs[n] for n in self.new})
        refs = defaultdict(int)
        deps = {v: set() for v in nodes}
        for owner, seq in [(None, self.seqs["main"])] + [(v, body[v]) for v in nodes]:
            for i in seq:
                t = self.toks[i]
                if t[0] in ("M", "N"):
                    refs[t] += 1
                    if owner is not None:
                        deps[owner].add(t)
        users = defaultdict(set)
        indeg = {v: len(deps[v]) for v in nodes}
        for v in nodes:
            for d in deps[v]:
                users[d].add(v)
        heap, order = [], []
        for v in nodes:
            if indeg[v] == 0:
                heappush(heap, (-refs[v], str(v), v))
        while heap:
            _, _, v = heappop(heap)
            order.append(v)
            for u in users[v]:
                indeg[u] -= 1
                if indeg[u] == 0:
                    heappush(heap, (-refs[u], str(u), u))
        assert len(order) == len(nodes), "cycle"
        index = {v: k for k, v in enumerate(order)}

        def enc(seq: list[int]) -> bytes:
            out = bytearray()
            for i in seq:
                t = self.toks[i]
                out += t[1] if t[0] in ("T", "P") else bytes([N_CALLMACRO]) + compact(index[t])
            return bytes(out)
        decls = b"".join(bytes([N_MACRO]) + compact(len(enc(body[v]))) + enc(body[v]) for v in order)
        return decls + enc(self.seqs["main"]), {"declarations": len(order), "new_macros": len(self.new),
                                                "decl_len": len(decls)}


def compress(script: bytes, protect: tuple[int, int] = (0, 0), min_savings=DEFAULT_MIN_SAVINGS) -> tuple[bytes, dict]:
    """Smallest result over the minimum-saving thresholds. `protect` is a byte range of the main script."""
    t0 = time.time()
    best = None
    for ms in min_savings:
        c = Compressor(script, ms, protect)
        c.run()
        cand, st = c.assemble()
        if best is None or len(cand) < len(best[0]):
            best = (cand, {**st, "min_saving": ms})
    out, st = best
    assert unroll(out) == unroll(script), "unrolled scripts differ"
    return out, {**st, "input_bytes": len(script), "output_bytes": len(out), "seconds": round(time.time() - t0, 1)}
