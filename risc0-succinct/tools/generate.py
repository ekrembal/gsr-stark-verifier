#!/usr/bin/env python3
"""Generate the Tapscript v2 verifier for a RISC Zero v3.0.6 succinct receipt under the padded SHA-256 suite.

The script is specialized to the recursion circuit (RECURSION:rev1v1, po2 18) and to one statement: the
control ID (code root), the control root it must be a leaf of, the inner control root and the claim digest in the
output globals.
Everything else -- the seal, the control-ID inclusion proof and per-query DEEP quotient hints -- is witness.

All field values are packed: an extension element is four 96-bit lanes of one integer (see packed.py). Row
values are kept in RISC Zero's Montgomery (R-scaled) form; every check is linear in them, so the R factor is
carried through instead of being removed.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

import babybear as bb
import packed as pk
import reference as ref
import witness as wit
from babybear import P
from field import FN_SPREAD, Field, norm
from gsr import Asm, Script, V, assemble

ROOT = Path(__file__).resolve().parents[1]
FN_QUERY = 200
PO2 = 18
DOMAIN_PO2 = PO2 + 2
TRACE_TOP = 32
TRACE_LEVELS = 15
FRI_ROUNDS = 3
FRI_DOMAIN_PO2 = [16, 12, 8]
FRI_LEVELS = wit.FRI_LEVELS
FINAL_DEGREE = 64
OUT_WORDS = 33
MASK_SHORT = 528
MASK_LONG = 10560
CHECK_COMBO = 5
QUERY_ITEMS = ["accum", "accum_path", "code", "code_path", "data", "data_path", "check", "check_path",
               "hints", "fri0", "fri0_path", "fri1", "fri1_path", "fri2", "fri2_path"]
# OP_TX selector: collate, all outputs, amount + scriptPubKey. The result is the concatenation of the serialized
# outputs (u64 LE amount, compact-size scriptPubKey), i.e. the BIP 341 `sha_outputs` preimage.
OUTPUTS_SELECTOR = bytes([0x00, 0x01, 0x00, 0x02, 0x00, 0x03])
CLAIM_OUT = 16
SETUP_ITEMS = ["out", "ctrl_index", "ctrl_path", "code_top", "data_top", "accum_top", "check_top", "coeff",
               "fri_top0", "fri_top1", "fri_top2", "final"]


def word_mask(n_words: int, sel) -> int:
    return sum(0xFFFFFFFF << (32 * i) for i in range(n_words) if sel(i))


class Statement:
    """What the verifier is specialized to (compile-time constants).

    With `covenant`, the claim digest is not a constant: the Script recomputes it with the spending transaction's
    serialized outputs (read with OP_TX) as the journal; the image ID, exit code and other claim fields stay constant.
    """

    def __init__(self, receipt: dict, covenant: bool = False) -> None:
        self.control_id = bytes.fromhex(receipt["control_id"])
        self.control_root = bytes.fromhex(receipt["control_root"])
        self.inner_control_root = bytes.fromhex(receipt["inner_control_root"])
        self.claim_digest = bytes.fromhex(receipt["claim_digest"])
        self.covenant = covenant
        if receipt["hashfn"] != "sha-256-padded" or receipt["circuit_info"] != "RECURSION:rev1v1":
            raise ValueError("unsupported receipt parameters")
        if covenant:
            claim = receipt["claim"]
            if claim["assumptions_digest"] != "00" * 32 or (claim["sys_exit"], claim["user_exit"]) != (0, 0):
                raise ValueError("covenant receipts must be unconditional and halt with exit code 0")
            self.image_id = bytes.fromhex(claim["pre"])
            self.output_head = hashlib.sha256(b"risc0.Output").digest()
            self.output_tail = bytes.fromhex(claim["assumptions_digest"]) + struct.pack("<H", 2)
            self.claim_head = (hashlib.sha256(b"risc0.ReceiptClaim").digest() + bytes.fromhex(claim["input"])
                               + self.image_id + bytes.fromhex(claim["post"]))
            self.claim_tail = struct.pack("<IIH", claim["sys_exit"], claim["user_exit"], 4)
            if self.claim_for(bytes.fromhex(receipt["journal"])) != self.claim_digest:
                raise ValueError("claim digest does not match the claim fields and journal")

    # Covenant extension points: `head()` is emitted before the function definitions and leaves the values named
    # `head_names` on the stack; `extra_items` are witness items above the setup items; `prologue` runs first in
    # the main body and `journal_digest` yields SHA256(journal) for the claim.
    extra_items: tuple[str, ...] = ()
    head_names: tuple[str, ...] = ()

    def head(self) -> Script:
        return Script()

    def prologue(self, m: Asm, items: dict[str, V], heads: list[V]) -> None:
        pass

    def journal_digest(self, m: Asm) -> V:
        m.push(OUTPUTS_SELECTOR)
        m.op("TX", 1, V("journal"))
        return m.op("SHA256", 1, V("jd")).top()

    def claim_for(self, journal: bytes) -> bytes:
        """RISC Zero's ReceiptClaim digest for this image with `journal` (tagged_struct hashing)."""
        output = hashlib.sha256(self.output_head + hashlib.sha256(journal).digest() + self.output_tail).digest()
        return hashlib.sha256(self.claim_head + output + self.claim_tail).digest()

    def fixed_out(self) -> dict[int, int]:
        """Output global index -> required true value (inner control root words, claim digest halves)."""
        fixed = {}
        for i, w in enumerate(struct.unpack("<8I", self.inner_control_root)):
            fixed[2 * i] = w
        if not self.covenant:
            for i, h in enumerate(struct.unpack("<16H", self.claim_digest)):
                fixed[CLAIM_OUT + i] = h
        return fixed


class Rng:
    """The padded SHA-256 transcript: pool0/pool1 digests on the stack."""

    def __init__(self, a: Asm, pool0: bytes, pool1: bytes) -> None:
        self.a = a
        self.p0 = a.push(pool0, V("pool0"))
        self.p1 = a.push(pool1, V("pool1"))
        self.used = 0

    def step(self) -> None:
        a = self.a
        a.roll(self.p0)
        a.pick(self.p1)
        p0 = a.op("CAT", 2, V()).op("SHA256", 1, V("pool0")).top()
        a.pick(p0)
        a.roll(self.p1)
        self.p1 = a.op("CAT", 2, V()).op("SHA256", 1, V("pool1")).top()
        self.p0, self.used = p0, 0

    def mix(self, digest: V) -> None:
        a = self.a
        a.roll(self.p0)
        a.roll(digest)
        a.push(b"\x01")
        a.op("CAT", 2, V()).op("XOR", 2, V())
        a.push(32)
        self.p0 = a.op("LEFT", 2, V("pool0")).top()
        self.step()

    def word(self) -> V:
        if self.used == 8:
            self.step()
        a = self.a
        a.pick(self.p0)
        a.push(4 * self.used)
        a.push(4)
        self.used += 1
        return a.op("SUBSTR", 3, V("w", 1 << 32)).top()

    def elem(self) -> V:
        a = self.a
        acc = self.word()
        for _ in range(5):
            w = self.word()
            a.roll(acc)
            a.push(32)
            a.op("LSHIFT", 2, V())
            a.roll(w)
            acc = a.op("ADD", 2, V()).top()
        a.push(P)
        return a.op("MOD", 2, V("elem", P)).top()

    def ext(self) -> V:
        a = self.a
        es = [self.elem() for _ in range(4)]
        a.roll(es[3])
        for k in (2, 1, 0):
            a.push(pk.W)
            a.op("LSHIFT", 2, V())
            a.roll(es[k])
            a.op("ADD", 2, V())
        a.st[-1] = V("ext", P, True)
        return a.top()


class Gen:
    def __init__(self, statement: Statement, circuit: dict) -> None:
        self.stmt = statement
        self.circuit = circuit
        self.taps = ref.TapSet(circuit)
        self.layout = wit.Layout(self.taps)
        self.used: dict[int, list | Script] = {}

    # ---- shared emitters (work on any Asm) ----
    @staticmethod
    def size_check(a: Asm, v: V, n: int) -> None:
        a.pick(v)
        a.raw(assemble(["SIZE", "NIP", n, "NUMEQUAL", "VERIFY"]), 1)

    @staticmethod
    def range_check(a: Asm, v: V, masks: dict) -> None:
        """Every little-endian u32 word of `v` is < P: add 2^32-P to even (resp. odd) words in isolation and
        require no carry into the neighbouring word."""
        a.pick(v)
        a.pick(masks["me"])
        a.op("AND", 2, V())
        a.pick(masks["ce"])
        a.op("ADD", 2, V())
        a.pick(masks["mo"])
        a.op("AND", 2, V())
        a.pick(v)
        a.pick(masks["mo"])
        a.op("AND", 2, V())
        a.pick(masks["co"])
        a.op("ADD", 2, V())
        a.pick(masks["me"])
        a.op("AND", 2, V())
        a.raw(assemble(["OR", 0, "NUMEQUAL", "VERIFY"]), 2)

    @staticmethod
    def top_root(a: Asm, top: V, n: int) -> V:
        level = []
        for i in range(n // 2):
            a.pick(top)
            a.push(64 * i)
            a.push(64)
            level.append(a.op("SUBSTR", 3, V()).op("SHA256", 1, V("h")).top())
        while len(level) > 1:
            nxt = []
            for j in range(0, len(level), 2):
                a.roll(level[j])
                a.roll(level[j + 1])
                nxt.append(a.op("CAT", 2, V()).op("SHA256", 1, V("h")).top())
            level = nxt
        return level[0]

    @staticmethod
    def merkle(a: Asm, row: V, path: V, levels: int, bits: list[V], top: V, toff: V) -> None:
        a.pick(row)
        a.op("SHA256", 1, V("cur"))
        for k in range(levels):
            a.pick(path)
            a.push(32 * k)
            a.push(32)
            a.op("SUBSTR", 3, V())
            a.pick(bits[k])
            a.raw(assemble(["IF", "SWAP", "ENDIF", "CAT", "SHA256"]), 3, V("cur"))
        a.pick(top)
        a.pick(toff)
        a.push(32)
        a.op("SUBSTR", 3, V())
        a.raw(assemble(["EQUAL", "VERIFY"]), 2)

    @staticmethod
    def column(a: Asm, x: V, stride: int, i: int, consts: dict) -> V:
        """Extension element from words (i, i+stride, i+2 stride, i+3 stride) of `x`, packed into 96-bit lanes:
        mask the four words, then one multiplication moves word j from bit 32*stride*j to 3G + 96 j."""
        a.pick(x)
        if i:
            a.push(32 * i)
            a.op("RSHIFT", 2, V())
        a.pick(consts[f"mcol{stride}"])
        a.op("AND", 2, V())
        a.pick(consts[f"ccol{stride}"])
        a.op("MUL", 2, V())
        a.push(3 * (32 * stride - pk.W))
        a.op("RSHIFT", 2, V())
        a.pick(consts["mask4"])
        return a.op("AND", 2, V("col", P, True)).top()

    @staticmethod
    def column_consts(stride: int) -> tuple[int, int]:
        g = 32 * stride - pk.W
        mcol = sum(0xFFFFFFFF << (32 * stride * j) for j in range(4))
        ccol = sum(1 << (g * (3 - j)) for j in range(4))
        return mcol, ccol

    # ---- constraint evaluation (poly_ext), one straight-line block in the main script ----
    def poly_ext(self, f: Field, eval_u: list, out_vals: dict, mix: list[V], poly_mix: V) -> V:
        block = self.circuit["poly_ext"]["block"]
        fp: list = []
        mx: list = []
        pows = {1: poly_mix}

        def powmix(e: int) -> V:
            if e not in pows:
                h = e // 2
                pows[e] = f.mul(powmix(h), powmix(e - h))
            return pows[e]

        def prep(i: int, limit: int) -> None:
            v = fp[i]
            if isinstance(v, V) and v.bound > limit:
                fp[i] = f.reduce(v, consume=False)

        def scaled(term, e: int):
            """poly_mix^e * term."""
            if e == 0:
                return term
            if isinstance(term, V) and term.ext and term.bound > pk.MUL_IN_BOUND:
                term = f.reduce(term, consume=False)
            return f.mul(powmix(e), term)

        def add_tot(tot, term):
            if isinstance(tot, int) and tot == 0:
                return term
            return f.add(tot, term)

        for step in block:
            op = step[0]
            if op == "Const":
                fp.append(norm(step[1]))
            elif op == "ConstExt":
                fp.append(norm(tuple(step[1:5])))
            elif op == "Get":
                fp.append(eval_u[step[1]])
            elif op == "GetGlobal":
                fp.append(out_vals[step[2]] if step[1] == 0 else mix[step[2]])
            elif op in ("Add", "Sub", "Mul"):
                x, y = fp[step[1]], fp[step[2]]
                cx, cy = not isinstance(x, V), not isinstance(y, V)
                if cx and cy:
                    fx, fy = bb_ext(x), bb_ext(y)
                    r = bb.add(fx, fy) if op == "Add" else bb.sub(fx, fy) if op == "Sub" else bb.mul(fx, fy)
                    fp.append(norm(r))
                    continue
                if op == "Add":
                    fp.append(y if cx and x == 0 else x if cy and y == 0 else f.add(x, y))
                elif op == "Sub":
                    fp.append(x if cy and y == 0 else f.sub(x, y))
                else:
                    if (cx and x == 0) or (cy and y == 0):
                        fp.append(0)
                    elif cx and x == 1:
                        fp.append(y)
                    elif cy and y == 1:
                        fp.append(x)
                    else:
                        if isinstance(x, V) and isinstance(y, V) and x.ext and y.ext:
                            prep(step[1], pk.MUL_IN_BOUND)
                            prep(step[2], pk.MUL_IN_BOUND)
                        elif isinstance(x, V) and isinstance(y, V):
                            if x.bound * y.bound >= 1 << 95:
                                prep(step[1] if x.bound >= y.bound else step[2], 1 << 35)
                        fp.append(f.mul(fp[step[1]], fp[step[2]]))
            elif op == "True":
                mx.append((0, 0))
            elif op == "AndEqz":
                tot, e = mx[step[1]]
                term = fp[step[2]]
                if not (isinstance(term, int) and term == 0):
                    tot = add_tot(tot, scaled(term, e))
                mx.append((tot, e + 1))
            elif op == "AndCond":
                tot, e = mx[step[1]]
                itot, ie = mx[step[3]]
                cond = fp[step[2]]
                if not (isinstance(itot, int) and itot == 0) and not (isinstance(cond, int) and cond == 0):
                    t = itot if (isinstance(cond, int) and cond == 1) else f.mul(cond, itot)
                    tot = add_tot(tot, scaled(t, e))
                mx.append((tot, e + ie))
            else:
                raise ValueError(op)
        tot = mx[self.circuit["poly_ext"]["ret"]][0]
        assert isinstance(tot, V)
        return tot

    # ---- the per-query function body ----
    def query_body(self, persist: list[V], pv: dict) -> tuple[Script, list[V]]:
        items = {n: V(n) for n in QUERY_ITEMS}
        pos = V("pos", 1 << 20)
        a = Asm([items[n] for n in reversed(QUERY_ITEMS)] + persist + [pos])
        f = Field(a, inline=False, used=self.used)
        taps = self.taps

        # position-derived values
        a.pick(pos)
        bits = []
        for _ in range(TRACE_LEVELS):
            b = V("bit", 2)
            a.raw(assemble(["DUP", 1, "AND", 0, "ADD", "SWAP", "2DIV"]), 1, b, V("p"))
            bits.append(b)
        a.op("DROP", 1)

        def derived(ops: list, tag: str, bnd: int = 1 << 20) -> V:
            a.pick(pos)
            a.raw(assemble(ops), 1, V(tag, bnd))
            return a.top()

        toff = derived([10, "RSHIFT", 992, "AND"], "toff")
        fri_toff = [derived([6, "RSHIFT", 992, "AND"], "t0"), derived([2, "RSHIFT", 992, "AND"], "t1"),
                    derived([4, "MUL", 992, "AND"], "t2")]
        quot = [derived([16, "RSHIFT"], "q0"), derived([12, "RSHIFT", 15, "AND"], "q1"),
                derived([8, "RSHIFT", 15, "AND"], "q2")]
        nib = [derived([4, "MUL", 60, "AND"], "n0")]
        nib += [derived([4 * k - 2, "RSHIFT", 60, "AND"], f"n{k}") for k in range(1, 5)]
        a.drop(pos)

        def power(base: int, windows: int, tag: str) -> V:
            acc: V | None = None
            for k in range(windows):
                table = b"".join(struct.pack("<I", pow(base, v << (4 * k), P)) for v in range(16))
                a.push(table)
                a.pick(nib[k])
                a.push(4)
                a.op("SUBSTR", 3, V("t", P))
                if acc is not None:
                    a.raw(assemble(["MUL", P, "MOD"]), 2, V(tag, P))
                acc = a.top()
            assert acc is not None
            return acc

        x = power(bb.ROU_FWD[DOMAIN_PO2], 5, "x")
        s_r = [power(bb.ROU_REV[FRI_DOMAIN_PO2[r] + 4], [4, 3, 2][r], f"s{r}") for r in range(FRI_ROUNDS)]
        xf = power(bb.ROU_FWD[FRI_DOMAIN_PO2[-1]], 2, "xf")
        for v in nib:
            a.drop(v)

        # trace and check rows
        rows = {}
        for g in ("accum", "code", "data", "check"):
            row = a.roll(items[g])
            self.size_check(a, row, 4 * self.layout.rows[g])
            self.range_check(a, row, pv["masks"])
            path = a.roll(items[g + "_path"])
            self.size_check(a, path, 32 * TRACE_LEVELS)
            self.merkle(a, row, path, TRACE_LEVELS, bits, pv[g + "_top"], toff)
            a.drop(path)
            rows[g] = row
        groups = {ref.GROUP_ACCUM: "accum", ref.GROUP_CODE: "code", ref.GROUP_DATA: "data"}

        # tot_c = sum over registers of mix^r * row value
        members: list[list[tuple[int, str, int]]] = [[] for _ in range(CHECK_COMBO + 1)]
        for r, reg in enumerate(taps.regs):
            members[reg["combo"]].append((r, groups[reg["group"]], reg["offset"]))
        for i in range(ref.CHECK_SIZE):
            members[CHECK_COMBO].append((taps.reg_count + i, "check", i))
        tot = []
        for c in range(CHECK_COMBO + 1):
            terms = []
            for r, g, off in members[c]:
                a.pick(rows[g])
                a.push(4 * off)
                a.push(4)
                a.op("SUBSTR", 3, V("w", P))
                if r:
                    a.pick(pv["mixpow"][r])
                    a.op("MUL", 2, V("mw", pk.REDUCED * P, True))
                terms.append(a.top())
            tot.append(f.reduce(f.sum(terms)))
        for g in rows:
            a.drop(rows[g])

        xp = [1, x]
        for _ in range(6):
            xp.append(f.reduce(f.mul(xp[-1], x)))

        hints = a.roll(items["hints"])
        self.size_check(a, hints, 16 * (CHECK_COMBO + 1))
        self.range_check(a, hints, pv["masks"])
        qv = []
        for c in range(CHECK_COMBO + 1):
            a.pick(hints)
            a.push(16 * c)
            a.push(16)
            a.op("SUBSTR", 3, V())
            qv.append(f.fn(FN_SPREAD, pk.spread_ops(), 1, V("q", 1 << 32, True)))
        a.drop(hints)

        # q_c * D_c(x) == tot_c - U_c(x)
        for c in range(CHECK_COMBO + 1):
            dco = pv["dcoef"][c]
            n = len(dco)
            terms = [f.fetch(dco[0])]
            for j in range(1, n):
                terms.append(f.mul(dco[j], xp[j]))
            terms.append(f.fetch(xp[n]))
            d = f.reduce(f.sum(terms))
            cu = pv["cu"][c]
            terms = [f.fetch(cu[0])]
            for k in range(1, len(cu)):
                terms.append(f.mul(cu[k], xp[k]))
            u = f.sum(terms)
            e = f.mul(qv[c], d, cy=True)
            e = f.add(e, u, True, True)
            e = f.sub(e, tot[c], True, True)
            f.canon(e)
            a.raw(assemble([0, "NUMEQUAL", "VERIFY"]), 1)
        for v in qv:
            a.roll(v)
        goal = f.reduce(f.sum(qv))

        # FRI rounds
        for r in range(FRI_ROUNDS):
            row = a.roll(items[f"fri{r}"])
            self.size_check(a, row, 256)
            self.range_check(a, row, pv["masks"])
            path = a.roll(items[f"fri{r}_path"])
            self.size_check(a, path, 32 * FRI_LEVELS[r])
            self.merkle(a, row, path, FRI_LEVELS[r], bits, pv[f"fri_top{r}"], fri_toff[r])
            a.drop(path)
            gc = f.canon(goal)
            cols = [self.column(a, row, 16, i, pv) for i in range(16)]
            a.pick(quot[r])
            a.raw(assemble([15, "SWAP", "SUB", "PICK"]), 1, V("dq"))
            a.pick(gc)
            a.raw(assemble(["NUMEQUAL", "VERIFY"]), 2)
            y = f.reduce(f.mul(pv["rmix"][r], s_r[r]))
            lvl, ys, w = cols, y, bb.ROU_REV[4]
            while len(lvl) > 1:
                n = len(lvl) // 2
                nxt = []
                for i in range(n):
                    e = f.add(lvl[i], lvl[i + n])
                    o = f.sub(lvl[i], lvl[i + n], True, True)
                    if i:
                        o = f.mul(o, pow(w, i, P), True)
                    t = f.mul(ys, o, cy=True)
                    nxt.append(f.add(e, t, True, True))
                lvl = nxt
                if n > 1:
                    ys = f.mul(ys, ys)
                w = w * w % P
            goal = f.reduce(f.mul(lvl[0], pow(16, P - 2, P), True))
            a.drop(row)

        # final polynomial at xf
        xfp = [1, xf]
        for _ in range(FINAL_DEGREE - 2):
            xfp.append(f.reduce(f.mul(xfp[-1], xf)))
        terms = [f.fetch(pv["final"][0])]
        for k in range(1, FINAL_DEGREE):
            terms.append(f.mul(pv["final"][k], xfp[k]))
        fx = f.canon(f.sum(terms))
        f.canon(goal)
        a.roll(fx)
        a.raw(assemble(["NUMEQUAL", "VERIFY"]), 2)

        for name in QUERY_ITEMS:
            assert not a.has(items[name]), name
        above = len(a.st) - len(persist)
        assert a.st[:len(persist)] == persist
        a.push(above)
        a.s.op("MULTI", "DROP")
        a.st = list(persist)
        return a.s, persist

    # ---- setup: transcript, commitments, constraint check, per-proof constants ----
    def covenant(self, m: Asm) -> V:
        """Return the claim digest, with the spending transaction's serialized outputs as journal, as packed
        output-global words."""
        st = self.stmt
        jd = st.journal_digest(m)

        m.push(st.output_head)
        m.roll(jd)
        m.op("CAT", 2, V())
        m.push(st.output_tail)
        m.op("CAT", 2, V())
        m.op("SHA256", 1, V())
        m.push(st.claim_head)
        m.raw(assemble(["SWAP", "CAT"]), 2, V())
        m.push(st.claim_tail)
        m.op("CAT", 2, V())
        claim = m.op("SHA256", 1, V("claim")).top()
        # Claim digest half i (u16 LE) lands in output global CLAIM_OUT + i as a Montgomery word.
        acc = None
        for i in range(16):
            m.pick(claim)
            m.push(2 * i)
            m.push(2)
            m.op("SUBSTR", 3, V())
            m.push(bb.R)
            word = m.raw(assemble(["MUL", P, "MOD", 32 * (CLAIM_OUT + i), "LSHIFT"]), 2, V()).top()
            if acc is not None:
                m.roll(acc)
                m.roll(word)
                word = m.op("ADD", 2, V()).top()
            acc = word
        m.drop(claim)
        assert acc is not None
        return acc

    def generate(self, plan: dict[int, int] | None = None, pool: list[int] | None = None) -> tuple[Script, dict]:
        """Emit the verifier. Pass the `info["accesses"]` of a first call as `plan` to emit liveness-optimized code."""
        taps, circuit = self.taps, self.circuit
        V.serial = 0
        self.used = {}
        q_items = [[V(f"q{q}.{n}") for n in QUERY_ITEMS] for q in range(ref.QUERIES)]
        s_items = {n: V(n) for n in SETUP_ITEMS}
        base = [v for q in reversed(range(ref.QUERIES)) for v in reversed(q_items[q])]
        x_items = {n: V(n) for n in self.stmt.extra_items}
        heads = [V(n) for n in self.stmt.head_names]
        m = Asm(base + [s_items[n] for n in reversed(SETUP_ITEMS)] + list(x_items.values()) + heads, plan)
        f = Field(m, inline=False, used=self.used, pool=pool)
        self.stmt.prologue(m, x_items, heads)

        # range-check masks
        masks = {}
        for name, pattern in (("me", b"\xff" * 4 + bytes(4)), ("mo", bytes(4) + b"\xff" * 4),
                              ("ce", struct.pack("<I", (1 << 32) - P) + bytes(4)),
                              ("co", bytes(4) + struct.pack("<I", (1 << 32) - P))):
            m.push(pattern)
            size = len(pattern)
            while size < MASK_LONG:
                m.raw(assemble(["DUP", "CAT"]), 1, V())
                size *= 2
            m.push(MASK_LONG)
            masks[name] = m.op("LEFT", 2, V(name + "L")).top()
        short = {}
        for name in masks:
            m.pick(masks[name])
            m.push(MASK_SHORT)
            short[name] = m.op("LEFT", 2, V(name)).top()

        rng_host = ref.Rng()
        for info in (ref.PROOF_SYSTEM_INFO, circuit["circuit_info"].encode()):
            h = ref.sha(ref.words_bytes([bb.to_mont(b) for b in info] + [0] * (16 - len(info))))
            rng_host.mix(h)
        rng = Rng(m, rng_host.pool0, rng_host.pool1)

        def commit_bytes(v: V) -> None:
            m.pick(v)
            rng.mix(m.op("SHA256", 1, V("d")).top())

        claim_words = self.covenant(m) if self.stmt.covenant else None

        # output globals and po2
        out = m.roll(s_items["out"])
        self.size_check(m, out, 4 * OUT_WORDS)
        self.range_check(m, out, masks)
        commit_bytes(out)
        m.pick(out)
        m.push(4 * (OUT_WORDS - 1))
        m.push(4)
        m.op("SUBSTR", 3, V())
        m.raw(assemble([PO2, "NUMEQUAL", "VERIFY"]), 1)
        fixed = self.stmt.fixed_out()
        bound = set(fixed) | (set(range(CLAIM_OUT, CLAIM_OUT + 16)) if claim_words else set())
        m.pick(out)
        m.push(word_mask(OUT_WORDS, lambda i: i in bound))
        m.op("AND", 2, V())
        m.push(sum(bb.to_mont(v) << (32 * i) for i, v in fixed.items()))
        if claim_words:
            m.roll(claim_words)
            m.op("ADD", 2, V())
        m.raw(assemble(["NUMEQUAL", "VERIFY"]), 2)
        out_vals: dict[int, int | V] = dict(fixed)
        for i in range(circuit["output_size"]):
            if i not in fixed:
                m.pick(out)
                m.push(4 * i)
                m.push(4)
                m.op("SUBSTR", 3, V())
                m.push(bb.R_INV)
                out_vals[i] = m.raw(assemble(["MUL", P, "MOD"]), 2, V(f"out{i}", P)).top()
        m.drop(out)

        # trace commitments; the code root must be a leaf of the control root
        tops = {}
        for g in ("code", "data", "accum", "check"):
            t = m.roll(s_items[g + "_top"])
            self.size_check(m, t, 32 * TRACE_TOP)
            root = self.top_root(m, t, TRACE_TOP)
            tops[g] = t
            if g == "code":
                m.pick(root)
                m.push(self.stmt.control_id)
                m.raw(assemble(["EQUAL", "VERIFY"]), 2)
                idx = m.roll(s_items["ctrl_index"])
                path = m.roll(s_items["ctrl_path"])
                self.size_check(m, path, 32 * 8)
                cur = m.pick(root)
                for k in range(8):
                    m.roll(cur)
                    m.pick(path)
                    m.push(32 * k)
                    m.push(32)
                    m.op("SUBSTR", 3, V())
                    m.pick(idx)
                    cur = m.raw(assemble([1, "AND", 0, "ADD", "IF", "SWAP", "ENDIF", "CAT", "SHA256"]), 3,
                                V("cur")).top()
                    m.roll(idx)
                    idx = m.op("2DIV", 1, V("idx")).top()
                m.drop(path)
                m.roll(idx)
                m.raw(assemble([0, "NUMEQUAL", "VERIFY"]), 1)
                m.roll(cur)
                m.push(self.stmt.control_root)
                m.raw(assemble(["EQUAL", "VERIFY"]), 2)
            rng.mix(root)
            if g == "data":
                mix = [rng.elem() for _ in range(circuit["mix_size"])]
            elif g == "accum":
                poly_mix = rng.ext()
            elif g == "check":
                z = rng.ext()

        coeff = m.roll(s_items["coeff"])
        self.size_check(m, coeff, 4 * self.layout.coeff_words)
        self.range_check(m, coeff, masks)
        commit_bytes(coeff)
        n_coeff = self.layout.coeff_words // 4
        raw = []
        for c in range(0, n_coeff, 16):
            k = min(16, n_coeff - c)
            m.pick(coeff)
            m.push(16 * c)
            m.push(16 * k)
            chunk = m.op("SUBSTR", 3, V("chunk")).top()
            for e in range(k):
                m.pick(chunk)
                m.push(16 * e)
                m.push(16)
                m.op("SUBSTR", 3, V())
                raw.append(f.fn(FN_SPREAD, pk.spread_ops(), 1, V("coef", P, True)))
            m.drop(chunk)
        m.drop(coeff)

        # eval_u: coefficient j of a register's polynomial is raw_j * R^-1, evaluated at z * back_one^back
        zp: list = [None, z]
        for _ in range(6):
            zp.append(f.mul(zp[-1], z))
        zr = [bb.R_INV] + [f.reduce(f.mul(zp[j], bb.R_INV)) for j in range(1, 7)]
        back_one = bb.ROU_REV[PO2]
        eval_u: list[V] = []
        off = 0
        for reg in taps.regs:
            coefs = [f.mul(raw[off + j], zr[j]) for j in range(reg["size"])]
            for back in reg["backs"]:
                terms = [f.fetch(coefs[0])]
                for j in range(1, reg["size"]):
                    c = pow(back_one, back * j, P)
                    terms.append(f.fetch(coefs[j]) if c == 1 else f.mul(coefs[j], c))
                eval_u.append(f.sum(terms))
            off += reg["size"]

        result = self.poly_ext(f, eval_u, out_vals, mix, poly_mix)

        nt = taps.num_taps
        s_k = []
        for k in range(4):
            terms = [f.mul(raw[nt + 4 * k], bb.R_INV)]
            for i, rmi in enumerate([0, 2, 1, 3]):
                if i:
                    terms.append(f.mul(raw[nt + rmi + 4 * k], zr[i]))
            s_k.append(f.sum(terms))
        terms = [f.fetch(s_k[0])]
        for k in range(1, 4):
            terms.append(f.mul(s_k[k], tuple(1 if j == k else 0 for j in range(4))))
        check = f.sum(terms)
        zz = f.reduce(f.mul(z, 3))
        for _ in range(PO2):
            zz = f.mul(zz, zz)
        zz = f.add(zz, P - 1)
        check = f.canon(f.mul(check, zz, True, True))
        f.canon(result)
        m.raw(assemble(["NUMEQUAL", "VERIFY"]), 2)
        z4 = f.mul(zp[2], zp[2])
        f.canon(z4, consume=False)
        m.raw(assemble([pk.W, "RSHIFT", "VERIFY"]), 1)

        # FRI batching constants
        fri_mix = rng.ext()
        mixpow = [1, fri_mix]
        for _ in range(taps.reg_count + ref.CHECK_SIZE - 2):
            mixpow.append(f.mul(mixpow[-1], fri_mix))
        cu_terms: list[list[tuple[int, int]]] = [[] for _ in range(taps.tot_combo_backs + 1)]
        off = 0
        for r, reg in enumerate(taps.regs):
            for i in range(reg["size"]):
                cu_terms[taps.combo_begin[reg["combo"]] + i].append((r, off + i))
            off += reg["size"]
        for i in range(ref.CHECK_SIZE):
            cu_terms[taps.tot_combo_backs].append((taps.reg_count + i, off + i))
        cu_flat = []
        for terms_k in cu_terms:
            terms = [f.fetch(raw[ci]) if r == 0 else f.mul(mixpow[r], raw[ci]) for r, ci in terms_k]
            cu_flat.append(f.reduce(f.sum(terms)))
        cu = [cu_flat[taps.combo_begin[c]:taps.combo_begin[c + 1]] for c in range(taps.combos_count)]
        cu.append([cu_flat[taps.tot_combo_backs]])

        dcoef = []
        for c in range(taps.combos_count):
            poly: list = [1]
            for back in taps.combo(c):
                root = f.reduce(f.mul(z, pow(back_one, back, P)))
                nxt: list = []
                for j in range(len(poly) + 1):
                    hi = poly[j - 1] if j >= 1 else None
                    lo = None
                    if j < len(poly):
                        lo = root if (isinstance(poly[j], int) and poly[j] == 1) else f.mul(root, poly[j])
                    if lo is None:
                        nxt.append(hi)
                    elif hi is None:
                        nxt.append(f.reduce(f.sub(0, lo)))
                    else:
                        nxt.append(f.reduce(f.sub(hi, lo)))
                poly = nxt
            dcoef.append(poly[:-1])
        dcoef.append([f.reduce(f.sub(0, z4))])

        rmix = []
        for r in range(FRI_ROUNDS):
            t = m.roll(s_items[f"fri_top{r}"])
            self.size_check(m, t, 32 * 32)
            rng.mix(self.top_root(m, t, 32))
            tops[f"fri_top{r}"] = t
            rmix.append(rng.ext())
        final = m.roll(s_items["final"])
        self.size_check(m, final, 16 * FINAL_DEGREE)
        self.range_check(m, final, masks)
        commit_bytes(final)
        consts = {}
        for stride in (16, 64):
            mc, cc = self.column_consts(stride)
            consts[f"mcol{stride}"] = m.push(mc, V(f"mcol{stride}"))
            consts[f"ccol{stride}"] = m.push(cc, V(f"ccol{stride}"))
        consts["mask4"] = m.push(pk.EXT_MASK4, V("mask4"))
        final_c = [self.column(m, final, 64, k, consts) for k in range(FINAL_DEGREE)]
        m.drop(final)

        blob = m.pick(rng.p0)
        for _ in range(6):
            rng.step()
            m.roll(blob)
            m.pick(rng.p0)
            blob = m.op("CAT", 2, V("posblob")).top()

        # compact everything the queries need into a fixed persistent block
        pv = {"masks": short, "mixpow": mixpow, "cu": cu, "dcoef": dcoef, "rmix": rmix, "final": final_c,
              "mcol16": consts["mcol16"], "ccol16": consts["ccol16"], "mask4": consts["mask4"]}
        pv.update({g + "_top": tops[g] for g in ("code", "data", "accum", "check")})
        pv.update({f"fri_top{r}": tops[f"fri_top{r}"] for r in range(FRI_ROUNDS)})
        keep: list = list(short.values()) + [consts["mcol16"], consts["ccol16"], consts["mask4"]]
        keep += [tops[k] for k in ("code", "data", "accum", "check")] + [tops[f"fri_top{r}"] for r in range(3)]
        keep += mixpow[1:] + cu_flat + [v for d in dcoef for v in d] + rmix + final_c + [blob]
        assert all(isinstance(v, V) for v in keep)
        for v in reversed(keep):
            m.pick(v)
            m.op("TOALTSTACK", 1)
        region = len(m.st) - len(base)
        m.push(region)
        m.s.op("MULTI", "DROP")
        m.st = list(base)
        copies = []
        for v in keep:
            m.s.op("FROMALTSTACK")
            m.st.append(v)
            copies.append(v)
        persist = list(m.st[len(base):])
        m.active = False

        body, _ = self.query_body(persist, pv)
        self.used[FN_QUERY] = body

        for q in range(ref.QUERIES):
            m.pick(blob)
            m.push(4 * q)
            m.push(4)
            m.op("SUBSTR", 3, V())
            m.push(0xFFFFF)
            m.raw(assemble(["AND", 0, "ADD"]), 2, V("pos"))
            m.call(FN_QUERY, 1)
            block = q_items[q]
            nb = len(m.st) - len(persist)
            assert all(v in block for v in m.st[nb - len(block):nb])
            del m.st[nb - len(block):nb]
        assert m.st == persist
        m.push(len(persist))
        m.s.op("MULTI", "DROP")
        m.s.int(1)

        prologue = Script()
        sizes = {}
        for fid in sorted(self.used):
            body_ops = self.used[fid]
            code = body_ops if isinstance(body_ops, Script) else assemble(body_ops)
            prologue.data(bytes(code.code)).int(fid).op("DEFINE")
            sizes[fid] = len(code.code)
        script = self.stmt.head().extend(prologue).extend(m.s)
        info = {"functions": {fid: sizes[fid] for fid in self.used},
                "query_body_bytes": len(body.code), "persist": len(persist), "accesses": m.accesses,
                "pool": f.pool_candidates()}
        return script, info


def bb_ext(c) -> tuple:
    return c if isinstance(c, tuple) else bb.e(c)


def prover_hints(gen: Gen, receipt: dict, seal: bytes) -> list[bytes]:
    """Per-query DEEP quotient hints for a seal the reference verifier accepts."""
    trace: dict = {}
    ref.verify_receipt(receipt, seal, trace)
    return wit.deep_hints(wit.split_seal(seal, gen.layout), trace, gen.taps)


def build_witness(gen: Gen, receipt: dict, seal: bytes, hints: list[bytes] | None = None) -> list[bytes]:
    """Witness stack, bottom first; queries deepest (query 0 just below the setup items). `hints` lets tests
    pair any seal (including a rejected one) with chosen hints."""
    if hints is None:
        hints = prover_hints(gen, receipt, seal)
    split = wit.split_seal(seal, gen.layout)
    proof = receipt["control_inclusion_proof"]
    setup = {"out": split["out"], "ctrl_index": int(proof["index"]).to_bytes(4, "little").rstrip(b"\0"),
             "ctrl_path": b"".join(bytes.fromhex(d) for d in proof["digests"]),
             "code_top": split["code_top"], "data_top": split["data_top"], "accum_top": split["accum_top"],
             "check_top": split["check_top"], "coeff": split["coeff"], "final": split["final"]}
    for r in range(FRI_ROUNDS):
        setup[f"fri_top{r}"] = split["fri_top"][r]
    stack = []
    for q in reversed(range(ref.QUERIES)):
        items = dict(split["queries"][q], hints=hints[q])
        stack += [items[n] for n in reversed(QUERY_ITEMS)]
    stack += [setup[n] for n in reversed(SETUP_ITEMS)]
    return stack


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--receipt", default=str(ROOT / "fixtures/receipt.json"))
    ap.add_argument("--seal", default=str(ROOT / "fixtures/seal.bin"))
    ap.add_argument("--out", default=str(ROOT / "build/bundle.json"))
    args = ap.parse_args()
    receipt = json.loads(Path(args.receipt).read_text())
    seal = Path(args.seal).read_bytes()
    gen = Gen(Statement(receipt), ref.load_circuit())
    first = gen.generate()[1]
    script, info = gen.generate(first["accesses"], first["pool"])
    info["pooled"] = len(info.pop("pool"))
    del info["accesses"]
    stack = build_witness(gen, receipt, seal)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"script": script.code.hex(), "witness": [x.hex() for x in stack], "info": info}))
    print(json.dumps({"script_bytes": len(script.code), "witness_items": len(stack),
                      "witness_bytes": sum(map(len, stack)), **info}))


if __name__ == "__main__":
    main()
