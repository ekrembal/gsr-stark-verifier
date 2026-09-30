"""Prover-side witness preparation: split a seal into the verifier's witness items and compute DEEP hints.

The split is a fixed re-chunking of the seal (every seal word lands in exactly one item, in order), so the Script
checks each item's exact size and exact consumption of the stack instead of re-parsing the seal.
"""
import struct

import babybear as bb
import reference as ref
from babybear import P

TRACE_TOP = 32
TRACE_LEVELS = 15
FRI_LEVELS = [11, 7, 3]
COMBOS = 5


class Layout:
    def __init__(self, taps: "ref.TapSet") -> None:
        self.rows = {"accum": taps.group_size(ref.GROUP_ACCUM), "code": taps.group_size(ref.GROUP_CODE),
                     "data": taps.group_size(ref.GROUP_DATA), "check": ref.CHECK_SIZE}
        self.coeff_words = 4 * (taps.num_taps + ref.CHECK_SIZE)


def split_seal(seal_bytes: bytes, layout: Layout) -> dict:
    if len(seal_bytes) % 4:
        raise ref.VerifyError("ReceiptFormatError")
    words = list(struct.unpack(f"<{len(seal_bytes) // 4}I", seal_bytes))
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(words):
            raise ref.VerifyError("ReceiptFormatError")
        out = ref.words_bytes(words[pos:pos + n])
        pos += n
        return out

    s: dict = {"out": take(33), "code_top": take(8 * TRACE_TOP), "data_top": take(8 * TRACE_TOP),
               "accum_top": take(8 * TRACE_TOP), "check_top": take(8 * TRACE_TOP),
               "coeff": take(layout.coeff_words), "fri_top": [], "queries": []}
    for _ in range(3):
        s["fri_top"].append(take(8 * 32))
    s["final"] = take(4 * 64)
    for _ in range(ref.QUERIES):
        q: dict = {}
        for g in ("accum", "code", "data", "check"):
            q[g] = take(layout.rows[g])
            q[g + "_path"] = take(8 * TRACE_LEVELS)
        for r, levels in enumerate(FRI_LEVELS):
            q[f"fri{r}"] = take(64)
            q[f"fri{r}_path"] = take(8 * levels)
        s["queries"].append(q)
    if pos != len(words):
        raise ref.VerifyError("ReceiptFormatError")
    return s


def row_words(b: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(b) // 4}I", b))


def deep_hints(split: dict, trace: dict, taps: "ref.TapSet") -> list[bytes]:
    """Per query, q_c = (tot_c - U_c(x)) / D_c(x) for the five tap combos and the check combo, over R-scaled
    (Montgomery-word) row values; the Script checks q_c * D_c(x) == tot_c - U_c(x) instead of inverting."""
    z, fri_mix = trace["z"], trace["fri_mix"]
    back_one = bb.ROU_REV[trace["po2"]]
    combo_u = [bb.scale(c, bb.R) for c in trace["combo_u"]]
    gen = bb.ROU_FWD[20]
    pows, cur = [], bb.ONE
    for _ in range(taps.reg_count + ref.CHECK_SIZE):
        pows.append(cur)
        cur = bb.mul(cur, fri_mix)
    out = []
    for q, tq in zip(split["queries"], trace["queries"]):
        x = bb.e(pow(gen, tq["pos"], P))
        rows = [row_words(q["accum"]), row_words(q["code"]), row_words(q["data"])]
        tot = [bb.ZERO] * (COMBOS + 1)
        for reg, mp in zip(taps.regs, pows):
            tot[reg["combo"]] = bb.add(tot[reg["combo"]], bb.scale(mp, rows[reg["group"]][reg["offset"]]))
        for i, w in enumerate(row_words(q["check"])):
            tot[-1] = bb.add(tot[-1], bb.scale(pows[taps.reg_count + i], w))
        hint = b""
        for c in range(COMBOS + 1):
            if c < COMBOS:
                u = bb.poly_eval(combo_u[taps.combo_begin[c]:taps.combo_begin[c + 1]], x)
                d = bb.ONE
                for back in taps.combo(c):
                    d = bb.mul(d, bb.sub(x, bb.scale(z, pow(back_one, back, P))))
            else:
                u = combo_u[taps.tot_combo_backs]
                d = bb.sub(x, bb.power(z, 4))
            qc = bb.mul(bb.sub(tot[c], u), bb.inv(d))
            hint += ref.words_bytes(list(qc))
        out.append(hint)
    return out
