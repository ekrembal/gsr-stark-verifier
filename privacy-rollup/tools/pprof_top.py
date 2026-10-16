#!/usr/bin/env python3
"""Summarize a RISC Zero pprof cycle profile without Go: flat and cumulative cycles per function.

usage: pprof_top.py <profile.pb> [N] [substring-filter]
       pprof_top.py <profile.pb> N --callers SUBSTRING   cycles under SUBSTRING, by immediate caller
"""
import gzip
import sys
from collections import defaultdict


def varint(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return r, i


def fields(b):
    i = 0
    while i < len(b):
        k, i = varint(b, i)
        f, t = k >> 3, k & 7
        if t == 0:
            v, i = varint(b, i)
        elif t == 2:
            n, i = varint(b, i)
            v = b[i:i + n]
            i += n
        elif t == 1:
            v = b[i:i + 8]
            i += 8
        elif t == 5:
            v = b[i:i + 4]
            i += 4
        else:
            raise ValueError(t)
        yield f, t, v


def ints(t, v):
    if t == 0:
        return [v]
    out, i = [], 0
    while i < len(v):
        x, i = varint(v, i)
        out.append(x)
    return out


def main():
    raw = open(sys.argv[1], "rb").read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    top = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    flt = sys.argv[3] if len(sys.argv) > 3 else None
    callee = sys.argv[4] if flt == "--callers" else None
    samples, locs, funcs, strings = [], {}, {}, []
    for f, t, v in fields(raw):
        if f == 2:
            ls, vals = [], []
            for g, tt, vv in fields(v):
                if g == 1:
                    ls += ints(tt, vv)
                elif g == 2:
                    vals += ints(tt, vv)
            samples.append((ls, vals[0] if vals else 0))
        elif f == 4:
            lid, fids = 0, []
            for g, tt, vv in fields(v):
                if g == 1:
                    lid = vv
                elif g == 4:
                    for h, t3, v3 in fields(vv):
                        if h == 1:
                            fids.append(v3)
            locs[lid] = fids
        elif f == 5:
            fid = name = 0
            for g, tt, vv in fields(v):
                if g == 1:
                    fid = vv
                elif g == 2:
                    name = vv
            funcs[fid] = name
        elif f == 6:
            strings.append(v.decode("utf-8", "replace"))
    name = {fid: strings[s] for fid, s in funcs.items()}
    flat, cum, callers = defaultdict(int), defaultdict(int), defaultdict(int)
    total = 0
    for ls, val in samples:
        total += val
        stack = [name[fid] for l in ls for fid in locs.get(l, [])]
        if callee:
            hits = [i for i, fn in enumerate(stack) if callee in fn]
            if hits:
                j = hits[-1] + 1
                callers[stack[j] if j < len(stack) else "<root>"] += val
        if stack:
            flat[stack[0]] += val
        for fn in set(stack):
            cum[fn] += val
    print(f"total {total:,} cycles")
    if callee:
        for v, k in sorted(((v, k) for k, v in callers.items()), reverse=True)[:top]:
            print(f"{v:>12,} {100 * v / total:5.1f}%  {k[:150]}")
        return
    for title, d in (("cumulative", cum), ("flat", flat)):
        print(f"-- {title}")
        rows = [(v, k) for k, v in d.items() if not flt or flt in k]
        for v, k in sorted(rows, reverse=True)[:top]:
            print(f"{v:>12,} {100 * v / total:5.1f}%  {k[:150]}")


if __name__ == "__main__":
    main()
