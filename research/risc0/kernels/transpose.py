#!/usr/bin/env python3
"""Seal-to-lane rearrangement for the DEEP-ALI columns, run in the pinned interpreter.

The 50 query rows opened in the accum, code, data, and check trees hold 12 + 23 + 128 + 16 = 179
BabyBear words each (4 bytes, as serialised in the seal). Vectorised DEEP-ALI arithmetic needs the
transpose: one integer per column whose lanes are the 50 queries. This kernel:

  1. pads each 716-byte row to 192 words and concatenates the rows (row q at byte 768*q),
  2. transposes every 64x64 tile of 4-byte words in place with six delta swaps on the whole matrix
     (masks are generated in Script, not pushed),
  3. splits the result into 192 column items of 64 four-byte lanes,
  4. spreads each column into three 12-byte-lane vectors (lanes q = 0, 1, 2 mod 3), which is the
     layout the lazy multiply-accumulate and Barrett kernels need for headroom.

Every stage is checked for exact equality against a Python model and metered by running prefixes of
the script; the reported cost of a stage is the difference between consecutive prefixes.
"""
import json
import random
import subprocess

from gsr_script import BITCOIN_UTIL, BUDGET, Script

P = 2013265921
QUERIES = 50
TILE = 64
COLUMNS = COLS = ROW_BYTES = 0


def configure(columns: int) -> None:
    """Real column count; the matrix is padded to whole 64-word tiles."""
    global COLUMNS, COLS, ROW_BYTES
    COLUMNS, COLS = columns, -(-columns // TILE) * TILE
    ROW_BYTES = COLS * 4


LANE = 12


def run_prefix(script: Script, stack: list[bytes]) -> tuple[int, list[bytes]]:
    """Run a script prefix and return (varops, final stack). A sentinel item below the inputs keeps the
    stack from being consumed by the clean-stack check, so the prefix always ends with that error."""
    request = {"protocol": 1, "sigversion": "tapscript_v2", "script": script.code.hex(),
               "stack": ["01"] + [x.hex() for x in stack], "varops_budget": BUDGET}
    out = json.loads(subprocess.run([str(BITCOIN_UTIL), "evalscript"], input=json.dumps(request),
                                    capture_output=True, text=True, check=True).stdout)
    assert out["error"] == "Stack size must be exactly one after execution", out["error"]
    assert out["stack-after"][0] == "01"
    return BUDGET - out["varops-budget-remaining"], [bytes.fromhex(x) for x in out["stack-after"][1:]]


def as_int(b: bytes) -> int:
    return int.from_bytes(b, "little")


def tree_cat(s: Script, count: int) -> None:
    """Concatenate `count` stack items in order using pairwise levels (MULTI CAT is quadratic)."""
    while count > 1:
        pairs, odd = divmod(count, 2)
        if odd:
            s.op("TOALTSTACK")
        for _ in range(pairs):
            s.op("CAT", "TOALTSTACK")
        for _ in range(pairs + odd):
            s.op("FROMALTSTACK")
        count = pairs + odd


def mask_script(s: Script, b: int) -> None:
    """Mask of words (r, c) with r mod 2b < b and c mod 2b >= b over a 64-row, 192-column matrix."""
    s.data(bytes(4 * b) + b"\xff" * (4 * b))
    size = 8 * b
    while size < ROW_BYTES:
        s.op("DUP", "CAT")
        size *= 2
    s.int(ROW_BYTES).op("LEFT")
    rows = 1
    while rows < b:
        s.op("DUP", "CAT")
        rows *= 2
    period = 2 * b
    while period < TILE:
        s.op("DUP").int(period * ROW_BYTES * 8).op("LSHIFT", "OR")
        period *= 2


def mask_value(b: int) -> int:
    m = 0
    for r in range(TILE):
        for c in range(COLS):
            if r % (2 * b) < b and c % (2 * b) >= b:
                m |= 0xFFFFFFFF << (32 * (r * COLS + c))
    return m


def split_halves(s: Script, count: int, size: int) -> None:
    """Split each of `count` items (`size` bytes, possibly high-zero-trimmed) into two halves, in order."""
    half = size // 2
    for _ in range(count):
        s.op("DUP").int(half).op("LEFT", "SWAP").int(half).int(half).op("SUBSTR")
        s.op("TOALTSTACK", "TOALTSTACK")
    for _ in range(2 * count):
        s.op("FROMALTSTACK")


def main(columns: int) -> list[tuple[str, int]]:
    configure(columns)
    random.seed(2)
    rows = [[random.randrange(P) for _ in range(COLUMNS)] for _ in range(QUERIES)]
    witness = [b"".join(x.to_bytes(4, "little") for x in row) for row in rows]
    pad = bytes(ROW_BYTES - 4 * COLUMNS)

    s = Script()
    stages = []
    for _ in range(QUERIES):
        s.data(pad).op("CAT", "TOALTSTACK")
    for _ in range(QUERIES):
        s.op("FROMALTSTACK")
    tree_cat(s, QUERIES)
    stages.append(("build row-major matrix (pad + concatenate 50 rows)", len(s.code)))

    matrix = sum(row[c] << (32 * (q * COLS + c)) for q, row in enumerate(rows) for c in range(COLUMNS))
    b = TILE // 2
    while b:
        shift = (b * COLS - b) * 32
        s.op("DUP").int(shift).op("RSHIFT", "OVER", "XOR")
        mask_script(s, b)
        s.op("AND", "DUP").int(shift).op("LSHIFT", "XOR", "XOR")
        m = mask_value(b)
        t = ((matrix >> shift) ^ matrix) & m
        matrix ^= t ^ (t << shift)
        stages.append((f"delta swap b={b} (incl. in-Script mask)", len(s.code)))
        b //= 2

    count, size = 1, TILE * ROW_BYTES
    while size > ROW_BYTES:
        split_halves(s, count, size)
        count, size = 2 * count, size // 2
    tiles = COLS // TILE
    for _ in range(TILE):
        for t in range(tiles):
            if t < tiles - 1:
                s.op("DUP")
            s.int(256 * t).int(256).op("SUBSTR")
            if t < tiles - 1:
                s.op("SWAP")
        s.op(*["TOALTSTACK"] * tiles)
    for _ in range(tiles * TILE):
        s.op("FROMALTSTACK")
    stages.append((f"split into {COLS} column items (64 x 4-byte lanes)", len(s.code)))

    lane_masks = [sum(0xFFFFFFFF << (32 * q) for q in range(k, TILE, 3)) for k in range(3)]
    # Model of the transposed columns (after split): order and value.

    def word(x: int, i: int) -> int:
        return (x >> (32 * i)) & 0xFFFFFFFF

    columns = []
    for j in range(TILE):
        for t in range(COLS // TILE):
            columns.append(sum(word(matrix, j * COLS + 64 * t + q) << (32 * q) for q in range(TILE)))

    prev = 0
    results = []
    for name, end in stages:
        prefix = Script()
        prefix.code = s.code[:end]
        cost, after = run_prefix(prefix, witness)
        results.append((name, cost - prev))
        prev = cost
    assert [as_int(x) for x in after] == columns, "transpose mismatch"
    col_of = {}
    for j in range(TILE):
        for t in range(COLS // TILE):
            col_of[64 * t + j] = (COLS // TILE) * j + t
    for c in range(COLUMNS):
        expect = sum(rows[q][c] << (32 * q) for q in range(QUERIES))
        assert columns[col_of[c]] == expect

    # Phase spread measured on its own, over the 179 real columns in stack order.
    real = [columns[col_of[c]] for c in range(COLUMNS)]
    stack = [x.to_bytes((x.bit_length() + 7) // 8, "little") for x in real]
    spread = Script()
    for k in range(3):
        spread.int(lane_masks[k])
    base_cost, _ = run_prefix(spread, stack)
    for i in range(COLUMNS):
        # stack: cols..., m0 m1 m2, then 3 outputs per processed column
        outputs = 3 * i
        for k in range(3):
            spread.int(COLUMNS - 1 - i + 3 + outputs + k).op("PICK").int(3 + outputs).op("PICK", "AND")
            if k:
                spread.int(32 * k).op("RSHIFT")
    cost, after = run_prefix(spread, stack)
    ints = [as_int(x) for x in after]
    produced = ints[COLUMNS + 3:]
    for i, colv in enumerate(real):
        for k in range(3):
            expect = sum(((colv >> (32 * q)) & 0xFFFFFFFF) << (96 * ((q - k) // 3)) for q in range(k, TILE, 3))
            assert produced[3 * i + k] == expect, (i, k)
    results.append((f"spread {COLUMNS} columns into 3 x 12-byte-lane vectors", cost - base_cost))

    return results + [("script bytes excluding spread", len(s.code))]


def report(columns: int) -> None:
    results = main(columns)
    total = 0
    print(f"{columns} columns:")
    for name, cost in results[:-1]:
        total += cost
        print(f"  {name:53s} {cost:>12,}")
    print(f"  {'total rearrangement':53s} {total:>12,}")
    print(f"  {results[-1][0]:53s} {results[-1][1]:>12,}")


if __name__ == "__main__":
    report(179)
    report(371)
