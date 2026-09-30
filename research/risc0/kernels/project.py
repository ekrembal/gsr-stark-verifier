#!/usr/bin/env python3
"""Compose the metered kernels into a projection of an optimised RISC Zero succinct-receipt verifier.

Kernel costs come from running real Script in the pinned interpreter (packed_kernels.py, transpose.py).
Operation counts come from the instrumented RISC Zero v3.0.6 verifier (research/risc0/padded-suite-run.txt),
the recursion circuit's tap set, and the FRI structure (research/risc0/fri-structure.py). Rows marked
"est" use an unmetered per-item price. Nothing here is a complete verifier: the composition, stack
scheduling between kernels, and control flow are not written, so the total is a projection.
"""
import packed_kernels
import transpose

QUERIES = 50
ROUNDS = 3
PHASES = 3  # each 64-lane column spreads into three 12-byte-lane vectors
COORDS = 4

# Measured elsewhere in this repository.
HASHING = 30_451_946  # padded SHA-256 Merkle and Fiat-Shamir, research/risc0/gsr-risc0-fri-costs.cpp
SCALAR_MULMOD = 7_720
SCALAR_EXT_MUL = 19 * 7_720 + 12 * 5_802  # scalar model: 19 base mul + 12 base add per ext mul
SEAL_BYTES = 222_668
BUDGET_PER_WU = 10_000

# Unmetered per-item estimates.
EST_TABLE_POWER = 25_000  # two-level root-of-unity table lookup + one mulmod
EST_MERKLE_DIRECTION = 5_000  # index-bit test and conditional swap per Merkle parent
MERKLE_PARENTS = 4_363


def main() -> None:
    k, sizes = packed_kernels.main()
    rearrange = sum(cost for _, cost in transpose.main(371)[:-1])

    ext_mul, ext_add, ext_sub = k["ext_mul (Kronecker, reduced)"], k["ext_add (lazy)"], k["ext_sub (lazy)"]
    ext_scalar = k["ext_scalar_mul (ext x per-query base, reduced)"]
    invoke = k["ext_mul via OP_INVOKE"] - ext_mul
    pmac, pred = k["phase vec_mac (22-lane vector)"], k["phase vec_reduce (Barrett, 22 lanes)"]
    padd = k["vec_add (50 lanes)"]  # conservative for 22-lane phase vectors
    extract, eq, insert = (k["lane_extract (4 vectors -> packed ext at one query)"],
                           k["ext_eq (hinted canonical equality)"], k["lane_insert (scalar -> phase-vector lane)"])

    rows = []

    def row(phase: str, what: str, count: int, unit: int, kind: str = "kernel") -> None:
        rows.append((phase, what, count, unit, count * unit, kind))

    # Query-independent work (one evaluation point).
    row("setup", "tap evaluations, Horner over 163 registers (sum s(s-1))", 2_792, ext_mul)
    row("setup", "mix powers and combo_u accumulation (179 + 659) + remaining 90", 928, ext_mul)
    row("setup", "extension additions", 4_110, ext_add)
    row("setup", "9 distinct tap points z * w^back", 9, ext_scalar)
    row("setup", "remaining base-field powers", 2_208, SCALAR_MULMOD, "scalar")
    row("constraint", "extension multiplications (measured)", 7_287, ext_mul)
    row("constraint", "extension additions (measured)", 5_289, ext_add)
    row("constraint", "extension subtractions (measured)", 1_385, ext_sub)
    row("invoke", "OP_INVOKE overhead for single-point ext_mul calls", 2_792 + 928 + 7_287, invoke)
    row("final poly", "256-point NTT twiddles", 1_024, ext_scalar)
    row("final poly", "256-point NTT additions/subtractions", 2_048, (ext_add + ext_sub) // 2)
    row("final poly", "per-query table read + equality", QUERIES, packed_kernels_row_ext(k) + eq)

    # Seal rearrangement for every query-major opening (DEEP columns and all FRI rows).
    row("rearrange", "transpose 50 x 371 opened words into phase vectors", 1, rearrange)

    # DEEP-ALI, vectorised over queries.
    row("deep", "tap sums: 179 terms x 4 coords x 3 phases", 179 * COORDS * PHASES, pmac)
    row("deep", "combo polynomials u_i(x): 21 terms", 21 * COORDS * PHASES, pmac)
    row("deep", "divisor polynomials: 27 terms", 27 * COORDS * PHASES, pmac)
    row("deep", "reduce numerators and divisors (12 ext)", 12 * COORDS * PHASES, pred)
    row("deep", "numerator subtraction (6 ext)", 6 * COORDS * PHASES, padd)
    row("deep", "x^1..x^6 per query", 6 * QUERIES, SCALAR_MULMOD, "scalar")
    row("deep", "insert x powers into lanes", 7 * QUERIES, insert)
    row("deep", "per query: extract 12 ext values", 12 * QUERIES, extract)
    row("deep", "per query: div * inv hint, check == 1", 6 * QUERIES, ext_mul + eq)
    row("deep", "per query: num * inv, sum", 6 * QUERIES, ext_mul + ext_add)

    # FRI, three 16-way rounds.
    row("fri", "16-point inverse NTT twiddles (49) on vectors", ROUNDS * 49 * COORDS * PHASES, pmac + pred)
    row("fri", "16-point inverse NTT add/sub (64) on vectors", ROUNDS * 64 * COORDS * PHASES, padd)
    row("fri", "scale c_i by mix^i (15 terms x 16 products)", ROUNDS * 15 * 16 * PHASES, pmac)
    row("fri", "reduce scaled coefficients", ROUNDS * 16 * COORDS * PHASES, pred)
    row("fri", "per query-round: extract 16 coefficients", ROUNDS * QUERIES * 16, extract)
    row("fri", "per query-round: Horner in w_q (15 steps)", ROUNDS * QUERIES * 15, ext_scalar + ext_add)
    row("fri", "per query-round: w_q table power", ROUNDS * QUERIES, EST_TABLE_POWER, "est")
    row("fri", "per query-round: goal check (select + equality)", ROUNDS * QUERIES, extract + eq)

    row("hash", "padded SHA-256 Merkle + Fiat-Shamir (priced)", 1, HASHING, "priced")
    row("hash", "Merkle direction handling", MERKLE_PARENTS, EST_MERKLE_DIRECTION, "est")

    total = sum(r[4] for r in rows)
    print(f"{'phase':11s} {'work':58s} {'count':>7s} {'unit':>9s} {'varops':>14s}  source")
    for phase, what, count, unit, cost, kind in rows:
        print(f"{phase:11s} {what:58s} {count:>7,} {unit:>9,} {cost:>14,}  {kind}")
    by_phase = {}
    for r in rows:
        by_phase[r[0]] = by_phase.get(r[0], 0) + r[4]
    print()
    for phase, cost in by_phase.items():
        print(f"{phase:11s} {cost:>16,}")
    print(f"{'total':11s} {total:>16,}")
    estimated = sum(r[4] for r in rows if r[5] == "est")
    print(f"of which unmetered estimates {estimated:,}")
    seal_budget = SEAL_BYTES * BUDGET_PER_WU
    print(f"budget contributed by the seal alone ({SEAL_BYTES:,} WU): {seal_budget:,}")
    print(f"budget of a 400,000 WU spend: {400_000 * BUDGET_PER_WU:,}")
    for glue in (1.0, 1.5, 2.0):
        need = int(total * glue)
        print(f"glue x{glue}: {need:,} varops = {need / BUDGET_PER_WU:,.0f} WU of budget")
    calls = 2_792 + 928 + 7_287 + 12 * QUERIES
    print(f"invoked ext_mul body bytes: {calls:,} calls x {sizes['ext_mul body bytes']} B = "
          f"{calls * sizes['ext_mul body bytes']:,} of 4,000,000")
    print(f"scalar-model extension multiplication: {SCALAR_EXT_MUL:,}; packed kernel: {ext_mul:,}")


def packed_kernels_row_ext(k: dict[str, int]) -> int:
    return k["row_ext (FRI row words -> packed ext)"]


if __name__ == "__main__":
    main()
