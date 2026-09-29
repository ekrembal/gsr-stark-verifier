#!/usr/bin/env python3
"""Structural model of the RISC Zero v3.0.6 recursion verifier, checked against measurement.

Derives the Merkle and FRI shape of the succinct receipt from the constants in
risc0-zkp (QUERIES, INV_RATE, FRI_FOLD, FRI_MIN_DEGREE), the recursion tap set,
and RECURSION_PO2, then compares the predicted hash counts with the counts
measured by research/risc0/risc0-gsr-measure.patch. Predicting the measured
numbers is what licenses using this model to ask "what if" questions about a
GSR script -- different query counts, fold factors or circuit sizes.

    python3 research/risc0/fri-structure.py
"""

QUERIES = 50
INV_RATE = 4
FRI_FOLD = 16
FRI_MIN_DEGREE = 256
EXT_SIZE = 4
RECURSION_PO2 = 18

# group_size() over the recursion tap set: last tap offset + 1, per group.
GROUP_COLS = {"accum": 12, "code": 23, "data": 128}
CHECK_COLS = INV_RATE * EXT_SIZE
TAP_SIZE = 643  # taps in the recursion tap set
OUTPUT_SIZE = 32  # CircuitImpl::OUTPUT_SIZE, the recursion circuit's globals

# Slices hashed once, outside the query loop, in base field elements:
# the proof system and circuit info blocks, the globals plus po2, and the DEEP
# tap interpolation coefficients (extension elements, hence EXT_SIZE each).
SETUP_SLICES = [16, 16, OUTPUT_SIZE + 1, EXT_SIZE * (TAP_SIZE + CHECK_COLS)]

MEASURED_PAIRS = 4363
MEASURED_SLICES = 355
MEASURED_SLICE_BYTES = 86028


def top_size(row_size: int, queries: int) -> int:
    """MerkleTreeParams: the highest layer whose width is still at most `queries`."""
    layers = row_size.bit_length() - 1
    top_layer = 0
    for i in range(1, layers):
        if (1 << i) > queries:
            break
        top_layer = i
    return 1 << top_layer


class Tree:
    def __init__(self, name: str, row_size: int, col_size: int):
        self.name = name
        self.row_size = row_size
        self.col_size = col_size
        self.top = top_size(row_size, QUERIES)

    @property
    def setup_pairs(self) -> int:
        """Hashing the read-once top row up to the root."""
        return self.top - 1

    @property
    def path_pairs(self) -> int:
        """Branch length from a leaf up to the top row."""
        return (self.row_size.bit_length() - 1) - (self.top.bit_length() - 1)


def main() -> None:
    cycles = 1 << RECURSION_PO2
    domain = INV_RATE * cycles

    trees = [Tree(name, domain, cols) for name, cols in GROUP_COLS.items()]
    trees.append(Tree("check", domain, CHECK_COLS))

    # FRI: fold by 16 until the degree drops to FRI_MIN_DEGREE.
    degree, fri_domain = cycles, domain
    rounds = []
    while degree > FRI_MIN_DEGREE:
        rounds.append(Tree(f"fri round {len(rounds)}", fri_domain // FRI_FOLD,
                           FRI_FOLD * EXT_SIZE))
        fri_domain //= FRI_FOLD
        degree //= FRI_FOLD

    print(f"po2 {RECURSION_PO2}, {cycles} cycles, evaluation domain {domain}")
    print(f"{len(rounds)} FRI rounds, final degree {degree}, "
          f"{EXT_SIZE * degree} final coefficients\n")
    print(f"{'tree':<14}{'rows':>10}{'cols':>7}{'top':>6}{'path':>6}")
    for t in trees + rounds:
        print(f"{t.name:<14}{t.row_size:>10}{t.col_size:>7}{t.top:>6}{t.path_pairs:>6}")

    setup = sum(t.setup_pairs for t in trees + rounds)
    per_query_pairs = sum(t.path_pairs for t in trees + rounds)
    pairs = setup + QUERIES * per_query_pairs

    # One leaf slice hash per tree per query, the final FRI coefficients, and
    # the transcript slices hashed once at the start.
    slices = QUERIES * len(trees + rounds) + 1 + len(SETUP_SLICES)
    slice_elems = (QUERIES * sum(t.col_size for t in trees + rounds)
                   + EXT_SIZE * degree + sum(SETUP_SLICES))

    print(f"\nsetup pairs {setup}, {per_query_pairs} path pairs per query")
    print(f"predicted digest pairs  {pairs:>7}  measured {MEASURED_PAIRS:>7}"
          f"  delta {MEASURED_PAIRS - pairs:>5}  (Fiat-Shamir rng steps, 2 pairs each)")
    print(f"predicted slice hashes  {slices:>7}  measured {MEASURED_SLICES:>7}"
          f"  delta {MEASURED_SLICES - slices:>5}")
    print(f"predicted slice bytes   {4 * slice_elems:>7}  measured {MEASURED_SLICE_BYTES:>7}"
          f"  delta {MEASURED_SLICE_BYTES - 4 * slice_elems:>5}")


if __name__ == "__main__":
    main()
