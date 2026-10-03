#!/usr/bin/env python3
"""Input frame and independent integer oracle for the field_dot4 guest.

Each 256-byte record is four canonical little-endian (a_i, b_i) pairs; the
expected journal is the canonical 32-byte sum(a_i * b_i) mod p per record.
"""
import argparse
import hashlib
from pathlib import Path
import random

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='directory for frame.bin and expected.bin')
    parser.add_argument('--records', type=int, default=1024)
    args = parser.parse_args()
    if not 1 <= args.records <= 1024:
        parser.error('records must be 1..1024 (guest frame bound is 256 KiB)')
    rng = random.Random(0x6473_7434)
    boundaries = [0, 1, 2, P - 1, P - 2, (P - 1) // 2, (P + 1) // 2, 2**128, 2**253, P - 2**64]
    records = [[(a, b)] * 4 for a in boundaries for b in boundaries]
    records.append([(P - 1, P - 1)] * 4)
    records.append([(0, P - 1), (P - 1, 0), (1, 1), (P - 1, 1)])
    while len(records) < args.records:
        records.append([(rng.choice(boundaries) if rng.random() < 0.25 else rng.randrange(P),
                         rng.choice(boundaries) if rng.random() < 0.25 else rng.randrange(P))
                        for _ in range(4)])
    records = records[:args.records]
    frame, expected = bytearray(), bytearray()
    for record in records:
        for a, b in record:
            frame += a.to_bytes(32, 'little') + b.to_bytes(32, 'little')
        expected += (sum(a * b for a, b in record) % P).to_bytes(32, 'little')
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'frame.bin').write_bytes(frame)
    (args.output / 'expected.bin').write_bytes(expected)
    print(f'{len(records)} records, frame sha256={hashlib.sha256(frame).hexdigest()}, '
          f'expected sha256={hashlib.sha256(expected).hexdigest()}')


if __name__ == '__main__':
    main()
