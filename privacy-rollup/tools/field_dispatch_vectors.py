#!/usr/bin/env python3
"""Independent integer oracle for the field_dispatch guest's dispatch boundaries."""
import argparse
import hashlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    fields = [
        (21888242871839275222246405745257275088548364400416034343698204186575808495617, 32),
        (21888242871839275222246405745257275088696311157297823662689037894645226208583, 32),
        (17, 8),
    ]
    def sample(i, seed, p):
        return [0, 1, p-1, (seed+i*987654321) % p][min(i % 7, 3)]
    output = bytearray()
    for p, width in fields:
        for seed in [0, 1, 97, 123456789]:
            for length in [0, 1, 3, 4, 5, 7, 31, 32, 33]:
                value = sum(sample(i, seed, p) * sample(i+3, seed+17, p)
                            for i in range(length)) % p
                output.extend(value.to_bytes(width, 'little'))
    if args.output.exists():
        if args.output.read_bytes() != output:
            parser.error('existing oracle differs; refusing to overwrite')
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(output)
    print(f'{len(fields) * 4 * 9} outputs, {len(output)} bytes, sha256={hashlib.sha256(output).hexdigest()}')


if __name__ == '__main__':
    main()
