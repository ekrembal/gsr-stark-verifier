#!/usr/bin/env python3
"""Independently check native SHA vector digests with Python's hashlib.

Raw compression states and Spongefish outputs are compared byte-for-byte with
the accelerated guest by exec_sha256_check; hashlib does not expose those APIs.
"""
import argparse
import hashlib
import json
from pathlib import Path

LENGTHS = [0, 1, 2, 3, 31, 32, 55, 56, 57, 63, 64, 65, 95, 111, 112, 119, 120,
           127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097]


def data(length):
    return bytes((i * 131 + (i >> 3) + 17) & 255 for i in range(length))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    raw = args.reference.read_bytes()
    position, checked = 0, 0

    def check(expected):
        nonlocal position, checked
        assert raw[position:position + len(expected)] == expected, f"digest mismatch at byte {position}"
        position += len(expected)
        checked += 1

    for length in LENGTHS:
        for offset in range(4):
            message = data(length + 4)[offset:offset + length]
            check(hashlib.sha256(message).digest())
            check(hashlib.sha224(message).digest())
    check(hashlib.sha512(data(4097)).digest())
    position += 6 * 4 * 32  # Raw compression states: native/guest differential.
    for size in [0, 1, 31, 32, 55, 56, 63, 64, 65, 128, 511]:
        for count in [0, 1, 3]:
            messages = data(size * count + 1)[1:]
            for i in range(count):
                check(hashlib.sha256(messages[i * size:(i + 1) * size]).digest())
    position += 11 * (97 + 65)  # Spongefish transcript outputs: native/guest differential.
    assert position == len(raw) == 11702
    report = {"passed": True, "hashlib_digest_comparisons": checked, "reference_bytes": len(raw),
              "reference_sha256": hashlib.sha256(raw).hexdigest(), "raw_compression_cases": 24,
              "transcript_sequences": 11,
              "note": "Raw compression/transcript bytes require the separate guest comparison."}
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
