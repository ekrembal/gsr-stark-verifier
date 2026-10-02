#!/usr/bin/env python3
"""Recover the checksum-pinned v3.0.6 recursion ZIP from the official r0vm binary.

Fallback for environments that cannot fetch RISC Zero's S3 archive. No content
is executed. The output must match the unmodified RISC Zero build.rs SHA-256.
"""
import argparse
import hashlib
from pathlib import Path
import struct

EXPECTED = "744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("r0vm", type=Path)
    parser.add_argument("out", type=Path)
    args = parser.parse_args()
    binary = args.r0vm.read_bytes()
    search = 0
    while True:
        end = binary.find(b"PK\x05\x06", search)
        if end < 0:
            raise RuntimeError("no embedded ZIP matching the pinned checksum")
        search = end + 1
        if end + 22 > len(binary):
            continue
        size, offset, comment = struct.unpack_from("<IIH", binary, end + 12)
        start = end - size - offset
        if start < 0 or end + 22 + comment > len(binary):
            continue
        archive = binary[start:end + 22 + comment]
        if hashlib.sha256(archive).hexdigest() != EXPECTED:
            continue
        args.out.write_bytes(archive)
        print(f"{EXPECTED}  {args.out} ({len(archive)} bytes)")
        return


if __name__ == "__main__":
    main()
