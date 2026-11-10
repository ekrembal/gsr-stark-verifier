#!/usr/bin/env python3
"""Generate a fixed-claim or witness-claim verifier bundle."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "risc0-succinct/tools"))

import gsr_tooling
from pairing_script import build_pairing_script


def generate(claim_mode: str, compress: bool) -> dict:
    fixture = json.loads((ROOT / "fixtures/receipt.json").read_text())
    script, witness = build_pairing_script(fixture, claim_mode)
    uncompressed = bytes(script.code)
    compressed = None
    compression = None
    if compress:
        compressed, compression = gsr_tooling.compress(uncompressed)
        anchored, _ = gsr_tooling.rewrite(
            "anchor", "--protect", "0", script=uncompressed
        )
        unroll_result = gsr_tooling.run("unroll", script=compressed)
        if unroll_result.returncode:
            raise RuntimeError(unroll_result.stderr.strip())
        unrolled = bytes.fromhex(unroll_result.stdout.strip())
        if unrolled != anchored:
            raise RuntimeError("compressed Script does not unroll to the anchored Script")
        gsr_tooling.check(compressed)
    deployed = compressed if compressed is not None else uncompressed
    return {
        "script": deployed.hex(),
        "witness": [item.hex() for item in witness.stack],
        "info": {
            "claim_mode": claim_mode,
            "uncompressed_script_bytes": len(uncompressed),
            "compressed_script_bytes": len(compressed) if compressed is not None else None,
            "unrolled_script_bytes": len(unrolled) if compressed is not None else len(uncompressed),
            "witness_items": len(witness.stack),
            "witness_bytes": sum(map(len, witness.stack)),
            "compression": compression,
            "stage_ranges": {
                name: list(bounds) for name, bounds in witness.stage_ranges.items()
            },
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--claim", choices=("fixed", "witness"), default="fixed")
    parser.add_argument("--compress", action="store_true")
    parser.add_argument("--out", default=str(ROOT / "build/bundle.json"))
    args = parser.parse_args()
    bundle = generate(args.claim, args.compress)
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bundle))
    print(json.dumps(bundle["info"], indent=2))


if __name__ == "__main__":
    main()
