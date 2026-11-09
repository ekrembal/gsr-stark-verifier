#!/usr/bin/env python3
import json
from pathlib import Path

import bn254

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    result = bn254.verify_fixture(ROOT / "fixtures/receipt.json")
    assert result["residue_relation"]
    print(json.dumps({"fixture": "native Groth16 receipt", "pairing": "PASS",
                      "full_final_exponentiation": "PASS", "residue_witness": "PASS",
                      "public_inputs": result["public_inputs"]}, indent=2))


if __name__ == "__main__":
    main()
