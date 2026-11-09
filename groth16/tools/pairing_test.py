#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT.parent / "risc0-succinct/tools"))

from bn254 import P
from gsr import BITCOIN_UTIL, EVAL_BUDGET, num
from pairing_ref import fixture_pairing
from pairing_script import build_pairing_script


def evaluate(script, stack):
    request = {
        "protocol": 1,
        "sigversion": "tapscript_v2",
        "script": script.code.hex(),
        "stack": [item.hex() for item in stack],
        "varops_budget": EVAL_BUDGET,
    }
    return subprocess.run(
        [str(BITCOIN_UTIL), "evalscript"],
        input=json.dumps(request),
        capture_output=True,
        text=True,
    )


def rejected(script, witness, index):
    stack = list(witness.stack)
    value = int.from_bytes(stack[index], "little")
    stack[index] = num((value + 1) % P)
    result = evaluate(script, stack)
    if result.returncode == 0:
        response = json.loads(result.stdout)
        if not response.get("error"):
            raise AssertionError(f"tampered witness item {index} was accepted")


def main():
    fixture = json.loads((ROOT / "fixtures/receipt.json").read_text())
    raw, traces = fixture_pairing(fixture)
    assert len(raw) == 12 and len(traces[3].slope_witnesses) == 87
    script, witness = build_pairing_script(fixture)
    result = evaluate(script, witness.stack)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    response = json.loads(result.stdout)
    if response.get("error"):
        raise RuntimeError(response["error"])
    varops = EVAL_BUDGET - response["varops-budget-remaining"]
    for name in ("c", "wi", "slopes"):
        index = (
            witness.layout[name][0]
            if name != "slopes"
            else witness.layout["slopes"][0][0]
        )
        rejected(script, witness, index)
    print(
        json.dumps(
            {
                "status": "PASS",
                "naf_pairing": "PASS",
                "dynamic_pairing_script": "PASS",
                "corrupted_c": "REJECTED",
                "corrupted_wi": "REJECTED",
                "corrupted_slope": "REJECTED",
                "script_bytes": len(script.code),
                "witness_items": len(witness.stack),
                "varops": varops,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
