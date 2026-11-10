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
from pairing_ref import ATE_LOOP_COUNT, fixture_pairing
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
    rejected_stack(script, stack, f"tampered witness item {index}")


def rejected_stack(script, stack, description):
    result = evaluate(script, stack)
    if result.returncode == 0:
        response = json.loads(result.stdout)
        if not response.get("error"):
            raise AssertionError(f"{description} was accepted")


def main():
    fixture = json.loads((ROOT / "fixtures/receipt.json").read_text())
    raw, traces = fixture_pairing(fixture)
    assert len(raw) == 12 and len(traces[3].slope_witnesses) == 87
    script, witness = build_pairing_script(fixture)
    step_blocks = {}
    digits = tuple(reversed(ATE_LOOP_COUNT[:-1]))
    for digit, (start, end) in zip(
        digits, witness.miller_step_ranges, strict=True
    ):
        kind = "double" if digit == 0 else f"double_add_{digit:+d}"
        block = bytes(script.code[start:end])
        if kind in step_blocks and step_blocks[kind] != block:
            raise AssertionError(f"{kind} Miller-loop steps are not byte-identical")
        step_blocks[kind] = block
    result = evaluate(script, witness.stack)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    response = json.loads(result.stdout)
    if response.get("error"):
        raise RuntimeError(response["error"])
    varops = EVAL_BUDGET - response["varops-budget-remaining"]
    tamper_indices = {
        "c": witness.layout["c"][0],
        "wi": witness.layout["wi"][0],
        "slope": witness.layout["slopes"][0][0],
        "line_constant": witness.layout["line_constants"][0][0],
    }
    for index in tamper_indices.values():
        rejected(script, witness, index)
    first, second = witness.layout["line_constants"][0][:2]
    split_stack = list(witness.stack)
    if len(split_stack[second]) < 2:
        raise AssertionError("line-constant test pair is too short to split")
    split_stack[first] += split_stack[second][:1]
    split_stack[second] = split_stack[second][1:]
    rejected_stack(script, split_stack, "line-constant boundary mutation")
    print(
        json.dumps(
            {
                "status": "PASS",
                "naf_pairing": "PASS",
                "dynamic_pairing_script": "PASS",
                "byte_identical_miller_steps": "PASS",
                "miller_step_macros": len(step_blocks),
                "corrupted_c": "REJECTED",
                "corrupted_wi": "REJECTED",
                "corrupted_slope": "REJECTED",
                "corrupted_line_constant": "REJECTED",
                "line_constant_boundary_mutation": "REJECTED",
                "script_bytes": len(script.code),
                "witness_items": len(witness.stack),
                "varops": varops,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
