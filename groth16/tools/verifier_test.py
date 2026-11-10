#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "risc0-succinct/tools"))
from bn254 import G2_X0, P, is_g2_subgroup_x0, sqrt_fp2
from gsr import BITCOIN_UTIL, EVAL_BUDGET, Script, num
import gsr_tooling
from msm import claim_scalars
from pairing_ref import g2_x0_subgroup_trace
from pairing_script import build_pairing_script
from py_ecc.bn128 import FQ2, b2, is_on_curve

ROOT = Path(__file__).resolve().parents[1]


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


def rejected(script, witness, index, value):
    stack = list(witness.stack)
    stack[index] = num(value)
    result = evaluate(script, stack)
    if result.returncode == 0:
        response = json.loads(result.stdout)
        if not response.get("error"):
            raise AssertionError(f"tampered witness item {index} was accepted")


def compressed_script(script):
    original = bytes(script.code)
    compressed, _ = gsr_tooling.compress(original)
    anchored, _ = gsr_tooling.rewrite("anchor", "--protect", "0", script=original)
    unrolled = gsr_tooling.run("unroll", script=compressed)
    if unrolled.returncode or bytes.fromhex(unrolled.stdout.strip()) != anchored:
        raise AssertionError("compressed verifier does not unroll to the anchored Script")
    result = Script()
    result.code = bytearray(compressed)
    return result


def point_outside_g2_subgroup():
    for x0 in range(1, 100):
        x = FQ2([x0, x0 + 1])
        y = sqrt_fp2(x**3 + b2)
        if y is None:
            continue
        point = (x, y)
        if not is_on_curve(point, b2):
            continue
        if not is_g2_subgroup_x0(point):
            return point
    raise RuntimeError("failed to find a twist point outside G2 subgroup")


def subgroup_slope_values(trace):
    slopes = []
    for step_index in reversed(range(len(trace["steps"]))):
        step = trace["steps"][step_index]
        slopes.extend((step["double_slope"], step["add_slope"]))
    slopes.extend(
        trace["relations"][name]
        for name in ("double_x0", "psi2_x0", "psi_x0", "x0_plus_one")
    )
    return slopes


def main():
    fixture = json.loads((ROOT / "fixtures/receipt.json").read_text())
    script, witness = build_pairing_script(fixture, "fixed")
    result = evaluate(script, witness.stack)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    response = json.loads(result.stdout)
    if response.get("error"):
        raise RuntimeError(response["error"])
    fixed_varops = EVAL_BUDGET - response["varops-budget-remaining"]
    if len(witness.subgroup_step_ranges) != G2_X0.bit_length() - 1:
        raise AssertionError("incorrect number of x0 subgroup scalar steps")
    step_blocks = {}
    for bit, (start, end) in zip(
        bin(G2_X0)[3:], witness.subgroup_step_ranges, strict=True
    ):
        kind = "double" if bit == "0" else "double_add"
        block = bytes(script.code[start:end])
        if kind in step_blocks and step_blocks[kind] != block:
            raise AssertionError(f"{kind} subgroup steps are not byte-identical")
        step_blocks[kind] = block
    if set(step_blocks) != {"double", "double_add"}:
        raise AssertionError("expected double and double-add subgroup macros")
    shamir_blocks = {
        bytes(script.code[start:end]) for start, end in witness.shamir_step_ranges
    }
    if len(shamir_blocks) != 1 or len(witness.shamir_step_ranges) != 128:
        raise AssertionError("Shamir MSM steps are not one byte-identical block")
    compressed_fixed = compressed_script(script)
    compressed_result = evaluate(compressed_fixed, witness.stack)
    if compressed_result.returncode or json.loads(compressed_result.stdout).get("error"):
        raise AssertionError("compressed fixed-claim verifier failed")

    for name in ("A", "B", "C"):
        for coordinate in witness.layout[name]:
            index = coordinate[0]
            value = int.from_bytes(witness.stack[index], "little")
            rejected(script, witness, index, value ^ 1)
    outside = point_outside_g2_subgroup()
    outside_witness = list(witness.stack)
    for target, coordinate in zip(
        witness.layout["B"], outside, strict=True
    ):
        for index, value in zip(target, coordinate.coeffs, strict=True):
            outside_witness[index] = num(int(value))
    outside_trace = g2_x0_subgroup_trace(outside)
    if outside_trace["accepts"]:
        raise AssertionError("test point unexpectedly satisfies the x0 relation")
    for indices, slope in zip(
        witness.layout["subgroup_slopes"],
        subgroup_slope_values(outside_trace),
        strict=True,
    ):
        for index, value in zip(indices, slope, strict=True):
            outside_witness[index] = num(value)
    outside_result = evaluate(script, outside_witness)
    if outside_result.returncode == 0 and not json.loads(outside_result.stdout).get("error"):
        raise AssertionError("on-twist B point outside G2 subgroup was accepted")

    ax = witness.layout["A"][0][0]
    rejected(script, witness, ax, int.from_bytes(witness.stack[ax], "little") + P)
    ay = witness.layout["A"][1][0]
    rejected(
        script,
        witness,
        ay,
        (int.from_bytes(witness.stack[ay], "little") + 1) % P,
    )
    c0, _ = claim_scalars(fixture)
    claim_index = witness.layout["claim"][0][0]
    rejected(script, witness, claim_index, c0 + 1)

    for name in ("c", "c_inv", "wi"):
        index = witness.layout[name][0]
        value = int.from_bytes(witness.stack[index], "little")
        rejected(script, witness, index, value ^ 1)
    slope_index = witness.layout["slopes"][0][0]
    rejected(
        script,
        witness,
        slope_index,
        int.from_bytes(witness.stack[slope_index], "little") ^ 1,
    )
    line_constant_index = witness.layout["line_constants"][0][0]
    rejected(
        script,
        witness,
        line_constant_index,
        int.from_bytes(witness.stack[line_constant_index], "little") ^ 1,
    )
    bit_index = witness.layout["bits"][0][0][0]
    bit = int.from_bytes(witness.stack[bit_index], "little")
    rejected(script, witness, bit_index, bit ^ 1)
    rejected(script, witness, bit_index, 2)

    witness_script, witness_mode = build_pairing_script(fixture, "witness")
    output_check = Script().data(bytes.fromhex(fixture["claim_digest"]))
    output_check.op("EQUALVERIFY").int(1)
    witness_script.extend(output_check)
    result = evaluate(witness_script, witness_mode.stack)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    response = json.loads(result.stdout)
    if response.get("error"):
        raise RuntimeError(response["error"])
    compressed_witness = compressed_script(witness_script)
    compressed_result = evaluate(compressed_witness, witness_mode.stack)
    if compressed_result.returncode or json.loads(compressed_result.stdout).get("error"):
        raise AssertionError("compressed witness-claim verifier failed")
    print(json.dumps({
        "status": "PASS",
        "claim_fixed": "PASS",
        "claim_witness": "PASS",
        "compressed_fixed": "PASS",
        "compressed_witness": "PASS",
        "compression_equivalence": "PASS",
        "claim_witness_digest_bytes": fixture["claim_digest"],
        "subgroup_step_macros": len(step_blocks),
        "shamir_step_macros": len(shamir_blocks),
        "tampered_A_B_C": "REJECTED",
        "out_of_subgroup_B": "REJECTED",
        "noncanonical_field": "REJECTED",
        "off_curve_A": "REJECTED",
        "wrong_fixed_claim": "REJECTED",
        "tampered_c_c_inv_wi": "REJECTED",
        "tampered_slope": "REJECTED",
        "tampered_line_constant": "REJECTED",
        "wrong_shamir_bit": "REJECTED",
        "non_boolean_shamir_bit": "REJECTED",
        "fixed_script_bytes": len(script.code),
        "fixed_witness_items": len(witness.stack),
        "fixed_varops": fixed_varops,
    }, indent=2))


if __name__ == "__main__":
    main()
