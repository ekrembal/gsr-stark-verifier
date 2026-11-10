#!/usr/bin/env python3
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "risc0-succinct/tools"))
from bn254 import P
from gsr import BITCOIN_UTIL, EVAL_BUDGET, Script, num
import gsr_tooling
from msm import claim_scalars
from pairing_ref import G2_SUBGROUP_SCALAR, PSI_X, PSI_Y
from pairing_script import build_pairing_script
from py_ecc.bn128 import FQ2, b2, is_on_curve, multiply

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


def sqrt_mod(value):
    value %= P
    if value == 0:
        return 0
    if pow(value, (P - 1) // 2, P) != 1:
        return None
    q, s = P - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (P - 1) // 2, P) != P - 1:
        z += 1
    m, c, t, root = s, pow(z, q, P), pow(value, q, P), pow(value, (q + 1) // 2, P)
    while t != 1:
        i, t2 = 1, t * t % P
        while t2 != 1:
            t2 = t2 * t2 % P
            i += 1
        b = pow(c, 1 << (m - i - 1), P)
        root = root * b % P
        c = b * b % P
        t = t * c % P
        m = i
    return root


def sqrt_fp2(value):
    a, b = map(int, value.coeffs)
    norm = sqrt_mod((a * a + b * b) % P)
    if norm is None:
        return None
    inverse_two = pow(2, -1, P)
    for signed_norm in (norm, -norm % P):
        real = sqrt_mod((a + signed_norm) * inverse_two)
        if real is None:
            continue
        if real:
            imaginary = b * pow(2 * real, -1, P) % P
            candidate = FQ2([real, imaginary])
            if candidate * candidate == value:
                return candidate
        elif b == 0:
            imaginary = sqrt_mod((signed_norm - a) * inverse_two % P)
            if imaginary is not None:
                candidate = FQ2([0, imaginary])
                if candidate * candidate == value:
                    return candidate
    return None


def point_outside_g2_subgroup():
    for x0 in range(1, 100):
        x = FQ2([x0, x0 + 1])
        y = sqrt_fp2(x**3 + b2)
        if y is None:
            continue
        point = (x, y)
        if not is_on_curve(point, b2):
            continue
        psi = (x**P * PSI_X, y**P * PSI_Y)
        if multiply(point, G2_SUBGROUP_SCALAR) != psi:
            return point
    raise RuntimeError("failed to find a twist point outside G2 subgroup")


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
    digit_index = witness.layout["digits"][0][0]
    digit = int.from_bytes(witness.stack[digit_index], "little")
    rejected(script, witness, digit_index, (digit + 1) % 16)

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
        "tampered_A_B_C": "REJECTED",
        "out_of_subgroup_B": "REJECTED",
        "noncanonical_field": "REJECTED",
        "off_curve_A": "REJECTED",
        "wrong_fixed_claim": "REJECTED",
        "tampered_c_c_inv_wi": "REJECTED",
        "tampered_slope": "REJECTED",
        "tampered_line_constant": "REJECTED",
        "wrong_window_digit": "REJECTED",
        "fixed_script_bytes": len(script.code),
        "fixed_witness_items": len(witness.stack),
        "fixed_varops": fixed_varops,
    }, indent=2))


if __name__ == "__main__":
    main()
