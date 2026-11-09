#!/usr/bin/env python3
import json
import random
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "risc0-succinct/tools"))
from gsr import BITCOIN_UTIL, EVAL_BUDGET, Script, num

from bn254 import FQ2, FQ12, Fp6, P
from fields import FP, FP2, FP6, FP12

FIELDS = (FP, FP2, FP6, FP12)


def run_script(script, stack):
    test = Script().extend(script).int(1).int(1)
    request = {
        "protocol": 1,
        "sigversion": "tapscript_v2",
        "script": test.code.hex(),
        "stack": [item.hex() for item in stack],
        "varops_budget": EVAL_BUDGET,
    }
    proc = subprocess.run(
        [str(BITCOIN_UTIL), "evalscript"],
        input=json.dumps(request),
        capture_output=True,
        text=True,
    )
    if proc.returncode:
        raise RuntimeError(proc.stderr or proc.stdout)
    result = json.loads(proc.stdout)
    error = result["error"]
    if error and "exactly one" not in error.lower():
        raise RuntimeError(error)
    values = [int.from_bytes(bytes.fromhex(item), "little") for item in result["stack-after"]]
    return values[:-2], EVAL_BUDGET - result["varops-budget-remaining"]


def as_py_ecc(field, values):
    if field is FP2:
        return FQ2(values)
    if field is FP6:
        return Fp6(tuple(FQ2(values[i : i + 2]) for i in range(0, 6, 2)))
    if field is FP12:
        coeffs = [0] * 12
        for value, (u, v, w) in zip(values, field.basis, strict=True):
            degree = 2 * v + w
            if u:
                coeffs[degree + 6] += value
                coeffs[degree] -= 9 * value
            else:
                coeffs[degree] += value
        return FQ12(coeffs)
    return values[0]


def to_py_fq12(field, values):
    coeffs = [0] * 12
    for value, (u, v, w) in zip(values, field.basis, strict=True):
        degree = 2 * v + w
        if u:
            coeffs[degree + 6] += value
            coeffs[degree] -= 9 * value
        else:
            coeffs[degree] += value
    return FQ12(coeffs)


def py_ecc_equal(field, left, right):
    if field is FP6:
        return left.coeffs == right.coeffs
    if field is FP:
        return left % P == int(right) % P
    return left == right


def check_script(field, operation, left, right=None, sparse_indices=None):
    if operation in ("add", "sub"):
        expected = getattr(field, operation)(left, right)
        script = field.emit(operation)
        witness = [*left, *right]
    elif operation == "mul":
        expected = field.mul(left, right)
        script = field.emit("mul")
        witness = [*left, *right]
    elif operation == "square":
        expected = field.square(left)
        script = field.emit("square")
        witness = list(left)
    elif operation == "sparse_mul":
        sparse = [right[i] for i in sparse_indices]
        expected = field.mul_sparse(left, sparse, sparse_indices)
        script = field.emit("sparse_mul", sparse_indices)
        witness = [*left, *sparse]
    elif operation == "frobenius":
        expected = field.frobenius(left, 1)
        script = field.emit_frobenius(1)
        witness = list(left)
    else:
        raise ValueError(operation)

    stack = [num(value) for value in witness]
    actual, varops = run_script(script, stack)
    if tuple(actual) != expected:
        raise AssertionError(f"{field.name}.{operation}: expected {expected}, got {actual}")
    return varops


def main() -> None:
    rng = random.Random(0)
    costs = {}
    for field in FIELDS:
        n = field.degree
        a = tuple(rng.randrange(P) for _ in range(n))
        b = tuple(rng.randrange(P) for _ in range(n))
        checks = {
            "add": check_script(field, "add", a, b),
            "sub": check_script(field, "sub", a, b),
            "mul": check_script(field, "mul", a, b),
            "square": check_script(field, "square", a),
            "frobenius": check_script(field, "frobenius", a),
        }
        sparse_indices = tuple(range(min(3, n)))
        checks["sparse_mul"] = check_script(field, "sparse_mul", a, b, sparse_indices)
        if field is FP2:
            assert py_ecc_equal(field, as_py_ecc(field, field.mul(a, b)),
                                as_py_ecc(field, a) * as_py_ecc(field, b))
        elif field is FP6:
            assert py_ecc_equal(field, as_py_ecc(field, field.mul(a, b)),
                                as_py_ecc(field, a) * as_py_ecc(field, b))
        elif field is FP12:
            assert py_ecc_equal(field, as_py_ecc(field, field.mul(a, b)),
                                as_py_ecc(field, a) * as_py_ecc(field, b))
        if field is FP:
            assert field.add(a, b) == ((a[0] + b[0]) % P,)
            assert field.sub(a, b) == ((a[0] - b[0]) % P,)
        else:
            left_py, right_py = as_py_ecc(field, a), as_py_ecc(field, b)
            assert py_ecc_equal(field, as_py_ecc(field, field.add(a, b)), left_py + right_py)
            assert py_ecc_equal(field, as_py_ecc(field, field.sub(a, b)), left_py - right_py)
            assert py_ecc_equal(field, as_py_ecc(field, field.square(a)), left_py * left_py)
        assert to_py_fq12(field, field.frobenius(a, 1)) == to_py_fq12(field, a) ** P
        costs[field.name] = checks
    print(json.dumps({"status": "PASS", "varops": costs}, indent=2))


if __name__ == "__main__":
    main()
