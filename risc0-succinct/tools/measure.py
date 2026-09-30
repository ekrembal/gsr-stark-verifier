#!/usr/bin/env python3
"""Measure the generated verifier as a complete 1-input, 1-output Taproot spend under the pinned Core interpreter.

Reuses recursive-stwo's deterministic transaction builder and its instrumented `gsr-meter`, so Core itself derives
the transaction weight and the varops budget from the serialized transaction and the spent output.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STWO_TOOLS = ROOT.parent / "recursive-stwo/tools"
sys.path.insert(0, str(STWO_TOOLS))
from transaction import meter_request  # noqa: E402

from gsr import op_success_offsets  # noqa: E402

METER = ROOT.parent / "recursive-stwo/build/harness/gsr-meter"


def meter(bundle: dict, tx=None, spent_value: int = 5_000_000_000) -> dict:
    """Meter `bundle` as the only input of `tx` (default: the deterministic 1-in/1-out spend)."""
    request = meter_request(bundle, tx, spent_value)
    path = ROOT / "build/measurement-input.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(request))
    proc = subprocess.run([str(METER), str(path)], capture_output=True, text=True)
    if not proc.stdout:
        raise RuntimeError(proc.stderr)
    return json.loads(proc.stdout)


def limits(bundle: dict, execution: dict) -> dict:
    return {
        "standard_weight": execution["transaction_weight"] <= 400000,
        "varops": execution["varops"] <= execution["budget"],
        "invoked_body_bytes": execution["invoked_body_bytes"] <= 4000000,
        "function_ids": len(bundle["info"]["functions"]) <= 256,
        "stack_entries": execution["peak_entries"] <= 32768,
        "live_payload": execution["peak_payload_bytes"] <= 8000000,
        "single_element": execution["peak_element_bytes"] <= 4000000,
        "no_op_success": not op_success_offsets(bytes.fromhex(bundle["script"])),
        "verifier": execution["ok"] and execution["final_stack_exact_true"] and not execution["immediate_success"],
    }


def main() -> None:
    bundle = json.loads(Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "build/bundle.json").read_text())
    execution = meter(bundle)
    checks = limits(bundle, execution)
    keys = ("ok", "error", "transaction_weight", "budget", "varops", "sha256_calls", "sha256_input_bytes",
            "function_calls", "invoked_body_bytes", "peak_entries", "peak_payload_bytes", "peak_element_bytes")
    report = {"script_bytes": len(bytes.fromhex(bundle["script"])),
              "witness_items": len(bundle["witness"]),
              "witness_payload_bytes": sum(len(bytes.fromhex(w)) for w in bundle["witness"]),
              **{k: execution[k] for k in keys}, "limits": checks, "limits_pass": all(checks.values())}
    report_path = ROOT / "build/cost-report.json"
    report_path.write_text(json.dumps({**report, "opcodes": execution["opcodes"]}, indent=2) + "\n")
    print(json.dumps(report, indent=1))
    if not report["limits_pass"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
