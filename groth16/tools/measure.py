#!/usr/bin/env python3
"""Measure the generated verifier as a complete 1-input, 1-output Taproot spend under the pinned Core interpreter.

Reuses recursive-stwo's deterministic transaction builder and its instrumented `gsr-meter`, so Core itself derives
the transaction weight and the varops budget from the serialized transaction and the spent output.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STWO_TOOLS = ROOT.parent / "recursive-stwo/tools"
RISC0_TOOLS = ROOT.parent / "risc0-succinct/tools"
sys.path.insert(0, str(RISC0_TOOLS))
sys.path.insert(0, str(STWO_TOOLS))
from transaction import build, meter_request  # noqa: E402

from gsr import op_success_offsets  # noqa: E402

METER = Path(
    os.environ.get("GSR_METER", str(ROOT.parent / "recursive-stwo/build/harness/gsr-meter"))
)


def meter(
    bundle: dict,
    tx=None,
    spent_value: int = 5_000_000_000,
    annex_bytes: int = 0,
) -> dict:
    """Meter `bundle` as the only input of `tx` (default: the deterministic 1-in/1-out spend)."""
    if tx is None:
        tx, _, _ = build(bundle)
    if annex_bytes:
        if annex_bytes < 1:
            raise ValueError("annex_bytes must be positive")
        tx.wit.vtxinwit[0].scriptWitness.stack.append(
            b"\x50" + bytes(annex_bytes - 1)
        )
    request = meter_request(bundle, tx, spent_value)
    if "GSR_METER" not in os.environ:
        request["budget"] = tx.get_weight() * 10000
    path = ROOT / "build/measurement-input.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(request))
    proc = subprocess.run([str(METER), str(path)], capture_output=True, text=True)
    if not proc.stdout:
        raise RuntimeError(proc.stderr)
    return json.loads(proc.stdout)


def limits(bundle: dict, execution: dict) -> dict:
    unrolled_bytes = execution.get("unrolled_bytes")
    if unrolled_bytes is None:
        unrolled_bytes = bundle.get("info", {}).get("unrolled_script_bytes")
    if unrolled_bytes is None:
        unrolled_bytes = len(bytes.fromhex(bundle["script"]))
    if bundle.get("info", {}).get("claim_mode") == "witness":
        verified_output = execution.get("final_stack_entries") == 1
    else:
        verified_output = execution.get("final_stack_exact_true", False)
    return {
        "standard_weight": execution.get("transaction_weight", 0) <= 400000,
        "varops": execution.get("varops", 0) <= execution.get("budget", 0),
        "unrolled_bytes": unrolled_bytes <= 4000000,
        "stack_entries": execution.get("peak_entries", 0) <= 32768,
        "live_payload": execution.get("peak_payload_bytes", 0) <= 8000000,
        "single_element": execution.get("peak_element_bytes", 0) <= 4000000,
        "no_op_success": not op_success_offsets(bytes.fromhex(bundle["script"])),
        "verifier": execution.get("ok", False)
        and verified_output
        and not execution.get("immediate_success", False),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", nargs="?", default=str(ROOT / "build/bundle.json"))
    parser.add_argument("--annex-bytes", type=int, default=0)
    args = parser.parse_args()
    bundle = json.loads(Path(args.bundle).read_text())
    execution = meter(bundle, annex_bytes=args.annex_bytes)
    checks = limits(bundle, execution)
    keys = (
        "ok", "error", "transaction_weight", "budget", "varops", "sha256_calls",
        "sha256_input_bytes", "macro_references", "unrolled_bytes", "peak_entries",
        "peak_payload_bytes", "peak_element_bytes", "final_stack_entries",
        "final_stack_exact_true",
    )
    report = {"script_bytes": len(bytes.fromhex(bundle["script"])),
              "witness_items": len(bundle["witness"]),
              "witness_payload_bytes": sum(len(bytes.fromhex(w)) for w in bundle["witness"]),
              "annex_bytes": args.annex_bytes,
              **{k: execution[k] for k in keys}, "limits": checks, "limits_pass": all(checks.values())}
    report_path = ROOT / "build/cost-report.json"
    report_path.write_text(json.dumps({**report, "opcodes": execution["opcodes"]}, indent=2) + "\n")
    print(json.dumps(report, indent=1))
    if not report["limits_pass"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
