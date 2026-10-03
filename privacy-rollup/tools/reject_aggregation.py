#!/usr/bin/env python3
"""Check guest rejections on local, synthetic input frames. Execution only.

First run profile_aggregation.py to establish acceptance of the original frames
with these same executables. Generate variants with aggregation-cases --release.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("cases", type=Path)
    parser.add_argument("--verify", required=True, type=Path)
    parser.add_argument("--program", type=Path, help="combined verify_joinsplit .bin override")
    parser.add_argument("--settle", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    report = []
    for kind in ["verify", "batch"]:
        for name in ["public-input", "narg-first", "hint-middle", "narg-extra"]:
            proof = args.cases / f"{name}.pc"
            if kind == "verify":
                cmd = [str(args.verify), str(args.inputs / "vk.pc"), str(proof)]
                if args.program:
                    cmd.append(str(args.program))
            else:
                cmd = [str(args.settle), "exec", str(args.inputs / "witness.json"),
                       str(args.out / name), str(proof)]
            run_rejection(cmd, args.out / f"{kind}-{name}.log", kind, name, report)
    (args.out / "results.json").write_text(json.dumps({"execution_only": True, "cases": report}, indent=2) + "\n")
    print(f"passed: {len(report)} guest rejections")


def run_rejection(cmd, log_path, kind, name, report):
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    log = result.stdout + result.stderr
    log_path.write_text(log)
    if not result.returncode or "Guest panicked" not in log:
        raise RuntimeError(f"expected a guest panic for {kind}/{name}; see {log_path}")
    report.append({"kind": kind, "name": name, "returncode": result.returncode,
                   "command": cmd, "log_sha256": hashlib.sha256(log.encode()).hexdigest()})
    print(f"rejected: {kind}/{name}", flush=True)


if __name__ == "__main__":
    main()
