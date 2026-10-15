#!/usr/bin/env python3
"""Measure execution only on fixed input frames; never requests a receipt.

Run from an activated environment after building the host/guest. Keep the input
directory and baseline executables for comparisons. GNU time measures peak host
RSS (not guest RAM). Inclusive spans overlap; exclusive spans can be compared.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    pr = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path, help="directory containing proof0.pc and witness.json (plus vk.pc for --kind verify)")
    parser.add_argument("--label", required=True)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--kind", choices=["verify", "batch"], default="verify")
    parser.add_argument("--binary", type=Path, help="saved baseline or current host executable")
    parser.add_argument("--program", "--elf", dest="program", type=Path,
                        help="saved combined verify_joinsplit .bin (verify only)")
    parser.add_argument("--out", type=Path, default=pr.parent / "build/aggregation")
    args = parser.parse_args()
    if not 1 <= args.runs <= 10:
        parser.error("runs must be between 1 and 10")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.label):
        parser.error("label must be a simple filename component")
    if args.kind == "batch" and args.program:
        parser.error("program override is available only for verify")
    time_binary = shutil.which("time")
    if not time_binary:
        parser.error("GNU time is required on PATH")
    args.out.mkdir(parents=True, exist_ok=True)
    inputs = args.inputs.resolve()
    binary = (args.binary or pr / "prover/target/release" / ("exec_joinsplit" if args.kind == "verify" else "settle")).resolve()
    hashes = {name: {"bytes": (inputs / name).stat().st_size, "sha256": digest(inputs / name)}
              for name in (["vk.pc"] if args.kind == "verify" else []) + ["proof0.pc", "witness.json"]}
    runs = []
    for i in range(args.runs):
        stem = args.out / f"{args.label}-{args.kind}-{i}"
        if args.kind == "verify":
            cmd = [str(binary), str(inputs / "vk.pc"), str(inputs / "proof0.pc")]
            if args.program:
                cmd.append(str(args.program.resolve()))
        else:
            cmd = [str(binary), "exec", str(inputs / "witness.json"), str(stem) + "-journal", str(inputs / "proof0.pc")]
        timed = [time_binary, "-v", "-o", str(stem) + ".time", *cmd]
        result = subprocess.run(timed, capture_output=True, text=True, timeout=900)
        log = result.stdout + result.stderr
        Path(str(stem) + ".log").write_text(log)
        if result.returncode:
            raise RuntimeError(f"execution failed ({result.returncode}); see {stem}.log")
        time_log = Path(str(stem) + ".time").read_text()
        rss = int(re.search(r"Maximum resident set size \(kbytes\): (\d+)", time_log)[1])
        if args.kind == "verify":
            measurement = next(json.loads(line) for line in result.stdout.splitlines() if line.startswith('{'))
            measurement["phases"] = {n: int(c) for n, c in re.findall(r"phase (\w+): (\d+) cycles", log)}
            measurement["phases"]["verify"] = int(re.search(r"verify cycles: (\d+)", log)[1])
            measurement["spans"] = [{"name": n, "inclusive_cycles": int(c), "exclusive_cycles": int(e), "calls": int(k)}
                for n, c, e, k in re.findall(r"span (.+): inclusive=(\d+) exclusive=(\d+) calls=(\d+)", log)]
        else:
            c, s, t = re.search(r"executed: (\d+) cycles, (\d+) segments, ([\d.]+)s", log).groups()
            measurement = {"cycles": int(c), "segments": int(s), "runtime_seconds": float(t),
                           "image_id": re.search(r"image id ([0-9a-f]{64})", log)[1],
                           "journal_sha256": digest(Path(str(stem) + "-journal/journal.bin"))}
        measurement.update(command=cmd, peak_host_rss_kib=rss)
        runs.append(measurement)
        print(json.dumps({"label": args.label, "kind": args.kind, "run": i, "cycles": measurement["cycles"],
                          "segments": measurement["segments"], "runtime_seconds": measurement["runtime_seconds"], "peak_host_rss_kib": rss}), flush=True)
    report = {"label": args.label, "kind": args.kind, "execution_only": True, "inputs": hashes,
              "binary_sha256": digest(binary), "program_sha256": digest(args.program) if args.program else None,
              "cpu_count": os.cpu_count(), "platform": platform.platform(),
              "cpu_quota": read_limit("cpu.max"), "memory_limit_bytes": read_limit("memory.max"), "runs": runs}
    (args.out / f"{args.label}-{args.kind}.json").write_text(json.dumps(report, indent=2) + "\n")


def read_limit(name):
    path = Path("/sys/fs/cgroup") / name
    return path.read_text().strip() if path.exists() else None


if __name__ == "__main__":
    main()
