#!/usr/bin/env python3
"""Optional host-only compiler experiment, not part of the default build.

Use as RUSTC_WRAPPER after removing only the selected host packages' generated
Cargo artifacts. Cargo does not fingerprint this wrapper's added flags: clean
those packages again when returning to the default compiler. Saved executables
and guest programs are independent of that build-cache operation.
"""
import json
import os
import sys

COMPONENTS = {
    "risc0_core", "risc0_zkp", "risc0_circuit_rv32im",
    "risc0_circuit_recursion", "risc0_circuit_keccak", "risc0_zkvm",
    "proof_chain_bench",
}
selection = os.environ.get("GSR_NATIVE_RUST_CRATES")
if selection:
    selected = set(selection.split(","))
    if not selected <= COMPONENTS:
        raise SystemExit("GSR_NATIVE_RUST_CRATES must be a subset of the explicit host crate list")
    COMPONENTS = selected


def option(args, name):
    for index, arg in enumerate(args):
        if arg == name and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1]
    return None


compiler, *args = sys.argv[1:]
crate = option(args, "--crate-name")
target = option(args, "--target")
if crate in COMPONENTS and target in (None, "x86_64-unknown-linux-gnu"):
    args += ["-C", "target-cpu=native", "-C", "codegen-units=1"]
    log = os.environ.get("GSR_NATIVE_RUST_LOG")
    if log:
        fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.write(fd, (json.dumps({"crate": crate, "target": target, "added_flags": args[-4:]}) + "\n").encode())
        os.close(fd)
os.execv(compiler, [compiler, *args])
