#!/usr/bin/env python3
"""Build and run the pinned optional CPU evaluator differential test.

Pass the SDK sys crate's Cargo OUT_DIR from a GSR_BUILD_CPU_BATCH=1 build.
Use bounded_command.py around this tool to retain resource/log evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk", required=True, type=Path)
    p.add_argument("--sys-out", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--expect-disabled", action="store_true",
                   help="check the portable build's unavailable stub")
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name("cpu_poly_differential.cpp").resolve()
    if a.expect_disabled:
        source = a.out / "disabled.cpp"
        source.write_text('''#include "fp.h"
#include "fpext.h"
#include <cstdlib>
#include <cstring>
extern "C" bool risc0_circuit_rv32im_cpu_poly_fp_batch_available();
extern "C" const char* risc0_circuit_rv32im_cpu_poly_fp_batch(
    size_t, size_t, const risc0::FpExt*, const risc0::Fp* const*, risc0::FpExt*);
int main() {
  if (risc0_circuit_rv32im_cpu_poly_fp_batch_available()) return 1;
  const char* error = risc0_circuit_rv32im_cpu_poly_fp_batch(0,0,nullptr,nullptr,nullptr);
  if (!error || !std::strstr(error, "GSR_BUILD_CPU_BATCH=1")) return 2;
  std::free(const_cast<char*>(error));
}
''')
    includes = [a.sdk / "risc0/sys/cxx",
                a.sdk / "risc0/circuit/rv32im-sys/kernels/cxx_batch",
                a.sys_out / "cpu_poly_batch"]
    libraries = [a.sys_out / "librisc0_rv32im_cpu.a",
                 a.sys_out / "librisc0_rv32im_cpu_batch.a"]
    flags = [] if a.expect_disabled else ["-march=native", "-fno-tree-slp-vectorize",
                                         "-fno-tree-loop-vectorize"]
    if a.expect_disabled:
        libraries = libraries[:1]
    command = ["c++", "-O2", "-std=c++17", *flags,
               *["-I" + str(d) for d in includes], str(source),
               *map(str, libraries), "-o", str(a.out / "check")]
    subprocess.run(command, check=True)
    subprocess.run([str(a.out / "check")], check=True)
    evidence = {
        "commands": [command, [str(a.out / "check")]],
        "sha256": {str(f): hashlib.sha256(f.read_bytes()).hexdigest()
                   for f in [source, *libraries, a.out / "check"]},
        "compiler": subprocess.check_output(["c++", "--version"], text=True),
    }
    (a.out / "commands.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    main()
