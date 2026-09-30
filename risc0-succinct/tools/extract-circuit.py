#!/usr/bin/env python3
"""Extract the recursion circuit's generated tap set and constraint program into fixtures/circuit.json.

Reads RISC Zero's generated sources (risc0/circuit/recursion/src/{taps,poly_ext,info}.rs) verbatim; the
JSON is the verifier's only description of the circuit.
"""
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def find(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    assert m is not None, pattern
    return m.group(1)


def main() -> None:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("RISC0_DIR", Path.home() / "risc0")) / "risc0/circuit/recursion/src"
    taps_rs = (src / "taps.rs").read_text()
    taps = [dict(zip(("offset", "back", "group", "combo", "skip"), map(int, m))) for m in re.findall(
        r"TapData \{\s*offset: (\d+),\s*back: (\d+),\s*group: (\d+),\s*combo: (\d+),\s*skip: (\d+),\s*\}",
        taps_rs)]

    def array(name: str) -> list[int]:
        body = find(name + r": &\[([^\]]*)\]", taps_rs)
        return [int(x) for x in body.replace("\n", " ").split(",") if x.strip()]

    def scalar(name: str) -> int:
        return int(find(name + r": (\d+),", taps_rs))

    poly_rs = (src / "poly_ext.rs").read_text()
    block: list[list] = []
    for m in re.finditer(r"PolyExtStep::(\w+)(?:\(([^)]*)\))?,", poly_rs):
        args = [int(x) for x in m.group(2).split(",")] if m.group(2) else []
        block.append([m.group(1)] + args)
    ret = int(find(r"ret: (\d+),", poly_rs))
    info_rs = (src / "info.rs").read_text()
    circuit: dict = {
        "source": "risc0/circuit/recursion/src (RISC Zero v3.0.6), generated code",
        "circuit_info": find(r'ProtocolInfo\(\*b"([^"]+)"\)', info_rs),
        "output_size": int(find(r"OUTPUT_SIZE: usize = (\d+)", info_rs)),
        "mix_size": int(find(r"MIX_SIZE: usize = (\d+)", info_rs)),
        "taps": taps,
        "combo_taps": array("combo_taps"),
        "combo_begin": array("combo_begin"),
        "group_begin": array("group_begin"),
        "combos_count": scalar("combos_count"),
        "reg_count": scalar("reg_count"),
        "tot_combo_backs": scalar("tot_combo_backs"),
        "poly_ext": {"block": block, "ret": ret},
    }
    assert len(taps) == circuit["group_begin"][-1]
    (ROOT / "fixtures/circuit.json").write_text(json.dumps(circuit, separators=(",", ":")) + "\n")
    ops: dict[str, int] = {}
    for step in block:
        ops[step[0]] = ops.get(step[0], 0) + 1
    print(len(taps), "taps;", len(block), "steps;", ops)


if __name__ == "__main__":
    main()
