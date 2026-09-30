#!/usr/bin/env python3
"""Run a generated bundle (script + witness) through the pinned interpreter's evalscript."""
import json
import sys
from pathlib import Path

from gsr import Script, evalscript

ROOT = Path(__file__).resolve().parents[1]


def run(bundle: dict) -> dict:
    s = Script()
    s.code += bytes.fromhex(bundle["script"])
    return evalscript(s, [bytes.fromhex(x) for x in bundle["witness"]])


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "build/bundle.json")
    r = run(json.loads(Path(path).read_text()))
    r.pop("stack-after", None)
    print(json.dumps({k: v for k, v in r.items() if k != "stack-after"}, indent=1)[:3000])
