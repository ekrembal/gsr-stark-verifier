#!/usr/bin/env python3
"""JSON command-line front end of `rollup_covenant`, used by `pr-batcher`.

    covenant_cli.py script  <template.json> <rollup-id-hex> <root-hex>
        -> {"script_pubkey", "script_bytes"}
    covenant_cli.py witness <template.json> <rollup-id-hex> <old-root-hex> <receipt.json> <seal.bin> <new-root-hex> <annex-hex>
        -> {"stack": [hex, ...], "successor_script_pubkey"}   # input-0 witness, bottom first, annex last

The suffix of the covenant leaf depends only on the template and the rollup id, so `witness` rebuilds the
leaf for `old-root` and derives the successor from it exactly as the Script does.
"""
import json
import sys
from pathlib import Path

import rollup_covenant as rc


def covenant(template: str, rollup_id: str, root: str) -> rc.Covenant:
    return rc.Covenant(json.loads(Path(template).read_text()), bytes.fromhex(rollup_id), bytes.fromhex(root))


def main() -> None:
    a = sys.argv[1:]
    if len(a) == 4 and a[0] == "script":
        cov = covenant(*a[1:])
        print(json.dumps({"script_pubkey": cov.script_pubkey.hex(), "script_bytes": len(cov.script)}))
    elif len(a) == 8 and a[0] == "witness":
        cov = covenant(*a[1:4])
        receipt = json.loads(Path(a[4]).read_text())
        seal = Path(a[5]).read_bytes()
        new_root, annex = bytes.fromhex(a[6]), bytes.fromhex(a[7])
        stack = cov.witness(receipt, seal, new_root, annex)
        print(json.dumps({"stack": [s.hex() for s in stack],
                          "successor_script_pubkey": rc.successor_script_pubkey(cov, new_root).hex()}))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
