#!/usr/bin/env python3
"""JSON command-line front end of `rollup_covenant`, used by `pr-batcher`.

    covenant_cli.py script  <template.json> <rollup-id-hex>
        -> {"script_pubkey", "script_bytes"}   # the rollup's fixed address
    covenant_cli.py witness <template.json> <rollup-id-hex> <old-root-hex> <receipt.json> <seal.bin> <new-root-hex> <annex-hex>
        -> {"stack": [hex, ...], "script_pubkey"}   # input-0 witness, bottom first, annex last
    covenant_cli.py escrow-body <template.json> <rollup-id-hex>
        -> {"body"}   # deposit escrow sweep body (deposit_escrow.py)
"""
import json
import sys
from pathlib import Path

import deposit_escrow as de
import rollup_covenant as rc


def covenant(template: str, rollup_id: str) -> rc.Covenant:
    return rc.Covenant(json.loads(Path(template).read_text()), bytes.fromhex(rollup_id))


def main() -> None:
    a = sys.argv[1:]
    if len(a) == 3 and a[0] == "script":
        cov = covenant(*a[1:])
        print(json.dumps({"script_pubkey": cov.script_pubkey.hex(), "script_bytes": len(cov.script)}))
    elif len(a) == 8 and a[0] == "witness":
        cov = covenant(*a[1:3])
        receipt = json.loads(Path(a[4]).read_text())
        seal = Path(a[5]).read_bytes()
        old_root, new_root, annex = bytes.fromhex(a[3]), bytes.fromhex(a[6]), bytes.fromhex(a[7])
        stack = cov.witness(receipt, seal, old_root, new_root, annex)
        print(json.dumps({"stack": [s.hex() for s in stack], "script_pubkey": cov.script_pubkey.hex()}))
    elif len(a) == 3 and a[0] == "escrow-body":
        print(json.dumps({"body": de.sweep_body(covenant(*a[1:]).script_pubkey).hex()}))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
