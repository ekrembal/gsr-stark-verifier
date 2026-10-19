"""Point the apply-batch receipt template at the current guest image.

`python3 tools/retemplate.py [<image-id-hex>]` sets `claim.pre` to the image (default: the output of
`prover/target/release/settle id`) and recomputes `claim_digest`; the sample journal, control root and
seal parameters are unchanged, as they do not depend on the guest.
"""
import json
import subprocess
import sys
from pathlib import Path

import rollup_covenant as rc

PR = Path(__file__).resolve().parents[1]
TEMPLATE = PR / "fixtures/apply-batch/receipt-template.json"


def main():
    image = sys.argv[1] if len(sys.argv) > 1 else subprocess.run(
        [str(PR / "prover/target/release/settle"), "id"], check=True, capture_output=True, text=True).stdout.strip()
    assert len(bytes.fromhex(image)) == 32, image
    t = json.loads(TEMPLATE.read_text())
    t["claim"]["pre"] = image
    t["claim_digest"] = rc.ref.claim_digest(t["claim"]).hex()
    TEMPLATE.write_text(json.dumps(t, indent=2) + "\n")
    print(json.dumps({"pre": image, "claim_digest": t["claim_digest"]}))


if __name__ == "__main__":
    main()
