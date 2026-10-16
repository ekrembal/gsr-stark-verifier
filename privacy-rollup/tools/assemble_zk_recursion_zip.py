#!/usr/bin/env python3
"""Add the zirgen-built `resolve_zk.zkr` to RISC Zero's upstream `recursion_zkr.zip`.

    assemble_zk_recursion_zip.py <upstream recursion_zkr.zip> <resolve_zk.zkr> <out.zip>

Every upstream entry is copied unchanged; the output is deterministic (fixed timestamps).
"""
import hashlib
import sys
import zipfile

UPSTREAM_SHA256 = "744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849"


def main() -> None:
    src, zkr, dst = sys.argv[1:4]
    assert hashlib.sha256(open(src, "rb").read()).hexdigest() == UPSTREAM_SHA256, "unexpected upstream archive"
    data = open(zkr, "rb").read()
    with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zo:
        assert "resolve_zk.zkr" not in zi.namelist()
        for info in zi.infolist():
            zo.writestr(info, zi.read(info.filename))
        entry = zipfile.ZipInfo("resolve_zk.zkr", (1980, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        zo.writestr(entry, data)
    print("resolve_zk.zkr sha256", hashlib.sha256(data).hexdigest())
    print("archive sha256", hashlib.sha256(open(dst, "rb").read()).hexdigest())


if __name__ == "__main__":
    main()
